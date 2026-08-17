import { canonicalDigest, createIdentity, VerificationBudgetExceeded } from "@kinnet/crypto";
import {
  keyEventLogSchema,
  MAX_GRANT_CHAIN_LINKS,
  MAX_KEY_EVENT_KEYS,
  MAX_KEY_LOG_EVENTS
} from "@kinnet/protocol";
import { beginVerificationOperation, createVerificationContext } from "@kinnet/trust";
import { describe, expect, it } from "vitest";

import {
  createDiscoveryView,
  DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS,
  MAX_ISSUERS_PER_REQUEST
} from "../src/discovery-view.js";

const identity = createIdentity({
  currentSeed: new Uint8Array(32).fill(9),
  nextSeed: new Uint8Array(32).fill(10)
});

/**
 * A discovery stub that counts requests. Every unknown id 404s — exactly what a fabricated
 * participant id gets from a real discovery service, and the case that used to leave a
 * `null` entry resident in the cache forever.
 */
function countingFetch() {
  const paths: string[] = [];
  const impl: typeof fetch = async (input) => {
    const url = new URL(
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url
    );
    paths.push(url.pathname);
    if (url.pathname === `/participants/${identity.id}/key-log`) {
      return Response.json({ events: identity.log });
    }
    if (url.pathname.endsWith("/relationships")) {
      return Response.json({ relationship: null });
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  };
  return { impl, paths };
}

/** A mutable clock so TTL expiry can be driven without real time. */
function clock(startMs: number) {
  let wall = startMs;
  let mono = 0;
  return {
    now: () => new Date(wall),
    monotonicNowMs: () => mono,
    /** Real time passes: both timelines advance together. */
    advanceSeconds(seconds: number) {
      wall += seconds * 1000;
      mono += seconds * 1000;
    },
    /** Only the wall clock is stepped — an NTP correction or snapshot restore. */
    stepWallSeconds(seconds: number) {
      wall += seconds * 1000;
    }
  };
}

const START = Date.parse("2026-06-12T00:00:00.000Z");

describe("discovery view cache bounds", () => {
  it("rejects a foreign-view operation before fetching or consulting a key-state memo", async () => {
    const firstHost = countingFetch();
    const secondHost = countingFetch();
    const first = createDiscoveryView({
      discoveryUrl: "https://first.example",
      fetch: firstHost.impl
    });
    const second = createDiscoveryView({
      discoveryUrl: "https://second.example",
      fetch: secondHost.impl
    });
    const context = createVerificationContext({ remaining: 10 });
    const operation = beginVerificationOperation(first, { context });

    await expect(first.getKeyState(identity.id, undefined, operation)).resolves.toMatchObject({
      id: identity.id
    });
    await expect(second.getKeyState(identity.id, undefined, operation)).rejects.toThrow(
      /different TrustView/
    );
    expect(secondHost.paths).toHaveLength(0);
  });

  it("serves legitimate repeat lookups from the cache beneath the ceiling", async () => {
    const { impl, paths } = countingFetch();
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      ...(() => {
        const c = clock(START);
        return { now: c.now, monotonicNowMs: c.monotonicNowMs };
      })(),
      maxCacheEntries: 100
    });

    expect(await view.getKeyState(identity.id)).not.toBeNull();
    expect(await view.getKeyState(identity.id)).not.toBeNull();
    expect(await view.getKeyState(identity.id)).not.toBeNull();

    // One fetch for three reads: the ceiling did not interfere with a normal working set.
    expect(paths).toHaveLength(1);
    expect(view.cacheSize()).toBe(1);
  });

  it("holds a full legitimate working set right up to the ceiling", async () => {
    const { impl, paths } = countingFetch();
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      ...(() => {
        const c = clock(START);
        return { now: c.now, monotonicNowMs: c.monotonicNowMs };
      })(),
      maxCacheEntries: 20
    });

    for (let i = 0; i < 20; i += 1) {
      await view.getRelationshipEdge("pk_zHmai", `pk_participant_${i}`, "pk_zHmai", "represents");
    }
    expect(view.cacheSize()).toBe(20);
    expect(paths).toHaveLength(20);

    // Every one of them is still a hit.
    for (let i = 0; i < 20; i += 1) {
      await view.getRelationshipEdge("pk_zHmai", `pk_participant_${i}`, "pk_zHmai", "represents");
    }
    expect(paths).toHaveLength(20);
  });

  it("caps the cache when an attacker cycles fabricated ids", async () => {
    const { impl, paths } = countingFetch();
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      ...(() => {
        const c = clock(START);
        return { now: c.now, monotonicNowMs: c.monotonicNowMs };
      })(),
      maxCacheEntries: 5
    });

    for (let i = 0; i < 500; i += 1) {
      // Fabricated ids: each 404s and used to leave a resident `null` entry.
      expect(await view.getKeyState(`pk_fabricated_${i}`)).toBeNull();
    }

    expect(paths).toHaveLength(500);
    // The map never exceeded the ceiling — this is the whole security condition.
    expect(view.cacheSize()).toBeLessThanOrEqual(5);
  });

  it("does not rescan the cache on every admission during a fabricated-id flood", async () => {
    // Eviction is the flood's steady state, and it must not carry O(size) work per lookup.
    const { impl } = countingFetch();
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      ...(() => {
        const c = clock(START);
        return { now: c.now, monotonicNowMs: c.monotonicNowMs };
      })(),
      cacheTtlSeconds: 60,
      maxCacheEntries: 50
    });

    for (let i = 0; i < 50; i += 1) {
      await view.getRelationshipEdge("pk_zHmai", `pk_seed_${i}`, "pk_zHmai", "represents");
    }
    const sweepsBeforeFlood = view.cacheSweepCount();

    // The clock never moves, so nothing can expire and no sweep can free anything.
    for (let i = 0; i < 300; i += 1) {
      await view.getKeyState(`pk_fabricated_${i}`);
    }
    expect(view.cacheSweepCount()).toBe(sweepsBeforeFlood);
    expect(view.cacheSize()).toBeLessThanOrEqual(50);
  });

  it("does not serve stale key state after a backward wall-clock step", async () => {
    // The cache TTL is what lets a fresh REVOCATION become visible, so serving past it is
    // authorization-relevant, not just staleness. Measured on the wall clock, a backward step
    // pushed every deadline back into the future and the cache kept answering from memory.
    const time = clock(START);
    const { impl, paths } = countingFetch();
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      now: time.now,
      monotonicNowMs: time.monotonicNowMs,
      cacheTtlSeconds: 60,
      maxCacheEntries: 100
    });

    await view.getKeyState(identity.id);
    expect(paths).toHaveLength(1);

    // Real time passes beyond the TTL, but the wall clock is stepped back further — so on
    // the wall timeline the entry looks freshly written.
    time.advanceSeconds(61);
    time.stepWallSeconds(-3600);

    await view.getKeyState(identity.id);
    // Re-fetched: the monotonic deadline passed and the wall rewind could not undo it.
    expect(paths).toHaveLength(2);
  });

  it("keeps serving from cache within the TTL despite a wall-clock step", async () => {
    // The converse: a wall jump must not expire a cache entry early either.
    const time = clock(START);
    const { impl, paths } = countingFetch();
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      now: time.now,
      monotonicNowMs: time.monotonicNowMs,
      cacheTtlSeconds: 60,
      maxCacheEntries: 100
    });

    await view.getKeyState(identity.id);
    time.stepWallSeconds(86_400); // wall jumps a day forward; no real time passes
    await view.getKeyState(identity.id);
    expect(paths).toHaveLength(1);
  });

  it("keeps deadline order when a concurrent fetch replaces the same key", async () => {
    // `Map.set` on an existing key keeps its ORIGINAL position. Two concurrent lookups of the
    // same path both miss and both insert; without deleting first, the replaced entry keeps
    // an old position while carrying a NEW deadline, so the first entry no longer holds the
    // earliest deadline and the O(1) sweep gate reads a stale answer — the cache then wedges
    // at its ceiling holding reclaimable entries.
    const time = clock(START);
    let release: (() => void) | null = null;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    let slowSeen = false;
    const impl: typeof fetch = async (input) => {
      const url = new URL(
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url
      );
      if (url.pathname.includes("pk_dup") && !slowSeen) {
        slowSeen = true;
        await blocked;
      }
      return Response.json({ relationship: null });
    };
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      now: time.now,
      monotonicNowMs: time.monotonicNowMs,
      cacheTtlSeconds: 60,
      maxCacheEntries: 2
    });

    // First lookup of pk_dup blocks in fetch.
    const first = view.getRelationshipEdge("pk_zHmai", "pk_dup", "pk_zHmai", "represents");
    await new Promise((resolve) => setTimeout(resolve, 0));

    // A second, later lookup of the SAME key misses and completes first, inserting pk_dup.
    time.advanceSeconds(10);
    await view.getRelationshipEdge("pk_zHmai", "pk_dup", "pk_zHmai", "represents");

    // Release the first: it replaces pk_dup with a deadline stamped now.
    time.advanceSeconds(5);
    release!();
    await first;

    // Another key fills the ceiling.
    await view.getRelationshipEdge("pk_zHmai", "pk_other", "pk_zHmai", "represents");
    expect(view.cacheSize()).toBe(2);

    // Past pk_dup's replacement deadline but not pk_other's: the gate must see pk_dup as the
    // earliest and reclaim it rather than believe nothing is reclaimable.
    time.advanceSeconds(61);
    await view.getRelationshipEdge("pk_zHmai", "pk_third", "pk_zHmai", "represents");
    expect(view.cacheSize()).toBeLessThanOrEqual(2);
  });

  it("evicts oldest-first, so eviction costs only a re-fetch", async () => {
    const { impl, paths } = countingFetch();
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      ...(() => {
        const c = clock(START);
        return { now: c.now, monotonicNowMs: c.monotonicNowMs };
      })(),
      maxCacheEntries: 2
    });

    await view.getRelationshipEdge("pk_zHmai", "pk_a", "pk_zHmai", "represents");
    await view.getRelationshipEdge("pk_zHmai", "pk_b", "pk_zHmai", "represents");
    expect(view.cacheSize()).toBe(2);

    // Third distinct id evicts the oldest (pk_a), not the newest.
    await view.getRelationshipEdge("pk_zHmai", "pk_c", "pk_zHmai", "represents");
    expect(view.cacheSize()).toBe(2);

    expect(paths).toHaveLength(3);
    await view.getRelationshipEdge("pk_zHmai", "pk_b", "pk_zHmai", "represents");
    expect(paths).toHaveLength(3); // still cached
    await view.getRelationshipEdge("pk_zHmai", "pk_a", "pk_zHmai", "represents");
    expect(paths).toHaveLength(4); // evicted, so re-fetched — correctness unchanged
  });

  it("removes expired entries from the map without them being re-read", async () => {
    const { impl } = countingFetch();
    const time = clock(START);
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      now: time.now,
      monotonicNowMs: time.monotonicNowMs,
      cacheTtlSeconds: 60,
      maxCacheEntries: 10_000
    });

    for (let i = 0; i < 50; i += 1) {
      await view.getKeyState(`pk_fabricated_${i}`);
    }
    expect(view.cacheSize()).toBe(50);

    // Nobody ever asks for those 50 ids again. One later lookup, past the TTL, is enough:
    // they are dropped from the map, not merely rendered unreadable.
    time.advanceSeconds(61);
    await view.getKeyState(identity.id);
    expect(view.cacheSize()).toBe(1);
  });

  it("keeps unexpired entries when the sweep runs", async () => {
    const { impl, paths } = countingFetch();
    const time = clock(START);
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl,
      now: time.now,
      monotonicNowMs: time.monotonicNowMs,
      cacheTtlSeconds: 60,
      maxCacheEntries: 10_000
    });

    await view.getRelationshipEdge("pk_zHmai", "pk_old", "pk_zHmai", "represents");
    time.advanceSeconds(50);
    await view.getRelationshipEdge("pk_zHmai", "pk_new", "pk_zHmai", "represents");
    // A sweep fires here (>= one TTL window since the first), but only pk_old is stale.
    time.advanceSeconds(20);
    await view.getRelationshipEdge("pk_zHmai", "pk_third", "pk_zHmai", "represents");

    expect(view.cacheSize()).toBe(2);
    expect(paths).toHaveLength(3);
    await view.getRelationshipEdge("pk_zHmai", "pk_new", "pk_zHmai", "represents");
    expect(paths).toHaveLength(3);
  });
});

describe("targeted relationship-edge lookup over HTTP", () => {
  // Schema-valid ids: base58btc has no "l" or "0", so a made-up id would fail
  // `relationshipSchema` and every assertion here would pass vacuously on a null.
  const AGENT = "pk_zAgent";
  const ORG = "pk_zHmai";
  const OTHER = "pk_zStranger";

  const edge = (over: Record<string, unknown> = {}) => ({
    id: "rel-1",
    subjectId: AGENT,
    predicate: "represents",
    objectId: ORG,
    issuedBy: ORG,
    issuedAt: "2026-06-10T00:00:00.000Z",
    signature: "zRe1Sig",
    ...over
  });

  /** Records the request path, and answers with whatever the test wants served. */
  function serving(relationship: unknown) {
    const urls: string[] = [];
    const impl: typeof fetch = async (input) => {
      const href =
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const url = new URL(href);
      urls.push(url.pathname + url.search);
      return Response.json({ relationship });
    };
    return { impl, urls };
  }

  function makeView(impl: typeof fetch) {
    return createDiscoveryView({ discoveryUrl: "https://discovery.example.com", fetch: impl });
  }

  it("asks the targeted question and returns the matching edge", async () => {
    const { impl, urls } = serving(edge());
    const view = makeView(impl);

    expect(await view.getRelationshipEdge(ORG, AGENT, ORG, "represents")).toEqual(edge());
    expect(urls).toEqual([
      `/participants/${AGENT}/relationships?issuer=${ORG}&object=${ORG}&predicate=represents`
    ]);
  });

  it("caches one tuple under one path, and treats a different tuple as a different question", async () => {
    const { impl, urls } = serving(edge());
    const view = makeView(impl);

    await view.getRelationshipEdge(ORG, AGENT, ORG, "represents");
    await view.getRelationshipEdge(ORG, AGENT, ORG, "represents");
    expect(urls).toHaveLength(1);

    await view.getRelationshipEdge(ORG, AGENT, ORG, "employedBy");
    expect(urls).toHaveLength(2);
  });

  it("returns null when discovery holds no edge for the tuple", async () => {
    const { impl } = serving(null);
    expect(await makeView(impl).getRelationshipEdge(ORG, AGENT, ORG, "represents")).toBeNull();
  });

  it("rejects an edge whose tuple is not the one that was requested", async () => {
    // The host filtered; that is a hint, not a fact. Each of these is a well-formed, plausible
    // record that answers a DIFFERENT question — and a caller that accepted any of them would
    // be authorizing against an edge nobody asked for.
    for (const substituted of [
      edge({ issuedBy: OTHER }),
      edge({ subjectId: OTHER }),
      edge({ objectId: OTHER }),
      edge({ predicate: "employedBy" })
    ]) {
      const { impl } = serving(substituted);
      expect(await makeView(impl).getRelationshipEdge(ORG, AGENT, ORG, "represents")).toBeNull();
    }
  });

  it("returns null for a malformed record rather than handing it on", async () => {
    const { impl } = serving({ subjectId: AGENT, objectId: ORG, predicate: "represents" });
    expect(await makeView(impl).getRelationshipEdge(ORG, AGENT, ORG, "represents")).toBeNull();
  });
});

describe("issuer-targeted revocation lookup over HTTP", () => {
  // A real multihash: `revocationSchema` rejects anything else, and this view parses every
  // record it returns, so a made-up digest string would make these tests vacuous.
  const DIGEST = canonicalDigest({ revoked: "record" });
  // Schema-valid participant ids: base58btc has no "l", so "pk_zAlice" would be rejected by
  // `revocationSchema` and every assertion below would pass vacuously on an empty list.
  const ALICE = "pk_zAaa";
  const BOB = "pk_zBbb";

  const revocation = (issuerId: string) => ({
    revokes: DIGEST,
    issuerId,
    revokedAt: "2026-06-10T00:00:00.000Z",
    signature: ["zRevSig"]
  });

  /** A stand-in for the discovery route: answers only the (digest, issuer) pairs it was asked. */
  function targetedFetch(rows: { revokes: string; issuerId: string }[]) {
    const urls: string[] = [];
    const impl: typeof fetch = async (input) => {
      const href =
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const url = new URL(href);
      urls.push(url.pathname + url.search);
      const digest = decodeURIComponent(url.pathname.replace("/revocations/", ""));
      const issuers = url.searchParams.getAll("issuer");
      return Response.json({
        revocations: rows.filter((row) => row.revokes === digest && issuers.includes(row.issuerId))
      });
    };
    return { impl, urls };
  }

  function makeView(impl: typeof fetch) {
    return createDiscoveryView({ discoveryUrl: "https://discovery.example.com", fetch: impl });
  }

  it("encodes the digest and every issuer, and returns only what came back", async () => {
    const { impl, urls } = targetedFetch([revocation(ALICE)]);
    const view = makeView(impl);

    const found = await view.getRevocations(DIGEST, [ALICE, BOB]);
    expect(found.map((r) => r.issuerId)).toEqual([ALICE]);
    expect(urls).toEqual([
      `/revocations/${encodeURIComponent(DIGEST)}?issuer=pk_zAaa&issuer=pk_zBbb`
    ]);
  });

  it("caches one issuer set under a canonical key, so order and repeats do not refetch", async () => {
    const { impl, urls } = targetedFetch([revocation(BOB)]);
    const view = makeView(impl);

    expect((await view.getRevocations(DIGEST, [ALICE, BOB])).map((r) => r.issuerId)).toEqual([BOB]);
    // Same set, different order, and with a duplicate — the same question, so the same entry.
    expect((await view.getRevocations(DIGEST, [BOB, ALICE, BOB])).map((r) => r.issuerId)).toEqual([
      BOB
    ]);
    expect(urls).toHaveLength(1);

    // A DIFFERENT set is a different question and must go to the network.
    await view.getRevocations(DIGEST, [ALICE]);
    expect(urls).toHaveLength(2);
    expect(view.cacheSize()).toBe(2);
  });

  it("returns nothing, and asks nothing, for an empty issuer set", async () => {
    const { impl, urls } = targetedFetch([revocation(ALICE)]);
    const view = makeView(impl);

    expect(await view.getRevocations(DIGEST, [])).toEqual([]);
    expect(urls).toEqual([]);
  });

  it("drops a malformed record rather than returning it as a revocation", async () => {
    const impl: typeof fetch = async () =>
      Response.json({ revocations: [{ revokes: DIGEST, issuerId: ALICE }, revocation(ALICE)] });
    const view = makeView(impl);

    // The first row has no `revokedAt` or signature; a hostile host can send anything.
    expect((await view.getRevocations(DIGEST, [ALICE])).map((r) => r.issuerId)).toEqual([ALICE]);
    expect(await view.getRevocations(DIGEST, [ALICE])).toHaveLength(1);
  });

  it("throws rather than reporting no revocation when the route refuses the request", async () => {
    // The 64-issuer bound answers 400. A revocation lookup that swallowed that would read as
    // "nothing revoked", which is the fail-open shape this whole path exists to remove.
    const impl: typeof fetch = async () =>
      Response.json({ error: "too_many_issuers" }, { status: 400 });
    const view = makeView(impl);

    await expect(view.getRevocations(DIGEST, [ALICE])).rejects.toThrow(/400/);
  });
});

describe("issuer-targeted revocation lookup past the route's per-request bound", () => {
  const DIGEST = canonicalDigest({ revoked: "big-chain-record" });

  // base58btc has no 0, O, I or l, so ids have to be built from its alphabet or
  // `revocationSchema` rejects them and every assertion here would pass on an empty list.
  const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  /**
   * `pk_z` + a two-character base58 counter. Fixed width and big-endian, so ASCII order equals
   * index order — which is what lets a test say "this id lands in the SECOND chunk", since the
   * view chunks the SORTED list.
   */
  function issuerId(index: number): string {
    return `pk_z${BASE58[Math.floor(index / 58)]!}${BASE58[index % 58]!}`;
  }

  const revocation = (issuerId: string) => ({
    revokes: DIGEST,
    issuerId,
    revokedAt: "2026-06-10T00:00:00.000Z",
    signature: ["zRevSig"]
  });

  /**
   * Stands in for the discovery route, bound included: it answers only the pairs it was asked
   * for, and it REFUSES an over-sized ask with the route's own 400 rather than trimming it.
   */
  function routeFetch(rows: { revokes: string; issuerId: string }[]) {
    const asks: string[][] = [];
    const impl: typeof fetch = async (input) => {
      const href =
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const url = new URL(href);
      const issuers = url.searchParams.getAll("issuer");
      asks.push(issuers);
      if (issuers.length > MAX_ISSUERS_PER_REQUEST) {
        return Response.json({ error: "too_many_issuers" }, { status: 400 });
      }
      const digest = decodeURIComponent(url.pathname.replace("/revocations/", ""));
      return Response.json({
        revocations: rows.filter((row) => row.revokes === digest && issuers.includes(row.issuerId))
      });
    };
    return { impl, asks };
  }

  function makeView(impl: typeof fetch) {
    return createDiscoveryView({ discoveryUrl: "https://discovery.example.com", fetch: impl });
  }

  it("splits an over-bound issuer set across requests and unions the answers", async () => {
    // One more issuer than fits in a request. The ONLY revocation published is by the issuer
    // that sorts LAST, so it lands in the second chunk: a client that sent one truncated
    // request, or that stopped after the first chunk, would report this record as absent —
    // and absent means "not revoked".
    const total = MAX_ISSUERS_PER_REQUEST + 1;
    const issuers = Array.from({ length: total }, (_, index) => issuerId(index));
    const onlyInSecondChunk = issuers[total - 1]!;
    const { impl, asks } = routeFetch([revocation(onlyInSecondChunk)]);
    const view = makeView(impl);

    const found = await view.getRevocations(DIGEST, issuers);

    expect(found.map((r) => r.issuerId)).toEqual([onlyInSecondChunk]);
    expect(asks).toHaveLength(2);
    expect(asks[0]).toHaveLength(MAX_ISSUERS_PER_REQUEST);
    expect(asks[0]).not.toContain(onlyInSecondChunk);
    expect(asks[1]).toEqual([onlyInSecondChunk]);
    // Every requested issuer is asked about exactly once across the chunks: split, not trimmed.
    expect([...asks[0]!, ...asks[1]!].sort()).toEqual([...issuers].sort());
  });

  it("unions matches drawn from more than one chunk", async () => {
    const total = MAX_ISSUERS_PER_REQUEST * 2 + 3;
    const issuers = Array.from({ length: total }, (_, index) => issuerId(index));
    const first = issuers[0]!;
    const last = issuers[total - 1]!;
    const { impl, asks } = routeFetch([revocation(first), revocation(last)]);
    const view = makeView(impl);

    expect((await view.getRevocations(DIGEST, issuers)).map((r) => r.issuerId).sort()).toEqual(
      [first, last].sort()
    );
    expect(asks).toHaveLength(3);
  });

  it("sends a set at the bound as exactly one request", async () => {
    const issuers = Array.from({ length: MAX_ISSUERS_PER_REQUEST }, (_, index) => issuerId(index));
    const target = issuers[MAX_ISSUERS_PER_REQUEST - 1]!;
    const { impl, asks } = routeFetch([revocation(target)]);
    const view = makeView(impl);

    expect((await view.getRevocations(DIGEST, issuers)).map((r) => r.issuerId)).toEqual([target]);
    expect(asks).toHaveLength(1);
  });

  it("caches each chunk under its own path, so a repeated over-bound ask refetches nothing", async () => {
    const total = MAX_ISSUERS_PER_REQUEST + 1;
    const issuers = Array.from({ length: total }, (_, index) => issuerId(index));
    const { impl, asks } = routeFetch([revocation(issuers[total - 1]!)]);
    const view = makeView(impl);

    await view.getRevocations(DIGEST, issuers);
    expect(asks).toHaveLength(2);
    expect(view.cacheSize()).toBe(2);

    // The same set again — and the same set shuffled, which sorts back to the same chunks.
    await view.getRevocations(DIGEST, issuers);
    await view.getRevocations(DIGEST, [...issuers].reverse());
    expect(asks).toHaveLength(2);
  });
});

/**
 * The view's verification allowance.
 *
 * It has to be PUBLISHED on the view, not merely used inside `getKeyState`: the paths that
 * actually replay a chain's logs — `@kinnet/trust`'s resolver and this package's record
 * verifier — reach the log through `getKeyLog` and read the ceiling off the view. A view that
 * kept the number to itself would leave those on the general ceiling, which is what shipped
 * once and what these assertions exist to catch.
 */
describe("the view's verification allowance", () => {
  const discoveryUrl = "https://discovery.example.com";

  it.each([
    ["missing", undefined, DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS],
    ["NaN", Number.NaN, DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS],
    ["positive infinity", Number.POSITIVE_INFINITY, DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS],
    ["negative infinity", Number.NEGATIVE_INFINITY, DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS],
    ["negative", -1, DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS],
    ["fraction", 1.5, DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS],
    ["non-number", "7", DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS],
    ["zero", 0, 0],
    ["safe override", 7, 7]
  ])("normalizes a %s option once and publishes %d", (_label, value, expected) => {
    const view = createDiscoveryView({
      discoveryUrl,
      fetch: countingFetch().impl,
      maxSignatureVerifications: value as number
    });
    expect(view.maxSignatureVerifications).toBe(expected);
  });

  it("pins the 13A honest-verdict policy to the protocol constants", () => {
    const A = MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS;
    expect(DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS).toBe((3 * MAX_GRANT_CHAIN_LINKS + 1) * A);
    expect(DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS).toBe(13_312);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 1.5, "7"])(
    "normalizes an explicit malformed remaining=%s to zero before replay",
    async (value) => {
      const view = createDiscoveryView({ discoveryUrl, fetch: countingFetch().impl });
      const budget = { remaining: value } as unknown as { remaining: number };
      await expect(view.getKeyState(identity.id, budget)).rejects.toBeInstanceOf(
        VerificationBudgetExceeded
      );
      expect(budget.remaining).toBe(0);
    }
  );
});

describe("getKeyState binds the served log to the id it was asked for", () => {
  const attacker = createIdentity({
    currentSeed: new Uint8Array(32).fill(21),
    nextSeed: new Uint8Array(32).fill(22)
  });

  /** A hostile host: every key-log path answers with the attacker's own genuine log. */
  function substitutingFetch(): typeof fetch {
    return async (input) => {
      const url = new URL(
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url
      );
      if (url.pathname.endsWith("/key-log")) {
        return Response.json({ events: attacker.log });
      }
      return Response.json({ error: "not_found" }, { status: 404 });
    };
  }

  it("returns null when the host answers one participant's id with another's log", async () => {
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: substitutingFetch()
    });

    // The log itself is impeccable — served at its OWN id it resolves.
    const genuine = await view.getKeyState(attacker.id);
    expect(genuine?.id).toBe(attacker.id);

    // Served at the victim's id it resolves to nothing. Binding here closes every consumer at
    // once, including the ones that never compared `state.id` themselves.
    expect(await view.getKeyState(identity.id)).toBeNull();
  });

  it("fails closed for a caller carrying a budget, without spending the mismatch as cost", async () => {
    // A substituted log must not arrive as a `VerificationBudgetExceeded`: callers treat cost
    // as a retryable stall. It is `null` — the fail-closed answer this method's contract has.
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: substitutingFetch()
    });
    const budget = { remaining: DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS };

    await expect(view.getKeyState(identity.id, budget)).resolves.toBeNull();
  });

  it("still resolves an honestly served log", async () => {
    const { impl } = countingFetch();
    const view = createDiscoveryView({
      discoveryUrl: "https://discovery.example.com",
      fetch: impl
    });

    expect((await view.getKeyState(identity.id))?.id).toBe(identity.id);
  });
});

/**
 * Spec 015 S6.1 at the verifier's own untrusted-host path.
 *
 * This module's contract is that "nothing served is trusted as such", and every record it
 * returns arrives through one `getJson`. A delivery whose JSON carries a duplicate object key
 * has no single meaning — `JSON.parse` resolves it last-wins, other parsers first-wins — so
 * two implementations handed ONE byte string would replay two different key logs and derive
 * two different `prior` chains from it. 015 S6.1 refuses the delivery rather than picking.
 *
 * `z.strictObject` cannot stand in for this and it is worth saying why: a schema inspects the
 * ALREADY-RESOLVED object, by which point the duplicate has been silently decided. Only a
 * strict parse of the bytes sees it. The test below asserts exactly that gap.
 */
describe("strict JSON parsing of discovery deliveries (spec 015 S6.1)", () => {
  const honest = JSON.stringify({ events: identity.log });
  const duplicated = honest.replace('"threshold":"1"', '"threshold":"9","threshold":"1"');

  const serving =
    (body: string): typeof fetch =>
    async () =>
      new Response(body, { status: 200, headers: { "content-type": "application/json" } });

  it("the hostile body really is one byte string with two readings", () => {
    expect(duplicated).not.toBe(honest);
    expect(duplicated).toContain('"threshold":"9","threshold":"1"');
    // Last-wins is what a plain parse yields; a first-wins parser reads 9 from the same bytes.
    const lastWins = JSON.parse(duplicated) as { events: { threshold: string }[] };
    expect(lastWins.events[0]!.threshold).toBe("1");
    // And the resolved object is schema-valid, which is why a schema cannot catch this.
    expect(keyEventLogSchema.safeParse(lastWins.events).success).toBe(true);
  });

  it("accepts the honest delivery and refuses the duplicate-key one", async () => {
    const good = createDiscoveryView({ discoveryUrl: "http://d", fetch: serving(honest) });
    expect(await good.getKeyLog(identity.id)).toHaveLength(identity.log.length);
    expect(await good.getKeyState(identity.id)).toMatchObject({ id: identity.id });

    const hostile = createDiscoveryView({ discoveryUrl: "http://d", fetch: serving(duplicated) });
    await expect(hostile.getKeyLog(identity.id)).rejects.toThrow(/duplicate key "threshold"/);
    await expect(hostile.getKeyState(identity.id)).rejects.toThrow(/duplicate key "threshold"/);
  });

  it("refuses rather than reporting the record absent", async () => {
    // The refusal must not be reachable as `null`. "I will not interpret these bytes" and
    // "there is no such record" are different answers, and collapsing the first into the
    // second would let a hostile host suppress a key log by making it ambiguous. A throw is
    // the same class `getJson` already used for a bad HTTP status, so this adds no new one.
    const hostile = createDiscoveryView({ discoveryUrl: "http://d", fetch: serving(duplicated) });
    await expect(hostile.getKeyLog(identity.id)).rejects.toThrow();
  });
});
