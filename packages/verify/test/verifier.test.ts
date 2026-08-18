import {
  canonicalBytes,
  canonicalDigest,
  commitToKeyState,
  createIdentity,
  DEFAULT_MAX_SKEW_SECONDS,
  deriveParticipantId,
  encodeKeyRef,
  encodeSignature,
  eventDigest,
  generateKeyPair,
  keyLogAnchor,
  rotateIdentity,
  sign,
  signRecord,
  signRequest,
  signThresholdRecord,
  type Identity,
  type KeyPair
} from "@kinnet/crypto";
import {
  MAX_GRANT_CHAIN_LINKS,
  MAX_KEY_EVENT_KEYS,
  MAX_KEY_LOG_EVENTS,
  type Grant,
  type KeyEvent,
  type Relationship,
  type Revocation
} from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  abilityCovers,
  createVerifier,
  DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS,
  VerifyCapacityError,
  VerifyError,
  type VerifierOptions
} from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const NOW = new Date("2026-06-12T00:00:00.000Z");
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);
const ISSUED_AT = new Date(NOW.getTime() - 11 * 86_400_000).toISOString();
const TARGET = "https://api.example.com/quote";

const org = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
const agent = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
const intruder = createIdentity({ currentSeed: seed(5), nextSeed: seed(6) });

type DiscoveryData = {
  logs?: Record<string, KeyEvent[]>;
  relationships?: Record<string, Relationship[]>;
  revocations?: Record<string, Revocation[]>;
};

/** A fetch stub speaking the discovery API's read surface. */
function discoveryFetch(data: DiscoveryData): typeof fetch {
  return async (input) => {
    const url = new URL(
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url
    );
    const keyLog = /^\/participants\/([^/]+)\/key-log$/.exec(url.pathname);
    if (keyLog) {
      const log = data.logs?.[decodeURIComponent(keyLog[1]!)];
      return log
        ? Response.json({ events: log })
        : Response.json({ error: "key_log_not_found" }, { status: 404 });
    }
    const relationships = /^\/participants\/([^/]+)\/relationships$/.exec(url.pathname);
    if (relationships) {
      // Only the TARGETED form is served. A consumer that asked for the listing gets the
      // route's 400, which throws in the client — so a test cannot pass by scanning.
      const subjectId = decodeURIComponent(relationships[1]!);
      const issuer = url.searchParams.get("issuer");
      const object = url.searchParams.get("object");
      const predicate = url.searchParams.get("predicate");
      if (issuer === null || object === null || predicate === null) {
        return Response.json({ error: "invalid_query" }, { status: 400 });
      }
      const edge = (data.relationships?.[subjectId] ?? []).find(
        (row) =>
          row.issuedBy === issuer &&
          row.subjectId === subjectId &&
          row.objectId === object &&
          row.predicate === predicate
      );
      return Response.json({ relationship: edge ?? null });
    }
    const revocations = /^\/revocations\/([^/]+)$/.exec(url.pathname);
    if (revocations) {
      return Response.json({
        revocations: data.revocations?.[decodeURIComponent(revocations[1]!)] ?? []
      });
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  };
}

function representsEdge(): Relationship {
  return signRecord(
    {
      id: "rel-represents-1",
      subjectId: agent.id,
      predicate: "represents",
      objectId: org.id,
      issuedBy: org.id,
      issuedAt: ISSUED_AT
    },
    org.currentKeys[0]!.secretKey
  ) as Relationship;
}

function makeVerifier(data: DiscoveryData, overrides: Partial<VerifierOptions> = {}) {
  return createVerifier({
    discoveryUrl: "https://discovery.example.com",
    fetch: discoveryFetch(data),
    now: () => NOW,
    ...overrides
  });
}

function signedRequest(signer: Identity, body = '{"want":"quote"}', created = NOW_SECONDS) {
  const headers = signRequest({
    method: "POST",
    url: TARGET,
    body,
    keyId: signer.id,
    secretKey: signer.currentKeys[0]!.secretKey,
    created
  });
  return { method: "POST", url: TARGET, headers: { ...headers }, body };
}

const happyData: DiscoveryData = {
  logs: { [org.id]: org.log, [agent.id]: agent.log },
  relationships: { [agent.id]: [representsEdge()] }
};

describe("inbound agent verification", () => {
  it("verifies a signed request and reports the agent, reading no relationship", async () => {
    // No `requireRepresents`, so representation is not a question this surface asks — and the
    // verifier must not answer it anyway by reading edges nobody demanded.
    const verifier = makeVerifier(happyData);
    const verified = await verifier.verify(signedRequest(agent));
    expect(verified).toEqual({
      agentId: agent.id,
      actor: agent.id,
      delegated: false,
      abilities: null,
      satisfiedKey: encodeKeyRef(agent.currentKeys[0]!.publicKey),
      chain: null,
      actorKeyState: expect.objectContaining({ id: agent.id })
    });
  });

  it("rejects a request without a signature", async () => {
    const verifier = makeVerifier(happyData);
    await expect(
      verifier.verify({ method: "POST", url: TARGET, headers: {}, body: "{}" })
    ).rejects.toMatchObject({ name: "VerifyError", reason: "missing_signature", status: 401 });
  });

  it("rejects an agent with no resolvable key log", async () => {
    const verifier = makeVerifier({ logs: { [org.id]: org.log } });
    await expect(verifier.verify(signedRequest(agent))).rejects.toMatchObject({
      reason: "agent_key_log_unresolved"
    });
  });

  it("rejects a tampered body, naming the digest rather than the signature", async () => {
    const verifier = makeVerifier(happyData);
    const request = signedRequest(agent);
    await expect(verifier.verify({ ...request, body: '{"want":"refund"}' })).rejects.toMatchObject({
      // Was `signature_invalid`. A body that does not match its Content-Digest is far more often
      // a rewriting intermediary than an attacker, and under the old reason that diagnosis was
      // unavailable to everyone downstream. Still 401 — the request is not admitted.
      reason: "content_digest_mismatch",
      status: 401
    });
  });

  it("rejects a signature by a key that is not the agent's", async () => {
    const verifier = makeVerifier({
      logs: { ...happyData.logs, [intruder.id]: intruder.log },
      relationships: happyData.relationships
    });
    const headers = signRequest({
      method: "POST",
      url: TARGET,
      body: "{}",
      keyId: agent.id,
      secretKey: intruder.currentKeys[0]!.secretKey,
      created: NOW_SECONDS
    });
    await expect(
      verifier.verify({ method: "POST", url: TARGET, headers: { ...headers }, body: "{}" })
    ).rejects.toMatchObject({ reason: "signature_invalid" });
  });

  it("rejects a stale signature and a replayed nonce", async () => {
    const verifier = makeVerifier(happyData);

    await expect(
      verifier.verify(signedRequest(agent, "{}", NOW_SECONDS - 3600))
    ).rejects.toMatchObject({ reason: "signature_stale" });

    const request = signedRequest(agent);
    await verifier.verify(request);
    await expect(verifier.verify(request)).rejects.toMatchObject({ reason: "nonce_replayed" });
  });

  it("refuses a replay at the LAST second the signature is still fresh", async () => {
    // Regression for a real replay hole. Freshness is `|now - created| <= maxSkew`
    // (inclusive), so a signature is presentable across the closed interval
    // [created - S, created + S] — a 2S-wide window. The nonce TTL used to be exactly 2S,
    // so at `created + S` the guard had already forgotten the nonce while the signature
    // was still fresh: accepted at t, refused at t + 2S - 1, ACCEPTED AGAIN at t + 2S.
    //
    // This is deliberately a REQUEST-level test. The guard-level suite is what missed the
    // bug, because at that layer the off-by-one looks like a reasonable window boundary.
    const S = DEFAULT_MAX_SKEW_SECONDS;
    let clockSeconds = NOW_SECONDS - S;
    const verifier = makeVerifier(happyData, { now: () => new Date(clockSeconds * 1000) });

    // One signature, created at NOW_SECONDS, presented as early as freshness allows.
    const request = signedRequest(agent, "{}", NOW_SECONDS);
    await expect(verifier.verify(request)).resolves.toMatchObject({ agentId: agent.id });

    // Mid-window: refused (this arm always worked).
    clockSeconds = NOW_SECONDS + S - 1;
    await expect(verifier.verify(request)).rejects.toMatchObject({ reason: "nonce_replayed" });

    // The boundary. Freshness still passes here, so the nonce MUST still be remembered.
    clockSeconds = NOW_SECONDS + S;
    await expect(verifier.verify(request)).rejects.toMatchObject({ reason: "nonce_replayed" });

    // One second on, the signature is stale and freshness owns the rejection — which is
    // why no margin beyond `+1` is needed.
    clockSeconds = NOW_SECONDS + S + 1;
    await expect(verifier.verify(request)).rejects.toMatchObject({ reason: "signature_stale" });
  });

  it("retains the nonce across a wall rewind while retention has not elapsed", async () => {
    // Retention rides the monotonic clock, so a wall step cannot shorten it. Both clocks are
    // driven here — the previous version of this test never advanced the monotonic clock at
    // all, so the nonce was never reclaimed and the assertion proved nothing about rewinds.
    const S = DEFAULT_MAX_SKEW_SECONDS;
    let wallSeconds = NOW_SECONDS;
    // Deliberately never advanced: the point of this test is a wall excursion with zero
    // elapsed real time, so retention cannot have run out on the monotonic timeline.
    const monoMs = 0;
    const verifier = makeVerifier(happyData, {
      now: () => new Date(wallSeconds * 1000),
      monotonicNowMs: () => monoMs
    });

    const request = signedRequest(agent, "{}", NOW_SECONDS);
    await expect(verifier.verify(request)).resolves.toMatchObject({ agentId: agent.id });

    // A wall excursion with no real time elapsed: retention is untouched.
    wallSeconds = NOW_SECONDS + 4 * S;
    await expect(verifier.verify(signedRequest(agent, "{}", wallSeconds))).resolves.toBeTruthy();
    wallSeconds = NOW_SECONDS;
    await expect(verifier.verify(request)).rejects.toMatchObject({ reason: "nonce_replayed" });

    // And nothing is refused on capacity or clock grounds throughout.
    wallSeconds = NOW_SECONDS + 4 * S;
    await expect(verifier.verify(signedRequest(agent, "{}", wallSeconds))).resolves.toBeTruthy();
  });

  it("DOCUMENTED RESIDUAL: a one-second wall rewind replays a reclaimed nonce", async () => {
    // The residual at the REQUEST level, at its true magnitude. Retention must genuinely
    // elapse first — which needs the monotonic clock advanced, not just the wall clock.
    const S = DEFAULT_MAX_SKEW_SECONDS;
    const created = NOW_SECONDS;
    let wallSeconds = created - S; // earliest presentation
    let monoMs = 0;
    const verifier = makeVerifier(happyData, {
      now: () => new Date(wallSeconds * 1000),
      monotonicNowMs: () => monoMs
    });

    const request = signedRequest(agent, "{}", created);
    await expect(verifier.verify(request)).resolves.toMatchObject({ agentId: agent.id });

    // Real time advances to the reclamation point, created + S + 1, on BOTH clocks.
    const elapsed = 2 * S + 1;
    wallSeconds += elapsed;
    monoMs += elapsed * 1000;
    expect(wallSeconds).toBe(created + S + 1);
    // Drive a sweep so the nonce is actually reclaimed.
    await expect(verifier.verify(signedRequest(agent, "{}", wallSeconds))).resolves.toBeTruthy();

    // One second back on the wall clock and the original signature is fresh again.
    wallSeconds -= 1;
    expect(Math.abs(wallSeconds - created)).toBeLessThanOrEqual(S);
    await expect(verifier.verify(request)).resolves.toMatchObject({ agentId: agent.id });
  });

  it("reports an unusable surface clock as capacity, not as a bad signature", async () => {
    // Previously unreachable: `verifyRequest` validated the clock and threw a plain Error,
    // which this layer mapped to `signature_invalid`/401 — telling the caller its signature
    // was bad when the fault was entirely ours. The documented `clock_invalid` reason could
    // not be observed through either adapter.
    const verifier = makeVerifier(happyData, { now: () => new Date(Number.NaN) });
    await expect(verifier.verify(signedRequest(agent))).rejects.toMatchObject({
      name: "VerifyCapacityError",
      reason: "clock_invalid",
      status: 503
    });
  });

  it("verifies legitimate load beneath the nonce ceiling untouched", async () => {
    // The ceiling is a memory bound, not a throughput bound: everything under it verifies.
    const verifier = makeVerifier(happyData, { maxTrackedNonces: 4 });
    for (let i = 0; i < 4; i += 1) {
      const verified = await verifier.verify(signedRequest(agent, `{"n":${i}}`));
      expect(verified.agentId).toBe(agent.id);
    }
  });

  it("fails closed at the nonce ceiling without evicting a live nonce", async () => {
    const verifier = makeVerifier(happyData, { maxTrackedNonces: 2 });

    // Fill the map. The first request's nonce is the oldest live entry.
    const first = signedRequest(agent, '{"n":0}');
    await verifier.verify(first);
    await verifier.verify(signedRequest(agent, '{"n":1}'));

    // Over the ceiling, the new request is refused — never admitted unrecorded. 503, not
    // 401: the caller's credentials are fine, the surface is out of capacity.
    await expect(verifier.verify(signedRequest(agent, '{"n":2}'))).rejects.toMatchObject({
      name: "VerifyCapacityError",
      reason: "nonce_capacity",
      status: 503
    });

    // And the oldest live nonce was NOT evicted to make room: its replay is still refused.
    await expect(verifier.verify(first)).rejects.toMatchObject({ reason: "nonce_replayed" });
  });

  it("denies under requireRepresents when the represents edge is revoked", async () => {
    // The lookup finds the edge; the resolver still rejects it. Narrowing the read did not
    // move the signature/expiry/revocation checks anywhere.
    const edge = representsEdge();
    const revocation = signThresholdRecord(
      {
        revokes: canonicalDigest(edge),
        issuerId: org.id,
        anchor: keyLogAnchor(org.log),
        revokedAt: ISSUED_AT
      },
      [org.currentKeys[0]!.secretKey]
    ) as Revocation;
    const verifier = makeVerifier(
      {
        logs: happyData.logs,
        relationships: { [agent.id]: [edge] },
        revocations: { [revocation.revokes]: [revocation] }
      },
      { requireRepresents: org.id }
    );

    await expect(verifier.verify(signedRequest(agent))).rejects.toMatchObject({
      reason: "represents_chain_unverified"
    });
  });

  it("denies under requireRepresents when the represents edge has expired", async () => {
    const expired = signRecord(
      {
        id: "rel-expired-1",
        subjectId: agent.id,
        predicate: "represents",
        objectId: org.id,
        issuedBy: org.id,
        issuedAt: ISSUED_AT,
        expiresAt: new Date(NOW.getTime() - 86_400_000).toISOString()
      },
      org.currentKeys[0]!.secretKey
    ) as Relationship;
    const verifier = makeVerifier(
      { logs: happyData.logs, relationships: { [agent.id]: [expired] } },
      { requireRepresents: org.id }
    );

    await expect(verifier.verify(signedRequest(agent))).rejects.toMatchObject({
      reason: "represents_chain_unverified"
    });
  });

  it("gates on requireRepresents", async () => {
    const accepted = await makeVerifier(happyData, { requireRepresents: org.id }).verify(
      signedRequest(agent)
    );
    expect(accepted.agentId).toBe(agent.id);

    const noEdge = makeVerifier(
      { logs: happyData.logs, relationships: {} },
      { requireRepresents: org.id }
    );
    await expect(noEdge.verify(signedRequest(agent))).rejects.toMatchObject({
      reason: "represents_chain_unverified"
    });
  });

  it("asks only the targeted question, and only when requireRepresents is set", async () => {
    // The wire form is what discriminates: a scan of every edge naming the agent would reach
    // the same ALLOW, so the verdict alone would pass under the code this replaces.
    const paths: string[] = [];
    const recording: typeof fetch = async (input, init) => {
      const href =
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const url = new URL(href);
      paths.push(url.pathname + url.search);
      return discoveryFetch(happyData)(input, init);
    };

    const quiet = createVerifier({
      discoveryUrl: "https://discovery.example.com",
      fetch: recording,
      now: () => NOW
    });
    await quiet.verify(signedRequest(agent));
    expect(paths.filter((path) => path.includes("/relationships"))).toEqual([]);

    paths.length = 0;
    const gated = createVerifier({
      discoveryUrl: "https://discovery.example.com",
      fetch: recording,
      now: () => NOW,
      requireRepresents: org.id
    });
    await gated.verify(signedRequest(agent, '{"want":"quote2"}'));
    expect(paths.filter((path) => path.includes("/relationships"))).toEqual([
      `/participants/${encodeURIComponent(agent.id)}/relationships` +
        `?issuer=${encodeURIComponent(org.id)}&object=${encodeURIComponent(org.id)}` +
        `&predicate=represents`
    ]);
  });

  it("denies on a self-issued represents edge", async () => {
    // An agent cannot self-issue its way into representing anyone. It is not even on the key
    // that gets read: the decision key names the ORGANIZATION as issuer, so this edge — stored
    // under a different tuple — is invisible to the lookup as well as invalid to the resolver.
    const selfIssued = signRecord(
      {
        id: "rel-self-1",
        subjectId: agent.id,
        predicate: "represents",
        objectId: org.id,
        issuedBy: agent.id,
        issuedAt: ISSUED_AT
      },
      agent.currentKeys[0]!.secretKey
    ) as Relationship;
    const verifier = makeVerifier(
      { logs: happyData.logs, relationships: { [agent.id]: [selfIssued] } },
      { requireRepresents: org.id }
    );

    await expect(verifier.verify(signedRequest(agent))).rejects.toMatchObject({
      reason: "represents_chain_unverified"
    });
  });
});

describe("delegated requests (spec 011)", () => {
  const user = createIdentity({ currentSeed: seed(7), nextSeed: seed(8) });
  const backend = createIdentity({ currentSeed: seed(9), nextSeed: seed(10) });
  const service = createIdentity({ currentSeed: seed(11), nextSeed: seed(12) });
  const session = generateKeyPair(seed(13));
  const sessionKeyRef = encodeKeyRef(session.publicKey);
  const otherSession = generateKeyPair(seed(14));

  const EXPIRES_AT = new Date(NOW.getTime() + 19 * 86_400_000).toISOString();

  /** The self-issued root: user delegates to the session key (spec 009 root shape). */
  function sessionGrant(overrides: Partial<Grant> = {}): Grant {
    return signThresholdRecord(
      {
        subjectId: user.id,
        issuerId: user.id,
        audienceId: sessionKeyRef,
        abilities: ["msg/send"],
        caveats: { aud: [service.id] },
        // Spec 016: required on a participant-issued link, forbidden on the key-issued tail
        // below.
        anchor: keyLogAnchor(user.log),
        proof: null,
        issuedAt: ISSUED_AT,
        expiresAt: EXPIRES_AT,
        ...overrides
      },
      [user.currentKeys[0]!.secretKey]
    ) as Grant;
  }

  /** The multi-hop tail: the session key sub-delegates to the backend participant. */
  function backendGrant(root: Grant): Grant {
    return signThresholdRecord(
      {
        subjectId: user.id,
        issuerId: sessionKeyRef,
        audienceId: backend.id,
        abilities: ["msg/send"],
        caveats: {},
        proof: canonicalDigest(root),
        issuedAt: ISSUED_AT
      },
      [session.secretKey]
    ) as Grant;
  }

  function delegatedRequest(
    chain: Grant[],
    signing: { keyId?: string; secretKey?: Uint8Array; body?: string } = {}
  ) {
    const body = signing.body ?? '{"want":"quote"}';
    const headers = signRequest({
      method: "POST",
      url: TARGET,
      body,
      keyId: signing.keyId ?? sessionKeyRef,
      secretKey: signing.secretKey ?? session.secretKey,
      created: NOW_SECONDS,
      grants: chain
    });
    return { method: "POST", url: TARGET, headers: { ...headers }, body };
  }

  const delegatedData: DiscoveryData = {
    logs: { [user.id]: user.log, [backend.id]: backend.log }
  };

  function makeDelegatedVerifier(
    data: DiscoveryData = delegatedData,
    overrides: Partial<VerifierOptions> = {}
  ) {
    return makeVerifier(data, { verifierId: service.id, ...overrides });
  }

  it("verifies a browser-session request: KeyRef keyid plus a single-link chain", async () => {
    const verifier = makeDelegatedVerifier();
    const chain = [sessionGrant()];
    const verified = await verifier.verify(delegatedRequest(chain));
    expect(verified).toEqual({
      agentId: user.id,
      actor: sessionKeyRef,
      delegated: true,
      abilities: ["msg/send"],
      satisfiedKey: sessionKeyRef,
      chain,
      actorKeyState: null
    });
  });

  it("verifies the multi-hop tail: participant keyid presenting the full chain", async () => {
    const root = sessionGrant();
    const chain = [backendGrant(root), root];
    const verifier = makeDelegatedVerifier();
    const verified = await verifier.verify(
      delegatedRequest(chain, {
        keyId: backend.id,
        secretKey: backend.currentKeys[0]!.secretKey
      })
    );
    expect(verified).toEqual({
      agentId: user.id,
      actor: backend.id,
      delegated: true,
      abilities: ["msg/send"],
      satisfiedKey: encodeKeyRef(backend.currentKeys[0]!.publicKey),
      chain,
      actorKeyState: expect.objectContaining({ id: backend.id })
    });
  });

  it("rejects a keyid that is neither a participant id nor a KeyRef", async () => {
    const verifier = makeDelegatedVerifier();
    for (const keyId of ["junk keyid!!", "pk_", "zO0Il", "zabc"]) {
      await expect(
        verifier.verify(delegatedRequest([sessionGrant()], { keyId }))
      ).rejects.toMatchObject({ name: "VerifyError", reason: "keyid_invalid" });
    }
  });

  it("rejects a KeyRef keyid without a PN-Grants header", async () => {
    const verifier = makeDelegatedVerifier();
    const headers = signRequest({
      method: "POST",
      url: TARGET,
      body: "{}",
      keyId: sessionKeyRef,
      secretKey: session.secretKey,
      created: NOW_SECONDS
    });
    await expect(
      verifier.verify({ method: "POST", url: TARGET, headers: { ...headers }, body: "{}" })
    ).rejects.toMatchObject({ reason: "delegation_required" });
  });

  it("rejects a PN-Grants header the signature does not cover", async () => {
    const verifier = makeDelegatedVerifier();
    const uncovered = signRequest({
      method: "POST",
      url: TARGET,
      body: "{}",
      keyId: sessionKeyRef,
      secretKey: session.secretKey,
      created: NOW_SECONDS
    });
    const covered = delegatedRequest([sessionGrant()], { body: "{}" });
    await expect(
      verifier.verify({
        method: "POST",
        url: TARGET,
        headers: { ...uncovered, "pn-grants": covered.headers["pn-grants"] },
        body: "{}"
      })
    ).rejects.toMatchObject({ reason: "signature_invalid" });
  });

  it("rejects a chain that fails to decode as grants_malformed", async () => {
    const verifier = makeDelegatedVerifier();
    const bogusChain = [{ bogus: true } as unknown as Grant];
    await expect(verifier.verify(delegatedRequest(bogusChain))).rejects.toMatchObject({
      reason: "grants_malformed"
    });
  });

  it("rejects a chain whose leaf audience is not the signing keyid", async () => {
    const verifier = makeDelegatedVerifier();
    // The chain audiences the session key, but the backend presents it as its own.
    await expect(
      verifier.verify(
        delegatedRequest([sessionGrant()], {
          keyId: backend.id,
          secretKey: backend.currentKeys[0]!.secretKey
        })
      )
    ).rejects.toMatchObject({ reason: "grants_leaf_audience_mismatch" });
  });

  it("rejects a chain whose aud does not admit this verifier", async () => {
    const elsewhere = sessionGrant({ caveats: { aud: [backend.id] } });
    await expect(
      makeDelegatedVerifier().verify(delegatedRequest([elsewhere]))
    ).rejects.toMatchObject({ reason: "grant_audience_not_admitted" });
  });

  it("rejects an aud-restricted chain when the verifier has no verifierId", async () => {
    const verifier = makeVerifier(delegatedData);
    await expect(verifier.verify(delegatedRequest([sessionGrant()]))).rejects.toMatchObject({
      reason: "grant_audience_not_admitted"
    });
  });

  it("rejects an expired session grant", async () => {
    const expired = sessionGrant({ expiresAt: new Date(NOW.getTime() - 86_400_000).toISOString() });
    await expect(makeDelegatedVerifier().verify(delegatedRequest([expired]))).rejects.toMatchObject(
      { reason: "grant_expired" }
    );
  });

  it("rejects a revoked session grant", async () => {
    const root = sessionGrant();
    const revocation = signThresholdRecord(
      {
        revokes: canonicalDigest(root),
        issuerId: user.id,
        anchor: keyLogAnchor(user.log),
        revokedAt: ISSUED_AT
      },
      [user.currentKeys[0]!.secretKey]
    ) as Revocation;
    const verifier = makeDelegatedVerifier({
      ...delegatedData,
      revocations: { [revocation.revokes]: [revocation] }
    });
    await expect(verifier.verify(delegatedRequest([root]))).rejects.toMatchObject({
      reason: "grant_revoked"
    });
  });

  it("rejects a request signed by a key other than the KeyRef keyid", async () => {
    const verifier = makeDelegatedVerifier();
    await expect(
      verifier.verify(delegatedRequest([sessionGrant()], { secretKey: otherSession.secretKey }))
    ).rejects.toMatchObject({ reason: "signature_invalid" });
  });

  it("rejects a delegated request whose chain does not cover requireAbilities", async () => {
    const verifier = makeDelegatedVerifier(delegatedData, { requireAbilities: ["ledger/write"] });
    await expect(verifier.verify(delegatedRequest([sessionGrant()]))).rejects.toMatchObject({
      reason: "grants_abilities_insufficient"
    });
  });

  it("accepts prefix-covered abilities and lets root-authority requests pass trivially", async () => {
    const covered = await makeDelegatedVerifier(delegatedData, {
      requireAbilities: ["ledger/write"]
    }).verify(delegatedRequest([sessionGrant({ abilities: ["ledger"] })]));
    expect(covered.abilities).toEqual(["ledger"]);

    // Non-delegated: the participant acts with root authority; requireAbilities is moot.
    const rootAuthority = await makeVerifier(happyData, {
      requireAbilities: ["ledger/write"]
    }).verify(signedRequest(agent));
    expect(rootAuthority.delegated).toBe(false);
    expect(rootAuthority.abilities).toBeNull();
  });

  describe("requireAud — audience binding is opt-in and closes the aud-less chain", () => {
    // An aud-less chain is legal whenever no link has a key audience (spec 011 mandates
    // `aud` only there), and it names no verifier — so without requireAud it is admitted
    // at every relying party, whatever verifierId that party states.
    const audlessRoot = signThresholdRecord(
      {
        subjectId: user.id,
        issuerId: user.id,
        audienceId: backend.id,
        abilities: ["msg/send"],
        caveats: {},
        anchor: keyLogAnchor(user.log),
        proof: null,
        issuedAt: ISSUED_AT,
        expiresAt: EXPIRES_AT
      },
      [user.currentKeys[0]!.secretKey]
    ) as Grant;

    function audlessRequest() {
      return delegatedRequest([audlessRoot], {
        keyId: backend.id,
        secretKey: backend.currentKeys[0]!.secretKey
      });
    }

    it("accepts an aud-less chain by default, at a verifier it never named", async () => {
      const verified = await makeDelegatedVerifier().verify(audlessRequest());
      expect(verified).toEqual({
        agentId: user.id,
        actor: backend.id,
        delegated: true,
        abilities: ["msg/send"],
        satisfiedKey: encodeKeyRef(backend.currentKeys[0]!.publicKey),
        chain: [audlessRoot],
        actorKeyState: expect.objectContaining({ id: backend.id })
      });

      // Not even a foreign verifierId keeps it out — that is the gap requireAud closes.
      const elsewhere = await makeVerifier(delegatedData, { verifierId: service.id }).verify(
        audlessRequest()
      );
      expect(elsewhere.agentId).toBe(user.id);
    });

    it("rejects an aud-less chain with grant_audience_required under requireAud", async () => {
      const verifier = makeDelegatedVerifier(delegatedData, { requireAud: true });
      await expect(verifier.verify(audlessRequest())).rejects.toMatchObject({
        name: "VerifyError",
        reason: "grant_audience_required",
        status: 401
      });
    });

    it("still accepts an aud-bound chain naming this verifier under requireAud", async () => {
      const verified = await makeDelegatedVerifier(delegatedData, { requireAud: true }).verify(
        delegatedRequest([sessionGrant()])
      );
      expect(verified.abilities).toEqual(["msg/send"]);
    });

    it("leaves non-delegated requests untouched by requireAud", async () => {
      const verified = await makeVerifier(happyData, { requireAud: true }).verify(
        signedRequest(agent)
      );
      expect(verified).toEqual({
        agentId: agent.id,
        actor: agent.id,
        delegated: false,
        abilities: null,
        satisfiedKey: encodeKeyRef(agent.currentKeys[0]!.publicKey),
        chain: null,
        actorKeyState: expect.objectContaining({ id: agent.id })
      });
    });
  });

  it("rejects a replayed nonce in delegated mode", async () => {
    const verifier = makeDelegatedVerifier();
    const request = delegatedRequest([sessionGrant()]);
    await verifier.verify(request);
    await expect(verifier.verify(request)).rejects.toMatchObject({ reason: "nonce_replayed" });
  });

  /**
   * Security review finding 10 — the replay nonce is COMMITTED only after the request has
   * fully authorized.
   *
   * The nonce map is bounded and never evicts a live entry, so at its ceiling every signed
   * request on the process is refused for up to a full retention window. Committing before
   * grant-chain authorization meant a caller whose requests are all REJECTED could still spend
   * that capacity, and minting valid signatures needs nothing but a self-minted keypair.
   *
   * THE MUTATION THESE TESTS CATCH: committing the nonce where the question is asked — i.e.
   * a single `nonceGuard.check(...)` before `verifyGrantChain` instead of `peek` there and
   * `check` after every authorization stage. Each test below is watched to fail that way: the
   * first two turn a success into `nonce_replayed`/`nonce_capacity`, the last into a 503 where
   * a 401 belongs.
   *
   * The lever throughout is a discovery dataset with the chain issuer's key log MISSING and
   * then added. The signing principal is a bare KeyRef, which needs no log of its own, so the
   * SIGNATURE verifies identically in both states and only the chain's verdict moves — which
   * puts the difference exactly on the two sides of the reorder. `cacheTtlSeconds: 0` keeps the
   * discovery view from answering the second call from the first call's miss.
   */
  describe("finding 10 — the nonce is committed only after full authorization", () => {
    it("admits the identical request, nonce and all, once its chain authorizes", async () => {
      const data: DiscoveryData = { logs: {} };
      const verifier = makeDelegatedVerifier(data, { cacheTtlSeconds: 0 });
      const request = delegatedRequest([sessionGrant()]);

      // Rejected on the chain — the issuer's key log cannot be resolved. This happens strictly
      // after the signature (and therefore after the nonce is known), which is what makes it a
      // test of the ordering rather than of an earlier gate.
      await expect(verifier.verify(request)).rejects.toMatchObject({ status: 401 });

      data.logs![user.id] = user.log;

      // The very same bytes — same signature, same nonce — now authorize. Under the old
      // ordering the rejected attempt had already recorded this nonce and this is
      // `nonce_replayed`.
      const verified = await verifier.verify(request);
      expect(verified.agentId).toBe(user.id);
      expect(verified.delegated).toBe(true);
    });

    it("spends no nonce capacity on requests the chain rejects", async () => {
      // One slot for the whole verifier: if a single rejected request commits, the authorized
      // one at the end is refused `nonce_capacity` instead of being verified.
      const data: DiscoveryData = { logs: {} };
      const verifier = makeDelegatedVerifier(data, { maxTrackedNonces: 1, cacheTtlSeconds: 0 });

      for (let i = 0; i < 8; i += 1) {
        // Distinct bodies mean distinct nonces, so this is capacity being consumed rather
        // than one nonce being re-presented.
        await expect(
          verifier.verify(delegatedRequest([sessionGrant()], { body: `{"n":${i}}` }))
        ).rejects.toMatchObject({ status: 401 });
      }

      data.logs![user.id] = user.log;
      const verified = await verifier.verify(
        delegatedRequest([sessionGrant()], { body: '{"n":"good"}' })
      );
      expect(verified.agentId).toBe(user.id);
    });

    it("still refuses the replay of a request that did authorize", async () => {
      // The guarantee the reorder must not weaken. Deferring the commit is only safe if a
      // successfully-verified request is unreplayable, and the commit is the last statement
      // before the return precisely so that it is.
      const verifier = makeDelegatedVerifier(delegatedData, { maxTrackedNonces: 1 });
      const request = delegatedRequest([sessionGrant()]);
      expect((await verifier.verify(request)).agentId).toBe(user.id);
      await expect(verifier.verify(request)).rejects.toMatchObject({
        reason: "nonce_replayed",
        status: 401
      });
      // Twice, because a commit that only happened on the first replay-check would still pass
      // a single-replay assertion.
      await expect(verifier.verify(request)).rejects.toMatchObject({ reason: "nonce_replayed" });
    });

    it("reports a saturated map to an unauthorized caller as 401, not as capacity", async () => {
      // A rejected request never reaches the commit, so a full map cannot turn an
      // authorization failure into a 503 — the caller is told the truth about why it failed,
      // and an attacker cannot use the ceiling to mask rejections as outages.
      const data: DiscoveryData = { logs: { [user.id]: user.log } };
      const verifier = makeDelegatedVerifier(data, { maxTrackedNonces: 1, cacheTtlSeconds: 0 });

      // Saturate with one authorized request...
      await verifier.verify(delegatedRequest([sessionGrant()], { body: '{"n":"fill"}' }));

      // ...an authorized caller is now refused on capacity, 503, exactly as before...
      await expect(
        verifier.verify(delegatedRequest([sessionGrant()], { body: '{"n":"next"}' }))
      ).rejects.toMatchObject({
        name: "VerifyCapacityError",
        reason: "nonce_capacity",
        status: 503
      });

      // ...while an unauthorized one is rejected on its own merits and consumes nothing.
      delete data.logs![user.id];
      await expect(
        verifier.verify(delegatedRequest([sessionGrant()], { body: '{"n":"bad"}' }))
      ).rejects.toMatchObject({ name: "VerifyError", status: 401 });
    });
  });

  it("rejects a tampered chain whose subject is not the root issuer", async () => {
    const tampered = sessionGrant({ subjectId: backend.id });
    await expect(
      makeDelegatedVerifier().verify(delegatedRequest([tampered]))
    ).rejects.toMatchObject({ reason: "grant_root_not_self_issued" });
  });

  describe("e2ee chains are never request-valid (spec 014)", () => {
    // The attack this closes: an MLS credential is handed to counterparties and, via
    // KeyPackages, to strangers. It carries no `aud` (014 lifts 011's requirement for
    // exactly this shape), so if it authorized requests it would be a general-purpose
    // bearer token with no audience restriction. It must authorize zero requests anywhere.
    const credential = () => sessionGrant({ abilities: ["e2ee/leaf"], caveats: {} });

    it("rejects a request presenting a pure credential chain", async () => {
      await expect(
        makeDelegatedVerifier().verify(delegatedRequest([credential()]))
      ).rejects.toMatchObject({
        name: "VerifyError",
        reason: "grant_e2ee_not_request_valid",
        status: 401
      });
    });

    it("rejects a credential chain at a verifier demanding no abilities at all", async () => {
      // No requireAbilities, no requireAud, no requireRepresents — a bare surface still
      // rejects, because the rule is the chain's, not the surface's policy.
      const verifier = makeVerifier(delegatedData);
      await expect(verifier.verify(delegatedRequest([credential()]))).rejects.toMatchObject({
        reason: "grant_e2ee_not_request_valid"
      });
    });

    it("rejects the bare `e2ee` ability", async () => {
      await expect(
        makeDelegatedVerifier().verify(
          delegatedRequest([sessionGrant({ abilities: ["e2ee"], caveats: {} })])
        )
      ).rejects.toMatchObject({ reason: "grant_e2ee_not_request_valid" });
    });

    it("rejects a MIXED chain instead of authorizing its `msg/send` half", async () => {
      // The whole-chain reading, pinned so two verifiers cannot differ: the surface asks
      // only for `msg/send`, which the chain does carry — and it is still rejected, with
      // the e2ee reason rather than `grants_abilities_insufficient`.
      const mixed = sessionGrant({ abilities: ["e2ee/leaf", "msg/send"] });
      const verifier = makeDelegatedVerifier(delegatedData, { requireAbilities: ["msg/send"] });
      await expect(verifier.verify(delegatedRequest([mixed]))).rejects.toMatchObject({
        reason: "grant_e2ee_not_request_valid"
      });
    });

    it("does NOT treat `e2eex` or `e2eeleaf` as e2ee — those requests authorize normally", async () => {
      for (const ability of ["e2eex/leaf", "e2eeleaf"]) {
        const verifier = makeDelegatedVerifier(delegatedData, { requireAbilities: [ability] });
        const verified = await verifier.verify(
          delegatedRequest([sessionGrant({ abilities: [ability] })])
        );
        expect(verified.abilities).toEqual([ability]);
        expect(verified.agentId).toBe(user.id);
      }
    });

    it("rejects a credential chain through the Fetch-API adapter", async () => {
      const { headers, body } = delegatedRequest([credential()]);
      const request = new Request(TARGET, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body
      });
      await expect(makeDelegatedVerifier().verifyFetch(request)).rejects.toMatchObject({
        reason: "grant_e2ee_not_request_valid"
      });
    });

    it("ends 401 with the e2ee reason through the Express-style middleware", async () => {
      const { headers, body } = delegatedRequest([credential()]);
      const req = {
        method: "POST",
        protocol: "https",
        originalUrl: "/quote",
        headers: { ...headers, host: "api.example.com" } as Record<string, string>,
        // Raw bytes, as `express.raw` delivers them — the middleware refuses anything else.
        body: Buffer.from(body, "utf8"),
        get(name: string) {
          return this.headers[name.toLowerCase()];
        }
      };
      let responded: unknown;
      let statusCode: number | undefined;

      await makeDelegatedVerifier().middleware()(
        req,
        {
          status(code: number) {
            statusCode = code;
            return {
              json: (payload: unknown) => {
                responded = payload;
                return undefined;
              }
            };
          }
        },
        () => {
          throw new Error("next() must not be called on a credential-bearing request");
        }
      );

      expect(statusCode).toBe(401);
      expect(responded).toEqual({
        error: "unauthorized_agent",
        reason: "grant_e2ee_not_request_valid"
      });
    });
  });
});

describe("runtime adapters", () => {
  it("verifies a Fetch-API Request (edge runtimes)", async () => {
    const verifier = makeVerifier(happyData);
    const { headers, body } = signedRequest(agent);
    const request = new Request(TARGET, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body
    });

    const verified = await verifier.verifyFetch(request);
    expect(verified).toEqual({
      agentId: agent.id,
      actor: agent.id,
      delegated: false,
      abilities: null,
      satisfiedKey: encodeKeyRef(agent.currentKeys[0]!.publicKey),
      chain: null,
      actorKeyState: expect.objectContaining({ id: agent.id }),
      octets: new TextEncoder().encode(body)
    });
  });

  it("attaches req.verifiedAgent through the Express-style middleware", async () => {
    const verifier = makeVerifier(happyData);
    const { headers, body } = signedRequest(agent);

    const req = {
      method: "POST",
      protocol: "https",
      originalUrl: "/quote",
      headers: { ...headers, host: "api.example.com" } as Record<string, string>,
      // A `Buffer`, exactly what `express.raw({ type: "*/*" })` leaves on `req.body`. It is a
      // `Uint8Array`, so the adapter forwards it with no copy and no decode.
      body: Buffer.from(body, "utf8"),
      get(name: string) {
        return this.headers[name.toLowerCase()];
      },
      verifiedAgent: undefined
    };
    let nextCalled = false;
    let statusCode: number | undefined;

    await verifier.middleware()(
      req,
      {
        status(code: number) {
          statusCode = code;
          return { json: () => undefined };
        }
      },
      () => {
        nextCalled = true;
      }
    );

    expect(nextCalled).toBe(true);
    expect(statusCode).toBeUndefined();
    expect(req.verifiedAgent).toEqual({
      agentId: agent.id,
      actor: agent.id,
      delegated: false,
      abilities: null,
      satisfiedKey: encodeKeyRef(agent.currentKeys[0]!.publicKey),
      chain: null,
      actorKeyState: expect.objectContaining({ id: agent.id })
    });
  });

  it("ends 401 through the middleware when verification fails", async () => {
    const verifier = makeVerifier(happyData);
    const req = {
      method: "POST",
      protocol: "https",
      originalUrl: "/quote",
      headers: { host: "api.example.com" } as Record<string, string>,
      body: new TextEncoder().encode("{}"),
      get(name: string) {
        return this.headers[name.toLowerCase()];
      }
    };
    let responded: unknown;
    let statusCode: number | undefined;

    await verifier.middleware()(
      req,
      {
        status(code: number) {
          statusCode = code;
          return {
            json: (payload: unknown) => {
              responded = payload;
              return undefined;
            }
          };
        }
      },
      () => {
        throw new Error("next() must not be called on a rejected request");
      }
    );

    expect(statusCode).toBe(401);
    expect(responded).toEqual({ error: "unauthorized_agent", reason: "missing_signature" });
  });

  it("exposes VerifyError with a 401 status for custom handlers", () => {
    const error = new VerifyError("missing_signature");
    expect(error.status).toBe(401);
    expect(error.name).toBe("VerifyError");
  });

  it("distinguishes a capacity refusal from an auth failure for custom handlers", () => {
    // A handler that only knows VerifyError still catches this (so nothing breaks), but one
    // that reads `status` or checks the subclass can tell "retry later" from "you are not
    // authorized" — which is the difference between a client backing off and a client
    // giving up or pointlessly re-authenticating.
    const error = new VerifyCapacityError("nonce_capacity");
    expect(error).toBeInstanceOf(VerifyError);
    expect(error.status).toBe(503);
    expect(error.name).toBe("VerifyCapacityError");
  });

  it("re-exports the spec-009 ability cover rule for surfaces enforcing their own vocabulary", () => {
    // Covers: exact match and path-children, to any depth.
    expect(abilityCovers("ledger", "ledger")).toBe(true);
    expect(abilityCovers("ledger", "ledger/write")).toBe(true);
    expect(abilityCovers("ledger", "ledger/write/bulk")).toBe(true);

    // Does not cover: a sibling namespace that merely shares a string prefix — the
    // confusion a naive startsWith test would admit.
    expect(abilityCovers("ledger", "ledger-admin")).toBe(false);
    expect(abilityCovers("ledger", "ledger.admin")).toBe(false);
    expect(abilityCovers("ledger", "ledgers/write")).toBe(false);
    expect(abilityCovers("ledger", "")).toBe(false);

    // Nor does a narrower grant cover a wider requirement, in either direction.
    expect(abilityCovers("ledger/write", "ledger")).toBe(false);
    expect(abilityCovers("ledger/write", "ledger/read")).toBe(false);
  });
});

/**
 * One allowance for a whole `verify()` call.
 *
 * `verify()` runs several verifications — the actor's key-state replay, a presented grant
 * chain, a represents chain — and each of them used to build its own ceiling from the view, so
 * the documented per-request bound was really a per-call one. These assertions exist because
 * every mutation that deletes the shared budget passed the suite before them.
 */
describe("the verification call's shared allowance", () => {
  // Twelve-event logs, so each stage costs a countable amount rather than one verification.
  function longLived() {
    let a = agent;
    let o = org;
    for (let index = 0; index < 11; index += 1) {
      a = rotateIdentity(a);
      o = rotateIdentity(o);
    }
    const edge = signRecord(
      {
        id: "rel-shared-budget",
        subjectId: a.id,
        predicate: "represents",
        objectId: o.id,
        issuedBy: o.id,
        issuedAt: ISSUED_AT
      },
      o.currentKeys[0]!.secretKey
    ) as Relationship;
    return {
      a,
      o,
      data: {
        logs: { [a.id]: a.log, [o.id]: o.log },
        relationships: { [a.id]: [edge] }
      } satisfies DiscoveryData
    };
  }

  // Measured: the actor replay costs 12, the RFC 9421 signature costs one, and the represents
  // path costs 25 (agent replay 12, then issuer replay plus relationship check 13). The actor's
  // current KeyState is deliberately returned for envelope reuse; the resolver memo stores the
  // full historical signer-state sequence, so these unlike values do not alias.
  const COMPOSED = 38;
  // Above every individual stage and below their sum. That gap is what discriminates: with a
  // per-call ceiling each stage fits comfortably and the request succeeds; with one shared
  // allowance it cannot, because the stages are spending the same 30.
  const ABOVE_EVERY_STAGE_BELOW_THE_SUM = 30;

  it("covers actor replay and the represents chain from one ceiling", async () => {
    const { a, o, data } = longLived();

    const funded = makeVerifier(data, {
      requireRepresents: o.id,
      maxSignatureVerifications: COMPOSED
    });
    await expect(funded.verify(signedRequest(a))).resolves.toMatchObject({ agentId: a.id });

    // One verification short of the composed cost, the request is refused.
    const short = makeVerifier(data, {
      requireRepresents: o.id,
      maxSignatureVerifications: COMPOSED - 1
    });
    await expect(short.verify(signedRequest(a))).rejects.toMatchObject({
      reason: expect.stringMatching(/_too_expensive$/)
    });
  }, 30_000);

  it("refuses a ceiling that every stage fits but their sum does not", async () => {
    const { a, o, data } = longLived();
    expect(ABOVE_EVERY_STAGE_BELOW_THE_SUM).toBeLessThan(COMPOSED);

    // THE assertion of this file. A verifier that builds a fresh allowance per stage sees 30
    // three times over and admits this request; one that shares a single 30 cannot. Every way
    // of removing the sharing — `verify()` not minting a budget, `getKeyState` ignoring the
    // one it is handed, `budgetFor` ignoring a supplied budget, `verifyRepresentsChain` not
    // threading it — makes this pass, which is exactly what it must not do.
    const verifier = makeVerifier(data, {
      requireRepresents: o.id,
      maxSignatureVerifications: ABOVE_EVERY_STAGE_BELOW_THE_SUM
    });
    await expect(verifier.verify(signedRequest(a))).rejects.toMatchObject({
      reason: expect.stringMatching(/_too_expensive$/)
    });
  }, 30_000);

  it("reports a grant-chain cost refusal as capacity too", async () => {
    // The third of the three places a cost refusal can surface, and the one that was
    // unpinned: reverting `asVerifyFailure` on the chain path to a plain `VerifyError` left
    // every other test green. A delegated caller presenting a perfectly good chain must not be
    // told 401 because this verifier declined to spend enough to read it.
    let user = createIdentity({ currentSeed: seed(41), nextSeed: seed(42) });
    for (let index = 0; index < 11; index += 1) {
      user = rotateIdentity(user);
    }
    const verifierId = createIdentity({ currentSeed: seed(43), nextSeed: seed(44) }).id;
    const sessionKey = generateKeyPair(seed(45));
    const sessionRef = encodeKeyRef(sessionKey.publicKey);
    const chain = [
      signThresholdRecord(
        {
          subjectId: user.id,
          issuerId: user.id,
          audienceId: sessionRef,
          abilities: ["msg/send"],
          caveats: { aud: [verifierId] },
          anchor: keyLogAnchor(user.log),
          proof: null,
          issuedAt: ISSUED_AT,
          expiresAt: new Date(NOW.getTime() + 19 * 86_400_000).toISOString()
        },
        [user.currentKeys[0]!.secretKey]
      ) as Grant
    ];
    const body = '{"want":"quote"}';
    const request = {
      method: "POST",
      url: TARGET,
      headers: {
        ...signRequest({
          method: "POST",
          url: TARGET,
          body,
          keyId: sessionRef,
          secretKey: sessionKey.secretKey,
          created: NOW_SECONDS,
          grants: chain
        })
      },
      body
    };

    const verifier = makeVerifier(
      { logs: { [user.id]: user.log } },
      { verifierId, maxSignatureVerifications: 4 }
    );

    await expect(verifier.verify(request)).rejects.toMatchObject({
      name: "VerifyCapacityError",
      status: 503,
      reason: expect.stringMatching(/_too_expensive$/)
    });
  }, 30_000);

  it("reports running out of allowance as capacity, never as an auth failure", async () => {
    const { a, o, data } = longLived();
    // A cost refusal means "this verifier declined to spend enough to judge you", not "your
    // credentials are wrong". A 401 would send a caller with a perfectly good chain to
    // re-present it forever, and would land in an auth-failure metric.
    const verifier = makeVerifier(data, { requireRepresents: o.id, maxSignatureVerifications: 4 });
    await expect(verifier.verify(signedRequest(a))).rejects.toMatchObject({
      name: "VerifyCapacityError",
      status: 503,
      reason: "agent_key_log_too_expensive"
    });
  }, 30_000);
});

/**
 * WHICH cost reason a delegated `verify()` refuses with, pinned because the answer depends on
 * which stage spends the last unit of the shared allowance.
 *
 * Both are cost refusals and both reach the same answer at every surface, so nothing about
 * authorization turns on this. The reason string is a diagnostic, and a comment that names the
 * wrong one sends an operator to look at the wrong stage.
 *
 * The mechanism, and why it is not arbitrary: `verify()` resolves a PARTICIPANT keyid's own key
 * state BEFORE it verifies the chain, off the same allowance. That first replay shifts where the
 * allowance runs out — into a signature search rather than into the next link's replay — so the
 * same chain, the same logs and the same ceiling produce different reasons for the two keyid
 * shapes. Sized here with short logs and an explicit ceiling so the boundary is arithmetic
 * rather than a coincidence of the default: each identity's log is one event over one key, so a
 * replay costs exactly 1.
 */
describe("a delegated verify() refused on cost names the stage that ran out", () => {
  const issuer = createIdentity({ currentSeed: seed(40), nextSeed: seed(41) });
  const leafParticipant = createIdentity({ currentSeed: seed(42), nextSeed: seed(43) });
  const session = generateKeyPair(seed(44));
  const sessionKeyRef = encodeKeyRef(session.publicKey);

  function rootFor(audienceId: string, withAud: boolean): Grant {
    return signThresholdRecord(
      {
        subjectId: issuer.id,
        issuerId: issuer.id,
        audienceId,
        abilities: ["quote"],
        caveats: withAud ? { aud: [org.id] } : {},
        anchor: keyLogAnchor(issuer.log),
        proof: null,
        issuedAt: ISSUED_AT,
        expiresAt: new Date(NOW.getTime() + 86_400_000).toISOString()
      },
      [issuer.currentKeys[0]!.secretKey]
    ) as Grant;
  }

  function request(keyId: string, secretKey: Uint8Array, grants: Grant[]) {
    const body = '{"want":"quote"}';
    return {
      method: "POST",
      url: TARGET,
      headers: signRequest({
        method: "POST",
        url: TARGET,
        body,
        keyId,
        secretKey,
        created: NOW_SECONDS,
        grants
      }),
      body
    };
  }

  async function reasonOf(promise: Promise<unknown>): Promise<string> {
    try {
      await promise;
      return "<accepted>";
    } catch (error) {
      return (error as { reason?: string }).reason ?? "<no reason>";
    }
  }

  /**
   * WATCHED TO FAIL: raise `maxSignatureVerifications` to 3 in this case. Three verifications are
   * enough for the RFC 9421 check, this short log's replay and its link signature, so the request is ACCEPTED and
   * this reads `<accepted>` — which is the point: the reason is decided by where the allowance
   * runs out, and moving the boundary by one verification changes the answer.
   */
  it("names the key log when the allowance runs out in a link replay (session-KeyRef keyid)", async () => {
    const chain = [rootFor(sessionKeyRef, true)];
    const verifier = makeVerifier(
      { logs: { [issuer.id]: issuer.log } },
      { verifierId: org.id, maxSignatureVerifications: 1 }
    );
    expect(await reasonOf(verifier.verify(request(sessionKeyRef, session.secretKey, chain)))).toBe(
      "grant_issuer_key_log_too_expensive"
    );
  });

  /**
   * WATCHED TO FAIL: drop `maxSignatureVerifications` to 0. The actor replay then exhausts
   * first and this reads `agent_key_log_too_expensive` — a different stage again, and the one
   * that proves the ordering claim above is load-bearing rather than decorative.
   */
  it("names the signature check when a participant keyid's own replay moved the boundary", async () => {
    // The actor's replay costs 1 and runs first, so an allowance of 1 is spent before the chain
    // starts — leaving the link's own replay to succeed on... nothing. The exhaustion therefore
    // lands inside `verifyGrantChain`'s signature stage rather than in its replay stage.
    const chain = [rootFor(leafParticipant.id, false)];
    const verifier = makeVerifier(
      {
        logs: { [issuer.id]: issuer.log, [leafParticipant.id]: leafParticipant.log }
      },
      { verifierId: org.id, maxSignatureVerifications: 3 }
    );
    expect(
      await reasonOf(
        verifier.verify(
          request(leafParticipant.id, leafParticipant.currentKeys[0]!.secretKey, chain)
        )
      )
    ).toBe("grant_signature_check_too_expensive");
  });
});

type WideVerificationIdentity = {
  id: string;
  log: KeyEvent[];
  states: KeyPair[][];
};

/** Generated 1-of-K identity whose matching signer is last in every state. */
function wideVerificationIdentity(events: number, width: number): WideVerificationIdentity {
  const states = Array.from({ length: events + 1 }, () =>
    Array.from({ length: width }, () => generateKeyPair())
  );
  const refs = (pairs: KeyPair[]) => pairs.map((pair) => encodeKeyRef(pair.publicKey));
  const signEvent = (unsigned: Omit<KeyEvent, "signature">, signer: KeyPair): KeyEvent => ({
    ...unsigned,
    signature: [encodeSignature(sign(canonicalBytes(unsigned), signer.secretKey))]
  });
  const establishment = {
    seq: "0",
    kind: "icp" as const,
    keys: refs(states[0]!),
    threshold: "1",
    next: commitToKeyState(refs(states[1]!), "1")
  };
  const id = deriveParticipantId(establishment);
  const log: KeyEvent[] = [
    signEvent({ ...establishment, id, prior: null }, states[0]![width - 1]!)
  ];
  for (let index = 1; index < events; index += 1) {
    log.push(
      signEvent(
        {
          id,
          seq: String(index),
          prior: eventDigest(log[index - 1]!),
          kind: "rot",
          keys: refs(states[index]!),
          threshold: "1",
          next: commitToKeyState(refs(states[index + 1]!), "1")
        },
        states[index]![width - 1]!
      )
    );
  }
  return { id, log, states: states.slice(0, events) };
}

describe("the 13A verifier default against generated honest and hostile compositions", () => {
  const E = MAX_KEY_LOG_EVENTS;
  const K = MAX_KEY_EVENT_KEYS;
  const L = MAX_GRANT_CHAIN_LINKS;
  const A = E * K;
  const issuers = Array.from({ length: L }, () => wideVerificationIdentity(E, K));
  const agent = issuers[L - 1]!;
  const actor = wideVerificationIdentity(E, K);
  const organization = wideVerificationIdentity(E, K);
  const stranger = generateKeyPair();

  const currentPair = (identity: WideVerificationIdentity) =>
    identity.states[identity.states.length - 1]![K - 1]!;
  const inceptionPair = (identity: WideVerificationIdentity) => identity.states[0]![K - 1]!;

  const chain: Grant[] = [];
  let proof: string | null = null;
  for (let index = L - 1; index >= 0; index -= 1) {
    const link = signThresholdRecord(
      {
        subjectId: agent.id,
        issuerId: issuers[index]!.id,
        audienceId: index === 0 ? actor.id : issuers[index - 1]!.id,
        abilities: ["quote"],
        caveats: {},
        // Signed under the issuer's INCEPTION state, so spec 016's anchor names that event.
        anchor: eventDigest(issuers[index]!.log[0]!),
        proof,
        issuedAt: ISSUED_AT
      },
      [inceptionPair(issuers[index]!).secretKey]
    ) as Grant;
    proof = canonicalDigest(link);
    chain.unshift(link);
  }

  const edge = signRecord(
    {
      id: "rel-generated-budget",
      subjectId: agent.id,
      predicate: "represents",
      objectId: organization.id,
      issuedBy: organization.id,
      issuedAt: ISSUED_AT
    },
    inceptionPair(organization).secretKey
  ) as Relationship;

  const logs = Object.fromEntries(
    [actor, organization, ...issuers].map((identity) => [identity.id, identity.log])
  );
  const request = () => {
    const body = '{"want":"generated-budget"}';
    const headers = signRequest({
      method: "POST",
      url: TARGET,
      body,
      keyId: actor.id,
      secretKey: currentPair(actor).secretKey,
      created: NOW_SECONDS,
      grants: chain
    });
    return { method: "POST", url: TARGET, headers: { ...headers }, body };
  };
  /**
   * Every identity in this fixture, so a revocation can be anchored (spec 016) to the state its
   * signer belongs to — the inception state, which is where every signature here is made.
   */
  const identityById = new Map(
    [actor, organization, ...issuers].map((identity) => [identity.id, identity])
  );

  const revocationOf = (digest: string, issuerId: string, secretKey: Uint8Array): Revocation =>
    signThresholdRecord(
      {
        revokes: digest,
        issuerId,
        // The inception event of the named issuer's own log. A candidate anchored anywhere else
        // would be skipped before any curve work, and these fixtures exist to measure work.
        anchor: eventDigest(identityById.get(issuerId)!.log[0]!),
        revokedAt: ISSUED_AT
      },
      [secretKey]
    ) as Revocation;

  function verifier(maxSignatureVerifications: number, revocations: Record<string, Revocation[]>) {
    return makeVerifier(
      {
        logs,
        relationships: { [agent.id]: [edge] },
        revocations
      },
      { requireRepresents: organization.id, maxSignatureVerifications }
    );
  }

  it("measures the memoized full honest success at 7A + 5K", async () => {
    // The composition, term by term, at `E = MAX_KEY_LOG_EVENTS`, `K = MAX_KEY_EVENT_KEYS`,
    // `L = MAX_GRANT_CHAIN_LINKS`, `A = E * K` (one full-length 1-of-K replay):
    //
    //   7A  seven replays — the actor, the four chain issuers, the organization, and the
    //       agent's own — each memoized, so a distinct log is replayed once per request
    //   5K  five record checks — four anchored chain links and the represents edge
    //
    // It was `11A + K` before spec 016, and the whole of the difference is the four chain
    // links: each was offered to every state its issuer's log had ever committed (`A` apiece,
    // since these fixtures sign under the INCEPTION state and the search ran newest-first), and
    // each now names the one state it is judged against (`K`). The replays are untouched — they
    // are what a verifier pays to resolve an issuer at all — and they now dominate the request
    // so completely that the record checks are under one percent of it.
    const exact = 7 * A + 5 * K;
    await expect(verifier(exact, {}).verify(request())).resolves.toMatchObject({
      agentId: agent.id,
      delegated: true
    });
    await expect(verifier(exact - 1, {}).verify(request())).rejects.toMatchObject({
      name: "VerifyCapacityError",
      status: 503
    });
  }, 300_000);

  it("reaches a late genuine relationship revocation at exactly 7A + 6K", async () => {
    // One more `K` than the honest success: the genuine revocation candidate is anchored to the
    // organization's inception state and costs one walk against it. Before 016 it cost `A` — the
    // full history search — which is why this figure was `12A + K`.
    const revocation = revocationOf(
      canonicalDigest(edge),
      organization.id,
      inceptionPair(organization).secretKey
    );
    expect(DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS).toBe(13 * A);
    await expect(
      verifier(DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS, {
        [revocation.revokes]: [revocation]
      }).verify(request())
    ).rejects.toMatchObject({
      name: "VerifyError",
      status: 401,
      reason: "represents_chain_unverified"
    });
    const exact = 7 * A + 6 * K;
    await expect(
      verifier(exact - 1, {
        [revocation.revokes]: [revocation]
      }).verify(request())
    ).rejects.toMatchObject({ name: "VerifyCapacityError", status: 503 });
  }, 300_000);

  it("does not let an 18A outer request widen the operation past its own ceiling", async () => {
    // A hostile view answering every lookup with conforming-count candidates signed by a key in
    // nobody's log, and anchored to real key events so each one reaches the walk rather than
    // being skipped for free.
    const revocations: Record<string, Revocation[]> = {};
    for (let index = 0; index < chain.length; index += 1) {
      const digest = canonicalDigest(chain[index]!);
      revocations[digest] = chain
        .slice(index)
        .slice(0, 2)
        .map((link) => revocationOf(digest, link.issuerId, stranger.secretKey));
    }
    const edgeDigest = canonicalDigest(edge);
    revocations[edgeDigest] = [revocationOf(edgeDigest, organization.id, stranger.secretKey)];

    // The whole hostile composition now costs `7A + 13K` — the same seven replays, plus a walk
    // for each of the nine decoys and the five honest record checks — so it fits inside the 13A
    // default with room to spare, where before 016 it exhausted it. The bound has stopped biting
    // on this shape, and that is spec 016's effect rather than a weakening: the decoys are still
    // checked, and still fail.
    const hostileCost = 7 * A + 13 * K;
    await expect(
      verifier(DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS, revocations).verify(request())
    ).resolves.toMatchObject({ agentId: agent.id });
    await expect(verifier(hostileCost, revocations).verify(request())).resolves.toMatchObject({
      agentId: agent.id
    });

    // The property this test exists for, unchanged: a request-wide allowance LARGER than the
    // verifier's per-operation ceiling does not widen the operation. With the operation capped
    // below what the hostile composition costs, the tick is refused for capacity even though the
    // request offered 18A — and the outer budget shows exactly the operation's own ceiling
    // spent, not a verification more.
    const operationCeiling = 7 * A;
    expect(operationCeiling).toBeLessThan(hostileCost);
    const bounded = verifier(operationCeiling, revocations);
    const context = bounded.beginRequest({ maxSignatureVerifications: 18 * A });
    await expect(bounded.verify(request(), context)).rejects.toMatchObject({
      name: "VerifyCapacityError",
      status: 503
    });
    expect(context.budget.remaining).toBe(18 * A - operationCeiling);
  }, 300_000);
});

/**
 * Security review 2026-08, finding 5 — "signed bytes are not the delivered bytes".
 *
 * The RFC 9530 digest the spec 004 signature covers is over the CONTENT OCTETS. Both adapters
 * used to decode the body to text before digesting it (`Request.text()` on the Fetch path,
 * `TextDecoder.decode` on the Express path), and UTF-8 decoding is not injective: every
 * malformed sequence becomes U+FFFD rather than an error. So the three octets `EF BF BD` — a
 * body that legitimately contains U+FFFD — and the single octet `FF` reached the verifier as
 * the same string. One signature covered both, and the application was handed whichever bytes
 * actually arrived.
 *
 * These tests run that substitution through each adapter. WATCHED TO FAIL against the old
 * behaviour — restored by making `contentDigest` re-encode a decoded copy of its input — both
 * "refuses" cases verify successfully. The binary and byte-identical cases pass either way and
 * are not claimed to catch that mutation: they pin that the fix costs nothing legitimate, and
 * the binary ones could not be expressed at all before, since `InboundRequest.body` was a
 * `string`.
 */
describe("delivered bytes, not decoded text (finding 5)", () => {
  /** `{"note":"<U+FFFD>"}` with U+FFFD correctly encoded as EF BF BD. What the sender signs. */
  const SIGNED_BODY = new TextEncoder().encode('{"note":"�"}');
  /** The same delivery with those three octets replaced by the single invalid octet FF. */
  const SUBSTITUTED_BODY = new Uint8Array([
    ...SIGNED_BODY.subarray(0, 9),
    0xff,
    ...SIGNED_BODY.subarray(12)
  ]);
  /** Content no decoder can round-trip: every byte value once. */
  const BINARY_BODY = new Uint8Array(Array.from({ length: 256 }, (_unused, index) => index));

  const signedBytes = (body: Uint8Array<ArrayBuffer>) => ({
    headers: signRequest({
      method: "POST",
      url: TARGET,
      body,
      keyId: agent.id,
      secretKey: agent.currentKeys[0]!.secretKey,
      created: NOW_SECONDS
    }),
    body
  });

  it("the two deliveries really are indistinguishable once decoded", () => {
    // The premise the rest of this block rests on. If this ever stops holding, the tests
    // below prove nothing and must be rebuilt rather than deleted.
    const decoder = new TextDecoder();
    expect(decoder.decode(SUBSTITUTED_BODY)).toBe(decoder.decode(SIGNED_BODY));
    expect(SUBSTITUTED_BODY).not.toEqual(SIGNED_BODY);
  });

  describe("the Fetch-API adapter", () => {
    const fetchRequest = (headers: Record<string, string>, body: Uint8Array<ArrayBuffer>) =>
      new Request(TARGET, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body
      });

    it("refuses a body substituted for one that decodes the same way", async () => {
      const { headers } = signedBytes(SIGNED_BODY);
      await expect(
        makeVerifier(happyData).verifyFetch(fetchRequest(headers, SUBSTITUTED_BODY))
      ).rejects.toMatchObject({ reason: "content_digest_mismatch", status: 401 });
    });

    it("accepts the byte-identical delivery", async () => {
      const { headers, body } = signedBytes(SIGNED_BODY);
      await expect(
        makeVerifier(happyData).verifyFetch(fetchRequest(headers, body))
      ).resolves.toMatchObject({ agentId: agent.id });
    });

    it("round-trips a binary body", async () => {
      const { headers, body } = signedBytes(BINARY_BODY);
      await expect(
        makeVerifier(happyData).verifyFetch(fetchRequest(headers, body))
      ).resolves.toMatchObject({ agentId: agent.id });
    });

    it("hands back the verified octets, so no consumer has to re-read the request", async () => {
      // The adapter reads bytes to keep the digest honest; that guarantee dies at the return
      // statement unless the caller can get those same bytes. A consumer left to re-read the
      // request reaches for `.text()` or `.json()`, decodes with U+FFFD replacement, and
      // rebuilds finding 5 inside its own code — so the octets come back with the agent.
      const { headers, body } = signedBytes(BINARY_BODY);
      const request = fetchRequest(headers, body);
      const verified = await makeVerifier(happyData).verifyFetch(request);

      expect(verified.octets).toEqual(BINARY_BODY);
      // And the re-read a consumer would otherwise have done does NOT give these bytes: the
      // lossy decode is right there, one convenient method call away.
      expect(new TextEncoder().encode(await request.text())).not.toEqual(verified.octets);
    });

    it("returns empty octets for a bodiless signed GET", async () => {
      const headers = signRequest({
        method: "GET",
        url: TARGET,
        body: new Uint8Array(0),
        keyId: agent.id,
        secretKey: agent.currentKeys[0]!.secretKey,
        created: NOW_SECONDS
      });
      const verified = await makeVerifier(happyData).verifyFetch(
        new Request(TARGET, { method: "GET", headers })
      );
      expect(verified.octets).toEqual(new Uint8Array(0));
    });
  });

  describe("the Express-style adapter", () => {
    const run = async (body: unknown, headers: Record<string, string>) => {
      const req = {
        method: "POST",
        protocol: "https",
        originalUrl: "/quote",
        headers: { ...headers, host: "api.example.com" } as Record<string, string>,
        body,
        get(name: string) {
          return this.headers[name.toLowerCase()];
        },
        verifiedAgent: undefined
      };
      let responded: { error?: string; reason?: string } | undefined;
      let statusCode: number | undefined;
      let nextCalled = false;
      await makeVerifier(happyData).middleware()(
        req,
        {
          status(code: number) {
            statusCode = code;
            return {
              json: (payload: unknown) => {
                responded = payload as { error?: string; reason?: string };
                return undefined;
              }
            };
          }
        },
        () => {
          nextCalled = true;
        }
      );
      return { statusCode, responded, nextCalled, req };
    };

    it("refuses a body substituted for one that decodes the same way", async () => {
      const { headers } = signedBytes(SIGNED_BODY);
      // `express.raw` hands the middleware a Buffer, so that is what the substitution
      // arrives as.
      const result = await run(Buffer.from(SUBSTITUTED_BODY), headers);
      expect(result.nextCalled).toBe(false);
      expect(result.statusCode).toBe(401);
      expect(result.responded).toEqual({
        error: "unauthorized_agent",
        reason: "content_digest_mismatch"
      });
    });

    it("accepts the byte-identical delivery", async () => {
      const { headers, body } = signedBytes(SIGNED_BODY);
      const result = await run(Buffer.from(body), headers);
      expect(result.nextCalled).toBe(true);
      expect(result.req.verifiedAgent).toMatchObject({ agentId: agent.id });
    });

    it("round-trips a binary body", async () => {
      const { headers, body } = signedBytes(BINARY_BODY);
      const result = await run(Buffer.from(body), headers);
      expect(result.nextCalled).toBe(true);
      expect(result.req.verifiedAgent).toMatchObject({ agentId: agent.id });
    });

    it("refuses a decoded string body outright, whatever it says", async () => {
      // The migration this fix forces: `express.text` decodes before the middleware sees the
      // request, so the adapter would be vouching for bytes it never saw. A correctly signed
      // request mounted that way is refused rather than quietly accepted — the string here
      // IS the exact text the sender signed, and it still does not pass.
      const text = '{"want":"quote"}';
      const headers = signRequest({
        method: "POST",
        url: TARGET,
        body: text,
        keyId: agent.id,
        secretKey: agent.currentKeys[0]!.secretKey,
        created: NOW_SECONDS
      });
      const result = await run(text, headers);
      expect(result.nextCalled).toBe(false);
      expect(result.statusCode).toBe(401);
      expect(result.responded).toEqual({ error: "unauthorized_agent", reason: "body_not_raw" });
    });
  });
});
