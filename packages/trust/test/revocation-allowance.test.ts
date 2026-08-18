/**
 * The revocation search's sub-allowance — the term every cost model in this repo used to omit.
 *
 * `verifyGrantChain` calls `findRevocation` ONCE PER LINK, with the authorized revokers of that
 * link and every link above it, so a chain opens `L(L+1)/2` candidate slots rather than `L`.
 * Each slot was an unbounded `states x keys x signatures` search over records an untrusted view
 * chose to send, which is why a conforming chain cost multiples of what its callers believed.
 *
 * Spec 015 collapsed the per-slot search to `states x keys` (the greedy walk spends at most one
 * verification per listed key whatever the record's signature count, and a count that is not
 * exactly the threshold is refused on its LENGTH before any curve work), and spec 016 has since
 * removed the `states` factor too: an anchored candidate names the ONE key state it is judged
 * against, so a slot costs at most `K = MAX_KEY_EVENT_KEYS`. The slot COUNT is untouched, so the
 * composition is still the view's to choose and the sub-allowance is still what bounds it — what
 * moved is the price of a slot, and with it the allowance, re-derived here as `2K`.
 *
 * The fixtures still run at `MAX_KEY_LOG_EVENTS`, but for a different reason: the log length is
 * now what the REPLAY costs, not what a candidate costs, and the replay is what a hostile answer
 * still buys per issuer it names.
 *
 * Every expectation here is an expression in the IMPORTED protocol constants and in the log
 * length the fixture actually builds. Writing the products as literals would assert nothing:
 * the point of these tests is to fail if a constant moves and the derivation does not.
 */
import {
  canonicalBytes,
  canonicalDigest,
  commitToKeyState,
  deriveParticipantId,
  encodeKeyRef,
  encodeSignature,
  eventDigest,
  generateKeyPair,
  sign,
  signThresholdRecord,
  type KeyPair
} from "@kinnet/crypto";
import {
  MAX_GRANT_CHAIN_LINKS,
  MAX_KEY_EVENT_KEYS,
  MAX_KEY_LOG_EVENTS,
  MAX_RECORD_SIGNATURES,
  type Grant,
  type KeyEvent,
  type ParticipantId,
  type Revocation
} from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  MAX_REVOCATION_CANDIDATE_VERIFICATIONS,
  verifyGrantChain,
  type TrustView,
  type VerificationBudget
} from "../src/index.js";

const K = MAX_KEY_EVENT_KEYS;
const L = MAX_GRANT_CHAIN_LINKS;
const S = MAX_RECORD_SIGNATURES;
const R = MAX_REVOCATION_CANDIDATE_VERIFICATIONS;

/** A well-formed multihash that is the digest of no key event of any log (spec 016). */
const NO_SUCH_EVENT = canonicalDigest({ anchor: "no key event of any log" });

const NOW = new Date("2026-06-12T00:00:00.000Z");
const ISSUED_AT = new Date(NOW.getTime() - 11 * 86_400_000).toISOString();

/** Deterministic, and distinct across every key this file mints (256 fills are not enough). */
let seedCounter = 0;
function nextSeed(): Uint8Array {
  const bytes = new Uint8Array(32);
  seedCounter += 1;
  new DataView(bytes.buffer).setUint32(0, seedCounter);
  return bytes;
}

type WideIdentity = { id: ParticipantId; log: KeyEvent[]; states: KeyPair[][] };

/**
 * A conforming 1-of-K identity — `threshold: "1"` over `MAX_KEY_EVENT_KEYS` keys, which is
 * schema-valid, publishes to discovery and authenticates. The real signing key is LAST in each
 * event, the honest worst case: nothing about key order is normative and no verifier may assume
 * a cheap one. A wide-identity helper, kept local because a test helper cannot be imported
 * across package boundaries.
 */
function wideIdentity(events: number): WideIdentity {
  const refs = (keyPairs: KeyPair[]): string[] =>
    keyPairs.map((keyPair) => encodeKeyRef(keyPair.publicKey));
  const states = Array.from({ length: events + 1 }, () =>
    Array.from({ length: K }, () => generateKeyPair(nextSeed()))
  );
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
  const log: KeyEvent[] = [signEvent({ ...establishment, id, prior: null }, states[0]![K - 1]!)];
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
        states[index]![K - 1]!
      )
    );
  }
  return { id, log, states: states.slice(0, events) };
}

/** The honest worst case for one walk: the LAST key of the oldest state. */
const oldestKey = (identity: WideIdentity): KeyPair =>
  identity.states[0]![identity.states[0]!.length - 1]!;

/** Spec 016's anchor for the oldest state — the inception event these fixtures sign under. */
const oldestAnchor = (identity: WideIdentity): string => eventDigest(identity.log[0]!);

/**
 * A leaf-first chain of `L` links over `L + 1` identities, every link signed under — and, per
 * spec 016, ANCHORED to — its issuer's oldest state. Anchoring to the oldest rather than the tip
 * is a producer's prerogative (016 _Producer rules_: any state whose keys it still holds), and
 * it keeps these fixtures honest worst cases: the signing key is last in the state's key list,
 * so each link's walk spends the full `K`.
 */
function grantChain(identities: WideIdentity[]): Grant[] {
  const chain: Grant[] = [];
  let previous: Grant | null = null;
  for (let depth = 0; depth < L; depth += 1) {
    const issuer = identities[depth]!;
    const unsigned = {
      subjectId: identities[0]!.id,
      issuerId: issuer.id,
      audienceId: identities[depth + 1]!.id,
      abilities: ["msg"],
      caveats: {},
      anchor: oldestAnchor(issuer),
      proof: previous === null ? null : canonicalDigest(previous),
      issuedAt: ISSUED_AT
    };
    const signed = signThresholdRecord(unsigned, [oldestKey(issuer).secretKey]) as Grant;
    chain.push(signed);
    previous = signed;
  }
  return chain.reverse();
}

/**
 * A revocation candidate. `anchor` is required (spec 016) and is what decides whether the
 * candidate reaches curve work at all: an anchor naming a real event of the issuer's log costs
 * the walk, and one naming no event is skipped for free.
 */
function revocationOf(
  digest: string,
  issuerId: ParticipantId,
  secretKeys: Uint8Array[],
  anchor: string
) {
  return signThresholdRecord(
    { revokes: digest, issuerId, anchor, revokedAt: ISSUED_AT },
    secretKeys
  ) as Revocation;
}

function viewOf(
  identities: WideIdentity[],
  getRevocations: (digest: string, issuerIds: readonly string[]) => Revocation[]
): TrustView {
  const logs = new Map(identities.map((identity) => [identity.id, identity.log]));
  return {
    async getKeyLog(id) {
      return logs.get(id) ?? null;
    },
    async getRevocations(digest, issuerIds) {
      return getRevocations(digest, issuerIds);
    }
  };
}

/** Runs a chain verification on an allowance large enough never to bind, and reports the spend. */
async function meter(chain: Grant[], view: TrustView) {
  const ceiling = 100_000_000;
  const budget: VerificationBudget = { remaining: ceiling };
  const verdict = await verifyGrantChain(chain, view, { now: NOW, purpose: "request", budget });
  return { verdict, spent: ceiling - budget.remaining };
}

/**
 * Diagnostic backstop for every test in this file. These suites are CPU-bound — thousands of
 * Ed25519 verifications over maximal conforming fixtures — so how long one takes is a fact about
 * the machine and its load, not about the code under test. The former per-test values (120–240 s)
 * were sized to an unloaded workstation and tripped on loaded machines; a shared CI runner
 * splitting a few cores across the whole monorepo's suites is exactly that machine. This exists
 * only to stop a genuinely wedged run hanging forever — it must never decide a verdict, and a
 * failure that reads `Test timed out` means the worker was starved, not that the bound moved.
 */
const TEST_BACKSTOP_MS = 600_000;

describe("revocation candidate sub-allowance", () => {
  /**
   * The honest ceiling the sub-allowance is sized from, and the proof it cannot refuse it.
   *
   * Discovery signature-checks a revocation against its issuer's then-current key state before
   * storing it, so an honest candidate verifies and the loop returns on it. Spec 016 decides what
   * that costs: the candidate names ONE state and exactly that state is walked, so the honest
   * ceiling is `K` — one verification per listed key, and the fixture puts the signing key LAST
   * so the full `K` is spent. The log's length does not enter it, which is the whole of 016's
   * effect here: the same record cost `E * K` when it was offered to every state the log had
   * committed. Measured, not assumed.
   *
   * WATCHED TO FAIL: set `MAX_REVOCATION_CANDIDATE_VERIFICATIONS` to `MAX_KEY_EVENT_KEYS / 2` —
   * half the honest ceiling. The verdict turns from `grant_revoked` into
   * `grant_signature_check_too_expensive`, i.e. the bound starts refusing an honest revocation
   * check, which is the failure this test exists to catch.
   */
  it(
    "never refuses an honest revocation anchored to the oldest state of a full-length log",
    async () => {
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const chain = grantChain(identities);
      const leaf = chain[0]!;
      const leafIssuer = identities.find((identity) => identity.id === leaf.issuerId)!;
      const leafDigest = canonicalDigest(leaf);

      const view = viewOf(identities, (digest) =>
        digest === leafDigest
          ? [
              revocationOf(
                digest,
                leafIssuer.id,
                [oldestKey(leafIssuer).secretKey],
                oldestAnchor(leafIssuer)
              )
            ]
          : []
      );

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_revoked" });

      // The lookup itself: one replay (`E * K`) and one anchored link check (`K`) precede it.
      const beforeTheLookup = events * K + K;
      expect(spent - beforeTheLookup).toBe(K);
      // ...which is the honest ceiling, and the allowance clears it by exactly its headroom.
      expect(R).toBe(2 * K);
      expect(R / K).toBe(2);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * The second half of `R = 2K` is for an answer that makes the verifier pay a complete
   * conforming check before it reaches the genuine record. Both candidates carry the one-member
   * signature set these `threshold: "1"` issuers require, and both anchor to a real event of
   * their own issuer's log, so both reach the walk: the first member verifies under no listed
   * key, the second is the genuine issuer's last key in its oldest state. Each costs exactly `K`.
   *
   * WATCHED TO FAIL: subtract one from `MAX_REVOCATION_CANDIDATE_VERIFICATIONS`. The genuine
   * candidate then reaches its last key with no allowance remaining and the verdict changes from
   * `grant_revoked` to `grant_signature_check_too_expensive`. This is the exact boundary; the
   * one-candidate test above remains the control that `K` alone still clears.
   */
  it(
    "admits one full rejected check followed by one full genuine check at exactly 2K",
    async () => {
      const events = MAX_KEY_LOG_EVENTS;
      const A = events * K;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const chain = grantChain(identities);
      const leaf = chain[0]!;
      const leafIssuer = identities.find((identity) => identity.id === leaf.issuerId)!;
      const upstreamIssuer = identities.find((identity) => identity.id === chain[L - 1]!.issuerId)!;
      const leafDigest = canonicalDigest(leaf);
      const stranger = generateKeyPair(nextSeed());

      const view = viewOf(identities, (digest) =>
        digest === leafDigest
          ? [
              revocationOf(
                digest,
                upstreamIssuer.id,
                [stranger.secretKey],
                oldestAnchor(upstreamIssuer)
              ),
              revocationOf(
                digest,
                leafIssuer.id,
                [oldestKey(leafIssuer).secretKey],
                oldestAnchor(leafIssuer)
              )
            ]
          : []
      );

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_revoked" });
      expect(R).toBe(2 * K);
      // Two replays (the leaf issuer's and the upstream issuer's, the latter driven by the lookup
      // itself) and one anchored link check precede the two candidate checks. Removing those
      // isolates the sub-allowance, which the two candidates fill exactly.
      expect(spent - (2 * A + K)).toBe(R);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * THE SANDWICH. A ceiling above every individual stage and below their sum is the only shape
   * that catches "each call bounded, composition unbounded" — and composition is precisely what
   * was unbounded here, since the per-link lookups were each finite and their sum was not.
   *
   * WATCHED TO FAIL: drop `candidateAllowance` from the `signedAtAnchor` call in
   * `findRevocation`. Every candidate of every slot then completes, the leaf lookup pays `L * K`
   * instead of `R`, nothing is refused, and the verdict assertion below fails with
   * `valid: true`.
   */
  it(
    "bounds a hostile revocation answer to the closed form the callers can add up",
    async () => {
      // One candidate per REQUESTED issuer — the most a view may return without the oversized
      // answer being rejected outright — each carrying EXACTLY ONE signature, by a key in
      // nobody's log, and each ANCHORED to a real event of the issuer it names.
      //
      // Both of those choices are what makes the answer expensive, and both are inversions worth
      // stating. A candidate padded to `MAX_RECORD_SIGNATURES` is refused by S1's `m = t` length
      // check against these `threshold: "1"` issuers, before any curve work; and a candidate
      // whose anchor names no event of its issuer's log is skipped by 016's lookup, also before
      // any curve work. Padding and mis-anchoring are the CHEAP answers; the expensive one is a
      // candidate that conforms in count and names a real state, and whose members verify under
      // no listed key. Both cheap shapes are pinned below.
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const byId = new Map(identities.map((identity) => [identity.id, identity]));
      const chain = grantChain(identities);
      const stranger = generateKeyPair(nextSeed());

      let answers = 0;
      const view = viewOf(identities, (digest, issuerIds) => {
        answers += 1;
        return issuerIds.map((issuerId) =>
          revocationOf(
            digest,
            issuerId as ParticipantId,
            [stranger.secretKey],
            oldestAnchor(byId.get(issuerId as ParticipantId)!)
          )
        );
      });

      const { verdict, spent } = await meter(chain, view);

      // Fails closed: an exhausted lookup is a cost refusal, never "not revoked".
      expect(verdict).toEqual({ valid: false, reason: "grant_signature_check_too_expensive" });

      // BELOW their sum: the closed form beside `verifyGrantChain`. Neither `S` nor `E` is in the
      // record terms now — a link's own check costs `K` and a candidate's costs `K`, because the
      // walk is bounded by one state's key list and a non-conforming count never reaches it.
      const chainCeiling = L * (events * K) + L * K + L * R;
      expect(spent).toBeLessThanOrEqual(chainCeiling);
      // ...and below the term this bounds: the candidate slots a chain opens, unbounded by R.
      expect(spent).toBeLessThan(L * (events * K) + L * K + ((L * (L + 1)) / 2) * K);
      // ABOVE the individual stages: more than one lookup's allowance, so the assertion is not
      // passing because nothing ran.
      expect(spent).toBeGreaterThan(R);
      expect(answers).toBeGreaterThan(0);

      // The PADDING inversion, pinned rather than described: the same answer padded to
      // `MAX_RECORD_SIGNATURES` is refused on its length before any curve work, so every one of
      // the `L(L+1)/2` slots costs ZERO and the chain runs to completion.
      const padded = await meter(
        chain,
        viewOf(identities, (digest, issuerIds) =>
          issuerIds.map((issuerId) =>
            revocationOf(
              digest,
              issuerId as ParticipantId,
              Array.from({ length: S }, () => stranger.secretKey),
              oldestAnchor(byId.get(issuerId as ParticipantId)!)
            )
          )
        )
      );
      expect(padded.verdict.valid).toBe(true);
      // Nothing but the chain's own work is in it: `L` replays plus `L` anchored link checks, and
      // not one verification for any padded candidate. Equality, not a bound.
      expect(padded.spent).toBe(L * events * K + L * K);

      // The ANCHOR inversion, and it is new with 016. The same conforming-count candidates,
      // anchored to a digest no key log carries: each is skipped before any curve work, so the
      // hostile answer costs exactly what the padded one does.
      const unanchored = await meter(
        chain,
        viewOf(identities, (digest, issuerIds) =>
          issuerIds.map((issuerId) =>
            revocationOf(digest, issuerId as ParticipantId, [stranger.secretKey], NO_SUCH_EVENT)
          )
        )
      );
      expect(unanchored.verdict.valid).toBe(true);
      expect(unanchored.spent).toBe(L * events * K + L * K);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * The sub-allowance is PER LOOKUP and shared across that lookup's candidates. Minted per
   * CANDIDATE it would bound nothing: the cost would still scale with however many records the
   * view chose to send, which is the amplification it exists to remove.
   *
   * WATCHED TO FAIL: move the `candidateAllowance` object inside the `for (const candidate)` loop
   * in `findRevocation`. Each candidate then gets a fresh `2K`, which is twice what one costs, so
   * every slot completes, nothing is refused, and the verdict below turns `valid: true`.
   */
  it(
    "shares one allowance across a lookup's candidates rather than minting one each",
    async () => {
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const byId = new Map(identities.map((identity) => [identity.id, identity]));
      const chain = grantChain(identities);
      const stranger = generateKeyPair(nextSeed());
      const view = viewOf(identities, (digest, issuerIds) =>
        issuerIds.map((issuerId) =>
          revocationOf(
            digest,
            issuerId as ParticipantId,
            [stranger.secretKey],
            oldestAnchor(byId.get(issuerId as ParticipantId)!)
          )
        )
      );

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_signature_check_too_expensive" });
      // The refusal lands inside the LEAF's lookup, so everything spent up to it is: every replay
      // the chain can drive (the signer memo caps them at one per distinct issuer, and a lookup
      // asking about upstream issuers is what drives the ones the loop has not reached yet), the
      // leaf link's own anchored check, and ONE sub-allowance across all of that lookup's
      // candidates. Minted per candidate instead, the same lookup would spend one allowance per
      // requested issuer and blow straight through this.
      expect(spent).toBeLessThanOrEqual(L * (events * K) + K + R);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * Exhaustion may never read as "not revoked". A genuine revocation hidden behind enough decoys
   * must produce a cost refusal, not an authorization.
   *
   * WATCHED TO FAIL: replace the `signedAtAnchor(...)` call in `findRevocation` with one wrapped
   * in `try { ... } catch { continue; }`. The genuine revocation is then never CHECKED — its own
   * walk throws on the exhausted allowance and the throw is swallowed — the lookup returns null,
   * and the chain verifies `valid: true`. That is the silent downgrade of the one check that
   * withdraws authority.
   */
  it(
    "refuses rather than reporting not-revoked when decoys exhaust the allowance",
    async () => {
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const byId = new Map(identities.map((identity) => [identity.id, identity]));
      const chain = grantChain(identities);
      const leaf = chain[0]!;
      const leafIssuer = identities.find((identity) => identity.id === leaf.issuerId)!;
      const leafDigest = canonicalDigest(leaf);
      const stranger = generateKeyPair(nextSeed());

      const view = viewOf(identities, (digest, issuerIds) => {
        if (digest !== leafDigest) {
          return [];
        }
        // Decoys first, the genuine revocation last: a hostile host chooses the order. Each decoy
        // carries exactly one signature, matching these issuers' `threshold: "1"`, and anchors to
        // a real event of its own issuer's log — so it clears both of the free rejections and
        // costs the full `K`. The leaf has `L` authorized revokers, so `L - 1` decoys precede the
        // genuine record and the allowance of `2K` is gone before it is reached.
        const decoys = issuerIds
          .filter((issuerId) => issuerId !== leafIssuer.id)
          .map((issuerId) =>
            revocationOf(
              digest,
              issuerId as ParticipantId,
              [stranger.secretKey],
              oldestAnchor(byId.get(issuerId as ParticipantId)!)
            )
          );
        return [
          ...decoys,
          revocationOf(
            digest,
            leafIssuer.id,
            [oldestKey(leafIssuer).secretKey],
            oldestAnchor(leafIssuer)
          )
        ];
      });

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_signature_check_too_expensive" });
      expect(verdict.valid).toBe(false);
      // The genuine record is the last candidate and the allowance is gone by the decoy before
      // it, so the run stops one replay past the exhaustion: the replays the lookup drove, the
      // leaf's own anchored check, and the two decoy checks the sub-allowance paid for.
      expect(spent).toBe(L * (events * K) + K + R);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * The `too_expensive` branch inside `findRevocation` is REACHABLE, and a comment there used to
   * claim it was not. The authorized revokers for a link are the issuers of that link and every
   * link ABOVE it, and the chain is walked leaf first — so the leaf's lookup asks about issuers
   * whose logs no iteration has replayed yet, and the first replay of one of them happens inside
   * the lookup. That replay can exhaust the shared allowance like any other.
   *
   * WATCHED TO FAIL: change the `throw new VerificationBudgetExceeded(...)` in that branch to
   * `continue`. The lookup then answers null — "not revoked" — for an issuer it could not
   * resolve, and the reason this test reads turns into `grant_issuer_key_log_too_expensive`,
   * produced several links later when that issuer's own iteration finds the memo's cached
   * `too_expensive`. The chain still fails closed, but only because the MEMO happened to
   * remember, which is exactly the dependency `SignerStateCache`'s own doc says the refusal must
   * not have: delete the cache and the same shape reads as not-revoked.
   */
  it(
    "fails closed when the first replay of an upstream issuer happens inside the lookup",
    async () => {
      const events = 32;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const chain = grantChain(identities);
      const leaf = chain[0]!;
      const leafDigest = canonicalDigest(leaf);
      // The root's issuer — an UPSTREAM issuer whose log the leaf iteration has not touched.
      const upstream = identities.find((identity) => identity.id === chain[L - 1]!.issuerId)!;
      const stranger = generateKeyPair(nextSeed());

      const view = viewOf(identities, (digest) =>
        digest === leafDigest
          ? [revocationOf(digest, upstream.id, [stranger.secretKey], oldestAnchor(upstream))]
          : []
      );

      // Enough for the leaf's own replay and anchored link check and nothing like enough for a
      // second replay, which is what the lookup is about to drive.
      const budget: VerificationBudget = { remaining: events * K + K };
      const verdict = await verifyGrantChain(chain, view, { now: NOW, purpose: "request", budget });
      expect(verdict).toEqual({
        valid: false,
        reason: "grant_signature_check_too_expensive"
      });
    },
    TEST_BACKSTOP_MS
  );
});

/**
 * The chain-cost arithmetic itself, pinned.
 *
 * The closed form beside `verifyGrantChain` once had one product written two different ways
 * twelve lines apart, and nothing in the suite noticed. These measure the quantities the
 * derivation actually claims — under spec 016 a replay per distinct issuer plus `K` per record —
 * so the numbers in the prose cannot drift from the code without a red test.
 */
describe("the chain cost arithmetic", () => {
  /**
   * WATCHED TO FAIL: change the expectation to `L * (E * K) + L * K + 2 * K` — one honest
   * revocation check too many. It fails by exactly `K`.
   */
  it(
    "spends exactly L*E*K + L*K + K on a chain the view honestly reports revoked at the ROOT",
    async () => {
      // The ROOT link, so every link above it is verified in full before the lookup that finds
      // anything — this is the maximal honest chain, not an early exit.
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const chain = grantChain(identities);
      const root = chain[L - 1]!;
      const rootIssuer = identities.find((identity) => identity.id === root.issuerId)!;
      const rootDigest = canonicalDigest(root);

      const view = viewOf(identities, (digest) =>
        digest === rootDigest
          ? [
              revocationOf(
                digest,
                rootIssuer.id,
                [oldestKey(rootIssuer).secretKey],
                oldestAnchor(rootIssuer)
              )
            ]
          : []
      );

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_revoked" });
      expect(spent).toBe(L * (events * K) + L * K + K);
      // Spelled out, because this is the product the prose beside `verifyGrantChain` claims: the
      // replays dominate, and the record terms are `K` each rather than `E * K` each.
      expect(L * (events * K)).toBe(4096);
      expect(spent).toBe(4136);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * THE THIRD CASE. A candidate that parses, targets the right digest, comes from a requested
   * issuer and names a real key state but FAILS its signature check costs `K`, the lookup returns
   * null, and the chain CARRIES ON — so the rejection adds to the chain's cost instead of
   * replacing part of it, and the verdict is still `valid: true`. The revocation lookup and the
   * rest are NOT alternatives: reading them as "never both" understates the cost.
   *
   * WATCHED TO FAIL: assert `spent` equals the no-revocation cost `L * (E * K) + L * K`, which is
   * what "never both" implies. It fails by `L * K` = 32.
   */
  it(
    "adds K per link for a rejected candidate, and still returns valid",
    async () => {
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const chain = grantChain(identities);
      const digests = chain.map((link) => canonicalDigest(link));
      const byId = new Map(identities.map((identity) => [identity.id, identity]));
      const stranger = generateKeyPair(nextSeed());

      // One candidate per link, from that link's OWN issuer so it is a requested revoker, anchored
      // to a real event of that issuer's log so it reaches the walk, and signed by a key in
      // nobody's log so it can never verify. One candidate costs `K`, which is under the
      // sub-allowance — so this shape is not what R bounds, and R does not change it.
      const view = viewOf(identities, (digest) => {
        const index = digests.indexOf(digest);
        if (index < 0) {
          return [];
        }
        const issuerId = chain[index]!.issuerId as ParticipantId;
        return [
          revocationOf(digest, issuerId, [stranger.secretKey], oldestAnchor(byId.get(issuerId)!))
        ];
      });

      const { verdict, spent } = await meter(chain, view);
      expect(verdict.valid).toBe(true);
      expect(spent).toBe(L * (events * K) + L * K + L * K);
      expect(spent).toBeGreaterThan(L * (events * K) + L * K);
      // Each lookup stays inside the sub-allowance, which is why removing R would not change this
      // number by one verification. The bound is not what limits this shape.
      expect(K).toBeLessThan(R);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * WHAT SPEC 015 S4's REORDER COSTS, and the reason the cost is admissible.
   *
   * S4 forbids treating `digest(parent) == proof` as a verified link until the parent's own
   * signature set has been checked, so `verifyGrantChain`'s `proof` comparison moved out of the
   * structural pre-loop and into the per-link walk. A bad `proof` pointer used to be refused for
   * free — the comparison was the first thing the pre-loop did — and now the links beneath it
   * are signature-checked first. That is a real number on a PRE-AUTHENTICATION path, so it is
   * measured here rather than described beside the code.
   *
   * The argument the numbers below carry is not "the chain is capped, so the work is capped".
   * It is that the CEILING did not move: a `proof` pointer is a digest, so anyone can compute a
   * correct one without any key, and a chain with correct pointers and one bad signature already
   * made a verifier spend the full `L * 2E * K` before the reorder. The reorder raises the FLOOR
   * for one malformed shape and leaves the most an attacker can extract exactly where it was.
   *
   * The pre-change figures quoted in the comment beside `verifyGrantChain` (0, 0, and 8192) were
   * measured the only way they can be — by running these same three chains against the resolver
   * as of 6c31fdc^ — and cannot be asserted here, since that code is gone. Everything this test
   * asserts is measured against the code in the tree.
   *
   * WATCHED TO FAIL: move the `proof` comparison back into the structural pre-loop. The two
   * mismatch shapes then cost 0 and both `spent` assertions fail; their verdicts do not change,
   * which is the point — the reorder is a cost and ordering change, not a verdict change.
   */
  it(
    "costs a proof mismatch what a bad signature already cost, and no more",
    async () => {
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const honest = grantChain(identities);
      const view = viewOf(identities, () => []);
      const stranger = generateKeyPair(nextSeed());
      // A well-formed multihash that is no link of this chain: the pointer an attacker who wants
      // the digest comparison to fail supplies. It is re-SIGNED into the link below, not patched
      // in, so nothing but the pointer is wrong.
      const decoy = canonicalDigest({ decoy: "no link of this chain" });

      const issuerOf = (link: Grant): WideIdentity =>
        identities.find((identity) => identity.id === link.issuerId)!;
      /**
       * Re-issues a link with a different `proof`, signed afresh by its own issuer.
       * `signThresholdRecord` drops the old signature before signing, so the result is a properly
       * signed record and not a patched one — only the pointer differs.
       */
      const restamp = (link: Grant, proof: string): Grant =>
        signThresholdRecord({ ...link, proof }, [oldestKey(issuerOf(link)).secretKey]) as Grant;

      // (1) THE LEAF's pointer is the decoy. The chain is walked leaf first and a link's `proof`
      // is compared only after its PARENT has been accepted, so this is caught at the second
      // iteration: two links replayed and signature-checked, `2 * (E * K + K)`.
      const atLeaf = await meter([restamp(honest[0]!, decoy), ...honest.slice(1)], view);
      expect(atLeaf.verdict).toEqual({ valid: false, reason: "grant_proof_mismatch" });
      expect(atLeaf.spent).toBe(2 * (events * K + K));
      expect(atLeaf.spent).toBe(2064);

      // (2) THE DEEPEST PAIR: the root's child points at the decoy instead of at the root, and
      // every link below it is re-stamped onto the pointer it now has — so this chain has exactly
      // ONE broken pointer, and it is the last one the walk reaches. The whole chain is verified
      // before the rejection, which makes this the worst case for the reorder.
      const atDeepestChain = [...honest];
      atDeepestChain[L - 2] = restamp(atDeepestChain[L - 2]!, decoy);
      for (let index = L - 3; index >= 0; index -= 1) {
        atDeepestChain[index] = restamp(
          atDeepestChain[index]!,
          canonicalDigest(atDeepestChain[index + 1]!)
        );
      }
      const atDeepest = await meter(atDeepestChain, view);
      expect(atDeepest.verdict).toEqual({ valid: false, reason: "grant_proof_mismatch" });
      expect(atDeepest.spent).toBe(L * (events * K + K));
      expect(atDeepest.spent).toBe(4128);

      // (2b) The same pointer re-stamped WITHOUT rebuilding the links below it. Re-signing a link
      // changes its digest, so its own child's pointer goes stale too and the walk rejects at the
      // SHALLOWER of the two breaks — one iteration earlier, 6144. Pinned because it is the shape
      // a tampering attacker actually produces, and it is CHEAPER than (2) rather than dearer: a
      // second break can only move the rejection earlier.
      const cascading = [...honest];
      cascading[L - 2] = restamp(cascading[L - 2]!, decoy);
      const atCascading = await meter(cascading, view);
      expect(atCascading.verdict).toEqual({ valid: false, reason: "grant_proof_mismatch" });
      expect(atCascading.spent).toBe((L - 1) * (events * K + K));
      expect(atCascading.spent).toBe(3096);
      expect(atCascading.spent).toBeLessThan(atDeepest.spent);

      // (3) THE CONTROL, and the whole argument. Correct pointers throughout — recomputed over the
      // root as re-signed — and one signature by a key in nobody's log. The walk verifies three
      // links, replays the root's log, checks it against its anchored state, and refuses: the
      // same `L * (E * K + K)` the worst mismatch costs, reachable with no key material and
      // reachable BEFORE the reorder, which is why the reorder raises no ceiling.
      const bogus = [...honest];
      bogus[L - 1] = signThresholdRecord(honest[L - 1]!, [stranger.secretKey]) as Grant;
      for (let index = L - 2; index >= 0; index -= 1) {
        bogus[index] = restamp(bogus[index]!, canonicalDigest(bogus[index + 1]!));
      }
      const control = await meter(bogus, view);
      expect(control.verdict).toEqual({ valid: false, reason: "grant_signature_invalid" });
      expect(control.spent).toBe(L * (events * K + K));
      expect(control.spent).toBe(4128);

      // The ceiling claim, as an equality rather than as prose: the dearest a broken `proof`
      // pointer can be made is exactly what a bad signature over correct pointers already cost.
      expect(atDeepest.spent).toBe(control.spent);
      expect(atLeaf.spent).toBeLessThan(control.spent);
    },
    TEST_BACKSTOP_MS
  );
});
