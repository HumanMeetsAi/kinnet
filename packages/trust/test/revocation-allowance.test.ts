/**
 * The revocation search's sub-allowance — the term every cost model in this repo used to omit.
 *
 * `verifyGrantChain` calls `findRevocation` ONCE PER LINK, with the authorized revokers of that
 * link and every link above it, so a chain opens `L(L+1)/2` candidate slots rather than `L`.
 * Each slot was an unbounded `states x keys x signatures` search over records an untrusted view
 * chose to send, which is why a conforming chain cost multiples of what its callers believed.
 *
 * Spec 015 has since collapsed the per-slot search to `states x keys`: the greedy walk spends at
 * most one verification per listed key whatever the record's signature count, and a count that
 * is not exactly the threshold is refused on its LENGTH before any curve work. The slot COUNT is
 * untouched, so the composition is still unbounded without the sub-allowance — what changed is
 * how much a hostile view gets per slot, and therefore how long a log it needs to reach the
 * bound. The fixtures below run at `MAX_KEY_LOG_EVENTS` for that reason.
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
 * a cheap one. The twin of `apps/node/test/wide-identity.ts`, kept local because a test helper
 * cannot be imported across package boundaries.
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

/** The honest worst case for a state search: the last key of the OLDEST state. */
const oldestKey = (identity: WideIdentity): KeyPair =>
  identity.states[0]![identity.states[0]!.length - 1]!;

/**
 * A leaf-first chain of `L` links over `L + 1` identities, every link signed under its issuer's
 * oldest state so that each signature search walks the issuer's whole history.
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
      proof: previous === null ? null : canonicalDigest(previous),
      issuedAt: ISSUED_AT
    };
    const signed = signThresholdRecord(unsigned, [oldestKey(issuer).secretKey]) as Grant;
    chain.push(signed);
    previous = signed;
  }
  return chain.reverse();
}

function revocationOf(digest: string, issuerId: ParticipantId, secretKeys: Uint8Array[]) {
  return signThresholdRecord(
    { revokes: digest, issuerId, revokedAt: ISSUED_AT },
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
   * storing it, so an honest candidate always verifies; what it costs is decided by how far the
   * issuer has rotated since. `signedByAnyState` searches states newest-first, so the honest
   * WORST case is a revocation issued before a full rotation history — `E * K`, the whole
   * search — and that is exactly what "a record verifies against any state a participant has
   * held" exists for. Measured, not assumed.
   *
   * WATCHED TO FAIL: set `MAX_REVOCATION_CANDIDATE_VERIFICATIONS` to
   * `MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS` / 2 — half the honest ceiling. The verdict turns
   * from `grant_revoked` into `grant_signature_check_too_expensive`, i.e. the bound starts
   * refusing an honest revocation check, which is the failure this test exists to catch.
   */
  it(
    "never refuses an honest revocation signed under the oldest state of a full-length log",
    async () => {
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const chain = grantChain(identities);
      const leaf = chain[0]!;
      const leafIssuer = identities.find((identity) => identity.id === leaf.issuerId)!;
      const leafDigest = canonicalDigest(leaf);

      const view = viewOf(identities, (digest) =>
        digest === leafDigest
          ? [revocationOf(digest, leafIssuer.id, [oldestKey(leafIssuer).secretKey])]
          : []
      );

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_revoked" });

      // The lookup itself: one replay and one link-signature search precede it, each `E * K`.
      const beforeTheLookup = 2 * events * K;
      expect(spent - beforeTheLookup).toBe(events * K);
      // ...which is the honest ceiling, and the allowance clears it by exactly its headroom.
      expect(R).toBe(2 * MAX_KEY_LOG_EVENTS * K);
      expect(R / (MAX_KEY_LOG_EVENTS * K)).toBe(2);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * The second half of `R = 2A` is for an answer that makes the verifier spend a complete
   * conforming search before it reaches the genuine record. Both candidates have the required
   * one-member signature set: the first member is absent from every state, while the second is
   * the genuine issuer's last key in its oldest state. Each therefore costs exactly `A`.
   *
   * WATCHED TO FAIL: subtract one from `MAX_REVOCATION_CANDIDATE_VERIFICATIONS`. The genuine
   * candidate then reaches its last key with no allowance remaining and the verdict changes
   * from `grant_revoked` to `grant_signature_check_too_expensive`. This is the exact boundary;
   * the one-candidate test above remains the control that `A` alone still clears.
   */
  it(
    "admits one full rejected search followed by one full genuine search at exactly 2A",
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
              revocationOf(digest, upstreamIssuer.id, [stranger.secretKey]),
              revocationOf(digest, leafIssuer.id, [oldestKey(leafIssuer).secretKey])
            ]
          : []
      );

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_revoked" });
      expect(R).toBe(2 * A);
      // Leaf replay + leaf signature + first replay of the upstream issuer precede the two
      // candidate searches. Removing those three exact `A` terms isolates the sub-allowance.
      expect(spent - 3 * A).toBe(R);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * THE SANDWICH. A ceiling above every individual stage and below their sum is the only shape
   * that catches "each call bounded, composition unbounded" — and composition is precisely what
   * was unbounded here, since the per-link lookups were each finite and their sum was not.
   *
   * WATCHED TO FAIL: measured with the sub-allowance removed — drop `candidateAllowance` from
   * the `signedByAnyState` call in `findRevocation` — this chain spends 18,432, which is
   * `L * 2E * K + (L(L+1)/2) * E * K`, and returns `valid: true`. The verdict assertion below
   * fails, and the closed-form ceiling it asserts (16,384) is exceeded by 2048.
   */
  it(
    "bounds a hostile revocation answer to the closed form the callers can add up",
    async () => {
      // At the schema's MAXIMUM log length, and that is now what makes the bound bite. Under spec
      // 015's walk a candidate's state search costs `E * K` however many signatures it carries,
      // so one candidate costs 1024 here, TWO exactly fill the 2048 sub-allowance, and the third
      // is refused — the bound is exercised rather than merely present. A shorter log no longer
      // reaches it: at 32 events a candidate costs 256 and the four a leaf lookup may be given
      // total 1024, inside the allowance. Measured — the same hostile answer over 32-event logs
      // completes at 4608 verifications and returns `valid: true`.
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const chain = grantChain(identities);
      const stranger = generateKeyPair(nextSeed());

      // One candidate per REQUESTED issuer — the most a view may return without the oversized
      // answer being rejected outright — each carrying EXACTLY ONE signature, by a key in
      // nobody's log, so every one forces the full states x keys search.
      //
      // One signature and not `MAX_RECORD_SIGNATURES`, and the inversion is worth stating: under
      // spec 015 the issuers here have `threshold: "1"`, so a padded candidate is refused by S1's
      // `m = t` LENGTH check before any curve work and costs the verifier nothing at all. Padding
      // is now the cheap answer; the expensive one is a candidate whose member count conforms and
      // whose members verify under no listed key. Pinned below rather than merely stated here:
      // the padded answer this test used to send is now the WEAKER one.
      let answers = 0;
      const view = viewOf(identities, (digest, issuerIds) => {
        answers += 1;
        return issuerIds.map((issuerId) =>
          revocationOf(digest, issuerId as ParticipantId, [stranger.secretKey])
        );
      });

      const { verdict, spent } = await meter(chain, view);

      // Fails closed: an exhausted lookup is a cost refusal, never "not revoked".
      expect(verdict).toEqual({ valid: false, reason: "grant_signature_check_too_expensive" });

      // BELOW their sum: the closed form beside `verifyGrantChain`. `S` is absent from it now —
      // a link's own search costs `E * K` whatever the record's signature count, because the walk
      // is bounded by the key list and a non-conforming count never reaches the walk.
      const chainCeiling = L * (events * K) + L * (events * K) + L * R;
      expect(spent).toBeLessThanOrEqual(chainCeiling);
      // ...and below the unbounded term this replaced, which is what the old code spent.
      expect(spent).toBeLessThan(((L * (L + 1)) / 2) * events * K);
      // ABOVE the individual stages: more than one link's own work, and more than one lookup's
      // allowance, so the assertion is not passing because nothing ran.
      expect(spent).toBeGreaterThan(events * K);
      expect(spent).toBeGreaterThan(R);
      expect(answers).toBeGreaterThan(0);

      // And the inversion, pinned rather than described. The SAME answer padded to
      // `MAX_RECORD_SIGNATURES` — the shape this test sent while a signature set only had to
      // contain a threshold's worth of valid members — is now refused by S1's `m = t` length
      // check against these `threshold: "1"` issuers, before any curve work. Every one of the
      // `L(L+1)/2` padded candidates therefore costs ZERO, nothing exhausts, and the chain runs
      // to completion.
      //
      // Its TOTAL is higher than the refused run above (8192 against 6144) and that is not a
      // contradiction: the refused run stopped part-way. What the two numbers say together is
      // that padding buys a hostile view no verifier work at all, so the answer it has to send
      // to reach the sub-allowance is the conforming-count one.
      const padded = await meter(
        chain,
        viewOf(identities, (digest, issuerIds) =>
          issuerIds.map((issuerId) =>
            revocationOf(
              digest,
              issuerId as ParticipantId,
              Array.from({ length: S }, () => stranger.secretKey)
            )
          )
        )
      );
      expect(padded.verdict.valid).toBe(true);
      // Nothing but the chain's own work is in it: `L` replays plus `L` link searches, each
      // `E * K`, and not one verification for any of the `L(L+1)/2` padded candidates. Equality,
      // not a bound — a padded candidate that cost even one verification would break it.
      expect(padded.spent).toBe(L * 2 * events * K);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * The sub-allowance is PER LOOKUP and shared across that lookup's candidates. Minted per
   * CANDIDATE it would bound nothing: the cost would still scale with however many records the
   * view chose to send, which is the amplification it exists to remove.
   *
   * WATCHED TO FAIL: move the `candidateAllowance` object inside the `for (const candidate)`
   * loop in `findRevocation`. Each candidate then gets a fresh 2048, which is twice what one
   * costs, so every slot completes: measured, the chain verifies `valid: true` at 18,432
   * verifications and blows through the 7168 bound below.
   */
  it(
    "shares one allowance across a lookup's candidates rather than minting one each",
    async () => {
      // Full-length logs and single-signature candidates, for the reason spelled out in the test
      // above: a candidate's cost is `E * K` and no longer scales with its signature count, so
      // the sub-allowance is only reached when one candidate's state search is a large enough
      // fraction of it.
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const chain = grantChain(identities);
      const stranger = generateKeyPair(nextSeed());
      const view = viewOf(identities, (digest, issuerIds) =>
        issuerIds.map((issuerId) =>
          revocationOf(digest, issuerId as ParticipantId, [stranger.secretKey])
        )
      );

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_signature_check_too_expensive" });
      // The refusal lands inside the LEAF's lookup, so everything spent up to it is: every
      // replay the chain can drive (the signer memo caps them at one per distinct issuer, and a
      // lookup asking about upstream issuers is what drives the ones the loop has not reached
      // yet), the leaf link's own single-signature search, and ONE sub-allowance across all of
      // that lookup's candidates. Minted per candidate instead, the same lookup would spend one
      // allowance per requested issuer and blow straight through this.
      //
      // Measured at 6144 against a bound of 7168: the leaf's lookup exhausts the sub-allowance on
      // its second candidate, so the third's replay is paid for and its search is not.
      expect(spent).toBeLessThanOrEqual(L * (events * K) + events * K + R);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * Exhaustion may never read as "not revoked". A genuine revocation hidden behind enough
   * padded decoys must produce a cost refusal, not an authorization.
   *
   * WATCHED TO FAIL: replace the `signedByAnyState(...)` call in `findRevocation` with one
   * wrapped in `try { ... } catch { continue; }`. The genuine revocation is then never CHECKED
   * — its own search throws on the exhausted allowance and the throw is swallowed — the lookup
   * returns null, and the chain verifies `valid: true` at 10,240 verifications. Measured. That
   * is the silent downgrade of the one check that withdraws authority.
   */
  it(
    "refuses rather than reporting not-revoked when decoys exhaust the allowance",
    async () => {
      // Full-length logs, and they are what makes the decoys expensive enough to exhaust the
      // sub-allowance at all. Under spec 015 a candidate's cost is `E * K` — its signature count
      // drops out — so at 32 events three decoys cost 768 against an allowance of 2048 and the
      // genuine revocation is reached: measured, that shape now returns `grant_revoked` at 2304
      // verifications, which is a correct verdict but not the property this test is for. At
      // `E = MAX_KEY_LOG_EVENTS` a decoy costs 1024, two exhaust the allowance, and the third
      // decoy's search is refused before the genuine record behind it is ever examined.
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
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
        // carries exactly one signature, matching these issuers' `threshold: "1"`, so it clears
        // S1's `m = t` length check and forces the whole `E * K` state search — a decoy padded to
        // `MAX_RECORD_SIGNATURES` would be refused on its length and cost nothing.
        const decoys = issuerIds
          .filter((issuerId) => issuerId !== leafIssuer.id)
          .map((issuerId) => revocationOf(digest, issuerId as ParticipantId, [stranger.secretKey]));
        return [...decoys, revocationOf(digest, leafIssuer.id, [oldestKey(leafIssuer).secretKey])];
      });

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_signature_check_too_expensive" });
      expect(verdict.valid).toBe(false);
      // The genuine record is the fourth candidate and the allowance is gone by the third, so the
      // run stops one replay past the exhaustion: `L` replays, the leaf's own search, and the two
      // decoy searches the sub-allowance paid for. Measured at 7168.
      expect(spent).toBe(L * (events * K) + events * K + R);
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
        digest === leafDigest ? [revocationOf(digest, upstream.id, [stranger.secretKey])] : []
      );

      // Enough for the leaf's own replay and signature search and nothing like enough for a
      // second replay, which is what the lookup is about to drive.
      const budget: VerificationBudget = { remaining: 2 * events * K + K };
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
 * The closed form beside `verifyGrantChain` had `L * 2E * K` written as 9216 in one sentence and
 * 8192 in another, twelve lines apart, and nothing in the suite noticed. These measure the two
 * quantities the derivations actually claim, so the numbers in the prose cannot drift from the
 * code without a red test.
 */
describe("the chain cost arithmetic", () => {
  /**
   * WATCHED TO FAIL: change the expectation to `L * 2 * E * K + 2 * E * K` — one honest
   * revocation search too many, which is the shape the "10,240" typo described. It fails by
   * exactly `E * K`.
   */
  it(
    "spends exactly L*2E*K + E*K on a chain the view honestly reports revoked at the ROOT",
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
          ? [revocationOf(digest, rootIssuer.id, [oldestKey(rootIssuer).secretKey])]
          : []
      );

      const { verdict, spent } = await meter(chain, view);
      expect(verdict).toEqual({ valid: false, reason: "grant_revoked" });
      expect(spent).toBe(L * 2 * events * K + events * K);
      // Spelled out, because the prose got this product wrong: L*2E*K is 8192, not 9216.
      expect(L * 2 * events * K).toBe(8192);
      expect(spent).toBe(9216);
    },
    TEST_BACKSTOP_MS
  );

  /**
   * THE THIRD CASE. A candidate that parses, targets the right digest and comes from a requested
   * issuer but FAILS its signature check costs `E * K`, the lookup returns null, and the chain
   * CARRIES ON — so the rejection adds to the chain's cost instead of replacing part of it, and
   * the verdict is still `valid: true`. Every earlier version of this derivation said the
   * revocation search and the rest were alternatives ("never both"); they are not.
   *
   * WATCHED TO FAIL: assert `spent` equals the no-revocation cost `L * 2 * E * K`, which is what
   * "never both" implies. It fails by `L * E * K` = 4096.
   */
  it(
    "adds E*K per link for a rejected candidate, and still returns valid",
    async () => {
      const events = MAX_KEY_LOG_EVENTS;
      const identities = Array.from({ length: L + 1 }, () => wideIdentity(events));
      const chain = grantChain(identities);
      const digests = chain.map((link) => canonicalDigest(link));
      const stranger = generateKeyPair(nextSeed());

      // One candidate per link, from that link's OWN issuer so it is a requested revoker, signed
      // by a key in nobody's log so it can never verify. One candidate costs E*K, which is under
      // the sub-allowance — so this shape is not what R bounds, and R does not change it.
      const view = viewOf(identities, (digest) => {
        const index = digests.indexOf(digest);
        return index >= 0
          ? [revocationOf(digest, chain[index]!.issuerId as ParticipantId, [stranger.secretKey])]
          : [];
      });

      const { verdict, spent } = await meter(chain, view);
      expect(verdict.valid).toBe(true);
      expect(spent).toBe(L * 2 * events * K + L * (events * K));
      expect(spent).toBeGreaterThan(L * 2 * events * K);
      // Each lookup stays well inside the sub-allowance, which is why removing R would not change
      // this number by one verification. The bound is not what limits this shape.
      expect(events * K).toBeLessThan(R);
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
      // iteration: two links replayed and signature-checked, `2 * 2E * K`.
      const atLeaf = await meter([restamp(honest[0]!, decoy), ...honest.slice(1)], view);
      expect(atLeaf.verdict).toEqual({ valid: false, reason: "grant_proof_mismatch" });
      expect(atLeaf.spent).toBe(2 * 2 * events * K);
      expect(atLeaf.spent).toBe(4096);

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
      expect(atDeepest.spent).toBe(L * 2 * events * K);
      expect(atDeepest.spent).toBe(8192);

      // (2b) The same pointer re-stamped WITHOUT rebuilding the links below it. Re-signing a link
      // changes its digest, so its own child's pointer goes stale too and the walk rejects at the
      // SHALLOWER of the two breaks — one iteration earlier, 6144. Pinned because it is the shape
      // a tampering attacker actually produces, and it is CHEAPER than (2) rather than dearer: a
      // second break can only move the rejection earlier.
      const cascading = [...honest];
      cascading[L - 2] = restamp(cascading[L - 2]!, decoy);
      const atCascading = await meter(cascading, view);
      expect(atCascading.verdict).toEqual({ valid: false, reason: "grant_proof_mismatch" });
      expect(atCascading.spent).toBe((L - 1) * 2 * events * K);
      expect(atCascading.spent).toBe(6144);
      expect(atCascading.spent).toBeLessThan(atDeepest.spent);

      // (3) THE CONTROL, and the whole argument. Correct pointers throughout — recomputed over the
      // root as re-signed — and one signature by a key in nobody's log. The walk verifies three
      // links, replays the root's log, searches every state it has held, and refuses: the same
      // `L * 2E * K` the worst mismatch costs, reachable with no key material and reachable
      // BEFORE the reorder, which is why the reorder raises no ceiling.
      const bogus = [...honest];
      bogus[L - 1] = signThresholdRecord(honest[L - 1]!, [stranger.secretKey]) as Grant;
      for (let index = L - 2; index >= 0; index -= 1) {
        bogus[index] = restamp(bogus[index]!, canonicalDigest(bogus[index + 1]!));
      }
      const control = await meter(bogus, view);
      expect(control.verdict).toEqual({ valid: false, reason: "grant_signature_invalid" });
      expect(control.spent).toBe(L * 2 * events * K);
      expect(control.spent).toBe(8192);

      // The ceiling claim, as an equality rather than as prose: the dearest a broken `proof`
      // pointer can be made is exactly what a bad signature over correct pointers already cost.
      expect(atDeepest.spent).toBe(control.spent);
      expect(atLeaf.spent).toBeLessThan(control.spent);
    },
    TEST_BACKSTOP_MS
  );
});
