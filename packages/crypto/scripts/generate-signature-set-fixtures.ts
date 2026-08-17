/**
 * Regenerates the committed spec-015 signature-set conformance vectors from deterministic
 * seeds. A change to spec 015 updates this script and the fixture together.
 *
 * Run from the repo root (after `pnpm build`). BOTH commands, in order — this script writes
 * `JSON.stringify(…, null, 2)` and the committed file is prettier-formatted, so skipping the
 * second step leaves a diff that is pure formatting and makes the fixture look non-reproducible:
 *
 *   pnpm exec tsx packages/crypto/scripts/generate-signature-set-fixtures.ts
 *   pnpm exec prettier --write packages/crypto/test/fixtures/signature-set-vectors.json
 */
import { writeFileSync } from "node:fs";

import {
  canonicalBytes,
  canonicalDigest,
  decodeKeyRef,
  decodeSignature,
  encodeKeyRef,
  encodeSignature,
  generateKeyPair,
  sign,
  verify,
  type KeyPair
} from "@kinnet/crypto";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const ISSUED_AT = "2026-06-12T00:00:00.000Z";
const REVOKED_AT = "2026-06-12T00:00:00.000Z";
/** A stand-in digest for the record a Revocation names; never dereferenced by these vectors. */
const REVOKED_DIGEST = "zQmc6UYfYm7JAhahkGriEwatG3MQxULGH1wWJo6xdz9ZtGm";

// Three committee keys plus one key that appears in no state, used for the unlisted-key vector.
const committee: KeyPair[] = [seed(41), seed(42), seed(43)].map((s) => generateKeyPair(s));
const outsider = generateKeyPair(seed(44));
const soleKey = generateKeyPair(seed(45));

const ORG_ID = "pk_zQmXbJDQAmijYmFxknjGFdCoVRC5TqrzUmRFHnWMrgtmJQa";
const ADMIN_ID = "pk_zQmRKW8VtVdmgjKaz6N11iFC4EJB1s1sy7BNkz8YQXoetwC";

type Unsigned = Record<string, unknown>;

const revocation: Unsigned = {
  revokes: REVOKED_DIGEST,
  issuerId: ORG_ID,
  revokedAt: REVOKED_AT
};

const grant: Unsigned = {
  subjectId: ORG_ID,
  issuerId: ORG_ID,
  audienceId: ADMIN_ID,
  abilities: ["directory"],
  caveats: {},
  proof: null,
  issuedAt: ISSUED_AT
};

/** The signing input of spec 001: UTF-8( JCS( record − signature ) ). */
const inputFor = (unsigned: Unsigned): Uint8Array => canonicalBytes(unsigned);
const signOver = (unsigned: Unsigned, key: KeyPair): string =>
  encodeSignature(sign(inputFor(unsigned), key.secretKey));

/**
 * A well-formed Ed25519 signature that verifies under NO key of any state: a real signature by
 * a real key over DIFFERENT bytes. This is the shape that defeated revocation — an attacker who
 * touches the bytes needs no private key at all, but a signature that decodes is the realistic
 * artifact.
 */
const junkSignature = (unsigned: Unsigned): string =>
  encodeSignature(sign(canonicalBytes({ ...unsigned, tampered: true }), outsider.secretKey));

type Vector = {
  name: string;
  why: string;
  valid: boolean;
  schema: "grant" | "revocation" | null;
  schemaValid: boolean;
  state: { keys: string[]; threshold: string };
  record: Unsigned & { signature: string[] };
  signingInput: string;
  digest: string;
  /** matrix[i][j] = verify(signature i, signingInput, state.keys[j]). */
  matrix: boolean[][];
};

function vector(
  name: string,
  why: string,
  valid: boolean,
  schema: Vector["schema"],
  schemaValid: boolean,
  unsigned: Unsigned,
  keys: string[],
  threshold: string,
  signature: string[]
): Vector {
  const input = inputFor(unsigned);
  const record = { ...unsigned, signature };
  return {
    name,
    why,
    valid,
    schema,
    schemaValid,
    state: { keys, threshold },
    record,
    signingInput: new TextDecoder().decode(input),
    digest: canonicalDigest(record),
    matrix: signature.map((member) =>
      keys.map((keyRef) => verify(decodeSignature(member), input, decodeKeyRef(keyRef)))
    )
  };
}

const committeeKeyRefs = committee.map((key) => encodeKeyRef(key.publicKey));
const soleKeyRef = encodeKeyRef(soleKey.publicKey);

const vectors: Vector[] = [
  vector(
    "valid — single signature, 1-of-1",
    "One key, threshold 1, one member verifying under it. m = t = n = 1, so there is nothing to " +
      "order and nothing surplus. The overwhelmingly common shape today.",
    true,
    "revocation",
    true,
    revocation,
    [soleKeyRef],
    "1",
    [signOver(revocation, soleKey)]
  ),
  // ---------------------------------------------------------------------------------------
  // The DELETION FAMILY: one unsigned record, one 2-of-3 state, three signature arrays that
  // are subsequences of each other. Deleting the middle member of (1/3) gives exactly (2/3);
  // deleting a member of (2/3) gives exactly (3/3). Exactly one of the three is valid, and
  // that is the whole case for m = t. Under the rule 015 replaces, (1/3) and (2/3) were BOTH
  // valid with different digests, so anyone could convert one into the other with no key.
  // ---------------------------------------------------------------------------------------
  vector(
    "deletion family 1/3 — over-signed 2-of-3, m = 3",
    "All three committee keys signed a record whose state requires two. Every member verifies " +
      "under a distinct key in key order, so this passes S2 and S3 and fails only S1's exact " +
      "count: m = 3, t = 2. Under the rule 015 replaces this was VALID, and deleting any one " +
      "member left another valid record with a different digest — the surplus-deletion " +
      "malleability that decided the m = t rule.",
    false,
    "revocation",
    true,
    revocation,
    committeeKeyRefs,
    "2",
    committee.map((key) => signOver(revocation, key))
  ),
  vector(
    "deletion family 2/3 — the conforming 2-of-3, m = t = 2",
    "Keys 0 and 2 signed, in that order, so the assignment is strictly increasing in key index " +
      "and m = t = 2 < n = 3. This is byte-for-byte what deleting the middle member of 1/3 " +
      "produces, and it is VALID — correctly so, because it is exactly the record the signers " +
      "authorized and it manufactures no authority. The property m = t buys is not that this " +
      "form is unreachable, but that it is the ONLY conforming member of the family.",
    true,
    "revocation",
    true,
    revocation,
    committeeKeyRefs,
    "2",
    [signOver(revocation, committee[0]!), signOver(revocation, committee[2]!)]
  ),
  vector(
    "deletion family 3/3 — one member deleted from the conforming set, m = 1",
    "Byte-for-byte what deleting the second member of 2/3 produces. The remaining signature " +
      "verifies under key 0, but m = 1 and t = 2, so S1 rejects it before any curve work. This " +
      "is the deletion attack applied to a CONFORMING record, and it is closed: no edit carries " +
      "a verifier from one valid record in this family to another.",
    false,
    "revocation",
    true,
    revocation,
    committeeKeyRefs,
    "2",
    [signOver(revocation, committee[0]!)]
  ),
  vector(
    "invalid — duplicate signature",
    "Both members are the same signature by key 0. Key 0 can be assigned only once, so the " +
      "second member is unassignable (S2, injective). Under the rule 015 replaces this record " +
      "verified at threshold 2 only if another key also signed; the duplicate itself was never " +
      "rejected, and it changed the digest.",
    false,
    "revocation",
    true,
    revocation,
    committeeKeyRefs,
    "2",
    [signOver(revocation, committee[0]!), signOver(revocation, committee[0]!)]
  ),
  vector(
    "invalid — non-verifying extra appended to a 1-of-1 grant (the revocation bypass)",
    "The exploited shape. A valid grant signed by its sole issuer key, plus one arbitrary " +
      "signature that verifies under nothing. The rule 015 replaces accepted it — one listed " +
      "key had a valid signature — while the appended member changed the digest the revocation " +
      "was keyed to. Rejected here three times over: m = 2 is not t = 1 (S1), m exceeds n = 1 " +
      "(S1), and the extra member verifies under no listed key (S2).",
    false,
    "grant",
    true,
    grant,
    [soleKeyRef],
    "1",
    [signOver(grant, soleKey), junkSignature(grant)]
  ),
  vector(
    "invalid — non-verifying extra that passes every count check",
    "The same attack against a 2-of-2 state: m = 2 equals the threshold AND does not exceed " +
      "n = 2, so every count rule in 015 and 009 is satisfied and ONLY S2 rejects it. This is " +
      "the vector that shows counting is not enough — an implementation that checks lengths, " +
      "the exact-count rule and the threshold but never asks which key each member verifies " +
      "under accepts a record carrying one genuine signature and one forgery-shaped junk value.",
    false,
    "grant",
    true,
    grant,
    [committeeKeyRefs[0]!, committeeKeyRefs[1]!],
    "2",
    [signOver(grant, committee[0]!), junkSignature(grant)]
  ),
  vector(
    "invalid — duplicate signature the current implementation ACCEPTS",
    "The duplication half of the defect, in the shape where today's verifyThresholdRecord gets " +
      "it wrong. A 1-of-2 state and the same signature twice: the current rule counts satisfied " +
      "KEYS, finds key 0 satisfied, and 1 >= 1 accepts — while the appended duplicate changed " +
      "the digest. 015 rejects on S1 (m = 2, t = 1). The other duplicate vector here sits at " +
      "threshold 2, where the current rule happens to reject for its own reasons; this one is " +
      "the case that is actually exploitable today, so the suite pins both.",
    false,
    "revocation",
    true,
    revocation,
    [committeeKeyRefs[0]!, committeeKeyRefs[1]!],
    "1",
    [signOver(revocation, committee[0]!), signOver(revocation, committee[0]!)]
  ),
  vector(
    "invalid — key state listing the same key twice (S0)",
    "The state itself is malformed: K = (K0, K0, K1) with t = 2. An INDEX-based reading of S2 " +
      "pairs the two identical members with positions 0 and 1 and accepts, letting one signature " +
      "satisfy a threshold of two — while the reference implementation, which dedupes by key " +
      "value, rejects. S0 closes it by making the state invalid, and S2's injectivity is on key " +
      "value rather than list position. 003 gains the matching record-layer rule; keyEventSchema " +
      "still accepts such an event today.",
    false,
    "revocation",
    true,
    revocation,
    [committeeKeyRefs[0]!, committeeKeyRefs[0]!, committeeKeyRefs[1]!],
    "2",
    [signOver(revocation, committee[0]!), signOver(revocation, committee[0]!)]
  ),
  vector(
    "invalid — mis-ordered set",
    "Both members verify, under distinct keys 2 and 0 — but in that order the assignment is " +
      "decreasing, so S3 rejects it. Reordering to key order yields the second vector above, " +
      "with a different digest. Without S3 an m-member set would have m! valid byte-forms.",
    false,
    "revocation",
    true,
    revocation,
    committeeKeyRefs,
    "2",
    [signOver(revocation, committee[2]!), signOver(revocation, committee[0]!)]
  ),
  vector(
    "invalid — signature by a key the state does not list",
    "A single well-formed signature over exactly these bytes, by a key that is not in the " +
      "state. It verifies under nothing listed, so S2 rejects it. Membership of the state's key " +
      "list — not signature well-formedness — is what counts.",
    false,
    "revocation",
    true,
    revocation,
    committeeKeyRefs,
    "1",
    [signOver(revocation, outsider)]
  ),
  vector(
    "invalid — threshold above the state's key count",
    "Two keys, threshold 3. Unsatisfiable by construction, so 015 makes the STATE invalid " +
      "rather than leaving a state every record fails against. `keyEventSchema` bounds `keys` " +
      "and constrains `threshold` to ^[1-9][0-9]*$ with no upper bound and no cross-field rule, " +
      "so this event is representable and accepted today.",
    false,
    "revocation",
    true,
    revocation,
    [committeeKeyRefs[0]!, committeeKeyRefs[1]!],
    "3",
    [signOver(revocation, committee[0]!), signOver(revocation, committee[1]!)]
  ),
  vector(
    "invalid — degenerate threshold, empty state, empty set",
    '`threshold: "0"` is outside ^[1-9][0-9]*$, so S1 rejects it and there is no verdict to ' +
      'reach. Recorded because `verifyThresholdRecord({signature: []}, [], "0")` returns TRUE ' +
      "today: the comparison `satisfied.size >= Number(threshold)` is 0 >= 0. The record schemas " +
      "make an empty signature array unrepresentable, so this is a public-API surface rather " +
      "than stored data — which is why `schemaValid` is false here.",
    false,
    "revocation",
    false,
    revocation,
    [],
    "0",
    []
  )
];

// ------------------------------------------------------------------------------------------
// Spec 003's "no two states may share a quorum" rule, adopted as the interim measure that
// closes the cross-state routes until record anchoring (015 -> 016) lands. These vectors are
// about KEY LOG SHAPE, not about any one record's signature set, so they carry key states
// rather than records: |keys(A) n keys(B)| < min(t_A, t_B) for EVERY pair of committed states.
// ------------------------------------------------------------------------------------------

/** Eight distinct keys, enough for a 5-key state plus a disjoint replacement set. */
const pool: KeyPair[] = [61, 62, 63, 64, 65, 66, 67, 68].map((n) => generateKeyPair(seed(n)));
const k = pool.map((pair) => encodeKeyRef(pair.publicKey));

type LogRuleVector = {
  name: string;
  why: string;
  legal: boolean;
  states: { keys: string[]; threshold: string }[];
};

const logRuleVectors: LogRuleVector[] = [
  {
    name: "illegal — route 3: the later state's keys are a SUBSET of the earlier state's",
    why:
      "The cross-state deletion route, as executed. A record signed by all three keys conforms " +
      "against A; delete one member — no key required — and the remaining two conform against B. " +
      "Shared keys 2, min threshold 2, so 2 < 2 is false and the log is rejected.",
    legal: false,
    states: [
      { keys: [k[0]!, k[1]!, k[2]!], threshold: "3" },
      { keys: [k[0]!, k[2]!], threshold: "2" }
    ]
  },
  {
    name: "illegal — route 4: the later state is a PERMUTATION of the earlier state",
    why:
      "The cross-state reorder route, as executed. Same two keys, opposite order, so a record " +
      "conforming against A conforms against B once its two members are swapped. Both " +
      "thresholds are 2, which is why the m = t rule alone gives no protection here. Shared 2, " +
      "min threshold 2.",
    legal: false,
    states: [
      { keys: [k[0]!, k[1]!], threshold: "2" },
      { keys: [k[1]!, k[0]!], threshold: "2" }
    ]
  },
  {
    name: "illegal — variant G: the key set GROWS, which a backwards-looking rule misses",
    why:
      "The attack does not care which state came first. The m = 2 record conforming against B " +
      "loses a member and conforms against A. B is not a subset of A, so a rule phrased as " +
      "'no state may be a subset of an EARLIER one' accepts this log; the intersection rule " +
      "rejects it, shared 1 against min threshold 1.",
    legal: false,
    states: [
      { keys: [k[0]!], threshold: "1" },
      { keys: [k[0]!, k[1]!], threshold: "2" }
    ]
  },
  {
    name: "illegal — variant P: partial rotation with a lowered threshold",
    why:
      "THE case that killed the more permissive rule, kept so a future reader does not propose " +
      "it again. The rotation retires K2, introduces K3 and keeps K0 and K1 — neither key set " +
      "is a subset or a permutation of the other, so subset/permutation rules in BOTH the " +
      "one-way and symmetric forms accept this log. It is still a working attack: drop one " +
      "member from the m = 3 record conforming against A and the remaining two conform against " +
      "B. Shared 2, min threshold 2. This is why the rule counts the intersection against the " +
      "threshold rather than comparing key lists.",
    legal: false,
    states: [
      { keys: [k[0]!, k[1]!, k[2]!], threshold: "3" },
      { keys: [k[0]!, k[1]!, k[3]!], threshold: "2" }
    ]
  },
  {
    name: "legal — 1-of-1 rotation, the shape every first-party log has",
    why:
      "A rotation that replaces its single key shares nothing: 0 < 1. Every documented " +
      "first-party participant is this shape, which is why the rule costs zero migration.",
    legal: true,
    states: [
      { keys: [k[0]!], threshold: "1" },
      { keys: [k[1]!], threshold: "1" }
    ]
  },
  {
    name: "legal — 3-of-5 retaining two old keys",
    why:
      "Key reuse is NOT forbidden, only reuse up to a quorum. Two keys carry over against a " +
      "threshold of three: 2 < 3, so the log is legal. This is the boundary from the permissive " +
      "side, and it is what makes the intersection rule strictly weaker than banning reuse.",
    legal: true,
    states: [
      { keys: [k[0]!, k[1]!, k[2]!, k[3]!, k[4]!], threshold: "3" },
      { keys: [k[0]!, k[1]!, k[5]!, k[6]!, k[7]!], threshold: "3" }
    ]
  },
  {
    name: "legal — 2-of-3 retaining exactly one old key",
    why:
      "The most a 2-of-3 may keep. One key carries over against a threshold of two: 1 < 2. " +
      "Retaining TWO would share a quorum and be rejected — the restriction an operator most " +
      "needs to know about, pinned here from the legal side.",
    legal: true,
    states: [
      { keys: [k[0]!, k[1]!, k[2]!], threshold: "2" },
      { keys: [k[0]!, k[3]!, k[4]!], threshold: "2" }
    ]
  },
  {
    name: "illegal — a non-adjacent pair, so the rule is over ALL pairs not consecutive ones",
    why:
      "States 0 and 2 share both their keys against a threshold of two, while each is legal " +
      "against the state between them. Records verify against ANY state a log ever committed, " +
      "so every pair is live and the rule must be checked pairwise across the whole log. A " +
      "replay that only compared consecutive events would accept this log and leave the route " +
      "open.",
    legal: false,
    states: [
      { keys: [k[0]!, k[1]!], threshold: "2" },
      { keys: [k[2]!, k[3]!, k[4]!], threshold: "3" },
      { keys: [k[1]!, k[0]!], threshold: "2" }
    ]
  }
];

const target = new URL("../test/fixtures/signature-set-vectors.json", import.meta.url);
writeFileSync(
  target,
  `${JSON.stringify(
    {
      note:
        "Conformance vectors for spec 015 (canonical signature sets). Every vector is " +
        "verifiable from bytes alone: `signingInput` is the UTF-8 JCS of the record without its " +
        "`signature` field (spec 001), `matrix[i][j]` records whether signature i verifies over " +
        "that input under `state.keys[j]` (Ed25519, spec 005), and `digest` is the spec-003 " +
        "multihash of the JCS of the COMPLETE signed record, signature array included. `valid` " +
        "is the spec-015 verdict for the record against `state`: every member verifies under a " +
        "distinct listed key, in strictly increasing key-list order, with m = t <= n, no key " +
        "repeated in the state, and a threshold in ^[1-9][0-9]*$. `schemaValid` is the separate " +
        "question of whether @kinnet/protocol's schema for `schema` accepts the record shape. " +
        "Regenerate with packages/crypto/scripts/generate-signature-set-fixtures.ts.",
      vectors,
      logRuleNote:
        "Conformance vectors for spec 003's 'no two states may share a quorum' rule, the " +
        "interim measure that closes the cross-state routes until record anchoring lands. Each " +
        "vector is a sequence of key states one log commits, in order. `legal` is true iff " +
        "|keys(A) n keys(B)| < min(threshold(A), threshold(B)) holds for EVERY pair of states, " +
        "not merely consecutive ones — records verify against any state a log ever committed, " +
        "so every pair is simultaneously live. These carry no records and no signatures: the " +
        "rule constrains log SHAPE, and a third party can check every vector by intersecting " +
        "the key lists.",
      logRuleVectors
    },
    null,
    2
  )}\n`
);

console.log(
  `Wrote ${vectors.length} signature-set vectors and ${logRuleVectors.length} log-rule vectors to ${target.pathname}`
);
