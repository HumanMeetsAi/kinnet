/**
 * Regenerates the committed spec-016 record-anchoring vectors from deterministic seeds. A
 * change to spec 016 or to `checkAnchoredSignatureSet` updates this script and the fixture
 * together.
 *
 * What the suite is for. Spec 015 S5 let a record be judged against ANY state its issuer's log
 * ever committed, and 015 documents two keyless edits that exploit it: route 3 deletes a member
 * so the remainder conforms against a later, narrower state, and route 4 reorders members so
 * they conform against a permuted one. 016 replaces the existential with a lookup — the record
 * names the one state it is judged against — and these vectors execute both routes, plus the
 * two variants (G and P) that defeated the narrower log-shape rules, against the anchored rule.
 * Every log below REPLAYS VALID, including the ones an earlier interim rule refused for sharing
 * a quorum: the closure is now in the record, not in the log's shape.
 *
 * Run from the repo root (after `pnpm build`). BOTH commands, in order — this script writes
 * `JSON.stringify(…, null, 2)` and the committed file is prettier-formatted, so skipping the
 * second step leaves a diff that is pure formatting and makes the fixture look non-reproducible:
 *
 *   pnpm exec tsx packages/crypto/scripts/generate-record-anchoring-fixtures.ts
 *   pnpm exec prettier --write packages/crypto/test/fixtures/record-anchoring-vectors.json
 */
import { writeFileSync } from "node:fs";

import {
  canonicalBytes,
  canonicalDigest,
  checkAnchoredSignatureSet,
  commitToKeyState,
  deriveParticipantId,
  encodeKeyRef,
  encodeSignature,
  eventDigest,
  generateKeyPair,
  replayKeyLogStates,
  sign,
  type AnchoredKeyState,
  type KeyPair
} from "@kinnet/crypto";
import {
  grantSchema,
  keyEventLogSchema,
  revocationSchema,
  type KeyEvent,
  type ParticipantId
} from "@kinnet/protocol";

const seed = (fill: number) => new Uint8Array(32).fill(fill);
const keyPair = (fill: number): KeyPair => generateKeyPair(seed(fill));
const ref = (pair: KeyPair): string => encodeKeyRef(pair.publicKey);

const ISSUED_AT = "2026-06-12T00:00:00.000Z";
/** A stand-in digest for the record a Revocation names; never dereferenced by these vectors. */
const REVOKED_DIGEST = "zQmc6UYfYm7JAhahkGriEwatG3MQxULGH1wWJo6xdz9ZtGm";
/** The audience of the Grant-shaped vectors; a participant, so 011 asks for no expiry. */
const AUDIENCE_ID = "pk_zQmRKW8VtVdmgjKaz6N11iFC4EJB1s1sy7BNkz8YQXoetwC";

type Unsigned = Record<string, unknown>;

// ---------------------------------------------------------------------------------------------
// Key logs. Each is built by hand rather than through `createIdentity`, because every shape here
// is an M-of-N one that `createIdentity`/`rotateIdentity` cannot mint (they preserve a 1-of-1).
// ---------------------------------------------------------------------------------------------

type Shape = {
  /** The keys this event reveals, in order. */
  keys: KeyPair[];
  /** The threshold this event declares — and, for a rotation, the one the PRIOR event committed. */
  threshold: string;
  /** The state committed for the NEXT event. */
  nextKeys: KeyPair[];
  nextThreshold: string;
};

function mint(unsigned: Omit<KeyEvent, "signature">, signers: KeyPair[]): KeyEvent {
  const bytes = canonicalBytes(unsigned);
  return {
    ...unsigned,
    signature: signers.map((pair) => encodeSignature(sign(bytes, pair.secretKey)))
  };
}

/** An inception carrying exactly its threshold in signatures, in key order (015 S1, S3). */
function inception(shape: Shape): KeyEvent {
  const establishment = {
    seq: "0",
    kind: "icp" as const,
    keys: shape.keys.map(ref),
    threshold: shape.threshold,
    next: commitToKeyState(shape.nextKeys.map(ref), shape.nextThreshold)
  };
  const id = deriveParticipantId(establishment);
  return mint({ ...establishment, id, prior: null }, shape.keys.slice(0, Number(shape.threshold)));
}

/** A rotation revealing exactly the committed state, signed by the revealed keys (003). */
function rotation(previous: KeyEvent, shape: Shape): KeyEvent {
  const unsigned = {
    id: previous.id,
    seq: String(Number(previous.seq) + 1),
    prior: eventDigest(previous),
    kind: "rot" as const,
    keys: shape.keys.map(ref),
    threshold: shape.threshold,
    next: commitToKeyState(shape.nextKeys.map(ref), shape.nextThreshold)
  };
  return mint(unsigned, shape.keys.slice(0, Number(shape.threshold)));
}

/** A log plus its replayed, anchor-tagged states — the lookup table 016's rule resolves against. */
type Log = { events: KeyEvent[]; id: ParticipantId; states: AnchoredKeyState[] };

function log(events: KeyEvent[]): Log {
  const { states } = replayKeyLogStates(events);
  if (!keyEventLogSchema.safeParse(events).success) {
    throw new Error("Every log in this fixture must be schema-valid as well as replay-valid");
  }
  return { events, id: states[0]!.id, states };
}

// Route 3 (015): a 3-of-3 narrowing to a 2-of-2 whose keys are a SUBSET, in the same order.
const r3 = [keyPair(1), keyPair(2), keyPair(3)];
const r3Next = [r3[0]!, r3[2]!];
const routeThree = log(
  (() => {
    const icp = inception({
      keys: r3,
      threshold: "3",
      nextKeys: r3Next,
      nextThreshold: "2"
    });
    return [
      icp,
      rotation(icp, {
        keys: r3Next,
        threshold: "2",
        nextKeys: [keyPair(4), keyPair(5)],
        nextThreshold: "2"
      })
    ];
  })()
);

// Route 4 (015): a 2-of-2 rotating into a PERMUTATION of itself.
const r4 = [keyPair(11), keyPair(12)];
const routeFour = log(
  (() => {
    const icp = inception({
      keys: r4,
      threshold: "2",
      nextKeys: [r4[1]!, r4[0]!],
      nextThreshold: "2"
    });
    return [
      icp,
      rotation(icp, {
        keys: [r4[1]!, r4[0]!],
        threshold: "2",
        nextKeys: [keyPair(13), keyPair(14)],
        nextThreshold: "2"
      })
    ];
  })()
);

// Variant G (015): the key set GROWS — [K0] t=1 -> [K0,K1] t=2.
const vg = [keyPair(21), keyPair(22)];
const variantG = log(
  (() => {
    const icp = inception({
      keys: [vg[0]!],
      threshold: "1",
      nextKeys: vg,
      nextThreshold: "2"
    });
    return [
      icp,
      rotation(icp, {
        keys: vg,
        threshold: "2",
        nextKeys: [keyPair(23), keyPair(24)],
        nextThreshold: "2"
      })
    ];
  })()
);

// Variant P (015): a partial rotation that retires one key, introduces one, and keeps a quorum.
const vp = [keyPair(31), keyPair(32), keyPair(33), keyPair(34)];
const vpNext = [vp[0]!, vp[1]!, vp[3]!];
const variantP = log(
  (() => {
    const icp = inception({
      keys: [vp[0]!, vp[1]!, vp[2]!],
      threshold: "3",
      nextKeys: vpNext,
      nextThreshold: "2"
    });
    return [
      icp,
      rotation(icp, {
        keys: vpNext,
        threshold: "2",
        nextKeys: [keyPair(35), keyPair(36)],
        nextThreshold: "2"
      })
    ];
  })()
);

// A 2-of-3 rotation retaining TWO of its three keys — the shape the interim log rule cost and
// 016 gives back. Both states are 2-of-3 and they share a quorum.
const q = [keyPair(41), keyPair(42), keyPair(43), keyPair(44)];
const qNext = [q[0]!, q[1]!, q[3]!];
const sharedQuorum = log(
  (() => {
    const icp = inception({
      keys: [q[0]!, q[1]!, q[2]!],
      threshold: "2",
      nextKeys: qNext,
      nextThreshold: "2"
    });
    return [
      icp,
      rotation(icp, {
        keys: qNext,
        threshold: "2",
        nextKeys: [keyPair(45), keyPair(46)],
        nextThreshold: "2"
      })
    ];
  })()
);

// A three-event 1-of-1 log: the "record anchored to a state two rotations back" case.
const rotating = [keyPair(51), keyPair(52), keyPair(53), keyPair(54)];
const rotatingLog = log(
  (() => {
    const icp = inception({
      keys: [rotating[0]!],
      threshold: "1",
      nextKeys: [rotating[1]!],
      nextThreshold: "1"
    });
    const first = rotation(icp, {
      keys: [rotating[1]!],
      threshold: "1",
      nextKeys: [rotating[2]!],
      nextThreshold: "1"
    });
    return [
      icp,
      first,
      rotation(first, {
        keys: [rotating[2]!],
        threshold: "1",
        nextKeys: [rotating[3]!],
        nextThreshold: "1"
      })
    ];
  })()
);

/** A different participant's log, for the cross-log anchor vector. */
const stranger = log([
  inception({
    keys: [keyPair(61)!],
    threshold: "1",
    nextKeys: [keyPair(62)!],
    nextThreshold: "1"
  })
]);

// ---------------------------------------------------------------------------------------------
// Records.
// ---------------------------------------------------------------------------------------------

/** The unsigned body of a Revocation issued by `issuer`, anchored to `anchor` (008, 016). */
const revocation = (issuerId: ParticipantId, anchor: string): Unsigned => ({
  revokes: REVOKED_DIGEST,
  issuerId,
  anchor,
  revokedAt: ISSUED_AT
});

/** The unsigned body of a self-issued Grant, anchored to `anchor` (009, 011, 016). */
const grant = (issuerId: ParticipantId, anchor: string): Unsigned => ({
  subjectId: issuerId,
  issuerId,
  audienceId: AUDIENCE_ID,
  abilities: ["directory"],
  caveats: {},
  proof: null,
  anchor,
  issuedAt: ISSUED_AT
});

/** Signs a record's signature set: one member per signer, over the spec-001 signing input. */
function signSet(unsigned: Unsigned, signers: KeyPair[]): string[] {
  const bytes = canonicalBytes(unsigned);
  return signers.map((pair) => encodeSignature(sign(bytes, pair.secretKey)));
}

type Rejection =
  | "anchor_unknown"
  | "signature_count_not_threshold"
  | "member_verifies_under_no_listed_key"
  | "members_not_injectively_assignable"
  | "members_out_of_key_order";

const CODES: Record<Rejection, string> = {
  anchor_unknown:
    "016: the record's `anchor` names no event of the issuer's key log, so there is no state " +
    "to judge it against. NOT a signature-set rule — it fires before any curve work, and on a " +
    "possibly stale view it is the verdict that says 'refetch the log', not 'this is forged'.",
  signature_count_not_threshold:
    "015 S1's `m = t`, decided against the ANCHORED state. This is what a member deletion " +
    "becomes once the record names its state: the remainder is short of the anchored " +
    "threshold, and the narrower state it would have satisfied is never tried.",
  member_verifies_under_no_listed_key:
    "015 S2 (totality) against the anchored state: some member verifies under none of that " +
    "state's keys. Also what a REWRITTEN anchor produces — the anchor is inside the signing " +
    "input, so changing it invalidates every member of the set.",
  members_not_injectively_assignable:
    "015 S2 (injectivity) against the anchored state: every member verifies, but not under " +
    "distinct keys.",
  members_out_of_key_order:
    "015 S3 against the anchored state: an injective assignment exists but none is strictly " +
    "increasing in key order. This is what a member REORDER becomes under anchoring."
};

type Vector = {
  name: string;
  why: string;
  /** Which @kinnet/protocol schema the record claims to be. */
  schema: "revocation" | "grant";
  /** The issuer's key log, exactly as delivered. */
  events: KeyEvent[];
  /** Per event: the spec-003 digest of the COMPLETE event — the values `anchor` may name. */
  anchors: string[];
  /**
   * A SECOND participant's log, present only on the cross-log vector: the anchor is a genuine
   * event digest of this log and names no event of `events`.
   */
  foreignEvents?: KeyEvent[];
  record: Unsigned & { anchor: string; signature: string[] };
  /** The spec-001 signing input: UTF-8 JCS of the record without its `signature` field. */
  signingInput: string;
  /** The spec-003 digest of the COMPLETE signed record. */
  digest: string;
  /** Whether the named schema accepts the record shape — a separate gate from verification. */
  schemaValid: boolean;
  /** The state the anchor resolves to, or null when it resolves to none. */
  anchoredState: { keys: string[]; threshold: string; seq: string } | null;
  valid: boolean;
  rejection: Rejection | null;
};

const vectors: Vector[] = [];

function vector(
  name: string,
  why: string,
  schema: Vector["schema"],
  source: Log,
  record: Unsigned & { anchor: string; signature: string[] },
  expectation: { valid: true } | { valid: false; rejection: Rejection },
  foreign?: Log
): void {
  const verdict = checkAnchoredSignatureSet(record, source.states, { explain: true });
  if (verdict.ok !== expectation.valid) {
    throw new Error(
      `Vector "${name}" expected valid=${expectation.valid} but the check returned ${
        verdict.ok ? "valid" : `${verdict.code}`
      }`
    );
  }
  if (!verdict.ok && !expectation.valid && verdict.code !== expectation.rejection) {
    throw new Error(
      `Vector "${name}" expected rejection ${expectation.rejection}, got ${verdict.code}`
    );
  }

  const unsigned: Unsigned = { ...record };
  delete unsigned["signature"];
  const state = source.states.find((candidate) => candidate.anchor === record.anchor);

  vectors.push({
    name,
    why,
    schema,
    events: source.events,
    anchors: source.states.map((candidate) => candidate.anchor),
    ...(foreign === undefined ? {} : { foreignEvents: foreign.events }),
    record,
    signingInput: new TextDecoder().decode(canonicalBytes(unsigned)),
    digest: canonicalDigest(record),
    schemaValid: (schema === "revocation" ? revocationSchema : grantSchema).safeParse(record)
      .success,
    anchoredState:
      state === undefined ? null : { keys: state.keys, threshold: state.threshold, seq: state.seq },
    valid: expectation.valid,
    rejection: expectation.valid ? null : expectation.rejection
  });
}

// --- Route 3: cross-state DELETION -----------------------------------------------------------
{
  const anchor = routeThree.states[0]!.anchor;
  const later = routeThree.states[1]!.anchor;
  const unsigned = revocation(routeThree.id, anchor);
  const signature = signSet(unsigned, r3);

  vector(
    "route 3 — the original 3-of-3 revocation, anchored to the inception",
    "The honest record 015's route 3 attacks: three members, one per key of the inception " +
      "state, in key order. It stays valid after the rotation, which is the property 012 " +
      "protects — an anchor names a HISTORICAL state and the log is append-only, so the named " +
      "event is still there however many rotations follow.",
    "revocation",
    routeThree,
    { ...unsigned, anchor, signature },
    { valid: true }
  );

  vector(
    "route 3 — the keyless deletion, anchor unchanged",
    "The attack, executed. Deleting the middle member needs no key at all, and the remaining " +
      "two members verify under the later state's two keys in order — so under 015 S5's " +
      "existential this edited record was VALID, with a different digest, which is what let a " +
      "revoked record be edited into one no revocation names. Under 016 the edit keeps the " +
      "anchor it inherited, the anchored state has threshold 3, and two members are not three: " +
      "the narrower state that would accept it is never tried.",
    "revocation",
    routeThree,
    { ...unsigned, anchor, signature: [signature[0]!, signature[2]!] },
    { valid: false, rejection: "signature_count_not_threshold" }
  );

  vector(
    "route 3 — the keyless deletion with the anchor rewritten to the later state",
    "The obvious next move, and why the anchor is a FIELD OF THE SIGNED RECORD rather than " +
      "metadata: rewriting it to name the state the edit would satisfy changes the signing " +
      "input, so both surviving members stop verifying under anything. The edit that needed no " +
      "key now needs one from the anchored state, which is to say it is not a keyless edit any " +
      "more.",
    "revocation",
    routeThree,
    {
      ...unsigned,
      anchor: later,
      signature: [signature[0]!, signature[2]!]
    },
    { valid: false, rejection: "member_verifies_under_no_listed_key" }
  );
}

{
  const anchor = routeThree.states[0]!.anchor;
  const unsigned = grant(routeThree.id, anchor);
  const signature = signSet(unsigned, r3);
  vector(
    "route 3 — the same shape as a Grant, anchored to the inception",
    "Anchoring is a property of the signature-set record, not of one record type: a Grant with " +
      "a participant issuer carries `anchor` and is decided by the identical rule. Recorded " +
      "because 009 chains grants by digest, so the keyless edit that route 3 describes is worth " +
      "as much against a grant link as against a revocation.",
    "grant",
    routeThree,
    { ...unsigned, anchor, signature },
    { valid: true }
  );

  vector(
    "route 3 — the Grant with its middle member deleted",
    "The same deletion against the same anchored state, on the Grant shape.",
    "grant",
    routeThree,
    { ...unsigned, anchor, signature: [signature[0]!, signature[2]!] },
    { valid: false, rejection: "signature_count_not_threshold" }
  );
}

// --- Route 4: cross-state REORDER ------------------------------------------------------------
{
  const anchor = routeFour.states[0]!.anchor;
  const later = routeFour.states[1]!.anchor;
  const unsigned = revocation(routeFour.id, anchor);
  const signature = signSet(unsigned, r4);

  vector(
    "route 4 — the original 2-of-2 revocation, anchored to the inception",
    "The honest record: two members in the inception state's key order. The rotation reveals " +
      "the same two keys in the OPPOSITE order, which is a legal log — key reuse across states " +
      "is permitted, and 016 is what makes it harmless.",
    "revocation",
    routeFour,
    { ...unsigned, anchor, signature },
    { valid: true }
  );

  vector(
    "route 4 — the members swapped, anchor unchanged",
    "Swapping the two members is keyless and gives a second byte-form with a second digest. " +
      "Against the permuted later state it conforms; against the ANCHORED state it is out of " +
      "key order, which is 015 S3, and the permuted state is never tried. Note m = t = 2 on " +
      "both sides, so the exact-count rule gives no protection here at all — the anchor is " +
      "what does.",
    "revocation",
    routeFour,
    { ...unsigned, anchor, signature: [signature[1]!, signature[0]!] },
    { valid: false, rejection: "members_out_of_key_order" }
  );

  vector(
    "route 4 — the first member duplicated in place of the second",
    "The third keyless edit of the family, alongside deletion and reordering: repeat a member " +
      "instead of dropping one, and the count rule is satisfied. It fails S2's injectivity — " +
      "both members verify under the anchored state's first key and nothing assigns them " +
      "distinct ones — which is the rule that makes 'm members' mean 'm signers'.",
    "revocation",
    routeFour,
    { ...unsigned, anchor, signature: [signature[0]!, signature[0]!] },
    { valid: false, rejection: "members_not_injectively_assignable" }
  );

  vector(
    "route 4 — the members swapped with the anchor rewritten to the permuted state",
    "As with route 3: naming the state the reorder would satisfy changes the signed bytes, and " +
      "neither member verifies any more.",
    "revocation",
    routeFour,
    { ...unsigned, anchor: later, signature: [signature[1]!, signature[0]!] },
    { valid: false, rejection: "member_verifies_under_no_listed_key" }
  );
}

// --- Variant G: the key set grows ------------------------------------------------------------
{
  const anchor = variantG.states[1]!.anchor;
  const unsigned = revocation(variantG.id, anchor);
  const signature = signSet(unsigned, vg);

  vector(
    "variant G — the 2-of-2 record anchored to the rotation, on a log that now REPLAYS VALID",
    "015's variant G: `[K0] t=1` growing to `[K0,K1] t=2`, so the states share a quorum. An " +
      "earlier interim log rule refused this log outright; 016 accepts it and closes the attack " +
      "in the record instead. The honest record here is signed under the LATER state.",
    "revocation",
    variantG,
    { ...unsigned, anchor, signature },
    { valid: true }
  );

  vector(
    "variant G — the deletion that a backwards-looking log rule would have missed",
    "Dropping the second member leaves one that verifies under the inception's single key at " +
      "threshold 1 — the attack does not care which state came first, which is why log-shape " +
      "rules phrased over 'an earlier state' missed it. Anchored, the record still names the " +
      "rotation, one member is not two, and the inception state is never tried.",
    "revocation",
    variantG,
    { ...unsigned, anchor, signature: [signature[0]!] },
    { valid: false, rejection: "signature_count_not_threshold" }
  );
}

// --- Variant P: partial rotation keeping a quorum ---------------------------------------------
{
  const anchor = variantP.states[0]!.anchor;
  const unsigned = revocation(variantP.id, anchor);
  const signature = signSet(unsigned, [vp[0]!, vp[1]!, vp[2]!]);

  vector(
    "variant P — the 3-of-3 record anchored to the inception, on a log that now REPLAYS VALID",
    "015's variant P: `[K0,K1,K2] t=3` rotating to `[K0,K1,K3] t=2` — it retires a key, " +
      "introduces a key, and keeps two. Neither key list is a subset or a permutation of the " +
      "other, which is why every narrow log-shape rule accepted it while it remained a working " +
      "attack; the only log rule that caught it also forbade the partial rotation operators " +
      "actually want. 016 makes the log legal again.",
    "revocation",
    variantP,
    { ...unsigned, anchor, signature },
    { valid: true }
  );

  vector(
    "variant P — the deletion, refused against the anchored state",
    "Dropping the third member leaves two that conform against the later 2-of-3. The anchored " +
      "state's threshold is 3, so the record is refused there and the later state is not " +
      "consulted. This is the vector that shows anchoring delivers what no key-list rule could: " +
      "the attack is closed AND the partial rotation stays legal.",
    "revocation",
    variantP,
    { ...unsigned, anchor, signature: [signature[0]!, signature[1]!] },
    { valid: false, rejection: "signature_count_not_threshold" }
  );
}

// --- Anchors that resolve to nothing ----------------------------------------------------------
{
  // A well-formed multihash of bytes no event of this log ever produced.
  const unknown = canonicalDigest({ note: "not a key event of any log" });
  const reanchored = { ...revocation(routeThree.id, unknown), anchor: unknown };

  vector(
    "unknown anchor — a well-formed digest naming no event of the issuer's log",
    "The record is honestly signed over its own bytes by all three inception keys, so nothing " +
      "about the signature set is wrong; the anchor simply resolves to no state. 016 makes this " +
      "a refusal rather than an invitation to try the states that ARE present — falling back to " +
      "a search would restore S5's existential through the back door. On a view that may be " +
      "stale a verifier SHOULD refetch the log once before concluding, which is why this " +
      "rejection is its own class.",
    "revocation",
    routeThree,
    { ...reanchored, signature: signSet(reanchored, r3) },
    { valid: false, rejection: "anchor_unknown" }
  );
}

{
  const foreignAnchor = stranger.states[0]!.anchor;
  const unsigned = revocation(routeThree.id, foreignAnchor);
  vector(
    "cross-log anchor — a genuine event digest, from a DIFFERENT participant's log",
    "The anchor is real: it is the inception digest of `foreignEvents`, a valid log of another " +
      "participant. It is still unknown to the issuer's log, and that is the whole question — " +
      "an anchor selects a state WITHIN the log the record's issuer id resolves to, and never " +
      "carries a log with it. A verifier that resolved anchors globally would let anyone graft " +
      "a state they control onto someone else's record.",
    "revocation",
    routeThree,
    { ...unsigned, anchor: foreignAnchor, signature: signSet(unsigned, r3) },
    { valid: false, rejection: "anchor_unknown" },
    stranger
  );
}

// --- Anchoring does not orphan, and does not float --------------------------------------------
{
  const anchor = rotatingLog.states[1]!.anchor;
  const unsigned = revocation(rotatingLog.id, anchor);
  vector(
    "non-tip anchor — an honest record anchored two rotations before the log's tip",
    "The property that separates anchoring from 'verify against the current state', which 012 " +
      "forbids: this record names the state at seq 1, the log has since rotated to seq 2, and " +
      "the record is still valid. An append-only log keeps the named event forever, so an " +
      "anchored record survives any number of later rotations.",
    "revocation",
    rotatingLog,
    { ...unsigned, anchor, signature: signSet(unsigned, [rotating[1]!]) },
    { valid: true }
  );
}

{
  const earlier = rotatingLog.states[1]!.anchor;
  const unsigned = revocation(rotatingLog.id, earlier);
  vector(
    "misdirected anchor — a set satisfying the current state, anchored to the earlier one",
    "The converse of the vector above, and the reason the rule is a lookup rather than a hint. " +
      "This record is internally consistent: the anchor naming seq 1 is inside the signing " +
      "input, and the single member verifies — under the key of the CURRENT state at seq 2, " +
      "which is the state the set genuinely satisfies. A verifier that searched the log for a " +
      "state the set fits would find that one and accept. 016 tries exactly one state, the one " +
      "the record names, and against seq 1 the member verifies under no listed key. A record " +
      "whose set fails against its anchored state is invalid even where another state of the " +
      "same log accepts it.",
    "revocation",
    rotatingLog,
    { ...unsigned, anchor: earlier, signature: signSet(unsigned, [rotating[2]!]) },
    { valid: false, rejection: "member_verifies_under_no_listed_key" }
  );
}

// --- A rotation that retains a quorum, with records anchored to each state ---------------------
{
  const first = sharedQuorum.states[0]!.anchor;
  const second = sharedQuorum.states[1]!.anchor;

  const early = revocation(sharedQuorum.id, first);
  const earlySignature = signSet(early, [q[0]!, q[1]!]);
  vector(
    "shared quorum — a record anchored to the earlier of two 2-of-3 states",
    "A rotation that retires one key of three, introduces one, and keeps two: the states share " +
      "a quorum, which an earlier interim log rule forbade and 016 permits. This record names " +
      "the earlier state and satisfies it.",
    "revocation",
    sharedQuorum,
    { ...early, anchor: first, signature: earlySignature },
    { valid: true }
  );

  const late = revocation(sharedQuorum.id, second);
  vector(
    "shared quorum — a record anchored to the later of two 2-of-3 states",
    "The same log, the same two signing keys — they are retained across the rotation — and the " +
      "later state named instead. Also valid. Both records are honest and each is judged " +
      "against its own state, which is what makes the shared quorum harmless: no record is ever " +
      "offered to both.",
    "revocation",
    sharedQuorum,
    { ...late, anchor: second, signature: signSet(late, [q[0]!, q[1]!]) },
    { valid: true }
  );

  vector(
    "shared quorum — the earlier state's set offered under the later state's anchor",
    "The shared quorum's keys are listed in both states at the same threshold, so under 015 " +
      "S5's existential a set valid against one was automatically worth trying against the " +
      "other. Anchoring removes the question: the anchor is signed, so re-pointing it at the " +
      "other state leaves the members verifying under nothing.",
    "revocation",
    sharedQuorum,
    { ...early, anchor: second, signature: earlySignature },
    { valid: false, rejection: "member_verifies_under_no_listed_key" }
  );
}

const target = new URL("../test/fixtures/record-anchoring-vectors.json", import.meta.url);
writeFileSync(
  target,
  `${JSON.stringify(
    {
      note:
        "Conformance vectors for spec 016 (record anchoring): a signature-set record naming, by " +
        "key-event digest, the ONE key state it is judged against. Every vector is verifiable " +
        "from bytes alone. `events` is the issuer's key log exactly as delivered and every one " +
        "of them REPLAYS VALID per spec 003, including the logs whose states share a quorum. " +
        "`anchors[i]` is the spec-003 digest of the complete event i — the values `record.anchor` " +
        "may name, and the same values event i+1's `prior` carries. `signingInput` is the UTF-8 " +
        "JCS of the record WITHOUT its `signature` field (spec 001), so a reader can see that " +
        "`anchor` is inside the signed bytes; `digest` is the spec-003 multihash of the complete " +
        "signed record. `anchoredState` is the state the anchor resolves to, or null when it " +
        "resolves to none. `valid` is the 016 verdict: the log replays, the anchor names an " +
        "event of it, and the set satisfies 015 S0-S3 against THAT state and no other. For a " +
        "refusal, `rejection` is the normative class (see `codes`). `schemaValid` is the " +
        "separate question of whether @kinnet/protocol's schema for `schema` accepts the record " +
        "shape. Historical note: the pre-016 reference implementation's interim spec-003 quorum " +
        "rule rejected the route-3, route-4, variant-G and variant-P logs outright, so those " +
        "edits were never reachable in shipped code; the vectors demonstrate the attack on 015 " +
        "S5's rule as stated, which 016 closes structurally while making those logs legal again. " +
        "Regenerate with packages/crypto/scripts/generate-record-anchoring-fixtures.ts.",
      codes: CODES,
      vectors
    },
    null,
    2
  )}\n`
);

const rejected = vectors.filter((entry) => !entry.valid).length;
console.log(
  `Wrote ${vectors.length} record-anchoring vectors (${rejected} rejections, ${
    vectors.length - rejected
  } accepted) to ${target.pathname}`
);
