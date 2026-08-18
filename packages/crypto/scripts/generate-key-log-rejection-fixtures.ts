/**
 * Regenerates the committed spec-003 key-log replay/rotation vectors from deterministic seeds.
 * A change to spec 003, spec 015 or `replayKeyLog`'s rejection wording updates this script and
 * the fixture together.
 *
 * The suite is deliberately REJECTION-heavy. An acceptance-only fixture is weaker than it looks:
 * the committed identity fixture carries one 1-of-1 inception, no rotation, no threshold above
 * one and no rejection vector at all, so an independent implementation with broken chaining,
 * sequencing, pre-rotation or threshold handling passes it. Every rejection below is isolated to
 * ONE rule wherever the rule can be violated on its own: the surrounding event is otherwise
 * honest and honestly re-signed, so a vector cannot pass for the wrong reason.
 *
 * Run from the repo root (after `pnpm build`). BOTH commands, in order — this script writes
 * `JSON.stringify(…, null, 2)` and the committed file is prettier-formatted, so skipping the
 * second step leaves a diff that is pure formatting and makes the fixture look non-reproducible:
 *
 *   pnpm exec tsx packages/crypto/scripts/generate-key-log-rejection-fixtures.ts
 *   pnpm exec prettier --write packages/crypto/test/fixtures/key-log-rejection-vectors.json
 */
import { writeFileSync } from "node:fs";

import {
  canonicalBytes,
  canonicalDigest,
  commitToKeyState,
  deriveParticipantId,
  encodeKeyRef,
  encodeSignature,
  generateKeyPair,
  replayKeyLog,
  replayKeyLogFor,
  sign,
  type KeyPair,
  type KeyState
} from "@kinnet/crypto";
import { keyEventLogSchema, type KeyEvent, type ParticipantId } from "@kinnet/protocol";

const seed = (fill: number) => new Uint8Array(32).fill(fill);
const keyPair = (fill: number): KeyPair => generateKeyPair(seed(fill));
const ref = (pair: KeyPair): string => encodeKeyRef(pair.publicKey);

type Unsigned = Omit<KeyEvent, "signature">;

/** The spec-001 signing input's shape: the event with its `signature` field removed. */
function stripSignature(event: KeyEvent): Record<string, unknown> {
  const unsigned: Record<string, unknown> = { ...event };
  delete unsigned.signature;
  return unsigned;
}

/** Signs an event with the given keys, in the given order (015 S3's canonical order). */
function mint(unsigned: Unsigned, signers: KeyPair[]): KeyEvent {
  const bytes = canonicalBytes(unsigned);
  return {
    ...unsigned,
    signature: signers.map((pair) => encodeSignature(sign(bytes, pair.secretKey)))
  };
}

type Establishment = {
  /** The keys this event reveals, in order. */
  keys: KeyPair[];
  /** The threshold this event declares. */
  threshold: string;
  /** The keys the NEXT event must reveal — hashed into `next`, never disclosed here. */
  nextKeys: KeyPair[];
  /** The threshold the NEXT event must declare — inside the commitment (003, _The committed next key state_). */
  nextThreshold: string;
  /**
   * The commitment to write into `next`, bypassing {@link commitToKeyState}.
   *
   * Only for the state-repeats-key vector: the helper refuses to commit to a state no
   * conforming event could reveal, which is the right behaviour on the commit side and would
   * make the REVEAL-side rule untestable from bytes. The value is what the helper would have
   * computed — the digest of `{keys, threshold}` — so the vector still names a commitment a
   * rotation can reproduce.
   */
  nextCommitment?: string;
};

/** The pre-rotation commitment this establishment carries (003, _The committed next key state_). */
function commitment(shape: Establishment): string {
  return shape.nextCommitment ?? commitToKeyState(shape.nextKeys.map(ref), shape.nextThreshold);
}

/** An honest inception: the participant id hashes exactly this establishment data (002). */
function inception(shape: Establishment, signers = shape.keys): KeyEvent {
  const establishment = {
    seq: "0",
    kind: "icp" as const,
    keys: shape.keys.map(ref),
    threshold: shape.threshold,
    next: commitment(shape)
  };
  const id = deriveParticipantId(establishment);
  return mint({ ...establishment, id, prior: null }, signers);
}

/** An honest rotation chained to `previous`. Overrides are applied BEFORE signing. */
function rotation(
  previous: KeyEvent,
  shape: Establishment,
  options: { signers?: KeyPair[]; override?: Partial<Unsigned> } = {}
): KeyEvent {
  const unsigned: Unsigned = {
    id: previous.id,
    seq: String(Number(previous.seq) + 1),
    prior: canonicalDigest(previous),
    kind: "rot",
    keys: shape.keys.map(ref),
    threshold: shape.threshold,
    next: commitment(shape),
    ...options.override
  };
  return mint(unsigned, options.signers ?? shape.keys);
}

// ---------------------------------------------------------------------------------------------
// Key material. Distinct seeds per role so a vector's failure names a key a reader can find.
// ---------------------------------------------------------------------------------------------
const root = keyPair(1); //  the 1-of-1 inception key
const rotated = keyPair(2); //  the key the 1-of-1 inception commits to
const future = keyPair(3); //  what the rotation commits to in turn
const committee = [keyPair(11), keyPair(12)]; // a committed 2-of-2 next state
const beyond = [keyPair(13), keyPair(14)]; //  what that committee commits to
const uncommitted = keyPair(21); //  a key no commitment ever names
const outsider = keyPair(22); //  a key no state ever lists

/** The 1-of-1 shape every documented first-party participant has. */
const ONE_OF_ONE: Establishment = {
  keys: [root],
  threshold: "1",
  nextKeys: [rotated],
  nextThreshold: "1"
};
/** A 1-of-1 inception that pre-commits a 2-of-2 committee — the M-of-N rotation under test. */
const COMMITS_COMMITTEE: Establishment = {
  keys: [root],
  threshold: "1",
  nextKeys: committee,
  nextThreshold: "2"
};

type Rejection =
  | "chain_prior_mismatch"
  | "sequence_not_contiguous"
  | "signature_count_not_threshold"
  | "signature_set_not_conforming"
  | "commitment_not_reproduced"
  | "state_repeats_key"
  | "work_budget_exceeded"
  | "participant_mismatch";

const CODES: Record<Rejection, string> = {
  chain_prior_mismatch:
    "An event's `prior` is not the digest of the event before it (003). The hash chain is what " +
    "makes a log an append-only history rather than a bag of events.",
  sequence_not_contiguous:
    "`seq` is not the previous event's `seq` plus one (003) — a gap, a repeat, or a jump.",
  signature_count_not_threshold:
    "The event carries a number of signatures other than exactly its threshold (015 S1's " +
    "`m = t`). Counted before any curve work.",
  signature_set_not_conforming:
    "015 S2/S3: some member does not verify under a distinct listed key in strictly increasing " +
    "key order. Covers a signature by an unlisted key and a tampered event body alike — the " +
    "verifier learns only that the set does not conform, which is all it can honestly report.",
  commitment_not_reproduced:
    "A rotation's `{keys, threshold}` does not reproduce the PRIOR event's `next` commitment " +
    "(003, _The committed next key state_). The threshold is inside the commitment, so a " +
    "rotation cannot restate it — this is the rule that closes the lowered-threshold rotation.",
  state_repeats_key:
    "015 S0: the event's key list holds the same key twice, so the state is invalid and every " +
    "record checked against it is invalid with it.",
  work_budget_exceeded:
    "The replay would spend more Ed25519 verifications than its budget allows. NOT a verdict on " +
    "the log — a refusal to spend CPU on attacker-supplied input — so it is a distinct class.",
  participant_mismatch:
    "The log is internally valid and belongs to a DIFFERENT participant than the caller asked " +
    "for: the substituted-log attack, refused by `replayKeyLogFor`."
};

type Vector = {
  name: string;
  why: string;
  valid: boolean;
  /** Present when the caller binds the log to an expected participant (`replayKeyLogFor`). */
  expectedId?: ParticipantId;
  /** Replay options the vector is judged under; absent means the defaults. */
  options?: { maxSignatureVerifications?: number };
  events: KeyEvent[];
  /** Per event: UTF-8 JCS of the event WITHOUT its `signature` field — the signing input (001). */
  signingInputs: string[];
  /** Per event: the spec-003 digest of the COMPLETE event, which the next event's `prior` names. */
  digests: string[];
  /** Whether `keyEventLogSchema` accepts the array — a separate question from replay validity. */
  schemaValid: boolean;
  /** The resulting key state, for accepted logs only. */
  state: KeyState | null;
  /** Which rule refused the log, for rejected logs only. */
  rejection: Rejection | null;
  /** The reference implementation's exact throw, for rejected logs only. */
  error: { name: string; message: string } | null;
};

function vector(
  name: string,
  why: string,
  events: KeyEvent[],
  expectation:
    | { valid: true }
    | { valid: false; rejection: Rejection }
    | { valid: false; rejection: Rejection; expectedId: ParticipantId },
  options?: { maxSignatureVerifications?: number }
): Vector {
  const replayOptions = options ?? {};
  const expectedId = "expectedId" in expectation ? expectation.expectedId : undefined;

  let state: KeyState | null = null;
  let error: { name: string; message: string } | null = null;
  try {
    state =
      expectedId === undefined
        ? replayKeyLog(events, replayOptions)
        : replayKeyLogFor(expectedId, events, replayOptions);
  } catch (thrown) {
    const caught = thrown as Error;
    error = { name: caught.name, message: caught.message };
  }

  if (expectation.valid !== (error === null)) {
    throw new Error(
      `Vector "${name}" expected valid=${expectation.valid} but the replay ${
        error === null ? "accepted" : `threw: ${error.message}`
      }`
    );
  }

  const signingInputs = events.map((event) =>
    new TextDecoder().decode(canonicalBytes(stripSignature(event)))
  );

  return {
    name,
    why,
    valid: expectation.valid,
    ...(expectedId === undefined ? {} : { expectedId }),
    ...(options === undefined ? {} : { options }),
    events,
    signingInputs,
    digests: events.map((event) => canonicalDigest(event)),
    // The schema's own answer, recorded rather than assumed: replay and schema are separate
    // gates, and a log the schema already refuses never reaches the rule the vector is about.
    schemaValid: keyEventLogSchema.safeParse(events).success,
    state,
    rejection: expectation.valid ? null : expectation.rejection,
    error
  };
}

// ---------------------------------------------------------------------------------------------
// Accepted logs. Present so the suite cannot pass by rejecting everything, and so a third party
// has the honest shapes to check its replay against before checking its refusals.
// ---------------------------------------------------------------------------------------------
const icp = inception(ONE_OF_ONE);
const rot = rotation(icp, {
  keys: [rotated],
  threshold: "1",
  nextKeys: [future],
  nextThreshold: "1"
});

const icpCommittee = inception(COMMITS_COMMITTEE);
const rotCommittee = rotation(icpCommittee, {
  keys: committee,
  threshold: "2",
  nextKeys: beyond,
  nextThreshold: "2"
});

const vectors: Vector[] = [
  vector(
    "accepted — 1-of-1 inception alone",
    "The shape every documented first-party participant has: one key, threshold 1, one " +
      "signature, and a commitment to a next state nobody has revealed yet. The participant id " +
      "is the digest of the establishment data ({seq, kind, keys, threshold, next}), so a " +
      "third party can rederive it from these bytes without any signature.",
    [icp],
    { valid: true }
  ),
  vector(
    "accepted — 1-of-1 rotation revealing the committed key",
    "The rotation reveals exactly the key the inception committed to, declares the committed " +
      "threshold, chains to the inception's digest, and is signed by the REVEALED key (KERI " +
      "semantics — recoverable when the outgoing key is lost or stolen). The id does not change.",
    [icp, rot],
    { valid: true }
  ),
  vector(
    "accepted — rotation revealing a committed 2-of-2 committee",
    "A 1-of-1 identity growing into a committee, which is the only way the shape of a key " +
      "state may change: the inception commits {two keys, threshold 2} and the rotation reveals " +
      "exactly that, carrying exactly two signatures in key order. An implementation that " +
      "handles only threshold 1 fails HERE rather than silently on a rejection vector.",
    [icpCommittee, rotCommittee],
    { valid: true }
  ),

  // -------------------------------------------------------------------------------------------
  // Chain and sequence.
  // -------------------------------------------------------------------------------------------
  vector(
    "rejected — the rotation's `prior` is not the inception's digest",
    "Isolated to the chain rule: the event is re-signed after the override, so its signature " +
      "set conforms and only `prior` is wrong. The value used is the digest of a DIFFERENT " +
      "honest inception (the committee one), which is the realistic shape — a splice from " +
      "another log, not random bytes.",
    [
      icp,
      rotation(
        icp,
        { keys: [rotated], threshold: "1", nextKeys: [future], nextThreshold: "1" },
        { override: { prior: canonicalDigest(icpCommittee) } }
      )
    ],
    { valid: false, rejection: "chain_prior_mismatch" }
  ),
  vector(
    "rejected — a sequence gap: seq jumps from 0 to 2",
    "Everything else is honest, including `prior`, which still names the inception. A verifier " +
      "that checked only the hash chain would accept this log and read a two-event history as " +
      "three events long — which is how a log with a withheld middle event would read.",
    [
      icp,
      rotation(
        icp,
        { keys: [rotated], threshold: "1", nextKeys: [future], nextThreshold: "1" },
        { override: { seq: "2" } }
      )
    ],
    { valid: false, rejection: "sequence_not_contiguous" }
  ),
  vector(
    "rejected — a duplicated sequence number: two events at seq 1",
    "The third event chains correctly to the second (its `prior` is the second's digest) and " +
      "reveals the correctly committed key state, so the ONLY thing wrong with it is that it " +
      "restates seq 1. The contiguity rule is what makes `seq` an index rather than a label.",
    (() => {
      const second = rotation(icp, {
        keys: [rotated],
        threshold: "1",
        nextKeys: [future],
        nextThreshold: "1"
      });
      const third = rotation(
        second,
        { keys: [future], threshold: "1", nextKeys: [uncommitted], nextThreshold: "1" },
        { override: { seq: "1" } }
      );
      return [icp, second, third];
    })(),
    { valid: false, rejection: "sequence_not_contiguous" }
  ),

  // -------------------------------------------------------------------------------------------
  // Threshold and signature set.
  // -------------------------------------------------------------------------------------------
  vector(
    "rejected — a 2-of-2 rotation carrying one signature",
    "The committed threshold is met by the DECLARED threshold but not by the signature count: " +
      "the rotation reveals the committed committee and declares `2`, so the commitment check " +
      "passes, and it then fails 015 S1's `m = t` with one member against a threshold of two. " +
      "The signature it does carry is genuine and verifies under key 0, so nothing but the " +
      "count is wrong — this is the vector that catches an implementation reading the threshold " +
      "as a floor it forgot to apply. `schemaValid` is false: `keyEventSchema` enforces `m = t` " +
      "too, so a delivery over HTTP never reaches the replay. The replay still owns the rule, " +
      "because its parameter is a bare event array rather than a parsed log.",
    [
      icpCommittee,
      rotation(
        icpCommittee,
        { keys: committee, threshold: "2", nextKeys: beyond, nextThreshold: "2" },
        { signers: [committee[0]!] }
      )
    ],
    { valid: false, rejection: "signature_count_not_threshold" }
  ),
  vector(
    "rejected — the inception is signed by a key it does not list",
    "A well-formed Ed25519 signature over exactly these bytes, by a key that appears in no " +
      "state. The participant id still derives correctly, because the id hashes the " +
      "establishment data and the signature is not part of it — so an implementation that " +
      "checked the id and skipped the curve would accept a log anyone could mint for any " +
      "establishment data.",
    [inception(ONE_OF_ONE, [outsider])],
    { valid: false, rejection: "signature_set_not_conforming" }
  ),
  vector(
    "rejected — a tampered event body under a genuine signature",
    "The honest rotation's `next` commitment is replaced after signing, and the original " +
      "signature is kept. Every structural check still passes: the chain digest is unchanged, " +
      "`seq` is contiguous, and the pre-rotation commitment covers `{keys, threshold}` rather " +
      "than `next`, so the commitment check cannot see this edit. Only the signature can — the " +
      "signing input is the whole event minus its signature array, and that is the point of " +
      "signing it. An implementation that verified signatures over the establishment data alone " +
      "would accept this and let anyone rewrite where the log rotates NEXT.",
    [icp, { ...rot, next: commitToKeyState([ref(uncommitted)], "1") }],
    { valid: false, rejection: "signature_set_not_conforming" }
  ),
  vector(
    "rejected — an event listing the same key twice",
    "The commitment names {[K, K], threshold 2} and the rotation reveals exactly that, so the " +
      "commitment check passes and 015 S0 is the only rule violated. Two signatures by the one " +
      "key would satisfy an INDEX-based reading of the threshold — one key counted twice — " +
      "which is why the state itself is invalid rather than the record merely failing against " +
      "it. The commitment is written directly rather than through `commitToKeyState`, which " +
      "refuses to commit to a state no conforming event could reveal — the reveal-side rule is " +
      "what this vector pins, and it must hold for bytes that arrive from anywhere. " +
      "`schemaValid` is " +
      "false — `keyEventSchema` carries the same rule, so both gates hold it, which is the " +
      "state 015 S0 asked for after the rule spent a while living only in the replay.",
    (() => {
      const repeats: Establishment = {
        keys: [root],
        threshold: "1",
        nextKeys: [rotated, rotated],
        nextThreshold: "2",
        nextCommitment: canonicalDigest({ keys: [ref(rotated), ref(rotated)], threshold: "2" })
      };
      const first = inception(repeats);
      return [
        first,
        rotation(first, {
          keys: [rotated, rotated],
          threshold: "2",
          nextKeys: [future],
          nextThreshold: "1"
        })
      ];
    })(),
    { valid: false, rejection: "state_repeats_key" }
  ),

  // -------------------------------------------------------------------------------------------
  // Pre-rotation: the prior event's commitment governs, threshold included (003).
  // -------------------------------------------------------------------------------------------
  vector(
    "rejected — the committed committee revealed at a LOWERED threshold",
    "The attack the commitment's threshold half exists to stop, executed. A holder of ONE key " +
      "from the committed 2-of-2 set reveals exactly the committed keys — the key list matches " +
      'byte for byte — declares `threshold: "1"`, signs once, and would take sole control of ' +
      "an M-of-N identity, then rotate again to keys only they hold. Because the commitment " +
      'covers {keys, threshold} rather than the key list alone, `commitToKeyState(keys, "1")` ' +
      "does not reproduce the prior `next`, and the log is refused BEFORE any signature is " +
      "verified. Note what the vector proves about ordering: the PRIOR event's commitment " +
      "governs, never the new event's own declaration.",
    [
      icpCommittee,
      rotation(
        icpCommittee,
        { keys: committee, threshold: "1", nextKeys: beyond, nextThreshold: "2" },
        { signers: [committee[0]!] }
      )
    ],
    { valid: false, rejection: "commitment_not_reproduced" }
  ),
  vector(
    "rejected — a rotation revealing keys that were never committed",
    "Pre-rotation in its plainest form: the inception committed to `rotated`, and this event " +
      "reveals a key nobody committed to, honestly signed by that key. This is what a stolen " +
      "current key buys an attacker — nothing — because the next key state was fixed one event " +
      "ago and the thief does not hold it.",
    [
      icp,
      rotation(icp, {
        keys: [uncommitted],
        threshold: "1",
        nextKeys: [future],
        nextThreshold: "1"
      })
    ],
    { valid: false, rejection: "commitment_not_reproduced" }
  ),
  // -------------------------------------------------------------------------------------------
  // Key reuse across states. Two states of one log may share keys, and may share a quorum of
  // them (spec 016): the cross-state routes are closed by anchoring the RECORD, not by
  // constraining rotation shape.
  // -------------------------------------------------------------------------------------------
  vector(
    "accepted — two committed states sharing a quorum",
    "A log whose rotation RE-REVEALS its own key set at the same threshold: the two states " +
      "share both keys against a threshold of two. Valid, and deliberately pinned as valid. An " +
      "earlier interim rule refused exactly this shape to keep 015's keyless cross-state " +
      "deletion and reordering routes out of reach; spec 016 closes those routes inside the " +
      "record instead — a signature-set record names the one state it is judged against — so " +
      "rotation flexibility comes back and a 2-of-3 may again retain two keys. Both events are " +
      "individually valid: the rotation reveals exactly the committed key state and carries " +
      "exactly its two signatures in key order.",
    (() => {
      const shared: Establishment = {
        keys: committee,
        threshold: "2",
        nextKeys: committee,
        nextThreshold: "2"
      };
      const first = inception(shared);
      return [
        first,
        rotation(first, {
          keys: committee,
          threshold: "2",
          nextKeys: beyond,
          nextThreshold: "2"
        })
      ];
    })(),
    { valid: true }
  ),
  vector(
    "accepted — a 2-of-3 rotation retaining two of its three keys",
    "The partial rotation the interim rule cost and spec 016 gives back: the rotation retires " +
      "one key, introduces one, and keeps two against a threshold of two — a shared quorum. It " +
      "replays valid. Records signed under either state stay verifiable, each against the " +
      "state its own anchor names, which is what makes the shared quorum harmless: no record " +
      "is ever offered to both states.",
    (() => {
      const before = [keyPair(31), keyPair(32), keyPair(33)];
      const after = [before[0]!, before[1]!, keyPair(34)];
      const shape: Establishment = {
        keys: before,
        threshold: "2",
        nextKeys: after,
        nextThreshold: "2"
      };
      const first = inception(shape, before.slice(0, 2));
      return [
        first,
        rotation(
          first,
          { keys: after, threshold: "2", nextKeys: [keyPair(35), keyPair(36)], nextThreshold: "2" },
          { signers: after.slice(0, 2) }
        )
      ];
    })(),
    { valid: true }
  ),

  // -------------------------------------------------------------------------------------------
  // The two refusals that are NOT verdicts on the log's contents.
  // -------------------------------------------------------------------------------------------
  vector(
    "rejected — an honest log refused by the work bound",
    "The accepted two-event log above, replayed under a budget of one Ed25519 verification. " +
      "The inception spends it, and the rotation is refused before spending a second. This is " +
      "the pre-auth posture: a replay an unauthenticated caller commands is metered, and the " +
      "refusal is a REFUSAL TO SPEND rather than a verdict — a caller must not cache it as " +
      "'this log is invalid', which is why it is its own error class.",
    [icp, rot],
    { valid: false, rejection: "work_budget_exceeded" },
    { maxSignatureVerifications: 1 }
  ),
  vector(
    "rejected — a perfectly valid log served for the wrong participant",
    "The substituted-log attack. The committee log is internally flawless; it simply is not the " +
      "log the caller asked for. A replay that discards the self-derived id — which is a claim " +
      "the log makes about itself, never a confirmation of whose log it is — lets an untrusted " +
      "discovery host serve attacker A's log at victim V's path and makes every record naming V " +
      "verify under A's keys. The binding is the whole defence, so it is a vector.",
    [icpCommittee, rotCommittee],
    { valid: false, rejection: "participant_mismatch", expectedId: icp.id }
  )
];

const target = new URL("../test/fixtures/key-log-rejection-vectors.json", import.meta.url);
writeFileSync(
  target,
  `${JSON.stringify(
    {
      note:
        "Replay conformance vectors for spec 003's key-history log — chaining, sequencing, " +
        "pre-rotation (including the committed THRESHOLD), spec 015's signature-set rules as " +
        "the log applies them, the work bound, and the participant binding. " +
        "Every vector is verifiable from bytes alone: `events` is the log exactly as delivered, " +
        "`signingInputs[i]` is the UTF-8 JCS of event i WITHOUT its `signature` field (the " +
        "spec-001 signing input), and `digests[i]` is the spec-003 multihash of the COMPLETE " +
        "event i, which event i+1's `prior` must name. `valid` is the replay verdict. For a " +
        "rejected log, `rejection` is the normative class (see `codes`) and `error` is the " +
        "reference implementation's exact throw — recorded so this repo's test can assert it " +
        "byte for byte, NOT as a wire contract another implementation must reproduce; conform " +
        "to `rejection`, not to the English. For an accepted log, `state` is the resulting key " +
        "state. `expectedId`, when present, means the log is judged with the participant " +
        "binding (`replayKeyLogFor`); `options` carries the replay options the verdict assumes. " +
        "Regenerate with packages/crypto/scripts/generate-key-log-rejection-fixtures.ts.",
      codes: CODES,
      vectors
    },
    null,
    2
  )}\n`
);

const rejected = vectors.filter((entry) => !entry.valid).length;
console.log(
  `Wrote ${vectors.length} key-log vectors (${rejected} rejections, ${
    vectors.length - rejected
  } accepted) to ${target.pathname}`
);
