/**
 * Key-history log — spec 003 (KERI-lite with pre-rotation) and spec 002 (the
 * participant ID hashes the inception event's establishment data).
 */
import {
  MAX_KEY_EVENT_KEYS,
  MAX_KEY_LOG_EVENTS,
  type KeyEvent,
  type KeyRef,
  type ParticipantId
} from "@kinnet/protocol";

import {
  DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS,
  safeVerificationCount,
  VerificationBudgetExceeded
} from "./budget.js";
import { decodeKeyRef, decodeSignature, encodeKeyRef, encodeSignature } from "./encoding.js";
import { canonicalBytes } from "./jcs.js";
import { generateKeyPair, sign, verify, type KeyPair } from "./keys.js";
import { canonicalDigest } from "./records.js";
import {
  checkKeyState,
  checkMemberCount,
  parseThreshold,
  walkSignatureSet
} from "./signature-set.js";

export type Identity = {
  id: ParticipantId;
  log: KeyEvent[];
  /** Active signing keys. */
  currentKeys: KeyPair[];
  /** Pre-committed next keys — keep in split custody per spec 003. */
  nextKeys: KeyPair[];
  /**
   * The threshold committed for {@link nextKeys}, i.e. the `threshold` the next rotation
   * MUST declare and the number of signatures it MUST carry. Part of the pre-rotation
   * commitment (see {@link commitToKeyState}), so it is not the rotating party's to choose.
   *
   * `null` when this holder holds no next keys — the custody-exit handover, where the
   * commitment names a state only someone else can reveal. Such an identity cannot rotate.
   */
  nextThreshold: string | null;
};

type EstablishmentData = {
  seq: string;
  kind: "icp" | "rot";
  keys: KeyRef[];
  threshold: string;
  next: string;
};

/**
 * The pre-rotation commitment: digest of the next key **state** — its ordered key list AND
 * the threshold that state will require (spec 003, _The committed next key state_).
 *
 * The threshold is inside the commitment, not merely alongside it. A commitment over the key
 * list alone leaves the rotating event free to name its own threshold, and a rotation's
 * signature count is judged against the threshold the event declares — so a holder of ONE key
 * in a multi-key committed set could reveal that set at `threshold: "1"`, sign once, and take
 * sole control of an M-of-N identity. Committing the threshold removes that free parameter:
 * the prior event decides how strongly the next event must be signed, and the rotating party
 * cannot restate it.
 *
 * Refuses a threshold outside 015 S1's `^[1-9][0-9]*$` domain. A commitment is a promise about
 * a state some later event must reproduce exactly, so a commitment over a threshold no
 * conforming event could declare is a promise nothing can keep — and it is unrecoverable, since
 * the keys it names are the only ones that may rotate next. This is the single domain authority
 * for a committed threshold: every path that produces one goes through here.
 *
 * Refuses a key list above {@link MAX_KEY_EVENT_KEYS}, and a key list containing the same key
 * twice, for exactly the same reason: no conforming event can list more keys than that or repeat
 * a key (spec 015 S0), so such a state is as unrevealable as a `t > n` one, and the bricking is
 * the recipient's either way.
 */
export function commitToKeyState(keys: KeyRef[], threshold: string): string {
  // The key list's own bound, and a pure length comparison, so it runs before the threshold is
  // parsed. `keyEventSchema` bounds `keys` to 1..MAX_KEY_EVENT_KEYS, so a wider committed state
  // names one no conforming event could ever reveal — the same unrecoverable shape as the two
  // threshold rules below, reachable only through a DIRECT caller because `rotateIdentity`
  // bounds its own `nextKeyCount`. Direct calls are how the documented custody and enrollment
  // handovers build their commitments.
  if (keys.length > MAX_KEY_EVENT_KEYS) {
    throw new Error(
      `Cannot commit to a key state listing ${keys.length} keys: spec 003 bounds a key event to ${MAX_KEY_EVENT_KEYS} keys, so no conforming event could reveal it`
    );
  }
  // Spec 015 S0, on the commit side. A repeated key is refused at REVEAL time by the schema and
  // by the replay (`state_repeats_key`), which is exactly the problem: the commitment names the
  // only state that may rotate next, so committing `{[K, K], t: 2}` bricks the identity — the
  // one event that reproduces the commitment is an event no conforming implementation accepts,
  // and the keys it names are the only ones that could sign a different one. The three refusals
  // here are one rule: a commitment MUST name a state some conforming event could reveal.
  //
  // Compared on key VALUE, like S0 and like the schema: an index-based reading is what would let
  // a holder of one key satisfy a threshold of two.
  if (new Set(keys).size !== keys.length) {
    throw new Error(
      `Cannot commit to a key state that lists the same key twice: spec 015 S0 makes such a state invalid, so no conforming event could reveal it`
    );
  }
  const value = parseThreshold(threshold);
  if (value === null) {
    throw new Error(
      `Cannot commit to a key state whose threshold "${threshold}" is not a decimal string matching ^[1-9][0-9]*$ (spec 015 S1)`
    );
  }
  // The adjacent half of S1, one comparison away with both arguments already in hand. Adding
  // the threshold to the commitment is what made `t > n` expressible at all — before it, the
  // commitment covered only the key list — so this is new surface rather than an inherited gap.
  // It bricks the RECIPIENT, not the caller: the documented custody handover builds its
  // commitment by calling this directly, and `rotateIdentity`'s own guard never sees it.
  if (value > keys.length) {
    throw new Error(
      `Cannot commit to a key state whose threshold "${threshold}" exceeds its ${keys.length} key(s): spec 015 S1 requires t <= n, so no conforming event could reveal it`
    );
  }
  return canonicalDigest({ keys, threshold });
}

/** Digest of a complete signed event, used for prior-chaining (spec 003). */
export function eventDigest(event: KeyEvent): string {
  return canonicalDigest(event);
}

function establishmentData(
  event: Pick<KeyEvent, "seq" | "kind" | "keys" | "threshold" | "next">
): EstablishmentData {
  return {
    seq: event.seq,
    kind: event.kind,
    keys: event.keys,
    threshold: event.threshold,
    next: event.next
  };
}

export function deriveParticipantId(establishment: EstablishmentData): ParticipantId {
  return `pk_${canonicalDigest(establishment)}`;
}

function signEvent(unsigned: Omit<KeyEvent, "signature">, signers: KeyPair[]): KeyEvent {
  const bytes = canonicalBytes(unsigned);
  return {
    ...unsigned,
    signature: signers.map((keyPair) => encodeSignature(sign(bytes, keyPair.secretKey)))
  };
}

export type CreateIdentityOptions = {
  /** Deterministic seeds for tests and fixtures; omit for random keys. */
  currentSeed?: Uint8Array;
  nextSeed?: Uint8Array;
};

export function createIdentity(options: CreateIdentityOptions = {}): Identity {
  const current = generateKeyPair(options.currentSeed);
  const next = generateKeyPair(options.nextSeed);

  const establishment: EstablishmentData = {
    seq: "0",
    kind: "icp",
    keys: [encodeKeyRef(current.publicKey)],
    threshold: "1",
    next: commitToKeyState([encodeKeyRef(next.publicKey)], "1")
  };

  const id = deriveParticipantId(establishment);
  const event = signEvent({ ...establishment, id, prior: null }, [current]);

  return { id, log: [event], currentKeys: [current], nextKeys: [next], nextThreshold: "1" };
}

export type RotateIdentityOptions = {
  /** Deterministic seeds for the generated next keys. */
  nextSeeds?: Uint8Array[];
  /**
   * How many keys to generate for the state committed AFTER this rotation. Defaults to the
   * number of keys this rotation reveals, so a 1-of-1 stays 1-of-1 and an M-of-N keeps its N.
   *
   * Together with {@link nextThreshold} this is how a participant changes the SHAPE of its key
   * state — growing a single key into a committee, or shrinking one back. Both take effect one
   * event later, because both are committed rather than declared.
   */
  nextKeyCount?: number;
  /**
   * Threshold to commit for the key state AFTER this rotation. Defaults to the threshold this
   * rotation itself establishes.
   *
   * This is the only place a participant may change its threshold, and the change takes effect
   * one event later: committing `{ nextKeyCount: 3, nextThreshold: "3" }` here means the NEXT
   * rotation reveals three keys, declares `"3"` and carries three signatures. A rotation can
   * never restate its own threshold — that is the point of committing it (see
   * {@link commitToKeyState}).
   *
   * Validated HERE, against {@link nextKeyCount}, rather than when the commitment is later
   * revealed. A commitment naming a threshold no revealing event could satisfy is unrecoverable
   * — the keys it commits to are the only ones that may rotate next, and rotation is the
   * compromise-recovery path — so the error has to land on the party making the mistake, not on
   * the party who can no longer act.
   */
  nextThreshold?: string;
  /**
   * Pre-computed commitment (`commitToKeyState`) to a next key state held by someone else —
   * the custody-exit handover: the rotation commits to keys this holder never sees, so
   * the committed holder alone can perform the following rotation. The returned identity
   * holds no next keys and cannot rotate again.
   *
   * Mutually exclusive with the three options above: the caller has already chosen the keys and
   * the threshold and hashed them, so passing both means one of the two was going to be
   * discarded silently.
   */
  nextCommitment?: string;
};

/**
 * Rotates to the pre-committed next key state. The rotation event is signed by the newly
 * revealed keys (KERI semantics) — recoverable even when the active key is stolen or lost —
 * and it declares the threshold the PRIOR event committed, carrying exactly that many
 * signatures. Neither the key list nor the threshold is this call's to choose; both were
 * fixed one event ago.
 */
export function rotateIdentity(identity: Identity, options: RotateIdentityOptions = {}): Identity {
  const previous = identity.log[identity.log.length - 1];
  if (!previous) {
    throw new Error("Cannot rotate an identity with an empty key log");
  }
  if (identity.nextKeys.length === 0 || identity.nextThreshold === null) {
    throw new Error(
      "Cannot rotate: this identity holds no pre-committed next keys (they were committed to another holder)"
    );
  }
  const handover = options.nextCommitment !== undefined;
  if (
    handover &&
    (options.nextSeeds !== undefined ||
      options.nextThreshold !== undefined ||
      options.nextKeyCount !== undefined)
  ) {
    throw new Error(
      "Pass either nextCommitment or the nextSeeds/nextKeyCount/nextThreshold options, not both"
    );
  }

  const revealed = identity.nextKeys;
  // The threshold this event MUST declare: the one the previous event committed. Not
  // `previous.threshold` (the outgoing state's) and not a value chosen here.
  //
  // Checked through `parseThreshold` rather than `Number()` because THIS is the value written
  // into the minted event's `threshold` field. `Number("01")` is 1, so a coercion-shaped
  // committed threshold used to mint an event this library itself refuses — the schema and the
  // replay both reject `"01"` — and it threw nowhere. That is reachable without forging
  // anything: a custody handover commits `commitToKeyState([key], "01")`, and the committed
  // holder's `Identity` then carries `"01"` correctly, because that is what reproduces the
  // commitment. Diagnosed against the identity's committed state, not against any option, since
  // the caller may have passed none.
  const threshold = identity.nextThreshold;
  const signerCount = parseThreshold(threshold);
  if (signerCount === null) {
    throw new Error(
      `Cannot rotate: this identity's committed next threshold "${threshold}" is not a decimal string matching ^[1-9][0-9]*$ (spec 015 S1), so no conforming event could declare it`
    );
  }
  if (signerCount > revealed.length) {
    throw new Error(
      `Cannot rotate: the committed next threshold "${threshold}" is not satisfiable by the ${revealed.length} pre-committed next keys`
    );
  }

  // Validate the state about to be COMMITTED before generating anything, so a bad next state is
  // refused here rather than one rotation later, when only the committed holder could act on it.
  const newNextThreshold = options.nextThreshold ?? threshold;
  let newNext: KeyPair[] = [];
  if (!handover) {
    const nextKeyCount = options.nextKeyCount ?? revealed.length;
    if (
      !Number.isSafeInteger(nextKeyCount) ||
      nextKeyCount < 1 ||
      nextKeyCount > MAX_KEY_EVENT_KEYS
    ) {
      throw new Error(
        `Cannot rotate: nextKeyCount must be a whole number from 1 to ${MAX_KEY_EVENT_KEYS}, not ${String(options.nextKeyCount)}`
      );
    }
    // 015 S1's threshold domain, by the same parser the verifier uses. `Number()` alone would
    // accept "01" and " 1", which coerce to 1 and would be committed, revealed, and only then
    // rejected — by a schema and a replay, after the log had been published.
    const newNextThresholdValue = parseThreshold(newNextThreshold);
    if (newNextThresholdValue === null) {
      throw new Error(
        `Cannot rotate: nextThreshold "${newNextThreshold}" is not a decimal string matching ^[1-9][0-9]*$ (spec 015 S1)`
      );
    }
    if (newNextThresholdValue > nextKeyCount) {
      throw new Error(
        `Cannot rotate: nextThreshold "${newNextThreshold}" exceeds the ${nextKeyCount} next key(s) it would be committed against, so no rotation could ever reveal that state`
      );
    }
    // Seeds are all-or-nothing against the key count. Surplus seeds would be discarded and a
    // short list would silently fill the remainder with RANDOM keys — from an option whose
    // whole purpose is determinism, and in a repo whose conformance fixtures are generated from
    // seeds. A fixture that cannot be regenerated is the failure this option exists to prevent.
    if (options.nextSeeds !== undefined && options.nextSeeds.length !== nextKeyCount) {
      throw new Error(
        `Cannot rotate: nextSeeds carries ${options.nextSeeds.length} seed(s) for ${nextKeyCount} next key(s); pass one seed per key or none at all`
      );
    }
    newNext = Array.from({ length: nextKeyCount }, (_, index) =>
      generateKeyPair(options.nextSeeds?.[index])
    );
  }

  const unsigned: Omit<KeyEvent, "signature"> = {
    id: identity.id,
    seq: String(Number(previous.seq) + 1),
    prior: eventDigest(previous),
    kind: "rot",
    keys: revealed.map((keyPair) => encodeKeyRef(keyPair.publicKey)),
    threshold,
    next:
      options.nextCommitment ??
      commitToKeyState(
        newNext.map((keyPair) => encodeKeyRef(keyPair.publicKey)),
        newNextThreshold
      )
  };

  // EXACTLY the threshold in signatures (015 S1's `m = t`), assigned in increasing key order
  // (S3): the first `t` revealed keys, which are already in the committed key order.
  const event = signEvent(unsigned, revealed.slice(0, signerCount));

  return {
    id: identity.id,
    log: [...identity.log, event],
    currentKeys: revealed,
    nextKeys: newNext,
    nextThreshold: handover ? null : newNextThreshold
  };
}

export type KeyState = {
  id: ParticipantId;
  keys: KeyRef[];
  threshold: string;
  seq: string;
};

/**
 * A key state together with the digest of the event that established it — the value spec 016's
 * `anchor` field names.
 *
 * `anchor` is `eventDigest(event)`, the same value the NEXT event's `prior` carries, so a state
 * and the record that names it are joined by a digest both sides already compute. A `seq` would
 * not do: it is unambiguous only within one replay-valid log, and 003 defers duplicity
 * detection, so two forks could carry different events at the same `seq` (015, _Options
 * considered_).
 */
export type AnchoredKeyState = KeyState & { anchor: string };

/**
 * The ceiling for replaying a log supplied by a caller who has not authenticated yet.
 *
 * `write-auth.ts` replays the key log carried in the request body to discover the keys the
 * request signature will then be checked against (spec 004's first-write bootstrap), so
 * this replay is work an anonymous caller commands. It gets its own, far smaller budget:
 * the general ceiling above is sized never to reject a legitimate log, which makes it much
 * too generous to hand to an unauthenticated stranger.
 *
 * 128 == `MAX_KEY_LOG_EVENTS`, i.e. one verification per event. That is exactly what a
 * 1-of-1 log costs — the greedy walk assigns the single member to the single key on its
 * first try — so a maximum length log of the only shape this codebase can mint fits
 * precisely, and nothing that can authenticate today is refused. Participants with
 * multi-key event sets AND long logs do not fit; see the note in `write-auth.ts`, where the
 * budget is injectable. The combined verification-budget pass deliberately retains this
 * value: it admits every full-length 1-of-1 log, while a cold 1-of-8 log reaches 16 events
 * and event 17 is refused unless an operator supplies the larger migration allowance.
 */
export const MAX_PREAUTH_SIGNATURE_VERIFICATIONS = MAX_KEY_LOG_EVENTS;

/**
 * Thrown when a replay would exceed its signature-verification budget. Distinct from the
 * ordinary replay failures above so callers can tell "this log is invalid" from "this log
 * is too expensive to judge" — the latter is a refusal to spend CPU on attacker-supplied
 * input, not a verdict on the log's contents.
 */
export class KeyLogWorkBudgetExceeded extends VerificationBudgetExceeded {
  constructor(message: string) {
    super(message);
    this.name = "KeyLogWorkBudgetExceeded";
  }
}

type WorkBudget = { limit: number; spent: number };

/** One metered Ed25519 verification. Throws rather than overspending the budget. */
function spendVerification(
  budget: WorkBudget,
  signature: Uint8Array,
  bytes: Uint8Array,
  publicKey: Uint8Array
): boolean {
  if (budget.spent >= budget.limit) {
    throw new KeyLogWorkBudgetExceeded(
      `Key log replay exceeded its budget of ${budget.limit} signature verifications`
    );
  }
  budget.spent += 1;
  return verify(signature, bytes, publicKey);
}

/**
 * Structure and signature checks for one event, per spec 003 and spec 015's S0–S3.
 *
 * `verifySignatures` false runs everything EXCEPT the Ed25519 verifications: S0's duplicate
 * keys, the 003 signature/key ratio, S1's whole threshold domain and exact-count rule, and —
 * importantly — decoding every KeyRef. Those are hashes, base58 decodes and integer
 * comparisons, cheap and independent of the curve, so an event whose signatures were already
 * proven still gets its full structural check.
 *
 * WHICH key state an event is judged against was spec 003's open contradiction — `:38` said the
 * event's own threshold, the replay paragraph said the prior event's — and 003 now resolves it
 * to neither: the state is the one the PREVIOUS event committed. This function still checks the
 * event against the event's own `threshold` and `keys`, and that is now the committed state
 * rather than a self-attested one, because `replay` requires `commitToKeyState(keys, threshold)`
 * to reproduce the prior event's `next` before this runs for a rotation. For an inception there
 * is no prior event and the state is the one the participant id hashes (002).
 *
 * So this function alone cannot tell an authorized rotation from a forged one — it is judging a
 * state, not deciding which state applies. That is `replay`'s job, and the split is why the
 * commitment check lives there.
 */
function verifyEventSignatures(
  event: KeyEvent,
  budget: WorkBudget,
  verifySignatures: boolean
): void {
  // Under threshold semantics a signature can only ever count once, against one of the
  // event's own keys, so more signatures than keys is meaningless — and it was exactly the
  // shape that made the old key x signature search expensive. Kept ahead of S1's exact-count
  // rule, which subsumes it (m = t <= n), because 003 states it as its own validity rule with
  // its own diagnosis: an operator told "3 signatures, 2 keys" learns more than one told
  // "3 members against a threshold of 2".
  if (event.signature.length > event.keys.length) {
    throw new Error(
      `Key event ${event.seq} carries ${event.signature.length} signatures but lists only ${event.keys.length} keys`
    );
  }
  // S0 and S1's state rules: no repeated key, a threshold in ^[1-9][0-9]*$, and t <= n. All
  // three make the STATE invalid, and every record checked against it invalid with it.
  const state = checkKeyState(event.keys, event.threshold);
  if (!state.ok) {
    throw new Error(`Key event ${event.seq} is invalid (${state.code}): ${state.message}`);
  }
  // S1's exact count: an event carries EXACTLY its threshold in signatures, not merely at
  // least it. A length comparison, so it runs before the signature array is decoded.
  const countRejection = checkMemberCount(event.signature.length, state.threshold);
  if (countRejection) {
    throw new Error(
      `Key event ${event.seq} is invalid (${countRejection.code}): ${countRejection.message}`
    );
  }

  const { signature, ...unsigned } = event;
  const bytes = canonicalBytes(unsigned);
  const signatures = signature.map(decodeSignature);

  // Decode EVERY key before verifying any of them. `keyRefSchema` only checks that a
  // KeyRef is base58btc text — `decodeKeyRef` is what enforces the 34-byte
  // multicodec-tagged ed25519-pub shape, and it is the only thing that does. Doing it here
  // rather than inside the walk below keeps that check total: the walk stops as soon as every
  // member is assigned, so a key sitting past that point would otherwise never be decoded, and
  // an event carrying an undecodable trailing KeyRef would replay clean, be stored, and then
  // throw from `verifyRecord` on every later read.
  const publicKeys = event.keys.map(decodeKeyRef);

  if (!verifySignatures) {
    return;
  }

  // S2 and S3, by 015's normative greedy forward walk: every member must verify under a
  // distinct listed key, assigned in strictly increasing key index. At most `keys` curve
  // operations, whatever the member count — the search this replaces was keys x signatures.
  const failed = walkSignatureSet(signatures.length, publicKeys.length, (member, key) =>
    spendVerification(budget, signatures[member]!, bytes, publicKeys[key]!)
  );
  if (failed !== null) {
    throw new Error(
      `Key event ${event.seq} signature ${failed} does not verify under a distinct listed key in key order (threshold ${event.threshold})`
    );
  }
}

export type ReplayKeyLogOptions = {
  /**
   * Ceiling on the total Ed25519 verifications this replay may perform, across every
   * event. Defaults to `DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS`; exceeding it throws
   * `KeyLogWorkBudgetExceeded`.
   */
  maxSignatureVerifications?: number;
  /**
   * How many leading events have ALREADY had their signatures verified, and may therefore
   * skip re-verification. Everything else about them is still checked: the chain digests,
   * the pre-rotation commitments, the participant-id derivation, key decoding, duplicate
   * keys, and the signature/key ratio.
   *
   * This exists because a key log is append-only. When a participant extends a log the
   * service already holds, only the new events are unproven; re-verifying the stored prefix
   * on every extension makes the cost of publishing grow with the log's length, which turns
   * any fixed budget into a ratchet that eventually freezes the identity — and key rotation
   * is the compromise-recovery path, so freezing it is the worst possible failure. Metering
   * the suffix keeps the cost of one extension constant no matter how long the log is.
   *
   * DANGEROUS IF MISUSED. The caller is asserting that these exact events, byte for byte,
   * were verified before. Pass it only after proving the prefix is identical to a log this
   * service already accepted — see `write-auth.ts`, which digests the stored prefix and
   * compares. Passing a length the caller has not proven admits forged signatures.
   */
  verifiedPrefixLength?: number;
  /**
   * Called with the number of Ed25519 verifications a SUCCESSFUL replay performed.
   *
   * For callers that must bound a whole request rather than one log: a grant chain replays a
   * log per distinct issuer, so a per-log ceiling multiplies by the link count. Reporting the
   * spend lets the caller carry one budget across all of them.
   *
   * Called on EVERY exit, including a throw. It once fired only on success, on the reasoning
   * that a failed replay ends the verification that asked for it — which is true on the chain
   * link path and false on the revocation path, where the caller keeps going. An uncharged
   * failure let a hostile view buy the whole allowance over and over.
   */
  onSignatureVerifications?: (spent: number) => void;
};

/**
 * Thrown when a replayed log is internally valid but belongs to a DIFFERENT participant than
 * the caller asked for — the substituted-log case.
 *
 * Distinct from the ordinary replay failures because it is a different accusation. Those say
 * "this log is malformed or forged"; this one says "this log is fine, and it is not the log
 * you asked for", which points at whoever served it rather than at whoever published it. It
 * is also NOT a {@link VerificationBudgetExceeded}: a substituted log is not a cost condition,
 * and callers that treat cost as a retryable stall must not retry this forever.
 */
export class KeyLogParticipantMismatch extends Error {
  /** The participant the caller asked about. */
  readonly expectedId: ParticipantId;
  /** The participant the log's own inception event derives. */
  readonly actualId: ParticipantId;

  constructor(expectedId: ParticipantId, actualId: ParticipantId) {
    super(`Key log for ${expectedId} replays as a different participant (${actualId})`);
    this.name = "KeyLogParticipantMismatch";
    this.expectedId = expectedId;
    this.actualId = actualId;
  }
}

/**
 * Replays a key log AND binds it to the participant it was fetched for. Use this — not
 * {@link replayKeyLog} — whenever the expected participant id is known.
 *
 * A `KeyState.id` is SELF-DERIVED from the log's own inception event (spec 002): it says which
 * identity this log describes, and nothing whatever about which identity it was served for.
 * The two are only equal because an honest host put the log at the right path, and the host is
 * untrusted by design. Replaying without this check means a host that serves participant A's
 * perfectly valid key log at participant V's path makes every record naming V verify under A's
 * keys — complete impersonation of V, requiring none of V's keys.
 *
 * Throws {@link KeyLogParticipantMismatch} when the replayed id is not `expectedId`, and
 * everything {@link replayKeyLog} throws otherwise. Bare `replayKeyLog` remains correct for the
 * one legitimate unbound case: deriving a participant id FROM a submitted log, where there is
 * no expected id to bind against (a discovery service's first-write bootstrap, spec 004).
 */
export function replayKeyLogFor(
  expectedId: ParticipantId,
  events: KeyEvent[],
  options: ReplayKeyLogOptions = {}
): KeyState {
  const state = replayKeyLog(events, options);
  if (state.id !== expectedId) {
    throw new KeyLogParticipantMismatch(expectedId, state.id);
  }
  return state;
}

/** Strips the anchor from a replayed state, for the callers that ask only for the state. */
function bareState(state: AnchoredKeyState): KeyState {
  return { id: state.id, keys: state.keys, threshold: state.threshold, seq: state.seq };
}

/**
 * Replays a key-event log per spec 003 and returns the current key state. Throws on
 * any chain, commitment, identity, or signature violation, and on exhausting the
 * signature-verification budget (see `ReplayKeyLogOptions`).
 *
 * The returned `id` is derived from the log's OWN inception event and is therefore a claim the
 * log makes about itself, never a confirmation that this is the log you asked for. A caller
 * holding an expected participant id must use {@link replayKeyLogFor}.
 *
 * A caller verifying an ANCHORED record (spec 016) wants {@link replayKeyLogStates} instead: it
 * is the same replay, and it keeps the per-event states the anchor selects among.
 */
export function replayKeyLog(events: KeyEvent[], options: ReplayKeyLogOptions = {}): KeyState {
  return bareState(runReplay(events, options).current);
}

/**
 * Replays a key-event log per spec 003 and returns EVERY state it commits, each tagged with the
 * digest of the event that established it — the lookup table spec 016's anchor resolves against.
 *
 * `states` is in sequence order, one entry per event, and `current` is its last entry. Same
 * replay, same budget and same rejections as {@link replayKeyLog}: an anchored verifier still
 * has to establish that the log itself is valid before any state of it means anything (016's
 * verification rule, clause 1).
 *
 * The digests are the ones the replay already computes for `prior` chaining, so keeping the
 * states costs no additional hashing and no additional curve work.
 */
export function replayKeyLogStates(
  events: KeyEvent[],
  options: ReplayKeyLogOptions = {}
): { current: AnchoredKeyState; states: AnchoredKeyState[] } {
  return runReplay(events, options);
}

/**
 * {@link replayKeyLogStates} bound to the participant the log was fetched for — the same
 * substituted-log defence {@link replayKeyLogFor} applies, and for the same reason: an anchor
 * selects a state WITHIN a log and says nothing about whose log it is, so a verifier holding an
 * expected participant id must bind the log before resolving the anchor.
 *
 * Throws {@link KeyLogParticipantMismatch} when the replayed id is not `expectedId`.
 */
export function replayKeyLogStatesFor(
  expectedId: ParticipantId,
  events: KeyEvent[],
  options: ReplayKeyLogOptions = {}
): { current: AnchoredKeyState; states: AnchoredKeyState[] } {
  const replayed = runReplay(events, options);
  if (replayed.current.id !== expectedId) {
    throw new KeyLogParticipantMismatch(expectedId, replayed.current.id);
  }
  return replayed;
}

/**
 * The anchor a producer writes into a record it signs under its CURRENT key state (spec 016):
 * the spec-003 digest of the log's last event.
 *
 * A producer MAY anchor to any earlier committed state whose keys it still holds — a verifier
 * cannot tell the difference and does not need to — but the tip is what a signer using its
 * current keys means, so this is the helper producers reach for: `anchor: keyLogAnchor(log)`.
 *
 * Throws on an empty log: there is no state to name, so there is no honest value to return.
 * This does NOT replay — the caller signing with its own keys already holds a replayed log; a
 * verifier resolves anchors through {@link replayKeyLogStates}, never through this.
 */
export function keyLogAnchor(events: KeyEvent[]): string {
  const last = events[events.length - 1];
  if (!last) {
    throw new Error("Cannot anchor to an empty key log: no key event exists to name");
  }
  return eventDigest(last);
}

/**
 * Resolves spec 016's `anchor` against a replayed log's states: the state established by the
 * event whose digest is `anchor`, or `undefined` when the log commits no such event.
 *
 * `undefined` is a verdict, not a fallback. 016 tries exactly the anchored state and no other,
 * so a caller MUST refuse a record whose anchor names no event of the issuer's log rather than
 * fall back to any state that happens to accept it.
 *
 * For deciding a record, `checkAnchoredSignatureSet` applies this same lookup and then the
 * S0–S3 check; this is for callers that want the state itself — reporting which state a record
 * was judged against, or deciding whether a cached log is fresh enough to conclude.
 */
export function findAnchoredKeyState(
  states: readonly AnchoredKeyState[],
  anchor: string
): AnchoredKeyState | undefined {
  return states.find((state) => state.anchor === anchor);
}

function runReplay(
  events: KeyEvent[],
  options: ReplayKeyLogOptions
): { current: AnchoredKeyState; states: AnchoredKeyState[] } {
  const budget: WorkBudget = {
    limit: safeVerificationCount(
      options.maxSignatureVerifications,
      DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS
    ),
    spent: 0
  };
  try {
    return replay(events, options, budget);
  } finally {
    options.onSignatureVerifications?.(budget.spent);
  }
}

function replay(
  events: KeyEvent[],
  options: ReplayKeyLogOptions,
  budget: WorkBudget
): { current: AnchoredKeyState; states: AnchoredKeyState[] } {
  // Both options are sanitized by ACCEPTING only a safe non-negative integer, never by
  // coercing whatever arrived. `Math.trunc(NaN)` is `NaN` and `Math.max(0, NaN)` is `NaN`, so
  // the obvious clamp let `NaN` and `Infinity` through — and every comparison against them is
  // false, which means `verifiedPrefixLength` silently discounted the WHOLE log and
  // `maxSignatureVerifications` silently removed the budget. Both failures are open, in the
  // direction that accepts forged signatures, and `Number(header)` or a JSON round-trip
  // produces exactly those values. An unusable value falls back to the safe end: verify
  // everything, and spend no more than the default.
  const verifiedPrefixLength = safeVerificationCount(options.verifiedPrefixLength, 0);
  // The log-length bound, enforced HERE rather than left to the schema.
  //
  // `keyEventLogSchema` bounds every in-repo delivery to MAX_KEY_LOG_EVENTS, but this
  // function's parameter is a bare `KeyEvent[]` rather than a parsed `KeyEventLog`, so a caller
  // can reach it with an unvalidated array. The replay's own work — one digest, one structural
  // check and up to `MAX_KEY_EVENT_KEYS` verifications per event, plus the state it retains for
  // spec 016's anchor lookup — is linear in the event count, and the function that spends it
  // should enforce the bound it is sized against rather than inherit it from a schema a caller
  // may not have run.
  //
  // Checked before the elements are touched, per spec 003's length-before-shape rule.
  if (events.length > MAX_KEY_LOG_EVENTS) {
    throw new Error(
      `A key log may carry at most ${MAX_KEY_LOG_EVENTS} events, not ${events.length}`
    );
  }
  const inception = events[0];
  if (!inception) {
    throw new Error("A key log must contain at least an inception event");
  }
  if (inception.kind !== "icp" || inception.seq !== "0" || inception.prior !== null) {
    throw new Error("The first key event must be an inception event with seq 0 and no prior");
  }
  // The schema enforces this on ordinary inputs, but replay accepts raw `KeyEvent[]` values too.
  // Guard inception here, before its establishment data is hashed for the participant id and
  // before any KeyRef, signature, or curve work. Rotations get the same width check through
  // `commitToKeyState(event.keys, event.threshold)` before their signatures are verified.
  if (inception.keys.length > MAX_KEY_EVENT_KEYS) {
    throw new Error(
      `Inception key event lists ${inception.keys.length} keys; spec 003 permits at most ${MAX_KEY_EVENT_KEYS}`
    );
  }
  if (inception.id !== deriveParticipantId(establishmentData(inception))) {
    throw new Error("The participant ID does not match the inception event's establishment data");
  }
  verifyEventSignatures(inception, budget, verifiedPrefixLength < 1);

  // One digest per event, computed once and reused twice: as the next event's `prior` target
  // and as the state's spec-016 anchor. Both are `eventDigest` of the complete signed event, so
  // an anchored record and a chained event name a state by the same value.
  let previousDigest = eventDigest(inception);
  const states: AnchoredKeyState[] = [
    {
      id: inception.id,
      keys: inception.keys,
      threshold: inception.threshold,
      seq: inception.seq,
      anchor: previousDigest
    }
  ];

  let previous = inception;
  let index = 1;
  for (const event of events.slice(1)) {
    if (event.kind !== "rot") {
      throw new Error(`Key event ${event.seq} after inception must be a rotation`);
    }
    if (event.id !== inception.id) {
      throw new Error(`Key event ${event.seq} belongs to a different participant`);
    }
    if (Number(event.seq) !== Number(previous.seq) + 1) {
      throw new Error(`Key event sequence is not contiguous at ${event.seq}`);
    }
    if (event.prior !== previousDigest) {
      throw new Error(`Key event ${event.seq} does not chain to the previous event`);
    }
    // The pre-rotation commitment covers the whole next key STATE — the ordered key list AND
    // its threshold (spec 003). Checking both in one comparison is what removes the rotating
    // event's free parameter: `threshold` is no longer something the revealing party names,
    // so the exact-count check below (`m = t` against the event's own threshold) is a check
    // against a threshold the PREVIOUS event fixed. Committing only the key list left a
    // holder of one key in a multi-key committed set free to reveal it at `threshold: "1"`
    // and take sole control of an M-of-N identity.
    //
    // The domain check comes first so this event, not the hashing helper, is what a malformed
    // threshold is blamed on. `replayKeyLog` accepts a bare `KeyEvent[]` — the parameter is not
    // a parsed `KeyEventLog` — so an unvalidated event can reach here, and `commitToKeyState`
    // now refuses an out-of-domain threshold. `verifyEventSignatures` would catch it too, via
    // `checkKeyState`, but only after this comparison. It is a string test, so it changes
    // nothing about the ordering that matters: the commitment is still established before any
    // signature is verified.
    //
    // The key-count bound is mirrored here for the same attribution reason, and first because
    // it is the pure length check of the three: `commitToKeyState` refuses a key list above
    // MAX_KEY_EVENT_KEYS, and this event — not the hashing helper — is what an over-wide key
    // list should be blamed on. `keyEventLogSchema` bounds every parsed delivery, but this
    // function's parameter is a bare `KeyEvent[]`.
    if (event.keys.length > MAX_KEY_EVENT_KEYS) {
      throw new Error(
        `Key event ${event.seq} lists ${event.keys.length} keys, above the ${MAX_KEY_EVENT_KEYS} a key event may carry (spec 003)`
      );
    }
    const declared = parseThreshold(event.threshold);
    if (declared === null) {
      throw new Error(
        `Key event ${event.seq} declares a threshold "${event.threshold}" outside ^[1-9][0-9]*$ (spec 015 S1)`
      );
    }
    if (declared > event.keys.length) {
      throw new Error(
        `Key event ${event.seq} declares a threshold "${event.threshold}" above its own ${event.keys.length} key(s) (spec 015 S1)`
      );
    }
    // S0, mirrored here for exactly the reason the two guards above are: `commitToKeyState` now
    // refuses a state that repeats a key, and a repeated key is this EVENT's defect, not the
    // hashing helper's. Formatted through `checkKeyState` — the same call `verifyEventSignatures`
    // makes a few lines later — so one repeated key produces one message wherever it is caught,
    // and the committed rejection vector keeps naming `state_repeats_key`. The threshold rules
    // it also carries are already decided above with their own diagnoses, so in practice only
    // S0 can fire here.
    const stateRule = checkKeyState(event.keys, event.threshold);
    if (!stateRule.ok) {
      throw new Error(
        `Key event ${event.seq} is invalid (${stateRule.code}): ${stateRule.message}`
      );
    }
    if (commitToKeyState(event.keys, event.threshold) !== previous.next) {
      throw new Error(
        `Key event ${event.seq} does not reveal the pre-committed next key state: its keys and threshold "${event.threshold}" do not reproduce the prior event's commitment`
      );
    }
    verifyEventSignatures(event, budget, index >= verifiedPrefixLength);
    previousDigest = eventDigest(event);
    states.push({
      id: inception.id,
      keys: event.keys,
      threshold: event.threshold,
      seq: event.seq,
      anchor: previousDigest
    });
    previous = event;
    index += 1;
  }

  // Two states of one log MAY share keys, and MAY share a quorum of them: a 2-of-3 rotation
  // that retires one key and keeps two is a valid log. Spec 015's keyless cross-state routes
  // (deleting or reordering members so an edited record conforms against a DIFFERENT state)
  // are closed by spec 016 instead — a signature-set record names the one state it is judged
  // against, so no record is ever offered to two states and there is nothing for an edit to
  // move between. The rule this replaces constrained rotation shape to protect records; the
  // protection now travels inside the record it protects.

  return { current: states[states.length - 1]!, states };
}
