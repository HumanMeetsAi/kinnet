/**
 * Canonical `(record, chain)` unit verification (spec 014 §"What verifies a unit — the
 * profile, pinned"; spec 012 §"Signing a Conversation" for the two signing modes).
 *
 * A spec-012/014 record travels as a **unit**: the record, and — when it is
 * delegated-signed — the leaf-first grant chain that authorizes it. The unit, not the
 * envelope, is what verifies, which is what lets any member re-deliver a delegated-signed
 * record in either transport mode and what makes a fully custodial participant (whose
 * custody signs grants and never records) usable on the E2EE lane at all.
 *
 * The rules are pinned in the spec precisely because a **node** and a **member** evaluate
 * the same bytes and must reach the same verdict; so they live here, once, and both callers
 * consume them. The one input that legitimately differs between the two is revocation —
 * hence {@link RecordUnitVerifyOptions.checkRevocation} is a REQUIRED option with no
 * default. A default here is exactly how one side silently gets the other side's answer.
 *
 * Failures that are **resolution** failures — an unresolvable key log at either end — are a
 * WAIT, never a rejection: key logs are monotone, so an honest verifier's verdict converges,
 * and rejecting on a cache miss would split the group. They are returned as invalid verdicts
 * carrying a distinguished reason ({@link isUnitWaitReason}), and never thrown.
 */
import {
  KeyLogParticipantMismatch,
  replayKeyLogFor,
  VerificationBudgetExceeded,
  verifyThresholdRecord
} from "@kinnet/crypto";
import {
  ABILITY_CONVERSATION_SELF_REMOVE,
  conversationSchema,
  conversationUpdateSchema,
  keyRefSchema,
  type Conversation,
  type ConversationUpdate,
  type Grant,
  type ParticipantId
} from "@kinnet/protocol";
import {
  abilityCovers,
  beginVerificationOperation,
  GRANT_CHAIN_COST_REASONS,
  verifyGrantChain,
  verificationWorkOptions,
  type ResolverReason,
  type TrustView,
  type Verification,
  type VerificationBudget,
  type VerificationContext,
  type VerificationOperation
} from "@kinnet/trust";

/**
 * The ability a delegated-signed `pn/conversation-update` record needs, minted from the
 * envelope type by spec 012's generative rule (`pn/<name>` ⇒ `msg/<name>`) and covered by
 * the bare `msg` umbrella under 009's path-prefix rule — the node applies the same string to
 * the delivery.
 */
const ABILITY_CONVERSATION_UPDATE = "msg/conversation-update";

/**
 * The ability a delegated-signed `pn/conversation` record needs — the same string the node
 * already requires of a delegated conversation delivery, by the same generative rule.
 */
const ABILITY_CONVERSATION = "msg/conversation";

export type RecordUnitVerifyOptions = {
  /**
   * The request's shared {@link VerificationBudget}. Omitted, this call builds its own from
   * `view.maxSignatureVerifications`, which bounds this call alone.
   */
  budget?: VerificationBudget;
  /** The request's outer budget and view-isolated signer-state memo. Takes precedence over budget. */
  context?: VerificationContext;
  /** Started by a composing verifier so nested calls share one local operation allowance. */
  operation?: VerificationOperation;
  /**
   * Whether revocation is a verification input. **Required, deliberately**: spec 014 pins the
   * asymmetry, and neither side may inherit the other's answer by omission.
   *
   * - A **node** gating a delivery passes `true`. That check is real time, local, and
   *   non-consensus — the same check its request verifier already runs.
   * - A **member** verifying stored evidence passes `false`. A revocation one member's
   *   discovery view holds and another's does not would make one member apply a commit and
   *   the other wait forever; a member that *does* know a chain revoked refuses to author or
   *   commit on top of it rather than re-deciding a delivered record's validity.
   *
   * Note that `@kinnet/trust`'s own `checkRevocation` defaults to `true` at record purpose;
   * this option is threaded through explicitly so the default is never what decides.
   */
  checkRevocation: boolean;
};

/**
 * The subset of {@link UNIT_WAIT_REASONS} that means "this verifier declined to spend enough to
 * judge the log", rather than "this verifier has not seen the log yet".
 *
 * A log refused for COST is not a forged unit, and it is not an absent one either: spec 003
 * makes a verification-work ceiling a local resource policy rather than a validity rule, so the
 * publisher's record may be perfectly good and the thing that has run short is here. Naming the
 * subset lets a surface report that distinctly — a node surface answers 503 rather than 401 —
 * while the wait RULE below is untouched: every cost reason is still a wait, and adding one to
 * this list adds it to {@link UNIT_WAIT_REASONS} too. That is a change in MEMBERSHIP, not in
 * semantics — the list went from six entries to seven when
 * `chain_invalid:grant_signature_check_too_expensive` was classified, which is the fix rather
 * than a side effect of it.
 *
 * DERIVED from `@kinnet/trust`, not transcribed from it, and the difference is the whole point.
 * A hand-written copy of the resolver's chain reasons is what this list used to be, and it
 * named one of the two: `grant_signature_check_too_expensive` was missing, so a chain refused at
 * the signature-search exit matched neither this list nor {@link UNIT_WAIT_REASONS} and fell
 * through to a node surface's malformed-record branch — a 400 telling a publisher to fix a record
 * that was perfectly good and, on the spec-014 path, a discard where the rules require a WAIT.
 *
 * Both halves of the guarantee are compile-time. {@link UnitCostReason} is derived from
 * `@kinnet/trust`'s exported list, so a reason added to the resolver arrives here already
 * prefixed; and this array is TYPED as that union, so an entry naming a reason no exit produces
 * does not compile either. {@link UnitCostReasonsAreClassified} closes the third side: every
 * cost-shaped reason `verifyUnit` can return is in this list.
 *
 * The two leading entries are this module's OWN reasons — the owner-mode key-log replay and
 * signature search, which no resolver call produces — so they are written out here.
 */
export type UnitCostReason =
  | "actor_key_log_too_expensive"
  | "creator_key_log_too_expensive"
  // `verifyUnit` prefixes every resolver reason it forwards with `chain_invalid:`; the prefix is
  // applied from the same constant so the two spellings cannot drift apart.
  | `chain_invalid:${(typeof GRANT_CHAIN_COST_REASONS)[number]}`;

export const UNIT_COST_REASONS: readonly UnitCostReason[] = [
  "actor_key_log_too_expensive",
  "creator_key_log_too_expensive",
  ...GRANT_CHAIN_COST_REASONS.map(
    (reason) =>
      `chain_invalid:${reason}` as `chain_invalid:${(typeof GRANT_CHAIN_COST_REASONS)[number]}`
  )
];

/**
 * Reasons that mean "this verifier could not resolve something yet", as opposed to "this unit
 * is forged". Spec 014 makes them a WAIT: the caller holds the record rather than rejecting
 * it, and re-verifies when its view catches up.
 */
export type UnitWaitReason =
  | "actor_key_log_unresolved"
  | "creator_key_log_unresolved"
  | "chain_invalid:grant_issuer_key_log_unresolved"
  | UnitCostReason;

export const UNIT_WAIT_REASONS: readonly UnitWaitReason[] = [
  "actor_key_log_unresolved",
  "creator_key_log_unresolved",
  "chain_invalid:grant_issuer_key_log_unresolved",
  // The cost reasons are SPREAD IN rather than repeated, so the subset relationship is
  // structural: a reason cannot be added to one list and forgotten in the other. Rejecting on
  // cost would discard a record that may be perfectly good, so it waits like the other
  // resolution stalls; raising the allowance is what clears it.
  ...UNIT_COST_REASONS
  // DELIBERATELY ABSENT: the `*_key_log_participant_mismatch` reasons. A log that replays as a
  // different participant is not a view that has yet to catch up — key logs are monotone and no
  // honest host ever serves one identity's log at another's path, so there is nothing to
  // converge to. Waiting on it would hold a forged unit forever and re-ask a hostile host for
  // the same substitution; it rejects instead.
];

/** True when an invalid verdict's reason is a resolution stall rather than a rejection. */
export function isUnitWaitReason(reason: string): boolean {
  return (UNIT_WAIT_REASONS as readonly string[]).includes(reason);
}

/**
 * True when a WAIT is specifically a cost refusal. Every reason this matches is also matched by
 * {@link isUnitWaitReason}, so a caller that does nothing with this keeps today's behaviour.
 */
export function isUnitCostReason(reason: string): boolean {
  return (UNIT_COST_REASONS as readonly string[]).includes(reason);
}

/**
 * Every reason a unit verification can return, including the resolver reasons it forwards.
 *
 * TWO THINGS have to carry this union for it to bind, and the first version of this carried only
 * one. `invalid` accepts only these — which stops a literal, a template string or a
 * concatenation naming something unlisted. And every function in this module that returns a
 * verdict declares `Promise<Verification<UnitReason>>` rather than the unparameterized
 * `Promise<Verification>`, which is what stops a bare `return { valid: false, reason: "..." }`
 * from bypassing `invalid` altogether. With a return type left unparameterized, `Verification`
 * defaults its reason to `string` and such a literal typechecks, lints and tests clean while
 * producing an UNCLASSIFIED cost reason — the exact 400-instead-of-503 defect this module exists
 * to close, reintroduced through the hole in its own guard.
 *
 * That second requirement is not local to this module. A verdict produced ANYWHERE and then fed
 * to {@link isUnitCostReason} or {@link isUnitWaitReason} needs a reason type, or the same
 * literal walks in from another package. A client SDK's own verdict positions — its conversation
 * record verifier, the verdict it binds while joining an E2EE conversation, and the verifier
 * factory's return — name {@link UnitReason} for exactly that reason, and `@kinnet/trust`'s own
 * statement verifiers name `StatementReason`. Every verdict position names its set; since
 * `Verification` has no default, one that did not would not compile.
 *
 * `chain_invalid:${ResolverReason}` is the forwarding arm: `verifyUnit` re-spells whatever
 * `verifyGrantChain` returns, so the union follows the resolver's own type and cannot fall
 * behind it.
 */
export type UnitReason =
  | "record_malformed"
  | "signature_invalid"
  | "chain_invalid:abilities_insufficient"
  | "chain_invalid:audience_not_key"
  | "chain_invalid:leaf_key_signature_invalid"
  | "chain_invalid:subject_not_actor"
  | "chain_invalid:subject_not_creator"
  | `${"actor" | "creator"}_key_log_${"unresolved" | "too_expensive" | "participant_mismatch"}`
  | `chain_invalid:${ResolverReason}`;

type Assert<T extends true> = T;

/**
 * Every cost-shaped reason `verifyUnit` can return is classified as a cost reason.
 *
 * ONE-DIRECTIONAL on purpose, unlike the resolver's twin: `UnitReason` admits
 * `chain_invalid:${ResolverReason}` in full, which includes cost reasons only the statement and
 * represents verifiers produce and `verifyUnit` never calls. Requiring the reverse inclusion
 * would demand this module classify reasons it cannot reach. Soundness comes from the other
 * side instead — {@link UNIT_COST_REASONS} is typed as {@link UnitCostReason}, so it cannot
 * name something the resolver does not export.
 *
 * WHAT NONE OF THIS COVERS, and the list is short but real:
 *
 *  - a reason produced by THROWING rather than returning. Nothing types the reason on an error
 *    object, so a `*_too_expensive` string reaching a surface through a thrown value is outside
 *    every check here. `@kinnet/verify`'s request verifier does exactly that on purpose and
 *    classifies with a suffix match, which is the right tool there — it needs the cost/invalid
 *    split and no per-reason handling.
 *  - a consumer that RE-SPELLS a reason on its way out. A node surface that passes these through
 *    verbatim loses nothing; a surface that rewrote them would need its own proof of the same
 *    shape, exactly as this module carries one for the `chain_invalid:` prefix it adds.
 *  - a position that names `Verification<string>` EXPLICITLY. `Verification`'s reason parameter
 *    no longer has a default, so omitting it does not compile and nothing opts out by accident;
 *    writing `string` still does, but it is now a visible choice in the signature rather than
 *    the silent shape of every unannotated return.
 */
export type UnitCostReasonsAreClassified = Assert<
  Extract<UnitReason, `${string}_too_expensive`> extends
    | UnitCostReason
    | `chain_invalid:${Exclude<ResolverReason, (typeof GRANT_CHAIN_COST_REASONS)[number]>}`
    ? true
    : false
>;

function invalid<R extends UnitReason>(reason: R): { valid: false; reason: R } {
  return { valid: false, reason };
}

type SignedRecord = Record<string, unknown> & { signature: string[] };

type KeyState = { keys: string[]; threshold: string };

/**
 * Every key state a participant's log has ever committed. Records verify against **any** of
 * them (spec 012, inherited by 014's evidence record): a rotation must not orphan records the
 * participant already signed. Returns null — never throws — when the log is absent or does not
 * replay, which the callers turn into the WAIT reason for that record kind.
 */
type ReplayedStates =
  | { kind: "ok"; states: KeyState[] }
  | { kind: "unresolved" }
  | { kind: "too_expensive" }
  /** The view served a valid log belonging to a different participant. Never a WAIT. */
  | { kind: "mismatched" };

async function replayedStates(
  view: TrustView,
  id: ParticipantId,
  operation: VerificationOperation
): Promise<ReplayedStates> {
  let log;
  try {
    log = await view.getKeyLog(id);
  } catch {
    return { kind: "unresolved" };
  }
  if (!log || log.length === 0) {
    return { kind: "unresolved" };
  }
  try {
    // Spends from the REQUEST's allowance, not a fresh one: this is one of several
    // verifications an inbound delivery drives, and a per-call ceiling bounds none of them.
    //
    // BOUND to `id`. `KeyState.id` is derived from the log's OWN inception event, so replaying
    // without comparing it proves only that some identity holds these keys. The view picked the
    // bytes; unbound, a host that answers the creator's or actor's id with an attacker's valid
    // log makes an owner-signed conversation record verify under the attacker's keys, which is
    // impersonation of the named participant with none of their keys.
    replayKeyLogFor(id, log, {
      ...verificationWorkOptions(operation)
    });
  } catch (error) {
    // Cost, invalidity and substitution are three different answers and must stay different:
    // "this verifier would not spend enough", "this log is wrong", and "this log is fine and is
    // not the one I asked for". The first two are WAITs; the third is a rejection.
    if (error instanceof VerificationBudgetExceeded) {
      return { kind: "too_expensive" };
    }
    return error instanceof KeyLogParticipantMismatch
      ? { kind: "mismatched" }
      : { kind: "unresolved" };
  }
  // Newest-first and de-duplicated, exactly as `@kinnet/trust`'s twin does it and for the same
  // reasons: a record verifies against ANY state its issuer has held, so neither ordering nor
  // a repeated key set can change the verdict, and nearly every record is signed by the state
  // current when it was written.
  const seen = new Set<string>();
  const states: KeyState[] = [];
  for (let index = log.length - 1; index >= 0; index -= 1) {
    const event = log[index]!;
    const fingerprint = `${event.threshold}:${event.keys.join(",")}`;
    if (seen.has(fingerprint)) {
      continue;
    }
    seen.add(fingerprint);
    states.push({ keys: event.keys, threshold: event.threshold });
  }
  return { kind: "ok", states };
}

/** Owner mode (spec 012 mode 1): the threshold signature verifies against any replay-valid state. */
/**
 * Metered against the view's ceiling, for the same reason `@kinnet/trust`'s namesake is: a
 * participant's log yields one key state per event, so under spec 015's greedy walk this is
 * `states x keys` work driven by data an untrusted view chose. Signature count is not a cost
 * dimension: `m != t` is rejected before curve work. A budget failure is re-thrown rather than
 * swallowed as `false` — it means "not judged", not "not signed".
 */
function signedByAnyState(
  record: SignedRecord,
  states: KeyState[],
  operation: VerificationOperation
): boolean {
  return states.some((state) => {
    try {
      // ONE allowance across every state, not a fresh one per state. A generic threshold call
      // owns a compatibility fallback much larger than one protocol key state, so omitting a
      // zero remaining value would refill work on every state and make this shared meter cosmetic.
      return verifyThresholdRecord(record, state.keys, state.threshold, {
        ...verificationWorkOptions(operation)
      });
    } catch (error) {
      if (error instanceof VerificationBudgetExceeded) {
        throw error;
      }
      return false;
    }
  });
}

/**
 * Delegated mode (spec 012 mode 2): the record's single signature verifies against exactly the
 * chain's leaf key. A malformed key ref cannot verify, so any decode failure is a rejection.
 *
 * The set must hold **exactly one** signature, and the length check is not pedantry. Threshold
 * verification accepts when *any* member of the set matches and ignores the rest, while
 * `canonicalDigest` covers the `signature` array — so an appended junk signature would turn a
 * valid unit into a second, distinct, equally-valid unit for the same logical change. It confers
 * no new authority (the epoch one-shot pins the change to one commit at one point in history),
 * but it breaks digest-based dedup, which spec 014 leans on throughout: "records are idempotent
 * by digest", a binding names a record by digest, and a held-evidence map is keyed by one. In
 * delegated mode a record has exactly one authorized signer, so one signature is the whole truth.
 * Owner mode is untouched — there a threshold really is a set.
 */
function signedByLeafKey(
  record: SignedRecord,
  leafKey: string,
  operation: VerificationOperation
): boolean {
  if (record.signature.length !== 1) {
    return false;
  }
  try {
    return verifyThresholdRecord(record, [leafKey], "1", {
      ...verificationWorkOptions(operation)
    });
  } catch (error) {
    if (error instanceof VerificationBudgetExceeded) {
      throw error;
    }
    return false;
  }
}

/** What differs between the two records the unit rules apply to; everything else is shared. */
type UnitProfile<R> = {
  /** The participant whose authority the record carries: the evidence actor, the conversation creator. */
  principal: (record: R) => ParticipantId;
  /** The record's own time — the instant every chain link's window is measured against. */
  recordTime: (record: R) => string;
  /** The ability the chain's leaf must cover for THIS record. */
  requiredAbility: (record: R) => string;
  /** Reason for an unresolvable principal key log; the node's existing string for this record. */
  keyLogUnresolvedReason: UnitReason;
  /** Reported when the log was refused for cost rather than being missing or invalid. */
  keyLogTooExpensiveReason: UnitReason;
  /**
   * Reported when the view served a replay-valid log belonging to a DIFFERENT participant.
   * Its own reason, and absent from {@link UNIT_WAIT_REASONS}: a substituted log is a
   * rejection, and an operator seeing it needs to know discovery answered with the wrong log
   * rather than go looking for a publishing fault at the named participant.
   */
  keyLogMismatchReason: UnitReason;
  /** Reason for a chain that delegates for somebody other than the record's principal. */
  subjectMismatchReason: UnitReason;
};

async function verifyUnit<R extends { signature: string[] }>(
  record: R,
  chain: Grant[] | null,
  view: TrustView,
  options: RecordUnitVerifyOptions,
  profile: UnitProfile<R>
): Promise<Verification<UnitReason>> {
  const principal = profile.principal(record);
  const operation = beginVerificationOperation(view, options);
  // Both record schemas are strict and their signature field is `string[]`, so the record IS
  // a signature-set record; the cast only tells the compiler what the schema already pins.
  const signed = record as unknown as SignedRecord;

  // Owner mode. Note the branch is on `chain === null`, not on "owner verification failed":
  // spec 014 pins that a presented chain is never decoration, so a unit carrying a chain is
  // judged as a delegated unit and nothing else. Silently ignoring a malformed chain because
  // the record happened to owner-verify makes the verdict depend on evaluation order and
  // hands an attacker a free field to grind.
  if (chain === null) {
    const resolved = await replayedStates(view, principal, operation);
    if (resolved.kind !== "ok") {
      if (resolved.kind === "too_expensive") {
        return invalid(profile.keyLogTooExpensiveReason);
      }
      return invalid(
        resolved.kind === "mismatched"
          ? profile.keyLogMismatchReason
          : profile.keyLogUnresolvedReason
      );
    }
    const states = resolved.states;
    let ownerSigned;
    try {
      ownerSigned = signedByAnyState(signed, states, operation);
    } catch (error) {
      if (error instanceof VerificationBudgetExceeded) {
        return invalid(profile.keyLogTooExpensiveReason);
      }
      throw error;
    }
    if (!ownerSigned) {
      return invalid("signature_invalid");
    }
    return { valid: true };
  }

  // Delegated mode. Windows are measured against the record's own time and NEVER the wall
  // clock (spec 014 rule 5): a wall-clock verdict would differ between an early member and a
  // joiner re-verifying the same record long after the authoring grant expired, and the same
  // commit would then apply for some members and stall forever for others. Caveats — `aud`
  // included — are not evaluated at record purpose (rule 6); revocation is the caller's call.
  const at = new Date(profile.recordTime(record));
  if (Number.isNaN(at.getTime())) {
    return invalid("record_malformed");
  }
  const verdict = await verifyGrantChain(chain, view, {
    purpose: "record",
    at,
    checkRevocation: options.checkRevocation,
    // The same allowance the owner-mode search above would have spent, so a delegated unit
    // costs one budget rather than one per stage.
    operation,
    ...(options.context ? { context: options.context } : {})
  });
  if (!verdict.valid) {
    return invalid(`chain_invalid:${verdict.reason}`);
  }
  // Rule 2: the chain delegates for the record's own principal. A chain subject anyone else
  // authorizes nothing here, however well-formed it is.
  if (verdict.subjectId !== principal) {
    return invalid(profile.subjectMismatchReason);
  }
  // Rule 3: the leaf audience is a bare KeyRef (spec 011) and the record verifies against
  // exactly that key. A participant-audience leaf names no signing key, so it can bind none.
  if (!keyRefSchema.safeParse(verdict.audienceId).success) {
    return invalid("chain_invalid:audience_not_key");
  }
  try {
    if (!signedByLeafKey(signed, verdict.audienceId, operation)) {
      return invalid("chain_invalid:leaf_key_signature_invalid");
    }
  } catch (error) {
    if (error instanceof VerificationBudgetExceeded) {
      // Keep the established spec-003 cost vocabulary: the leaf verification is part of
      // validating the delegated grant chain, even though it is charged here after the chain
      // resolver returns its audience.
      return invalid("chain_invalid:grant_signature_check_too_expensive");
    }
    throw error;
  }
  // Rule 4: leaf abilities cover what this record needs, under 009's path-prefix rule.
  const required = profile.requiredAbility(record);
  if (!verdict.abilities.some((granted) => abilityCovers(granted, required))) {
    return invalid("chain_invalid:abilities_insufficient");
  }
  return { valid: true };
}

/**
 * A self-departure (spec 014, amended 2026-08-02): a `remove` record whose `members` is exactly
 * `[actor]`. It is self-authorizing under the delivery rules — any member will commit it — so a
 * delegated signer holding it can expel its own subject from every conversation they are in,
 * and, since add authority is creator-only, the victim cannot restore themselves. Hence its own
 * ability, outside the `msg` namespace, which no everyday session grant carries.
 *
 * The `device-remove` variant of the same threat — a record naming every leaf its actor holds —
 * is deliberately **not** decided here: whether a removal takes the actor's *last* leaf is a
 * question about group state, and this verifier is bytes-alone. It is closed one layer up, at
 * commit validity (`device_removes_last_leaf` in a client's commit evaluator; spec 014, amended
 * 2026-08-03), where every member reads the same pre-commit tree and so reaches the same verdict.
 */
export function isSelfDeparture(record: ConversationUpdate): boolean {
  return (
    record.kind === "remove" && record.members.length === 1 && record.members[0] === record.actor
  );
}

const conversationUpdateProfile: UnitProfile<ConversationUpdate> = {
  principal: (record) => record.actor,
  recordTime: (record) => record.createdAt,
  requiredAbility: (record) =>
    isSelfDeparture(record) ? ABILITY_CONVERSATION_SELF_REMOVE : ABILITY_CONVERSATION_UPDATE,
  keyLogUnresolvedReason: "actor_key_log_unresolved",
  keyLogTooExpensiveReason: "actor_key_log_too_expensive",
  keyLogMismatchReason: "actor_key_log_participant_mismatch",
  subjectMismatchReason: "chain_invalid:subject_not_actor"
};

const conversationProfile: UnitProfile<Conversation> = {
  principal: (record) => record.creator,
  recordTime: (record) => record.createdAt,
  requiredAbility: () => ABILITY_CONVERSATION,
  keyLogUnresolvedReason: "creator_key_log_unresolved",
  keyLogTooExpensiveReason: "creator_key_log_too_expensive",
  keyLogMismatchReason: "creator_key_log_participant_mismatch",
  subjectMismatchReason: "chain_invalid:subject_not_creator"
};

/**
 * Verifies a `pn/conversation-update` unit — spec 014's evidence record plus, when it is
 * delegated-signed, its authorizing chain.
 *
 * `chain === null` selects owner mode; a chain, however broken, selects delegated mode and
 * nothing else. Reason strings: `record_malformed`, `actor_key_log_unresolved` (WAIT),
 * `actor_key_log_participant_mismatch` (the view served another participant's log — a
 * rejection, never a WAIT), `signature_invalid`, `chain_invalid:<detail>` where `<detail>` is either a
 * `@kinnet/trust` `grant_*` reason or one of `subject_not_actor`, `audience_not_key`,
 * `leaf_key_signature_invalid`, `abilities_insufficient`.
 */
export async function verifyConversationUpdateUnit(
  record: ConversationUpdate,
  chain: Grant[] | null,
  view: TrustView,
  options: RecordUnitVerifyOptions
): Promise<Verification<UnitReason>> {
  // Well-formedness gates the rules that read the record's own fields — the self-departure
  // test reads `kind`/`members`, whose cross-field discipline is schema-enforced. The
  // signature is verified over the value as given, never over a re-parsed copy: the bytes a
  // signature covers are the caller's bytes.
  if (!conversationUpdateSchema.safeParse(record).success) {
    return invalid("record_malformed");
  }
  return verifyUnit(record, chain, view, options, conversationUpdateProfile);
}

/**
 * Verifies a `pn/conversation` unit — spec 012's Conversation record plus, when it is
 * delegated-signed, its authorizing chain. The same unit over a different record (spec 014's
 * amendment applies the shape to both lanes): a custodial creator re-delivering their own
 * conversation record from a later session, or another member re-delivering it as
 * `addParticipant`'s first step, is exactly the case this closes.
 *
 * Reason strings mirror the update variant, with `creator_key_log_unresolved` (WAIT) and
 * `chain_invalid:subject_not_creator`.
 */
export async function verifyConversationRecordUnit(
  record: Conversation,
  chain: Grant[] | null,
  view: TrustView,
  options: RecordUnitVerifyOptions
): Promise<Verification<UnitReason>> {
  if (!conversationSchema.safeParse(record).success) {
    return invalid("record_malformed");
  }
  return verifyUnit(record, chain, view, options, conversationProfile);
}
