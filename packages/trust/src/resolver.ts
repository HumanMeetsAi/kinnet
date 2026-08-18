/**
 * Trust resolver — reference implementation for spec 008 (revocation), spec 009
 * (grant chains), and spec 011 (key principals, the `aud` caveat), plus
 * represents-chain verification (the S1 gate).
 *
 * Verification is offline-capable: everything resolves through a TrustView of key
 * logs and revocations, so a verifier can run from committed bytes alone.
 */
import {
  canonicalDigest,
  checkAnchoredSignatureSet,
  KeyLogParticipantMismatch,
  replayKeyLogStatesFor,
  safeVerificationCount,
  VerificationBudgetExceeded,
  verifyThresholdRecord,
  type AnchoredKeyState
} from "@kinnet/crypto";
import {
  audCaveatSchema,
  claimSchema,
  grantSchema,
  isE2eeAbility,
  MAX_GRANT_CHAIN_LINKS,
  MAX_KEY_EVENT_KEYS,
  relationshipSchema,
  revocationSchema,
  type Claim,
  type Grant,
  type KeyEvent,
  type KeyRef,
  type ParticipantId,
  type Principal,
  type Relationship,
  type Revocation
} from "@kinnet/protocol";

/** What a verifier must be able to look up; discovery serves both. */
export type TrustView = {
  getKeyLog(id: ParticipantId): Promise<KeyEvent[] | null>;
  /**
   * Ceiling on the Ed25519 verifications ONE key-log replay of this view's data may spend.
   * Omitted leaves `replayKeyLog`'s own default.
   *
   * A view is an untrusted source — that is the premise of every other rule here — and it
   * chooses the key logs this module replays, on a path that runs before the record or chain
   * in hand has proven anything. `replayKeyLog`'s default is sized never to reject a
   * schema-valid log, which is the right property for the service that owns the log and the
   * wrong one for data arriving from a host assumed hostile. A view that fetches over the
   * network should set this; an in-process one need not.
   */
  readonly maxSignatureVerifications?: number;
  /**
   * Revocations of `revokesDigest` published by any of `issuerIds` — an ISSUER-TARGETED
   * lookup, never a listing. Anyone may publish a revocation naming any digest, so the set of
   * records mentioning one digest is attacker-growable; a view that returned that whole set
   * would either be unbounded or truncate, and a truncated revocation answer reads as "not
   * revoked". A verifier always knows which issuers may revoke the record in hand, so it names
   * them. Batched: one call carries the whole authorized-revoker set for a record.
   *
   * A view MAY return fewer records than exist and MAY return records the caller did not ask
   * for; it is a narrowing hint from an untrusted source. {@link verifyGrantChain} and the
   * statement verifiers re-validate everything a view hands back, issuer membership included.
   *
   * It MUST NOT return more records than distinct ids in `issuerIds`. A revocation's identity
   * is (issuer, revoked-digest), so a longer answer describes records that cannot exist and
   * the verifier THROWS rather than sifting it — see `findRevocation`. A view that throws or
   * rejects is treated exactly like an unreachable one.
   *
   * What "treated like unreachable" means is the CALLER's policy, and it is fail-closed for
   * every authorization consumer: `verifyClaim` / `verifyRelationship` / `verifyGrantChain`
   * propagate the rejection, and the surfaces above them deny. The designed exception is
   * a leaf-credential verifier on the E2EE lane, which catches and renders the device UNVERIFIED
   * rather than refusing (spec 014, rule 3) — there the answer is a label on a UI, not an
   * authorization, and refusing a commit the rest of the group applied would split the group.
   */
  getRevocations(revokesDigest: string, issuerIds: readonly string[]): Promise<Revocation[]>;
};

export type VerifyOptions = {
  /** Verification time; defaults to the wall clock. */
  now?: Date;
  /**
   * A {@link VerificationBudget} to spend from, shared with whatever else this request is
   * verifying. Omitted, this call builds its own from `view.maxSignatureVerifications` — which
   * bounds THIS call and nothing else, so a caller that makes several must supply one to bound
   * the request.
   */
  budget?: VerificationBudget;
  /**
   * One request's outer allowance and successful signer-state memo. When present it takes
   * precedence over the legacy bare {@link VerificationBudget}; each public verification
   * operation still receives its own local allowance from the view.
   */
  context?: VerificationContext;
  /**
   * A started operation, threaded only by composing verifier implementations so nested trust
   * calls share one local allowance. Application code should pass {@link VerificationContext}
   * and let the public entry point start this.
   */
  operation?: VerificationOperation;
};

export type GrantVerifyOptions = VerifyOptions & {
  /**
   * Caveat evaluation hook. Caveats fail closed (spec 009): without an evaluator,
   * any grant carrying caveats other than `aud` is rejected. The `aud` caveat is
   * standard (spec 011) and evaluated natively against `verifierId`.
   */
  evaluateCaveats?: (grant: Grant) => boolean;
  /**
   * The verifying surface's own participant id, checked against the chain's
   * effective `aud` (spec 011). A chain restricted by `aud` is rejected unless this
   * id is admitted; omitting it fails closed for any chain carrying `aud`.
   *
   * It binds AUD-RESTRICTED chains only: an `aud`-less chain names no verifier and is
   * unrestricted by spec 011, so this id does not narrow it. Set `requireAud` to make
   * audience binding mandatory.
   */
  verifierId?: ParticipantId;
  /**
   * The verifier demands that delegation chains be audience-bound; a chain no link of
   * which carries an `aud` caveat is rejected (`grant_audience_required`).
   *
   * Spec 011 makes `aud` mandatory only for key-audience links, so a chain whose every
   * audience is a participant may legally omit it — and an unrestricted chain is
   * admitted by every verifier, whatever `verifierId` says. A relying party that treats
   * its own id as the boundary sets this. Defaults to false: behavior unchanged.
   *
   * Request purpose only. Spec 014 lifts 011's `aud` requirement for credential links
   * (there is no request surface to bind them to), so demanding `aud` while verifying a
   * credential would reject a record the schema calls valid; the demand is skipped there.
   */
  requireAud?: boolean;
  /**
   * What the chain is being presented AS (spec 014). Defaults to `"request"`, the
   * fail-closed side: a caller that never considered 014 gets the rejecting behavior.
   *
   * - `"request"` — the chain is offered as authorization for a request. Spec 014: "A
   *   verifier MUST reject a request whose presented chain contains **any** ability"
   *   in the `e2ee` namespace.
   * - `"credential"` — the chain is being member-verified as an MLS credential (the one
   *   place an `e2ee` chain is meant to be valid). Never set this on a request path.
   * - `"record"` — the chain is the authorizing half of a stored `(record, chain)` unit
   *   (a delegated-signed evidence record). Structure, signatures, subject constancy and
   *   ability attenuation are checked exactly as elsewhere; three things differ, each
   *   because the chain is being re-verified long after — and far from — the delivery it
   *   authorized:
   *   1. validity windows are measured against {@link at}, the record's own `createdAt`,
   *      never the wall clock (an expired grant does not retroactively unauthenticate
   *      what was signed under it, spec 011; and a wall-clock verdict would differ
   *      between an early member and a later joiner re-verifying the same record);
   *   2. caveats — `aud` included — are NOT evaluated: session grants are `aud`-bound to
   *      the node that gated the authoring delivery in real time, so a verifying member
   *      is never the named audience and fail-closed evaluation would reject every
   *      well-formed chain (spec 011: caveats are delivery-time-only for stored chains);
   *   3. revocation is checked only under {@link checkRevocation}.
   *   The `e2ee` namespace rejection is request-only and so does not apply.
   */
  purpose?: "request" | "credential" | "record";
  /**
   * The instant every link's `[issuedAt, expiresAt]` window is measured against at
   * `"record"` purpose: the record's `createdAt`. Required there and fail-closed
   * (`grant_record_time_required`) when absent — silently falling back to the wall clock
   * is the exact confusion this purpose exists to prevent. Ignored at other purposes,
   * which measure against {@link VerifyOptions.now}.
   *
   * A record dated before a link's `issuedAt` is rejected (`grant_not_yet_issued`): the
   * lower bound is what keeps `createdAt`, which the signer chooses, from reaching back
   * before the authority it cites existed.
   */
  at?: Date;
  /**
   * Whether revocation is a verification input at `"record"` purpose. Defaults to true;
   * the other purposes always check and ignore this flag.
   *
   * The node sets it (true) when gating a delivery: that check is real time, local, and
   * non-consensus. Members verifying stored evidence clear it, deliberately — a
   * revocation one member's discovery view holds and another's does not would make one
   * member apply a commit and the other wait forever. A member that does know a chain is
   * revoked refuses to build on it rather than re-deciding a delivered record's validity.
   */
  checkRevocation?: boolean;
};

/**
 * Every reason {@link verifyGrantChain} can return. Written out because the TYPE is what keeps
 * the cost-reason classification honest: `invalid` accepts only members of this union, and
 * {@link GrantChainVerification}'s invalid arm carries it, so a reason that is not listed here
 * cannot be produced — not by `invalid`, and not by a bare object literal either.
 */
export type GrantChainReason =
  | "grant_ability_escalation"
  | "grant_aud_escalation"
  | "grant_audience_not_admitted"
  | "grant_audience_required"
  | "grant_caveat_rejected"
  | "grant_chain_empty"
  | "grant_chain_incomplete"
  | "grant_chain_too_long"
  | "grant_e2ee_not_request_valid"
  | "grant_expired"
  /**
   * Spec 016: the link's `anchor` names no event of its issuer's key log, so there is no state
   * to judge its signature set against. Its own reason, never folded into
   * `grant_signature_invalid`, because 016 requires an unknown anchor to be reported
   * distinguishably from a signature-set failure: the two call for different responses — a bad
   * set is a forgery, an unknown anchor may be a view that has not seen the issuer's later
   * events. On this request-time path it is still a rejection (016, _Log freshness_).
   */
  | "grant_issuer_anchor_unknown"
  | "grant_issuer_key_log_participant_mismatch"
  | "grant_issuer_key_log_too_expensive"
  | "grant_issuer_key_log_unresolved"
  | "grant_issuer_not_parent_audience"
  | "grant_key_issuer_signature_invalid"
  | "grant_malformed"
  | "grant_not_yet_issued"
  | "grant_proof_mismatch"
  | "grant_record_time_required"
  | "grant_revoked"
  | "grant_root_not_self_issued"
  | "grant_signature_check_too_expensive"
  | "grant_signature_invalid"
  | "grant_subject_drift";

/** Every reason {@link verifyClaim} and {@link verifyRelationship} can return. */
type StatementReason =
  | `${"claim" | "relationship"}_${"malformed" | "expired" | "revoked" | "signature_invalid"}`
  | "issuer_key_log_participant_mismatch"
  | "issuer_key_log_too_expensive"
  | "issuer_key_log_unresolved";

/** The reasons {@link verifyRepresentsChain} adds to the two above, which it also forwards. */
type RepresentsOwnReason =
  | "agent_key_log_participant_mismatch"
  | "agent_key_log_too_expensive"
  | "agent_key_log_unresolved"
  | "edge_not_issued_by_represented"
  | "edge_object_mismatch"
  | "edge_predicate_mismatch"
  | "edge_subject_mismatch"
  | "grant_audience_not_agent"
  | "grant_subject_not_organization";

/** Every reason any entry point in this module can return. */
export type ResolverReason = GrantChainReason | StatementReason | RepresentsOwnReason;

/**
 * Generic in its reason so a caller that produces a WIDER set — `@kinnet/verify`'s unit verifier
 * forwards these and adds its own — names that set while this module's own returns stay pinned
 * to {@link ResolverReason}.
 *
 * NO DEFAULT, deliberately. It had one (`= string`), and the default was a silent opt-out from
 * every guarantee built on this type: a verdict-producing function written as
 * `Promise<Verification>` accepted any reason at all, so a bare
 * `{ valid: false, reason: "..._too_expensive" }` compiled clean and reached a consumer's
 * cost/wait classification unclassified. That is not hypothetical — it is how the hole was found,
 * twice, once inside this package's own consumers and once across a package boundary.
 * Without the default, omitting the parameter does not compile, so the choice has to be written
 * down at every position that produces a verdict.
 */
export type Verification<R extends string> = { valid: true } | { valid: false; reason: R };

export type GrantChainVerification =
  | {
      valid: true;
      subjectId: ParticipantId;
      /** The leaf's audience: a participant id or, per spec 011, a bare KeyRef. */
      audienceId: Principal;
      abilities: string[];
    }
  | { valid: false; reason: GrantChainReason };

export type RepresentsVerification =
  | {
      valid: true;
      agentId: ParticipantId;
      organizationId: ParticipantId;
      /** Present when a bounding grant chain was verified alongside the edge. */
      abilities?: string[];
    }
  | { valid: false; reason: ResolverReason };

function invalid<R extends ResolverReason>(reason: R): { valid: false; reason: R } {
  return { valid: false, reason };
}

/**
 * Every reason {@link verifyGrantChain} returns when it ran out of allowance rather than found
 * something wrong. There are TWO, and treating them as one was a real defect: a caller that
 * mapped only the key-log one reported a pure cost refusal as "this record is malformed".
 *
 * - `grant_issuer_key_log_too_expensive` — a link's issuer log could not be replayed within the
 *   allowance. Reported where it happens, because it names the log.
 * - `grant_signature_check_too_expensive` — the OTHER spender: the threshold-signature checks
 *   (a link against its issuer's anchored key state, a revocation candidate against its
 *   issuer's), and the revocation sub-allowance of
 *   {@link MAX_REVOCATION_CANDIDATE_VERIFICATIONS}. Spec 016 made each such check `K` rather
 *   than `E * K`, so it is now far below one replay; this reason still covers their
 *   multiplicity across links and revocation candidates, and it stays reachable because the
 *   shared allowance is spent by the replays too.
 *
 * EXPORTED so consumers classify from this list rather than from a hand-written copy of it.
 * `@kinnet/verify` builds its own cost-reason set by mapping over this one, so a reason added
 * here reaches that set without anybody remembering to.
 *
 * Kept honest by the TYPE SYSTEM rather than by a convention. {@link CostReasonsAreClassified}
 * below asserts that this list and the cost-shaped members of {@link GrantChainReason} are the
 * same set, in BOTH directions — so an unlisted cost reason fails to compile, and so does an
 * entry here that no exit produces.
 */
export const GRANT_CHAIN_COST_REASONS = [
  "grant_issuer_key_log_too_expensive",
  "grant_signature_check_too_expensive"
] as const;

/**
 * Every `*_too_expensive` reason ANY entry point in this module can return — the grant-chain
 * pair plus the ones only the statement and represents verifiers produce. Spec 003 makes a
 * verification-work ceiling a local resource policy rather than a validity rule, so every
 * surface above has to be able to tell this class apart from "invalid".
 *
 * This is the list to test a mapping against. It is NOT a claim that a suffix match is wrong:
 * `@kinnet/verify`'s request verifier matches `_too_expensive` as a suffix and is right to —
 * it needs no per-reason handling, only the cost/invalid split, and a suffix match cannot go
 * stale. A consumer that must ENUMERATE the reasons — because it maps each to a different
 * answer, as the record-unit verifier does — uses this list instead of writing its own.
 */
export const TRUST_COST_REASONS = [
  ...GRANT_CHAIN_COST_REASONS,
  /** {@link verifyClaim} / {@link verifyRelationship}: the issuer's log, its signature search, or its revocation lookup. */
  "issuer_key_log_too_expensive",
  /** {@link verifyRepresentsChain}: the agent's own log. */
  "agent_key_log_too_expensive"
] as const;

/** Any reason string shaped like a cost refusal. */
type CostShaped = `${string}_too_expensive`;

type Assert<T extends true> = T;
type SameSet<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

/**
 * The classification guarantee, as a COMPILE-TIME proof rather than a test convention.
 *
 * `invalid` takes {@link ResolverReason} and every verdict type's invalid arm carries it, so a
 * new refusal reason has to join that union before it can be returned — by `invalid`, by a bare
 * `{ valid: false, reason }` literal, or by a template string, none of which can widen to
 * `string` any more. These two aliases then fail to compile unless every cost-SHAPED member of
 * the union appears in the corresponding list, and unless every list entry is a member.
 *
 * What this does NOT cover, stated because the previous mechanism claimed more than it did: a
 * reason produced by throwing rather than returning, and a consumer that re-spells a reason on
 * its way out. `@kinnet/verify` prefixes these with `chain_invalid:` and carries its own proof
 * of the same shape for the result.
 */
export type ChainCostReasonsAreClassified = Assert<
  SameSet<Extract<GrantChainReason, CostShaped>, (typeof GRANT_CHAIN_COST_REASONS)[number]>
>;
export type CostReasonsAreClassified = Assert<
  SameSet<Extract<ResolverReason, CostShaped>, (typeof TRUST_COST_REASONS)[number]>
>;

function isExpiredAt(expiresAt: string | undefined, now: Date): boolean {
  return Boolean(expiresAt && Date.parse(expiresAt) <= now.getTime());
}

/**
 * Per-context memo of `signerStates`. A chain verification asks about the same
 * participant repeatedly — once per link, and again per link for revocation issuers — and
 * each ask replayed the log from scratch, so an N-link chain paid N replays for one
 * identity. A request context shares successful results across its constituent operations;
 * a call with no context gets a private map. Nothing survives the context, because a
 * longer-lived cache would have to reason about a log that rotates between requests.
 *
 * It is a memo, NOT a correctness mechanism. Exhaustion during a revocation lookup fails
 * closed because `findRevocation` throws on it directly; it does not depend on this map
 * happening to remember a `too_expensive` result. That distinction matters because an earlier
 * shape relied on the memo to carry the refusal, which meant deleting the cache would have
 * silently turned "could not check for a revocation" into "not revoked".
 */
type SignerStateCache = Map<ParticipantId, Promise<SignerStatesResult>>;

/**
 * One allowance shared across everything a single VERIFICATION CALL reaches.
 *
 * Every public entry point in this module accepts one and threads it through every Ed25519
 * verification it can drive — replay, threshold checks against each historical key state,
 * key-issuer links, revocation candidates, and the nested stages of a represents chain. A
 * chain replays a log per distinct issuer, so a per-log ceiling would multiply by the link
 * count; sharing one means the ceiling is what the call costs.
 *
 * SCOPE, stated precisely because it is easy to overstate: a bare caller-owned budget bounds one
 * operation. A {@link VerificationContext} adds a distinct outer allowance spanning every
 * operation the request handler passes it to; each operation keeps its own local meter as well.
 */
export type VerificationBudget = { remaining: number };

/**
 * One request's shared verification state.
 *
 * The outer budget is mutable and caller-owned. The memo is isolated first by exact
 * {@link TrustView} object identity and then by participant id, so bytes returned by one view
 * can never authorize a call made against another. Values are promises to coalesce concurrent
 * asks; only successful replay results remain cached.
 */
export type VerificationContext = {
  readonly budget: VerificationBudget;
  readonly signerStates: WeakMap<TrustView, SignerStateCache>;
};

/** Builds a request context while preserving the supplied budget object's identity. */
export function createVerificationContext(budget: VerificationBudget): VerificationContext {
  budget.remaining = safeVerificationCount(budget.remaining, 0);
  return { budget, signerStates: new WeakMap() };
}

/**
 * The meters and memo for one public trust/verify operation. Composing implementations thread
 * this through nested calls so their local allowance is not silently refreshed.
 */
export type VerificationOperation = {
  /** Exact view this operation was started for; signer bytes never cross this boundary. */
  readonly view: TrustView;
  /** Exact outer context, when any; prevents a composed caller from swapping its meter. */
  readonly context?: VerificationContext;
  readonly local?: VerificationBudget;
  readonly outer?: VerificationBudget;
  readonly signerStates: SignerStateCache;
};

/** Programming error: a composing caller threaded an operation across its ownership boundary. */
export class VerificationOperationMismatch extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationOperationMismatch";
  }
}

function normalizedBudget(
  view: TrustView,
  supplied: VerificationBudget | undefined
): VerificationBudget | undefined {
  if (supplied) {
    // Preserve the caller-owned object's identity and mutation semantics, but never pass a
    // malformed runtime value down to a leaf API where it could select that API's full fallback.
    // Zero is valid and remains zero, so repeating this at a nested entry cannot refill an
    // exhausted allowance.
    supplied.remaining = safeVerificationCount(supplied.remaining, 0);
    return supplied;
  }
  return view.maxSignatureVerifications === undefined
    ? undefined
    : { remaining: safeVerificationCount(view.maxSignatureVerifications, 0) };
}

/** Starts one locally bounded operation, optionally inside a wider request context. */
export function beginVerificationOperation(
  view: TrustView,
  options: Pick<VerifyOptions, "budget" | "context" | "operation"> = {}
): VerificationOperation {
  if (options.operation) {
    if (options.operation.view !== view) {
      throw new VerificationOperationMismatch(
        "A verification operation cannot be reused with a different TrustView"
      );
    }
    if (options.context !== undefined && options.operation.context !== options.context) {
      throw new VerificationOperationMismatch(
        "A verification operation cannot be reused with a different VerificationContext"
      );
    }
    return options.operation;
  }
  if (options.context) {
    // Context precedence is deliberate: a stale caller may pass both old `budget` and new
    // `context`; the outer request meter must be the context's exact object, never a refill.
    options.context.budget.remaining = safeVerificationCount(options.context.budget.remaining, 0);
    let signerStates = options.context.signerStates.get(view);
    if (!signerStates) {
      signerStates = new Map();
      options.context.signerStates.set(view, signerStates);
    }
    return {
      view,
      context: options.context,
      local: normalizedBudget(view, undefined),
      outer: options.context.budget,
      signerStates
    };
  }
  return {
    view,
    local: normalizedBudget(view, options.budget),
    signerStates: new Map()
  };
}

/**
 * Crypto-leaf options that charge every distinct applicable meter in parallel.
 *
 * Candidate allowance is the third meter used by revocation lookup. Object de-duplication is
 * load-bearing: a legacy caller may use the same object in two positions and one curve check
 * must never be charged twice to it.
 */
export function verificationWorkOptions(
  operation: VerificationOperation,
  allowance?: VerificationBudget
): {
  maxSignatureVerifications?: number;
  onSignatureVerifications?: (spent: number) => void;
} {
  const budgets = Array.from(
    new Set(
      [operation.local, operation.outer, allowance].filter(
        (budget): budget is VerificationBudget => budget !== undefined
      )
    )
  );
  for (const budget of budgets) {
    budget.remaining = safeVerificationCount(budget.remaining, 0);
  }
  if (budgets.length === 0) {
    return {};
  }
  return {
    maxSignatureVerifications: Math.min(...budgets.map((budget) => budget.remaining)),
    onSignatureVerifications: (spent) => {
      for (const budget of budgets) {
        budget.remaining -= spent;
      }
    }
  };
}

/**
 * Why a signer state could not be produced.
 *
 * Spec 003 makes a verification-work ceiling a local resource policy, not a validity rule,
 * and requires a refusal on cost to be reported distinguishably from "invalid" — otherwise a
 * publisher whose log is perfectly correct is told to go and fix it, and an operator sees an
 * authenticity failure where they have a capacity condition.
 *
 * Carried PER CALL rather than latched on the budget. A latch is sticky: once anything had
 * been refused for cost, every later absent-or-invalid log reported as too expensive too,
 * which inverts the exact distinction this exists to draw.
 */
type SignerStatesResult =
  | {
      kind: "ok";
      /**
       * Every state the log commits, in sequence order, each tagged with the digest of the
       * event that established it — spec 016's anchor lookup table. Sequence order rather
       * than newest-first because that is what the replay produces and what an anchor lookup
       * is indifferent to; the one consumer that still WALKS states (the scalar-signature
       * statements, outside 016's scope) reverses as it goes.
       */
      states: AnchoredKeyState[];
    }
  | { kind: "unresolved" }
  | { kind: "too_expensive" }
  /**
   * The view answered with a log that replays perfectly and belongs to somebody else — the
   * substituted-log case. Its own kind, not folded into `unresolved`, for two reasons.
   *
   * Diagnosability: "no key log resolves for V" sends an operator to look at V's publishing,
   * where the fault is entirely in the host that answered. And convergence: key logs are
   * monotone, so `unresolved` legitimately means "wait, my view may catch up" to the callers
   * that treat it that way (`@kinnet/verify`'s unit verifier does). A log that derives a
   * different participant id is not a view lagging behind — no honest host ever produces it —
   * so it must reject rather than stall forever.
   */
  | { kind: "mismatched" };

/**
 * Every key state a participant's replay-valid log commits, each tagged with the digest of the
 * event that established it (spec 016).
 *
 * ONE replay per issuer per operation, whatever asks: an anchored record resolves its own state
 * out of this table by digest (Revocation, participant-issued Grant), and the scalar-signature
 * statements — Claim and Relationship, which 016 does not scope — still walk it. Both read the
 * same replay, so adding the anchor lookup added no curve work to either.
 */
async function signerStates(
  view: TrustView,
  id: ParticipantId,
  operation: VerificationOperation
): Promise<SignerStatesResult> {
  const cache = operation.signerStates;
  const cached = cache.get(id);
  if (cached !== undefined) {
    return cached;
  }
  const pending = resolveSignerStates(view, id, operation);
  cache.set(id, pending);
  try {
    const resolved = await pending;
    if (resolved.kind !== "ok" && cache.get(id) === pending) {
      cache.delete(id);
    }
    return resolved;
  } catch (error) {
    if (cache.get(id) === pending) {
      cache.delete(id);
    }
    throw error;
  }
}

async function resolveSignerStates(
  view: TrustView,
  id: ParticipantId,
  operation: VerificationOperation
): Promise<SignerStatesResult> {
  const log = await view.getKeyLog(id);
  if (!log || log.length === 0) {
    return { kind: "unresolved" };
  }
  let replayed;
  try {
    // The view's own ceiling, not the general one: this replay is driven by data the view
    // supplied, and every caller above reaches here before anything has been authenticated.
    // When a shared budget is in play the remaining allowance is what applies, and what this
    // replay spends comes off it — including a replay that FAILED, or a view able to force
    // failures would buy the allowance again on every attempt.
    //
    // BOUND to `id`, and that binding is load-bearing rather than belt-and-braces. A
    // `KeyState.id` is self-derived from the log's own inception event, so a bare replay
    // establishes only that SOME identity owns these keys — never that it is the identity
    // whose records we are about to check. The view chose which bytes to return for this id;
    // unbound, a host serving participant A's genuine log at participant V's path makes every
    // claim, relationship and grant naming V verify under A's keys, with none of V's keys
    // involved. The returned state was previously discarded, which is exactly how the check
    // went missing.
    //
    // Binding matters MORE under spec 016, not less: an anchor selects a state WITHIN a log and
    // says nothing about whose log it is, so an unbound replay would let a substituted log
    // supply the very state a record's anchor names.
    replayed = replayKeyLogStatesFor(id, log, {
      // No fallback to `view.maxSignatureVerifications` here: every public entry point builds
      // a shared budget from it, so a missing budget means the view set no ceiling at all. A
      // second path that read the view directly would be an untested branch that silently
      // took a FRESH full allowance per replay instead of sharing one.
      ...verificationWorkOptions(operation)
    });
  } catch (error) {
    if (error instanceof VerificationBudgetExceeded) {
      return { kind: "too_expensive" };
    }
    return error instanceof KeyLogParticipantMismatch
      ? { kind: "mismatched" }
      : { kind: "unresolved" };
  }
  // Handed back exactly as the replay produced them: one entry per event, in sequence order,
  // each carrying the anchor that selects it. No re-walk of `log` here — the digests are the
  // ones the replay already computed for `prior` chaining, so re-deriving them would be the
  // same hashing done twice, and a locally rebuilt list is a second place for the state an
  // anchor resolves to to be wrong.
  //
  // The old shape — newest-first, de-duplicated by `threshold:keys` — is gone with the
  // existential it served. De-duplication in particular MUST NOT come back: two events can now
  // legally commit the same key set (spec 016 retires 003's "no two states may share a quorum"),
  // and they are different anchors, so collapsing them would drop a state some record names.
  return { kind: "ok", states: replayed.states };
}

/**
 * Does the record verify against any key state this participant has held?
 *
 * SCALAR-SIGNATURE RECORDS ONLY — Claim and Relationship, lifted into set form by
 * {@link asSignatureSet}. Spec 016 scopes `anchor` to the four signature-set record types and
 * leaves these two as they were, so they keep 015 S5's existential: a rotation must not orphan
 * a claim its issuer signed years ago, and a one-member set carries no keyless cross-state edit
 * (there is nothing to delete or reorder), which is the malleability anchoring exists to close.
 * The anchored records — Revocation, participant-issued Grant — go through
 * {@link signedAtAnchor} instead, and this function must not be reintroduced for them.
 *
 * MOST RECENT FIRST, and distinct key sets only. The order cannot change WHICH records verify;
 * it changes what they cost, and with a shared budget in play a cost refusal is itself a
 * verdict. Nearly every honest statement is signed by the state current when it was written, so
 * newest-first finds its match immediately where oldest-first would walk the whole history.
 * De-duplication is the same argument — two events listing the same keys and threshold are one
 * question asked twice — and it is now a shape that really occurs: spec 016 retires 003's "no
 * two states may share a quorum", so a log MAY re-list a key set. Collapsing duplicates is safe
 * HERE, where the states are searched, and would be a defect in the anchored lookup, where each
 * state is named by its own digest.
 *
 * METERED against the shared allowance. `resolveSignerStates` yields one state PER LOG EVENT —
 * up to `MAX_KEY_LOG_EVENTS` — each listing up to `MAX_KEY_EVENT_KEYS` keys, and spec 015's
 * greedy walk spends at most one verification per listed key per state, so one call is at most
 * `E * K` = `128 x 8` = 1024 verifications. That figure is now confined to this path: an
 * anchored record costs `K`.
 *
 * Throws {@link VerificationBudgetExceeded} when the allowance runs out; the call sites render
 * that as a cost refusal rather than as a bad signature.
 */
function signedByAnyState(
  record: Record<string, unknown> & { signature: string[] },
  states: readonly AnchoredKeyState[],
  operation: VerificationOperation
): boolean {
  const seen = new Set<string>();
  for (let index = states.length - 1; index >= 0; index -= 1) {
    const state = states[index]!;
    const fingerprint = `${state.threshold}:${state.keys.join(",")}`;
    if (seen.has(fingerprint)) {
      continue;
    }
    seen.add(fingerprint);
    if (
      verifyThresholdRecord(record, state.keys, state.threshold, {
        ...verificationWorkOptions(operation)
      })
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Spec 016's verdict for an anchored signature-set record: the state its `anchor` names, and
 * that state alone.
 *
 * Three outcomes, and the third is why this returns a string rather than a boolean. An unknown
 * anchor is not a signature failure — 016 requires a verifier to "report that outcome
 * distinguishably from a signature-set failure", because the two call for different responses:
 * a failing set is a forgery, while an anchor naming no event of the log may equally be a view
 * that has not caught up with the issuer's later rotations.
 *
 * WHAT IT COSTS. One run of 015's greedy walk against ONE state: at most
 * `K = MAX_KEY_EVENT_KEYS` = 8 verifications, whatever the log's length and whatever the
 * record's member count (a set whose count is not exactly the threshold is refused on its
 * length before any curve work). The `E` factor of {@link signedByAnyState} is gone, not
 * reduced — the lookup is by digest and exactly one state is tried — and an unknown anchor
 * costs ZERO curve work, because there is no state to walk.
 *
 * `allowance`, when supplied, is a SECOND ceiling charged in parallel with the shared one —
 * the revocation search's sub-allowance (see {@link MAX_REVOCATION_CANDIDATE_VERIFICATIONS}).
 * Both are charged for every verification and the tighter of the two is what stops the walk, so
 * exhausting either throws. Two separate objects rather than one nested budget because the
 * shared allowance must still see what a revocation lookup spent: work that came off a
 * sub-allowance is work the request performed, and a caller bounding a whole request would
 * otherwise be told it was free.
 *
 * Throws {@link VerificationBudgetExceeded} when either allowance runs out; the call sites
 * render that as a cost refusal rather than as a bad signature.
 */
function signedAtAnchor(
  record: Record<string, unknown> & { signature: string[]; anchor: string },
  states: readonly AnchoredKeyState[],
  operation: VerificationOperation,
  allowance?: VerificationBudget
): "ok" | "anchor_unknown" | "signature_invalid" {
  const result = checkAnchoredSignatureSet(record, states, {
    ...verificationWorkOptions(operation, allowance)
  });
  if (result.ok) {
    return "ok";
  }
  return result.code === "anchor_unknown" ? "anchor_unknown" : "signature_invalid";
}

/** Lifts a single-signature record (claim, relationship) into the signature-set form. */
function asSignatureSet<T extends { signature: string }>(
  record: T
): Omit<T, "signature"> & { signature: string[] } {
  return { ...record, signature: [record.signature] };
}

/**
 * Ed25519 verifications ONE revocation lookup may spend checking candidate signatures.
 *
 * WHY A SUB-ALLOWANCE EXISTS AT ALL. Everything else a chain verification does is sized by the
 * chain: one replay and one signature check per link, so `MAX_GRANT_CHAIN_LINKS` bounds it. The
 * revocation search is not sized that way — a link may ask about `u` authorized participant
 * issuers and an UNTRUSTED VIEW chooses the candidate bytes — so the lookup's contribution to a
 * caller's cost model has to be a constant of this module rather than a number the view picks.
 *
 * RE-DERIVED FOR SPEC 016, not carried over. The previous value was `2 * E * K` = 2048, sized on
 * the `E` factor of an any-state search: a revocation was offered to every state its issuer's log
 * had ever committed, so ONE candidate could cost `E * K` = 1024. Anchoring removes that factor —
 * a revocation names the one state it is judged against and `checkAnchoredSignatureSet` tries
 * that state and no other — so the arithmetic is done again from the new shape. Writing
 * `K = MAX_KEY_EVENT_KEYS` (8) and `L = MAX_GRANT_CHAIN_LINKS` (4):
 *
 *   one candidate    <= K        = 8      one run of 015's greedy walk against ONE state
 *   honest ceiling   =  K        = 8      an honest lookup returns on the genuine record
 *   this allowance   = 2 * K     = 16     (headroom factor exactly 2, as before)
 *
 * WHAT "HONEST CEILING = K" MEANS. The per-candidate term is `K` for any candidate a view can
 * send: a set whose member count is not exactly the anchored state's threshold is refused on its
 * LENGTH before any curve work, one whose anchor names no event of the issuer's log is skipped
 * before any curve work, and one that reaches the walk costs at most one verification per listed
 * key. Neither the log's length nor the record's member count appears. And an honest lookup pays
 * that term ONCE: discovery signature-checks a revocation before storing it, so an honest
 * candidate verifies and the loop returns on it. A lookup that pays for a second candidate has
 * already been sent one record that is not what it claims to be.
 *
 * WHY NOT `K` EXACTLY, and why not `L * K`. `K` is the smallest constant that admits the honest
 * ceiling, and it would refuse the first stale or forged answer placed ahead of the genuine
 * record — a shape the previous constant deliberately tolerated. The factor of two buys exactly
 * that: one rejected, stale, or hostile candidate followed by the genuine revocation, and no
 * more. At the other end, `L * K` = 32 is the most a CONFORMING answer can cost (at most one
 * record per requested issuer, and this module names at most `L` issuers), so an allowance of
 * `L * K` could never bind — it would be arithmetic rather than a bound, and a hostile view
 * filling every slot would spend the maximum by right.
 *
 * THE REPLAY IS NOT CHARGED HERE, and the accounting is unchanged in that respect: an issuer's
 * key log is replayed through `signerStates`, which charges the operation's local and outer
 * meters and never this sub-allowance, and it is memoized per operation, so a lookup asking about
 * `u` issuers pays at most `u` replays ONCE for the whole verification rather than once per
 * candidate. This constant covers candidate signature checks and nothing else — which is why a
 * hostile answer still costs a verifier a replay per named issuer, bounded by the operation's own
 * allowance rather than by this one.
 *
 * AN UNKNOWN ANCHOR COSTS NOTHING. A candidate whose anchor names no event of its issuer's log is
 * not the issuer's record; it does not revoke, and it is skipped like any other candidate that
 * fails its checks — before any curve work, so a view that answers every lookup with unanchored
 * candidates buys itself zero verifications rather than a full search each.
 *
 * IT DOES NOT FOLLOW that everything within this allowance fits a caller's own ceiling. A
 * rejected candidate leaves the chain running, so its cost ADDS to the chain's rather than
 * replacing part of it. This constant bounds what ONE LOOKUP may spend; whether the composition
 * fits is the caller's ceiling to state (see {@link verifyGrantChain}'s closed form).
 *
 * EXHAUSTION FAILS CLOSED. Running out throws {@link VerificationBudgetExceeded} out of
 * `findRevocation`, exactly as an issuer resolving `too_expensive` already did, and the callers
 * render it as `grant_signature_check_too_expensive` / `issuer_key_log_too_expensive`. A lookup
 * that ran out established nothing, and "nothing" must never read as "not revoked".
 */
export const MAX_REVOCATION_CANDIDATE_VERIFICATIONS = 2 * MAX_KEY_EVENT_KEYS;

/**
 * Finds a valid revocation for a record digest (spec 008): issued by an authorized
 * revoker and signed per a key state from the revoker's own replay-valid log.
 * Unauthorized or badly signed revocations are ignored, so a forged revocation
 * cannot withdraw someone else's record.
 *
 * The view is asked for the authorized revokers BY NAME, in one batched call — so the
 * candidate list a verifier examines is sized by this set and not by however many
 * revocations strangers published against the digest.
 *
 * Round trips: one view call per record checked. A chain is capped at
 * `MAX_GRANT_CHAIN_LINKS`, and the authorized-revoker set for a link is a suffix of that chain,
 * so this resolver asks for at most `MAX_GRANT_CHAIN_LINKS` issuers at once. A conforming chain
 * therefore stays below the discovery route's per-request issuer bound; `createDiscoveryView`'s
 * chunking is defensive behavior for direct calls outside this resolver, not a term in this
 * chain's request count.
 *
 * Narrowing the ask does not make the answer trusted. The discovery host serving it is
 * hostile in the threat model: it may withhold records, and it may return records nobody
 * asked for. So every predicate below still runs on every candidate — schema, digest
 * equality, membership in `authorizedRevokers`, key-log replay, signature — exactly as when
 * this scanned an unfiltered listing. Deleting any of them would let the SERVER pick which
 * revocation counts.
 */
async function findRevocation(
  view: TrustView,
  digest: string,
  authorizedRevokers: ParticipantId[],
  operation: VerificationOperation
): Promise<Revocation | null> {
  const requested = new Set(authorizedRevokers);
  const candidates = await view.getRevocations(digest, authorizedRevokers);
  // ONE sub-allowance for this whole lookup, shared across its candidates rather than minted
  // per candidate. Per-candidate is the shape that does not bound anything: the caller's cost
  // would still scale with however many candidates the view chose to send, which is the
  // amplification this exists to remove. Shared, the lookup's contribution to the caller's
  // model is the constant below, whatever the view answers with.
  const candidateAllowance: VerificationBudget = {
    remaining: MAX_REVOCATION_CANDIDATE_VERIFICATIONS
  };
  // The work this loop does must be sized by the issuer set WE named, not by what the server
  // chose to send. A hostile view is free to answer a two-issuer question with a million
  // records: every one of them would be schema-parsed, and the ones bearing a requested
  // issuer id would each cost a key-log fetch and replay. Narrowing the ASK does not narrow
  // the ANSWER, so the answer is checked too. At most one revocation per requested issuer can
  // exist — (issuer, revoked-digest) is a revocation's identity — so more candidates than
  // distinct issuers asked for is a malformed answer on its face.
  //
  // Throwing is the right severity, and it is cheap: this is the same failure class as the
  // view being unreachable, and every caller already treats a thrown lookup as a denial. It
  // costs nothing in verdict integrity either — a hostile view can already force the
  // fail-open direction simply by WITHHOLDING the revocation, so refusing its oversized
  // answer takes away an amplification vector without handing it any new power.
  //
  // This bounds RECORDS processed, not BYTES received: the response body is parsed by the
  // view before it reaches here, so a hostile host can still make a verifier read and parse an
  // arbitrarily large body. That bound belongs at the HTTP layer and is deferred to the
  // outbound-response caps (W1); see the note in `@kinnet/verify`'s discovery view.
  if (candidates.length > requested.size) {
    throw new Error(
      `Revocation lookup returned ${candidates.length} records for ${requested.size} requested issuers`
    );
  }
  for (const candidate of candidates) {
    const parsed = revocationSchema.safeParse(candidate);
    if (!parsed.success || parsed.data.revokes !== digest) {
      continue;
    }
    // Re-checked client-side even though the view was asked for exactly these issuers: the
    // view is untrusted, so "I only asked for these" is not evidence that "these are what
    // came back". A record from an unrequested issuer is ignored — not honored, not an error.
    if (!requested.has(parsed.data.issuerId)) {
      continue;
    }
    const resolved = await signerStates(view, parsed.data.issuerId, operation);
    if (resolved.kind === "too_expensive") {
      // Propagated, not swallowed: a revocation lookup that ran out of allowance established
      // nothing, and "nothing" must not read as "not revoked".
      //
      // REACHABLE, and it must not be assumed otherwise. The authorized revokers for a link are
      // the issuers of that link and every link ABOVE it, and
      // `verifyGrantChain` walks the chain leaf first — so at the leaf this asks about issuers
      // whose logs no iteration has replayed yet, and the first replay of one of them happens
      // HERE. That replay can exhaust the shared allowance like any other. Both this branch and
      // the one below — a candidate whose issuer resolves fine but whose signature check
      // exhausts an allowance — are live, and each is pinned by a test.
      throw new VerificationBudgetExceeded("Revocation lookup exceeded its verification budget");
    }
    // `kind === "ok"` is what excludes a SUBSTITUTED issuer log here, and ignoring the
    // candidate is the right disposal rather than throwing. A revocation whose issuer's log
    // came back belonging to somebody else is not evidence of anything — it is a forgery
    // attempt, in the direction of withdrawing a record the issuer never revoked, and the
    // established handling for a candidate that fails its checks is to skip it. Nor does
    // skipping hand the view anything: it can already suppress a genuine revocation by simply
    // not returning it, so a substituted issuer log buys no suppression power it lacked.
    if (resolved.kind !== "ok") {
      continue;
    }
    // Spec 016: the candidate is judged against the state its own `anchor` names, and no other.
    //
    // An UNKNOWN ANCHOR is a skip, not an error, and the distinction is about what the record
    // is rather than about how expensive it was. A revocation whose anchor names no event of
    // the issuer's log is not that issuer's record — it is a candidate that failed one of this
    // loop's checks, like a wrong `revokes` digest or an unrequested issuer — so it does not
    // revoke, and the search carries on to the next candidate. It is surfaced exactly as those
    // are: the loop continues, `findRevocation` answers null if nothing else verifies, and the
    // caller reports "not revoked" rather than a cost or an invalidity. It costs no
    // verifications, so it draws nothing from `candidateAllowance` either.
    //
    // This is a REQUEST-TIME path (016, _Log freshness_): the resolver holds no refetch hook,
    // and the log it judges against was fetched from the view during THIS operation — the
    // signer-state memo lives no longer than the request context, so there is no stale cached
    // replay of this module's own to refresh. A view that caches key logs across requests owns
    // that freshness decision behind `getKeyLog`.
    if (signedAtAnchor(parsed.data, resolved.states, operation, candidateAllowance) === "ok") {
      return parsed.data;
    }
  }
  return null;
}

async function verifyIssuedStatement(
  record: (Claim | Relationship) & Record<string, unknown>,
  kind: "claim" | "relationship",
  view: TrustView,
  options: VerifyOptions
): Promise<Verification<StatementReason>> {
  const now = options.now ?? new Date();
  if (isExpiredAt(record.expiresAt, now)) {
    return invalid(`${kind}_expired`);
  }

  // A statement verification gets its own shared allowance for exactly the reasons a chain
  // does: the same untrusted view drives it, and it asks about the issuer twice (here and
  // again for the revocation lookup). Without one, each of those took a fresh full allowance.
  const operation = beginVerificationOperation(view, options);

  try {
    const resolved = await signerStates(view, record.issuedBy, operation);
    if (resolved.kind === "too_expensive") {
      return invalid("issuer_key_log_too_expensive");
    }
    if (resolved.kind === "mismatched") {
      return invalid("issuer_key_log_participant_mismatch");
    }
    if (resolved.kind !== "ok") {
      return invalid("issuer_key_log_unresolved");
    }
    if (!signedByAnyState(asSignatureSet(record), resolved.states, operation)) {
      return invalid(`${kind}_signature_invalid`);
    }

    if (await findRevocation(view, canonicalDigest(record), [record.issuedBy], operation)) {
      return invalid(`${kind}_revoked`);
    }
  } catch (error) {
    if (error instanceof VerificationBudgetExceeded) {
      return invalid("issuer_key_log_too_expensive");
    }
    throw error;
  }

  return { valid: true };
}

/** Verifies a claim: shape, expiry, issuer signature via the key log, revocation. */
export async function verifyClaim(
  claim: Claim,
  view: TrustView,
  options: VerifyOptions = {}
): Promise<Verification<StatementReason>> {
  if (!claimSchema.safeParse(claim).success) {
    return invalid("claim_malformed");
  }
  return verifyIssuedStatement(claim, "claim", view, options);
}

/** Verifies a relationship edge: shape, expiry, issuer signature, revocation. */
export async function verifyRelationship(
  relationship: Relationship,
  view: TrustView,
  options: VerifyOptions = {}
): Promise<Verification<StatementReason>> {
  if (!relationshipSchema.safeParse(relationship).success) {
    return invalid("relationship_malformed");
  }
  return verifyIssuedStatement(relationship, "relationship", view, options);
}

/** Path-prefix cover (spec 009): "directory" covers "directory/curate". */
export function abilityCovers(parent: string, child: string): boolean {
  return parent === child || child.startsWith(`${parent}/`);
}

/**
 * Classifies a principal by shape (spec 011): participant ids carry the `pk_` prefix,
 * bare KeyRefs are plain multibase — disjoint by construction. Anything matching
 * neither shape is already schema-rejected.
 */
function isParticipantPrincipal(principal: Principal): principal is ParticipantId {
  return principal.startsWith("pk_");
}

/**
 * Verifies a key-issued link (spec 011 chain rule 1, key branch): a bare-key issuer
 * has no log, so its signature is self-certifying — exactly one signature, verifying
 * over the canonical record bytes against the KeyRef itself.
 */
function signedByKeyIssuer(link: Grant, keyRef: KeyRef, operation: VerificationOperation): boolean {
  if (link.signature.length !== 1) {
    return false;
  }
  try {
    return verifyThresholdRecord(link, [keyRef], "1", {
      ...verificationWorkOptions(operation)
    });
  } catch (error) {
    if (error instanceof VerificationBudgetExceeded) {
      throw error;
    }
    // A schema-shaped KeyRef can still fail to decode (wrong multicodec); the
    // signature cannot verify against a key that does not exist.
    return false;
  }
}

/** Cover for `aud` (spec 011): every id the child names is present in the parent's. */
function audNarrows(inherited: ParticipantId[], aud: ParticipantId[]): boolean {
  return aud.every((id) => inherited.includes(id));
}

/** Normalizes a link's `aud` caveat (spec 011) to a list, or null when absent. */
function audOf(link: Grant): ParticipantId[] | null {
  const aud = link.caveats["aud"];
  if (aud === undefined) {
    return null;
  }
  // Well-formedness is schema-enforced (grantSchema cross-field rules) before we get here.
  const parsed = audCaveatSchema.parse(aud);
  return Array.isArray(parsed) ? parsed : [parsed];
}

/**
 * Verifies a grant chain (specs 009/011), presented leaf first with the self-issued
 * root last. Checks, per the specs: signatures — participant issuers via their key
 * logs, key issuers self-certifying against the KeyRef itself — root self-issuance,
 * issuer-equals-parent-audience over principals, constant subject, ability
 * attenuation, narrowing-only `aud` with the verifier admitted (and, under
 * `requireAud`, an `aud` present at all), fail-closed non-`aud` caveats, expiry, and
 * revocation by the participant issuers of the link and its ancestors (key principals
 * cannot author revocations).
 *
 * Spec 014 adds one rule at request purpose (the default): a chain carrying ANY `e2ee`
 * ability in ANY link is never a request authorization — see the check below.
 *
 * At `"record"` purpose the same structural checks run against a record's `createdAt`
 * instead of the clock, with caveats unevaluated and revocation optional — see
 * {@link GrantVerifyOptions.purpose}.
 *
 * WHAT ONE CHAIN COSTS, as a closed form a caller can add up. Writing
 * `E = MAX_KEY_LOG_EVENTS` (128), `K = MAX_KEY_EVENT_KEYS` (8), `L = MAX_GRANT_CHAIN_LINKS` (4),
 * `R = MAX_REVOCATION_CANDIDATE_VERIFICATIONS` (16):
 *
 *   chain cost  = L * (E * K)                    issuer-log replays
 *               + L * K                          link signature checks
 *               + sum_i min(R, u_i * K)          candidate checks at each link
 *
 * The conservative substitution `sum_i ... <= L*R` gives `4 * 1024 + 32 + 64` = 4192; it is an
 * upper bound, not the exact cost of every chain. The replay term is `L` and not `L(L+1)/2`
 * because {@link SignerStateCache} makes each distinct issuer replay once per verification
 * however many links and revocation lookups ask about it.
 *
 * THE `E` FACTOR HAS LEFT THE RECORD TERMS, and that is spec 016's whole effect on cost. The
 * middle term was `L * (E * K)`: a link was offered to every state its issuer's log had ever
 * committed, so the states of the log multiplied the keys of a state. An anchored link names
 * ONE state, so the term is `L * K` — the replay still dominates, and it is work a verifier
 * performs anyway to resolve the issuer. (The signature COUNT left the form one spec earlier,
 * with 015: a set whose member count is not exactly the threshold is refused on its length
 * before any curve work, so `K` is the per-link ceiling for every record the schema admits.)
 *
 * The candidate term is the whole reason {@link MAX_REVOCATION_CANDIDATE_VERIFICATIONS} exists:
 * without it the revocation search contributes `(L(L+1)/2) * K`, chosen by the VIEW rather than
 * by the chain — a bound of the same shape as the one it replaces, an order of magnitude
 * smaller, and still the view's number rather than the chain's.
 *
 * The HONEST ceiling is the one a caller sizing a timeout wants: an honest lookup finds at most
 * one genuine revocation and returns on it, so the chain pays at most one candidate check of
 * `K` in total rather than the conservative `L * R`, giving `L * (E * K) + L * K + K` = 4136.
 *
 * "Honest" there means the VIEW is honest as well as the chain. A view that answers a lookup
 * with a candidate the verifier must reject is not covered by it: that candidate costs at most
 * `K`, the lookup returns null, and the chain carries on to the next link, so the rejections
 * ADD to the chain's cost rather than replacing part of it. The addition is now bounded by
 * `L * R` = 64 rather than by `L * E * K` = 4096, so a hostile view's contribution has stopped
 * being the dominant term of this form.
 */
export async function verifyGrantChain(
  chain: Grant[],
  view: TrustView,
  options: GrantVerifyOptions = {}
): Promise<GrantChainVerification> {
  if (chain.length === 0) {
    return invalid("grant_chain_empty");
  }
  // Depth before content. Every link below costs a key-log replay, so an unbounded chain is
  // unbounded work chosen by whoever presented it — and it is presented before anything has
  // been proven. `decodeGrantsHeader` applies the same cap, but a chain can reach here
  // without passing through that codec.
  if (chain.length > MAX_GRANT_CHAIN_LINKS) {
    return invalid("grant_chain_too_long");
  }
  for (const grant of chain) {
    if (!grantSchema.safeParse(grant).success) {
      return invalid("grant_malformed");
    }
  }

  // One local allowance for this whole operation plus, when supplied, the request's outer
  // allowance and view-isolated signer memo. Nested calls thread this exact operation.
  const operation = beginVerificationOperation(view, options);

  // Spec 014: "`e2ee` abilities are member-verified and never request-valid. A verifier
  // MUST reject a request whose presented chain contains **any** ability satisfying the
  // predicate." The reading is WHOLE-CHAIN and ANY-ability, pinned so two verifiers cannot
  // differ — a chain mixing `e2ee/leaf` with `msg/send` is rejected outright rather than
  // authorizing its `msg/send` half. This is what makes it safe for 014 to lift 011's `aud`
  // requirement for credential links: a stolen credential authorizes zero requests anywhere,
  // so the namespace rule is the bound the caveat would have been. It runs before every other
  // check so the reason an operator sees names the actual rule, and it is the DEFAULT so a
  // caller that never considered 014 fails closed. `isE2eeAbility` is imported, never
  // re-implemented: the exemption and the rejection must stay the same function.
  const purpose = options.purpose ?? "request";
  if (purpose === "request" && chain.some((link) => link.abilities.some(isE2eeAbility))) {
    return invalid("grant_e2ee_not_request_valid");
  }

  // The instant validity windows are measured against. Record purpose measures against
  // the record's own time and NEVER the wall clock, so it takes `at` and refuses to run
  // without it rather than quietly answering a different question (`now`'s default).
  let windowAt: Date;
  if (purpose === "record") {
    if (options.at === undefined) {
      return invalid("grant_record_time_required");
    }
    windowAt = options.at;
  } else {
    windowAt = options.now ?? new Date();
  }

  const root = chain[chain.length - 1]!;
  if (root.proof !== null) {
    return invalid("grant_chain_incomplete");
  }
  if (root.issuerId !== root.subjectId) {
    return invalid("grant_root_not_self_issued");
  }

  // The `proof` digest comparison is NOT here, and its absence is spec 015 S4: a verifier
  // MUST NOT "compare the digest to a `prior` or `proof` pointer as proof of chaining" until
  // the record's signature set has been checked and accepted. Following a `proof` pointer to
  // FETCH a candidate parent is allowed — the pointer is a lookup key — but treating
  // `digest(parent) == proof` as a verified link is not, so that comparison moved into the
  // per-link loop below, where it runs immediately after the parent's own set has been
  // checked. The purely structural checks that follow read stored fields and compute no
  // digest, so they stay here and keep rejecting a malformed chain before any curve work.
  //
  // WHAT THE MOVE COSTS. MEASURED, not derived: four-link chains over full-length 1-of-8 logs
  // at the schema maxima (`E` = 128, `K` = 8, `L` = 4), read off the shared budget's drawdown —
  // the pre-change column by running the same three chains against the resolver as of 6c31fdc^,
  // the post-change column cross-checked by bisecting `maxSignatureVerifications` for the
  // smallest allowance that is not refused on cost. Verifications, not milliseconds:
  //
  //   proof mismatch at the leaf          0 -> 4096   `grant_proof_mismatch`
  //   proof mismatch at the deepest pair  0 -> 8192   `grant_proof_mismatch`
  //   correct proofs, one bad signature   8192 = 8192 `grant_signature_invalid`
  //
  // A bad pointer used to be free — the comparison was the first thing this loop did — and now
  // every link beneath it is replayed and signature-checked first, so the deepest mismatch pays
  // for the whole chain, `L * 2E * K`. (A mismatch that also breaks its child's pointer is
  // CHEAPER, not dearer: the walk rejects at the shallower break, measured 6144. Tampering
  // produces that shape; the isolated one above is the worst case.)
  //
  // WHY THAT IS ADMISSIBLE, and "the chain is capped, so the work is capped" is not the
  // argument — a cap of 8192 verifications on a pre-authentication path is a real number, and
  // boundedness alone does not answer it. The answer is that 8192 WAS ALREADY REACHABLE before
  // the move, by the control shape above: a `proof` pointer is a digest, so anyone can compute
  // correct ones with no key material at all, and a chain carrying correct pointers and one bad
  // signature made a verifier spend the full `L * 2E * K` then and spends the same now. The
  // reorder therefore raises the FLOOR for one malformed shape — a broken pointer stops being
  // free — without raising the CEILING: the dearest a broken pointer can be made, 8192, is a
  // figure an attacker with no key material could already extract before the move.
  //
  // All three figures are asserted in `packages/trust/test/revocation-allowance.test.ts`
  // ("costs a proof mismatch what a bad signature already cost, and no more"), so they cannot
  // drift from the code without a red test.
  for (let index = 0; index < chain.length - 1; index += 1) {
    const link = chain[index]!;
    const parent = chain[index + 1]!;
    if (link.issuerId !== parent.audienceId) {
      return invalid("grant_issuer_not_parent_audience");
    }
    if (link.subjectId !== parent.subjectId) {
      return invalid("grant_subject_drift");
    }
    const covered = link.abilities.every((ability) =>
      parent.abilities.some((parentAbility) => abilityCovers(parentAbility, ability))
    );
    if (!covered) {
      return invalid("grant_ability_escalation");
    }
  }

  // Caveats bind a chain to the surface it is exercised against; a stored record is not
  // one. Record purpose therefore evaluates none of them — `aud` included, whose named
  // audience is the delivering node and never the member re-reading the record.
  if (purpose !== "record") {
    // Effective aud (spec 011), walked root → leaf: unrestricted until a link carries
    // `caveats.aud`; a carrying link must be covered by the effective aud it inherits
    // (narrowing only) and then becomes the new effective aud.
    let effectiveAud: ParticipantId[] | null = null;
    for (let index = chain.length - 1; index >= 0; index -= 1) {
      const aud = audOf(chain[index]!);
      if (!aud) {
        continue;
      }
      if (effectiveAud !== null && !audNarrows(effectiveAud, aud)) {
        return invalid("grant_aud_escalation");
      }
      effectiveAud = aud;
    }
    if (effectiveAud) {
      // A verifier that cannot state its own id cannot evaluate `aud`; caveats fail
      // closed (spec 009), so no `verifierId` rejects like a verifier not admitted.
      if (options.verifierId === undefined || !effectiveAud.includes(options.verifierId)) {
        return invalid("grant_audience_not_admitted");
      }
    } else if (options.requireAud && purpose === "request") {
      // No link carried `aud`, so the chain is unrestricted and every verifier would
      // admit it — including one this chain's subject never meant to reach. Credential
      // purpose is exempt: spec 014 lifts the `aud` requirement for credential links, and
      // the resolver must not reject as unbound what the schema accepts as valid.
      return invalid("grant_audience_required");
    }
  }

  // Revocation is a verification input everywhere except a member re-reading a stored
  // record, where a view-dependent answer would split the group (see `checkRevocation`).
  const checkRevocation = purpose === "record" ? (options.checkRevocation ?? true) : true;

  // Every cost refusal inside this loop lands here. Replay exhaustion is reported where it
  // happens (it names the key log); this catches the OTHER spender — threshold-signature
  // checks. Since spec 016 one such check is `K` against one anchored state rather than `E * K`
  // against every state a log committed, so a single check can no longer exhaust an allowance a
  // replay fits in; they still recur across links and revocation candidates, and the accumulated
  // spend still has to be told apart from a bad signature.
  try {
    for (let index = 0; index < chain.length; index += 1) {
      const link = chain[index]!;
      if (isExpiredAt(link.expiresAt, windowAt)) {
        return invalid("grant_expired");
      }
      if (purpose === "record" && windowAt.getTime() < Date.parse(link.issuedAt)) {
        // The lower half of the window. `createdAt` is signer-chosen, so without this a
        // record could cite authority that did not yet exist when it claims to have been
        // written; the upper half moving off the wall clock is what makes it load-bearing.
        return invalid("grant_not_yet_issued");
      }
      if (purpose !== "record") {
        // `aud` is standard and evaluated natively above; every other caveat still fails
        // closed without an evaluator, which sees the full link (spec 009).
        const hasForeignCaveats = Object.keys(link.caveats).some((key) => key !== "aud");
        if (hasForeignCaveats && !(options.evaluateCaveats?.(link) ?? false)) {
          return invalid("grant_caveat_rejected");
        }
      }
      if (isParticipantPrincipal(link.issuerId)) {
        const resolved = await signerStates(view, link.issuerId, operation);
        if (resolved.kind === "too_expensive") {
          return invalid("grant_issuer_key_log_too_expensive");
        }
        if (resolved.kind === "mismatched") {
          return invalid("grant_issuer_key_log_participant_mismatch");
        }
        if (resolved.kind !== "ok") {
          return invalid("grant_issuer_key_log_unresolved");
        }
        // Spec 016 chain rule 1, participant branch: a participant-issued link carries an
        // `anchor` and is judged against the state that anchor names, and no other. `grantSchema`
        // (checked for every link above) requires the field exactly when the issuer is a
        // participant, so the undefined arm is unreachable through this entry point and is
        // handled as a malformed link rather than as a signature failure — a link with no anchor
        // is not a link whose signature is wrong.
        if (link.anchor === undefined) {
          return invalid("grant_malformed");
        }
        // Cast rather than reconstructed: the bytes a signature covers are the bytes as given,
        // and narrowing an optional property does not narrow the object type.
        const anchored = signedAtAnchor(
          link as Grant & { anchor: string },
          resolved.states,
          operation
        );
        // Reported distinguishably from a bad set, as 016 requires: an unknown anchor may be a
        // view that has not seen the issuer's later events, where a failing set is a forgery.
        // The chain is invalid either way on this request-time path — a verifier here has no
        // refetch hook and no reason to stall — but an operator reading the two reasons is sent
        // to different places.
        if (anchored === "anchor_unknown") {
          return invalid("grant_issuer_anchor_unknown");
        }
        if (anchored !== "ok") {
          return invalid("grant_signature_invalid");
        }
      } else if (!signedByKeyIssuer(link, link.issuerId, operation)) {
        return invalid("grant_key_issuer_signature_invalid");
      }
      // Spec 015 S4: this link's signature set has just been accepted, so its digest is now
      // meaningful and the CHILD's `proof` pointer may be treated as a verified link. The
      // chain is walked leaf first, so the child is the previous index and its `proof` is a
      // stored string that needed no verification of its own.
      const child = index > 0 ? chain[index - 1]! : null;
      if (child !== null && child.proof !== canonicalDigest(link)) {
        return invalid("grant_proof_mismatch");
      }
      // Authorized revokers: the participant principals among this link's issuer and
      // every upstream issuer — the subject at minimum, via the self-issued root. Key
      // principals cannot author revocations (spec 011).
      if (checkRevocation) {
        const upstreamIssuers = chain
          .slice(index)
          .map((upstream) => upstream.issuerId)
          .filter(isParticipantPrincipal);
        if (await findRevocation(view, canonicalDigest(link), upstreamIssuers, operation)) {
          return invalid("grant_revoked");
        }
      }
    }
  } catch (error) {
    if (error instanceof VerificationBudgetExceeded) {
      return invalid("grant_signature_check_too_expensive");
    }
    throw error;
  }

  const leaf = chain[0]!;
  return {
    valid: true,
    subjectId: leaf.subjectId,
    audienceId: leaf.audienceId,
    abilities: leaf.abilities
  };
}

/** The predicate a represents edge carries. */
export const REPRESENTS_PREDICATE = "represents";

export type RepresentsChain = {
  agentId: ParticipantId;
  organizationId: ParticipantId;
  /** The represents edge: subject agent, object organization, issued by the organization. */
  edge: Relationship;
  /** Optional bounding grant chain, leaf first; subject organization, leaf audience agent. */
  grants?: Grant[];
};

/**
 * Verifies "this agent represents this organization" (the S1 gate): the agent
 * resolves to a replay-valid key log, the represents edge is issued and signed by the
 * represented organization, nothing is expired or revoked, and any presented grant
 * chain delegates the organization's authority to the agent.
 */
export async function verifyRepresentsChain(
  chain: RepresentsChain,
  view: TrustView,
  options: GrantVerifyOptions = {}
): Promise<RepresentsVerification> {
  const { agentId, organizationId, edge, grants } = chain;

  // Thread one operation through the agent lookup, relationship, and optional grant chain.
  // That preserves the 13A local ceiling even when the request context around it is larger.
  const operation = beginVerificationOperation(view, options);
  const shared: GrantVerifyOptions = {
    ...options,
    operation
  };
  const agentStates = await signerStates(view, agentId, operation);
  if (agentStates.kind === "too_expensive") {
    return invalid("agent_key_log_too_expensive");
  }
  if (agentStates.kind === "mismatched") {
    return invalid("agent_key_log_participant_mismatch");
  }
  if (agentStates.kind !== "ok") {
    return invalid("agent_key_log_unresolved");
  }

  if (edge.predicate !== REPRESENTS_PREDICATE) {
    return invalid("edge_predicate_mismatch");
  }
  if (edge.subjectId !== agentId) {
    return invalid("edge_subject_mismatch");
  }
  if (edge.objectId !== organizationId) {
    return invalid("edge_object_mismatch");
  }
  // Only the represented party may assert representation; an agent cannot
  // self-issue its way into "represents Acme".
  if (edge.issuedBy !== organizationId) {
    return invalid("edge_not_issued_by_represented");
  }

  const edgeVerdict = await verifyRelationship(edge, view, shared);
  if (!edgeVerdict.valid) {
    return edgeVerdict;
  }

  if (grants && grants.length > 0) {
    const grantVerdict = await verifyGrantChain(grants, view, shared);
    if (!grantVerdict.valid) {
      return grantVerdict;
    }
    if (grantVerdict.subjectId !== organizationId) {
      return invalid("grant_subject_not_organization");
    }
    if (grantVerdict.audienceId !== agentId) {
      return invalid("grant_audience_not_agent");
    }
    return { valid: true, agentId, organizationId, abilities: grantVerdict.abilities };
  }

  return { valid: true, agentId, organizationId };
}
