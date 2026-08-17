/**
 * The rejection types every verification surface throws, and the reason vocabulary they carry.
 *
 * They live in their own module rather than beside `createVerifier` for one structural reason:
 * `discovery-view.ts` needs to throw {@link VerifyCapacityError} when its outbound fetch throttle
 * is saturated, and `verifier.ts` imports `discovery-view.ts` to build its view. Defining the
 * classes in `verifier.ts` made those two modules import each other. That cycle happened to work
 * — the classes are only referenced from function bodies, so both module bodies finish evaluating
 * before either is used — but it worked by accident of evaluation order, and the first top-level
 * reference added on either side would turn it into a temporal-dead-zone crash at import time.
 *
 * A leaf module with no imports of its own cannot participate in a cycle. Both classes are
 * re-exported from `verifier.ts` and from the package index, so no consumer sees this move.
 *
 * The `@kinnet/trust` import below does not reintroduce one: it is `import type`, erased before
 * the module ever runs, so this file still emits with no imports at all.
 */
import type { ResolverReason } from "@kinnet/trust";

/**
 * Every reason THIS PACKAGE puts on a {@link VerifyError} — the request verifier's own
 * vocabulary plus the discovery view's two throttle refusals. Resolver reasons, which arrive
 * verbatim from `@kinnet/trust` and are not this package's to enumerate, are the other arm of
 * {@link VerifyReason}.
 *
 * Written out as a union rather than left as `string` because the union is what makes the
 * capacity classification below checkable: {@link VERIFY_CAPACITY_REASONS} is typed as a subset
 * of this, and {@link VerifyReasonsAreClassified} asserts the two agree. A reason added to one
 * and forgotten in the other does not compile — the same discipline `@kinnet/trust`'s
 * `ResolverReason` and this package's own `UnitReason` carry.
 */
export type KnownVerifyReason =
  /** The signature keyid is neither a participant id nor a decodable KeyRef. */
  | "keyid_invalid"
  /** No RFC 9421 `Signature-Input` header with a keyid was found. */
  | "missing_signature"
  /** A bare-KeyRef keyid arrived without the grant chain that would authorize it. */
  | "delegation_required"
  /** Replaying the actor's key log would exceed this verifier's allowance. */
  | "agent_key_log_too_expensive"
  /** No replay-valid key log resolves for the claimed participant. */
  | "agent_key_log_unresolved"
  /** This surface's own clock is not a usable integer second count. */
  | "clock_invalid"
  /** The RFC 9421 key search would exceed this verifier's allowance. */
  | "request_signature_too_expensive"
  /** The request signature does not verify, or the request does not match the profile. */
  | "signature_invalid"
  /**
   * The signature's `created` time is outside the clock-skew window: the receipt expired, or
   * was minted too far in the future. Split out of `signature_invalid` because the remedy is
   * the caller's CLOCK (or a fresh retry), never its keys — see `maxSkewSeconds`.
   */
  | "signature_stale"
  /**
   * The `Content-Digest` header does not match the presented body (RFC 9530). Split out of
   * `signature_invalid` because a body-rewriting intermediary produces it far more often than
   * an attacker does, and "your credentials are wrong" sends an operator to the wrong layer.
   */
  | "content_digest_mismatch"
  /** The request nonce has already been used at this verifier. */
  | "nonce_replayed"
  /** Replay-nonce tracking is full and nothing has expired; the verifier refuses. */
  | "nonce_capacity"
  /** The PN-Grants header failed to decode. */
  | "grants_malformed"
  /** The chain's leaf audience is not the signing keyid principal. */
  | "grants_leaf_audience_mismatch"
  /** The presented chain does not cover this surface's `requireAbilities`. */
  | "grants_abilities_insufficient"
  /** `requireRepresents` is set and no verified represents chain exists. */
  | "represents_chain_unverified"
  /** The middleware saw a parsed body; it needs the raw bytes. */
  | "body_not_raw"
  /** The discovery fetch queue is full; the view refuses rather than fanning out further. */
  | "discovery_fetch_capacity"
  /** A discovery fetch did not get a throttle slot before its deadline. */
  | "discovery_fetch_timeout"
  /**
   * A discovery exchange did not COMPLETE — connect, headers and body — inside its deadline.
   *
   * Distinct from `discovery_fetch_timeout`, which is the queue: that one never opened a
   * socket and is cured by the process being less busy, this one opened a socket the host
   * then stalled and is cured by the host answering. Reusing one reason for both would tell
   * an operator to look at their own fan-out when the fault is upstream.
   */
  | "discovery_fetch_deadline"
  /**
   * A discovery response carried more bytes than the view will accept — either declared in
   * `content-length` or observed while streaming.
   *
   * NOT capacity: see {@link KnownVerifyCapacityReason}. The host chose to send this, and
   * sending it again is all a retry can buy.
   */
  | "discovery_response_too_large"
  /**
   * A discovery lookup could not be answered because the host was UNREACHABLE or FAILING — a
   * transport error (DNS, connection refused, connection reset, TLS) or a 5xx/429 response to a
   * well-formed lookup.
   *
   * Capacity, and this is the point of the reason existing: the raw `TypeError` a failed fetch
   * throws and the plain `Error` a 5xx used to throw both reached the surface unclassified and
   * were answered 401 — "your credentials are wrong" when discovery is simply down, which sends
   * a correct caller to re-authenticate against an outage a retry would have ridden out. It is
   * the transport-layer sibling of `discovery_fetch_deadline` (a host that stalls) and
   * `discovery_fetch_timeout` (a queue that never opened a socket): all three mean "could not
   * reach discovery, retry later", not "rejected". A 4xx OTHER than 404 stays a 401 — that is
   * the host rejecting the request, which a retry cannot change.
   */
  | "discovery_unavailable"
  /**
   * Discovery answered with a redirect. The view follows none, so the lookup is refused with
   * no second request issued. NOT capacity, for the same reason as the byte cap.
   */
  | "discovery_redirect_refused";

/**
 * Every reason a {@link VerifyError} raised by this package carries.
 *
 * TWO ARMS, because two packages produce them. {@link KnownVerifyReason} is what this package
 * decides on its own. `ResolverReason` arrives from `@kinnet/trust` and is re-thrown VERBATIM —
 * `createVerifier` passes a chain verdict's reason straight through rather than re-spelling it,
 * so this union follows the resolver's own type and cannot fall behind it. (`@kinnet/verify`'s
 * unit verifier makes the opposite choice and prefixes what it forwards; it carries its own
 * proof for the prefix. Here there is nothing to prove because nothing is rewritten.)
 */
export type VerifyReason = KnownVerifyReason | ResolverReason;

/**
 * The members of {@link KnownVerifyReason} that mean "out of capacity" rather than "rejected on
 * the merits" — every reason this package raises as a {@link VerifyCapacityError} / 503.
 *
 * NOT DERIVABLE FROM THE SPELLING, which is why it is a written list. `@kinnet/trust` can
 * classify its own by the `_too_expensive` suffix, and `createVerifier` rightly uses that suffix
 * test on the reasons it forwards. This package's capacity set does not share a suffix: a
 * saturated nonce map (`nonce_capacity`), an unusable clock (`clock_invalid`), a full fetch
 * queue (`discovery_fetch_capacity`, `discovery_fetch_timeout`), a stalled discovery exchange
 * (`discovery_fetch_deadline`) and an unreachable or failing host (`discovery_unavailable`) are
 * all 503s that no suffix rule would catch. A consumer classifying by suffix alone would answer
 * 401 for SIX of these eight, which is the mistake this list exists to prevent.
 *
 * WHY THE OTHER TWO DISCOVERY REFUSALS ARE NOT HERE. `discovery_response_too_large` and
 * `discovery_redirect_refused` also come from the discovery view, and both are deliberately
 * left in the 401 arm — the same arm as `agent_key_log_unresolved`, which is the closest
 * existing relative: all three mean "discovery yielded no usable record, so this request is
 * denied". 503 is a promise that RETRYING HELPS, and it does not here. Nothing about this
 * process is short of anything; the host chose to send an oversized body or a redirect, and it
 * will choose the same on the next attempt. Labelling them 503 would put a misbehaving or
 * hostile upstream into capacity alerting and invite a retry loop against an answer that
 * cannot change. (Neither 401 nor 503 is a perfect fit for "my upstream misbehaved" — a
 * gateway status would be — but this vocabulary is binary, and of the two, "rejected, do not
 * retry" is the true half.)
 */
export type KnownVerifyCapacityReason = Extract<
  KnownVerifyReason,
  | "agent_key_log_too_expensive"
  | "clock_invalid"
  | "request_signature_too_expensive"
  | "nonce_capacity"
  | "discovery_fetch_capacity"
  | "discovery_fetch_timeout"
  | "discovery_fetch_deadline"
  | "discovery_unavailable"
>;

/**
 * {@link KnownVerifyReason} as a value, for consumers enumerating the vocabulary.
 *
 * `as const satisfies` rather than an annotated `readonly KnownVerifyReason[]`, and the
 * difference is the whole proof. An ANNOTATION widens every element to the declared type, so
 * `(typeof KNOWN_VERIFY_REASONS)[number]` comes back as `KnownVerifyReason` no matter what the
 * array actually contains — and {@link VerifyReasonsAreClassified}, comparing the union against
 * itself, would pass vacuously while the list was missing half its entries. `as const` keeps the
 * literal tuple so the comparison has something real to compare, and `satisfies` still rejects an
 * entry that names nothing in the union. `@kinnet/trust`'s `GRANT_CHAIN_COST_REASONS` is `as
 * const` for exactly this reason.
 */
export const KNOWN_VERIFY_REASONS = [
  "keyid_invalid",
  "missing_signature",
  "delegation_required",
  "agent_key_log_too_expensive",
  "agent_key_log_unresolved",
  "clock_invalid",
  "request_signature_too_expensive",
  "signature_invalid",
  "signature_stale",
  "content_digest_mismatch",
  "nonce_replayed",
  "nonce_capacity",
  "grants_malformed",
  "grants_leaf_audience_mismatch",
  "grants_abilities_insufficient",
  "represents_chain_unverified",
  "body_not_raw",
  "discovery_fetch_capacity",
  "discovery_fetch_timeout",
  "discovery_fetch_deadline",
  "discovery_unavailable",
  "discovery_response_too_large",
  "discovery_redirect_refused"
] as const satisfies readonly KnownVerifyReason[];

/** {@link KnownVerifyCapacityReason} as a value. Every entry is answered 503, never 401. */
export const VERIFY_CAPACITY_REASONS = [
  "agent_key_log_too_expensive",
  "clock_invalid",
  "request_signature_too_expensive",
  "nonce_capacity",
  "discovery_fetch_capacity",
  "discovery_fetch_timeout",
  "discovery_fetch_deadline",
  "discovery_unavailable"
] as const satisfies readonly KnownVerifyCapacityReason[];

type Assert<T extends true> = T;
type SameSet<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

/**
 * The classification guarantee, as a compile-time proof rather than a test convention — the
 * shape `@kinnet/trust`'s `CostReasonsAreClassified` established and this package's
 * `UnitCostReasonsAreClassified` follows.
 *
 * Three sides, and all three are needed:
 *  - the value list and the union are the SAME SET, in both directions, so a reason added to the
 *    union but not the list fails to compile and so does a list entry naming nothing;
 *  - the capacity list and the capacity union likewise;
 *  - every cost-SHAPED member of {@link KnownVerifyReason} is classified as capacity, which is
 *    what keeps this package's list agreeing with the suffix rule `createVerifier` applies to
 *    the resolver reasons it forwards. Without it the two mechanisms could disagree about a
 *    reason ending in `_too_expensive` depending on which package produced it.
 *
 * WHAT IT DOES NOT COVER: a reason produced by a surface layered ON TOP of this package.
 * `VerifyError` is generic in its reason precisely so such a surface can carry its own
 * vocabulary (`apps/node` throws `envelope_signature_too_expensive`), and nothing here reaches
 * into it. Those surfaces answer for their own classification; `isVerifyCapacityReason` still
 * catches theirs when it is cost-shaped.
 */
export type VerifyReasonsAreClassified = Assert<
  SameSet<KnownVerifyReason, (typeof KNOWN_VERIFY_REASONS)[number]>
>;
export type VerifyCapacityReasonsAreClassified = Assert<
  SameSet<KnownVerifyCapacityReason, (typeof VERIFY_CAPACITY_REASONS)[number]>
>;
export type VerifyCostShapedReasonsAreCapacity = Assert<
  Extract<KnownVerifyReason, `${string}_too_expensive`> extends KnownVerifyCapacityReason
    ? true
    : false
>;

/**
 * True when a reason means "retry later" (503) rather than "your request was rejected" (401).
 *
 * Accepts a bare `string` so a caller holding a reason off the wire — a JSON error body, a log
 * line — can classify it without first proving it is a member of the union. Two rules, matching
 * the two producers exactly: membership in {@link VERIFY_CAPACITY_REASONS} for this package's
 * own reasons, and the `_too_expensive` suffix for the resolver reasons `createVerifier`
 * forwards verbatim (and for any layered surface that follows the same convention). The suffix
 * arm cannot go stale as `@kinnet/trust` grows new cost reasons, which is why it is a suffix
 * test here and an enumeration there.
 */
export function isVerifyCapacityReason(reason: string): boolean {
  return (
    (VERIFY_CAPACITY_REASONS as readonly string[]).includes(reason) ||
    reason.endsWith("_too_expensive")
  );
}

/** True when a reason is an authentication/authorization rejection: the 401 complement. */
export function isVerifyAuthReason(reason: string): boolean {
  return !isVerifyCapacityReason(reason);
}

/**
 * GENERIC IN ITS REASON, defaulting to {@link VerifyReason}.
 *
 * The default is what nearly every consumer sees: `catch (e) { if (e instanceof VerifyError) }`
 * narrows to `VerifyError<VerifyReason>`, so `e.reason` is the closed vocabulary above and a
 * `switch` over it can be exhaustive. That is the whole point of typing it — it was `string`,
 * which told a consumer nothing and let a typo reach a response body.
 *
 * The parameter exists because the set is genuinely OPEN one level up. A surface composing this
 * package adds verification stages of its own and needs reasons for them — `apps/node` throws
 * `envelope_signature_too_expensive` for a stage that lives entirely in that app — and a closed
 * type would force it to either misreport under a borrowed reason or stop using these classes.
 * Widening the property back to `string` to accommodate that would give up the vocabulary for
 * everyone; a type parameter keeps the default closed and lets the exception name itself.
 *
 * Inside this package the reason is pinned tighter than the class: `verifier.ts` constructs
 * through helpers constrained to {@link VerifyReason}, so a typo here does not compile even
 * though the class itself would accept it.
 */
export class VerifyError<Reason extends string = VerifyReason> extends Error {
  /**
   * Suggested HTTP status for a rejection response. 401 for every authentication and
   * authorization rejection; see {@link VerifyCapacityError} for the one case that is not
   * an auth failure at all.
   */
  readonly status: number = 401;

  constructor(
    readonly reason: Reason,
    message?: string
  ) {
    super(message ?? reason);
    this.name = "VerifyError";
  }
}

/**
 * The request was not rejected on its merits — the surface is out of capacity (replay-nonce
 * tracking, or the outbound discovery-fetch throttle) and refuses to proceed rather than accept a
 * request it cannot account for.
 *
 * This is a `VerifyError` so existing handlers keep catching it, but it carries 503 because
 * conflating it with 401 misleads every consumer of the response: a client reads 401 as
 * "my credentials are wrong" and may stop retrying or re-authenticate pointlessly, while
 * logs and alerting see an auth-failure spike instead of a capacity incident. The condition
 * is transient and the correct client behaviour is to retry later.
 *
 * Its reason defaults to the CAPACITY subset rather than to all of {@link VerifyReason}, so a
 * caller that narrows on this class gets the narrower vocabulary too.
 */
export class VerifyCapacityError<
  Reason extends string = KnownVerifyCapacityReason
> extends VerifyError<Reason> {
  override readonly status: number = 503;

  constructor(reason: Reason, message?: string) {
    super(reason, message);
    this.name = "VerifyCapacityError";
  }
}
