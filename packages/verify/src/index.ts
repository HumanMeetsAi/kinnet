/**
 * The normative ability cover rule (spec 009): `granted` covers `required` when they are
 * equal or `required` is a path-child of `granted` — `directory` covers
 * `directory/curate`, but not `directory-admin`. Re-exported from `@kinnet/trust` so
 * services enforcing their own ability vocabulary against `VerifiedAgent.abilities` use
 * the spec rule instead of reimplementing it as a string prefix test.
 */
export { abilityCovers } from "@kinnet/trust";
export type { VerificationBudget, VerificationContext } from "@kinnet/trust";
/**
 * Grant-chain verification, re-exported so a resource server that vendors only this package can
 * run the exact check the middleware runs internally. A self-contained OAuth chain access token
 * (`decodeChainAccessToken` from `@kinnet/crypto`) is verified with `verifyGrantChain(chain,
 * view, { verifierId: <own id>, requireAud: true, purpose: "request" })` — the resolver lives in
 * `@kinnet/trust`, but a consumer of this middleware should not have to add a dependency on the
 * resolver package to name the verdict, its options, or the reason it rejected a chain.
 * `GRANT_CHAIN_COST_REASONS` is the subset that means "could not check" (503), not "checked and
 * refused" (401) — the split a resource needs to keep a discovery outage from reading as a wave
 * of invalid tokens.
 */
export {
  verifyGrantChain,
  GRANT_CHAIN_COST_REASONS,
  type GrantChainReason,
  type GrantChainVerification,
  type GrantVerifyOptions
} from "@kinnet/trust";
/**
 * The trust resolver's reason vocabulary, re-exported because `createVerifier` re-throws these
 * VERBATIM on a `VerifyError` (a rejected grant chain keeps `grant_expired`, `grant_revoked`,
 * `grant_audience_not_admitted` and the rest). It is one arm of {@link VerifyReason}, so a
 * consumer exhaustively handling `VerifyError.reason` needs the type — and needing to add a
 * dependency on `@kinnet/trust` to name a reason this package handed you is a papercut with no
 * upside.
 */
export type { ResolverReason } from "@kinnet/trust";
/**
 * The signature freshness window, in seconds, and its default of 120. Re-exported because it is
 * the number an operator has to reason about when configuring `maxSkewSeconds`, and it lives in
 * `@kinnet/crypto` — a package a service using this middleware otherwise never imports. See the
 * README's freshness section for its relationship to replay-nonce retention.
 */
export { DEFAULT_MAX_SKEW_SECONDS } from "@kinnet/crypto";
/**
 * The verdict shape the unit verifiers return: `{ valid: true }` or `{ valid: false, reason }`.
 * Re-exported from `@kinnet/trust` so a caller need not depend on the resolver package to name
 * what `verifyConversationUpdateUnit` gave it.
 */
export type { Verification } from "@kinnet/trust";
export {
  createDiscoveryView,
  DEFAULT_FETCH_DEADLINE_MS,
  DEFAULT_FETCH_QUEUE_TIMEOUT_MS,
  DEFAULT_MAX_CACHE_ENTRIES,
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS,
  DEFAULT_MAX_CONCURRENT_FETCHES,
  DEFAULT_MAX_QUEUED_FETCHES,
  MAX_ISSUERS_PER_REQUEST,
  type DiscoveryView,
  type DiscoveryViewOptions
} from "./discovery-view.js";
export {
  isVerifyAuthReason,
  isVerifyCapacityReason,
  KNOWN_VERIFY_REASONS,
  VERIFY_CAPACITY_REASONS,
  VerifyCapacityError,
  VerifyError,
  type KnownVerifyCapacityReason,
  type KnownVerifyReason,
  type VerifyReason
} from "./errors.js";
export { AbilityMappingError, MCP_ABILITY_NAMESPACE, mcpToolAbility } from "./mcp-ability.js";
export {
  createStaticTrustView,
  type StaticTrustView,
  type StaticTrustViewOptions
} from "./static-view.js";
export {
  createVerifier,
  VerifierConfigurationError,
  type InboundRequest,
  type VerifiedAgent,
  type VerifiedFetch,
  type Verifier,
  type VerifierOptions
} from "./verifier.js";
export {
  isSelfDeparture,
  isUnitCostReason,
  isUnitWaitReason,
  UNIT_COST_REASONS,
  UNIT_WAIT_REASONS,
  type UnitCostReason,
  type UnitReason,
  type UnitWaitReason,
  verifyConversationRecordUnit,
  verifyConversationUpdateUnit,
  type RecordUnitVerifyOptions
} from "./record-unit.js";
export {
  reauthorizeStream,
  delegationTreeDigest,
  type CurrentKeyStateFn,
  type ReauthorizeStreamOptions,
  type StreamAuthRecord,
  type StreamReauthorization
} from "./reauthorize-stream.js";
