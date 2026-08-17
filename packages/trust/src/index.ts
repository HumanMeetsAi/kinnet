import type { Claim, Relationship } from "@kinnet/protocol";

export type TrustRecord = Claim | Relationship;

export function isExpired(record: TrustRecord, now = new Date()): boolean {
  return Boolean(record.expiresAt && Date.parse(record.expiresAt) <= now.getTime());
}

export function issuedBy(record: TrustRecord, participantId: string): boolean {
  return record.issuedBy === participantId;
}

export {
  actionIdCaveatSchema,
  amountSchema,
  approvalTierSchema,
  beneficiaryCaveatSchema,
  createFinancialCaveatEvaluator,
  currencySchema,
  evaluateFinancialCaveats,
  FINANCIAL_CAVEAT_KEYS,
  type FinancialAction,
  type FinancialCaveatKey
} from "./financial-caveats.js";

export {
  assertGrant,
  GrantValidationError,
  validateGrant,
  type GrantIssue,
  type GrantValidation
} from "./grant-validate.js";
export {
  abilityCovers,
  beginVerificationOperation,
  createVerificationContext,
  GRANT_CHAIN_COST_REASONS,
  MAX_REVOCATION_CANDIDATE_VERIFICATIONS,
  REPRESENTS_PREDICATE,
  TRUST_COST_REASONS,
  verifyClaim,
  verifyGrantChain,
  verifyRelationship,
  verifyRepresentsChain,
  verificationWorkOptions,
  type GrantChainReason,
  type GrantChainVerification,
  type GrantVerifyOptions,
  type VerificationBudget,
  type VerificationContext,
  type VerificationOperation,
  VerificationOperationMismatch,
  type RepresentsChain,
  type ResolverReason,
  type RepresentsVerification,
  type TrustView,
  type Verification,
  type VerifyOptions
} from "./resolver.js";
