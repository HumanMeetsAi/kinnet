/**
 * Ceilings on signature-verification WORK, shared by key-log replay and threshold-record
 * verification.
 *
 * These live in their own module because both of those paths need them and one imports the
 * other. They are also a distinct KIND of rule: spec 003 makes a verification-work ceiling a
 * local resource policy, not a validity rule, so a refusal on cost must stay reportable
 * separately from "this is invalid" — a publisher told the wrong one goes and re-publishes a
 * record that was never wrong.
 */
import { MAX_KEY_EVENT_KEYS, MAX_KEY_EVENT_SIGNATURES, MAX_KEY_LOG_EVENTS } from "@kinnet/protocol";

/**
 * Thrown when a verification would exceed the caller's budget. Callers that carry one
 * allowance across several verifications catch this and report it as a cost condition.
 */
export class VerificationBudgetExceeded extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationBudgetExceeded";
  }
}

/**
 * Compatibility ceiling for generic threshold-record verification.
 *
 * A generic caller may supply a runtime-sized key list rather than a protocol-bounded key
 * event. Keep the historical 8192 ceiling for that exported API; key-log replay has its own
 * tighter, schema-derived default below. Splitting the names prevents a later replay tuning
 * pass from silently narrowing generic `verifyThresholdRecord` callers.
 */
export const DEFAULT_MAX_SIGNATURE_VERIFICATIONS =
  MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS * MAX_KEY_EVENT_SIGNATURES;

/**
 * Ed25519 verifications one key-log replay may spend by default.
 *
 * Spec 015's greedy walk performs at most one verification per listed key, regardless of the
 * signature count. A conforming event therefore costs at most `MAX_KEY_EVENT_KEYS`, and a full
 * conforming log costs at most `MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS` = 1024. This is tight:
 * an 8-of-8 event consumes all eight steps, and 128 such events consume the whole allowance.
 */
export const DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS = MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS;

/**
 * A caller-supplied count, or `fallback` if it is not a safe non-negative integer.
 *
 * Deliberately a whitelist. `NaN`, `Infinity`, negatives, fractions, and anything non-numeric
 * all resolve to the fallback rather than being coerced into something that compares
 * strangely — these values gate signature verification, so a permissive reading of a
 * malformed one is a forgery. `Math.max(0, Math.trunc(x))` is NOT enough: it passes `NaN`
 * and `Infinity` straight through, and every comparison against those is false.
 */
export function safeVerificationCount(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : fallback;
}
