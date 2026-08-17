/**
 * Financial caveats: an evaluator for grant caveats that bound what a delegated agent may
 * SPEND, and to whom.
 *
 * WHERE THIS PLUGS IN. `verifyGrantChain` evaluates exactly one caveat natively — `aud`
 * (spec 011) — and fails closed on every other caveat key: a link carrying any foreign
 * caveat is rejected unless {@link GrantVerifyOptions.evaluateCaveats} returns `true` for
 * that link. This module supplies such a hook for the financial vocabulary below.
 *
 * WHY A FACTORY AND NOT A BARE FUNCTION. The resolver's hook signature is
 * `(grant: Grant) => boolean`: it sees the whole link and NO request context, because the
 * resolver has none to give — it verifies a chain, not a call. A cap like `maxAmount` is
 * meaningless without knowing the amount being attempted, so the request side has to be
 * bound in by the CALLER, one evaluator per action:
 *
 * ```ts
 * const verdict = await verifyGrantChain(chain, view, {
 *   now,
 *   verifierId: serviceId,
 *   evaluateCaveats: createFinancialCaveatEvaluator({
 *     amount: "42.50",
 *     currency: "USD",
 *     beneficiary: "acct:vendor-7"
 *   })
 * });
 * ```
 *
 * The action is what the RELYING PARTY says the request is actually doing (an MCP shim
 * verifying a tool call, say). It is not signed and is not part of the chain; the chain
 * bounds it, and the relying party is trusted to describe its own pending side effect
 * honestly. A shim that lies to its own evaluator has already lost.
 *
 * CHAIN COMPOSITION NEEDS NO CODE HERE. The resolver runs the hook once PER LINK, and one
 * `false` rejects the whole chain. So a chain whose root caps spending at 1000 USD and
 * whose leaf caps it at 100 USD authorizes at most 100 USD: each link's caveats are applied
 * independently against the same action and the effective authority is their INTERSECTION.
 * That falls out of "every link must accept" and needs no cross-link reasoning, which is
 * deliberate — cross-link reasoning is where a narrowing rule gets a widening bug. Note the
 * consequence: unlike `aud`, these caveats are NOT checked for narrowing. A leaf that
 * raises its cap above its parent's does not escalate anything, because the parent's lower
 * cap is still evaluated and still rejects.
 *
 * FAIL-CLOSED, THREE TIMES OVER, because every one of these is a way to accidentally widen
 * authority to "unbounded":
 *   1. an unrecognized caveat key denies (the evaluator must never bless a constraint it
 *      cannot enforce — that is the protocol's own rule and returning `true` would launder
 *      a foreign caveat past it);
 *   2. a malformed caveat value denies (a cap the schema rejects is not "no cap");
 *   3. a missing action field denies (an action that does not state its amount cannot be
 *      proven to be within a spending cap).
 *
 * MONEY IS NEVER A FLOAT here. Amounts are decimal STRINGS compared as scaled BigInts —
 * `0.1 + 0.2 !== 0.3` is a rounding curiosity in a report and an authorization bypass in a
 * cap.
 */
import type { Grant } from "@kinnet/protocol";
import { z } from "zod";

/**
 * The caveat keys this evaluator understands, `aud` excluded — the resolver owns that one
 * and evaluates it natively against `verifierId`, so this module must neither re-check it
 * nor treat it as unknown.
 *
 * Exported so a consumer minting grants can assert it is only using keys the verifier can
 * enforce, rather than discovering at verification time that its caveat is foreign.
 */
export const FINANCIAL_CAVEAT_KEYS = [
  "maxAmount",
  "currency",
  "beneficiary",
  "actionId",
  "approvalTier"
] as const;

export type FinancialCaveatKey = (typeof FINANCIAL_CAVEAT_KEYS)[number];

/** `aud` plus the financial vocabulary: every key a chain may carry past this evaluator. */
const ADMITTED_KEYS: ReadonlySet<string> = new Set<string>([...FINANCIAL_CAVEAT_KEYS, "aud"]);

/**
 * The longest decimal string either side of a comparison may be. NOT a protocol rule and
 * not a currency rule — a denial-of-service bound. `BigInt(...)` on an attacker-chosen
 * digit string is superlinear, and both sides of this comparison are attacker-influenced
 * (the caveat comes from a presented chain, the action from a request), on a code path that
 * runs before any signature has been checked. 63 digits of integer part is many orders of
 * magnitude beyond any real denomination, so nothing legitimate is excluded, and a value
 * over the bound DENIES like any other malformed value rather than being truncated.
 */
const MAX_AMOUNT_LENGTH = 82; // 63 integer digits + "." + 18 fractional digits.

/**
 * A non-negative decimal amount: no sign, no exponent, no leading zeros, at most 18
 * fractional digits (enough for wei-scale tokens). The exclusions are the point — "-5",
 * "1e5", "0x10", " 1 " and "١٢٣" all deny, so no string that a lenient numeric parser would
 * silently accept as something else can reach the comparison.
 */
export const amountSchema = z
  .string()
  .max(MAX_AMOUNT_LENGTH)
  .regex(/^(0|[1-9][0-9]*)(\.[0-9]{1,18})?$/);

/**
 * A currency code: uppercase, 3-8 characters, letter-initial. Covers ISO-4217 ("USD") and
 * the common crypto tickers ("USDC", "WBTC"). Case is significant and never folded —
 * comparison is exact, so "usd" denies rather than quietly matching "USD"; a caveat author
 * and an action author who disagree about case disagree about something, and guessing which
 * is what a bypass looks like.
 */
export const currencySchema = z.string().regex(/^[A-Z][A-Z0-9]{2,7}$/);

const nonEmptyStringSchema = z.string().min(1);

/**
 * A beneficiary constraint: one permitted payee, or a non-empty allow-list of them — the
 * same shape `aud` uses, for the same reason (an allow-list is the narrowing form of a
 * single value). Beneficiary identifiers are opaque to this module: it compares them
 * exactly and ascribes them no structure, so an account number, a participant id and a
 * `payto:` URI all work, and none is normalized.
 */
export const beneficiaryCaveatSchema = z.union([
  nonEmptyStringSchema,
  z.array(nonEmptyStringSchema).min(1)
]);

/** Binds a grant to ONE specific action, by an id the relying party assigns. */
export const actionIdCaveatSchema = nonEmptyStringSchema;

/**
 * The minimum approval level the action must have obtained, on a deployment-defined 0..100
 * scale. Bounded at both ends so the vocabulary stays closed: a tier outside the range —
 * in the caveat OR in the action — is malformed and denies. In particular an action
 * claiming tier 101 does not clear a tier-100 caveat by being "even higher"; it is a value
 * this vocabulary does not define, and undefined values deny.
 */
export const approvalTierSchema = z.number().int().min(0).max(100);

/**
 * What the relying party says the request is actually doing. Every field is optional
 * because a caller describes only the dimensions its action has — but an absent field
 * cannot satisfy a caveat that constrains it, so omitting one is a denial and never a
 * waiver (see the fail-closed rules on the module doc).
 */
export type FinancialAction = {
  /** Decimal string, same grammar as {@link amountSchema}. Never a number. */
  amount?: string;
  currency?: string;
  beneficiary?: string;
  actionId?: string;
  approvalTier?: number;
};

/**
 * Whether a value is a plain object — the only shape a caveat map is ever legitimately in.
 * `grantSchema` parses `caveats` with `z.record(...)`, which yields exactly that.
 *
 * The check is deliberately narrow rather than `typeof === "object"`, because two of the
 * things that check admits would be APPROVED by the sweep below instead of denied:
 * `Object.keys([])` is empty, so an empty array reads as "no caveats", and so does any
 * class instance whose state lives on its prototype. Neither reached this function from a
 * verified grant, so neither is a case to be lenient about. A null prototype is admitted
 * (it is a plain map with no inherited surface at all); a foreign prototype is not, since
 * a constraint parked there is invisible to `Object.keys` and approving around an
 * invisible constraint is precisely how a caveat gets laundered.
 */
function isCaveatMap(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

/** Own-property presence, immune to a prototype-borne `maxAmount` on a hostile object. */
function has(caveats: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(caveats, key);
}

/**
 * Scales a validated decimal string to an integer in units of `10^fractionDigits`.
 * The input is already known to match {@link amountSchema}, so the split is total and the
 * digits are ASCII.
 */
function scaled(value: string, fractionDigits: number): bigint {
  const dot = value.indexOf(".");
  const whole = dot === -1 ? value : value.slice(0, dot);
  const fraction = dot === -1 ? "" : value.slice(dot + 1);
  return BigInt(whole + fraction.padEnd(fractionDigits, "0"));
}

/** Fractional digit count of a validated decimal string. */
function fractionDigitsOf(value: string): number {
  const dot = value.indexOf(".");
  return dot === -1 ? 0 : value.length - dot - 1;
}

/**
 * `a <= b` over two validated decimal strings, compared at the LONGER of the two
 * fractional lengths so that trailing zeros carry no weight: "10" and "10.00" are one
 * amount, and so are "10.001" and "10.0010". Normalizing UP to the longer side (rather
 * than trimming down to the shorter) is what keeps a minor unit from being rounded away —
 * trimming would compare "10.01" against a cap of "10" as 10 vs 10 and let it through.
 */
function amountAtMost(a: string, b: string): boolean {
  const digits = Math.max(fractionDigitsOf(a), fractionDigitsOf(b));
  return scaled(a, digits) <= scaled(b, digits);
}

/**
 * Evaluates the financial caveats on ONE grant against ONE action.
 *
 * Pure and total: it returns `false` for anything it cannot positively approve and never
 * throws, because it runs inside `verifyGrantChain`'s per-link loop where a thrown error
 * would escape a verification call as an exception rather than a verdict.
 *
 * `aud` is ignored here — deliberately, and it is the one key that is neither enforced nor
 * treated as unknown, because the resolver has already evaluated it against `verifierId`
 * by the time this hook runs. Re-checking it here would need a verifier id this function
 * does not have and does not want.
 *
 * @param caveats the link's `caveats` map, exactly as it appears in the signed grant.
 * @param action  the pending side effect, as described by the relying party.
 */
export function evaluateFinancialCaveats(
  caveats: Record<string, unknown>,
  action: FinancialAction
): boolean {
  try {
    if (!isCaveatMap(caveats)) {
      return false;
    }

    // UNKNOWN-KEY SWEEP, first and unconditional. The protocol rejects a link with foreign
    // caveats unless an evaluator vouches for it, so an evaluator that returns `true` while
    // ignoring a key it does not understand has repealed that rule on the chain's behalf.
    // The sweep runs over every own key before any constraint is evaluated, so a chain
    // cannot smuggle an unenforced caveat alongside satisfiable ones.
    for (const key of Object.keys(caveats)) {
      if (!ADMITTED_KEYS.has(key)) {
        return false;
      }
    }

    // --- maxAmount ------------------------------------------------------------------
    if (has(caveats, "maxAmount")) {
      const cap = amountSchema.safeParse(caveats["maxAmount"]);
      if (!cap.success) {
        return false;
      }
      // An uncurrencied cap is not a cap: "at most 100" is satisfied by 100 of a currency
      // worth a hundred times more than the one the issuer had in mind. Rather than pick a
      // default currency (there is no correct one) the pairing is REQUIRED, so a grant
      // minted without it is inert instead of dangerously interpretable.
      if (!has(caveats, "currency")) {
        return false;
      }
      const capCurrency = currencySchema.safeParse(caveats["currency"]);
      if (!capCurrency.success) {
        return false;
      }
      // The action must name the same currency. Equality against an already-validated
      // caveat value is what makes a separate schema check of `action.currency`
      // unnecessary: nothing malformed can be equal to something well-formed.
      if (action.currency !== capCurrency.data) {
        return false;
      }
      const amount = amountSchema.safeParse(action.amount);
      if (!amount.success) {
        return false;
      }
      if (!amountAtMost(amount.data, cap.data)) {
        return false;
      }
    }

    // --- currency ---------------------------------------------------------------------
    // Evaluated on its own too, so a `currency` caveat WITHOUT a `maxAmount` still binds
    // the denomination (and so that a chain carrying both is not silently dependent on the
    // order the two branches happen to run in).
    if (has(caveats, "currency")) {
      const currency = currencySchema.safeParse(caveats["currency"]);
      if (!currency.success || action.currency !== currency.data) {
        return false;
      }
    }

    // --- beneficiary ------------------------------------------------------------------
    if (has(caveats, "beneficiary")) {
      const allowed = beneficiaryCaveatSchema.safeParse(caveats["beneficiary"]);
      if (!allowed.success) {
        return false;
      }
      const target = nonEmptyStringSchema.safeParse(action.beneficiary);
      if (!target.success) {
        return false;
      }
      const admitted = Array.isArray(allowed.data)
        ? allowed.data.includes(target.data)
        : allowed.data === target.data;
      if (!admitted) {
        return false;
      }
    }

    // --- actionId ---------------------------------------------------------------------
    if (has(caveats, "actionId")) {
      const bound = actionIdCaveatSchema.safeParse(caveats["actionId"]);
      if (!bound.success || action.actionId !== bound.data) {
        return false;
      }
    }

    // --- approvalTier -----------------------------------------------------------------
    if (has(caveats, "approvalTier")) {
      const minimum = approvalTierSchema.safeParse(caveats["approvalTier"]);
      if (!minimum.success) {
        return false;
      }
      // The action's own tier goes through the SAME schema: this is the one comparison
      // where a `>=` against an unvalidated number would be exploitable, since `Infinity`,
      // `1e400` and a non-integer all satisfy `>= minimum` while naming no defined tier.
      const attained = approvalTierSchema.safeParse(action.approvalTier);
      if (!attained.success || attained.data < minimum.data) {
        return false;
      }
    }

    return true;
  } catch {
    // Nothing above is expected to throw — every parse is a `safeParse` and every BigInt
    // is built from schema-validated digits. This exists because the function's contract is
    // totality: a hostile `caveats` object can carry a throwing getter, and one escaping
    // exception would turn a verification VERDICT into a crash inside the resolver's loop.
    return false;
  }
}

/**
 * Builds the per-action evaluator to hand to
 * {@link GrantVerifyOptions.evaluateCaveats}. One evaluator per action, never per session:
 * the closure IS the request context the resolver's hook signature does not carry.
 */
export function createFinancialCaveatEvaluator(action: FinancialAction): (grant: Grant) => boolean {
  return (grant) => evaluateFinancialCaveats(grant.caveats, action);
}
