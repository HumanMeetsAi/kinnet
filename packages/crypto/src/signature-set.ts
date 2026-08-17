/**
 * Canonical signature sets — spec 015 (S0–S3) and spec 003's "no two states may share a
 * quorum" replay rule.
 *
 * This module holds the parts of those rules that are pure combinatorics over key refs,
 * thresholds and verification outcomes: no curve work, no record shapes. `records.ts` and
 * `log.ts` both drive it, so the two paths cannot drift — which is the whole reason it is a
 * module rather than a helper inside either of them.
 *
 * The rules, and where each is decided here:
 *
 * - **S0** — a key state's key list holds no repeated key. {@link checkKeyState}, on key
 *   VALUE rather than list position, because an index-based reading is exactly the bug S0
 *   closes (015 §S2.2).
 * - **S1** — `threshold` matches `^[1-9][0-9]*$`, `t <= n`, and `m = t` exactly.
 *   {@link checkKeyState} and {@link checkMemberCount}. Both are length/format comparisons
 *   and both run before any curve work, per 015 §S1 and 003's length-before-shape rule.
 * - **S2/S3** — every member verifies under a distinct listed key, assigned in strictly
 *   increasing key index. {@link walkSignatureSet}, which is 015's normative greedy forward
 *   walk verbatim.
 *
 * S4 (the check precedes the digest) and S5 (the existential over states sits outside the
 * per-state check) are properties of the CALLERS, not of this module; they are asserted at
 * the call sites and in their tests.
 */

/** Which rule of spec 015 refused a signature set. */
export type SignatureSetRule = "S0" | "S1" | "S2/S3";

/**
 * Why a signature set was refused, at a finer grain than the rule number.
 *
 * Deliberately NOT collapsed into one "invalid signature set": a caller — and a test — must
 * be able to tell which rule fired, or a green suite cannot distinguish a real result from a
 * check that never ran. The three `explain`-only codes below refine
 * `no_conforming_assignment`; see {@link diagnoseAssignment}.
 */
export type SignatureSetRejectionCode =
  /** S0: the state lists the same key twice. */
  | "state_repeats_key"
  /** S1: `threshold` is not a decimal string in `^[1-9][0-9]*$`. */
  | "threshold_malformed"
  /** S1: `t > n` — unsatisfiable by construction, so the STATE is invalid. */
  | "threshold_exceeds_key_count"
  /** S1: `m != t`. Covers both the over-signed and the deleted-member halves. */
  | "signature_count_not_threshold"
  /** S2/S3: the greedy walk found no strictly increasing injective assignment. */
  | "no_conforming_assignment"
  /** S2 (totality), `explain` only: some member verifies under no listed key. */
  | "member_verifies_under_no_listed_key"
  /** S2 (injectivity), `explain` only: every member verifies, but not under distinct keys. */
  | "members_not_injectively_assignable"
  /** S3 (order), `explain` only: an injective assignment exists, but none is increasing. */
  | "members_out_of_key_order";

export type SignatureSetRejection = {
  ok: false;
  rule: SignatureSetRule;
  code: SignatureSetRejectionCode;
  message: string;
  /** The member the walk could not assign, for the S2/S3 codes only. */
  memberIndex?: number;
};

const THRESHOLD_PATTERN = /^[1-9][0-9]*$/;

function reject(
  rule: SignatureSetRule,
  code: SignatureSetRejectionCode,
  message: string,
  memberIndex?: number
): SignatureSetRejection {
  return memberIndex === undefined
    ? { ok: false, rule, code, message }
    : { ok: false, rule, code, message, memberIndex };
}

/**
 * S1's threshold domain: a decimal string matching `^[1-9][0-9]*$` — no sign, no leading
 * zero, no fraction, no whitespace, no empty string. Returns null for anything else.
 *
 * A `number` is admitted only when its decimal rendering would match, i.e. a safe integer
 * `>= 1`. It is NOT coerced: 015 forbids "the threshold parsed to zero, so zero signatures
 * suffice" explicitly as a fail-open outcome, and `Number("")`, `Number(null)` and
 * `Number("0x2")` are exactly the shapes that produce it.
 */
export function parseThreshold(threshold: number | string): number | null {
  const text = typeof threshold === "number" ? String(threshold) : threshold;
  if (typeof text !== "string" || !THRESHOLD_PATTERN.test(text)) {
    return null;
  }
  const value = Number(text);
  return Number.isSafeInteger(value) ? value : null;
}

export type KeyStateCheck =
  | { ok: true; keyCount: number; threshold: number }
  | SignatureSetRejection;

/**
 * S0 and S1's state rules: the key list holds no repeated key, and `1 <= t <= n`.
 *
 * `keyRefs` must already be in their canonical KeyRef text form — comparison is on the key
 * VALUE, and two encodings of one key would defeat that. Callers holding raw bytes encode
 * first (`records.ts` does).
 *
 * A state that fails either rule is invalid, and so is every record checked against it: this
 * returns a rejection rather than a "state is fine, records will fail" verdict, which is the
 * difference 015 §S1 draws between an invalid state and an unsatisfiable one.
 */
export function checkKeyState(
  keyRefs: readonly string[],
  threshold: number | string
): KeyStateCheck {
  const keyCount = keyRefs.length;
  if (new Set(keyRefs).size !== keyCount) {
    return reject(
      "S0",
      "state_repeats_key",
      `Key state lists ${keyCount} keys but only ${new Set(keyRefs).size} distinct ones`
    );
  }
  const parsed = parseThreshold(threshold);
  if (parsed === null) {
    return reject(
      "S1",
      "threshold_malformed",
      `Threshold ${JSON.stringify(String(threshold))} is not a decimal string matching ^[1-9][0-9]*$`
    );
  }
  if (parsed > keyCount) {
    return reject(
      "S1",
      "threshold_exceeds_key_count",
      `Key state has a threshold of ${parsed} but lists only ${keyCount} keys`
    );
  }
  return { ok: true, keyCount, threshold: parsed };
}

/**
 * S1's exact-count rule: `m = t`. Not "at least t", and not "at most n".
 *
 * A LENGTH comparison, so it runs before the signature array is decoded and before the record
 * is canonicalized — 015 §S1 requires it first "before any curve work", and a bound that
 * parses every element before reporting the violation has added a parse cost rather than a
 * bound.
 */
export function checkMemberCount(
  memberCount: number,
  threshold: number
): SignatureSetRejection | null {
  if (memberCount === threshold) {
    return null;
  }
  return reject(
    "S1",
    "signature_count_not_threshold",
    `Signature set carries ${memberCount} members against a threshold of ${threshold}`
  );
}

/**
 * Spec 015's normative decision procedure for S2 and S3 — the greedy forward walk, verbatim:
 *
 * ```
 *   j <- 0
 *   for i in 0 … m−1:
 *       while j < n and not verify(S_i, input, K_j):
 *           j <- j + 1
 *       if j = n:  REJECT
 *       j <- j + 1
 * ```
 *
 * Returns null when a conforming assignment was found, or the index of the member that could
 * not be assigned.
 *
 * Greedy earliest-match is not merely ONE search: if any strictly increasing injective
 * assignment exists this walk finds one (exchange argument), so "the walk rejected it" and
 * "no conforming assignment exists" are the same statement, and no implementation needs
 * backtracking. That is what makes the procedure a tie-break: two implementations running it
 * agree on every input, including inputs where more than one assignment exists.
 *
 * It performs **at most `n`** calls to `verifyAt` — one per listed key, whatever `m` is.
 * Every call is followed by an increment of `j` on both branches, `j` never decreases, and it
 * is bounded above by `n`. The member count is not a factor in the cost at all.
 */
export function walkSignatureSet(
  memberCount: number,
  keyCount: number,
  verifyAt: (memberIndex: number, keyIndex: number) => boolean
): number | null {
  let key = 0;
  for (let member = 0; member < memberCount; member += 1) {
    while (key < keyCount && !verifyAt(member, key)) {
      key += 1;
    }
    if (key === keyCount) {
      return member;
    }
    key += 1;
  }
  return null;
}

/**
 * Refines a walk failure into the specific rule that caused it, from a COMPLETE
 * member-by-key verification matrix.
 *
 * This is diagnosis, never the verdict: the verdict is {@link walkSignatureSet}'s, and this
 * cannot disagree with it — every branch below is reached only when the walk has already
 * rejected. It exists because "S2 and S3 are decided together" (015 §S3) makes a single
 * rejection code the honest hot-path answer, while a test battery whose rejections are all
 * the same code cannot show that each rule is separately enforced.
 *
 * It costs a full `m x n` matrix — the very search 015's walk replaces — so callers opt in.
 */
export function diagnoseAssignment(
  matrix: readonly (readonly boolean[])[]
): Extract<
  SignatureSetRejectionCode,
  | "member_verifies_under_no_listed_key"
  | "members_not_injectively_assignable"
  | "members_out_of_key_order"
> {
  // S2, totality: a member that verifies under no key of the state.
  if (matrix.some((row) => !row.some(Boolean))) {
    return "member_verifies_under_no_listed_key";
  }
  // S2, injectivity: every member verifies somewhere, but no assignment gives each its own
  // key. Kuhn's augmenting-path matching; m and n are bounded by the record schemas at 8.
  const assignedTo = new Map<number, number>();
  const augment = (member: number, seen: Set<number>): boolean => {
    const row = matrix[member] ?? [];
    for (let key = 0; key < row.length; key += 1) {
      if (!row[key] || seen.has(key)) {
        continue;
      }
      seen.add(key);
      const holder = assignedTo.get(key);
      if (holder === undefined || augment(holder, seen)) {
        assignedTo.set(key, member);
        return true;
      }
    }
    return false;
  };
  for (let member = 0; member < matrix.length; member += 1) {
    if (!augment(member, new Set<number>())) {
      return "members_not_injectively_assignable";
    }
  }
  // S3, order: an injective assignment exists, but no strictly increasing one does — which is
  // what the walk just failed to find.
  return "members_out_of_key_order";
}

/** A committed key state, as the quorum rule sees it: a key list and a threshold. */
export type QuorumState = { keys: readonly string[]; threshold: string };

/** The pair of states that violate spec 003's quorum rule, and the numbers that show it. */
export type QuorumViolation = {
  /** Indices into the states array as supplied — event order for a key log. */
  first: number;
  second: number;
  shared: number;
  minThreshold: number;
};

/**
 * Spec 003's "no two states may share a quorum": for EVERY pair of states `A`, `B` a log
 * commits, `|keys(A) ∩ keys(B)| < min(t_A, t_B)`.
 *
 * Over every pair and not merely consecutive ones, because records verify against any state
 * the log ever committed (008, 012) — so every pair is simultaneously live for verification,
 * and a rule checked pairwise on adjacent events leaves the route open between non-adjacent
 * ones.
 *
 * A malformed threshold is treated as `min` of nothing: this returns no violation for it and
 * leaves the rejection to S1, which owns the threshold domain. Callers run S1 per event
 * first, so a threshold reaching here has already been through it.
 *
 * Returns the FIRST violating pair in `(second, first)` scan order, or null.
 */
export function quorumViolation(states: readonly QuorumState[]): QuorumViolation | null {
  for (let second = 1; second < states.length; second += 1) {
    const b = states[second]!;
    const bThreshold = parseThreshold(b.threshold);
    if (bThreshold === null) {
      continue;
    }
    const bKeys = new Set(b.keys);
    for (let first = 0; first < second; first += 1) {
      const a = states[first]!;
      const aThreshold = parseThreshold(a.threshold);
      if (aThreshold === null) {
        continue;
      }
      let shared = 0;
      for (const key of new Set(a.keys)) {
        if (bKeys.has(key)) {
          shared += 1;
        }
      }
      const minThreshold = Math.min(aThreshold, bThreshold);
      if (shared >= minThreshold) {
        return { first, second, shared, minThreshold };
      }
    }
  }
  return null;
}
