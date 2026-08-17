/** Record signing and verification — spec 001 (detached signature over JCS). */
import { sha256 } from "@noble/hashes/sha2.js";

import {
  decodeKeyRef,
  decodeSignature,
  encodeKeyRef,
  encodeSha256Multihash,
  encodeSignature
} from "./encoding.js";
import {
  DEFAULT_MAX_SIGNATURE_VERIFICATIONS,
  safeVerificationCount,
  VerificationBudgetExceeded
} from "./budget.js";
import { assertSignableNumbers, canonicalBytes } from "./jcs.js";
import { sign, verify } from "./keys.js";
import {
  checkKeyState,
  checkMemberCount,
  diagnoseAssignment,
  walkSignatureSet,
  type SignatureSetRejection
} from "./signature-set.js";

/** Multibase multihash of the JCS of a value — the digest used for IDs and hash chains. */
export function canonicalDigest(value: unknown): string {
  return encodeSha256Multihash(sha256(canonicalBytes(value)));
}

type Signable = Record<string, unknown>;

/**
 * Signs a record per spec 001: the signature is computed over the canonical form of the
 * record without its signature field, then attached.
 */
export function signRecord<T extends Signable>(
  record: T,
  secretKey: Uint8Array
): T & { signature: string } {
  const unsigned: Signable = { ...record };
  delete unsigned.signature;
  assertSignableNumbers(unsigned);
  const signature = encodeSignature(sign(canonicalBytes(unsigned), secretKey));
  return { ...(unsigned as T), signature };
}

export type VerifyRecordOptions = {
  /** Ceiling on Ed25519 verifications this call may perform. */
  maxSignatureVerifications?: number;
  /** Reports the number of Ed25519 verifications on every exit, including a throw. */
  onSignatureVerifications?: (spent: number) => void;
};

/** Verifies a record against a public key given as raw bytes or a KeyRef. */
export function verifyRecord(
  record: Signable & { signature: string },
  publicKey: Uint8Array | string,
  options: VerifyRecordOptions = {}
): boolean {
  return verifyRecordAgainstAny(record, [publicKey], options);
}

/**
 * Verifies a single-signature record against any listed key.
 *
 * The record is decoded and canonicalized once, then keys are tried in order until one
 * verifies. This is the metered form for callers holding a current key state: repeating
 * {@link verifyRecord} in `Array.some` canonicalizes the same attacker-supplied record once per
 * key and gives a request-wide budget no way to observe any of those curve checks.
 */
export function verifyRecordAgainstAny(
  record: Signable & { signature: string },
  publicKeys: readonly (Uint8Array | string)[],
  options: VerifyRecordOptions = {}
): boolean {
  const { signature, ...unsigned } = record;
  const signatureBytes = decodeSignature(signature);
  const bytes = canonicalBytes(unsigned);
  const limit = safeVerificationCount(
    options.maxSignatureVerifications,
    DEFAULT_MAX_SIGNATURE_VERIFICATIONS
  );
  let spent = 0;
  try {
    for (const publicKey of publicKeys) {
      if (spent >= limit) {
        throw new VerificationBudgetExceeded(
          `Record verification exceeded its budget of ${limit} signature verifications`
        );
      }
      const keyBytes = typeof publicKey === "string" ? decodeKeyRef(publicKey) : publicKey;
      spent += 1;
      if (verify(signatureBytes, bytes, keyBytes)) {
        return true;
      }
    }
    return false;
  } finally {
    options.onSignatureVerifications?.(spent);
  }
}

/**
 * Signs a record that carries a signature set (KeyEvent, Revocation, Grant): one
 * signature per signer over the canonical form without the signature field.
 */
export function signThresholdRecord<T extends Signable>(
  record: T,
  secretKeys: Uint8Array[]
): T & { signature: string[] } {
  const unsigned: Signable = { ...record };
  delete unsigned.signature;
  assertSignableNumbers(unsigned);
  const bytes = canonicalBytes(unsigned);
  const signature = secretKeys.map((secretKey) => encodeSignature(sign(bytes, secretKey)));
  return { ...(unsigned as T), signature };
}

export type VerifyThresholdOptions = {
  /**
   * Ceiling on Ed25519 verifications this call may perform. Defaults to
   * `DEFAULT_MAX_SIGNATURE_VERIFICATIONS`; exceeding it throws
   * {@link VerificationBudgetExceeded}.
   */
  maxSignatureVerifications?: number;
  /**
   * Called on every exit, including a throw, with the number of verifications performed —
   * so a caller carrying ONE allowance across many records charges failures too.
   */
  onSignatureVerifications?: (spent: number) => void;
};

export type CheckSignatureSetOptions = VerifyThresholdOptions & {
  /**
   * On a walk failure, refine `no_conforming_assignment` into the specific rule that caused
   * it — S2 totality, S2 injectivity, or S3 order.
   *
   * Off by default and it must stay that way on any hot path: the refinement needs the full
   * `m x n` matrix, which is the search 015's walk exists to replace. It is metered like
   * every other verification, so a caller that turns it on pays for it against its own
   * allowance. Tests turn it on; production callers do not.
   */
  explain?: boolean;
};

export type CheckSignatureSetResult = { ok: true } | SignatureSetRejection;

/**
 * Decides a signature set against one key state per spec 015 — S0, S1, S2 and S3 — and says
 * WHICH rule refused it.
 *
 * The rule, in one sentence: a signature set is valid only if it holds exactly `threshold`
 * members, every one of which verifies, each against a distinct listed key, in strictly
 * increasing key-list order.
 *
 * Order of checks, and it is normative rather than an optimization (015 §S1, §S3):
 *
 *  1. **S0** — the state lists no repeated key.
 *  2. **S1** — `threshold` is in `^[1-9][0-9]*$` and `t <= n`.
 *  3. **S1** — `m = t`, a LENGTH comparison, before the signature array is decoded and
 *     before the record is canonicalized. A bound that decodes every member before reporting
 *     the violation has added a parse cost rather than a bound.
 *  4. **S2/S3** — the greedy forward walk, at most `n` verifications whatever `m` is.
 *
 * What this replaces, and why. The previous rule iterated the KEY set and counted satisfied
 * keys, stopping once the threshold was met: "at least `threshold` distinct listed keys have
 * SOME valid signature in the array". Under it a signature array could contain duplicates,
 * could contain members that verify against nothing at all, and could appear in any order,
 * and the record still verified — and because the array is inside the digested bytes, each
 * of those variants is a DIFFERENT digest that still verifies. That is what let a revoked
 * leaf grant be edited, by someone holding no key, into a record no revocation names.
 *
 * METERED exactly as before: `maxSignatureVerifications` bounds the Ed25519 verifications and
 * `onSignatureVerifications` reports the spend on every exit, throw included. What changes is
 * the amount — the walk is at most `n` per state where the search was `n x m`.
 *
 * S4 and S5 are the CALLER's to satisfy: this decides one set against one state, and says
 * nothing about when a caller may use the record's digest (S4) or about the existential over
 * the states a log committed (S5), which stays outside this call.
 */
export function checkSignatureSet(
  record: Signable & { signature: string[] },
  keys: (Uint8Array | string)[],
  threshold: number | string,
  options: CheckSignatureSetOptions = {}
): CheckSignatureSetResult {
  const limit = safeVerificationCount(
    options.maxSignatureVerifications,
    DEFAULT_MAX_SIGNATURE_VERIFICATIONS
  );
  let spent = 0;
  try {
    // Compared on the key VALUE, not on list position: S2's injectivity is stated on value
    // because an index-only reading would let one signature be counted twice against a state
    // that repeats a key. Encoding raw bytes here is what makes the two spellings of one key
    // compare equal.
    const keyRefs = keys.map((key) => (typeof key === "string" ? key : encodeKeyRef(key)));

    const state = checkKeyState(keyRefs, threshold);
    if (!state.ok) {
      return state;
    }
    const countRejection = checkMemberCount(record.signature.length, state.threshold);
    if (countRejection) {
      return countRejection;
    }

    const { signature, ...unsigned } = record;
    const bytes = canonicalBytes(unsigned);
    const signatures = signature.map(decodeSignature);

    // Keys are decoded LAZILY, one per step of the walk. `log.ts` decodes every key of an
    // event up front instead, and the asymmetry is deliberate: there `decodeKeyRef` is the
    // only check that a stored KeyRef is a real multicodec-tagged ed25519 key, and a log is
    // stored and re-read. Here the key set is a state a replay already validated, so a key
    // sitting past the point the walk stops needs no decode.
    const publicKeys: (Uint8Array | undefined)[] = new Array(state.keyCount);
    const publicKeyAt = (index: number): Uint8Array => {
      const cached = publicKeys[index];
      if (cached !== undefined) {
        return cached;
      }
      const decoded = decodeKeyRef(keyRefs[index]!);
      publicKeys[index] = decoded;
      return decoded;
    };
    const verifyAt = (memberIndex: number, keyIndex: number): boolean => {
      if (spent >= limit) {
        throw new VerificationBudgetExceeded(
          `Threshold verification exceeded its budget of ${limit} signature verifications`
        );
      }
      spent += 1;
      return verify(signatures[memberIndex]!, bytes, publicKeyAt(keyIndex));
    };

    const failed = walkSignatureSet(signatures.length, state.keyCount, verifyAt);
    if (failed === null) {
      return { ok: true };
    }
    if (!options.explain) {
      return {
        ok: false,
        rule: "S2/S3",
        code: "no_conforming_assignment",
        message: `Signature set member ${failed} could not be assigned a distinct listed key in increasing key order`,
        memberIndex: failed
      };
    }
    const matrix = signatures.map((_member, memberIndex) =>
      Array.from({ length: state.keyCount }, (_unused, keyIndex) => verifyAt(memberIndex, keyIndex))
    );
    const code = diagnoseAssignment(matrix);
    return {
      ok: false,
      rule: "S2/S3",
      code,
      message: `Signature set rejected: ${code} (first unassignable member ${failed})`,
      memberIndex: failed
    };
  } finally {
    options.onSignatureVerifications?.(spent);
  }
}

/**
 * {@link checkSignatureSet} as a boolean — the shape every existing caller wants.
 *
 * Kept as the wide surface because a caller that only needs "is this record validly signed"
 * should not have to destructure a verdict, and because the boolean is what composes into
 * S5's existential over key states (`states.some(...)`). Callers that need to report WHICH
 * rule refused a record use `checkSignatureSet` directly.
 */
export function verifyThresholdRecord(
  record: Signable & { signature: string[] },
  keys: (Uint8Array | string)[],
  threshold: number | string,
  options: VerifyThresholdOptions = {}
): boolean {
  return checkSignatureSet(record, keys, threshold, options).ok;
}
