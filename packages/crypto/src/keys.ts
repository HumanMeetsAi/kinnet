/** Ed25519 keypairs and raw sign/verify — spec 005, pure TypeScript via @noble. */
import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";

export type KeyPair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export function generateKeyPair(seed?: Uint8Array): KeyPair {
  const secretKey = seed ?? randomBytes(32);
  if (secretKey.length !== 32) {
    throw new Error(`An Ed25519 seed is 32 bytes, got ${secretKey.length}`);
  }
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

/**
 * The verification mode spec 005 pins: strict RFC 8032 **plus a low-order public-key
 * rejection**, NOT `@noble/curves`' default — and not stock RFC 8032 either, since the RFC's
 * §5.1.7 step 3 endorses the cofactored equation and so admits small-order public keys.
 *
 * The default is cofactored (ZIP-215), which accepts small-order public keys and
 * non-canonical point encodings. Under it a signature of `R` = the identity point and
 * `S` = 0 verifies under ALL 8 canonical small-order public keys, for any message, with
 * **no secret key involved** — small-order points have no discrete log to know, so this is
 * not a forgery and nothing about it is infeasible. All 8 encode as `KeyRef`s that
 * `decodeKeyRef` accepts. Measured against `@noble/curves` 2.2.0: the default and
 * `{zip215: true}` accept 8/8, `{zip215: false}` accepts 0/8.
 *
 * That is why this is not merely an interop wart. Under the cofactored mode one such signature
 * satisfies a whole threshold at once — 015's record-layer construction passes a 3-of-3 with no
 * key at all — so the pin is what makes a signature set's member count mean anything. Spec 005
 * makes the mode normative and 003 and 015 both cite it; the conformance vectors in
 * `test/fixtures/ed25519-verification-vectors.json` commit the construction.
 *
 * `verify` below takes no options parameter, deliberately: the mode is not a caller's choice,
 * so a new call site cannot silently inherit the library default. Keep direct
 * `@noble/curves/ed25519` imports confined to this file so a new site cannot reach around it
 * either (the reference implementation's repository enforces this with a lint rule).
 *
 * SCOPE, stated precisely, because `{zip215: false}` is not the whole of RFC 8032 strictness.
 * Against `@noble/curves` 2.2.0 it changes exactly two things: public keys and `R` must use
 * canonical field-element encodings (`0 <= y < p` rather than `0 <= y < 2^255`), and a
 * small-order public key is rejected outright. It does NOT switch the verification equation
 * from the cofactored form — noble evaluates `[h]R + [h][k]A' - [h][S]B == 0` in both modes.
 * Canonical, reduced `S` (`0 <= S < L`) is required in both modes already, so the pin does not
 * change that; it is normative here regardless, because another implementation's default may
 * differ.
 *
 * FROZEN, not merely `as const`. `as const` makes the property `readonly` for TypeScript and
 * nothing at all at runtime: the object is exported, so any module in the process — a
 * transitive dependency included — could have written `ED25519_VERIFY_OPTIONS.zip215 = true`
 * and silently returned every verifier in the process to the cofactored mode, with no call
 * site changed and no test touching a source file that would fail. `Object.freeze` makes that
 * assignment a `TypeError` under ES modules' implicit strict mode instead.
 */
export const ED25519_VERIFY_OPTIONS: Readonly<{ zip215: false }> = Object.freeze({
  zip215: false
} as const);

export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey, ED25519_VERIFY_OPTIONS);
  } catch {
    return false;
  }
}
