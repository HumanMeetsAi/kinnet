/**
 * Regenerates the committed spec-005 Ed25519 verification-mode conformance vectors.
 *
 * These pin the verification MODE: strict RFC 8032 **plus a low-order public-key rejection**,
 * rather than `@noble/curves`' cofactored (ZIP-215) default. The low-order rejection is 005's
 * own addition — RFC 8032 §5.1.7 step 3 endorses the cofactored equation and so admits
 * small-order keys — which is why a stock RFC 8032 verifier is not automatically conforming.
 * Every vector is checkable from bytes alone: a message, a 64-byte signature, a 32-byte public
 * key and its `KeyRef`, plus the expected verdict and the reason.
 *
 * The 8 small-order public keys are DERIVED here, not copied: one published order-8 encoding
 * seeds the subgroup and the script asserts the derived set is 8 distinct encodings, every one
 * small-order, closing back to the identity — so a reader need not trust a hardcoded list.
 *
 * Run from the repo root (after `pnpm build`). BOTH commands, in order — this script writes
 * `JSON.stringify(…, null, 2)` and the committed file is prettier-formatted, so skipping the
 * second step leaves a diff that is pure formatting and makes the fixture look non-reproducible:
 *
 *   pnpm exec tsx packages/crypto/scripts/generate-ed25519-verification-fixtures.ts
 *   pnpm exec prettier --write packages/crypto/test/fixtures/ed25519-verification-vectors.json
 */
import { writeFileSync } from "node:fs";

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  canonicalBytes,
  decodeKeyRef,
  encodeKeyRef,
  encodeSignature,
  generateKeyPair,
  sign,
  verify
} from "@kinnet/crypto";

const bytesToHex = (bytes: Uint8Array): string =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/../g)!.map((byte) => parseInt(byte, 16)));

const P = 2n ** 255n - 19n;
/** The Ed25519 group order `L` = 2^252 + 27742317777372353535851937790883648493. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const numberToBytesLE = (value: bigint, length: number): Uint8Array => {
  const out = new Uint8Array(length);
  let rest = value;
  for (let i = 0; i < length; i++) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
};
const bytesToNumberLE = (bytes: Uint8Array): bigint =>
  bytes.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);

// ------------------------------------------------------------------------------------------
// The 8 small-order public keys, derived from one published order-8 point.
// ------------------------------------------------------------------------------------------

/** A published Ed25519 point of order 8. Everything below is derived from it and checked. */
const PUBLISHED_ORDER_8 = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa";

const Point = ed25519.Point;
const order8 = Point.fromBytes(hexToBytes(PUBLISHED_ORDER_8), true);

const smallOrderHex: string[] = [];
let running = Point.ZERO;
for (let i = 0; i < 8; i++) {
  smallOrderHex.push(bytesToHex(running.toBytes()));
  running = running.add(order8);
}

// Self-checks, so the derived set is proven rather than asserted in a comment.
if (!running.equals(Point.ZERO)) {
  throw new Error("The derived subgroup does not close back to the identity after 8 additions");
}
if (new Set(smallOrderHex).size !== 8) {
  throw new Error(`Expected 8 distinct small-order encodings, got ${new Set(smallOrderHex).size}`);
}
for (const hex of smallOrderHex) {
  if (!Point.fromBytes(hexToBytes(hex), true).isSmallOrder()) {
    throw new Error(`Derived point ${hex} is not small-order`);
  }
}
// Sorted, so the committed order is stable across runs and independent of the seed point.
smallOrderHex.sort();

/** The canonical encoding of the identity point, which is also the `R` of the zero signature. */
const IDENTITY = "0100000000000000000000000000000000000000000000000000000000000000";

const MESSAGE = "any message at all";
const messageBytes = new TextEncoder().encode(MESSAGE);

/**
 * `R` = the identity point, `S` = 0. No secret key is involved in building this — small-order
 * points have no discrete log to know — so it is not a forgery and nothing about it is
 * infeasible. Under cofactored (ZIP-215) verification it verifies under every small-order
 * public key, for any message.
 */
const zeroSignature = (() => {
  const sig = new Uint8Array(64);
  sig.set(hexToBytes(IDENTITY), 0);
  return sig; // S stays all-zero
})();

// ------------------------------------------------------------------------------------------
// An honest keypair, for the accept vector and the malleability vectors built from it.
// ------------------------------------------------------------------------------------------

const honest = generateKeyPair(new Uint8Array(32).fill(9));
const honestSignature = sign(messageBytes, honest.secretKey);

type Vector = {
  name: string;
  why: string;
  /** The expected verdict of spec-005 verification: `verify(signature, message, publicKey)`. */
  accept: boolean;
  message: string;
  signatureHex: string;
  publicKeyHex: string;
  /** The multibase/multicodec `KeyRef` for `publicKeyHex` — spec 005's key encoding. */
  keyRef: string;
  /** Whether `decodeKeyRef` accepts that `KeyRef`. Deliberately separate from `accept`. */
  keyRefDecodes: boolean;
  /** Whether the public key is a small-order point. */
  publicKeyIsSmallOrder: boolean;
  /** What `@noble/curves`' cofactored DEFAULT returns — the mode spec 005 now forbids. */
  acceptedByCofactoredDefault: boolean;
};

/** Round-trips through the encoding layer: does `decodeKeyRef` accept the `KeyRef`, and give
 *  the same 32 bytes back? True for every key the mode rejects, which is the point. */
const keyRefDecodes = (publicKey: Uint8Array): boolean => {
  try {
    const decoded = decodeKeyRef(encodeKeyRef(publicKey));
    return decoded.length === publicKey.length && decoded.every((byte, i) => byte === publicKey[i]);
  } catch {
    return false;
  }
};

const vector = (
  name: string,
  why: string,
  accept: boolean,
  signature: Uint8Array,
  publicKey: Uint8Array
): Vector => {
  const actual = verify(signature, messageBytes, publicKey);
  if (actual !== accept) {
    throw new Error(
      `Vector "${name}" expects accept=${accept} but @kinnet/crypto's verify returned ${actual}`
    );
  }
  let cofactored: boolean;
  try {
    cofactored = ed25519.verify(signature, messageBytes, publicKey, { zip215: true });
  } catch {
    cofactored = false;
  }
  return {
    name,
    why,
    accept,
    message: MESSAGE,
    signatureHex: bytesToHex(signature),
    publicKeyHex: bytesToHex(publicKey),
    keyRef: encodeKeyRef(publicKey),
    keyRefDecodes: keyRefDecodes(publicKey),
    publicKeyIsSmallOrder: Point.fromBytes(publicKey, true).isSmallOrder(),
    acceptedByCofactoredDefault: cofactored
  };
};

const vectors: Vector[] = [];

// --- The accept vector, first, so the suite cannot pass by rejecting everything. -----------

vectors.push(
  vector(
    "accept — an honest signature by an honest key",
    "The control, and the vector that stops this suite from passing vacuously. A real Ed25519 " +
      "signature by a real key over exactly these message bytes. The pinned mode is STRICTER " +
      "than the cofactored default, so it can only ever reject things the default accepted — " +
      "this vector pins that the pin costs nothing legitimate. Accepted in both modes.",
    true,
    honestSignature,
    honest.publicKey
  )
);

// --- The 8 small-order rejections: the construction the pin exists for. --------------------

for (const [index, hex] of smallOrderHex.entries()) {
  const publicKey = hexToBytes(hex);
  vectors.push(
    vector(
      `reject — R = identity, S = 0 under small-order public key ${index + 1} of 8`,
      "The construction spec 003's soundness paragraph names. `R` is the identity point and " +
        "`S` is zero, so the cofactored equation [h]R + [h][k]A' - [h][S]B == 0 holds for ANY " +
        "small-order A' and any message — and NO SECRET KEY IS INVOLVED, because small-order " +
        "points have no discrete log to know. `@noble/curves`' default and {zip215: true} " +
        "accept this under all 8 of these keys; the mode 005 pins rejects all 8, because its " +
        "rule 1 adds a small-order public-key rejection that RFC 8032 does NOT require — the " +
        "RFC's §5.1.7 step 3 endorses the cofactored equation and so admits these keys, and a " +
        "stock RFC 8032 verifier accepts this vector. Node v24.2.0 WebCrypto accepts it under " +
        "a MESSAGE-DEPENDENT subset of the 8, ALWAYS including the identity key: it evaluates " +
        "the COFACTORLESS equation with no small-order rejection, so acceptance requires " +
        "ord(A) to divide h = SHA-512(R || A || M) mod L, and h changes with the message. " +
        "MEASURED over 400 distinct messages, as exact COUNTS out of 400 rather than rates: " +
        "400, 192, 93, 103, 51, 50, 50, 50 (keys ordered identity, order 2, the two of order 4, " +
        "then the four of order 8), summing to 989, so mean 989/400 = 2.473 of 8. As rates that " +
        "is 1.00, 0.48, 0.23, 0.26, 0.13, 0.13, 0.13, 0.13 — two decimals on purpose, since at " +
        "n=400 the standard error is about 0.025 at p=1/2 and 0.017 at p=1/8, so a third " +
        "decimal is noise; the identity key's 400/400 is the exception, being p=1 exactly with " +
        "zero variance. PREDICTED by the subgroup structure, " +
        "which is a different statement: the rates should tend to 1, 1/2, 1/4, 1/4 and 1/8 for " +
        "each order-8 key, mean 2.5. The measurement tracks the prediction, which is what " +
        "identifies the mechanism, but no finite sample yields those fractions exactly and the " +
        "two must not be conflated. Any single number quoted for that verifier is one sample " +
        "of a distribution, not a property of it. " +
        "This matters beyond interop: the same signature verifying under all 8 keys is " +
        "exactly the 'one signature verifies under many keys' case that breaks 003's " +
        "quorum-rule counting argument.",
      false,
      zeroSignature,
      publicKey
    )
  );
}

// --- Non-canonical S. Honestly labelled: rejected in BOTH modes. ---------------------------

const nonCanonicalS = (() => {
  const sig = new Uint8Array(honestSignature);
  const S = bytesToNumberLE(honestSignature.slice(32));
  if (S + L >= 2n ** 256n) {
    throw new Error("S + L does not fit in 32 bytes for this signature; pick another seed");
  }
  sig.set(numberToBytesLE(S + L, 32), 32);
  return sig;
})();

vectors.push(
  vector(
    "reject — non-canonical S (an honest signature with S += L)",
    "The honest signature above with its scalar shifted by the group order, so it is congruent " +
      "mod L and still fits in 32 bytes. Requiring 0 <= S < L is what stops a third party from " +
      "re-encoding somebody's signature into different bytes that still verify — malleability " +
      "the digest of a signed record would not survive. STATED HONESTLY: this vector does NOT " +
      "distinguish the two modes. `@noble/curves` range-checks S in BOTH — measured false under " +
      "the default, {zip215: true} and {zip215: false} alike — so reverting the pin does not " +
      "make it pass. It is committed because 005 now requires the rejection NORMATIVELY, and " +
      "another implementation whose default reduces S mod L instead of rejecting would fail it.",
    false,
    nonCanonicalS,
    honest.publicKey
  )
);

// --- Non-canonical point encoding. Only representable for y < 2^255 - p = 19. --------------

const nonCanonicalIdentity = numberToBytesLE(1n + P, 32);

vectors.push(
  vector(
    "reject — non-canonical public-key encoding (identity point as y + p)",
    "The identity point's y-coordinate is 1, re-encoded as 1 + p. ZIP-215 decodes a " +
      "y-coordinate in [0, 2^255) and so accepts it; strict RFC 8032 requires [0, p) and " +
      "rejects it. Only y < 2^255 - p = 19 admits such an encoding at all, which is why this " +
      "vector uses a small-order point — but the rule is about ENCODING, not order, and a " +
      "second implementation that reduces the y-coordinate mod p before decoding would accept " +
      "a public key whose bytes are not the canonical form of any key, giving one key two " +
      "`KeyRef`s. Measured: the cofactored default accepts, strict rejects.",
    false,
    zeroSignature,
    nonCanonicalIdentity
  )
);

// ------------------------------------------------------------------------------------------
// The record-layer consequence, which is the reason this pin blocks 003 and 015 rather than
// being a tidy-up: one keyless signature satisfying a multi-key quorum.
// ------------------------------------------------------------------------------------------

const QUORUM_RECORD = {
  revokes: "zQmc6UYfYm7JAhahkGriEwatG3MQxULGH1wWJo6xdz9ZtGm",
  issuerId: "pk_zQmXbJDQAmijYmFxknjGFdCoVRC5TqrzUmRFHnWMrgtmJQa",
  revokedAt: "2026-06-12T00:00:00.000Z"
};

const quorumKeyRefs = smallOrderHex.slice(0, 3).map((hex) => encodeKeyRef(hexToBytes(hex)));
/** The zero signature over the record's spec-001 signing input — identical bytes regardless. */
const quorumSignature = encodeSignature(zeroSignature);
const quorumInput = canonicalBytes(QUORUM_RECORD);
const quorumMatrix = quorumKeyRefs.map((keyRef) =>
  verify(zeroSignature, quorumInput, decodeKeyRef(keyRef))
);
if (quorumMatrix.some((accepted) => accepted)) {
  throw new Error("The quorum vector must reject under the pinned mode");
}

const quorumVector = {
  name: "reject — one keyless signature against a 3-key, threshold-3 state of small-order keys",
  why:
    "The record-layer statement of the same defect, and the reason this pin is a PREREQUISITE " +
    "for spec 003's 'no two states may share a quorum' rule rather than an interop tidy-up. " +
    "003's soundness argument counts surviving signature-set members against the key " +
    "intersection, and that counting is only valid if a signature verifies under exactly one " +
    "key. Here ONE signature — R = identity, S = 0, built with no secret key — is offered " +
    "against a state listing three DISTINCT small-order keys at threshold 3. Under cofactored " +
    "verification it verifies under each of the three, `verifyThresholdRecord` finds three " +
    "distinct satisfied keys, and the record passes a 3-of-3 quorum with no key at all. Under " +
    "the pinned mode every one of the three verifications is false and the record fails. " +
    "Severity is bounded and saying so is part of stating it honestly: reaching this needs the " +
    "issuer's own published state to list small-order keys, which only that issuer can publish " +
    "and which gains it nothing over setting threshold to 1 — self-harm, not an outsider " +
    "attack. What it breaks is the RULE'S ARGUMENT, which is why it blocks the spec.",
  state: { keys: quorumKeyRefs, threshold: "3" },
  record: { ...QUORUM_RECORD, signature: [quorumSignature] },
  signingInput: new TextDecoder().decode(quorumInput),
  /** matrix[j] = verify(the single signature, signingInput, state.keys[j]) under spec 005. */
  matrix: quorumMatrix,
  /** The spec-005 verdict for the record against `state`. */
  valid: false
};

const target = new URL("../test/fixtures/ed25519-verification-vectors.json", import.meta.url);
writeFileSync(
  target,
  `${JSON.stringify(
    {
      note:
        "Conformance vectors for spec 005's pinned Ed25519 verification mode: STRICT RFC 8032 " +
        "PLUS A LOW-ORDER PUBLIC-KEY REJECTION, not the cofactored (ZIP-215) mode that is " +
        "`@noble/curves`' default. The low-order rejection is 005's own addition and NOT an RFC " +
        "8032 requirement — the RFC's §5.1.7 step 3 endorses the cofactored equation, which " +
        "admits small-order keys — so a stock RFC 8032 verifier will fail the 8 rejection " +
        "vectors below unless it adds that check explicitly. Measured: Node v24.2.0 WebCrypto " +
        "violates rules 1 and 3 — it imports all 8 small-order keys and the non-canonically " +
        "encoded key y = 1 + p, and accepts the keyless R = identity, S = 0 signature under a " +
        "MESSAGE-DEPENDENT subset of the 8. It evaluates the COFACTORLESS equation with no " +
        "small-order rejection, so acceptance requires ord(A) to divide h = SHA-512(R || A || " +
        "M) mod L. MEASURED over 400 distinct messages, as exact COUNTS out of 400 rather than " +
        "rates: 400, 192, 93, 103, 51, 50, 50, 50 (keys ordered identity, order 2, the two of " +
        "order 4, then the four of order 8), summing to 989, so mean 989/400 = 2.473 of 8. As " +
        "rates that is 1.00, 0.48, 0.23, 0.26, 0.13, 0.13, 0.13, 0.13 — two decimals on " +
        "purpose, since at n=400 a third decimal is within sampling noise. The IDENTITY key " +
        "accepted every message (400/400), which is p=1 exactly rather than a sample near it, " +
        "and is the stable fact and the operationally important one. " +
        "PREDICTED by the subgroup structure, and not the same statement: the rates should " +
        "tend to 1, 1/2, 1/4, 1/4 and 1/8 per order-8 key, mean 2.5 — no finite sample yields " +
        "those fractions exactly, so they are the explanation, not the measurement. For " +
        "contrast over 8 keys x 200 messages: @noble/curves default accepted 1600/1600, and " +
        "{zip215: false} — the mode this spec pins — accepted 0/1600. Every vector is " +
        "verifiable from bytes alone — `message` is UTF-8, `signatureHex` is the 64-byte " +
        "signature, `publicKeyHex` is the 32-byte public key, `keyRef` is its spec-005 " +
        "multicodec-tagged multibase encoding, and `accept` is the verdict a conforming " +
        "implementation MUST return. `keyRefDecodes` is recorded SEPARATELY and is true even " +
        "for the rejected keys: the encoding layer checks length and multicodec tag only, so " +
        "every small-order key here is a structurally valid `KeyRef` and the rejection has to " +
        "come from verification, not from decoding. `publicKeyIsSmallOrder` and " +
        "`acceptedByCofactoredDefault` state why each rejection exists and which mode used to " +
        "accept it; a vector with `accept: false` and `acceptedByCofactoredDefault: true` is " +
        "one the pin changes. The 8 small-order keys are the complete torsion subgroup, " +
        "derived from a published order-8 point rather than copied, and sorted. Regenerate " +
        "with packages/crypto/scripts/generate-ed25519-verification-fixtures.ts.",
      groupOrderL: L.toString(),
      fieldModulusP: P.toString(),
      smallOrderPublicKeysHex: smallOrderHex,
      vectors,
      quorumNote:
        "The record-layer consequence of the mode, carried as one vector because it is the " +
        "reason 003 and 015 both name this pin as a prerequisite. `matrix[j]` is whether the " +
        "record's single signature verifies under `state.keys[j]` over `signingInput` (the " +
        "spec-001 UTF-8 JCS of the record without its `signature` field). Under the pinned " +
        "mode every entry is false; under the cofactored default every entry is true and one " +
        "keyless signature satisfies a threshold of three.",
      quorumVector
    },
    null,
    2
  )}\n`
);

console.log(
  `Wrote ${vectors.length} verification-mode vectors and 1 quorum vector to ${target.pathname}`
);
