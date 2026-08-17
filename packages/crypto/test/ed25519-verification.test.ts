/**
 * Spec 005 — the pinned Ed25519 verification mode: strict RFC 8032 PLUS a low-order
 * public-key rejection, not the cofactored ZIP-215 mode that is `@noble/curves`' default.
 * The low-order rejection is 005's own addition rather than an RFC 8032 requirement, so a
 * stock RFC 8032 verifier fails the 8 rejection vectors below.
 *
 * The fixture is the artifact: `packages/crypto/test/fixtures/ed25519-verification-vectors.json`
 * carries, for every vector, the message, the 64-byte signature, the 32-byte public key, its
 * `KeyRef`, whether that `KeyRef` decodes, whether the key is small-order, what the cofactored
 * default returns, and the verdict a conforming implementation must reach. A second
 * implementation can check itself against those bytes without running this file.
 *
 * What this file checks is that the fixture TELLS THE TRUTH — every recorded fact is recomputed
 * here from the bytes — and that `@kinnet/crypto`'s `verify` reaches the recorded verdicts.
 *
 * THE MUTATION THESE TESTS CATCH: reverting the pin at the one call site, i.e. dropping
 * `ED25519_VERIFY_OPTIONS` from the `ed25519.verify(...)` call in `packages/crypto/src/keys.ts`
 * (or setting `zip215: true`). Watched to fail that way before the pin landed: the 8
 * small-order vectors and the non-canonical-encoding vector flip to accepted, and the quorum
 * vector's 3-of-3 record verifies with one keyless signature. The accept vector and the
 * non-canonical-S vector do NOT catch that mutation and are not claimed to — see their
 * assertions below.
 */
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import { revocationSchema } from "@kinnet/protocol";

import {
  ED25519_VERIFY_OPTIONS,
  canonicalBytes,
  decodeKeyRef,
  decodeSignature,
  encodeKeyRef,
  verify,
  verifyThresholdRecord
} from "../src/index.js";

type Vector = {
  name: string;
  why: string;
  accept: boolean;
  message: string;
  signatureHex: string;
  publicKeyHex: string;
  keyRef: string;
  keyRefDecodes: boolean;
  publicKeyIsSmallOrder: boolean;
  acceptedByCofactoredDefault: boolean;
};

type QuorumVector = {
  name: string;
  why: string;
  state: { keys: string[]; threshold: string };
  record: Record<string, unknown> & { signature: string[] };
  signingInput: string;
  matrix: boolean[];
  valid: boolean;
};

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/ed25519-verification-vectors.json", import.meta.url), "utf8")
) as {
  note: string;
  groupOrderL: string;
  fieldModulusP: string;
  smallOrderPublicKeysHex: string[];
  vectors: Vector[];
  quorumNote: string;
  quorumVector: QuorumVector;
};

const { vectors, quorumVector, smallOrderPublicKeysHex } = fixture;

const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/../g)!.map((byte) => parseInt(byte, 16)));
const bytesToHex = (bytes: Uint8Array): string =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const byName = (name: string): Vector => {
  const found = vectors.find((candidate) => candidate.name === name);
  if (!found) {
    throw new Error(`No vector named ${name}`);
  }
  return found;
};

describe("spec 005 — the pinned verification mode", () => {
  // Asserted against the IMPORTED constant rather than a literal `{ zip215: false }` redefined
  // here: a test that restates the value cannot notice the source changing to `true`.
  it("pins strict RFC 8032 plus low-order rejection, and the mode is not a caller's choice", () => {
    expect(ED25519_VERIFY_OPTIONS).toStrictEqual({ zip215: false });
    // `verify` takes exactly three parameters — signature, message, publicKey. If an options
    // parameter were added, a new call site could inherit the library default again, which is
    // the omission the pin exists to make impossible.
    expect(verify.length).toBe(3);
  });

  // Finding 6d's residual: `as const` is a compile-time claim only. An un-frozen exported
  // options object lets any module in the process flip the mode for every verifier at once —
  // no call site edited, no source file a reviewer would look at. These assertions are the
  // runtime half of the pin.
  it("cannot be mutated back to the cofactored mode at runtime", () => {
    expect(Object.isFrozen(ED25519_VERIFY_OPTIONS)).toBe(true);

    const mutable = ED25519_VERIFY_OPTIONS as unknown as { zip215: boolean };
    // ES modules are implicitly strict, so a write to a frozen property throws rather than
    // failing silently — the loud form is what makes a hostile dependency's attempt visible.
    expect(() => {
      mutable.zip215 = true;
    }).toThrow(TypeError);
    expect(() => {
      Object.defineProperty(mutable, "zip215", { value: true });
    }).toThrow(TypeError);
    expect(() => {
      delete (mutable as { zip215?: boolean }).zip215;
    }).toThrow(TypeError);
    // Adding an option noble might honour is refused too, not just overwriting the pinned one.
    expect(() => {
      (mutable as Record<string, unknown>).prehash = true;
    }).toThrow(TypeError);

    expect(ED25519_VERIFY_OPTIONS).toStrictEqual({ zip215: false });
  });

  it("still rejects every small-order vector after a mutation attempt", () => {
    try {
      (ED25519_VERIFY_OPTIONS as unknown as { zip215: boolean }).zip215 = true;
    } catch {
      // Expected — asserted above. What matters here is the behaviour afterwards.
    }
    for (const hex of smallOrderPublicKeysHex) {
      const signature = new Uint8Array(64);
      signature[0] = 1;
      expect(verify(signature, new TextEncoder().encode("after mutation"), hexToBytes(hex))).toBe(
        false
      );
    }
  });

  it("carries the group order and field modulus the vectors are built from", () => {
    expect(BigInt(fixture.groupOrderL)).toBe(2n ** 252n + 27742317777372353535851937790883648493n);
    expect(BigInt(fixture.fieldModulusP)).toBe(2n ** 255n - 19n);
  });
});

describe("spec 005 verification-mode vectors — the fixture tells the truth", () => {
  it("lists the complete 8-element torsion subgroup, distinct and sorted", () => {
    expect(smallOrderPublicKeysHex).toHaveLength(8);
    expect(new Set(smallOrderPublicKeysHex).size).toBe(8);
    expect(smallOrderPublicKeysHex).toStrictEqual([...smallOrderPublicKeysHex].sort());
    for (const hex of smallOrderPublicKeysHex) {
      expect(hex).toHaveLength(64);
    }
  });

  it("is not a suite that passes by rejecting everything", () => {
    expect(vectors.filter((vector) => vector.accept).length).toBeGreaterThan(0);
    expect(vectors.filter((vector) => !vector.accept).length).toBeGreaterThan(0);
  });

  it.each(vectors.map((vector) => [vector.name, vector] as const))("%s", (_name, vector) => {
    const signature = hexToBytes(vector.signatureHex);
    const publicKey = hexToBytes(vector.publicKeyHex);
    const message = new TextEncoder().encode(vector.message);

    // Shapes, recomputed rather than trusted.
    expect(signature).toHaveLength(64);
    expect(publicKey).toHaveLength(32);

    // The recorded verdict is what the reference implementation reaches.
    expect(verify(signature, message, publicKey)).toBe(vector.accept);

    // The KeyRef round-trips, and `decodeKeyRef` accepts it — including for every key the
    // mode rejects. This is the split the fixture records: the encoding layer checks length
    // and multicodec tag only, so rejection can never come from decoding.
    expect(vector.keyRefDecodes).toBe(true);
    expect(encodeKeyRef(publicKey)).toBe(vector.keyRef);
    expect(bytesToHex(decodeKeyRef(vector.keyRef))).toBe(vector.publicKeyHex);

    // And verification through the KeyRef path agrees with the raw-bytes path.
    expect(verify(signature, message, decodeKeyRef(vector.keyRef))).toBe(vector.accept);
  });

  // `publicKeyIsSmallOrder` is a property of the decoded POINT; `smallOrderPublicKeysHex` is a
  // list of canonical ENCODINGS. Membership implies small-order, but not conversely — the
  // non-canonical vector encodes the identity point as y + p, so it is small-order while its
  // bytes are in no canonical list. Asserting equivalence here failed, correctly.
  it("records small-order membership consistently with the derived subgroup", () => {
    for (const vector of vectors) {
      if (smallOrderPublicKeysHex.includes(vector.publicKeyHex)) {
        expect(vector.publicKeyIsSmallOrder).toBe(true);
      }
    }
    // Every canonically-encoded small-order key appears as a rejected vector.
    const rejectedCanonical = vectors
      .filter((vector) => !vector.accept && smallOrderPublicKeysHex.includes(vector.publicKeyHex))
      .map((vector) => vector.publicKeyHex);
    expect([...new Set(rejectedCanonical)].sort()).toStrictEqual(smallOrderPublicKeysHex);
    // And the accepted vector's key is not small-order in either sense.
    const honest = byName("accept — an honest signature by an honest key");
    expect(honest.publicKeyIsSmallOrder).toBe(false);
    expect(smallOrderPublicKeysHex).not.toContain(honest.publicKeyHex);
  });
});

describe("the R = identity, S = 0 construction", () => {
  const smallOrderVectors = vectors.filter((vector) =>
    vector.name.startsWith("reject — R = identity, S = 0 under small-order public key")
  );

  it("covers all 8 canonical small-order public keys", () => {
    expect(smallOrderVectors).toHaveLength(8);
    expect(smallOrderVectors.map((vector) => vector.publicKeyHex).sort()).toStrictEqual(
      smallOrderPublicKeysHex
    );
  });

  it("is one signature — the same 64 bytes — offered against every one of them", () => {
    const signatures = new Set(smallOrderVectors.map((vector) => vector.signatureHex));
    expect(signatures.size).toBe(1);
    const signature = hexToBytes([...signatures][0]!);
    // R is the canonical identity-point encoding and S is zero. No secret key is involved.
    expect(bytesToHex(signature.slice(0, 32))).toBe(
      "0100000000000000000000000000000000000000000000000000000000000000"
    );
    expect([...signature.slice(32)].every((byte) => byte === 0)).toBe(true);
  });

  // THE WATCHED-FAIL VECTORS. Each of these accepted under the cofactored default, so each one
  // flips if the pin is reverted at the call site in `keys.ts`.
  it("is rejected under the pin and was accepted by the cofactored default — all 8", () => {
    for (const vector of smallOrderVectors) {
      expect(vector.accept).toBe(false);
      expect(vector.acceptedByCofactoredDefault).toBe(true);
      expect(vector.publicKeyIsSmallOrder).toBe(true);
      expect(
        verify(
          hexToBytes(vector.signatureHex),
          new TextEncoder().encode(vector.message),
          hexToBytes(vector.publicKeyHex)
        )
      ).toBe(false);
    }
  });
});

describe("what the pin does and does not change", () => {
  it("does not reject the honest signature — the pin costs nothing legitimate", () => {
    const vector = byName("accept — an honest signature by an honest key");
    expect(vector.accept).toBe(true);
    // Accepted in BOTH modes, so this vector deliberately does not catch the mutation.
    expect(vector.acceptedByCofactoredDefault).toBe(true);
    expect(vector.publicKeyIsSmallOrder).toBe(false);
  });

  it("rejects non-canonical S in both modes, so that vector is normative, not a mode test", () => {
    const vector = byName("reject — non-canonical S (an honest signature with S += L)");
    expect(vector.accept).toBe(false);
    // The honest claim: `@noble/curves` range-checks S regardless of the flag, so reverting the
    // pin does NOT make this vector pass. It is committed because 005 requires the rejection
    // normatively and another implementation's default may reduce S mod L instead.
    expect(vector.acceptedByCofactoredDefault).toBe(false);

    // The scalar really is congruent to the honest one mod L — i.e. this is the malleability
    // case and not simply corrupt bytes.
    const honest = byName("accept — an honest signature by an honest key");
    const L = BigInt(fixture.groupOrderL);
    const toNumberLE = (bytes: Uint8Array): bigint =>
      bytes.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
    const honestS = toNumberLE(hexToBytes(honest.signatureHex).slice(32));
    const shiftedS = toNumberLE(hexToBytes(vector.signatureHex).slice(32));
    expect(shiftedS).toBe(honestS + L);
    expect(shiftedS % L).toBe(honestS % L);
    // Same R, same key: only S moved.
    expect(vector.signatureHex.slice(0, 64)).toBe(honest.signatureHex.slice(0, 64));
    expect(vector.publicKeyHex).toBe(honest.publicKeyHex);
  });

  it("rejects a non-canonical point encoding the cofactored default accepted", () => {
    const vector = byName("reject — non-canonical public-key encoding (identity point as y + p)");
    expect(vector.accept).toBe(false);
    expect(vector.acceptedByCofactoredDefault).toBe(true);
    // The bytes decode as y = 1 + p, i.e. the identity point in a form outside [0, p).
    const P = BigInt(fixture.fieldModulusP);
    const y = hexToBytes(vector.publicKeyHex).reduceRight(
      (acc, byte) => (acc << 8n) | BigInt(byte),
      0n
    );
    expect(y).toBe(1n + P);
    expect(y).toBeGreaterThan(P);
    // It is NOT the canonical encoding of any key, so it is not in the derived subgroup list.
    expect(smallOrderPublicKeysHex).not.toContain(vector.publicKeyHex);
  });
});

describe("the record-layer consequence — why 003 and 015 name this pin a prerequisite", () => {
  it("refuses a 3-of-3 quorum offered one keyless signature", () => {
    const { state, record, matrix } = quorumVector;

    // The state lists three DISTINCT small-order keys, all structurally valid KeyRefs.
    expect(state.keys).toHaveLength(3);
    expect(new Set(state.keys).size).toBe(3);
    expect(state.threshold).toBe("3");
    for (const keyRef of state.keys) {
      expect(smallOrderPublicKeysHex).toContain(bytesToHex(decodeKeyRef(keyRef)));
    }

    // The record carries exactly one signature, and it is the R = identity, S = 0 value.
    expect(record.signature).toHaveLength(1);
    const signature = decodeSignature(record.signature[0]!);
    expect(bytesToHex(signature.slice(0, 32))).toBe(
      "0100000000000000000000000000000000000000000000000000000000000000"
    );
    expect([...signature.slice(32)].every((byte) => byte === 0)).toBe(true);

    // The recorded signing input is the spec-001 UTF-8 JCS of the record without `signature`.
    const unsigned: Record<string, unknown> = { ...record };
    delete unsigned.signature;
    const input = canonicalBytes(unsigned);
    expect(new TextDecoder().decode(input)).toBe(quorumVector.signingInput);

    // Every matrix entry is false under the pin, recomputed from the bytes.
    expect(matrix).toHaveLength(3);
    for (const [index, keyRef] of state.keys.entries()) {
      expect(verify(signature, input, decodeKeyRef(keyRef))).toBe(matrix[index]);
      expect(matrix[index]).toBe(false);
    }

    // THE WATCHED-FAIL ASSERTION. Under the cofactored default all three entries are true,
    // `verifyThresholdRecord` finds three distinct satisfied keys, and this returns true —
    // a 3-of-3 threshold met with no secret key in existence. Under the pin it is false.
    expect(verifyThresholdRecord(record, state.keys, state.threshold)).toBe(false);
    expect(quorumVector.valid).toBe(false);

    // The record is schema-valid, so the rejection is the verification mode's doing and not a
    // shape the protocol could never carry.
    expect(revocationSchema.safeParse(record).success).toBe(true);
  });
});
