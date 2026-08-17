/**
 * Canonical encodings (spec 005 _Canonical encodings_, spec 015 S7) — the shared validator every
 * encoded field in this package now goes through.
 *
 * The property under test is not "the decoder works" but "one value, one text": decode,
 * re-encode, exact textual equality, and the decoded length the field demands.
 */
import { describe, expect, it } from "vitest";

import {
  base64UrlNoPad,
  decodeBase64Url,
  decodeCanonical,
  encodeBase64Url,
  GROUP_NONCE_BYTES,
  isCanonical,
  multibaseBase58btc
} from "../src/index.js";

/** A 32-byte value's canonical multibase(base58btc) form; the fixture nonce from spec 014. */
const GROUP_NONCE = "zCs8KY3PiWrCMAytMsBRQo8EdGbticVtdvufLnb2UhXh";

describe("multibase(base58btc)", () => {
  it("round-trips every byte string it decodes", () => {
    for (const bytes of [
      Uint8Array.of(0),
      Uint8Array.of(0, 0, 0, 1),
      Uint8Array.of(255, 255, 255),
      Uint8Array.from({ length: 32 }, (_unused, index) => (index * 37) % 256)
    ]) {
      const text = multibaseBase58btc.encode(bytes);
      expect(multibaseBase58btc.decode(text)).toEqual(bytes);
      expect(isCanonical(text, multibaseBase58btc, { minBytes: 0 })).toBe(true);
    }
  });

  it("refuses anything that is not a base58btc multibase string", () => {
    expect(multibaseBase58btc.decode("f6Mkha")).toBeNull(); // wrong multibase prefix
    // A bare prefix decodes to zero bytes, which is not a value any field here carries — and
    // `keyRefSchema` has always refused it, so the codec agrees with the schema rather than
    // leaving "z" to be caught one layer up.
    expect(multibaseBase58btc.decode("z")).toBeNull();
    expect(multibaseBase58btc.decode("")).toBeNull();
    expect(multibaseBase58btc.decode("z0OIl")).toBeNull(); // 0, O, I, l are outside the alphabet
  });

  it("separates the length requirement from the encoding (finding 6b)", () => {
    // The review's exact case: alphabet-valid, inside the 32..44 character window a 32-byte
    // value falls in, and 23 bytes. Canonical — just not a nonce.
    const twentyThreeBytes = `z${"2".repeat(32)}`;
    expect(isCanonical(twentyThreeBytes, multibaseBase58btc, { minBytes: 1 })).toBe(true);
    expect(decodeCanonical(twentyThreeBytes, multibaseBase58btc)!.length).toBe(23);
    expect(isCanonical(twentyThreeBytes, multibaseBase58btc, { bytes: GROUP_NONCE_BYTES })).toBe(
      false
    );
    expect(decodeCanonical(GROUP_NONCE, multibaseBase58btc, { bytes: 32 })).toHaveLength(32);
  });
});

describe("unpadded base64url", () => {
  it("round-trips every byte string it decodes", () => {
    for (let length = 0; length <= 8; length += 1) {
      const bytes = Uint8Array.from({ length }, (_unused, index) => (index * 61 + 7) % 256);
      const text = encodeBase64Url(bytes);
      expect(decodeBase64Url(text)).toEqual(bytes);
      expect(isCanonical(text, base64UrlNoPad, { minBytes: 0 })).toBe(true);
    }
  });

  it("refuses the three non-canonical forms, and refuses them identically to @kinnet/sdk", () => {
    // "A" ends no quantum; "AB" carries bits past its one byte, which a permissive decoder
    // folds onto the byte "AA" gives; "=" padding is outside the house alphabet.
    for (const text of ["A", "AB", "AA==", "AA=", "A+A", "A/A"]) {
      expect(base64UrlNoPad.decode(text)).toBeNull();
      expect(isCanonical(text, base64UrlNoPad)).toBe(false);
      expect(() => decodeBase64Url(text)).toThrow();
    }
    expect(() => decodeBase64Url("A")).toThrow(/truncated final quantum/);
    expect(() => decodeBase64Url("A+A")).toThrow(/outside the alphabet/);
    expect(() => decodeBase64Url("AB")).toThrow(/non-zero trailing bits/);
  });

  it("holds an empty string to the default minimum of one byte", () => {
    // Decodable, and not a value: a field carrying zero bytes of payload is malformed, not
    // empty. `minBytes: 0` is available for the callers that mean it.
    expect(base64UrlNoPad.decode("")).toEqual(new Uint8Array(0));
    expect(isCanonical("", base64UrlNoPad)).toBe(false);
    expect(isCanonical("", base64UrlNoPad, { minBytes: 0 })).toBe(true);
  });
});

describe("decodeCanonical", () => {
  it("returns the bytes only when text, length and re-encoding all agree", () => {
    expect(decodeCanonical("AA", base64UrlNoPad, { bytes: 1 })).toEqual(Uint8Array.of(0));
    expect(decodeCanonical("AA", base64UrlNoPad, { bytes: 2 })).toBeNull();
    expect(decodeCanonical("AB", base64UrlNoPad, { bytes: 1 })).toBeNull();
    expect(decodeCanonical("!!", base64UrlNoPad)).toBeNull();
  });
});
