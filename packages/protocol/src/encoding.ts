/**
 * Canonical byte encodings — one decoder, one canonicity test, for every encoded string this
 * package validates (spec 005 _Canonical encodings_, spec 015 S7).
 *
 * A schema that checks only an alphabet and a textual length is not checking an encoding, it is
 * checking a character set. `z` + 32 `"2"`s matches the base58btc alphabet and the length window
 * a 32-byte value falls in, and decodes to **23** bytes; `"AB"` matches unpadded base64url and
 * carries four bits beyond its single byte, which a permissive decoder folds onto the same byte
 * `"AA"` gives. Both are second textual forms for a value that already has one, and every field
 * they appear in rides a signed, digest-identified record — so a second form is a second record.
 *
 * The test applied here is the same one in every case, and it is deliberately not "the decoder
 * did not throw": **decode, re-encode, require the re-encoding to equal the input exactly, and
 * require the decoded length the field demands.** Re-encoding is what makes the check total — it
 * needs no per-encoding catalogue of the ways a form can be non-canonical, so an encoding whose
 * quirks we have not enumerated is still held to exactly one form per value.
 *
 * This module is hand-rolled because `@kinnet/protocol` has no dependency but `zod` and takes
 * none to get a decoder: the substrate every implementation validates against cannot be the
 * package that drags in a codec. It is also the single source for the house base64url codec, so
 * that no two components of an implementation can disagree about which textual forms are valid —
 * a disagreement an external security review (2026-08) found in practice.
 */

/**
 * A byte encoding, as the canonicity test needs it: a total decoder that reports failure by
 * returning `null` rather than throwing, and its inverse.
 *
 * `decode` MUST reject anything outside the encoding's alphabet/framing; `encode` MUST produce
 * the encoding's canonical form. Canonicity is then decided by composing them, never by a
 * hand-written list of the deviations a decoder happens to know about.
 */
export type ByteEncoding = {
  readonly name: string;
  decode(text: string): Uint8Array | null;
  encode(bytes: Uint8Array): string;
};

const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function reverseTable(alphabet: string): Int8Array {
  const table = new Int8Array(128).fill(-1);
  for (let index = 0; index < alphabet.length; index += 1) {
    table[alphabet.charCodeAt(index)] = index;
  }
  return table;
}

const BASE58BTC_REVERSE = reverseTable(BASE58BTC_ALPHABET);
const BASE64URL_REVERSE = reverseTable(BASE64URL_ALPHABET);

/** The multibase prefix for base58btc (spec 005). */
const MULTIBASE_BASE58BTC_PREFIX = "z";

function decodeBase58(text: string): Uint8Array | null {
  // Big-endian base conversion. O(n^2) in the input length, which is why every caller filters on
  // a bounded length first: the fields this decodes are 32-byte nonces and 34-byte key refs.
  const bytes: number[] = [];
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    const value = code < 128 ? BASE58BTC_REVERSE[code]! : -1;
    if (value < 0) {
      return null;
    }
    let carry = value;
    for (let position = 0; position < bytes.length; position += 1) {
      carry += bytes[position]! * 58;
      bytes[position] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let leadingZeros = 0;
  while (leadingZeros < text.length && text[leadingZeros] === "1") {
    leadingZeros += 1;
  }
  const out = new Uint8Array(leadingZeros + bytes.length);
  for (let index = 0; index < bytes.length; index += 1) {
    out[leadingZeros + index] = bytes[bytes.length - 1 - index]!;
  }
  return out;
}

function encodeBase58(bytes: Uint8Array): string {
  const digits: number[] = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let position = 0; position < digits.length; position += 1) {
      carry += digits[position]! << 8;
      digits[position] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }
    out += "1";
  }
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    out += BASE58BTC_ALPHABET[digits[index]!];
  }
  return out;
}

/**
 * Multibase base58btc (spec 005): the `z` prefix followed by the base58btc body.
 *
 * The prefix is part of the encoded form, so it is part of what round-trips: a body that decodes
 * fine under a different multibase prefix is not this encoding.
 */
export const multibaseBase58btc: ByteEncoding = {
  name: "multibase(base58btc)",
  decode(text: string): Uint8Array | null {
    if (!text.startsWith(MULTIBASE_BASE58BTC_PREFIX) || text.length < 2) {
      return null;
    }
    return decodeBase58(text.slice(1));
  },
  encode(bytes: Uint8Array): string {
    return `${MULTIBASE_BASE58BTC_PREFIX}${encodeBase58(bytes)}`;
  }
};

/**
 * Unpadded base64url — the house encoding (spec 011's `1:` grants profile, and the
 * `pn/mls` / `pn/welcome` payload encoding pinned by spec 014).
 *
 * Padded input is not this encoding (`=` is outside the alphabet), a length ≡ 1 (mod 4) ends no
 * base64 quantum, and a final character carrying bits beyond the last whole byte re-encodes to a
 * different string — so all three fail the round-trip.
 */
export const base64UrlNoPad: ByteEncoding = {
  name: "base64url (unpadded)",
  decode(text: string): Uint8Array | null {
    if (text.length % 4 === 1) {
      return null;
    }
    const out = new Uint8Array(Math.floor((text.length * 3) / 4));
    let accumulator = 0;
    let bits = 0;
    let offset = 0;
    for (let index = 0; index < text.length; index += 1) {
      const code = text.charCodeAt(index);
      const value = code < 128 ? BASE64URL_REVERSE[code]! : -1;
      if (value < 0) {
        return null;
      }
      accumulator = (accumulator << 6) | value;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[offset] = (accumulator >> bits) & 0xff;
        offset += 1;
      }
    }
    // Leftover bits belong to no byte. Decoding them away is what folds "AB" onto "AA"; the
    // round-trip below would catch it anyway, and refusing here keeps the decoder itself total.
    if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) {
      return null;
    }
    return out;
  },
  encode(bytes: Uint8Array): string {
    let out = "";
    for (let index = 0; index < bytes.length; index += 3) {
      const b0 = bytes[index]!;
      const b1 = bytes[index + 1];
      const b2 = bytes[index + 2];
      out += BASE64URL_ALPHABET[b0 >> 2];
      out += BASE64URL_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
      if (b1 === undefined) {
        break;
      }
      out += BASE64URL_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
      if (b2 === undefined) {
        break;
      }
      out += BASE64URL_ALPHABET[b2 & 0x3f];
    }
    return out;
  }
};

/** What a field demands of the value behind its encoded form. */
export type ByteLengthRequirement = {
  /** Exact decoded length in bytes. */
  bytes?: number;
  /** Minimum decoded length in bytes; defaults to 1 — a field is never zero bytes of value. */
  minBytes?: number;
};

/**
 * THE shared validator (spec 015 S7). Decodes `text` under `encoding` and returns the bytes only
 * if the text is the encoding's one canonical form for them AND their length satisfies
 * `requirement`; otherwise `null`.
 *
 * Both halves are load-bearing and neither implies the other. Round-tripping alone accepts
 * `z` + 32 `"2"`s, which is the canonical encoding of a 23-byte value — just not of a nonce.
 * Length alone accepts `"AB"`, which is one byte, encoded non-canonically.
 */
export function decodeCanonical(
  text: string,
  encoding: ByteEncoding,
  requirement: ByteLengthRequirement = {}
): Uint8Array | null {
  const bytes = encoding.decode(text);
  if (bytes === null) {
    return null;
  }
  if (requirement.bytes !== undefined) {
    if (bytes.length !== requirement.bytes) {
      return null;
    }
  } else if (bytes.length < (requirement.minBytes ?? 1)) {
    return null;
  }
  if (encoding.encode(bytes) !== text) {
    return null;
  }
  return bytes;
}

/** {@link decodeCanonical} as a predicate, for schema refinements. */
export function isCanonical(
  text: string,
  encoding: ByteEncoding,
  requirement: ByteLengthRequirement = {}
): boolean {
  return decodeCanonical(text, encoding, requirement) !== null;
}

/** Encodes bytes as unpadded base64url. */
export function encodeBase64Url(bytes: Uint8Array): string {
  return base64UrlNoPad.encode(bytes);
}

/**
 * Decodes unpadded base64url, throwing on any deviation from the single canonical form.
 *
 * The diagnosis is re-derived on the failure path rather than threaded through the decoder: the
 * decoder stays total (it is what {@link decodeCanonical} composes), and naming which of the
 * three deviations occurred costs nothing on the path that succeeds.
 *
 * @throws TypeError on a character outside the alphabet, a length ≡ 1 (mod 4) — which no byte
 *   string encodes to — or a final character carrying non-zero bits beyond the last byte.
 */
export function decodeBase64Url(text: string): Uint8Array {
  const bytes = base64UrlNoPad.decode(text);
  if (bytes !== null) {
    return bytes;
  }
  if (text.length % 4 === 1) {
    throw new TypeError("Not an unpadded base64url string: truncated final quantum");
  }
  for (const character of text) {
    const code = character.charCodeAt(0);
    if (character.length > 1 || code > 127 || BASE64URL_REVERSE[code] === -1) {
      throw new TypeError(
        `Not an unpadded base64url string: "${character}" is outside the alphabet`
      );
    }
  }
  throw new TypeError("Not an unpadded base64url string: non-zero trailing bits");
}
