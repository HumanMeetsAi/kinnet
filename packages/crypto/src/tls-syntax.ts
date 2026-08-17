/**
 * TLS presentation-syntax primitives for the MLS profile — spec 014.
 *
 * RFC 9420 encodes a variable-size vector (`x<V>`) as a length header followed by the
 * vector's bytes. The header is the QUIC variable-length integer encoding (RFC 9000 §16)
 * with one restriction, RFC 9420 §2.1.2:
 *
 * > Vectors that start with the prefix "11" are invalid and MUST be rejected.
 *
 * so only the 1-, 2-, and 4-byte forms exist and the maximum vector length is 2^30 - 1.
 * The same section requires the minimum-length form:
 *
 * > The encoded value MUST use the smallest number of bits required to represent the
 * > value. When decoding, values using more bits than necessary MUST be treated as
 * > malformed.
 *
 * Both rules are enforced here, and neither is normalized away: a non-minimal header is
 * a second byte-form for one logical value, and in this spec a second byte-form means a
 * second signed commit for the same content.
 */

/** RFC 9420 §2.1.2: the 8-byte form is invalid, so a vector holds at most 2^30 - 1 bytes. */
export const MAX_VECTOR_LENGTH = (1 << 30) - 1;

function normalizeLength(value: number | bigint): number {
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new RangeError(`A varint value must be non-negative, got ${value}`);
    }
    if (value > BigInt(MAX_VECTOR_LENGTH)) {
      throw new RangeError(
        `A varint value must be at most 2^30 - 1 (RFC 9420 §2.1.2 rejects the 8-byte form), got ${value}`
      );
    }
    return Number(value);
  }
  if (!Number.isSafeInteger(value)) {
    throw new TypeError(`A varint value must be a safe integer, got ${value}`);
  }
  if (value < 0) {
    throw new RangeError(`A varint value must be non-negative, got ${value}`);
  }
  if (value > MAX_VECTOR_LENGTH) {
    throw new RangeError(
      `A varint value must be at most 2^30 - 1 (RFC 9420 §2.1.2 rejects the 8-byte form), got ${value}`
    );
  }
  return value;
}

function writeFixed(value: number, length: number, prefix: number): Uint8Array {
  const out = new Uint8Array(length);
  let rest = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    out[index] = rest % 256;
    rest = Math.floor(rest / 256);
  }
  out[0] = (out[0] ?? 0) | prefix;
  return out;
}

/**
 * Encodes a variable-length integer in the minimal QUIC form (RFC 9000 §16) permitted by
 * RFC 9420 §2.1.2 — always the shortest of the 1-, 2-, and 4-byte forms.
 */
export function encodeVarint(value: number | bigint): Uint8Array {
  const length = normalizeLength(value);
  if (length < 1 << 6) {
    return Uint8Array.of(length);
  }
  if (length < 1 << 14) {
    return writeFixed(length, 2, 0x40);
  }
  return writeFixed(length, 4, 0x80);
}

/**
 * Decodes a variable-length integer. Throws on a truncated header, on the `11` prefix
 * (the 8-byte form RFC 9420 forbids), and on a non-minimal encoding.
 */
export function decodeVarint(bytes: Uint8Array, offset = 0): { value: number; bytesRead: number } {
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new RangeError(`offset must be a non-negative integer, got ${offset}`);
  }
  const first = bytes[offset];
  if (first === undefined) {
    throw new Error(`Truncated varint: no length header at offset ${offset}`);
  }
  const prefix = first >> 6;
  if (prefix === 3) {
    throw new Error(
      'Invalid varint: a length header with prefix "11" (the 8-byte form) is rejected by RFC 9420 §2.1.2'
    );
  }
  const length = 1 << prefix;
  if (offset + length > bytes.length) {
    throw new Error(
      `Truncated varint: a ${length}-byte header at offset ${offset} runs past the end of ${bytes.length} bytes`
    );
  }
  let value = first & 0x3f;
  for (let index = 1; index < length; index += 1) {
    value = value * 256 + (bytes[offset + index] ?? 0);
  }
  // RFC 9420 §2.1.2: `if prefix >= 1 && v < (1 << (8*(length/2) - 2))` is malformed.
  if (prefix >= 1 && value < 1 << (8 * (length / 2) - 2)) {
    throw new Error(
      `Non-minimal varint: ${value} is encoded in ${length} bytes but fits in a shorter form`
    );
  }
  return { value, bytesRead: length };
}

export function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Encodes `opaque x<V>`: a minimal varint length header followed by the bytes. */
export function encodeOpaque(bytes: Uint8Array): Uint8Array {
  return concatBytes([encodeVarint(bytes.length), bytes]);
}

/**
 * Decodes `opaque x<V>` at `offset`. `bytesRead` covers the header and the body, so a
 * caller can walk a vector of vectors by accumulating it.
 */
export function decodeOpaque(
  bytes: Uint8Array,
  offset = 0
): { value: Uint8Array; bytesRead: number } {
  const header = decodeVarint(bytes, offset);
  const start = offset + header.bytesRead;
  const end = start + header.value;
  if (end > bytes.length) {
    throw new Error(
      `Truncated opaque vector: the header declares ${header.value} bytes but only ${
        bytes.length - start
      } remain`
    );
  }
  return { value: bytes.slice(start, end), bytesRead: header.bytesRead + header.value };
}

/** Lexicographic byte order — for UTF-8 this is codepoint order. */
export function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) {
      return difference;
    }
  }
  return left.length - right.length;
}
