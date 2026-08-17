/**
 * The kinnet MLS profile's binary encodings — spec 014.
 *
 * Three byte-level pins, quoted from the profile table and §"Binding evidence to the
 * commit"; MLS itself is adopted, not implemented here.
 *
 *  - `group_id` is "the **raw multihash bytes** of the conversation's digest id (012) —
 *    not its multibase string". The two have different lengths and would name different
 *    groups, hence the round-trip pair below.
 *  - `struct { opaque chain<V>; } PNCredential;` where "`chain` is the UTF-8 of 011's
 *    `1:`-prefixed chain encoding" — credential type `0xF001`.
 *  - `struct { opaque digest<V>; } Evidence; struct { Evidence evidence<V>; }
 *    PNCommitBinding;` — the Commit's `authenticated_data`, holding "the multihash
 *    digests of the `ConversationUpdate` records authorizing this commit, sorted by
 *    codepoint".
 *
 * The binding "MUST be minimal and exact, or the field is a covert channel in cleartext
 * on every commit", so this codec fails closed on everything that would give one logical
 * binding two byte-forms: trailing bytes, non-minimal length headers, unsorted entries,
 * duplicates, and entries that are not well-formed sha2-256 multihashes. Whether each
 * named digest actually covers a proposal in the commit is a validity rule above this
 * codec.
 */
import type { Grant } from "@kinnet/protocol";

import { fromMultibase, toMultibase } from "./encoding.js";
import { decodeGrantsHeader, encodeGrantsHeader } from "./grants-header.js";
import {
  compareBytes,
  concatBytes,
  decodeOpaque,
  encodeOpaque,
  encodeVarint
} from "./tls-syntax.js";

/** The private-use MLS `CredentialType` this profile pins (spec 014 profile table). */
export const KINNET_CREDENTIAL_TYPE = 0xf001;

// sha2-256 multihash: code 0x12, length 0x20, then the 32 digest bytes.
const MULTIHASH_SHA2_256_CODE = 0x12;
const MULTIHASH_SHA2_256_LENGTH = 0x20;
const MULTIHASH_BYTE_LENGTH = 34;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function isSha256Multihash(bytes: Uint8Array): boolean {
  return (
    bytes.length === MULTIHASH_BYTE_LENGTH &&
    bytes[0] === MULTIHASH_SHA2_256_CODE &&
    bytes[1] === MULTIHASH_SHA2_256_LENGTH
  );
}

/** Decodes a multibase digest id into its raw sha2-256 multihash bytes, or throws. */
function decodeSha256Multihash(digest: string, what: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = fromMultibase(digest);
  } catch {
    throw new Error(`${what} is not a base58btc multibase string: "${digest}"`);
  }
  if (!isSha256Multihash(bytes)) {
    throw new Error(`${what} is not a well-formed sha2-256 multihash: "${digest}"`);
  }
  return bytes;
}

function decodeUtf8(bytes: Uint8Array, what: string): string {
  try {
    return textDecoder.decode(bytes);
  } catch {
    throw new Error(`${what} is not valid UTF-8`);
  }
}

/**
 * Encodes `PNCredential` — the leaf-first grant chain (009/011) that binds an MLS
 * leaf to its participant, as the UTF-8 of the `1:` chain encoding inside an
 * `opaque chain<V>`.
 *
 * This is a codec: it does not evaluate 014's credential rules (the `e2ee`-only
 * abilities, empty caveats, the leaf audience being the leaf's signature key). Those are
 * chain-validity rules, checked where the chain is verified.
 */
export function encodePNCredential(chain: Grant[]): Uint8Array {
  return encodeOpaque(textEncoder.encode(encodeGrantsHeader(chain)));
}

/**
 * Decodes `PNCredential`. Fails closed on trailing bytes, a malformed length header,
 * non-UTF-8 bytes, an unknown chain prefix, and any element that is not a shape-valid
 * Grant.
 */
export function decodePNCredential(bytes: Uint8Array): Grant[] {
  const { value, bytesRead } = decodeOpaque(bytes, 0);
  if (bytesRead !== bytes.length) {
    throw new Error(`PNCredential has ${bytes.length - bytesRead} trailing byte(s)`);
  }
  return decodeGrantsHeader(decodeUtf8(value, "The PNCredential chain"));
}

/**
 * Encodes `PNCommitBinding` for a Commit's `authenticated_data`. The entries are
 * sorted by codepoint here rather than trusted from the caller, so two implementations
 * handed the same set produce the same bytes; duplicates are rejected rather than
 * collapsed, since a caller passing one twice is naming coverage it does not have.
 * The empty list is valid — it is what an update-path commit and the founding commit
 * carry.
 */
export function encodeCommitBinding(digests: string[]): Uint8Array {
  const entries = digests.map((digest) => {
    decodeSha256Multihash(digest, "A PNCommitBinding entry");
    return textEncoder.encode(digest);
  });
  entries.sort(compareBytes);
  let previous: Uint8Array | undefined;
  for (const entry of entries) {
    if (previous !== undefined && compareBytes(previous, entry) === 0) {
      throw new Error(`PNCommitBinding contains a duplicate entry: "${textDecoder.decode(entry)}"`);
    }
    previous = entry;
  }
  const body = concatBytes(entries.map((entry) => encodeOpaque(entry)));
  return concatBytes([encodeVarint(body.length), body]);
}

/**
 * Decodes `PNCommitBinding`, returning the digests in their encoded (sorted) order.
 * Fails closed on trailing bytes, a truncated or non-minimal length header, an entry
 * that is not a well-formed sha2-256 multihash, and — because the binding must have one
 * byte-form — entries that are out of order or duplicated.
 */
export function decodeCommitBinding(bytes: Uint8Array): string[] {
  const { value: body, bytesRead } = decodeOpaque(bytes, 0);
  if (bytesRead !== bytes.length) {
    throw new Error(`PNCommitBinding has ${bytes.length - bytesRead} trailing byte(s)`);
  }
  const digests: string[] = [];
  let previous: Uint8Array | undefined;
  let offset = 0;
  while (offset < body.length) {
    const entry = decodeOpaque(body, offset);
    offset += entry.bytesRead;
    if (previous !== undefined) {
      const order = compareBytes(previous, entry.value);
      if (order === 0) {
        throw new Error("PNCommitBinding contains a duplicate entry");
      }
      if (order > 0) {
        throw new Error("PNCommitBinding entries are not sorted by codepoint");
      }
    }
    const digest = decodeUtf8(entry.value, "A PNCommitBinding entry");
    decodeSha256Multihash(digest, "A PNCommitBinding entry");
    digests.push(digest);
    previous = entry.value;
  }
  return digests;
}

/**
 * Pads application content to a multiple of 256 bytes (spec 014 profile table) with a
 * self-describing frame: `struct { opaque content<V>; }` followed by zero bytes up to the
 * next 256-byte boundary. The frame mirrors MLS's own `PrivateMessageContent` padding
 * (zeros, stripped on decode, rejected when non-zero) and reuses this package's TLS codec,
 * so two implementations produce identical bytes for identical content.
 *
 * This is caller-side padding, deliberately: the adopted runtime's padding option is a
 * floor ("pad until length N"), not a multiple, so the profile's quantization is applied
 * here before the plaintext is handed to MLS. The minimum
 * output is one 256-byte block — empty content is a valid frame.
 */
export function padApplicationContent(content: Uint8Array): Uint8Array {
  const framed = encodeOpaque(content);
  const padded = new Uint8Array(Math.ceil(framed.length / 256) * 256);
  padded.set(framed);
  return padded;
}

/**
 * The inverse of {@link padApplicationContent}. Fails closed on everything that would give
 * one logical content two byte-forms: a length that is not a positive multiple of 256, a
 * truncated or non-minimal frame, and any non-zero padding byte.
 */
export function unpadApplicationContent(padded: Uint8Array): Uint8Array {
  if (padded.length === 0 || padded.length % 256 !== 0) {
    throw new Error(
      `Padded application content must be a positive multiple of 256 bytes, got ${padded.length}`
    );
  }
  const { value, bytesRead } = decodeOpaque(padded, 0);
  for (let i = bytesRead; i < padded.length; i += 1) {
    if (padded[i] !== 0) {
      throw new Error("Padded application content carries non-zero padding");
    }
  }
  if (Math.ceil(bytesRead / 256) * 256 !== padded.length) {
    throw new Error("Padded application content carries more padding than the frame needs");
  }
  return value;
}

/**
 * The MLS `group_id` for a conversation: the raw multihash bytes of the conversation's
 * digest id (012), not its multibase string.
 */
export function groupIdFromConversationId(conversationId: string): Uint8Array {
  return decodeSha256Multihash(conversationId, "A conversationId");
}

/** The inverse of {@link groupIdFromConversationId}. */
export function conversationIdFromGroupId(groupId: Uint8Array): string {
  if (!isSha256Multihash(groupId)) {
    throw new Error(
      `A group_id must be the ${MULTIHASH_BYTE_LENGTH} raw bytes of a sha2-256 multihash, got ${groupId.length} byte(s)`
    );
  }
  return toMultibase(groupId);
}
