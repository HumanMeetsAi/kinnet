/**
 * Multibase / multicodec / multihash encodings — spec 005.
 *
 * Keys and digests are multicodec-tagged and multibase(base58btc)-encoded; signatures
 * are multibase-encoded raw bytes (the suite is named by the verifying KeyRef).
 */
import { base58 } from "@scure/base";

const MULTIBASE_BASE58BTC = "z";
// varint(0xed) — the multicodec code for ed25519-pub
const ED25519_PUB_PREFIX = Uint8Array.of(0xed, 0x01);
// sha2-256 multihash: code 0x12, length 0x20
const SHA2_256_PREFIX = Uint8Array.of(0x12, 0x20);

export function toMultibase(bytes: Uint8Array): string {
  return `${MULTIBASE_BASE58BTC}${base58.encode(bytes)}`;
}

export function fromMultibase(text: string): Uint8Array {
  if (!text.startsWith(MULTIBASE_BASE58BTC)) {
    throw new Error(
      `Expected a base58btc multibase string (prefix "z"), got "${text.slice(0, 8)}…"`
    );
  }
  return base58.decode(text.slice(1));
}

function concatBytes(prefix: Uint8Array, bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(prefix.length + bytes.length);
  out.set(prefix, 0);
  out.set(bytes, prefix.length);
  return out;
}

/** KeyRef = multibase(multicodec(ed25519-pub) ‖ publicKeyBytes) */
export function encodeKeyRef(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`An Ed25519 public key is 32 bytes, got ${publicKey.length}`);
  }
  return toMultibase(concatBytes(ED25519_PUB_PREFIX, publicKey));
}

export function decodeKeyRef(keyRef: string): Uint8Array {
  const bytes = fromMultibase(keyRef);
  if (
    bytes.length !== 34 ||
    bytes[0] !== ED25519_PUB_PREFIX[0] ||
    bytes[1] !== ED25519_PUB_PREFIX[1]
  ) {
    throw new Error("Unsupported KeyRef: expected a multicodec-tagged ed25519-pub key");
  }
  return bytes.slice(2);
}

export function encodeSignature(signature: Uint8Array): string {
  return toMultibase(signature);
}

export function decodeSignature(signature: string): Uint8Array {
  return fromMultibase(signature);
}

/** Multihash (sha2-256) of a 32-byte digest, multibase-encoded. */
export function encodeSha256Multihash(digest: Uint8Array): string {
  if (digest.length !== 32) {
    throw new Error(`A sha2-256 digest is 32 bytes, got ${digest.length}`);
  }
  return toMultibase(concatBytes(SHA2_256_PREFIX, digest));
}
