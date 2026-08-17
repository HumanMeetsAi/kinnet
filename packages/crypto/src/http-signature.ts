/**
 * HTTP Message Signatures (RFC 9421) — the spec 004 write-auth profile.
 *
 * The profile is strict: one signature labeled "sig1", covered components exactly
 * `@method`, `@target-uri`, and `content-digest` (RFC 9530) — plus `pn-grants` when
 * the request carries a spec-011 grant chain — with `created`, `keyid` (the participant
 * ID or, per spec 011, a bare KeyRef), and `nonce` signature parameters. This
 * authenticates the write action; the record's own signature (spec 001/005)
 * authenticates content. When a PN-Grants header is present it MUST be covered:
 * this layer guarantees the presented chain bytes are what the signer signed; chain
 * semantics are verified elsewhere (spec 009/011).
 */
import type { Grant, KeyRef } from "@kinnet/protocol";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import { decodeKeyRef, toMultibase } from "./encoding.js";
import {
  DEFAULT_MAX_SIGNATURE_VERIFICATIONS,
  safeVerificationCount,
  VerificationBudgetExceeded
} from "./budget.js";
import { encodeGrantsHeader } from "./grants-header.js";
import { sign, verify } from "./keys.js";
import { assertWholeSeconds } from "./nonce-guard.js";
import { parseThreshold } from "./signature-set.js";

const SIGNATURE_LABEL = "sig1";
const COVERED_COMPONENTS = ["@method", "@target-uri", "content-digest"] as const;
const GRANTS_COMPONENT = "pn-grants";

const SIGNATURE_INPUT_PATTERN = new RegExp(
  `^${SIGNATURE_LABEL}=(\\("@method" "@target-uri" "content-digest"( "${GRANTS_COMPONENT}")?\\);created=(0|[1-9][0-9]*);keyid="([^"]+)";nonce="([^"]+)")$`
);
const SIGNATURE_PATTERN = new RegExp(`^${SIGNATURE_LABEL}=:([A-Za-z0-9+/]+={0,2}):$`);

const textEncoder = new TextEncoder();

/**
 * RFC 9530 Content-Digest header value for a request body.
 *
 * The digest is over the **content octets** — the bytes on the wire — and nothing else.
 * A `Uint8Array` is hashed exactly as given; a `string` is hashed as its UTF-8 encoding,
 * which is a SENDER-SIDE CONVENIENCE and nothing more: it is correct only for a caller
 * that goes on to transmit that same UTF-8 encoding, which is what `fetch` and every
 * sender in this repository do.
 *
 * A verifier must never reach the string form by decoding what it received. Decoding is
 * lossy in the direction that matters: `TextDecoder` maps every malformed sequence to
 * U+FFFD, so the three bytes `EF BF BD` (a legitimately encoded U+FFFD) and the single
 * byte `FF` (not UTF-8 at all) decode to the same character and would digest the same.
 * A signature computed over decoded text therefore authenticates a normalization of the
 * body rather than the body, and an intermediary can swap one for the other while the
 * signature still verifies — the delivered bytes are then unsigned. Digest the bytes you
 * were handed; decode afterwards, if at all.
 */
export function contentDigest(body: string | Uint8Array): string {
  const octets = typeof body === "string" ? textEncoder.encode(body) : body;
  return `sha-256=:${base64.encode(sha256(octets))}:`;
}

export function generateNonce(): string {
  return toMultibase(randomBytes(16));
}

function signatureParams(
  created: number,
  keyId: string,
  nonce: string,
  withGrants: boolean
): string {
  const covered: string[] = [...COVERED_COMPONENTS];
  if (withGrants) {
    covered.push(GRANTS_COMPONENT);
  }
  const components = covered.map((component) => `"${component}"`).join(" ");
  return `(${components});created=${created};keyid="${keyId}";nonce="${nonce}"`;
}

function signatureBase(
  method: string,
  url: string,
  digest: string,
  params: string,
  grantsHeader?: string
): string {
  const lines = [
    `"@method": ${method.toUpperCase()}`,
    `"@target-uri": ${url}`,
    `"content-digest": ${digest}`
  ];
  if (grantsHeader !== undefined) {
    lines.push(`"${GRANTS_COMPONENT}": ${grantsHeader}`);
  }
  lines.push(`"@signature-params": ${params}`);
  return lines.join("\n");
}

export type SignRequestOptions = {
  method: string;
  url: string;
  /**
   * The request body. A `string` is signed as its UTF-8 encoding, so passing one is
   * only correct when the same code path transmits that exact encoding (it is what
   * `fetch` does with a string body). Pass bytes for anything binary, or for anything
   * whose encoding this caller does not control.
   */
  body: string | Uint8Array;
  /** RFC 9421 keyid — the participant ID (spec 002). */
  keyId: string;
  secretKey: Uint8Array;
  /** Seconds since the epoch; defaults to now. */
  created?: number;
  nonce?: string;
  /**
   * Spec 011: a leaf-first grant chain to present with the request. When set, the
   * chain is carried in a PN-Grants header and covered by the signature.
   */
  grants?: Grant[];
};

export type SignedRequestHeaders = {
  "content-digest": string;
  "signature-input": string;
  signature: string;
  "pn-grants"?: string;
};

export function signRequest(options: SignRequestOptions): SignedRequestHeaders {
  const created = options.created ?? Math.floor(Date.now() / 1000);
  const nonce = options.nonce ?? generateNonce();
  const digest = contentDigest(options.body);
  const grantsHeader =
    options.grants !== undefined ? encodeGrantsHeader(options.grants) : undefined;
  const params = signatureParams(created, options.keyId, nonce, grantsHeader !== undefined);
  const base = signatureBase(options.method, options.url, digest, params, grantsHeader);
  const signature = sign(textEncoder.encode(base), options.secretKey);

  const headers: SignedRequestHeaders = {
    "content-digest": digest,
    "signature-input": `${SIGNATURE_LABEL}=${params}`,
    signature: `${SIGNATURE_LABEL}=:${base64.encode(signature)}:`
  };
  if (grantsHeader !== undefined) {
    headers["pn-grants"] = grantsHeader;
  }
  return headers;
}

export type VerifyRequestOptions = {
  method: string;
  url: string;
  /**
   * The body EXACTLY AS DELIVERED. Hand over the raw content octets: this function
   * digests what it is given, byte for byte, and a caller that decodes the request to
   * text first has already destroyed the property the digest exists to establish (see
   * {@link contentDigest}). A `string` is accepted for callers that hold the body as
   * text by construction — a test vector, or a sender re-checking its own request —
   * and is digested as its UTF-8 encoding.
   */
  body: string | Uint8Array;
  /** Header lookup is by lower-cased name; missing headers may be undefined. */
  headers: Record<string, string | undefined>;
  /** The participant's current signing keys, resolved from the key log (spec 003). */
  keys: KeyRef[];
  /**
   * Signing threshold from the key log; this profile supports `"1"` and refuses everything
   * else — a threshold above 1 as unsupported multi-signature, and anything outside 015 S1's
   * `^[1-9][0-9]*$` domain as malformed. Never coerced: see the parse below.
   */
  threshold?: string;
  /** Seconds since the epoch; defaults to now. Injected for tests. */
  now?: number;
  maxSkewSeconds?: number;
  /**
   * Spec 011: the raw PN-Grants header value, when the request carried one. If
   * present, the signature MUST cover `pn-grants` and is verified over this exact
   * value; if absent, a signature claiming `pn-grants` coverage is rejected.
   */
  grantsHeader?: string;
  /** Ceiling on Ed25519 verifications while probing the current key state. */
  maxSignatureVerifications?: number;
  /** Reports the number of Ed25519 verifications on every exit, including a throw. */
  onSignatureVerifications?: (spent: number) => void;
};

export type VerifiedWrite = {
  keyId: string;
  created: number;
  nonce: string;
  /**
   * The KeyRef that actually satisfied the signature (spec 013 §4). A rotated-out
   * key does not remain in `keys` after the key log advances, so recording which
   * key verified is the only way a continuing-authority surface (e.g. an SSE
   * stream) can later re-check that the signing key is still current. `keys` is
   * probed in order and the first match wins; multi-key sets that share a
   * signature (thresholds > 1) are not yet supported by this profile.
   */
  satisfiedKey: KeyRef;
};

/**
 * The default half-width, in seconds, of the window a signature's `created` parameter must
 * fall inside. A signature minted more than this long ago — or this far in the future — is
 * refused as {@link SignatureStaleError} regardless of whether it verifies.
 *
 * It is the ONLY freshness bound on a request signature, and it is what the replay-nonce
 * retention is derived from (`2 * skew + 1`, see `replayTtlSeconds`): a nonce may be forgotten
 * only once no signature bearing it can still be fresh. Raising the skew therefore lengthens
 * nonce retention, which is why the two are computed from one number rather than configured
 * apart. It has nothing to do with grant expiry — a chain's `[issuedAt, expiresAt]` window is
 * evaluated by the trust resolver against the same wall clock but is an authority lifetime,
 * not a transport freshness bound.
 */
export const DEFAULT_MAX_SKEW_SECONDS = 120;

/**
 * The base class for every rejection {@link verifyRequest} raises on its own account, so a
 * caller can tell "this request failed the spec 004 profile" from "something else threw while
 * verifying it" — most importantly {@link VerificationBudgetExceeded}, which is a cost refusal
 * and not a rejection at all.
 *
 * It exists so the two rejections a relying party has to REPORT DIFFERENTLY can be narrowed
 * without matching on message text. `@kinnet/verify` used to catch everything this function
 * threw and flatten it into one `signature_invalid` reason, which told a caller whose clock had
 * drifted, and a caller whose proxy had rewritten the body, the same untrue thing: that their
 * key was wrong. Message-sniffing would have "fixed" that while making every message string a
 * wire contract; a class hierarchy states the distinction where it is decided.
 *
 * Rejections with no distinct remedy stay on this base rather than each earning a subclass:
 * a malformed `Signature-Input`, an uncovered grants header, and a signature that simply does
 * not verify are all "this request is not authentic", and splitting them would hand an
 * unauthenticated caller a finer-grained oracle for no consumer's benefit.
 */
export class RequestSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestSignatureError";
  }
}

/**
 * The signature's `created` time is outside the allowed clock-skew window: the request was
 * minted too long ago (or too far in the future) to still be fresh.
 *
 * NOT an authentication failure in the usual sense — the signature itself may well be valid,
 * and typically is. The remedy belongs to the CALLER'S CLOCK or to a stale retry, never to its
 * keys, so a relying party that reports this as "signature invalid" sends the caller to
 * re-provision credentials that were never the problem. See {@link DEFAULT_MAX_SKEW_SECONDS}
 * for the window and `VerifyRequestOptions.maxSkewSeconds` to widen it.
 *
 * Thrown BEFORE any Ed25519 verification, so it costs nothing from the verification budget.
 */
export class SignatureStaleError extends RequestSignatureError {
  constructor(message: string) {
    super(message);
    this.name = "SignatureStaleError";
  }
}

/**
 * The `Content-Digest` header does not match the body actually presented (RFC 9530).
 *
 * Separated from a plain signature failure because the two have different causes and different
 * fixes: a digest mismatch is what a body-rewriting intermediary produces — a proxy that
 * re-encodes JSON, a framework that reserializes a parsed body before the verifier sees it —
 * far more often than it is what an attacker produces. Collapsed into `signature_invalid` it
 * reads as a credential problem and sends an operator hunting the wrong layer.
 *
 * Checked before the signature is parsed, so it also costs nothing from the budget.
 */
export class ContentDigestMismatchError extends RequestSignatureError {
  constructor(message: string) {
    super(message);
    this.name = "ContentDigestMismatchError";
  }
}

/**
 * Verifies a signed write request against the current key set and returns the
 * signature parameters. Throws on any failure. Nonce uniqueness is the caller's
 * responsibility — this function checks shape, freshness, digest, and signature.
 */
export function verifyRequest(options: VerifyRequestOptions): VerifiedWrite {
  const digestHeader = options.headers["content-digest"];
  const inputHeader = options.headers["signature-input"];
  const signatureHeader = options.headers["signature"];

  if (!digestHeader || !inputHeader || !signatureHeader) {
    throw new RequestSignatureError("Missing Content-Digest, Signature-Input, or Signature header");
  }

  if (digestHeader.trim() !== contentDigest(options.body)) {
    throw new ContentDigestMismatchError("Content-Digest does not match the request body");
  }

  const inputMatch = SIGNATURE_INPUT_PATTERN.exec(inputHeader.trim());
  if (!inputMatch) {
    throw new RequestSignatureError("Signature-Input does not match the spec 004 profile");
  }
  const [, params, grantsComponent, createdText, keyId, nonce] = inputMatch;
  const created = Number(createdText);

  const coversGrants = grantsComponent !== undefined;
  const grantsHeader = options.grantsHeader?.trim();
  if (grantsHeader !== undefined && !coversGrants) {
    throw new RequestSignatureError("PN-Grants header is present but not covered by the signature");
  }
  if (grantsHeader === undefined && coversGrants) {
    throw new RequestSignatureError(
      "Signature covers pn-grants but no PN-Grants header is present"
    );
  }

  // Validate the freshness inputs BEFORE comparing against them. `NaN` is the dangerous
  // case: every comparison with it is false, so `> maxSkew` would never reject and the
  // clock-skew window — the whole basis of replay protection — would be silently disabled
  // while the signature still verified. Fractional values are refused too, because the
  // replay TTL derived from this skew (`2 * skew + 1`, see `replayTtlSeconds`) is a
  // statement about whole seconds.
  const now = assertWholeSeconds(options.now ?? Math.floor(Date.now() / 1000), "now");
  const maxSkew = assertWholeSeconds(
    options.maxSkewSeconds ?? DEFAULT_MAX_SKEW_SECONDS,
    "maxSkewSeconds"
  );
  if (Math.abs(now - created) > maxSkew) {
    throw new SignatureStaleError(
      "Signature created time is outside the allowed clock-skew window"
    );
  }

  const signatureMatch = SIGNATURE_PATTERN.exec(signatureHeader.trim());
  if (!signatureMatch) {
    throw new RequestSignatureError("Signature header does not match the spec 004 profile");
  }
  const signatureBytes = base64.decode(signatureMatch[1]!);

  // Spec 015 S1's threshold domain, PARSED and never coerced — the same `parseThreshold` the
  // record layer and the key-log replay use, so one definition of "a threshold" governs all
  // three. `Number(options.threshold ?? "1")` was fail-open in shape: a malformed value gives
  // `NaN`, every comparison with `NaN` is false, so `NaN > 1` did not reject and a request
  // presenting an unparseable threshold was verified as if it were 1-of-1. Nothing reachable
  // supplied one — every caller takes the value from a schema-validated key log — but a public
  // API whose safety rests on a regex two packages away is exactly the shape 015 S1 forbids, and
  // spec 004's threshold rule is a MUST rather than an assumption about callers.
  const threshold = parseThreshold(options.threshold ?? "1");
  if (threshold === null) {
    throw new RequestSignatureError(
      `Request threshold ${JSON.stringify(String(options.threshold))} is not a decimal string matching ^[1-9][0-9]*$ (spec 015 S1)`
    );
  }
  if (threshold > 1) {
    throw new RequestSignatureError(
      "Multi-signature thresholds are not yet supported for write-auth"
    );
  }

  const base = signatureBase(
    options.method,
    options.url,
    digestHeader.trim(),
    params!,
    grantsHeader
  );
  const baseBytes = textEncoder.encode(base);
  const limit = safeVerificationCount(
    options.maxSignatureVerifications,
    DEFAULT_MAX_SIGNATURE_VERIFICATIONS
  );
  let spent = 0;
  let satisfiedKey: KeyRef | undefined;
  try {
    for (const keyRef of options.keys) {
      const publicKey = decodeKeyRef(keyRef);
      if (spent >= limit) {
        throw new VerificationBudgetExceeded(
          `Request verification exceeded its budget of ${limit} signature verifications`
        );
      }
      spent += 1;
      if (verify(signatureBytes, baseBytes, publicKey)) {
        satisfiedKey = keyRef;
        break;
      }
    }
  } finally {
    options.onSignatureVerifications?.(spent);
  }

  if (satisfiedKey === undefined) {
    throw new RequestSignatureError(
      "Signature does not verify against the participant's current keys"
    );
  }

  return { keyId: keyId!, created, nonce: nonce!, satisfiedKey };
}
