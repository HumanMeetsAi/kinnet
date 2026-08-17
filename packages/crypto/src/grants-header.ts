/**
 * PN-Grants header codec (spec 011): `"1:" + base64url( UTF8( JSON array of Grant
 * records, leaf first ) )`. The `1:` prefix names the encoding so a future profile
 * (chain-in-body, chain-by-digest) is additive; anything else is rejected. Decoding is
 * strict and fail-closed — every element must be a shape-valid Grant. Chain semantics
 * (issuer resolution, expiry, revocation) are the verifier's job, not this codec's.
 *
 * Everything after the prefix is `./grant-chain-payload.ts`, shared with the chain access token
 * codec so the two deliveries cannot diverge in what they accept.
 */
import type { Grant } from "@kinnet/protocol";

import {
  decodeGrantChainPayload,
  encodeGrantChainPayload,
  type GrantChainLabels
} from "./grant-chain-payload.js";

const PROFILE_PREFIX = "1:";

/** Wording of the shared payload guards' refusals for this delivery. */
const LABELS: GrantChainLabels = { payload: "PN-Grants", chain: "PN-Grants chain" };

/** Encodes a leaf-first grant chain as a PN-Grants header value. */
export function encodeGrantsHeader(chain: Grant[]): string {
  return PROFILE_PREFIX + encodeGrantChainPayload(chain);
}

/**
 * Decodes a PN-Grants header value into a leaf-first grant chain. Throws on any
 * deviation from the `1:` profile: unknown prefix, bad base64url, bad UTF-8/JSON, a
 * non-array or empty payload, or any element that is not a shape-valid Grant.
 */
export function decodeGrantsHeader(value: string): Grant[] {
  if (!value.startsWith(PROFILE_PREFIX)) {
    throw new Error("unsupported PN-Grants encoding");
  }
  return decodeGrantChainPayload(value.slice(PROFILE_PREFIX.length), LABELS);
}
