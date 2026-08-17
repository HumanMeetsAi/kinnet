/**
 * Chain access token codec: `"pnc1." + base64url( UTF8( JSON array of Grant records, leaf
 * first ) )`.
 *
 * This is the wire form of an OAuth access token that IS the spec-009/011 delegation chain the
 * user consented to, rather than a handle the resource must trade back to the authorization
 * server. The resource server decodes it and verifies the chain against discovery like any other
 * delegated request, so the token carries its own authority and no introspection state exists to
 * hold.
 *
 * The payload after the prefix is byte-identical to the `PN-Grants` header's payload after its
 * `1:` version prefix — same encoding, same guards, in the same order (`./grant-chain-payload.ts`)
 * — so one chain has one payload encoding no matter which delivery carries it. The prefixes stay
 * distinct because the deliveries are: `pnc1.` names an OAuth bearer credential, which travels
 * through OAuth-shaped code (`Authorization: Bearer`, token caches, logs) that must not mistake
 * it for a header chain and must reject an unversioned or foreign token outright.
 */
import type { Grant } from "@kinnet/protocol";

import {
  decodeGrantChainPayload,
  encodeGrantChainPayload,
  type GrantChainLabels
} from "./grant-chain-payload.js";

/** Version prefix of the chain access token. Anything else is refused, never guessed at. */
export const CHAIN_ACCESS_TOKEN_PREFIX = "pnc1.";

/** Wording of the shared payload guards' refusals for this delivery. */
const LABELS: GrantChainLabels = { payload: "Chain access token", chain: "Chain access token" };

/** Encodes a leaf-first grant chain as an OAuth chain access token. */
export function encodeChainAccessToken(chain: Grant[]): string {
  return CHAIN_ACCESS_TOKEN_PREFIX + encodeGrantChainPayload(chain);
}

/**
 * Decodes a chain access token into a leaf-first grant chain. Throws on any deviation from the
 * `pnc1.` profile: unknown or missing prefix, bad base64url, bad UTF-8/JSON, a non-array or
 * empty payload, more links than spec 011 allows, or any element that is not a shape-valid
 * Grant. Shape only — whether the chain authorizes anything is the resource server's
 * verification, which runs on the result.
 */
export function decodeChainAccessToken(token: string): Grant[] {
  if (!token.startsWith(CHAIN_ACCESS_TOKEN_PREFIX)) {
    throw new Error("unsupported chain access token encoding");
  }
  return decodeGrantChainPayload(token.slice(CHAIN_ACCESS_TOKEN_PREFIX.length), LABELS);
}
