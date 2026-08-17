/**
 * The payload half of spec 011's grant-chain deliveries: `base64url( UTF8( JSON array of Grant
 * records, leaf first ) )`.
 *
 * Two wire forms carry exactly these bytes behind different prefixes — the `PN-Grants` header
 * (`1:`, `./grants-header.ts`) and the OAuth chain access token (`pnc1.`,
 * `./chain-access-token.ts`). The prefix is each delivery's own business; everything after it
 * must be read identically, in the same order, or one delivery becomes a way to smuggle past a
 * guard the other enforces. The guards therefore live here once, and each caller supplies only
 * the words its refusals use.
 */
import { grantSchema, MAX_GRANT_CHAIN_LINKS, parseJsonStrict, type Grant } from "@kinnet/protocol";
import { base64urlnopad } from "@scure/base";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

/** How a delivery names itself in its refusals: `<payload> payload is …`, `<chain> carries …`. */
export type GrantChainLabels = {
  /** Names the payload, e.g. `PN-Grants` → "PN-Grants payload is not valid base64url". */
  payload: string;
  /** Names the chain, e.g. `PN-Grants chain` → "PN-Grants chain carries 5 links, …". */
  chain: string;
};

/**
 * Encodes a leaf-first grant chain as the shared payload. An empty chain is refused here rather
 * than on decode: no delivery accepts one, so encoding it would only mint bytes nothing reads.
 */
export function encodeGrantChainPayload(chain: Grant[]): string {
  if (chain.length === 0) {
    throw new Error("Cannot encode an empty grant chain");
  }
  return base64urlnopad.encode(textEncoder.encode(JSON.stringify(chain)));
}

/**
 * Decodes the shared payload into a leaf-first grant chain. Throws on bad base64url, bad
 * UTF-8/JSON, a non-array or empty payload, an overlong chain, or any element that is not a
 * shape-valid Grant. Chain semantics (issuer resolution, expiry, revocation) are the verifier's
 * job, not this codec's.
 */
export function decodeGrantChainPayload(payload: string, labels: GrantChainLabels): Grant[] {
  let bytes: Uint8Array;
  try {
    bytes = base64urlnopad.decode(payload);
  } catch {
    throw new Error(`${labels.payload} payload is not valid base64url`);
  }
  let parsed: unknown;
  try {
    // STRICT (spec 015 S6.1): a delivery whose JSON contains a duplicate object key, at any
    // depth, is refused outright rather than resolved. Last-wins and first-wins are both
    // defensible and parsers disagree, so two implementations handed ONE delivery would
    // otherwise build two different Grant objects and digest them differently — and a Grant's
    // digest is what its child's `proof` names and what 008 keys its revocation by. These are
    // the highest-traffic delivery points for a signature-set record in the repo: every
    // delegated request carries a chain through here, before anything has been proven.
    parsed = parseJsonStrict(textDecoder.decode(bytes));
  } catch {
    throw new Error(`${labels.payload} payload is not valid UTF-8 JSON`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error(`${labels.payload} payload must be a non-empty JSON array`);
  }
  // Length before shape: verifying a chain replays the issuer's key log per link, so the
  // depth is work the caller chooses and it is chosen before anything has been proven.
  // Rejecting here also keeps the per-element `grantSchema.parse` bounded.
  if (parsed.length > MAX_GRANT_CHAIN_LINKS) {
    throw new Error(
      `${labels.chain} carries ${parsed.length} links, more than the ${MAX_GRANT_CHAIN_LINKS} allowed`
    );
  }
  return parsed.map((element) => grantSchema.parse(element));
}
