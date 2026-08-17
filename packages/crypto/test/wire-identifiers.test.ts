/**
 * Brand neutrality of the wire identifiers this package owns (spec 000, _Wire identifiers are
 * brand-neutral_): the HTTP signature component and header name that carry a delegated grant
 * chain (spec 011). `@kinnet/protocol` guards the reserved envelope-type prefix in its own
 * suite; it cannot reach these without depending on this package.
 *
 * The MLS `PNCredential` / `PNCommitBinding` struct names (spec 014) are TLS
 * presentation-language names: they are never serialized, so there are no bytes to assert. What
 * does reach the wire for that profile is the numeric private-use credential type, pinned below
 * — a number carries no brand.
 */
import type { Grant } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import * as crypto from "../src/index.js";

const GRANT: Grant = {
  subjectId: "pk_z6MkSubject1111",
  issuerId: "pk_z6MkSubject1111",
  audienceId: "z6MkSessionKey1111",
  abilities: ["msg/send"],
  caveats: { aud: "pk_z6MkVerifier1111" },
  proof: null,
  issuedAt: "2026-07-21T12:00:00.000Z",
  expiresAt: "2026-07-28T12:00:00.000Z",
  signature: ["z2SignatureBytes1111"]
};

describe("wire identifiers are brand-neutral (spec 000)", () => {
  const identity = crypto.createIdentity();
  const headers = crypto.signRequest({
    method: "PUT",
    url: "http://localhost/participants/pk_z1/key-log",
    body: JSON.stringify({ hello: "world" }),
    keyId: identity.id,
    secretKey: identity.currentKeys[0]!.secretKey,
    created: 1_780_000_000,
    nonce: crypto.generateNonce(),
    grants: [GRANT]
  });

  it("carries a delegated chain in the `pn-grants` header", () => {
    expect(headers["pn-grants"]).toBeDefined();
  });

  it("covers it under the `pn-grants` signature component", () => {
    expect(headers["signature-input"]).toContain('"pn-grants"');
  });

  it("names no signed header after the product", () => {
    expect(Object.keys(headers).filter((name) => /kinnet/i.test(name))).toEqual([]);
  });

  it("puts a private-use number, not a name, in the MLS credential type", () => {
    // Spec 014 pins `0xF001`. A number cannot carry a brand; the symbol naming it is an
    // implementation name, which 000 leaves branded.
    expect(crypto.KINNET_CREDENTIAL_TYPE).toBe(0xf001);
  });
});
