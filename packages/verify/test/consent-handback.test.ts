/**
 * Pins the OAuth consent worked-example fixture (the OAuth handback worked example, §9)
 * so it stays verifiable from committed bytes alone — the property the handback promises a
 * downstream resource server. The fixture is a `pnc1.` access token carrying a one-link
 * spec-009/011 consent chain aud-bound to the resource server's participant id, plus the subject's
 * key log so the chain verifies offline.
 *
 * If any of these assertions ever regress, the token kinnet hands a resource stopped meaning
 * what the handback says it means — which is exactly what a third party pinned to these bytes
 * would hit in production.
 */
import { readFileSync } from "node:fs";

import { canonicalDigest, decodeChainAccessToken } from "@kinnet/crypto";
import type { Grant, KeyEvent } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

// Imported from this package's own entry, not `@kinnet/trust`, on purpose: this is the exact
// surface a resource server that vendors only `@kinnet/verify` reaches, so the test also guards
// that the re-export stays present.
import { createStaticTrustView, verifyGrantChain } from "../src/index.js";

type Fixture = {
  subject: string;
  subjectKeyLog: KeyEvent[];
  resourceParticipantId: string;
  consentedScopes: string[];
  chain: Grant[];
  accessToken: string;
  grantDigest: string;
  issuedAt: string;
  expiresAt: string;
  /** A fixed instant inside [issuedAt, expiresAt]; verify against this, never the wall clock. */
  verifyAt: string;
  expectedVerdict: { valid: boolean; subjectId: string };
};

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/consent-handback.json", import.meta.url), "utf8")
) as Fixture;

describe("OAuth consent worked-example fixture", () => {
  it("decodes the access token to exactly the recorded chain", () => {
    expect(decodeChainAccessToken(fixture.accessToken)).toEqual(fixture.chain);
  });

  it("derives the recorded session/revocation digest from the leaf grant", () => {
    expect(canonicalDigest(fixture.chain[0]!)).toBe(fixture.grantDigest);
  });

  it("binds the leaf to the resource server by audience and aud caveat", () => {
    const leaf = fixture.chain[0]!;
    expect(leaf.audienceId).toBe(fixture.resourceParticipantId);
    expect(leaf.caveats["aud"]).toBe(fixture.resourceParticipantId);
    expect([...leaf.abilities].sort()).toEqual([...fixture.consentedScopes].sort());
  });

  it("verifies as the resource, from the bundled key log alone, with no network", async () => {
    const view = createStaticTrustView({ keyLogs: [fixture.subjectKeyLog] });
    const verdict = await verifyGrantChain(fixture.chain, view, {
      verifierId: fixture.resourceParticipantId,
      requireAud: true,
      purpose: "request",
      // Fixed instant inside the grant's validity window — the chain has a real expiresAt, so
      // verifying at the wall clock would flip to grant_expired once the fixture aged out.
      now: new Date(fixture.verifyAt)
    });
    // Narrow the discriminated union so a regression to a rejection fails loudly here rather
    // than at a property access.
    if (!verdict.valid) {
      throw new Error(`fixture chain was rejected: ${verdict.reason}`);
    }
    expect(verdict.subjectId).toBe(fixture.expectedVerdict.subjectId);
  });

  it("is contained to its audience: a different resource does not admit the same token", async () => {
    // The aud binding is the whole security story — the same bytes must fail at any other
    // resource id. Here the subject's own id stands in for some other resource that is not the
    // bound audience: synthetic, already in the fixture, and guaranteed !== resourceParticipantId.
    const view = createStaticTrustView({ keyLogs: [fixture.subjectKeyLog] });
    const verdict = await verifyGrantChain(fixture.chain, view, {
      verifierId: fixture.chain[0]!.subjectId,
      requireAud: true,
      purpose: "request",
      now: new Date(fixture.verifyAt)
    });
    if (verdict.valid) {
      throw new Error("a token aud-bound to one resource must not verify at another resource");
    }
    expect(verdict.reason).toBe("grant_audience_not_admitted");
  });
});
