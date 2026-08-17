/**
 * The issuers, decided by the verifiers that live beside them: every record minted here is
 * parsed by its own strict schema and then handed to the resolver against a view built from the
 * issuer's real key log. A mint that produces something this package refuses is a mint bug, and
 * this is the only place both halves are exercised over one set of bytes.
 */
import {
  canonicalBytes,
  canonicalDigest,
  createIdentity,
  encodeKeyRef,
  type Identity
} from "@kinnet/crypto";
import {
  claimSchema,
  grantSchema,
  relationshipSchema,
  revocationSchema,
  type Revocation
} from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  GrantValidationError,
  issueClaim,
  issueGrant,
  issueRelationship,
  issueRepresentsEdge,
  issueRevocation,
  REPRESENTS_PREDICATE,
  verifyClaim,
  verifyGrantChain,
  verifyRelationship,
  verifyRepresentsChain,
  type TrustView
} from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const NOW = new Date("2026-07-01T00:00:00.000Z");
const ISSUED_AT = "2026-06-01T00:00:00.000Z";
const EXPIRES_AT = "2027-06-01T00:00:00.000Z";

const org = createIdentity({ currentSeed: seed(11), nextSeed: seed(12) });
const agent = createIdentity({ currentSeed: seed(13), nextSeed: seed(14) });
const verifier = createIdentity({ currentSeed: seed(15), nextSeed: seed(16) });

function makeView(identities: Identity[], revocations: Revocation[] = []): TrustView {
  const logs = new Map(identities.map((identity) => [identity.id, identity.log]));
  return {
    async getKeyLog(id) {
      return logs.get(id) ?? null;
    },
    async getRevocations(digest, issuerIds) {
      return revocations.filter(
        (revocation) => revocation.revokes === digest && issuerIds.includes(revocation.issuerId)
      );
    }
  };
}

describe("issueRelationship", () => {
  it("mints an edge that parses strictly and verifies against the issuer's key log", async () => {
    const edge = issueRelationship(org, {
      id: "member-of-1",
      subjectId: agent.id,
      predicate: "member-of",
      objectId: org.id,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT
    });

    expect(relationshipSchema.parse(edge)).toEqual(edge);
    expect(edge.issuedBy).toBe(org.id);
    const verdict = await verifyRelationship(edge, makeView([org]), { now: NOW });
    expect(verdict.valid).toBe(true);
  });

  it("is byte-identical across two calls with the same fixed issuedAt", () => {
    const options = {
      id: "member-of-1",
      subjectId: agent.id,
      predicate: "member-of",
      objectId: org.id,
      issuedAt: ISSUED_AT
    };
    expect(canonicalBytes(issueRelationship(org, options))).toEqual(
      canonicalBytes(issueRelationship(org, options))
    );
  });

  it("omits expiresAt entirely when none was asked for, rather than signing an undefined", () => {
    const edge = issueRelationship(org, {
      id: "member-of-2",
      subjectId: agent.id,
      predicate: "member-of",
      objectId: org.id,
      issuedAt: ISSUED_AT
    });
    expect("expiresAt" in edge).toBe(false);
  });
});

describe("issueClaim", () => {
  it("mints a claim that parses strictly and verifies against the issuer's key log", async () => {
    const claim = issueClaim(org, {
      id: "role-1",
      subjectId: agent.id,
      claimType: "role",
      value: "operator",
      issuedAt: ISSUED_AT
    });

    expect(claimSchema.parse(claim)).toEqual(claim);
    expect(claim.issuedBy).toBe(org.id);
    const verdict = await verifyClaim(claim, makeView([org]), { now: NOW });
    expect(verdict.valid).toBe(true);
  });

  it("is byte-identical across two calls with the same fixed issuedAt", () => {
    const options = {
      id: "role-1",
      subjectId: agent.id,
      claimType: "role",
      value: { tier: 2, tags: ["a", "b"] },
      issuedAt: ISSUED_AT
    };
    expect(canonicalBytes(issueClaim(org, options))).toEqual(
      canonicalBytes(issueClaim(org, options))
    );
  });

  it("is refused by the verifier once the issuer revokes it", async () => {
    const claim = issueClaim(org, {
      id: "role-2",
      subjectId: agent.id,
      claimType: "role",
      value: "operator",
      issuedAt: ISSUED_AT
    });
    const revocation = issueRevocation(org, canonicalDigest(claim), {
      revokedAt: "2026-06-15T00:00:00.000Z",
      reason: "superseded"
    });

    const verdict = await verifyClaim(claim, makeView([org], [revocation]), { now: NOW });
    expect(verdict.valid).toBe(false);
    expect(verdict.valid ? undefined : verdict.reason).toBe("claim_revoked");
  });
});

describe("issueRepresentsEdge", () => {
  it("pins the represents predicate and defaults its id to represents-<agentId>", () => {
    const edge = issueRepresentsEdge(org, agent.id, { issuedAt: ISSUED_AT });
    expect(edge.predicate).toBe(REPRESENTS_PREDICATE);
    expect(edge.id).toBe(`represents-${agent.id}`);
    expect(edge.subjectId).toBe(agent.id);
    expect(edge.objectId).toBe(org.id);
  });

  it("verifies as a represents chain for the organization that issued it", async () => {
    const edge = issueRepresentsEdge(org, agent.id, { issuedAt: ISSUED_AT });
    const verdict = await verifyRepresentsChain(
      { agentId: agent.id, organizationId: org.id, edge },
      makeView([org, agent]),
      { now: NOW }
    );
    expect(verdict.valid).toBe(true);
  });

  it("is byte-identical to the same edge minted through issueRelationship", () => {
    const viaHelper = issueRepresentsEdge(org, agent.id, { issuedAt: ISSUED_AT });
    const viaGeneral = issueRelationship(org, {
      id: `represents-${agent.id}`,
      subjectId: agent.id,
      predicate: REPRESENTS_PREDICATE,
      objectId: org.id,
      issuedAt: ISSUED_AT
    });
    expect(canonicalBytes(viaHelper)).toEqual(canonicalBytes(viaGeneral));
  });
});

describe("issueGrant", () => {
  it("mints a root grant that parses strictly and whose chain verifies", async () => {
    const grant = issueGrant(org, agent.id, ["quotes/read", "orders/create"], {
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT
    });

    expect(grantSchema.parse(grant)).toEqual(grant);
    expect(grant.issuerId).toBe(org.id);
    expect(grant.subjectId).toBe(org.id);
    expect(grant.proof).toBeNull();

    const verdict = await verifyGrantChain([grant], makeView([org]), { now: NOW });
    expect(verdict.valid).toBe(true);
    expect(verdict.valid ? verdict.abilities : []).toEqual(["quotes/read", "orders/create"]);
  });

  it("is byte-identical across two calls with the same fixed issuedAt", () => {
    const mint = () =>
      issueGrant(org, agent.id, ["quotes/read"], {
        issuedAt: ISSUED_AT,
        expiresAt: EXPIRES_AT,
        caveats: { aud: verifier.id }
      });
    expect(canonicalBytes(mint())).toEqual(canonicalBytes(mint()));
  });

  it("rejects a key-audience grant with no expiresAt, at the mint rather than at the verifier", () => {
    // A bare KeyRef audience (spec 011's disposable principal, e.g. a browser session key).
    const sessionKey = encodeKeyRef(agent.currentKeys[0]!.publicKey);
    expect(() =>
      issueGrant(org, sessionKey, ["msg/send"], {
        issuedAt: ISSUED_AT,
        caveats: { aud: org.id }
      })
    ).toThrow(GrantValidationError);
  });

  it("rejects a malformed ability at the mint", () => {
    expect(() => issueGrant(org, agent.id, ["Orders/Create"], { issuedAt: ISSUED_AT })).toThrow(
      GrantValidationError
    );
  });
});

describe("issueRevocation", () => {
  it("mints a revocation that parses strictly and carries an array signature and no id", () => {
    const edge = issueRepresentsEdge(org, agent.id, { issuedAt: ISSUED_AT });
    const revocation = issueRevocation(org, canonicalDigest(edge), {
      revokedAt: "2026-06-15T00:00:00.000Z"
    });

    expect(revocationSchema.parse(revocation)).toEqual(revocation);
    expect(Array.isArray(revocation.signature)).toBe(true);
    expect("id" in revocation).toBe(false);
    expect("reason" in revocation).toBe(false);
    expect(revocation.revokes).toBe(canonicalDigest(edge));
  });

  it("is byte-identical across two calls with the same fixed revokedAt", () => {
    const digest = canonicalDigest(issueRepresentsEdge(org, agent.id, { issuedAt: ISSUED_AT }));
    const mint = () =>
      issueRevocation(org, digest, { revokedAt: "2026-06-15T00:00:00.000Z", reason: "superseded" });
    expect(canonicalBytes(mint())).toEqual(canonicalBytes(mint()));
  });

  it("flips a verified grant chain to grant_revoked", async () => {
    const grant = issueGrant(org, agent.id, ["quotes/read"], {
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT
    });
    const revocation = issueRevocation(org, canonicalDigest(grant), {
      revokedAt: "2026-06-15T00:00:00.000Z"
    });

    const verdict = await verifyGrantChain([grant], makeView([org], [revocation]), { now: NOW });
    expect(verdict.valid).toBe(false);
    expect(verdict.valid ? undefined : verdict.reason).toBe("grant_revoked");
  });
});
