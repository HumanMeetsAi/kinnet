import { readFileSync } from "node:fs";

import { canonicalDigest } from "@kinnet/crypto";
import type { Claim, Grant, KeyEvent, Relationship, Revocation } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  createFinancialCaveatEvaluator,
  verifyClaim,
  verifyGrantChain,
  verifyRepresentsChain,
  type FinancialAction,
  type TrustView
} from "../src/index.js";

type Fixture = {
  verifyAt: string;
  organizationLog: KeyEvent[];
  adminLog: KeyEvent[];
  agentLog: KeyEvent[];
  edge: Relationship;
  grants: Grant[];
  revokedClaim: Claim;
  revocation: Revocation;
  expect: {
    organizationId: string;
    agentId: string;
    edgeDigest: string;
    rootGrantDigest: string;
    leafGrantDigest: string;
    representsValid: boolean;
    abilities: string[];
    revokedClaimReason: string;
  };
};

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/represents-chain.json", import.meta.url), "utf8")
) as Fixture;

function fixtureView(): TrustView {
  const logs = new Map(
    [fixture.organizationLog, fixture.adminLog, fixture.agentLog].map((log) => [log[0]!.id, log])
  );
  return {
    async getKeyLog(id) {
      return logs.get(id) ?? null;
    },
    async getRevocations(digest, issuerIds) {
      return fixture.revocation.revokes === digest &&
        issuerIds.includes(fixture.revocation.issuerId)
        ? [fixture.revocation]
        : [];
    }
  };
}

describe("committed conformance fixture (specs 008/009)", () => {
  const now = new Date(fixture.verifyAt);

  it("pins the record digests third parties verify against", () => {
    expect(canonicalDigest(fixture.edge)).toBe(fixture.expect.edgeDigest);
    expect(canonicalDigest(fixture.grants[1]!)).toBe(fixture.expect.rootGrantDigest);
    expect(canonicalDigest(fixture.grants[0]!)).toBe(fixture.expect.leafGrantDigest);
    expect(fixture.grants[0]!.proof).toBe(fixture.expect.rootGrantDigest);
  });

  it("verifies the represents chain with its grant chain from bytes alone", async () => {
    const verdict = await verifyRepresentsChain(
      {
        agentId: fixture.expect.agentId,
        organizationId: fixture.expect.organizationId,
        edge: fixture.edge,
        grants: fixture.grants
      },
      fixtureView(),
      { now }
    );

    expect(verdict).toEqual({
      valid: fixture.expect.representsValid,
      agentId: fixture.expect.agentId,
      organizationId: fixture.expect.organizationId,
      abilities: fixture.expect.abilities
    });
  });

  it("rejects the committed revoked claim for the committed reason", async () => {
    const verdict = await verifyClaim(fixture.revokedClaim, fixtureView(), { now });
    expect(verdict).toEqual({ valid: false, reason: fixture.expect.revokedClaimReason });
  });

  it("does not verify the chain if any byte of the edge changes", async () => {
    const verdict = await verifyRepresentsChain(
      {
        agentId: fixture.expect.agentId,
        organizationId: fixture.expect.organizationId,
        edge: { ...fixture.edge, issuedAt: "2026-06-12T00:00:00.001Z" },
        grants: fixture.grants
      },
      fixtureView(),
      { now }
    );
    expect(verdict).toEqual({ valid: false, reason: "relationship_signature_invalid" });
  });
});

type DelegatedFixture = {
  verifyAt: string;
  verifierId: string;
  userLog: KeyEvent[];
  serviceLog: KeyEvent[];
  sessionKeyRef: string;
  grants: Grant[];
  expect: {
    userId: string;
    serviceId: string;
    sessionKeyRef: string;
    rootGrantDigest: string;
    sessionGrantDigest: string;
    serviceGrantDigest: string;
    valid: boolean;
    abilities: string[];
  };
};

const delegated = JSON.parse(
  readFileSync(new URL("./fixtures/delegated-chain.json", import.meta.url), "utf8")
) as DelegatedFixture;

function delegatedView(): TrustView {
  const logs = new Map([delegated.userLog, delegated.serviceLog].map((log) => [log[0]!.id, log]));
  return {
    async getKeyLog(id) {
      return logs.get(id) ?? null;
    },
    async getRevocations() {
      return [];
    }
  };
}

/** Corrupts one byte of a multibase signature without breaking its shape. */
function flipSignatureByte(signature: string): string {
  const last = signature.slice(-1);
  return signature.slice(0, -1) + (last === "2" ? "3" : "2");
}

describe("committed delegated-chain conformance fixture (spec 011)", () => {
  const now = new Date(delegated.verifyAt);
  const [serviceGrant, sessionGrant, rootGrant] = delegated.grants as [Grant, Grant, Grant];

  it("pins the digests, proof links, and session KeyRef", () => {
    expect(canonicalDigest(rootGrant)).toBe(delegated.expect.rootGrantDigest);
    expect(canonicalDigest(sessionGrant)).toBe(delegated.expect.sessionGrantDigest);
    expect(canonicalDigest(serviceGrant)).toBe(delegated.expect.serviceGrantDigest);
    expect(sessionGrant.proof).toBe(delegated.expect.rootGrantDigest);
    expect(serviceGrant.proof).toBe(delegated.expect.sessionGrantDigest);
    expect(sessionGrant.audienceId).toBe(delegated.expect.sessionKeyRef);
    expect(serviceGrant.issuerId).toBe(delegated.expect.sessionKeyRef);
  });

  it("verifies the user → session key → service chain from bytes alone", async () => {
    const verdict = await verifyGrantChain(delegated.grants, delegatedView(), {
      now,
      verifierId: delegated.verifierId
    });
    expect(verdict).toEqual({
      valid: delegated.expect.valid,
      subjectId: delegated.expect.userId,
      audienceId: delegated.expect.serviceId,
      abilities: delegated.expect.abilities
    });
  });

  it("rejects the chain when a byte of the session-key-issued link's signature flips", async () => {
    const tampered = {
      ...serviceGrant,
      signature: [flipSignatureByte(serviceGrant.signature[0]!)]
    };
    const verdict = await verifyGrantChain([tampered, sessionGrant, rootGrant], delegatedView(), {
      now,
      verifierId: delegated.verifierId
    });
    expect(verdict).toEqual({ valid: false, reason: "grant_key_issuer_signature_invalid" });
  });

  it("rejects the chain when a byte of the session-key link's signature flips", async () => {
    const tampered = {
      ...sessionGrant,
      signature: [flipSignatureByte(sessionGrant.signature[0]!)]
    };
    const verdict = await verifyGrantChain([serviceGrant, tampered, rootGrant], delegatedView(), {
      now,
      verifierId: delegated.verifierId
    });
    // Spec 015 S4: a verifier MUST NOT compare a digest to a `proof` pointer "as proof of
    // chaining" until the record's own signature set has been checked and accepted. The
    // resolver therefore checks this link's set first, and the flipped byte is caught there —
    // `grant_signature_invalid` — so the child's `proof` comparison is never reached.
    //
    // That order is normative rather than an optimisation, and the reason is the reason S4
    // exists: `digest(parent) == proof` asserts nothing about an unverified parent, and
    // `grant_proof_mismatch` (what this reported before) names the CHILD's pointer for a fault
    // lying entirely in the parent. The property under test is unchanged: a flipped byte
    // anywhere in a parent link is caught and the chain refused.
    expect(verdict).toEqual({ valid: false, reason: "grant_signature_invalid" });
  });

  it("rejects the chain when the leaf's abilities widen", async () => {
    const widened = { ...serviceGrant, abilities: ["msg/send", "directory"] };
    const verdict = await verifyGrantChain([widened, sessionGrant, rootGrant], delegatedView(), {
      now,
      verifierId: delegated.verifierId
    });
    expect(verdict).toEqual({ valid: false, reason: "grant_ability_escalation" });
  });

  it("rejects the chain when the leaf's aud widens", async () => {
    const widened = {
      ...serviceGrant,
      caveats: { aud: [delegated.expect.serviceId, delegated.expect.userId] }
    };
    const verdict = await verifyGrantChain([widened, sessionGrant, rootGrant], delegatedView(), {
      now,
      verifierId: delegated.verifierId
    });
    expect(verdict).toEqual({ valid: false, reason: "grant_aud_escalation" });
  });
});

type AudlessFixture = {
  verifyAt: string;
  userLog: KeyEvent[];
  appLog: KeyEvent[];
  serviceLog: KeyEvent[];
  grants: Grant[];
  expect: {
    userId: string;
    appId: string;
    serviceId: string;
    rootGrantDigest: string;
    leafGrantDigest: string;
    valid: boolean;
    abilities: string[];
    requireAudReason: string;
  };
};

const audless = JSON.parse(
  readFileSync(new URL("./fixtures/audless-chain.json", import.meta.url), "utf8")
) as AudlessFixture;

function audlessView(): TrustView {
  const logs = new Map(
    [audless.userLog, audless.appLog, audless.serviceLog].map((log) => [log[0]!.id, log])
  );
  return {
    async getKeyLog(id) {
      return logs.get(id) ?? null;
    },
    async getRevocations() {
      return [];
    }
  };
}

describe("committed aud-less-chain conformance fixture (spec 011)", () => {
  const now = new Date(audless.verifyAt);
  const accepted = {
    valid: audless.expect.valid,
    subjectId: audless.expect.userId,
    audienceId: audless.expect.serviceId,
    abilities: audless.expect.abilities
  };

  it("pins the digests and the absence of an aud caveat on every link", () => {
    expect(canonicalDigest(audless.grants[1]!)).toBe(audless.expect.rootGrantDigest);
    expect(canonicalDigest(audless.grants[0]!)).toBe(audless.expect.leafGrantDigest);
    expect(audless.grants[0]!.proof).toBe(audless.expect.rootGrantDigest);
    for (const grant of audless.grants) {
      expect(grant.caveats["aud"]).toBeUndefined();
    }
  });

  it("verifies from bytes alone at any verifier id — an aud-less chain restricts none", async () => {
    expect(await verifyGrantChain(audless.grants, audlessView(), { now })).toEqual(accepted);
    expect(
      await verifyGrantChain(audless.grants, audlessView(), {
        now,
        verifierId: audless.expect.serviceId
      })
    ).toEqual(accepted);
    expect(
      await verifyGrantChain(audless.grants, audlessView(), {
        now,
        verifierId: audless.expect.appId
      })
    ).toEqual(accepted);
  });

  it("is rejected from the same bytes by a verifier that demands audience binding", async () => {
    const verdict = await verifyGrantChain(audless.grants, audlessView(), {
      now,
      verifierId: audless.expect.serviceId,
      requireAud: true
    });
    expect(verdict).toEqual({ valid: false, reason: audless.expect.requireAudReason });
  });
});

type FinancialFixture = {
  verifyAt: string;
  treasuryLog: KeyEvent[];
  opsLog: KeyEvent[];
  agentLog: KeyEvent[];
  grants: Grant[];
  conformingAction: FinancialAction;
  overAmountAction: FinancialAction;
  expect: {
    treasuryId: string;
    opsId: string;
    agentId: string;
    rootGrantDigest: string;
    leafGrantDigest: string;
    caveats: Record<string, unknown>;
    valid: boolean;
    abilities: string[];
    overAmountReason: string;
    noEvaluatorReason: string;
    raisedCapReason: string;
  };
};

const financial = JSON.parse(
  readFileSync(new URL("./fixtures/financial-chain.json", import.meta.url), "utf8")
) as FinancialFixture;

function financialView(): TrustView {
  const logs = new Map(
    [financial.treasuryLog, financial.opsLog, financial.agentLog].map((log) => [log[0]!.id, log])
  );
  return {
    async getKeyLog(id) {
      return logs.get(id) ?? null;
    },
    async getRevocations() {
      return [];
    }
  };
}

describe("committed financial-caveat conformance fixture (spec 009 fail-closed caveats)", () => {
  const now = new Date(financial.verifyAt);
  const [financialLeaf, financialRoot] = financial.grants as [Grant, Grant];
  const accepted = {
    valid: financial.expect.valid,
    subjectId: financial.expect.treasuryId,
    audienceId: financial.expect.agentId,
    abilities: financial.expect.abilities
  };

  it("pins the digests, the proof link, and the exact caveat bytes under signature", () => {
    expect(canonicalDigest(financialRoot)).toBe(financial.expect.rootGrantDigest);
    expect(canonicalDigest(financialLeaf)).toBe(financial.expect.leafGrantDigest);
    expect(financialLeaf.proof).toBe(financial.expect.rootGrantDigest);
    expect(financialLeaf.caveats).toEqual(financial.expect.caveats);
    // The bound lives on the leaf alone; the root delegates unbounded payment authority.
    expect(financialRoot.caveats).toEqual({});
  });

  it("verifies the capped chain from bytes alone for the committed conforming action", async () => {
    const verdict = await verifyGrantChain(financial.grants, financialView(), {
      now,
      evaluateCaveats: createFinancialCaveatEvaluator(financial.conformingAction)
    });
    expect(verdict).toEqual(accepted);
  });

  it("rejects the committed action one minor unit over the cap, for the committed reason", async () => {
    const verdict = await verifyGrantChain(financial.grants, financialView(), {
      now,
      evaluateCaveats: createFinancialCaveatEvaluator(financial.overAmountAction)
    });
    expect(verdict).toEqual({ valid: false, reason: financial.expect.overAmountReason });
  });

  it("rejects the same bytes when no evaluator is supplied — caveats fail closed", async () => {
    const verdict = await verifyGrantChain(financial.grants, financialView(), { now });
    expect(verdict).toEqual({ valid: false, reason: financial.expect.noEvaluatorReason });
  });

  it("rejects the chain when one byte of a caveat value is flipped to raise the cap", async () => {
    // "1000.00" -> "9000.00": a single digit, and the most valuable one an attacker could
    // change. The evaluator would happily approve the conforming action against the raised
    // cap — so what refuses it is not the caveat logic but the SIGNATURE: caveats are
    // covered by the leaf's signature, and a self-service raise is a forgery. That
    // ordering is the property under test. (Lowering the cap instead would be caught by
    // the evaluator first and would prove nothing about whether caveats are signed.)
    const raised = {
      ...financialLeaf,
      caveats: { ...financialLeaf.caveats, maxAmount: "9000.00" }
    };
    const verdict = await verifyGrantChain([raised, financialRoot], financialView(), {
      now,
      evaluateCaveats: createFinancialCaveatEvaluator(financial.conformingAction)
    });
    expect(verdict).toEqual({ valid: false, reason: financial.expect.raisedCapReason });
  });
});
