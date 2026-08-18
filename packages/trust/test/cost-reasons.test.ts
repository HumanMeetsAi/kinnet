/**
 * The cost-reason lists, checked from BOTH sides.
 *
 * Spec 003 makes a verification-work ceiling a local resource policy rather than a validity
 * rule, so every surface above this module has to tell "I declined to spend enough" apart from
 * "this record is invalid". That only works while the list of cost reasons is the whole list,
 * and while every entry on it is a reason something actually returns. It was not whole:
 * `@kinnet/verify`'s copy named one of `verifyGrantChain`'s two exhaustion exits, and the
 * missing one reached a node surface as a malformed record.
 *
 * COMPLETENESS is a compile-time guarantee and deliberately not tested here.
 * `ChainCostReasonsAreClassified` / `CostReasonsAreClassified` in `src/resolver.ts` fail to
 * compile if a cost-shaped member of the reason union is missing from its list, and `invalid`
 * plus the narrowed verdict types mean a new reason cannot be produced without joining that
 * union — by a literal, a bare `{ valid: false, reason }` object, or a template string. A regex
 * over one file's source cannot do that job — three separate evasions walk through it (string
 * concatenation, a bare object literal, and moving the literal to another file); the type system
 * does not have that hole.
 *
 * SOUNDNESS is what these tests check, because no type can: every listed reason is DRIVEN out
 * of a real verification. A list entry that nothing produces is dead classification — it makes
 * a surface claim to handle a condition it will never see — and, unlike a set-equality
 * assertion over a scan, a failure here names the reason that could not be reached rather than
 * inviting the reader to delete it.
 */
import { createIdentity, keyLogAnchor, signRecord, signThresholdRecord } from "@kinnet/crypto";
import type { Claim, Grant, Relationship } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  GRANT_CHAIN_COST_REASONS,
  REPRESENTS_PREDICATE,
  TRUST_COST_REASONS,
  verifyClaim,
  verifyGrantChain,
  verifyRepresentsChain,
  type TrustView
} from "../src/index.js";

const NOW = new Date("2026-06-12T00:00:00.000Z");
const ISSUED_AT = new Date(NOW.getTime() - 11 * 86_400_000).toISOString();

const seed = (fill: number) => new Uint8Array(32).fill(fill);
const issuer = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
const agent = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });

const view: TrustView = {
  async getKeyLog(id) {
    return [issuer, agent].find((identity) => identity.id === id)?.log ?? null;
  },
  async getRevocations() {
    return [];
  }
};

const rootGrant = (): Grant =>
  signThresholdRecord(
    {
      subjectId: issuer.id,
      issuerId: issuer.id,
      audienceId: agent.id,
      abilities: ["msg"],
      caveats: {},
      anchor: keyLogAnchor(issuer.log),
      proof: null,
      issuedAt: ISSUED_AT
    },
    [issuer.currentKeys[0]!.secretKey]
  ) as Grant;

const claim = (): Claim =>
  signRecord(
    {
      id: "claim-1",
      subjectId: issuer.id,
      claimType: "domain",
      value: "acme.example",
      issuedBy: issuer.id,
      issuedAt: ISSUED_AT
    },
    issuer.currentKeys[0]!.secretKey
  ) as Claim;

const representsEdge = (): Relationship =>
  signRecord(
    {
      id: "edge-1",
      subjectId: agent.id,
      objectId: issuer.id,
      predicate: REPRESENTS_PREDICATE,
      issuedBy: issuer.id,
      issuedAt: ISSUED_AT
    },
    issuer.currentKeys[0]!.secretKey
  ) as Relationship;

const reasonOf = (verdict: { valid: boolean } & Partial<{ reason: string }>): string =>
  verdict.valid ? "<valid>" : (verdict.reason ?? "<none>");

/**
 * Each reason, and a verification that reaches it. Every identity here holds a one-event 1-of-1
 * log, so one replay costs exactly one verification — which is what lets a budget of 0 land in
 * the REPLAY and a budget of 1 land in the SIGNATURE SEARCH that follows it.
 */
const reachable: Record<string, () => Promise<string>> = {
  grant_issuer_key_log_too_expensive: async () =>
    reasonOf(await verifyGrantChain([rootGrant()], view, { now: NOW, budget: { remaining: 0 } })),
  grant_signature_check_too_expensive: async () =>
    reasonOf(await verifyGrantChain([rootGrant()], view, { now: NOW, budget: { remaining: 1 } })),
  issuer_key_log_too_expensive: async () =>
    reasonOf(await verifyClaim(claim(), view, { now: NOW, budget: { remaining: 0 } })),
  agent_key_log_too_expensive: async () =>
    reasonOf(
      await verifyRepresentsChain(
        { agentId: agent.id, organizationId: issuer.id, edge: representsEdge() },
        view,
        { now: NOW, budget: { remaining: 0 } }
      )
    )
};

describe("cost reasons are sound — every listed reason is reachable", () => {
  /**
   * WATCHED TO FAIL: add an entry to `TRUST_COST_REASONS` naming a reason no exit produces (it
   * must also be added to the reason union, or it will not compile). This fails naming that
   * reason as unreachable, rather than pointing at a set difference whose obvious fix is to
   * delete a real entry.
   */
  it.each([...TRUST_COST_REASONS])("%s is produced by a real verification", async (reason) => {
    const drive = reachable[reason];
    expect(
      drive,
      `${reason} is listed in TRUST_COST_REASONS but this test knows no verification that reaches it — either it is dead classification, or add the fixture that drives it`
    ).toBeDefined();
    expect(await drive!()).toBe(reason);
  });

  it("the grant-chain subset is reachable from verifyGrantChain specifically", async () => {
    // Not merely a subset of the larger list: these are the two the record-unit verifier maps,
    // and each has to be reachable from the chain verifier rather than from some other entry
    // point that happens to share a spelling.
    for (const reason of GRANT_CHAIN_COST_REASONS) {
      expect(TRUST_COST_REASONS as readonly string[]).toContain(reason);
      expect(await reachable[reason]!()).toBe(reason);
    }
    expect(GRANT_CHAIN_COST_REASONS.length).toBe(2);
    expect(TRUST_COST_REASONS.length).toBeGreaterThan(GRANT_CHAIN_COST_REASONS.length);
  });

  it("every listed reason is recognizable as a cost reason by shape", () => {
    for (const reason of TRUST_COST_REASONS) {
      expect(reason.endsWith("_too_expensive")).toBe(true);
    }
  });
});
