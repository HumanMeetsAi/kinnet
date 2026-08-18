import {
  canonicalBytes,
  canonicalDigest,
  commitToKeyState,
  createIdentity,
  deriveParticipantId,
  encodeKeyRef,
  encodeSignature,
  eventDigest,
  generateKeyPair,
  keyLogAnchor,
  rotateIdentity,
  sign,
  signRecord,
  signThresholdRecord,
  type Identity
} from "@kinnet/crypto";
import {
  MAX_GRANT_CHAIN_LINKS,
  MAX_KEY_LOG_EVENTS,
  type Claim,
  type KeyEvent,
  type Grant,
  type ParticipantId,
  type Principal,
  type Relationship,
  type Revocation
} from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  abilityCovers,
  beginVerificationOperation,
  createVerificationContext,
  REPRESENTS_PREDICATE,
  verifyClaim,
  verifyGrantChain,
  verifyRelationship,
  verifyRepresentsChain,
  verificationWorkOptions,
  VerificationOperationMismatch,
  type TrustView
} from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const NOW = new Date("2026-06-12T00:00:00.000Z");
const ISSUED_AT = new Date(NOW.getTime() - 11 * 86_400_000).toISOString();
const PAST = new Date(NOW.getTime() - 2 * 86_400_000).toISOString();
const FUTURE = new Date(NOW.getTime() + 19 * 86_400_000).toISOString();

const org = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
const admin = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
const agent = createIdentity({ currentSeed: seed(5), nextSeed: seed(6) });
const attacker = createIdentity({ currentSeed: seed(7), nextSeed: seed(8) });

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

function domainClaim(signer: Identity, overrides: Record<string, unknown> = {}): Claim {
  return signRecord(
    {
      id: "claim-domain-1",
      subjectId: org.id,
      claimType: "domain",
      value: "acme.example",
      issuedBy: org.id,
      issuedAt: ISSUED_AT,
      ...overrides
    },
    signer.currentKeys[0]!.secretKey
  ) as Claim;
}

function representsEdge(signer: Identity, overrides: Record<string, unknown> = {}): Relationship {
  return signRecord(
    {
      id: "rel-represents-1",
      subjectId: agent.id,
      predicate: "represents",
      objectId: org.id,
      issuedBy: org.id,
      issuedAt: ISSUED_AT,
      ...overrides
    },
    signer.currentKeys[0]!.secretKey
  ) as Relationship;
}

type GrantFields = {
  subjectId: ParticipantId;
  issuerId: Principal;
  audienceId: Principal;
  abilities: string[];
  proof: string | null;
  caveats?: Record<string, unknown>;
  expiresAt?: string;
  /**
   * Spec 016's anchor. Defaulted by {@link makeGrant} to the SIGNER's log tip, which is the
   * honest value whenever signer and issuer are the same participant; a test that signs one
   * participant's grant with another's keys passes the issuer's anchor explicitly, so the
   * verdict it pins is a signature failure rather than an unknown anchor.
   *
   * Left out entirely for a bare-key issuer: 016 forbids the field there and `grantSchema`
   * rejects a key-issued link that carries one.
   */
  anchor?: string;
};

function isParticipantId(principal: Principal): boolean {
  return principal.startsWith("pk_");
}

function signGrant(fields: GrantFields, secretKeys: Uint8Array[]): Grant {
  return signThresholdRecord({ caveats: {}, issuedAt: ISSUED_AT, ...fields }, secretKeys) as Grant;
}

function makeGrant(signer: Identity, fields: GrantFields): Grant {
  const anchored: GrantFields =
    fields.anchor !== undefined || !isParticipantId(fields.issuerId)
      ? fields
      : { ...fields, anchor: keyLogAnchor(signer.log) };
  return signGrant(anchored, [signer.currentKeys[0]!.secretKey]);
}

function revoke(
  signer: Identity,
  issuerId: ParticipantId,
  digest: string,
  anchor = keyLogAnchor(signer.log)
): Revocation {
  return signThresholdRecord({ revokes: digest, issuerId, anchor, revokedAt: PAST }, [
    signer.currentKeys[0]!.secretKey
  ]) as Revocation;
}

/** Root grant: the organization self-issues its authority to the admin. */
function rootGrant(overrides: Partial<Parameters<typeof makeGrant>[1]> = {}): Grant {
  return makeGrant(org, {
    subjectId: org.id,
    issuerId: org.id,
    audienceId: admin.id,
    abilities: ["directory"],
    proof: null,
    ...overrides
  });
}

/** Leaf grant: the admin attenuates the organization's authority down to the agent. */
function leafGrant(parent: Grant, overrides: Partial<Parameters<typeof makeGrant>[1]> = {}): Grant {
  return makeGrant(admin, {
    subjectId: org.id,
    issuerId: admin.id,
    audienceId: agent.id,
    abilities: ["directory/curate"],
    proof: canonicalDigest(parent),
    ...overrides
  });
}

describe("verification-budget normalization at public trust boundaries", () => {
  const validView = makeView([org, admin, agent]);
  const root = rootGrant();

  function withMaximum(value: unknown): TrustView {
    return { ...validView, maxSignatureVerifications: value as number };
  }

  it("preserves a missing custom-view maximum as the legacy unbudgeted behavior", async () => {
    expect(await verifyClaim(domainClaim(org), validView, { now: NOW })).toEqual({ valid: true });
    expect(await verifyRelationship(representsEdge(org), validView, { now: NOW })).toEqual({
      valid: true
    });
    expect(await verifyGrantChain([root], validView, { now: NOW })).toMatchObject({ valid: true });
    expect(
      await verifyRepresentsChain(
        { agentId: agent.id, organizationId: org.id, edge: representsEdge(org) },
        validView,
        { now: NOW }
      )
    ).toMatchObject({ valid: true });
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 1.5, "7"])(
    "fails closed when a custom view defines malformed maxSignatureVerifications=%s",
    async (value) => {
      expect(await verifyGrantChain([root], withMaximum(value), { now: NOW })).toEqual({
        valid: false,
        reason: "grant_issuer_key_log_too_expensive"
      });
    }
  );

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 1.5, "7"])(
    "normalizes an explicitly supplied malformed remaining=%s to zero on the caller object",
    async (value) => {
      const budget = { remaining: value } as unknown as { remaining: number };
      expect(await verifyGrantChain([root], validView, { now: NOW, budget })).toEqual({
        valid: false,
        reason: "grant_issuer_key_log_too_expensive"
      });
      expect(budget.remaining).toBe(0);
    }
  );

  it("fails closed at every public entry family without replacing the caller-owned budget", async () => {
    const cases = [
      {
        run: (budget: { remaining: number }) =>
          verifyClaim(domainClaim(org), validView, { now: NOW, budget }),
        reason: "issuer_key_log_too_expensive"
      },
      {
        run: (budget: { remaining: number }) =>
          verifyRelationship(representsEdge(org), validView, { now: NOW, budget }),
        reason: "issuer_key_log_too_expensive"
      },
      {
        run: (budget: { remaining: number }) =>
          verifyGrantChain([root], validView, { now: NOW, budget }),
        reason: "grant_issuer_key_log_too_expensive"
      },
      {
        run: (budget: { remaining: number }) =>
          verifyRepresentsChain(
            { agentId: agent.id, organizationId: org.id, edge: representsEdge(org) },
            validView,
            { now: NOW, budget }
          ),
        reason: "agent_key_log_too_expensive"
      }
    ];

    for (const testCase of cases) {
      const budget = { remaining: Number.NaN };
      const sameObject = budget;
      expect(await testCase.run(budget)).toEqual({ valid: false, reason: testCase.reason });
      expect(budget).toBe(sameObject);
      expect(budget.remaining).toBe(0);
    }
  });
});

describe("verification-operation ownership", () => {
  it("gives context precedence and charges overlapping local/outer/candidate objects once", () => {
    const view = { ...makeView([org]), maxSignatureVerifications: 9 };
    const outer = { remaining: 7 };
    const legacy = { remaining: 99 };
    const context = createVerificationContext(outer);
    const operation = beginVerificationOperation(view, { context, budget: legacy });
    const work = verificationWorkOptions(operation, outer);
    expect(work.maxSignatureVerifications).toBe(7);
    work.onSignatureVerifications!(3);
    expect(operation.local?.remaining).toBe(6);
    expect(outer.remaining).toBe(4);
    expect(legacy.remaining).toBe(99);

    const localAndCandidate = { remaining: 5 };
    const bare = beginVerificationOperation(view, { budget: localAndCandidate });
    verificationWorkOptions(bare, localAndCandidate).onSignatureVerifications!(2);
    expect(localAndCandidate.remaining).toBe(3);
  });

  it("normalizes a malformed explicit context in place and never refills exhausted zero", () => {
    const budget = { remaining: Number.NaN };
    const context = createVerificationContext(budget);
    expect(context.budget).toBe(budget);
    expect(budget.remaining).toBe(0);
    const operation = beginVerificationOperation(makeView([org]), { context });
    expect(verificationWorkOptions(operation).maxSignatureVerifications).toBe(0);
    beginVerificationOperation(makeView([org]), { context });
    expect(budget.remaining).toBe(0);
  });

  it("rejects reuse against a foreign view before that view can reuse signer state", async () => {
    const good = makeView([org]);
    const absent = makeView([]);
    const context = createVerificationContext({ remaining: 100 });
    const operation = beginVerificationOperation(good, { context });

    expect(await verifyClaim(domainClaim(org), good, { context, operation, now: NOW })).toEqual({
      valid: true
    });
    await expect(
      verifyClaim(domainClaim(org), absent, { context, operation, now: NOW })
    ).rejects.toBeInstanceOf(VerificationOperationMismatch);
  });

  it("rejects an operation paired with a different outer context", async () => {
    const view = makeView([org]);
    const original = createVerificationContext({ remaining: 100 });
    const foreign = createVerificationContext({ remaining: 100 });
    const operation = beginVerificationOperation(view, { context: original });

    await expect(
      verifyClaim(domainClaim(org), view, { context: foreign, operation, now: NOW })
    ).rejects.toBeInstanceOf(VerificationOperationMismatch);
    expect(original.budget.remaining).toBe(100);
    expect(foreign.budget.remaining).toBe(100);
  });

  it("coalesces concurrent signer resolution but evicts a failed promise", async () => {
    let reads = 0;
    let release: ((events: KeyEvent[]) => void) | undefined;
    const firstRead = new Promise<KeyEvent[]>((resolve) => {
      release = resolve;
    });
    const view: TrustView = {
      async getKeyLog() {
        reads += 1;
        if (reads === 1) return firstRead;
        if (reads === 2) throw new Error("transient discovery failure");
        return org.log;
      },
      async getRevocations() {
        return [];
      }
    };
    const context = createVerificationContext({ remaining: 100 });
    const claim = domainClaim(org);

    const one = verifyClaim(claim, view, { context, now: NOW });
    const two = verifyClaim(claim, view, { context, now: NOW });
    await Promise.resolve();
    expect(reads).toBe(1);
    release!(org.log);
    await expect(Promise.all([one, two])).resolves.toEqual([{ valid: true }, { valid: true }]);

    // A successful resolution remains cached, so use a fresh context to exercise rejection
    // eviction. The rejected promise must not poison the following funded retry.
    const retryContext = createVerificationContext({ remaining: 100 });
    await expect(verifyClaim(claim, view, { context: retryContext, now: NOW })).rejects.toThrow(
      "transient discovery failure"
    );
    await expect(verifyClaim(claim, view, { context: retryContext, now: NOW })).resolves.toEqual({
      valid: true
    });
    expect(reads).toBe(3);
  });
});

describe("claim verification (specs 001/003/008)", () => {
  const view = makeView([org, agent, attacker]);

  it("accepts a well-signed, unexpired, unrevoked claim", async () => {
    expect(await verifyClaim(domainClaim(org), view, { now: NOW })).toEqual({ valid: true });
  });

  it("rejects a tampered claim", async () => {
    const claim = { ...domainClaim(org), value: "evil.example" };
    expect(await verifyClaim(claim, view, { now: NOW })).toEqual({
      valid: false,
      reason: "claim_signature_invalid"
    });
  });

  it("rejects a claim forged by a key that is not the issuer's", async () => {
    expect(await verifyClaim(domainClaim(attacker), view, { now: NOW })).toEqual({
      valid: false,
      reason: "claim_signature_invalid"
    });
  });

  it("rejects an expired claim", async () => {
    const claim = domainClaim(org, { expiresAt: PAST });
    expect(await verifyClaim(claim, view, { now: NOW })).toEqual({
      valid: false,
      reason: "claim_expired"
    });
  });

  it("rejects a claim whose issuer has no resolvable key log", async () => {
    expect(await verifyClaim(domainClaim(org), makeView([agent]), { now: NOW })).toEqual({
      valid: false,
      reason: "issuer_key_log_unresolved"
    });
  });

  it("rejects malformed claims before touching the network", async () => {
    const claim = { ...domainClaim(org), issuedBy: "not-an-id" } as unknown as Claim;
    expect(await verifyClaim(claim, view, { now: NOW })).toEqual({
      valid: false,
      reason: "claim_malformed"
    });
  });

  it("rejects a claim revoked by its issuer", async () => {
    const claim = domainClaim(org);
    const revoked = makeView([org], [revoke(org, org.id, canonicalDigest(claim))]);
    expect(await verifyClaim(claim, revoked, { now: NOW })).toEqual({
      valid: false,
      reason: "claim_revoked"
    });
  });

  it("ignores a revocation forged in the issuer's name by another key", async () => {
    const claim = domainClaim(org);
    const forged = makeView([org, attacker], [revoke(attacker, org.id, canonicalDigest(claim))]);
    expect(await verifyClaim(claim, forged, { now: NOW })).toEqual({ valid: true });
  });

  it("ignores a revocation issued by a participant who is not the issuer", async () => {
    const claim = domainClaim(org);
    const unauthorized = makeView(
      [org, attacker],
      [revoke(attacker, attacker.id, canonicalDigest(claim))]
    );
    expect(await verifyClaim(claim, unauthorized, { now: NOW })).toEqual({ valid: true });
  });

  it("ignores a well-signed revocation from an issuer the view was not asked about", async () => {
    // The targeted lookup narrows the candidates; it does not make the answer trusted. This
    // view is the hostile discovery host: asked about the claim's issuer, it answers with a
    // record from someone else — correctly signed by that someone else and naming the right
    // digest, so only the client-side membership check stands between it and a revoked
    // verdict. The record must be ignored, and ignoring it must not throw.
    const claim = domainClaim(org);
    const digest = canonicalDigest(claim);
    const unrequested = revoke(attacker, attacker.id, digest);
    const asked: string[][] = [];
    const logs = new Map([org, attacker].map((identity) => [identity.id, identity.log]));
    const hostileView: TrustView = {
      async getKeyLog(id) {
        return logs.get(id) ?? null;
      },
      async getRevocations(revokesDigest, issuerIds) {
        asked.push([...issuerIds]);
        return revokesDigest === digest ? [unrequested] : [];
      }
    };

    expect(await verifyClaim(claim, hostileView, { now: NOW })).toEqual({ valid: true });
    // The claim's issuer is the whole authorized set and is exactly what was asked for, so
    // the ignored record was demonstrably outside the requested set rather than merely absent.
    expect(asked).toEqual([[org.id]]);
  });

  it("throws when a view answers with more records than issuers were asked about", async () => {
    // Work has to be sized by the issuer set the verifier NAMED, not by what the server chose
    // to send: a hostile view answering a one-issuer question with a huge list would have every
    // record schema-parsed and every plausible one costing a key-log fetch. Only one revocation
    // per (issuer, digest) can exist, so a longer answer is malformed on its face.
    //
    // A THROW, specifically — not `valid: true` (which would let the amplification through) and
    // not a `valid: false` reason (which would report the record as revoked on a server's say-so
    // and hand any host a denial-of-verification button). It is the same failure class as an
    // unreachable view, and authorization consumers deny on it.
    const claim = domainClaim(org);
    const digest = canonicalDigest(claim);
    const oversized: Revocation[] = [
      revoke(org, org.id, digest),
      revoke(attacker, attacker.id, digest)
    ];
    const logs = new Map([org, attacker].map((identity) => [identity.id, identity.log]));
    const floodingView: TrustView = {
      async getKeyLog(id) {
        return logs.get(id) ?? null;
      },
      async getRevocations() {
        return oversized;
      }
    };

    // One issuer is authorized to revoke a claim — its own — so two records is one too many.
    await expect(verifyClaim(claim, floodingView, { now: NOW })).rejects.toThrow(
      /2 records for 1 requested issuers/
    );
  });

  it("keeps a claim valid after the issuer rotates keys", async () => {
    const claim = domainClaim(org);
    const rotated = rotateIdentity(org);
    expect(await verifyClaim(claim, makeView([rotated]), { now: NOW })).toEqual({ valid: true });
  });

  it("honors a revocation signed with the issuer's post-rotation keys", async () => {
    const claim = domainClaim(org);
    const rotated = rotateIdentity(org);
    const view = makeView([rotated], [revoke(rotated, org.id, canonicalDigest(claim))]);
    expect(await verifyClaim(claim, view, { now: NOW })).toEqual({
      valid: false,
      reason: "claim_revoked"
    });
  });
});

describe("represents-chain verification (the S1 gate)", () => {
  const view = makeView([org, admin, agent, attacker]);

  function chain(edge: Relationship, grants?: Grant[]) {
    return { agentId: agent.id, organizationId: org.id, edge, grants };
  }

  it("verifies an org → agent represents chain end to end", async () => {
    const verdict = await verifyRepresentsChain(chain(representsEdge(org)), view, { now: NOW });
    expect(verdict).toEqual({ valid: true, agentId: agent.id, organizationId: org.id });
  });

  it("rejects an edge the agent issued about itself", async () => {
    const edge = representsEdge(agent, { issuedBy: agent.id });
    const verdict = await verifyRepresentsChain(chain(edge), view, { now: NOW });
    expect(verdict).toEqual({ valid: false, reason: "edge_not_issued_by_represented" });
  });

  it("rejects an edge with the wrong predicate", async () => {
    const edge = representsEdge(org, { predicate: "memberOf" });
    const verdict = await verifyRepresentsChain(chain(edge), view, { now: NOW });
    expect(verdict).toEqual({ valid: false, reason: "edge_predicate_mismatch" });
  });

  it("rejects an edge about a different agent or organization", async () => {
    const wrongSubject = representsEdge(org, { subjectId: attacker.id });
    expect(await verifyRepresentsChain(chain(wrongSubject), view, { now: NOW })).toEqual({
      valid: false,
      reason: "edge_subject_mismatch"
    });

    const wrongObject = representsEdge(org, { objectId: attacker.id });
    expect(await verifyRepresentsChain(chain(wrongObject), view, { now: NOW })).toEqual({
      valid: false,
      reason: "edge_object_mismatch"
    });
  });

  it("rejects a tampered edge", async () => {
    const edge = { ...representsEdge(org), issuedAt: "2026-06-02T00:00:00.000Z" };
    const verdict = await verifyRepresentsChain(chain(edge), view, { now: NOW });
    expect(verdict).toEqual({ valid: false, reason: "relationship_signature_invalid" });
  });

  it("rejects an expired edge", async () => {
    const edge = representsEdge(org, { expiresAt: PAST });
    const verdict = await verifyRepresentsChain(chain(edge), view, { now: NOW });
    expect(verdict).toEqual({ valid: false, reason: "relationship_expired" });
  });

  it("rejects a revoked edge", async () => {
    const edge = representsEdge(org);
    const revokedView = makeView([org, admin, agent], [revoke(org, org.id, canonicalDigest(edge))]);
    const verdict = await verifyRepresentsChain(chain(edge), revokedView, { now: NOW });
    expect(verdict).toEqual({ valid: false, reason: "relationship_revoked" });
  });

  it("rejects a chain whose agent has no resolvable key log", async () => {
    const verdict = await verifyRepresentsChain(chain(representsEdge(org)), makeView([org]), {
      now: NOW
    });
    expect(verdict).toEqual({ valid: false, reason: "agent_key_log_unresolved" });
  });

  it("verifies a chain with a bounding grant chain and reports its abilities", async () => {
    const root = rootGrant();
    const verdict = await verifyRepresentsChain(
      chain(representsEdge(org), [leafGrant(root), root]),
      view,
      { now: NOW }
    );
    expect(verdict).toEqual({
      valid: true,
      agentId: agent.id,
      organizationId: org.id,
      abilities: ["directory/curate"]
    });
  });

  it("rejects a grant chain that does not delegate the organization's authority", async () => {
    const foreignRoot = makeGrant(admin, {
      subjectId: admin.id,
      issuerId: admin.id,
      audienceId: agent.id,
      abilities: ["directory/curate"],
      proof: null
    });
    const verdict = await verifyRepresentsChain(chain(representsEdge(org), [foreignRoot]), view, {
      now: NOW
    });
    expect(verdict).toEqual({ valid: false, reason: "grant_subject_not_organization" });
  });

  it("rejects a grant chain that ends at someone other than the agent", async () => {
    const root = rootGrant({ audienceId: attacker.id });
    const verdict = await verifyRepresentsChain(chain(representsEdge(org), [root]), view, {
      now: NOW
    });
    expect(verdict).toEqual({ valid: false, reason: "grant_audience_not_agent" });
  });
});

/**
 * The shared verification allowance added for chain verification.
 *
 * This whole area shipped once with no tests at all, and two defects followed directly from
 * that: honest multi-issuer input was refused, and a hostile revocation answer was never
 * charged. These tests exist to fail when the budget wiring is removed, not merely to
 * describe it.
 */
describe("chain verification allowance", () => {
  /** A real M-of-M identity of `events` events — the honest shape, built the honest way. */
  function committee(events: number, size: number, base: number): Identity {
    const currentKeys = Array.from({ length: size }, (_, i) => generateKeyPair(seed(base + i)));
    const nextKeys = Array.from({ length: size }, (_, i) => generateKeyPair(seed(base + 20 + i)));
    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: currentKeys.map((k) => encodeKeyRef(k.publicKey)),
      threshold: String(size),
      // The committee stays M-of-M across every rotation, so the committed next state carries
      // the same threshold — `rotateIdentity` below declares it and signs with exactly M keys.
      next: commitToKeyState(
        nextKeys.map((k) => encodeKeyRef(k.publicKey)),
        String(size)
      )
    };
    const id = deriveParticipantId(establishment);
    const unsigned = { ...establishment, id, prior: null };
    const inception = {
      ...unsigned,
      signature: currentKeys.map((k) =>
        encodeSignature(sign(canonicalBytes(unsigned), k.secretKey))
      )
    };
    let identity: Identity = {
      id,
      log: [inception],
      currentKeys,
      nextKeys,
      nextThreshold: String(size)
    };
    for (let index = 1; index < events; index += 1) {
      identity = rotateIdentity(identity);
    }
    return identity;
  }

  function viewOf(
    identities: Identity[],
    options: {
      maxSignatureVerifications?: number;
      revocations?: Revocation[];
      revocationsFor?: (digest: string, issuerIds: ParticipantId[]) => Revocation[];
    } = {}
  ): TrustView & { keyLogReads: number } {
    const logs = new Map(identities.map((i) => [i.id, i.log]));
    const view = {
      keyLogReads: 0,
      ...(options.maxSignatureVerifications === undefined
        ? {}
        : { maxSignatureVerifications: options.maxSignatureVerifications }),
      async getKeyLog(id: ParticipantId) {
        view.keyLogReads += 1;
        return logs.get(id) ?? null;
      },
      async getRevocations(digest: string, issuerIds: ParticipantId[]) {
        return options.revocationsFor
          ? options.revocationsFor(digest, issuerIds)
          : (options.revocations ?? []).filter(
              (r) => r.revokes === digest && issuerIds.includes(r.issuerId)
            );
      }
    };
    return view;
  }

  function grantFrom(issuer: Identity, overrides: Record<string, unknown>): Grant {
    return signThresholdRecord(
      {
        subjectId: issuer.id,
        issuerId: issuer.id,
        audienceId: issuer.id,
        abilities: ["directory"],
        caveats: {},
        anchor: keyLogAnchor(issuer.log),
        proof: null,
        issuedAt: PAST,
        ...overrides
      },
      issuer.currentKeys.map((k) => k.secretKey)
    ) as Grant;
  }

  it("verifies an honest multi-issuer chain of full-length logs", async () => {
    // Three honest 2-of-2 identities at the schema's maximum log length. Under spec 015's
    // greedy forward walk an event costs at most one verification per LISTED KEY whatever its
    // signature count, and a 2-of-2 event costs exactly 2 — member i is assigned key i on its
    // first try — so each log replays for 128 x 2 = 256 and the three cost 768 between them.
    const a = committee(MAX_KEY_LOG_EVENTS, 2, 1);
    const b = committee(MAX_KEY_LOG_EVENTS, 2, 60);
    const c = committee(MAX_KEY_LOG_EVENTS, 2, 120);

    const root = grantFrom(a, { audienceId: b.id });
    const mid = signThresholdRecord(
      {
        subjectId: a.id,
        issuerId: b.id,
        audienceId: c.id,
        abilities: ["directory"],
        caveats: {},
        anchor: keyLogAnchor(b.log),
        proof: canonicalDigest(root),
        issuedAt: PAST
      },
      b.currentKeys.map((k) => k.secretKey)
    ) as Grant;
    const leaf = signThresholdRecord(
      {
        subjectId: a.id,
        issuerId: c.id,
        audienceId: a.id,
        abilities: ["directory/curate"],
        caveats: {},
        anchor: keyLogAnchor(c.log),
        proof: canonicalDigest(mid),
        issuedAt: PAST
      },
      c.currentKeys.map((k) => k.secretKey)
    ) as Grant;

    // 774 MEASURED, by running this chain against an allowance far above what it can spend and
    // reading the shared budget's drawdown: 3 x 256 to replay the logs, plus 2 per link to
    // check it against its issuer's newest key state (2 keys, one verification each). The
    // signature checks are metered too, which is what makes the allowance a bound on the
    // REQUEST rather than only on replay.
    const view = viewOf([a, b, c], { maxSignatureVerifications: 774 });
    expect(await verifyGrantChain([leaf, mid, root], view, { now: NOW })).toEqual({
      valid: true,
      subjectId: a.id,
      audienceId: a.id,
      abilities: ["directory/curate"]
    });

    // One verification short — 773, also measured, not inferred — it is refused, and refused
    // LOUDLY, as a cost condition rather than as a bad signature or a missing log, so an
    // operator meeting a real multi-signature participant raises the allowance instead of
    // debugging an "unresolved". The pair is what makes 774 the chain's cost rather than merely
    // an allowance it happens to fit under.
    const starved = viewOf([a, b, c], { maxSignatureVerifications: 773 });
    const verdict = await verifyGrantChain([leaf, mid, root], starved, { now: NOW });
    expect(verdict.valid).toBe(false);
    expect(verdict).toHaveProperty("reason");
    expect((verdict as { reason: string }).reason).toMatch(/_too_expensive$/);
  }, 60_000);

  it("reports an unaffordable log distinguishably from a missing or invalid one", async () => {
    const a = committee(20, 8, 1);
    const root = grantFrom(a, { audienceId: a.id });

    // Affordable: the allowance covers it.
    const affordable = viewOf([a], { maxSignatureVerifications: 4096 });
    expect((await verifyGrantChain([root], affordable, { now: NOW })).valid).toBe(true);

    // Same chain, same log, an allowance that cannot pay for it. This is a COST refusal and
    // spec 003 requires it be distinguishable from "invalid" — a publisher told
    // `..._unresolved` goes and re-publishes a log that was never wrong.
    const starved = viewOf([a], { maxSignatureVerifications: 1 });
    expect(await verifyGrantChain([root], starved, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_issuer_key_log_too_expensive"
    });

    // A genuinely absent log keeps the original reason, so the two stay separable.
    const empty = viewOf([], { maxSignatureVerifications: 4096 });
    expect(await verifyGrantChain([root], empty, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_issuer_key_log_unresolved"
    });
  }, 30_000);

  it("gives each verification its own allowance, so one cannot starve the next", async () => {
    const a = committee(12, 8, 1);
    const root = grantFrom(a, { audienceId: a.id });
    // Sized to fit one verification of this chain and no more. If the allowance leaked across
    // calls, the second would be refused.
    const view = viewOf([a], { maxSignatureVerifications: 12 * ((8 * 9) / 2) + 64 });

    expect((await verifyGrantChain([root], view, { now: NOW })).valid).toBe(true);
    expect((await verifyGrantChain([root], view, { now: NOW })).valid).toBe(true);
    expect((await verifyGrantChain([root], view, { now: NOW })).valid).toBe(true);
  }, 30_000);

  // The round-6 "sticky cause" test lived here and was vacuous: it asked about the MISSING
  // issuer first, so no latch could have been set, and it passed with stickiness fully
  // restored. Deleted rather than repaired, because the property is now structural: the cause
  // is returned per call from `resolveSignerStates` and cached with the result, so there is no
  // shared mutable flag for a later lookup to inherit. A test that mutates the code back to a
  // latch would be testing a shape that no longer exists.

  it("accepts a log that re-lists a key set, and judges each record at its own anchor", async () => {
    // THIS TEST REPLACES "refuses a log that re-lists a key set", whose premise spec 016 has
    // retired. 003's interim "No two states may share a quorum" required
    // `|keys(A) n keys(B)| < min(t_A, t_B)` for every pair of committed states, so a log that
    // re-revealed its own key set was rejected. 016 removes the rule: the keyless cross-state
    // edits it protected against are closed by anchoring instead — a signature-set record names
    // the ONE state it is judged against — so a re-listed state costs a verifier nothing and the
    // rotation flexibility comes back.
    //
    // Five events, two distinct key sets: events 1-4 all list `repeatedKey`. What the replay
    // must now do is ACCEPT it, and what the resolver must do is judge each record against the
    // state its anchor names — which for the two revocations below is two DIFFERENT events
    // carrying identical `(keys, threshold)`, distinguishable only by digest.
    const first = generateKeyPair(seed(40));
    const repeatedKey = generateKeyPair(seed(41));
    const repeatedRefs = [encodeKeyRef(repeatedKey.publicKey)];
    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: [encodeKeyRef(first.publicKey)],
      threshold: "1",
      next: commitToKeyState(repeatedRefs, "1")
    };
    const id = deriveParticipantId(establishment);
    const unsigned0 = { ...establishment, id, prior: null };
    const log: KeyEvent[] = [
      {
        ...unsigned0,
        signature: [encodeSignature(sign(canonicalBytes(unsigned0), first.secretKey))]
      }
    ];
    for (let seq = 1; seq <= 4; seq += 1) {
      const unsigned = {
        id,
        seq: String(seq),
        prior: eventDigest(log[seq - 1]!),
        kind: "rot" as const,
        keys: repeatedRefs,
        threshold: "1",
        next: commitToKeyState(repeatedRefs, "1")
      };
      log.push({
        ...unsigned,
        signature: [encodeSignature(sign(canonicalBytes(unsigned), repeatedKey.secretKey))]
      });
    }
    const issuer = { id, currentKeys: [first] };

    const viewOfLog = (
      events: KeyEvent[],
      revocations: Revocation[] = []
    ): TrustView & { keyLogReads: number } => {
      const view: TrustView & { keyLogReads: number } = {
        keyLogReads: 0,
        maxSignatureVerifications: 4096,
        async getKeyLog() {
          view.keyLogReads += 1;
          return events;
        },
        async getRevocations(digest, issuerIds) {
          return revocations.filter((r) => r.revokes === digest && issuerIds.includes(r.issuerId));
        }
      };
      return view;
    };

    const claim = signRecord(
      {
        id: "claim-dedup-1",
        subjectId: issuer.id,
        claimType: "domain",
        value: "dedup.example",
        issuedBy: issuer.id,
        issuedAt: ISSUED_AT
      },
      issuer.currentKeys[0]!.secretKey
    ) as Claim;

    // The log replays, so the inception-signed claim verifies against the state it was signed
    // under — a scalar signature, outside 016, still judged against any state the log commits.
    expect(await verifyClaim(claim, viewOfLog(log), { now: NOW })).toEqual({ valid: true });

    // And the anchored half. Two revocations of the same digest by the same issuer, signed by
    // the same key, differing ONLY in which of the two identical re-listed states they anchor
    // to: both name a real event, so both verify. This is the shape the retired rule made
    // unbuildable, and it is why an anchor is an event digest rather than a commitment to
    // `(keys, threshold)` — a state commitment could not tell these two events apart.
    const digest = canonicalDigest(claim);
    const anchoredAt = (event: KeyEvent): Revocation =>
      signThresholdRecord(
        { revokes: digest, issuerId: id, anchor: eventDigest(event), revokedAt: PAST },
        [repeatedKey.secretKey]
      ) as Revocation;
    for (const event of [log[3]!, log[4]!]) {
      expect(await verifyClaim(claim, viewOfLog(log, [anchoredAt(event)]), { now: NOW })).toEqual({
        valid: false,
        reason: "claim_revoked"
      });
    }

    // The negative control: a revocation whose set would satisfy the very same key state, but
    // anchored to an event this log does not carry, is not this issuer's record and does not
    // revoke. There is no fallback to "some state accepts it" — that existential is what 016
    // removed.
    const unknownAnchor = signThresholdRecord(
      {
        revokes: digest,
        issuerId: id,
        anchor: canonicalDigest({ anchor: "no such event" }),
        revokedAt: PAST
      },
      [repeatedKey.secretKey]
    ) as Revocation;
    expect(await verifyClaim(claim, viewOfLog(log, [unknownAnchor]), { now: NOW })).toEqual({
      valid: true
    });
  }, 30_000);

  it("draws a caller-supplied budget down through all three represents stages", async () => {
    // `verifyRepresentsChain` runs an agent lookup, a relationship verification and a grant
    // chain. Each used to build its own allowance from the same view, so a represents
    // verification spent three. The caller's budget must reach all three — and the only way to
    // see that is to hand one in and watch it fall.
    const org = committee(8, 1, 70);
    const agent = committee(8, 1, 90);
    const edge = signRecord(
      {
        id: "rel-budget-1",
        subjectId: agent.id,
        predicate: REPRESENTS_PREDICATE,
        objectId: org.id,
        issuedBy: org.id,
        issuedAt: ISSUED_AT
      },
      org.currentKeys[0]!.secretKey
    ) as Relationship;
    const grants = [
      signThresholdRecord(
        {
          subjectId: org.id,
          issuerId: org.id,
          audienceId: agent.id,
          abilities: ["directory"],
          caveats: {},
          anchor: keyLogAnchor(org.log),
          proof: null,
          issuedAt: PAST
        },
        org.currentKeys.map((k) => k.secretKey)
      ) as Grant
    ];

    const view = viewOf([org, agent], { maxSignatureVerifications: 1_000_000 });
    const budget = { remaining: 1_000_000 };
    const verdict = await verifyRepresentsChain(
      { agentId: agent.id, organizationId: org.id, edge, grants },
      view,
      { now: NOW, budget }
    );
    expect(verdict.valid).toBe(true);

    // The request operation coalesces the relationship and chain lookups of the same
    // organization state. The measured composition is therefore one 8-event replay per
    // participant plus the two successful record checks: 18. A higher number would mean the
    // signer-state memo stopped spanning the stages; a lower one would mean work escaped the
    // shared meter.
    const spent = 1_000_000 - budget.remaining;
    expect(spent).toBe(18);

    // And the budget is genuinely the ceiling: one short of what the run costs, it refuses.
    const starved = { remaining: spent - 1 };
    const refused = await verifyRepresentsChain(
      { agentId: agent.id, organizationId: org.id, edge, grants },
      view,
      { now: NOW, budget: starved }
    );
    expect(refused.valid).toBe(false);
    expect((refused as { reason: string }).reason).toMatch(/_too_expensive$/);
  }, 30_000);

  it("builds ONE allowance for a represents chain when the caller supplies none", async () => {
    // The companion to the test above, and the one that pins `verifyRepresentsChain`'s own
    // `shared` options object. When a caller DOES hand in a budget, forwarding `options`
    // unchanged happens to work — the budget rides along inside it. The bug this guards is the
    // other case: with no caller budget, forwarding `options` lets each nested stage build its
    // own from the view, which is what "three independent allowances" meant.
    const org = committee(8, 1, 70);
    const agent = committee(8, 1, 90);
    const edge = signRecord(
      {
        id: "rel-unshared",
        subjectId: agent.id,
        predicate: REPRESENTS_PREDICATE,
        objectId: org.id,
        issuedBy: org.id,
        issuedAt: ISSUED_AT
      },
      org.currentKeys[0]!.secretKey
    ) as Relationship;
    const grants = [
      signThresholdRecord(
        {
          subjectId: org.id,
          issuerId: org.id,
          audienceId: agent.id,
          abilities: ["directory"],
          caveats: {},
          anchor: keyLogAnchor(org.log),
          proof: null,
          issuedAt: PAST
        },
        org.currentKeys.map((k) => k.secretKey)
      ) as Grant
    ];
    const chain = { agentId: agent.id, organizationId: org.id, edge, grants };

    // Measured: the agent lookup costs 8, the relationship stage 9, the grant chain 9 — 26
    // composed. 15 is above every stage and below their sum, so it separates one shared
    // allowance from three independent ones.
    const shared = await verifyRepresentsChain(
      chain,
      viewOf([org, agent], { maxSignatureVerifications: 15 }),
      { now: NOW }
    );
    expect(shared.valid).toBe(false);
    expect((shared as { reason: string }).reason).toMatch(/_too_expensive$/);

    // And the whole thing verifies once the ceiling covers the composed cost.
    expect(
      (
        await verifyRepresentsChain(
          chain,
          viewOf([org, agent], { maxSignatureVerifications: 26 }),
          {
            now: NOW
          }
        )
      ).valid
    ).toBe(true);
  }, 30_000);

  it("shares one allowance for a claim, not one per lookup", async () => {
    // MINOR 4: the statement path took the no-budget branch, which meant a FRESH full
    // allowance per replay while asking about the issuer twice. It now builds a shared budget
    // like every other entry point, and reports a cost refusal distinguishably.
    // 1-of-1, because a claim carries a single signature: a threshold above one could never
    // be satisfied by one. A long log is what makes the lookup expensive.
    const issuer = committee(MAX_KEY_LOG_EVENTS, 1, 1);
    const claim = signRecord(
      {
        id: "claim-cost-1",
        subjectId: issuer.id,
        claimType: "domain",
        value: "cost.example",
        issuedBy: issuer.id,
        issuedAt: ISSUED_AT
      },
      issuer.currentKeys[0]!.secretKey
    ) as Claim;

    const funded = viewOf([issuer], { maxSignatureVerifications: 4096 });
    expect(await verifyClaim(claim, funded, { now: NOW })).toEqual({ valid: true });

    const starved = viewOf([issuer], { maxSignatureVerifications: 1 });
    expect(await verifyClaim(claim, starved, { now: NOW })).toEqual({
      valid: false,
      reason: "issuer_key_log_too_expensive"
    });
  }, 30_000);

  it("fails closed when the allowance runs out INSIDE the revocation lookup", async () => {
    // The exhaustion must happen only in `findRevocation`, so the chain itself is affordable
    // and the ONLY thing that can turn the verdict is how a cost refusal there is handled.
    // Swallowing it makes "could not check for a revocation" read as "not revoked" — a
    // silent downgrade of the one check that withdraws authority.
    const issuer = committee(64, 1, 1);
    const root = grantFrom(issuer, { audienceId: issuer.id });

    // 64 to replay the log + 1 to check the link against its anchored state, and NOT ONE MORE.
    // The margin used to be eight verifications of slack, sized against a candidate that had to
    // traverse 64 key states; spec 016 prices a candidate at one run of the walk against the ONE
    // state its anchor names, so the exhaustion is now bought by making the chain exactly
    // affordable and leaving the candidate's single verification unpayable.
    const view = viewOf([issuer], {
      maxSignatureVerifications: 64 + 1,
      // A candidate ANCHORED to the issuer's real state and signed by a key that is not the
      // issuer's. The anchor resolves, so the lookup reaches curve work — a candidate with an
      // unknown anchor would be skipped for free and prove nothing about cost. Its member count
      // matches the 1-of-1 state's threshold, so 015's length check does not refuse it either.
      revocationsFor: (digest) => [
        signThresholdRecord(
          {
            revokes: digest,
            issuerId: issuer.id,
            anchor: keyLogAnchor(issuer.log),
            revokedAt: PAST
          },
          [generateKeyPair(seed(250)).secretKey]
        ) as Revocation
      ]
    });

    const verdict = await verifyGrantChain([root], view, { now: NOW });
    expect(verdict.valid).toBe(false);
    expect((verdict as { reason: string }).reason).toMatch(/_too_expensive$/);
  }, 30_000);

  it("cannot be made to pay again by a hostile revocation answer", async () => {
    const a = committee(16, 8, 1);
    const b = committee(16, 8, 60);
    const root = grantFrom(a, { audienceId: b.id });
    const leaf = signThresholdRecord(
      {
        subjectId: a.id,
        issuerId: b.id,
        audienceId: a.id,
        abilities: ["directory"],
        caveats: {},
        anchor: keyLogAnchor(b.log),
        proof: canonicalDigest(root),
        issuedAt: PAST
      },
      b.currentKeys.map((k) => k.secretKey)
    ) as Grant;

    // Each log costs 16 x 8 = 128: spec 015's walk spends at most one verification per listed
    // key per event, and an 8-of-8 event spends exactly 8 (member i is assigned key i on its
    // first try). It was 16 x 36 = 576 under the key-counting search this replaced. The whole
    // chain, revocation answers included, MEASURES at 272 — two replays plus 8 per link — so
    // 200 pays for one replay and its link check and not for a second replay. The chain is
    // refused on cost either way; what matters is that a hostile revocation answer, which
    // sends the resolver back for another replay per upstream issuer, cannot reset the
    // allowance and buy an unbounded number of further replays.
    //
    // The REPLAY is the whole mechanism here, and more clearly so than before: `revoke` signs
    // with one key against an 8-of-8 issuer, so spec 015's `m = t` length check rejects each
    // candidate before any curve work and the candidates themselves are free. What they still
    // buy the hostile view is a key-log fetch and replay per upstream issuer named.
    let revocationAnswers = 0;
    const view = viewOf([a, b], {
      maxSignatureVerifications: 200,
      revocationsFor: (digest, issuerIds) => {
        revocationAnswers += 1;
        return issuerIds.map((issuerId) => revoke(issuerId === a.id ? a : b, issuerId, digest));
      }
    });

    // Fail closed and say why: a revocation that could not be checked is not "not revoked",
    // and running out of allowance is a cost condition rather than a bad signature.
    const verdict = await verifyGrantChain([leaf, root], view, { now: NOW });
    expect(verdict.valid).toBe(false);
    expect((verdict as { reason: string }).reason).toMatch(/_too_expensive$/);
    // Bounded work: the allowance is spent once across the whole verification, so the view
    // never gets to serve a second round of revocation candidates.
    expect(revocationAnswers).toBeLessThanOrEqual(1);
    expect(view.keyLogReads).toBeLessThanOrEqual(2);
  }, 30_000);
});

describe("grant-chain verification (spec 009)", () => {
  const view = makeView([org, admin, agent, attacker]);

  it("verifies a self-issued root grant", async () => {
    const root = rootGrant({ audienceId: agent.id });
    expect(await verifyGrantChain([root], view, { now: NOW })).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: agent.id,
      abilities: ["directory"]
    });
  });

  it("verifies a two-link org → admin → agent chain with attenuation", async () => {
    const root = rootGrant();
    expect(await verifyGrantChain([leafGrant(root), root], view, { now: NOW })).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: agent.id,
      abilities: ["directory/curate"]
    });
  });

  it("covers abilities by path prefix, not string prefix", () => {
    expect(abilityCovers("directory", "directory/curate")).toBe(true);
    expect(abilityCovers("directory", "directory")).toBe(true);
    expect(abilityCovers("directory", "directory-admin")).toBe(false);
    expect(abilityCovers("directory/curate", "directory")).toBe(false);
  });

  it("rejects ability escalation in a child link", async () => {
    const root = rootGrant();
    const escalated = leafGrant(root, { abilities: ["payments"] });
    expect(await verifyGrantChain([escalated, root], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_ability_escalation"
    });
  });

  it("rejects a link issued by someone other than the parent's audience", async () => {
    const root = rootGrant();
    const hijacked = makeGrant(attacker, {
      subjectId: org.id,
      issuerId: attacker.id,
      audienceId: agent.id,
      abilities: ["directory/curate"],
      proof: canonicalDigest(root)
    });
    expect(await verifyGrantChain([hijacked, root], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_issuer_not_parent_audience"
    });
  });

  it("rejects subject drift along the chain", async () => {
    const root = rootGrant();
    const drifted = leafGrant(root, { subjectId: admin.id });
    expect(await verifyGrantChain([drifted, root], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_subject_drift"
    });
  });

  it("rejects a broken proof digest", async () => {
    const root = rootGrant();
    const other = rootGrant({ abilities: ["msg"] });
    const mislinked = leafGrant(other);
    expect(await verifyGrantChain([mislinked, root], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_proof_mismatch"
    });
  });

  it("rejects a chain that does not end in a self-issued root", async () => {
    const fakeRoot = makeGrant(admin, {
      subjectId: org.id,
      issuerId: admin.id,
      audienceId: agent.id,
      abilities: ["directory"],
      proof: null
    });
    expect(await verifyGrantChain([fakeRoot], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_root_not_self_issued"
    });

    const root = rootGrant();
    expect(await verifyGrantChain([root, leafGrant(root)], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_chain_incomplete"
    });

    expect(await verifyGrantChain([], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_chain_empty"
    });
  });

  it("rejects a chain longer than MAX_GRANT_CHAIN_LINKS before verifying any link", async () => {
    const root = rootGrant();
    const overlong = Array.from({ length: MAX_GRANT_CHAIN_LINKS + 1 }, () => root);

    // Every link costs a key-log replay, so depth is work whoever presented the chain chose
    // — and they chose it before proving anything. `decodeGrantsHeader` caps this too, but a
    // chain can reach the resolver without passing through that codec.
    expect(await verifyGrantChain(overlong, view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_chain_too_long"
    });
  });

  it("replays each participant's key log once per verification, not once per issuer ask", async () => {
    const root = rootGrant();
    const leaf = leafGrant(root);
    // A revocation of the leaf, issued by `admin` — who is ALSO the leaf's issuer. So one
    // verification asks for admin's key state twice: once to check the link's signature,
    // once to check the revocation's. Those were two independent fetch-and-replays.
    const revocation = revoke(admin, admin.id, canonicalDigest(leaf));

    let fetches = 0;
    const backing = makeView([org, admin, agent, attacker], [revocation]);
    const counting: TrustView = {
      async getKeyLog(id) {
        fetches += 1;
        return backing.getKeyLog(id);
      },
      getRevocations: backing.getRevocations.bind(backing)
    };

    expect(await verifyGrantChain([leaf, root], counting, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_revoked"
    });
    // One participant asked about twice, resolved once.
    expect(fetches).toBe(1);
  });

  it("rejects an expired link", async () => {
    const root = rootGrant();
    const expired = leafGrant(root, { expiresAt: PAST });
    expect(await verifyGrantChain([expired, root], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_expired"
    });

    const live = leafGrant(root, { expiresAt: FUTURE });
    expect((await verifyGrantChain([live, root], view, { now: NOW })).valid).toBe(true);
  });

  it("rejects a tampered link", async () => {
    const root = rootGrant({ audienceId: agent.id });
    const tampered = { ...root, audienceId: attacker.id };
    expect(await verifyGrantChain([tampered], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_signature_invalid"
    });
  });

  it("rejects a chain whose link issuer has no key log", async () => {
    const root = rootGrant({ audienceId: agent.id });
    expect(await verifyGrantChain([root], makeView([agent]), { now: NOW })).toEqual({
      valid: false,
      reason: "grant_issuer_key_log_unresolved"
    });
  });

  it("honors a revocation of any link by an upstream issuer", async () => {
    const root = rootGrant();
    const leaf = leafGrant(root);

    const rootRevoked = makeView([org, admin, agent], [revoke(org, org.id, canonicalDigest(root))]);
    expect(await verifyGrantChain([leaf, root], rootRevoked, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_revoked"
    });

    const leafRevokedByRoot = makeView(
      [org, admin, agent],
      [revoke(org, org.id, canonicalDigest(leaf))]
    );
    expect(await verifyGrantChain([leaf, root], leafRevokedByRoot, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_revoked"
    });
  });

  it("accepts an answer exactly as long as the issuer set it asked about", async () => {
    // The boundary the check above must not cross: a legitimate view answering a two-issuer
    // question with two records is fine, and the revocation in it is honored as usual. Without
    // this, a stricter-than-intended bound (say `>=`) would pass the throw test and silently
    // break every real revoked-chain verdict.
    const root = rootGrant();
    const leaf = leafGrant(root);
    const digest = canonicalDigest(leaf);
    const bothAuthorized: Revocation[] = [
      revoke(admin, admin.id, digest),
      revoke(org, org.id, digest)
    ];
    const logs = new Map([org, admin, agent].map((identity) => [identity.id, identity.log]));
    const fullView: TrustView = {
      async getKeyLog(id) {
        return logs.get(id) ?? null;
      },
      async getRevocations(revokesDigest) {
        return revokesDigest === digest ? bothAuthorized : [];
      }
    };

    // The leaf's authorized revokers are the admin (its issuer) and the org (upstream): two.
    expect(await verifyGrantChain([leaf, root], fullView, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_revoked"
    });
  });

  it("asks the view once per link, naming every authorized revoker of that link", async () => {
    // A grant chain is capped at `MAX_GRANT_CHAIN_LINKS`, so each authorized-revoker set is
    // bounded by that same constant. The lookup is still BATCHED: one call carries the whole
    // set for a link, rather than making one round trip for every issuer in the chain suffix.
    const root = rootGrant();
    const leaf = leafGrant(root);
    const logs = new Map([org, admin, agent].map((identity) => [identity.id, identity.log]));
    const asked: { digest: string; issuerIds: string[] }[] = [];
    const countingView: TrustView = {
      async getKeyLog(id) {
        return logs.get(id) ?? null;
      },
      async getRevocations(digest, issuerIds) {
        asked.push({ digest, issuerIds: [...issuerIds] });
        return [];
      }
    };

    expect((await verifyGrantChain([leaf, root], countingView, { now: NOW })).valid).toBe(true);
    expect(asked).toEqual([
      // The leaf: its own issuer (the admin) plus everything upstream (the org).
      { digest: canonicalDigest(leaf), issuerIds: [admin.id, org.id] },
      // The root: only itself is upstream of it.
      { digest: canonicalDigest(root), issuerIds: [org.id] }
    ]);
  });

  it("ignores a revocation of an upstream link by a downstream audience", async () => {
    const root = rootGrant();
    const leaf = leafGrant(root);
    const downstream = makeView(
      [org, admin, agent],
      [revoke(admin, admin.id, canonicalDigest(root))]
    );
    expect((await verifyGrantChain([leaf, root], downstream, { now: NOW })).valid).toBe(true);
  });

  it("fails closed on caveats without an evaluator and consults one when given", async () => {
    const root = rootGrant({ audienceId: agent.id, caveats: { maxBudget: "100" } });

    expect(await verifyGrantChain([root], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_caveat_rejected"
    });

    const accepted = await verifyGrantChain([root], view, {
      now: NOW,
      evaluateCaveats: (grant) => grant.caveats.maxBudget === "100"
    });
    expect(accepted.valid).toBe(true);

    const declined = await verifyGrantChain([root], view, {
      now: NOW,
      evaluateCaveats: () => false
    });
    expect(declined).toEqual({ valid: false, reason: "grant_caveat_rejected" });
  });
});

describe("device-key grant chains (spec 011)", () => {
  // The user (org) delegates to a disposable browser session key, which re-delegates
  // an attenuated sub-grant to the backend service acting on the user's behalf.
  const sessionKey = generateKeyPair(seed(9));
  const sessionKeyRef = encodeKeyRef(sessionKey.publicKey);
  const service = createIdentity({ currentSeed: seed(10), nextSeed: seed(11) });
  const view = makeView([org, admin, agent, attacker, service]);

  /** Root: the user self-issues to the session key — expiring and service-bound. */
  function sessionRoot(overrides: Partial<GrantFields> = {}): Grant {
    return makeGrant(org, {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: sessionKeyRef,
      abilities: ["msg"],
      proof: null,
      expiresAt: FUTURE,
      caveats: { aud: [service.id] },
      ...overrides
    });
  }

  /** Sub-grant: the session key attenuates its authority down to the service. */
  function serviceGrant(
    parent: Grant,
    overrides: Partial<GrantFields> = {},
    signers: Uint8Array[] = [sessionKey.secretKey]
  ): Grant {
    return signGrant(
      {
        subjectId: org.id,
        issuerId: sessionKeyRef,
        audienceId: service.id,
        abilities: ["msg/send"],
        caveats: { aud: [service.id] },
        proof: canonicalDigest(parent),
        ...overrides
      },
      signers
    );
  }

  it("verifies a user → session key → service chain when the verifier is admitted", async () => {
    const root = sessionRoot();
    const chain = [serviceGrant(root), root];
    expect(await verifyGrantChain(chain, view, { now: NOW, verifierId: service.id })).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: service.id,
      abilities: ["msg/send"]
    });
  });

  it("rejects a key-issued link signed by a different key than the parent's audience", async () => {
    const root = sessionRoot();
    const forged = serviceGrant(root, {}, [attacker.currentKeys[0]!.secretKey]);
    expect(
      await verifyGrantChain([forged, root], view, { now: NOW, verifierId: service.id })
    ).toEqual({
      valid: false,
      reason: "grant_key_issuer_signature_invalid"
    });
  });

  it("rejects a key-issued link carrying two signatures", async () => {
    const root = sessionRoot();
    const doubled = serviceGrant(root, {}, [
      sessionKey.secretKey,
      attacker.currentKeys[0]!.secretKey
    ]);
    expect(
      await verifyGrantChain([doubled, root], view, { now: NOW, verifierId: service.id })
    ).toEqual({
      valid: false,
      reason: "grant_key_issuer_signature_invalid"
    });
  });

  it("classifies zero-budget key-issuer verification as capacity, not invalid", async () => {
    const root = sessionRoot();
    const leaf = serviceGrant(root);
    const budget = { remaining: 0 };
    expect(
      await verifyGrantChain([leaf, root], view, {
        now: NOW,
        verifierId: service.id,
        budget
      })
    ).toEqual({ valid: false, reason: "grant_signature_check_too_expensive" });
    expect(budget.remaining).toBe(0);
  });

  it("rejects a session key widening abilities in its sub-grant", async () => {
    const root = sessionRoot();
    const widened = serviceGrant(root, { abilities: ["directory"] });
    expect(
      await verifyGrantChain([widened, root], view, { now: NOW, verifierId: service.id })
    ).toEqual({
      valid: false,
      reason: "grant_ability_escalation"
    });
  });

  it("rejects a child aud not covered by the parent's effective aud", async () => {
    const root = sessionRoot();
    const widened = serviceGrant(root, { caveats: { aud: [service.id, attacker.id] } });
    expect(
      await verifyGrantChain([widened, root], view, { now: NOW, verifierId: service.id })
    ).toEqual({
      valid: false,
      reason: "grant_aud_escalation"
    });
  });

  it("rejects a verifier outside the effective aud, including via an inheriting link", async () => {
    const root = sessionRoot();
    const chain = [serviceGrant(root), root];
    expect(await verifyGrantChain(chain, view, { now: NOW, verifierId: attacker.id })).toEqual({
      valid: false,
      reason: "grant_audience_not_admitted"
    });

    // A leaf without its own aud inherits the root's restriction.
    const inheriting = [serviceGrant(root, { caveats: {} }), root];
    expect(await verifyGrantChain(inheriting, view, { now: NOW, verifierId: service.id })).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: service.id,
      abilities: ["msg/send"]
    });
    expect(await verifyGrantChain(inheriting, view, { now: NOW, verifierId: attacker.id })).toEqual(
      {
        valid: false,
        reason: "grant_audience_not_admitted"
      }
    );
  });

  it("fails closed on an aud-restricted chain verified without a verifierId", async () => {
    const root = sessionRoot();
    expect(await verifyGrantChain([serviceGrant(root), root], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_audience_not_admitted"
    });
  });

  it("evaluates aud natively but still fails closed on other caveats", async () => {
    const root = sessionRoot();
    // aud alone needs no evaluateCaveats hook (the happy path above proves it); a
    // foreign caveat alongside aud still does, and the evaluator sees the full link.
    const budgeted = serviceGrant(root, { caveats: { aud: [service.id], maxBudget: "100" } });
    expect(
      await verifyGrantChain([budgeted, root], view, { now: NOW, verifierId: service.id })
    ).toEqual({ valid: false, reason: "grant_caveat_rejected" });

    const accepted = await verifyGrantChain([budgeted, root], view, {
      now: NOW,
      verifierId: service.id,
      evaluateCaveats: (grant) => grant.caveats.maxBudget === "100"
    });
    expect(accepted.valid).toBe(true);
  });

  it("severs the whole chain when the subject revokes the root link", async () => {
    const root = sessionRoot();
    const chain = [serviceGrant(root), root];
    const revoked = makeView([org, service], [revoke(org, org.id, canonicalDigest(root))]);
    expect(await verifyGrantChain(chain, revoked, { now: NOW, verifierId: service.id })).toEqual({
      valid: false,
      reason: "grant_revoked"
    });
  });

  it("lets the subject revoke a key-issued link, and ignores unrelated revokers", async () => {
    const root = sessionRoot();
    const leaf = serviceGrant(root);

    const bySubject = makeView([org, service], [revoke(org, org.id, canonicalDigest(leaf))]);
    expect(
      await verifyGrantChain([leaf, root], bySubject, { now: NOW, verifierId: service.id })
    ).toEqual({
      valid: false,
      reason: "grant_revoked"
    });

    const byStranger = makeView(
      [org, attacker, service],
      [revoke(attacker, attacker.id, canonicalDigest(leaf))]
    );
    expect(
      (await verifyGrantChain([leaf, root], byStranger, { now: NOW, verifierId: service.id })).valid
    ).toBe(true);
  });

  describe("requireAud — demanding an audience-bound chain (spec 011)", () => {
    // The bypass this option closes: `aud` is mandatory only for KEY audiences, so a
    // chain delegated between participants may legally carry none — and an unrestricted
    // chain is admitted by every verifier, whatever verifierId it states.
    const audlessRoot = makeGrant(org, {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: admin.id,
      abilities: ["msg"],
      proof: null,
      caveats: {}
    });
    const audlessLeaf = makeGrant(admin, {
      subjectId: org.id,
      issuerId: admin.id,
      audienceId: service.id,
      abilities: ["msg/send"],
      proof: canonicalDigest(audlessRoot),
      caveats: {}
    });
    const audless = [audlessLeaf, audlessRoot];
    const accepted = {
      valid: true,
      subjectId: org.id,
      audienceId: service.id,
      abilities: ["msg/send"]
    };

    it("admits an aud-less chain at any verifier when requireAud is unset or false", async () => {
      expect(await verifyGrantChain(audless, view, { now: NOW })).toEqual(accepted);
      expect(await verifyGrantChain(audless, view, { now: NOW, verifierId: service.id })).toEqual(
        accepted
      );
      // The point of the option: verifierId alone does not keep this chain out of a
      // service the subject never named.
      expect(await verifyGrantChain(audless, view, { now: NOW, verifierId: attacker.id })).toEqual(
        accepted
      );
      expect(
        await verifyGrantChain(audless, view, {
          now: NOW,
          verifierId: attacker.id,
          requireAud: false
        })
      ).toEqual(accepted);
    });

    it("rejects an aud-less chain under requireAud, whatever the verifier id", async () => {
      const expected = { valid: false, reason: "grant_audience_required" };
      expect(await verifyGrantChain(audless, view, { now: NOW, requireAud: true })).toEqual(
        expected
      );
      expect(
        await verifyGrantChain(audless, view, {
          now: NOW,
          requireAud: true,
          verifierId: service.id
        })
      ).toEqual(expected);
    });

    it("rejects a self-issued aud-less root under requireAud", async () => {
      const selfIssued = makeGrant(org, {
        subjectId: org.id,
        issuerId: org.id,
        audienceId: service.id,
        abilities: ["msg"],
        proof: null,
        caveats: {}
      });
      expect(await verifyGrantChain([selfIssued], view, { now: NOW, requireAud: true })).toEqual({
        valid: false,
        reason: "grant_audience_required"
      });
      expect((await verifyGrantChain([selfIssued], view, { now: NOW })).valid).toBe(true);
    });

    it("admits an aud-bound chain naming this verifier under requireAud", async () => {
      const root = sessionRoot();
      const chain = [serviceGrant(root), root];
      expect(
        await verifyGrantChain(chain, view, { now: NOW, requireAud: true, verifierId: service.id })
      ).toEqual({
        valid: true,
        subjectId: org.id,
        audienceId: service.id,
        abilities: ["msg/send"]
      });
    });

    it("still rejects an aud naming another verifier as not admitted under requireAud", async () => {
      const root = sessionRoot();
      const chain = [serviceGrant(root), root];
      expect(
        await verifyGrantChain(chain, view, { now: NOW, requireAud: true, verifierId: attacker.id })
      ).toEqual({ valid: false, reason: "grant_audience_not_admitted" });

      // Missing verifierId keeps its own reason: the aud is present, just unevaluable.
      expect(await verifyGrantChain(chain, view, { now: NOW, requireAud: true })).toEqual({
        valid: false,
        reason: "grant_audience_not_admitted"
      });
    });

    it("satisfies requireAud when only one link carries aud (the inherited effective aud)", async () => {
      // Root binds the audience; the leaf carries no caveats and inherits it.
      const root = sessionRoot();
      const inheriting = [serviceGrant(root, { caveats: {} }), root];
      expect(
        await verifyGrantChain(inheriting, view, {
          now: NOW,
          requireAud: true,
          verifierId: service.id
        })
      ).toEqual({
        valid: true,
        subjectId: org.id,
        audienceId: service.id,
        abilities: ["msg/send"]
      });

      // And the mirror: only the leaf binds it, the root being unrestricted.
      const audlessRootBoundLeaf = makeGrant(org, {
        subjectId: org.id,
        issuerId: org.id,
        audienceId: admin.id,
        abilities: ["msg"],
        proof: null,
        caveats: {}
      });
      const boundLeaf = makeGrant(admin, {
        subjectId: org.id,
        issuerId: admin.id,
        audienceId: service.id,
        abilities: ["msg/send"],
        proof: canonicalDigest(audlessRootBoundLeaf),
        caveats: { aud: [service.id] }
      });
      expect(
        await verifyGrantChain([boundLeaf, audlessRootBoundLeaf], view, {
          now: NOW,
          requireAud: true,
          verifierId: service.id
        })
      ).toEqual({
        valid: true,
        subjectId: org.id,
        audienceId: service.id,
        abilities: ["msg/send"]
      });
    });
  });

  it("rejects an expired key-audience link", async () => {
    const root = sessionRoot({ expiresAt: PAST });
    expect(
      await verifyGrantChain([serviceGrant(root), root], view, { now: NOW, verifierId: service.id })
    ).toEqual({ valid: false, reason: "grant_expired" });
  });
});

describe("e2ee chains are never request-valid (spec 014)", () => {
  // The device holding an MLS leaf: a bare key, exactly the audience a credential names.
  const deviceKey = generateKeyPair(seed(20));
  const deviceKeyRef = encodeKeyRef(deviceKey.publicKey);
  const service = createIdentity({ currentSeed: seed(21), nextSeed: seed(22) });
  const view = makeView([org, admin, agent, service]);

  const rejected = { valid: false, reason: "grant_e2ee_not_request_valid" };

  /**
   * A credential (spec 014): self-issued by the member, audienced to the device's MLS
   * leaf key, abilities inside the `e2ee` namespace, empty caveats — including no `aud`,
   * which 014 lifts for exactly this shape.
   */
  function credential(abilities: string[] = ["e2ee/leaf"]): Grant {
    return makeGrant(org, {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: deviceKeyRef,
      abilities,
      proof: null,
      caveats: {},
      expiresAt: FUTURE
    });
  }

  it("rejects a pure credential chain presented as request authority", async () => {
    const chain = [credential()];
    expect(await verifyGrantChain(chain, view, { now: NOW })).toEqual(rejected);
    // A stolen credential authorizes zero requests ANYWHERE: no verifier id, no audience
    // policy, and no ability demand lets it through.
    expect(await verifyGrantChain(chain, view, { now: NOW, verifierId: service.id })).toEqual(
      rejected
    );
    expect(
      await verifyGrantChain(chain, view, { now: NOW, verifierId: service.id, requireAud: true })
    ).toEqual(rejected);
  });

  it("rejects the bare `e2ee` ability and deeper `e2ee/...` abilities", async () => {
    for (const ability of ["e2ee", "e2ee/leaf", "e2ee/leaf/extra"]) {
      expect(await verifyGrantChain([credential([ability])], view, { now: NOW })).toEqual(rejected);
    }
  });

  it("rejects a MIXED chain outright rather than authorizing its non-e2ee half", async () => {
    // The whole-chain reading: the leaf being exercised is a plain `msg/send`, but an
    // ancestor carries `e2ee/leaf`, so the chain is not a request authorization at all.
    const mixedRoot = makeGrant(org, {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: admin.id,
      abilities: ["e2ee/leaf", "msg/send"],
      proof: null,
      caveats: {}
    });
    const plainLeaf = makeGrant(admin, {
      subjectId: org.id,
      issuerId: admin.id,
      audienceId: agent.id,
      abilities: ["msg/send"],
      proof: canonicalDigest(mixedRoot),
      caveats: {}
    });
    expect(await verifyGrantChain([plainLeaf, mixedRoot], view, { now: NOW })).toEqual(rejected);

    // And the mirror: the e2ee ability sits on the leaf beside the exercised one.
    const mixedLeaf = makeGrant(admin, {
      subjectId: org.id,
      issuerId: admin.id,
      audienceId: agent.id,
      abilities: ["msg/send", "e2ee/leaf"],
      proof: canonicalDigest(mixedRoot),
      caveats: {}
    });
    expect(await verifyGrantChain([mixedLeaf, mixedRoot], view, { now: NOW })).toEqual(rejected);
  });

  it("rejects before any other check, so the reason always names the rule", async () => {
    // Expired AND e2ee: the operator sees why the chain can never work, not why it
    // happens to fail today. Two verifiers reading the same chain agree on the reason.
    expect(await verifyGrantChain([credential()], view, { now: new Date(FUTURE) })).toEqual(
      rejected
    );
  });

  it("does NOT treat `e2eex` or `e2eeleaf` as e2ee — they authorize normally", async () => {
    // Namespace test, not prefix test (spec 014). A neighbouring namespace must keep working.
    for (const ability of ["e2eex/leaf", "e2eeleaf", "e2ee-leaf", "leaf/e2ee"]) {
      const grant = makeGrant(org, {
        subjectId: org.id,
        issuerId: org.id,
        audienceId: deviceKeyRef,
        abilities: [ability],
        proof: null,
        caveats: { aud: [service.id] },
        expiresAt: FUTURE
      });
      expect(await verifyGrantChain([grant], view, { now: NOW, verifierId: service.id })).toEqual({
        valid: true,
        subjectId: org.id,
        audienceId: deviceKeyRef,
        abilities: [ability]
      });
    }
  });

  it("verifies the same credential chain at credential purpose (member verification)", async () => {
    // The one place an e2ee chain is meant to be valid — and the check that the resolver
    // does not independently re-impose 011's `aud` requirement that 014 lifted.
    expect(
      await verifyGrantChain([credential()], view, { now: NOW, purpose: "credential" })
    ).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: deviceKeyRef,
      abilities: ["e2ee/leaf"]
    });
    // `requireAud` is a request-surface knob; it must not reject a record the schema
    // accepts, so it does not apply at credential purpose.
    expect(
      await verifyGrantChain([credential()], view, {
        now: NOW,
        purpose: "credential",
        requireAud: true,
        verifierId: service.id
      })
    ).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: deviceKeyRef,
      abilities: ["e2ee/leaf"]
    });
  });

  it("rejects an e2ee chain presented as a represents chain's bounding grants", async () => {
    // verifyRepresentsChain funnels its `grants` through verifyGrantChain, so this path
    // inherits the rule: a credential cannot bound an agent's representation either.
    const bounding = makeGrant(org, {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: agent.id,
      abilities: ["e2ee/leaf"],
      proof: null,
      caveats: {}
    });
    expect(
      await verifyRepresentsChain(
        {
          agentId: agent.id,
          organizationId: org.id,
          edge: representsEdge(org),
          grants: [bounding]
        },
        view,
        { now: NOW }
      )
    ).toEqual(rejected);
  });
});

describe("self-remove sits outside the `msg` umbrella (spec 014)", () => {
  // The pinned ability string is `conversation/self-remove`, deliberately in its own
  // namespace: everyday `msg` session grants must not carry unilateral self-expulsion
  // authority, and putting it outside `msg` means the generic cover rule delivers that
  // with no exclusion carved into `abilityCovers`.
  const SELF_REMOVE = "conversation/self-remove";
  const view = makeView([org, admin, agent]);

  it("is not covered by `msg`, and covers only itself", () => {
    expect(abilityCovers("msg", SELF_REMOVE)).toBe(false);
    expect(abilityCovers("msg", "msg/conversation-update")).toBe(true);
    expect(abilityCovers(SELF_REMOVE, SELF_REMOVE)).toBe(true);
    expect(abilityCovers("conversation", SELF_REMOVE)).toBe(true);
    // Neighbouring names must not slip through the same-namespace check.
    expect(abilityCovers(SELF_REMOVE, "conversation/self-remove-all")).toBe(false);
    expect(abilityCovers("conversation/self", SELF_REMOVE)).toBe(false);
  });

  it("cannot be attenuated out of a `msg`-only grant", async () => {
    const root = rootGrant({ abilities: ["msg"] });
    const overreaching = leafGrant(root, { abilities: ["msg/conversation-update", SELF_REMOVE] });
    expect(await verifyGrantChain([overreaching, root], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_ability_escalation"
    });
  });

  it("attenuates normally when the root grants it explicitly", async () => {
    const root = rootGrant({ abilities: ["msg", SELF_REMOVE] });
    expect(
      await verifyGrantChain([leafGrant(root, { abilities: [SELF_REMOVE] }), root], view, {
        now: NOW
      })
    ).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: agent.id,
      abilities: [SELF_REMOVE]
    });

    const both = leafGrant(root, { abilities: ["msg/conversation-update", SELF_REMOVE] });
    expect((await verifyGrantChain([both, root], view, { now: NOW })).valid).toBe(true);
  });
});

describe("record-purpose chain verification (delegated-signed evidence)", () => {
  // The custodial shape: the actor's session key signs the evidence record, authorized by
  // a grant the actor issued to that key and `aud`-bound to the node that gated the
  // authoring delivery. Every later verifier — a joiner, a re-delivering member, the node
  // re-checking a relayed unit — is a third party to that `aud` and reads the chain long
  // after it expired.
  const sessionKey = generateKeyPair(seed(30));
  const sessionKeyRef = encodeKeyRef(sessionKey.publicKey);
  const node = createIdentity({ currentSeed: seed(31), nextSeed: seed(32) });
  const view = makeView([org, admin, agent, attacker, node]);

  /** The record's `createdAt`: inside the grant window, before the wall clock `NOW`. */
  const CREATED_AT = new Date("2026-06-05T00:00:00.000Z");
  const BEFORE_ISSUANCE = new Date("2026-05-20T00:00:00.000Z");

  /** A session grant that has since expired: issued ISSUED_AT, dead by PAST < NOW. */
  function sessionGrant(overrides: Partial<GrantFields> = {}): Grant {
    return makeGrant(org, {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: sessionKeyRef,
      abilities: ["msg"],
      proof: null,
      expiresAt: PAST,
      caveats: { aud: [node.id] },
      ...overrides
    });
  }

  const accepted = {
    valid: true,
    subjectId: org.id,
    audienceId: sessionKeyRef,
    abilities: ["msg"]
  };

  it("accepts a chain bound to a third party's `aud`, with no verifierId at all", async () => {
    // The headline: at request purpose this same chain is rejected at every verifier but
    // the node, which is why record purpose evaluates no caveats.
    expect(
      await verifyGrantChain([sessionGrant()], view, { purpose: "record", at: CREATED_AT })
    ).toEqual(accepted);
    expect(
      await verifyGrantChain([sessionGrant()], view, {
        purpose: "record",
        at: CREATED_AT,
        verifierId: attacker.id
      })
    ).toEqual(accepted);
    // Same bytes, request purpose, same third-party verifier: rejected.
    expect(
      await verifyGrantChain([sessionGrant({ expiresAt: FUTURE })], view, {
        now: NOW,
        verifierId: attacker.id
      })
    ).toEqual({ valid: false, reason: "grant_audience_not_admitted" });
  });

  it("measures the window against `at`, never the wall clock", async () => {
    const chain = [sessionGrant()];
    // Expired hours ago by the clock, valid when the record was written.
    expect(await verifyGrantChain(chain, view, { purpose: "record", at: CREATED_AT })).toEqual(
      accepted
    );
    // `now` is not consulted at record purpose — passing a clock that would reject it changes nothing.
    expect(
      await verifyGrantChain(chain, view, {
        purpose: "record",
        at: CREATED_AT,
        now: new Date(FUTURE)
      })
    ).toEqual(accepted);
    // The same chain at request purpose is expired, which is the behavior record purpose departs from.
    expect(await verifyGrantChain(chain, view, { now: NOW, verifierId: node.id })).toEqual({
      valid: false,
      reason: "grant_expired"
    });
  });

  it("still enforces the upper bound: a record dated after the grant died is rejected", async () => {
    expect(
      await verifyGrantChain([sessionGrant()], view, { purpose: "record", at: new Date(NOW) })
    ).toEqual({ valid: false, reason: "grant_expired" });
  });

  it("rejects a record backdated before the grant it cites was issued", async () => {
    expect(
      await verifyGrantChain([sessionGrant()], view, { purpose: "record", at: BEFORE_ISSUANCE })
    ).toEqual({ valid: false, reason: "grant_not_yet_issued" });

    // The boundary is inclusive: a record written the instant the grant was issued is authorized.
    expect(
      await verifyGrantChain([sessionGrant()], view, { purpose: "record", at: new Date(ISSUED_AT) })
    ).toEqual(accepted);
  });

  it("refuses to run at record purpose without `at` rather than falling back to the clock", async () => {
    expect(await verifyGrantChain([sessionGrant()], view, { purpose: "record" })).toEqual({
      valid: false,
      reason: "grant_record_time_required"
    });
    // Even with a `now` that would accept the chain: the two are different questions.
    expect(
      await verifyGrantChain([sessionGrant({ expiresAt: FUTURE })], view, {
        purpose: "record",
        now: NOW
      })
    ).toEqual({ valid: false, reason: "grant_record_time_required" });
  });

  it("checks revocation only under checkRevocation", async () => {
    const grant = sessionGrant();
    const revoked = makeView([org, node], [revoke(org, org.id, canonicalDigest(grant))]);

    // The node's delivery-time gate.
    expect(
      await verifyGrantChain([grant], revoked, {
        purpose: "record",
        at: CREATED_AT,
        checkRevocation: true
      })
    ).toEqual({ valid: false, reason: "grant_revoked" });

    // The member side: a revocation one member's view holds and another's does not must
    // not decide whether a delivered record is valid, so members clear the flag.
    expect(
      await verifyGrantChain([grant], revoked, {
        purpose: "record",
        at: CREATED_AT,
        checkRevocation: false
      })
    ).toEqual(accepted);

    // Omitted means checked: an unconsidered caller gets the stricter answer.
    expect(await verifyGrantChain([grant], revoked, { purpose: "record", at: CREATED_AT })).toEqual(
      { valid: false, reason: "grant_revoked" }
    );

    // And the flag is record-purpose-only: it cannot switch revocation off elsewhere.
    const live = sessionGrant({ expiresAt: FUTURE });
    const liveRevoked = makeView([org, node], [revoke(org, org.id, canonicalDigest(live))]);
    expect(
      await verifyGrantChain([live], liveRevoked, {
        now: NOW,
        verifierId: node.id,
        checkRevocation: false
      })
    ).toEqual({ valid: false, reason: "grant_revoked" });
  });

  it("does not trip the e2ee-namespace rule, which stays request-only", async () => {
    const credential = makeGrant(org, {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: sessionKeyRef,
      abilities: ["e2ee/leaf"],
      proof: null,
      caveats: {},
      expiresAt: PAST
    });
    expect(await verifyGrantChain([credential], view, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_e2ee_not_request_valid"
    });
    expect(
      await verifyGrantChain([credential], view, { purpose: "record", at: CREATED_AT })
    ).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: sessionKeyRef,
      abilities: ["e2ee/leaf"]
    });
  });

  it("evaluates no caveats at all — foreign ones neither reject nor need an evaluator", async () => {
    const budgeted = sessionGrant({ caveats: { aud: [node.id], maxBudget: "100" } });
    expect(await verifyGrantChain([budgeted], view, { purpose: "record", at: CREATED_AT })).toEqual(
      {
        valid: true,
        subjectId: org.id,
        audienceId: sessionKeyRef,
        abilities: ["msg"]
      }
    );
    // The same link fails closed at request purpose without an evaluator.
    expect(
      await verifyGrantChain(
        [sessionGrant({ caveats: { aud: [node.id], maxBudget: "100" }, expiresAt: FUTURE })],
        view,
        { now: NOW, verifierId: node.id }
      )
    ).toEqual({ valid: false, reason: "grant_caveat_rejected" });
  });

  it("keeps every structural check: signatures, attenuation, subject constancy, linkage", async () => {
    const root = sessionGrant({ abilities: ["msg", "conversation/self-remove"] });
    const sub = (overrides: Partial<GrantFields> = {}, signers = [sessionKey.secretKey]) =>
      signGrant(
        {
          subjectId: org.id,
          issuerId: sessionKeyRef,
          audienceId: agent.id,
          abilities: ["msg/conversation-update"],
          caveats: {},
          proof: canonicalDigest(root),
          expiresAt: PAST,
          ...overrides
        },
        signers
      );
    const options = { purpose: "record", at: CREATED_AT } as const;

    expect(await verifyGrantChain([sub(), root], view, options)).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: agent.id,
      abilities: ["msg/conversation-update"]
    });
    expect(
      await verifyGrantChain([sub({ abilities: ["directory"] }), root], view, options)
    ).toEqual({ valid: false, reason: "grant_ability_escalation" });
    expect(await verifyGrantChain([sub({ subjectId: admin.id }), root], view, options)).toEqual({
      valid: false,
      reason: "grant_subject_drift"
    });
    expect(
      await verifyGrantChain([sub({ proof: canonicalDigest(sub()) }), root], view, options)
    ).toEqual({ valid: false, reason: "grant_proof_mismatch" });
    expect(
      await verifyGrantChain([sub({}, [attacker.currentKeys[0]!.secretKey]), root], view, options)
    ).toEqual({ valid: false, reason: "grant_key_issuer_signature_invalid" });
    expect(await verifyGrantChain([{ ...root, abilities: ["directory"] }], view, options)).toEqual({
      valid: false,
      reason: "grant_signature_invalid"
    });
    expect(await verifyGrantChain([sub()], view, options)).toEqual({
      valid: false,
      reason: "grant_chain_incomplete"
    });
    expect(await verifyGrantChain([], view, options)).toEqual({
      valid: false,
      reason: "grant_chain_empty"
    });
    expect(
      await verifyGrantChain([{ ...sub(), issuedAt: "not-a-date" }, root], view, options)
    ).toEqual({ valid: false, reason: "grant_malformed" });
  });
});

describe("relationship verification", () => {
  const view = makeView([org, agent]);

  it("accepts a valid edge and rejects a malformed one", async () => {
    expect(await verifyRelationship(representsEdge(org), view, { now: NOW })).toEqual({
      valid: true
    });
    const malformed = { ...representsEdge(org), subjectId: "alice" } as unknown as Relationship;
    expect(await verifyRelationship(malformed, view, { now: NOW })).toEqual({
      valid: false,
      reason: "relationship_malformed"
    });
  });
});

/**
 * The hostile discovery host: it serves a key log that replays PERFECTLY and belongs to
 * somebody else. This is the whole threat model of this package stated in one view — the host
 * is untrusted, so the only thing tying a log to a participant is that the log's own inception
 * event derives that participant's id. Nothing in these tests involves a forged signature, a
 * malformed log, or any key of the victim's: every log here is genuine, and every record is
 * genuinely signed by whoever the host claims owns it.
 */
function substitutedLogView(
  substitutions: Record<string, Identity>,
  identities: Identity[] = [],
  revocations: Revocation[] = []
): TrustView {
  const honest = makeView(identities, revocations);
  return {
    getRevocations: honest.getRevocations,
    async getKeyLog(id) {
      const impostor = substitutions[id];
      return impostor ? impostor.log : honest.getKeyLog(id);
    }
  };
}

describe("substituted key logs — a host serving another participant's valid log", () => {
  it("would otherwise be a total impersonation: the same bytes verify under the attacker", async () => {
    // The control that gives the rest of this block its teeth. The attacker's log is valid and
    // the attacker's signature over a record naming the ORGANIZATION as issuer is a real
    // signature — so the ONLY thing standing between the attacker and issuing as the
    // organization is the check that the served log derives `org.id`.
    const asAttacker = domainClaim(attacker, { issuedBy: attacker.id });
    expect(await verifyClaim(asAttacker, makeView([attacker]), { now: NOW })).toEqual({
      valid: true
    });
  });

  it("rejects a claim whose issuer's log was substituted", async () => {
    // `issuedBy` is the organization; the signature is the attacker's; discovery answers the
    // organization's id with the attacker's log.
    const forged = domainClaim(attacker);
    expect(forged.issuedBy).toBe(org.id);

    const hostile = substitutedLogView({ [org.id]: attacker });
    expect(await verifyClaim(forged, hostile, { now: NOW })).toEqual({
      valid: false,
      reason: "issuer_key_log_participant_mismatch"
    });
  });

  it("rejects a relationship whose issuer's log was substituted", async () => {
    // A represents edge is the S1 gate's whole input: "this agent represents Acme", asserted
    // by Acme. A substituted log lets the attacker assert it on Acme's behalf.
    const forged = representsEdge(attacker);
    expect(forged.issuedBy).toBe(org.id);

    const hostile = substitutedLogView({ [org.id]: attacker }, [agent]);
    expect(await verifyRelationship(forged, hostile, { now: NOW })).toEqual({
      valid: false,
      reason: "issuer_key_log_participant_mismatch"
    });
  });

  it("rejects a grant chain whose self-issued root's log was substituted", async () => {
    // The root is where a chain's authority comes from: it is self-issued, so "who signed it"
    // and "whose authority it delegates" are the same question. A substituted root log lets an
    // attacker mint the organization's authority from nothing.
    const root = makeGrant(attacker, {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: admin.id,
      abilities: ["directory"],
      proof: null
    });
    const hostile = substitutedLogView({ [org.id]: attacker });

    expect(await verifyGrantChain([root], hostile, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_issuer_key_log_participant_mismatch"
    });
  });

  it("rejects a multi-link chain when only the root's issuer log was substituted", async () => {
    // Every other link is honest and verifies. The rejection has to come from the root, which
    // is checked last — so this pins that reaching a good leaf first does not let a forged
    // root through behind it.
    const root = makeGrant(attacker, {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: admin.id,
      abilities: ["directory"],
      proof: null
    });
    const leaf = leafGrant(root);
    const hostile = substitutedLogView({ [org.id]: attacker }, [admin, agent]);

    expect(await verifyGrantChain([leaf, root], hostile, { now: NOW })).toEqual({
      valid: false,
      reason: "grant_issuer_key_log_participant_mismatch"
    });
  });

  it("rejects a represents chain whose agent log was substituted", async () => {
    const edge = representsEdge(org);
    const hostile = substitutedLogView({ [agent.id]: attacker }, [org]);

    expect(
      await verifyRepresentsChain({ agentId: agent.id, organizationId: org.id, edge }, hostile, {
        now: NOW
      })
    ).toEqual({ valid: false, reason: "agent_key_log_participant_mismatch" });
  });

  it("does not honor a revocation whose issuer's log was substituted", async () => {
    // The other direction of the same power: a substituted issuer log makes a revocation the
    // organization never signed look authentic, withdrawing a record it still stands behind.
    // The leaf here is honest and its authorized revokers are (admin, org); the forged
    // revocation names org, and org's log is the substituted one.
    const root = rootGrant();
    const leaf = leafGrant(root);
    const forgedRevocation = revoke(attacker, org.id, canonicalDigest(leaf));
    const hostile = substitutedLogView({ [org.id]: attacker }, [admin, agent], [forgedRevocation]);

    const verdict = await verifyGrantChain([leaf, root], hostile, { now: NOW });
    // Not `grant_revoked`: the forged revocation is ignored, and the chain fails on the
    // substituted root instead. Ignoring it costs nothing — a host can already suppress a
    // genuine revocation by withholding it — while honoring it would let the host withdraw
    // anyone's grant.
    expect(verdict).toEqual({
      valid: false,
      reason: "grant_issuer_key_log_participant_mismatch"
    });
  });

  it("keeps substitution distinguishable from an absent log and from a cost refusal", async () => {
    // Three different failures with three different remedies: publish the log, raise the
    // allowance, stop trusting the host. Collapsing them sends operators to the wrong one.
    const forged = domainClaim(attacker);
    const absent = await verifyClaim(forged, makeView([]), { now: NOW });
    const substituted = await verifyClaim(forged, substitutedLogView({ [org.id]: attacker }), {
      now: NOW
    });

    expect(absent).toEqual({ valid: false, reason: "issuer_key_log_unresolved" });
    expect(substituted).toEqual({
      valid: false,
      reason: "issuer_key_log_participant_mismatch"
    });
  });
});

describe("record anchoring (spec 016)", () => {
  type KeyPair = ReturnType<typeof generateKeyPair>;
  type State = { keys: KeyPair[]; threshold: string };

  /**
   * Builds a replay-valid log over the exact key states given, in order.
   *
   * `createIdentity`/`rotateIdentity` cannot express these fixtures: the states here deliberately
   * SHARE keys across a rotation — a 3-of-3 shrinking to a 2-of-2 subset, a 2-of-3 retiring one
   * key and retaining two — which is precisely the shape 003's retired "no two states may share a
   * quorum" rule forbade and spec 016 brings back. Each event declares the threshold the previous
   * event committed and carries exactly that many signatures, in key order (015 S1/S3).
   */
  function logOf(states: State[], base: number): { id: ParticipantId; log: KeyEvent[] } {
    const refs = (keys: KeyPair[]): string[] => keys.map((k) => encodeKeyRef(k.publicKey));
    const tail: State = {
      keys: [generateKeyPair(seed(base + 90))],
      threshold: "1"
    };
    const nextOf = (index: number): State => states[index + 1] ?? tail;
    const signEvent = (unsigned: Omit<KeyEvent, "signature">, state: State): KeyEvent => ({
      ...unsigned,
      signature: state.keys
        .slice(0, Number(state.threshold))
        .map((k) => encodeSignature(sign(canonicalBytes(unsigned), k.secretKey)))
    });

    const first = states[0]!;
    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: refs(first.keys),
      threshold: first.threshold,
      next: commitToKeyState(refs(nextOf(0).keys), nextOf(0).threshold)
    };
    const id = deriveParticipantId(establishment);
    const log: KeyEvent[] = [signEvent({ ...establishment, id, prior: null }, first)];
    for (let index = 1; index < states.length; index += 1) {
      const state = states[index]!;
      log.push(
        signEvent(
          {
            id,
            seq: String(index),
            prior: eventDigest(log[index - 1]!),
            kind: "rot",
            keys: refs(state.keys),
            threshold: state.threshold,
            next: commitToKeyState(refs(nextOf(index).keys), nextOf(index).threshold)
          },
          state
        )
      );
    }
    return { id, log };
  }

  function viewOf(id: ParticipantId, log: KeyEvent[], revocations: Revocation[] = []): TrustView {
    return {
      async getKeyLog(asked) {
        return asked === id ? log : null;
      },
      async getRevocations(digest, issuerIds) {
        return revocations.filter((r) => r.revokes === digest && issuerIds.includes(r.issuerId));
      }
    };
  }

  const claimOf = (id: ParticipantId, key: KeyPair): Claim =>
    signRecord(
      {
        id: "claim-anchor-1",
        subjectId: id,
        claimType: "domain",
        value: "anchor.example",
        issuedBy: id,
        issuedAt: ISSUED_AT
      },
      key.secretKey
    ) as Claim;

  const revocationOf = (
    id: ParticipantId,
    digest: string,
    anchor: string,
    keys: KeyPair[]
  ): Revocation =>
    signThresholdRecord(
      { revokes: digest, issuerId: id, anchor, revokedAt: PAST },
      keys.map((k) => k.secretKey)
    ) as Revocation;

  it("rejects a chain link whose anchor names no event of its issuer's log", async () => {
    // 016: "a verifier MUST report that outcome distinguishably from a signature-set failure".
    // The link below is signed correctly by its issuer's current key — the ONLY thing wrong with
    // it is the state it names — so a resolver that folded this into `grant_signature_invalid`
    // would send an operator hunting a forgery where the answer is a state their view has not
    // seen.
    const unknown = canonicalDigest({ anchor: "no key event of this log" });
    const grant = rootGrant({ anchor: unknown });
    expect(await verifyGrantChain([grant], makeView([org, admin]), { now: NOW })).toEqual({
      valid: false,
      reason: "grant_issuer_anchor_unknown"
    });

    // The control: the same link, same keys, same everything, anchored to the issuer's real
    // state. It verifies — so the rejection above is about the anchor and nothing else.
    expect(await verifyGrantChain([rootGrant()], makeView([org, admin]), { now: NOW })).toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: admin.id,
      abilities: ["directory"]
    });

    // And the reason is NOT the signature reason, stated as an inequality because the two are
    // one enum apart and a consumer classifies on the string.
    const forged = rootGrant({ anchor: keyLogAnchor(org.log) });
    const tampered = signThresholdRecord({ ...forged }, [attacker.currentKeys[0]!.secretKey]);
    expect(
      await verifyGrantChain([tampered as Grant], makeView([org, admin]), { now: NOW })
    ).toEqual({ valid: false, reason: "grant_signature_invalid" });
  });

  it("honours a revocation anchored to a state the issuer has since rotated away from", async () => {
    // The producer rule's other half (016 _Producer rules_): a record MAY name any state whose
    // keys its issuer held, and a later rotation never orphans it — the log is append-only and
    // the named event stays where it is.
    const older = generateKeyPair(seed(150));
    const newer = generateKeyPair(seed(151));
    const { id, log } = logOf(
      [
        { keys: [older], threshold: "1" },
        { keys: [newer], threshold: "1" }
      ],
      150
    );
    const claim = claimOf(id, older);
    const digest = canonicalDigest(claim);

    const atOldState = revocationOf(id, digest, eventDigest(log[0]!), [older]);
    expect(await verifyClaim(claim, viewOf(id, log, [atOldState]), { now: NOW })).toEqual({
      valid: false,
      reason: "claim_revoked"
    });

    // ...and the tip state still works too, so the test above is not passing because anchoring
    // broke the ordinary case.
    const atTip = revocationOf(id, digest, keyLogAnchor(log), [newer]);
    expect(await verifyClaim(claim, viewOf(id, log, [atTip]), { now: NOW })).toEqual({
      valid: false,
      reason: "claim_revoked"
    });
  });

  it("ignores a revocation whose set satisfies the CURRENT state but names an earlier one", async () => {
    // The heart of 016: exactly one state is tried, and it is the one the record names. This
    // candidate is signed by the issuer's current key — under 015 S5's existential it revoked,
    // because SOME state accepted it — and it names the inception state, which does not.
    const older = generateKeyPair(seed(160));
    const newer = generateKeyPair(seed(161));
    const { id, log } = logOf(
      [
        { keys: [older], threshold: "1" },
        { keys: [newer], threshold: "1" }
      ],
      160
    );
    const claim = claimOf(id, older);
    const digest = canonicalDigest(claim);

    const misanchored = revocationOf(id, digest, eventDigest(log[0]!), [newer]);
    expect(await verifyClaim(claim, viewOf(id, log, [misanchored]), { now: NOW })).toEqual({
      valid: true
    });
  });

  it("closes the keyless edit of a 3-of-3 revocation against a 2-of-2 successor state", async () => {
    // The route 003's interim rule protected, on a log that rule made illegal and 016 makes legal
    // again: state A is 3-of-3 over {k1,k2,k3} and state B is 2-of-2 over {k1,k2} — a subset
    // sharing a full quorum of A.
    //
    // A genuine 3-of-3 revocation anchored at A is then edited by someone holding NO KEY: drop
    // the third member, and the remaining two are exactly what B requires, in B's key order. That
    // edit produced a different, still-valid revocation before 016. Now the record names A, the
    // edited set is two members against a threshold of three, and 015 S1 refuses it on its length
    // before any curve work — and rewriting the anchor to name B instead cannot help, because the
    // anchor is inside the bytes all three members signed.
    //
    // The log opens 1-of-1 only so that the revoked record can be a scalar-signed CLAIM: a claim
    // carries one signature and could not satisfy a multi-key threshold state. Events 1 and 2 are
    // the pair under test.
    const opening = generateKeyPair(seed(169));
    const k1 = generateKeyPair(seed(170));
    const k2 = generateKeyPair(seed(171));
    const k3 = generateKeyPair(seed(172));
    const { id, log } = logOf(
      [
        { keys: [opening], threshold: "1" },
        { keys: [k1, k2, k3], threshold: "3" },
        { keys: [k1, k2], threshold: "2" }
      ],
      170
    );
    const claim = claimOf(id, opening);
    const digest = canonicalDigest(claim);

    const genuine = revocationOf(id, digest, eventDigest(log[1]!), [k1, k2, k3]);
    expect(await verifyClaim(claim, viewOf(id, log, [genuine]), { now: NOW })).toEqual({
      valid: false,
      reason: "claim_revoked"
    });

    // Edit 1: delete the third member. Same anchor, same bytes under it — a keyless edit.
    const truncated = { ...genuine, signature: genuine.signature.slice(0, 2) } as Revocation;
    expect(await verifyClaim(claim, viewOf(id, log, [truncated]), { now: NOW })).toEqual({
      valid: true
    });

    // Edit 2: delete the member AND re-point the anchor at the 2-of-2 successor, which is the
    // move the whole route depended on. The two surviving signatures were made over bytes
    // carrying the OTHER anchor, so neither verifies here.
    const remapped = {
      ...genuine,
      anchor: eventDigest(log[2]!),
      signature: genuine.signature.slice(0, 2)
    } as Revocation;
    expect(await verifyClaim(claim, viewOf(id, log, [remapped]), { now: NOW })).toEqual({
      valid: true
    });
  });

  it("replays a 2-of-3 rotation that retains two keys, and verifies records at either state", async () => {
    // The rotation flexibility 016 buys back, stated as the shape 003's interim rule cost:
    // `|keys(A) n keys(B)| = 2` against `min(t_A, t_B) = 2`, so this log was rejected outright
    // and an M-of-N committee could not replace one member at a time.
    const opening = generateKeyPair(seed(179));
    const k1 = generateKeyPair(seed(180));
    const k2 = generateKeyPair(seed(181));
    const k3 = generateKeyPair(seed(182));
    const k4 = generateKeyPair(seed(183));
    const { id, log } = logOf(
      [
        { keys: [opening], threshold: "1" },
        { keys: [k1, k2, k3], threshold: "2" },
        { keys: [k1, k2, k4], threshold: "2" }
      ],
      180
    );
    const claim = claimOf(id, opening);
    const digest = canonicalDigest(claim);

    // The log replays — a scalar-signed claim against it verifies — and BOTH anchored records
    // verify, each at its own state, even though the two states accept the same signature set.
    expect(await verifyClaim(claim, viewOf(id, log), { now: NOW })).toEqual({ valid: true });
    for (const event of [log[1]!, log[2]!]) {
      const revocation = revocationOf(id, digest, eventDigest(event), [k1, k2]);
      expect(await verifyClaim(claim, viewOf(id, log, [revocation]), { now: NOW })).toEqual({
        valid: false,
        reason: "claim_revoked"
      });
    }
  });
});
