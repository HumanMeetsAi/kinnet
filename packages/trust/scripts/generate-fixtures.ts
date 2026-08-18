/**
 * Regenerates the committed trust-resolver conformance fixtures from deterministic
 * seeds. A spec change to 008/009/011 updates this script and the fixtures together.
 *
 * Run from the repo root (after `pnpm build`), then format — the committed files are
 * prettier-formatted, so skipping the last step shows every fixture as changed:
 *
 *   pnpm exec tsx packages/trust/scripts/generate-fixtures.ts
 *   pnpm format
 */
import { writeFileSync } from "node:fs";

import {
  canonicalDigest,
  createIdentity,
  encodeKeyRef,
  generateKeyPair,
  keyLogAnchor,
  rotateIdentity,
  signRecord,
  signThresholdRecord
} from "@kinnet/crypto";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const ISSUED_AT = "2026-06-12T00:00:00.000Z";
const REVOKED_AT = "2026-06-12T00:00:00.000Z";

// The organization rotates once so the fixture proves that records signed by an
// earlier key state stay verifiable against the published log.
const orgAtInception = createIdentity({ currentSeed: seed(11), nextSeed: seed(12) });
const org = rotateIdentity(orgAtInception, { nextSeeds: [seed(13)] });
const admin = createIdentity({ currentSeed: seed(21), nextSeed: seed(22) });
const agent = createIdentity({ currentSeed: seed(31), nextSeed: seed(32) });

// The represents edge, signed by the organization's inception key (pre-rotation).
const edge = signRecord(
  {
    id: "fixture-represents-1",
    subjectId: agent.id,
    predicate: "represents",
    objectId: org.id,
    issuedBy: org.id,
    issuedAt: ISSUED_AT
  },
  orgAtInception.currentKeys[0]!.secretKey
);

// Grant chain: org self-issues "directory" to the admin (signed with the rotated,
// current keys), and the admin attenuates "directory/curate" down to the agent.
const rootGrant = signThresholdRecord(
  {
    subjectId: org.id,
    issuerId: org.id,
    audienceId: admin.id,
    abilities: ["directory"],
    caveats: {},
    // Spec 016: a participant-issued grant names the key state it is signed under. The org
    // signs with its ROTATED keys, so the anchor is its log's tip.
    anchor: keyLogAnchor(org.log),
    proof: null,
    issuedAt: ISSUED_AT
  },
  [org.currentKeys[0]!.secretKey]
);

const leafGrant = signThresholdRecord(
  {
    subjectId: org.id,
    issuerId: admin.id,
    audienceId: agent.id,
    abilities: ["directory/curate"],
    caveats: {},
    anchor: keyLogAnchor(admin.log),
    proof: canonicalDigest(rootGrant),
    issuedAt: ISSUED_AT
  },
  [admin.currentKeys[0]!.secretKey]
);

// A claim the organization issued and later revoked with its current keys.
const revokedClaim = signRecord(
  {
    id: "fixture-claim-1",
    subjectId: org.id,
    claimType: "domain",
    value: "acme.example",
    issuedBy: org.id,
    issuedAt: ISSUED_AT
  },
  orgAtInception.currentKeys[0]!.secretKey
);

const revocation = signThresholdRecord(
  {
    revokes: canonicalDigest(revokedClaim),
    issuerId: org.id,
    // Spec 016: required on every Revocation.
    anchor: keyLogAnchor(org.log),
    revokedAt: REVOKED_AT,
    reason: "domain handed back"
  },
  [org.currentKeys[0]!.secretKey]
);

const fixture = {
  description:
    "Trust-resolver conformance fixture (specs 008/009): an org -> agent represents " +
    "chain with a bounding two-link grant chain, plus a revoked claim. The org log " +
    "contains one rotation; the edge and claim are signed by the pre-rotation key and " +
    "verify against any state (scalar signatures, outside spec 016), while the grants " +
    "and the revocation carry a spec-016 anchor naming the post-rotation state.",
  verifyAt: "2026-06-12T12:00:00.000Z",
  organizationLog: org.log,
  adminLog: admin.log,
  agentLog: agent.log,
  edge,
  grants: [leafGrant, rootGrant],
  revokedClaim,
  revocation,
  expect: {
    organizationId: org.id,
    agentId: agent.id,
    edgeDigest: canonicalDigest(edge),
    rootGrantDigest: canonicalDigest(rootGrant),
    leafGrantDigest: canonicalDigest(leafGrant),
    representsValid: true,
    abilities: ["directory/curate"],
    revokedClaimReason: "claim_revoked"
  }
};

const target = new URL("../test/fixtures/represents-chain.json", import.meta.url);
writeFileSync(target, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`Wrote ${target.pathname}`);

// --- Delegated chain (spec 011): user → session key → backend service ---------------

const DELEGATED_ISSUED_AT = "2026-07-01T00:00:00.000Z";
const SESSION_EXPIRES_AT = "2026-08-01T00:00:00.000Z";

const user = createIdentity({ currentSeed: seed(41), nextSeed: seed(42) });
const service = createIdentity({ currentSeed: seed(51), nextSeed: seed(52) });
// A disposable browser session key: no participant id, no log — the only bytes that
// reference it are the grants below.
const sessionKey = generateKeyPair(seed(61));
const sessionKeyRef = encodeKeyRef(sessionKey.publicKey);

// Root: the user self-issues its messaging authority, bound to the one service the
// chain may ever be presented to.
const delegatedRoot = signThresholdRecord(
  {
    subjectId: user.id,
    issuerId: user.id,
    audienceId: user.id,
    abilities: ["msg"],
    caveats: { aud: [service.id] },
    anchor: keyLogAnchor(user.log),
    proof: null,
    issuedAt: DELEGATED_ISSUED_AT
  },
  [user.currentKeys[0]!.secretKey]
);

// Session link: the user delegates to the session key — a key audience, so expiry and
// aud are mandatory (spec 011 validity rules).
const sessionGrant = signThresholdRecord(
  {
    subjectId: user.id,
    issuerId: user.id,
    audienceId: sessionKeyRef,
    abilities: ["msg"],
    caveats: { aud: [service.id] },
    anchor: keyLogAnchor(user.log),
    proof: canonicalDigest(delegatedRoot),
    issuedAt: DELEGATED_ISSUED_AT,
    expiresAt: SESSION_EXPIRES_AT
  },
  [user.currentKeys[0]!.secretKey]
);

// Leaf: the session key re-delegates an attenuated sub-grant to the backend service —
// a key-issued link, self-certifying with exactly one signature.
const serviceGrant = signThresholdRecord(
  {
    subjectId: user.id,
    issuerId: sessionKeyRef,
    audienceId: service.id,
    abilities: ["msg/send"],
    caveats: { aud: [service.id] },
    // NO anchor: a bare-key issuer has no key log and exactly one constructive state, so
    // spec 016 forbids the field here and `grantSchema` rejects a link that carries it.
    proof: canonicalDigest(sessionGrant),
    issuedAt: DELEGATED_ISSUED_AT,
    expiresAt: SESSION_EXPIRES_AT
  },
  [sessionKey.secretKey]
);

const delegatedFixture = {
  description:
    "Trust-resolver conformance fixture (spec 011): a three-link delegated chain — " +
    "the user self-issues 'msg' bound to one service, delegates to a disposable " +
    "session key (key audience: expiry and aud mandatory), and the session key " +
    "re-delegates an attenuated 'msg/send' sub-grant to the backend service " +
    "(key-issued link: exactly one self-certifying signature, and — spec 016 — no " +
    "anchor, unlike the two participant-issued links above). Verifiable from " +
    "these bytes alone with the service as verifier.",
  verifyAt: "2026-07-21T12:00:00.000Z",
  verifierId: service.id,
  userLog: user.log,
  serviceLog: service.log,
  sessionKeyRef,
  grants: [serviceGrant, sessionGrant, delegatedRoot],
  expect: {
    userId: user.id,
    serviceId: service.id,
    sessionKeyRef,
    rootGrantDigest: canonicalDigest(delegatedRoot),
    sessionGrantDigest: canonicalDigest(sessionGrant),
    serviceGrantDigest: canonicalDigest(serviceGrant),
    valid: true,
    abilities: ["msg/send"]
  }
};

const delegatedTarget = new URL("../test/fixtures/delegated-chain.json", import.meta.url);
writeFileSync(delegatedTarget, `${JSON.stringify(delegatedFixture, null, 2)}\n`);
console.log(`Wrote ${delegatedTarget.pathname}`);

// --- Aud-less chain (spec 011 `aud` absent): user → app → service, all participants ----

// `aud` is mandatory only for key audiences (011), so a chain whose every audience is a
// participant may legally carry none — and an unrestricted chain names no verifier, so
// every verifier admits it. This fixture pins both halves of that: valid as presented,
// and rejected by a verifier that demands audience binding (`requireAud`).
const appService = createIdentity({ currentSeed: seed(71), nextSeed: seed(72) });

const audlessRoot = signThresholdRecord(
  {
    subjectId: user.id,
    issuerId: user.id,
    audienceId: appService.id,
    abilities: ["msg"],
    caveats: {},
    anchor: keyLogAnchor(user.log),
    proof: null,
    issuedAt: DELEGATED_ISSUED_AT
  },
  [user.currentKeys[0]!.secretKey]
);

const audlessLeaf = signThresholdRecord(
  {
    subjectId: user.id,
    issuerId: appService.id,
    audienceId: service.id,
    abilities: ["msg/send"],
    caveats: {},
    anchor: keyLogAnchor(appService.log),
    proof: canonicalDigest(audlessRoot),
    issuedAt: DELEGATED_ISSUED_AT
  },
  [appService.currentKeys[0]!.secretKey]
);

const audlessFixture = {
  description:
    "Trust-resolver conformance fixture (spec 011, `aud` absent): a two-link chain " +
    "between participants only, so no link is required to carry an `aud` caveat and " +
    "none does. Verifiable from these bytes alone: valid at ANY verifier id, and " +
    "rejected as 'grant_audience_required' by a verifier that sets requireAud.",
  verifyAt: "2026-07-21T12:00:00.000Z",
  userLog: user.log,
  appLog: appService.log,
  serviceLog: service.log,
  grants: [audlessLeaf, audlessRoot],
  expect: {
    userId: user.id,
    appId: appService.id,
    serviceId: service.id,
    rootGrantDigest: canonicalDigest(audlessRoot),
    leafGrantDigest: canonicalDigest(audlessLeaf),
    valid: true,
    abilities: ["msg/send"],
    requireAudReason: "grant_audience_required"
  }
};

const audlessTarget = new URL("../test/fixtures/audless-chain.json", import.meta.url);
writeFileSync(audlessTarget, `${JSON.stringify(audlessFixture, null, 2)}\n`);
console.log(`Wrote ${audlessTarget.pathname}`);

// --- Financial-caveat chain (spec 009 fail-closed caveats): treasury → ops → agent -------

// Spec 009 leaves the non-`aud` caveat vocabulary to the relying party and makes the
// verifier fail closed on all of it. This fixture pins one such vocabulary — the financial
// caveats in `src/financial-caveats.ts` — as BYTES, so a third party can reproduce all
// three verdicts (conforming action, over-cap action, no evaluator) from this file alone
// and check their own evaluator against ours.
const FINANCIAL_ISSUED_AT = "2026-08-01T00:00:00.000Z";

const treasury = createIdentity({ currentSeed: seed(81), nextSeed: seed(82) });
const opsService = createIdentity({ currentSeed: seed(91), nextSeed: seed(92) });
const paymentAgent = createIdentity({ currentSeed: seed(101), nextSeed: seed(102) });

// Root: the treasury self-issues its unbounded payment authority to the ops service. No
// caveats at all — the bound is imposed one link down, which is the point of the fixture.
const financialRoot = signThresholdRecord(
  {
    subjectId: treasury.id,
    issuerId: treasury.id,
    audienceId: opsService.id,
    abilities: ["payments"],
    caveats: {},
    anchor: keyLogAnchor(treasury.log),
    proof: null,
    issuedAt: FINANCIAL_ISSUED_AT
  },
  [treasury.currentKeys[0]!.secretKey]
);

// Leaf: ops attenuates the ability to `payments/transfer` AND caps what it may move —
// at most 1000.00 USD, to one of two named beneficiaries. Both audiences are participants,
// so spec 011 requires no `aud` and these three are the only caveats on the chain.
const financialLeaf = signThresholdRecord(
  {
    subjectId: treasury.id,
    issuerId: opsService.id,
    audienceId: paymentAgent.id,
    abilities: ["payments/transfer"],
    caveats: {
      maxAmount: "1000.00",
      currency: "USD",
      beneficiary: ["acct:vendor-7", "acct:vendor-9"]
    },
    anchor: keyLogAnchor(opsService.log),
    proof: canonicalDigest(financialRoot),
    issuedAt: FINANCIAL_ISSUED_AT
  },
  [opsService.currentKeys[0]!.secretKey]
);

const financialFixture = {
  description:
    "Trust-resolver conformance fixture (spec 009 fail-closed caveats): a two-link " +
    "payment chain whose leaf carries the financial caveat vocabulary — maxAmount, " +
    "currency and a two-entry beneficiary allow-list. Verifiable from these bytes " +
    "alone: valid for the conforming action, 'grant_caveat_rejected' for an action one " +
    "minor unit over the cap, 'grant_caveat_rejected' with no evaluator supplied at " +
    "all, and 'grant_signature_invalid' when the cap digit is raised in place — the " +
    "caveats are signed, so a self-service raise is a forgery.",
  verifyAt: "2026-08-05T12:00:00.000Z",
  treasuryLog: treasury.log,
  opsLog: opsService.log,
  agentLog: paymentAgent.log,
  grants: [financialLeaf, financialRoot],
  // The relying party's description of the pending side effect. Not signed and not part of
  // the chain — the chain bounds it. Committed so the verdicts below are reproducible.
  conformingAction: {
    amount: "250.75",
    currency: "USD",
    beneficiary: "acct:vendor-7"
  },
  overAmountAction: {
    amount: "1000.01",
    currency: "USD",
    beneficiary: "acct:vendor-7"
  },
  expect: {
    treasuryId: treasury.id,
    opsId: opsService.id,
    agentId: paymentAgent.id,
    rootGrantDigest: canonicalDigest(financialRoot),
    leafGrantDigest: canonicalDigest(financialLeaf),
    caveats: financialLeaf.caveats,
    valid: true,
    abilities: ["payments/transfer"],
    overAmountReason: "grant_caveat_rejected",
    noEvaluatorReason: "grant_caveat_rejected",
    raisedCapReason: "grant_signature_invalid"
  }
};

const financialTarget = new URL("../test/fixtures/financial-chain.json", import.meta.url);
writeFileSync(financialTarget, `${JSON.stringify(financialFixture, null, 2)}\n`);
console.log(`Wrote ${financialTarget.pathname}`);
