/**
 * Unit tests for spec 014's pinned `(record, chain)` verification profile
 * (§"What verifies a unit — the profile, pinned"). Everything here is about the
 * PROFILE — a node's route-level behavior is that surface's own to test.
 */
import {
  canonicalDigest,
  createIdentity,
  encodeKeyRef,
  generateKeyPair,
  rotateIdentity,
  signThresholdRecord
} from "@kinnet/crypto";
import {
  ABILITY_CONVERSATION_SELF_REMOVE,
  type Conversation,
  type ConversationUpdate,
  type Grant,
  type KeyEvent,
  type Revocation
} from "@kinnet/protocol";
import { GRANT_CHAIN_COST_REASONS, type TrustView } from "@kinnet/trust";
import { describe, expect, it } from "vitest";

import {
  isUnitCostReason,
  isUnitWaitReason,
  UNIT_COST_REASONS,
  UNIT_WAIT_REASONS,
  verifyConversationRecordUnit,
  verifyConversationUpdateUnit
} from "../src/record-unit.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

/** The chain's window; the record sits inside it, "now" sits far outside it. */
const ISSUED_AT = "2026-07-01T00:00:00.000Z";
const EXPIRES_AT = "2026-08-01T00:00:00.000Z";
const CREATED_AT = "2026-07-15T12:00:00.000Z";

const node = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });

const actor = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
const other = createIdentity({ currentSeed: seed(5), nextSeed: seed(6) });

const session = generateKeyPair(seed(7));
const sessionKeyRef = encodeKeyRef(session.publicKey);
const strangerSession = generateKeyPair(seed(8));

const CONVERSATION_ID = canonicalDigest({ conversation: "fixture" });
const LEAF = encodeKeyRef(generateKeyPair(seed(9)).publicKey);
const GROUP_NONCE = "zCs8KY3PiWrCMAytMsBRQo8EdGbticVtdvufLnb2UhXh";

function makeView(config: {
  logs: Record<string, KeyEvent[]>;
  revocations?: Record<string, Revocation[]>;
}): TrustView {
  return {
    getKeyLog: async (id) => config.logs[id] ?? null,
    getRevocations: async (digest, issuerIds) =>
      (config.revocations?.[digest] ?? []).filter((r) => issuerIds.includes(r.issuerId))
  };
}

/** A session grant from `issuer` to a key, leaf-first single-link chain. */
function grant(
  issuer: ReturnType<typeof createIdentity>,
  overrides: Partial<Grant> = {},
  secretKey = issuer.currentKeys[0]!.secretKey
): Grant {
  return signThresholdRecord(
    {
      subjectId: issuer.id,
      issuerId: issuer.id,
      audienceId: sessionKeyRef,
      abilities: ["msg/conversation-update"],
      caveats: { aud: [node.id] },
      proof: null,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      ...overrides
    },
    [secretKey]
  ) as Grant;
}

type UpdateFields = Partial<Omit<ConversationUpdate, "signature">>;

function updateBody(overrides: UpdateFields = {}): Omit<ConversationUpdate, "signature"> {
  return {
    conversationId: CONVERSATION_ID,
    kind: "add",
    members: [other.id],
    leaves: [LEAF],
    actor: actor.id,
    epoch: "3",
    createdAt: CREATED_AT,
    ...overrides
  };
}

/** Owner-signed evidence: the actor's own threshold key state signs the record. */
function ownerUpdate(overrides: UpdateFields = {}, secretKey = actor.currentKeys[0]!.secretKey) {
  return signThresholdRecord(updateBody(overrides), [secretKey]) as ConversationUpdate;
}

/** Delegated-signed evidence: a session key signs the record; a chain authorizes the key. */
function sessionUpdate(overrides: UpdateFields = {}, secretKey = session.secretKey) {
  return signThresholdRecord(updateBody(overrides), [secretKey]) as ConversationUpdate;
}

/** A self-departure: `remove` whose `members` is exactly `[actor]` (spec 014). */
const SELF_DEPARTURE: UpdateFields = { kind: "remove", members: [actor.id] };
/** A device record: `members` is exactly `[actor]` too, but it is not a departure. */
const DEVICE_ADD: UpdateFields = { kind: "device-add", members: [actor.id] };

describe("verifyConversationUpdateUnit — owner mode (spec 014, chain absent)", () => {
  it("accepts a record signed by a key state the actor has since rotated away from", async () => {
    // The rule that matters: ANY replay-valid state, not just the current one. A
    // current-state-only check would retroactively un-authorize committed membership.
    const record = ownerUpdate();
    const rotated = rotateIdentity(actor);
    const view = makeView({ logs: { [actor.id]: rotated.log } });

    expect(
      await verifyConversationUpdateUnit(record, null, view, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("accepts a record signed by the actor's current state", async () => {
    const record = ownerUpdate();
    const view = makeView({ logs: { [actor.id]: actor.log } });

    expect(
      await verifyConversationUpdateUnit(record, null, view, { checkRevocation: false })
    ).toEqual({ valid: true });
  });

  it("rejects a record signed by somebody else's key", async () => {
    const record = ownerUpdate({}, other.currentKeys[0]!.secretKey);
    const view = makeView({ logs: { [actor.id]: actor.log, [other.id]: other.log } });

    expect(
      await verifyConversationUpdateUnit(record, null, view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "signature_invalid" });
  });

  it("waits — never throws — when the actor's key log cannot be resolved", async () => {
    const record = ownerUpdate();
    const view = makeView({ logs: {} });

    const verdict = await verifyConversationUpdateUnit(record, null, view, {
      checkRevocation: true
    });
    expect(verdict).toEqual({ valid: false, reason: "actor_key_log_unresolved" });
    expect(isUnitWaitReason("actor_key_log_unresolved")).toBe(true);
  });

  it("separates a log it would not pay for from one it could not find", async () => {
    const record = ownerUpdate();
    // A real, valid log the view simply will not spend enough to replay. Spec 003 makes a
    // work ceiling a local resource policy, not a validity rule, so this must not read as
    // "unresolved" — the actor's log is neither missing nor wrong.
    const starved: TrustView = {
      ...makeView({ logs: { [actor.id]: actor.log } }),
      maxSignatureVerifications: 0
    };

    const verdict = await verifyConversationUpdateUnit(record, null, starved, {
      checkRevocation: true
    });
    expect(verdict).toEqual({ valid: false, reason: "actor_key_log_too_expensive" });
    // And it WAITS rather than rejecting: the record may be perfectly good, and raising the
    // allowance is what clears it.
    expect(isUnitWaitReason("actor_key_log_too_expensive")).toBe(true);

    // The same view with an allowance that covers the log verifies it.
    const funded: TrustView = {
      ...makeView({ logs: { [actor.id]: actor.log } }),
      maxSignatureVerifications: 1024
    };
    expect(
      await verifyConversationUpdateUnit(record, null, funded, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("spends ONE allowance across the whole unit, not one per key state", async () => {
    // BLOCKER 1. A budget handed fresh to every key state bounds nothing: one
    // `verifyThresholdRecord` call now caps at one greedy walk over the keys, far under any
    // sane outer ceiling, so reminting the allowance for each state would let a maximal
    // `states x keys` walk appear metered. It must be shared across states and with replay.
    let rotated = actor;
    for (let index = 0; index < 12; index += 1) {
      rotated = rotateIdentity(rotated);
    }
    const log = rotated.log;
    // Signed by the ORIGINAL key, the oldest state, so the newest-first search must walk the
    // whole history to reach it — the shape that actually spends.
    const record = ownerUpdate({}, actor.currentKeys[0]!.secretKey);

    const view = (max: number): TrustView => ({
      maxSignatureVerifications: max,
      getKeyLog: async () => log,
      getRevocations: async () => []
    });

    // 13 events to replay plus 13 states to search: 26. Funded, it verifies.
    expect(
      await verifyConversationUpdateUnit(record, null, view(26), { checkRevocation: true })
    ).toEqual({ valid: true });

    // One short, it is refused ON COST — which is only possible if the replay and the search
    // draw on the same allowance. Per-call budgets would each see 13 and never fire.
    expect(
      await verifyConversationUpdateUnit(record, null, view(25), { checkRevocation: true })
    ).toEqual({ valid: false, reason: "actor_key_log_too_expensive" });
  });

  it("honours a caller-supplied budget instead of building its own", async () => {
    // `options.budget` is how a request handler makes one allowance cover several
    // verifications. If this ignored it and built a fresh one from the view, the budget would
    // bound this call alone and a handler running three of them would spend three.
    let rotated = actor;
    for (let index = 0; index < 12; index += 1) {
      rotated = rotateIdentity(rotated);
    }
    const log = rotated.log;
    const record = ownerUpdate({}, actor.currentKeys[0]!.secretKey);
    // A view whose OWN ceiling is generous, so anything that falls back to it succeeds.
    const view: TrustView = {
      maxSignatureVerifications: 1_000_000,
      getKeyLog: async () => log,
      getRevocations: async () => []
    };

    // Handed a budget large enough, it verifies AND the spend shows on the caller's object.
    const funded = { remaining: 1_000_000 };
    expect(
      await verifyConversationUpdateUnit(record, null, view, {
        checkRevocation: true,
        budget: funded
      })
    ).toEqual({ valid: true });
    const spent = 1_000_000 - funded.remaining;
    expect(spent).toBe(26);

    // Handed one that cannot pay, it refuses — even though the VIEW would have allowed it.
    // That is the whole assertion: the caller's allowance is what binds, not the view's.
    const starved = { remaining: spent - 1 };
    expect(
      await verifyConversationUpdateUnit(record, null, view, {
        checkRevocation: true,
        budget: starved
      })
    ).toEqual({ valid: false, reason: "actor_key_log_too_expensive" });
  });

  it("waits — never throws — when the view itself is unreachable", async () => {
    const record = ownerUpdate();
    const view: TrustView = {
      getKeyLog: async () => {
        throw new Error("discovery unreachable");
      },
      getRevocations: async () => []
    };

    await expect(
      verifyConversationUpdateUnit(record, null, view, { checkRevocation: true })
    ).resolves.toEqual({ valid: false, reason: "actor_key_log_unresolved" });
  });
});

describe("verifyConversationUpdateUnit — delegated mode (spec 014, chain present)", () => {
  const view = makeView({ logs: { [actor.id]: actor.log, [other.id]: other.log } });

  it("accepts a session-signed record whose chain covers msg/conversation-update", async () => {
    const record = sessionUpdate();

    expect(
      await verifyConversationUpdateUnit(record, [grant(actor)], view, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("rejects a chain whose subject is not the record's actor", async () => {
    // Well-formed chain, wrong principal: `other` delegated to this session key, but the
    // record claims `actor` authored it.
    const record = sessionUpdate();

    expect(
      await verifyConversationUpdateUnit(record, [grant(other)], view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "chain_invalid:subject_not_actor" });
  });

  it("rejects a record that does not verify against the chain's leaf key", async () => {
    const record = sessionUpdate({}, strangerSession.secretKey);

    expect(
      await verifyConversationUpdateUnit(record, [grant(actor)], view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "chain_invalid:leaf_key_signature_invalid" });
  });

  it("rejects a record carrying a second, unauthorized signature", async () => {
    // Threshold verification accepts on any matching member of the signature set and ignores the
    // rest, while `canonicalDigest` covers `signature` — so without the length rule an attacker
    // could append junk to a valid unit and mint a second, distinct, equally-valid record for the
    // same logical change. No new authority (the epoch one-shot pins the change), but it forges a
    // second identity for it, and identity-by-digest is what commit bindings and "records are
    // idempotent by digest" rest on. In delegated mode there is exactly one authorized signer.
    const record = sessionUpdate();
    const stranger = sessionUpdate({}, strangerSession.secretKey);
    const appended = {
      ...record,
      signature: [...record.signature, ...stranger.signature]
    } as ConversationUpdate;
    // It really is a second identity for the same change: same body, different digest.
    expect(canonicalDigest(appended)).not.toEqual(canonicalDigest(record));

    expect(
      await verifyConversationUpdateUnit(appended, [grant(actor)], view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "chain_invalid:leaf_key_signature_invalid" });
    // …and the authorized signature alone still verifies, so nothing legitimate is refused.
    expect(
      await verifyConversationUpdateUnit(record, [grant(actor)], view, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("rejects a chain whose leaf audience is a participant rather than a bare KeyRef", async () => {
    // A participant-audience leaf names no signing key, so it can bind none (spec 011).
    const record = sessionUpdate();
    const chain = [grant(actor, { audienceId: other.id })];

    expect(
      await verifyConversationUpdateUnit(record, chain, view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "chain_invalid:audience_not_key" });
  });

  it("rejects a chain whose abilities do not cover msg/conversation-update", async () => {
    const record = sessionUpdate();
    const chain = [grant(actor, { abilities: ["msg/read"] })];

    expect(
      await verifyConversationUpdateUnit(record, chain, view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "chain_invalid:abilities_insufficient" });
  });

  it("accepts a bare-`msg` umbrella chain for a device-add", async () => {
    // 009's path-prefix rule: `msg` covers `msg/conversation-update`, unchanged.
    const record = sessionUpdate(DEVICE_ADD);
    const chain = [grant(actor, { abilities: ["msg"] })];

    expect(
      await verifyConversationUpdateUnit(record, chain, view, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("rejects a bare-`msg` umbrella chain for a self-departure", async () => {
    // The split pinned by the 2026-08-02 amendment: an everyday session grant no longer
    // carries unilateral self-expulsion authority.
    const record = sessionUpdate(SELF_DEPARTURE);

    for (const abilities of [["msg"], ["msg/conversation-update"]]) {
      const chain = [grant(actor, { abilities })];
      expect(
        await verifyConversationUpdateUnit(record, chain, view, { checkRevocation: true })
      ).toEqual({ valid: false, reason: "chain_invalid:abilities_insufficient" });
    }
  });

  it("accepts a conversation/self-remove chain for a self-departure", async () => {
    const record = sessionUpdate(SELF_DEPARTURE);
    const chain = [grant(actor, { abilities: [ABILITY_CONVERSATION_SELF_REMOVE] })];

    expect(
      await verifyConversationUpdateUnit(record, chain, view, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("accepts a chain expired at the wall clock but valid at the record's createdAt", async () => {
    // Rule 5: windows are measured against the record's own time, never the clock. This
    // test is the whole point of re-delivery and joiner relay working at all.
    const record = sessionUpdate();
    const chain = [grant(actor, { expiresAt: "2026-07-16T00:00:00.000Z" })];
    expect(Date.now()).toBeGreaterThan(Date.parse("2026-07-16T00:00:00.000Z"));

    expect(
      await verifyConversationUpdateUnit(record, chain, view, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("rejects a record dated before the chain link it cites was issued", async () => {
    // The lower half of the window: `createdAt` is signer-chosen, so without it a record
    // could cite authority that did not yet exist when it claims to have been written.
    const record = sessionUpdate({ createdAt: "2026-06-01T00:00:00.000Z" });

    expect(
      await verifyConversationUpdateUnit(record, [grant(actor)], view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "chain_invalid:grant_not_yet_issued" });
  });

  it("splits on checkRevocation: the node rejects a revoked chain, a member does not", async () => {
    const record = sessionUpdate();
    const chain = [grant(actor)];
    const revocation = signThresholdRecord(
      { revokes: canonicalDigest(chain[0]!), issuerId: actor.id, revokedAt: CREATED_AT },
      [actor.currentKeys[0]!.secretKey]
    ) as Revocation;
    const revokedView = makeView({
      logs: { [actor.id]: actor.log },
      revocations: { [revocation.revokes]: [revocation] }
    });

    expect(
      await verifyConversationUpdateUnit(record, chain, revokedView, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "chain_invalid:grant_revoked" });
    expect(
      await verifyConversationUpdateUnit(record, chain, revokedView, { checkRevocation: false })
    ).toEqual({ valid: true });
  });

  it("waits — never throws — when the chain issuer's key log cannot be resolved", async () => {
    const record = sessionUpdate();
    const emptyView = makeView({ logs: {} });

    const verdict = await verifyConversationUpdateUnit(record, [grant(actor)], emptyView, {
      checkRevocation: true
    });
    expect(verdict).toEqual({
      valid: false,
      reason: "chain_invalid:grant_issuer_key_log_unresolved"
    });
    expect(isUnitWaitReason("chain_invalid:grant_issuer_key_log_unresolved")).toBe(true);
  });

  it("does not treat a chain-carrying unit's chain as decoration (decision D)", async () => {
    // A record that owner-verifies perfectly, presented with a chain that verifies not at
    // all. Fail closed: there is exactly one reason a unit is valid, and evaluation order
    // must never decide the verdict.
    const record = ownerUpdate();
    const garbage = [{ ...grant(actor), abilities: ["msg"] } as Grant];

    const verdict = await verifyConversationUpdateUnit(record, garbage, view, {
      checkRevocation: true
    });
    expect(verdict.valid).toBe(false);
    expect(verdict).toEqual({ valid: false, reason: "chain_invalid:grant_signature_invalid" });
    // …and the very same record verifies in owner mode when no chain is presented.
    expect(
      await verifyConversationUpdateUnit(record, null, view, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("rejects a present-but-empty chain rather than falling back to owner mode", async () => {
    const record = ownerUpdate();

    expect(await verifyConversationUpdateUnit(record, [], view, { checkRevocation: true })).toEqual(
      {
        valid: false,
        reason: "chain_invalid:grant_chain_empty"
      }
    );
  });

  it("rejects a malformed record before reading its fields", async () => {
    const record = { ...ownerUpdate(), members: [] } as unknown as ConversationUpdate;

    expect(
      await verifyConversationUpdateUnit(record, null, view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "record_malformed" });
  });
});

describe("verifyConversationRecordUnit — the same unit over spec 012's record", () => {
  const participants = [actor.id, other.id].sort();

  function conversationBody(): Omit<Conversation, "signature"> {
    return {
      creator: actor.id,
      participants,
      createdAt: CREATED_AT,
      lane: "e2ee",
      groupNonce: GROUP_NONCE
    };
  }

  const view = makeView({ logs: { [actor.id]: actor.log, [other.id]: other.log } });

  it("accepts an owner-signed record against a rotated-away key state", async () => {
    const record = signThresholdRecord(conversationBody(), [
      actor.currentKeys[0]!.secretKey
    ]) as Conversation;
    const rotated = rotateIdentity(actor);
    const rotatedView = makeView({ logs: { [actor.id]: rotated.log } });

    expect(
      await verifyConversationRecordUnit(record, null, rotatedView, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("accepts a delegated-signed record whose chain covers msg/conversation", async () => {
    const record = signThresholdRecord(conversationBody(), [session.secretKey]) as Conversation;
    const chain = [grant(actor, { abilities: ["msg/conversation"] })];

    expect(
      await verifyConversationRecordUnit(record, chain, view, { checkRevocation: true })
    ).toEqual({ valid: true });
  });

  it("rejects a chain whose abilities cover only msg/conversation-update", async () => {
    // The generative rule mints a distinct ability per reserved type: authority over
    // evidence is not authority over the conversation record.
    const record = signThresholdRecord(conversationBody(), [session.secretKey]) as Conversation;
    const chain = [grant(actor, { abilities: ["msg/conversation-update"] })];

    expect(
      await verifyConversationRecordUnit(record, chain, view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "chain_invalid:abilities_insufficient" });
  });

  it("rejects a chain whose subject is not the record's creator", async () => {
    const record = signThresholdRecord(conversationBody(), [session.secretKey]) as Conversation;
    const chain = [grant(other, { abilities: ["msg/conversation"] })];

    expect(
      await verifyConversationRecordUnit(record, chain, view, { checkRevocation: true })
    ).toEqual({ valid: false, reason: "chain_invalid:subject_not_creator" });
  });

  it("waits — never throws — when the creator's key log cannot be resolved", async () => {
    const record = signThresholdRecord(conversationBody(), [
      actor.currentKeys[0]!.secretKey
    ]) as Conversation;

    const verdict = await verifyConversationRecordUnit(record, null, makeView({ logs: {} }), {
      checkRevocation: true
    });
    expect(verdict).toEqual({ valid: false, reason: "creator_key_log_unresolved" });
    expect(isUnitWaitReason("creator_key_log_unresolved")).toBe(true);
  });
});

/**
 * The substituted-log attack against unit verification. Every log here replays perfectly and
 * every signature is genuine — the attacker holds none of the victim's keys. The only thing
 * that makes a unit the victim's is that the log discovery served for the victim's id derives
 * the victim's id, and this block is the test that nothing else was ever checked.
 */
describe("substituted key logs — a view serving another participant's valid log", () => {
  const attacker = createIdentity({ currentSeed: seed(31), nextSeed: seed(32) });

  /** Discovery answers `actor`/`creator` with the attacker's own genuine log. */
  const substituted = makeView({ logs: { [actor.id]: attacker.log } });

  const conversationBody: Omit<Conversation, "signature"> = {
    creator: actor.id,
    participants: [actor.id, other.id].sort(),
    createdAt: CREATED_AT,
    lane: "e2ee",
    groupNonce: GROUP_NONCE
  };

  it("rejects an owner-mode update the attacker signed in the actor's name", async () => {
    // Owner mode's entire authority IS the key state, so a substituted log hands the attacker
    // the actor's authorship of committed membership evidence.
    const record = ownerUpdate({}, attacker.currentKeys[0]!.secretKey);
    expect(record.actor).toBe(actor.id);

    expect(
      await verifyConversationUpdateUnit(record, null, substituted, { checkRevocation: false })
    ).toEqual({ valid: false, reason: "actor_key_log_participant_mismatch" });
  });

  it("rejects a self-departure the attacker signed in the actor's name", async () => {
    // The nastiest shape of the same thing: a self-departure is self-authorizing, every member
    // commits it, and add authority is creator-only — so the victim cannot restore themselves.
    const record = ownerUpdate(SELF_DEPARTURE, attacker.currentKeys[0]!.secretKey);

    expect(
      await verifyConversationUpdateUnit(record, null, substituted, { checkRevocation: false })
    ).toEqual({ valid: false, reason: "actor_key_log_participant_mismatch" });
  });

  it("rejects an owner-mode conversation record the attacker signed as the creator", async () => {
    const record = signThresholdRecord(conversationBody, [
      attacker.currentKeys[0]!.secretKey
    ]) as Conversation;

    expect(
      await verifyConversationRecordUnit(record, null, substituted, { checkRevocation: false })
    ).toEqual({ valid: false, reason: "creator_key_log_participant_mismatch" });
  });

  it("rejects a delegated unit whose chain issuer's log was substituted", async () => {
    // Delegated mode routes the same question through `@kinnet/trust`: the chain is rooted at
    // a grant self-issued by the actor, so a substituted actor log lets the attacker mint the
    // session authority the record is then signed under.
    const record = sessionUpdate();
    const chain = [grant(actor, {}, attacker.currentKeys[0]!.secretKey)];

    expect(
      await verifyConversationUpdateUnit(record, chain, substituted, { checkRevocation: false })
    ).toEqual({
      valid: false,
      reason: "chain_invalid:grant_issuer_key_log_participant_mismatch"
    });
  });

  it("rejects a delegated conversation record whose chain issuer's log was substituted", async () => {
    const record = signThresholdRecord(conversationBody, [session.secretKey]) as Conversation;
    const chain = [
      grant(actor, { abilities: ["msg/conversation"] }, attacker.currentKeys[0]!.secretKey)
    ];

    expect(
      await verifyConversationRecordUnit(record, chain, substituted, { checkRevocation: false })
    ).toEqual({
      valid: false,
      reason: "chain_invalid:grant_issuer_key_log_participant_mismatch"
    });
  });

  it("REJECTS rather than waits — a substituted log is not a view that will catch up", async () => {
    // The distinction this reason exists to draw. Key logs are monotone, so `unresolved` means
    // "my view may catch up" and the caller holds the record. No honest host ever serves one
    // identity's log at another's path, so there is nothing to converge to: waiting would hold
    // a forged unit forever and re-ask a hostile host for the same substitution.
    expect(isUnitWaitReason("actor_key_log_participant_mismatch")).toBe(false);
    expect(isUnitWaitReason("creator_key_log_participant_mismatch")).toBe(false);
    expect(isUnitWaitReason("chain_invalid:grant_issuer_key_log_participant_mismatch")).toBe(false);
    // …while the resolution stalls it is deliberately NOT grouped with still are waits.
    expect(isUnitWaitReason("actor_key_log_unresolved")).toBe(true);
    expect(isUnitWaitReason("creator_key_log_unresolved")).toBe(true);
  });

  it("keeps the actor's honest log working — the binding rejects only substitution", async () => {
    const record = ownerUpdate();
    const honest = makeView({ logs: { [actor.id]: actor.log } });

    expect(
      await verifyConversationUpdateUnit(record, null, honest, { checkRevocation: false })
    ).toEqual({ valid: true });
  });
});

/**
 * `UNIT_COST_REASONS` names the WAIT reasons that mean "this verifier declined to spend enough
 * to judge the log" rather than "this verifier has not seen it yet", so a surface can report
 * the two differently — a node surface answers 503 for the first and 401 for the second.
 */
describe("UNIT_COST_REASONS is a strict subset of the wait reasons", () => {
  it("keeps every cost reason a WAIT, so spec 014's semantics are untouched", () => {
    // WATCHED TO FAIL: stop spreading `...UNIT_COST_REASONS` into `UNIT_WAIT_REASONS` and
    // every one of these flips to false, which is the regression the spread exists to make
    // impossible — a cost refusal that stopped being a wait would have callers REJECT a
    // record whose only problem is this verifier's own ceiling.
    for (const reason of UNIT_COST_REASONS) {
      expect(isUnitWaitReason(reason)).toBe(true);
      expect(UNIT_WAIT_REASONS as readonly string[]).toContain(reason);
    }
  });

  /**
   * Every exhaustion exit `verifyGrantChain` has is classified here, derived from the
   * resolver's own export rather than transcribed. This is the assertion that would have
   * caught the shipped defect: `chain_invalid:grant_signature_check_too_expensive` was
   * produced by the resolver, matched neither list, and reached a node surface as a malformed
   * record — a 400 for a record whose only problem was this verifier's ceiling.
   *
   * WATCHED TO FAIL: replace the `...GRANT_CHAIN_COST_REASONS.map(...)` spread in
   * `UNIT_COST_REASONS` with the single literal
   * `"chain_invalid:grant_issuer_key_log_too_expensive"` — the list as it shipped. This test
   * then fails on the signature-check reason, as does any route-level test of a surface
   * built on it.
   */
  it("classifies every cost reason the trust resolver's chain verifier can return", () => {
    expect(GRANT_CHAIN_COST_REASONS.length).toBeGreaterThan(1);
    for (const reason of GRANT_CHAIN_COST_REASONS) {
      // `verifyUnit` forwards a chain verdict as `chain_invalid:<reason>`; that is the
      // spelling a caller sees, so that is the spelling that has to be classified.
      const forwarded = `chain_invalid:${reason}`;
      expect(isUnitCostReason(forwarded)).toBe(true);
      expect(isUnitWaitReason(forwarded)).toBe(true);
    }
  });

  it("is strict — a resolution stall is a wait but not a cost refusal", () => {
    expect(isUnitCostReason("actor_key_log_unresolved")).toBe(false);
    expect(isUnitCostReason("creator_key_log_unresolved")).toBe(false);
    expect(isUnitCostReason("chain_invalid:grant_issuer_key_log_unresolved")).toBe(false);
    expect(UNIT_COST_REASONS.length).toBeLessThan(UNIT_WAIT_REASONS.length);
  });

  it("does not admit a rejection reason", () => {
    // The mismatch reasons are not a wait and are certainly not a capacity condition: a log
    // that replays as a different participant has nothing to converge to.
    expect(isUnitCostReason("actor_key_log_participant_mismatch")).toBe(false);
    expect(isUnitCostReason("creator_key_log_participant_mismatch")).toBe(false);
    expect(isUnitCostReason("update_signature_invalid")).toBe(false);
  });
});

/**
 * The unit verifier's own cost-reason hop, checked from both sides.
 *
 * COMPLETENESS is compile-time: `invalid` in `record-unit.ts` takes a union of every reason a
 * unit verification can return, `UNIT_COST_REASONS` is typed as `UnitCostReason` (derived from
 * `@kinnet/trust`'s exported list), and `UnitCostReasonsAreClassified` fails to compile if a
 * cost-shaped member of the reason union is not in that list. None of those are testable at
 * runtime, and none of them can tell whether a listed reason is ever actually produced.
 *
 * SOUNDNESS is what this does: every entry is DRIVEN out of a real unit verification. A bogus
 * entry added to `UNIT_COST_REASONS` used to leave the whole suite green; it now fails to
 * compile, and if it somehow compiled it would fail here naming the reason nothing reaches.
 */
describe("UNIT_COST_REASONS is sound — every listed reason is reachable", () => {
  const reachableView = makeView({ logs: { [actor.id]: actor.log, [other.id]: other.log } });

  /**
   * Every identity here holds a one-event 1-of-1 log, so one replay costs exactly one
   * verification. That is what lets a budget of 0 land in the REPLAY and a budget of 1 land in
   * the SIGNATURE SEARCH immediately after it — the two exits whose conflation was the defect.
   */
  const reachable: Record<string, () => Promise<string>> = {
    actor_key_log_too_expensive: async () => {
      const verdict = await verifyConversationUpdateUnit(ownerUpdate(), null, reachableView, {
        checkRevocation: true,
        budget: { remaining: 0 }
      });
      return verdict.valid ? "<valid>" : verdict.reason;
    },
    creator_key_log_too_expensive: async () => {
      const record = signThresholdRecord(
        {
          creator: actor.id,
          participants: [actor.id, other.id].sort(),
          createdAt: CREATED_AT
        },
        [actor.currentKeys[0]!.secretKey]
      ) as Conversation;
      const verdict = await verifyConversationRecordUnit(record, null, reachableView, {
        checkRevocation: true,
        budget: { remaining: 0 }
      });
      return verdict.valid ? "<valid>" : verdict.reason;
    },
    "chain_invalid:grant_issuer_key_log_too_expensive": async () => {
      const verdict = await verifyConversationUpdateUnit(
        sessionUpdate(),
        [grant(actor)],
        reachableView,
        { checkRevocation: true, budget: { remaining: 0 } }
      );
      return verdict.valid ? "<valid>" : verdict.reason;
    },
    "chain_invalid:grant_signature_check_too_expensive": async () => {
      const verdict = await verifyConversationUpdateUnit(
        sessionUpdate(),
        [grant(actor)],
        reachableView,
        { checkRevocation: true, budget: { remaining: 1 } }
      );
      return verdict.valid ? "<valid>" : verdict.reason;
    }
  };

  /**
   * WATCHED TO FAIL: delete the `grant_signature_check_too_expensive` entry from
   * `@kinnet/trust`'s `GRANT_CHAIN_COST_REASONS` — the shipped omission. `UNIT_COST_REASONS`
   * loses the prefixed entry, this case stops running, and the count assertion below fails
   * with the list one shorter than the resolver's own chain-reason set.
   */
  it.each([...UNIT_COST_REASONS])("%s is produced by a real unit verification", async (reason) => {
    const drive = reachable[reason];
    expect(
      drive,
      `${reason} is listed in UNIT_COST_REASONS but this test knows no verification that reaches it`
    ).toBeDefined();
    expect(await drive!()).toBe(reason);
  });

  it("carries one entry per chain cost reason the resolver exports, plus its own two", () => {
    // Non-vacuous: if the derived spread were replaced by a single literal — the shape that
    // shipped — this is one short and says so.
    expect(UNIT_COST_REASONS.length).toBe(2 + GRANT_CHAIN_COST_REASONS.length);
    for (const reason of GRANT_CHAIN_COST_REASONS) {
      expect(UNIT_COST_REASONS as readonly string[]).toContain(`chain_invalid:${reason}`);
    }
  });
});

describe("record-unit budget normalization", () => {
  const view = makeView({ logs: { [actor.id]: actor.log } });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 1.5, "7"])(
    "normalizes malformed remaining=%s to zero and refuses owner verification on cost",
    async (value) => {
      const budget = { remaining: value } as unknown as { remaining: number };
      expect(
        await verifyConversationUpdateUnit(ownerUpdate(), null, view, {
          checkRevocation: true,
          budget
        })
      ).toEqual({ valid: false, reason: "actor_key_log_too_expensive" });
      expect(budget.remaining).toBe(0);
    }
  );

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 1.5, "7"])(
    "normalizes malformed custom-view max=%s to zero and refuses owner verification on cost",
    async (value) => {
      const malformedView: TrustView = {
        ...view,
        maxSignatureVerifications: value as unknown as number
      };
      expect(
        await verifyConversationUpdateUnit(ownerUpdate(), null, malformedView, {
          checkRevocation: true
        })
      ).toEqual({ valid: false, reason: "actor_key_log_too_expensive" });
    }
  );

  it("preserves missing, zero, and safe-integer custom-view policies", async () => {
    expect(
      await verifyConversationUpdateUnit(ownerUpdate(), null, view, { checkRevocation: true })
    ).toEqual({ valid: true });

    expect(
      await verifyConversationUpdateUnit(
        ownerUpdate(),
        null,
        { ...view, maxSignatureVerifications: 0 },
        { checkRevocation: true }
      )
    ).toEqual({ valid: false, reason: "actor_key_log_too_expensive" });

    expect(
      await verifyConversationUpdateUnit(
        ownerUpdate(),
        null,
        { ...view, maxSignatureVerifications: 2 },
        { checkRevocation: true }
      )
    ).toEqual({ valid: true });
  });
});
