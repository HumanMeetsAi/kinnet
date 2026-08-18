/**
 * Unit tests for the spec 013 §2.4.1 re-authorization contract. Everything here is
 * about the CONTRACT — the route-level behavior of an SSE endpoint is a node
 * surface's own to test.
 */
import {
  canonicalBytes,
  canonicalDigest,
  commitToKeyState,
  createIdentity,
  deriveParticipantId,
  encodeKeyRef,
  encodeSignature,
  generateKeyPair,
  replayKeyLogFor,
  rotateIdentity,
  sign,
  eventDigest,
  keyLogAnchor,
  signThresholdRecord,
  VerificationBudgetExceeded,
  type Identity
} from "@kinnet/crypto";
import type { Grant, KeyEvent, Revocation } from "@kinnet/protocol";
import { verifyGrantChain, type TrustView, type VerificationBudget } from "@kinnet/trust";
import { describe, expect, it } from "vitest";

import {
  delegationTreeDigest,
  reauthorizeStream,
  type CurrentKeyStateFn,
  type StreamAuthRecord
} from "../src/reauthorize-stream.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);
const NOW = new Date("2026-07-28T12:00:00.000Z");
const LATER = new Date("2026-07-28T12:30:00.000Z");
const ISSUED_AT = new Date(NOW.getTime() - 27 * 86_400_000).toISOString();
const EXPIRES_AT = new Date(NOW.getTime() + 4 * 86_400_000).toISOString();

const node = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });

/** A minimal TrustView + current-key-state pair driven from in-memory arrays. */
function makeView(config: {
  logs: Record<string, KeyEvent[]>;
  revocations?: Record<string, Revocation[]>;
}): {
  view: TrustView;
  getKeyState: (id: string) => Promise<{ id: string; keys: string[] } | null>;
} {
  const view: TrustView = {
    getKeyLog: async (id) => config.logs[id] ?? null,
    getRevocations: async (digest, issuerIds) =>
      (config.revocations?.[digest] ?? []).filter((r) => issuerIds.includes(r.issuerId))
  };
  // Deliberately UNBOUND: it reports the id the log itself derives, which is exactly what a
  // raw replay hands back — not the id that was asked for. That is the accessor shape
  // `reauthorizeStream` must defend against on its own, so the helper must not do it for it.
  const getKeyState = async (id: string): Promise<{ id: string; keys: string[] } | null> => {
    const log = config.logs[id];
    if (!log) {
      return null;
    }
    const current = log[log.length - 1];
    return current ? { id: log[0]!.id, keys: current.keys } : null;
  };
  return { view, getKeyState };
}

describe("reauthorizeStream — owner mode (spec 013 §2.4.1, §2.4.3)", () => {
  it("authorizes when the satisfying key is still in the current state", async () => {
    const owner = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
    const { view, getKeyState } = makeView({ logs: { [owner.id]: owner.log } });

    const verdict = await reauthorizeStream(
      {
        mode: "owner",
        subject: owner.id,
        principal: owner.id,
        satisfiedKey: encodeKeyRef(owner.currentKeys[0]!.publicKey),
        chain: null
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: true });
  });

  it("terminates with 'rotated' when the satisfying key is no longer current", async () => {
    // The stream opened under the pre-rotation key; the owner then rotated.
    const owner = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
    const openedKey = encodeKeyRef(owner.currentKeys[0]!.publicKey);
    const rotated = rotateIdentity(owner);
    const { view, getKeyState } = makeView({ logs: { [owner.id]: rotated.log } });

    const verdict = await reauthorizeStream(
      {
        mode: "owner",
        subject: owner.id,
        principal: owner.id,
        satisfiedKey: openedKey,
        chain: null
      },
      view,
      getKeyState,
      { now: LATER }
    );

    expect(verdict).toEqual({ authorized: false, reason: "rotated" });
  });

  it("terminates with 'unverifiable' when the subject's key log cannot be resolved", async () => {
    const owner = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
    const { view, getKeyState } = makeView({ logs: {} });

    const verdict = await reauthorizeStream(
      {
        mode: "owner",
        subject: owner.id,
        principal: owner.id,
        satisfiedKey: encodeKeyRef(owner.currentKeys[0]!.publicKey),
        chain: null
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: false, reason: "unverifiable" });
  });

  it("fails closed on a thrown key-state resolver", async () => {
    const owner = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
    const view: TrustView = {
      getKeyLog: async () => null,
      getRevocations: async () => []
    };
    const getKeyState = async (): Promise<{ id: string; keys: string[] } | null> => {
      throw new Error("view unreachable");
    };

    const verdict = await reauthorizeStream(
      {
        mode: "owner",
        subject: owner.id,
        principal: owner.id,
        satisfiedKey: encodeKeyRef(owner.currentKeys[0]!.publicKey),
        chain: null
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: false, reason: "unverifiable" });
  });
});

describe("reauthorizeStream — delegated mode (spec 013 §2.4.1)", () => {
  function makeSessionChain(user = createIdentity({ currentSeed: seed(5), nextSeed: seed(6) })): {
    user: ReturnType<typeof createIdentity>;
    session: ReturnType<typeof generateKeyPair>;
    sessionKeyRef: string;
    grant: (overrides?: Partial<Grant>) => Grant;
  } {
    const session = generateKeyPair(seed(7));
    const sessionKeyRef = encodeKeyRef(session.publicKey);
    return {
      user,
      session,
      sessionKeyRef,
      grant(overrides: Partial<Grant> = {}) {
        return signThresholdRecord(
          {
            subjectId: user.id,
            issuerId: user.id,
            audienceId: sessionKeyRef,
            abilities: ["msg/subscribe"],
            caveats: { aud: [node.id] },
            // Spec 016: the participant-issued link names the state that signs it.
            anchor: keyLogAnchor(user.log),
            proof: null,
            issuedAt: ISSUED_AT,
            expiresAt: EXPIRES_AT,
            ...overrides
          },
          [user.currentKeys[0]!.secretKey]
        ) as Grant;
      }
    };
  }

  it("authorizes a fresh session chain at `now`", async () => {
    const { user, sessionKeyRef, grant } = makeSessionChain();
    const chain = [grant()];
    const { view, getKeyState } = makeView({ logs: { [user.id]: user.log } });

    const verdict = await reauthorizeStream(
      {
        mode: "delegated",
        subject: user.id,
        principal: sessionKeyRef,
        satisfiedKey: sessionKeyRef,
        chain,
        verifierId: node.id,
        requiredAbilities: ["msg/subscribe"]
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: true });
  });

  it("terminates with 'revoked' when the chain has been revoked mid-stream", async () => {
    const { user, sessionKeyRef, grant } = makeSessionChain();
    const chain = [grant()];
    const revocation = signThresholdRecord(
      {
        revokes: canonicalDigest(chain[0]!),
        issuerId: user.id,
        anchor: keyLogAnchor(user.log),
        revokedAt: ISSUED_AT
      },
      [user.currentKeys[0]!.secretKey]
    ) as Revocation;
    const { view, getKeyState } = makeView({
      logs: { [user.id]: user.log },
      revocations: { [revocation.revokes]: [revocation] }
    });

    const verdict = await reauthorizeStream(
      {
        mode: "delegated",
        subject: user.id,
        principal: sessionKeyRef,
        satisfiedKey: sessionKeyRef,
        chain,
        verifierId: node.id
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: false, reason: "revoked" });
  });

  it("terminates with 'expired' when the chain's expiry has passed", async () => {
    const { user, sessionKeyRef, grant } = makeSessionChain();
    // Expired at `now` (LATER), but not at open (NOW).
    const chain = [grant({ expiresAt: new Date(NOW.getTime() + 15 * 60_000).toISOString() })];
    const { view, getKeyState } = makeView({ logs: { [user.id]: user.log } });

    const verdict = await reauthorizeStream(
      {
        mode: "delegated",
        subject: user.id,
        principal: sessionKeyRef,
        satisfiedKey: sessionKeyRef,
        chain,
        verifierId: node.id
      },
      view,
      getKeyState,
      { now: LATER }
    );

    expect(verdict).toEqual({ authorized: false, reason: "expired" });
  });

  it("terminates with 'audience_not_admitted' when the chain no longer names this node", async () => {
    const other = createIdentity({ currentSeed: seed(9), nextSeed: seed(10) });
    const { user, sessionKeyRef, grant } = makeSessionChain();
    // A chain whose aud names a different service — we simulate re-authorizing
    // against a differently-configured verifier for the same in-flight stream.
    const chain = [grant({ caveats: { aud: [other.id] } })];
    const { view, getKeyState } = makeView({ logs: { [user.id]: user.log } });

    const verdict = await reauthorizeStream(
      {
        mode: "delegated",
        subject: user.id,
        principal: sessionKeyRef,
        satisfiedKey: sessionKeyRef,
        chain,
        verifierId: node.id
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: false, reason: "audience_not_admitted" });
  });

  it("terminates with 'abilities_insufficient' when the chain no longer covers what the stream needs", async () => {
    const { user, sessionKeyRef, grant } = makeSessionChain();
    const chain = [grant({ abilities: ["msg/read"] })];
    const { view, getKeyState } = makeView({ logs: { [user.id]: user.log } });

    const verdict = await reauthorizeStream(
      {
        mode: "delegated",
        subject: user.id,
        principal: sessionKeyRef,
        satisfiedKey: sessionKeyRef,
        chain,
        verifierId: node.id,
        requiredAbilities: ["msg/subscribe"]
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: false, reason: "abilities_insufficient" });
  });

  it("terminates with 'unverifiable' on an empty or missing chain", async () => {
    const { user, sessionKeyRef } = makeSessionChain();
    const { view, getKeyState } = makeView({ logs: { [user.id]: user.log } });

    const verdict = await reauthorizeStream(
      {
        mode: "delegated",
        subject: user.id,
        principal: sessionKeyRef,
        satisfiedKey: sessionKeyRef,
        chain: [],
        verifierId: node.id
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: false, reason: "unverifiable" });
  });

  it("terminates a stream whose chain carries an e2ee ability (spec 014)", async () => {
    // A stream holds a request authorization open, so the re-check runs at request
    // purpose too — a credential can no more sustain a stream than open one. Spec 013's
    // close-reason vocabulary has no e2ee entry, so it lands on the fail-closed default.
    const { user, sessionKeyRef, grant } = makeSessionChain();
    const { view, getKeyState } = makeView({ logs: { [user.id]: user.log } });

    for (const abilities of [["e2ee/leaf"], ["e2ee"]]) {
      const verdict = await reauthorizeStream(
        {
          mode: "delegated",
          subject: user.id,
          principal: sessionKeyRef,
          satisfiedKey: sessionKeyRef,
          // A credential link: e2ee abilities and empty caveats (spec 014 schema shape).
          chain: [grant({ abilities, caveats: {} })],
          verifierId: node.id
        },
        view,
        getKeyState,
        { now: NOW }
      );
      expect(verdict).toEqual({ authorized: false, reason: "unverifiable" });
    }
  });

  it("keeps a neighbouring `e2eex` namespace streaming (prefix-confusion guard)", async () => {
    const { user, sessionKeyRef, grant } = makeSessionChain();
    const { view, getKeyState } = makeView({ logs: { [user.id]: user.log } });

    const verdict = await reauthorizeStream(
      {
        mode: "delegated",
        subject: user.id,
        principal: sessionKeyRef,
        satisfiedKey: sessionKeyRef,
        chain: [grant({ abilities: ["e2eex/leaf"] })],
        verifierId: node.id,
        requiredAbilities: ["e2eex/leaf"]
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: true });
  });
});

describe("delegationTreeDigest — budget accounting key (spec 013 §2.8)", () => {
  it("returns null for owner-mode streams", () => {
    expect(delegationTreeDigest(null)).toBeNull();
    expect(delegationTreeDigest([])).toBeNull();
  });

  it("returns the digest of the ROOT grant (chain tail) so re-delegation cannot evade the budget", () => {
    const user = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
    const session = generateKeyPair(seed(7));
    const sessionKeyRef = encodeKeyRef(session.publicKey);
    const root = signThresholdRecord(
      {
        subjectId: user.id,
        issuerId: user.id,
        audienceId: sessionKeyRef,
        abilities: ["msg/subscribe"],
        caveats: { aud: [node.id] },
        anchor: keyLogAnchor(user.log),
        proof: null,
        issuedAt: ISSUED_AT,
        expiresAt: EXPIRES_AT
      },
      [user.currentKeys[0]!.secretKey]
    ) as Grant;
    const sub = signThresholdRecord(
      {
        subjectId: user.id,
        issuerId: sessionKeyRef,
        audienceId: sessionKeyRef,
        abilities: ["msg/subscribe"],
        caveats: {},
        proof: canonicalDigest(root),
        issuedAt: ISSUED_AT
      },
      [session.secretKey]
    ) as Grant;

    // Two chains that share a root — a delegate can mint many sub-grants — must
    // yield the same tree digest, so a per-tree budget cannot be evaded.
    expect(delegationTreeDigest([root])).toBe(canonicalDigest(root));
    expect(delegationTreeDigest([sub, root])).toBe(canonicalDigest(root));
  });
});

describe("reauthorizeStream — a substituted current key state (spec 013 §2.4.3)", () => {
  /**
   * A log that replays clean under `signer`'s own id while ALSO listing keys the signer does
   * not hold. `verifyEventSignatures` permits `signature.length <= keys.length` and stops
   * verifying once the threshold is met, so a 1-of-N inception signed only by its first key
   * is entirely valid — and the trailing keys are never proven to belong to anybody.
   */
  function craftedLog(
    signer: { publicKey: Uint8Array; secretKey: Uint8Array },
    alsoList: string[]
  ) {
    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: [encodeKeyRef(signer.publicKey), ...alsoList],
      threshold: "1",
      next: commitToKeyState([encodeKeyRef(generateKeyPair(seed(90)).publicKey)], "1")
    };
    const unsigned = { ...establishment, id: deriveParticipantId(establishment), prior: null };
    return [
      {
        ...unsigned,
        signature: [encodeSignature(sign(canonicalBytes(unsigned), signer.secretKey))]
      }
    ] as KeyEvent[];
  }

  it("terminates the stream when the served state belongs to another participant", async () => {
    // The real vulnerability, and note that PLAIN substitution does not reach it: an
    // attacker's ordinary log lists only the attacker's own key, so `satisfiedKey` is absent
    // and the stream already closed as `rotated`. This is the crafted case.
    //
    // Alice opens a stream under her key, then rotates — the stream MUST close. Mallory mints
    // her own valid inception that also lists Alice's now-rotated-out key, and discovery
    // serves it at Alice's path. Without the binding, `keys.includes(satisfiedKey)` is true
    // and the stream that should have closed stays open.
    const alice = createIdentity({ currentSeed: seed(80), nextSeed: seed(81) });
    const openedKey = encodeKeyRef(alice.currentKeys[0]!.publicKey);
    rotateIdentity(alice);

    const mallory = generateKeyPair(seed(82));
    const substituted = craftedLog(mallory, [openedKey]);
    expect(substituted[0]!.id).not.toBe(alice.id);
    expect(substituted[0]!.keys).toContain(openedKey);

    // Discovery answers Alice's id with Mallory's crafted log.
    const { view, getKeyState } = makeView({ logs: { [alice.id]: substituted } });

    const verdict = await reauthorizeStream(
      {
        mode: "owner",
        subject: alice.id,
        principal: alice.id,
        satisfiedKey: openedKey,
        chain: null
      },
      view,
      getKeyState,
      { now: LATER }
    );

    expect(verdict).toEqual({ authorized: false, reason: "unverifiable" });
  });

  it("terminates a delegated stream whose participant leaf state was substituted", async () => {
    // The same hole on the other arm: a participant-audience leaf re-checks `satisfiedKey`
    // against the leaf participant's current state, through the same accessor.
    const alice = createIdentity({ currentSeed: seed(83), nextSeed: seed(84) });
    const openedKey = encodeKeyRef(alice.currentKeys[0]!.publicKey);
    const org = createIdentity({ currentSeed: seed(85), nextSeed: seed(86) });

    const root = signThresholdRecord(
      {
        subjectId: org.id,
        issuerId: org.id,
        audienceId: alice.id,
        abilities: ["msg/subscribe"],
        caveats: {},
        anchor: keyLogAnchor(org.log),
        proof: null,
        issuedAt: ISSUED_AT,
        expiresAt: EXPIRES_AT
      },
      [org.currentKeys[0]!.secretKey]
    ) as Grant;

    const mallory = generateKeyPair(seed(87));
    const substituted = craftedLog(mallory, [openedKey]);

    const { view, getKeyState } = makeView({
      logs: { [org.id]: org.log, [alice.id]: substituted }
    });

    const verdict = await reauthorizeStream(
      {
        mode: "delegated",
        subject: org.id,
        principal: alice.id,
        satisfiedKey: openedKey,
        chain: [root],
        requiredAbilities: ["msg/subscribe"]
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: false, reason: "unverifiable" });
  });

  it("still authorizes when the honestly served state is the subject's own", async () => {
    // The control: the binding rejects substitution and nothing else.
    const alice = createIdentity({ currentSeed: seed(88), nextSeed: seed(89) });
    const { view, getKeyState } = makeView({ logs: { [alice.id]: alice.log } });

    const verdict = await reauthorizeStream(
      {
        mode: "owner",
        subject: alice.id,
        principal: alice.id,
        satisfiedKey: encodeKeyRef(alice.currentKeys[0]!.publicKey),
        chain: null
      },
      view,
      getKeyState,
      { now: NOW }
    );

    expect(verdict).toEqual({ authorized: true });
  });
});

/**
 * The shared per-call verification budget (`ReauthorizeStreamOptions.budget`).
 *
 * The construction that matters is the SANDWICH: a ceiling set above every individual stage
 * and below their sum. A ceiling above the sum passes with or without the budget threaded, and
 * a ceiling below a single stage fails either way — only the sandwich tells "each stage is
 * bounded" apart from "the call is bounded".
 */
describe("reauthorizeStream — the shared verification budget", () => {
  /**
   * A budget that records every charge made against it, so total spend is observed rather than
   * taken from the call's own report. To its consumers `remaining` is an ordinary number; the
   * accessor exists only to keep the running total.
   */
  function meteredBudget(remaining: number): {
    budget: VerificationBudget;
    spent: () => number;
  } {
    let value = remaining;
    let spent = 0;
    const budget: VerificationBudget = {
      get remaining() {
        return value;
      },
      set remaining(next: number) {
        spent += value - next;
        value = next;
      }
    };
    return { budget, spent: () => spent };
  }

  /**
   * A view whose `getKeyState` behaves the way `createDiscoveryView`'s does: the replay is
   * metered against the caller's budget when one is passed, and a refusal on COST is RETHROWN
   * rather than flattened to `null`, because cost is not "no key log resolves". Without the
   * rethrow the leaf stage below would report a missing log, and the two conditions this
   * module has to keep apart would be indistinguishable to it.
   */
  function budgetedView(logs: Record<string, KeyEvent[]>): {
    view: TrustView;
    getKeyState: CurrentKeyStateFn;
  } {
    const view: TrustView = {
      getKeyLog: async (id) => logs[id] ?? null,
      getRevocations: async () => []
    };
    const getKeyState: CurrentKeyStateFn = async (id, budget) => {
      const events = logs[id];
      if (!events) {
        return null;
      }
      try {
        return replayKeyLogFor(id, events, {
          ...(budget
            ? {
                maxSignatureVerifications: budget.remaining,
                onSignatureVerifications: (charged: number) => (budget.remaining -= charged)
              }
            : {})
        });
      } catch (error) {
        if (budget && error instanceof VerificationBudgetExceeded) {
          throw error;
        }
        return null;
      }
    };
    return { view, getKeyState };
  }

  /** Rotate until the log is `events` long. A 1-of-1 replay costs one verification per event. */
  function grow(identity: Identity, events: number): Identity {
    let current = identity;
    while (current.log.length < events) {
      current = rotateIdentity(current);
    }
    return current;
  }

  /**
   * Long enough that each stage costs real work, short enough that the suite stays quick. The
   * value itself carries no meaning: every ceiling below is derived from the stage costs this
   * fixture actually incurs, measured inside the test.
   */
  const LOG_EVENTS = 24;

  /**
   * A one-link delegated shape with a PARTICIPANT leaf, so a re-check runs both stages — the
   * chain re-check, and the leaf participant's current-key-state lookup.
   *
   * The grant is signed under — and, per spec 016, anchored to — the issuer's INCEPTION state,
   * which the issuer has since rotated away from. The chain stage's cost is dominated by the
   * replay either way; the anchored check itself is one walk against the named state.
   */
  function delegatedFixture(): {
    view: TrustView;
    getKeyState: CurrentKeyStateFn;
    record: StreamAuthRecord;
    leafId: string;
    leafKey: string;
  } {
    const inception = createIdentity();
    const issuer = grow(inception, LOG_EVENTS);
    const leaf = grow(createIdentity(), LOG_EVENTS);
    const grant = signThresholdRecord(
      {
        subjectId: issuer.id,
        issuerId: issuer.id,
        audienceId: leaf.id,
        abilities: ["msg/subscribe"],
        caveats: {},
        // Signed under the issuer's INCEPTION state, so spec 016's anchor names that event —
        // not the tip the issuer has since rotated to.
        anchor: eventDigest(issuer.log[0]!),
        proof: null,
        issuedAt: ISSUED_AT,
        expiresAt: EXPIRES_AT
      },
      [inception.currentKeys[0]!.secretKey]
    ) as Grant;
    const { view, getKeyState } = budgetedView({
      [issuer.id]: issuer.log,
      [leaf.id]: leaf.log
    });
    const leafKey = encodeKeyRef(leaf.currentKeys[0]!.publicKey);
    return {
      view,
      getKeyState,
      record: {
        mode: "delegated",
        subject: issuer.id,
        principal: leaf.id,
        satisfiedKey: leafKey,
        chain: [grant],
        requiredAbilities: ["msg/subscribe"]
      },
      leafId: leaf.id,
      leafKey
    };
  }

  it("refuses a tick whose stages each fit the ceiling but whose SUM does not", async () => {
    // WATCHED TO FAIL against the pre-change code: with no `budget` option to thread, each
    // stage mints its own allowance, both complete, and the verdict is `{ authorized: true }`
    // instead of the refusal. The same mutation reproduces it on the changed code — drop
    // `budget` from the `verifyGrantChain` options, or from the `boundKeyState` calls, and the
    // surviving stage is enough to authorize.
    const { view, getKeyState, record, leafId, leafKey } = delegatedFixture();

    // Stage costs, measured against a ceiling far above either of them.
    const leafProbe = meteredBudget(100_000);
    await reauthorizeStream(
      { mode: "owner", subject: leafId, principal: leafId, satisfiedKey: leafKey, chain: null },
      view,
      getKeyState,
      { now: NOW, budget: leafProbe.budget }
    );
    const leafCost = leafProbe.spent();

    const wholeProbe = meteredBudget(100_000);
    expect(
      await reauthorizeStream(record, view, getKeyState, { now: NOW, budget: wholeProbe.budget })
    ).toEqual({ authorized: true });
    const chainCost = wholeProbe.spent() - leafCost;

    // The sandwich, asserted rather than assumed: above every individual stage, below the sum.
    const ceiling = Math.max(chainCost, leafCost) + 1;
    expect(chainCost).toBeLessThan(ceiling);
    expect(leafCost).toBeLessThan(ceiling);
    expect(chainCost + leafCost).toBeGreaterThan(ceiling);

    const metered = meteredBudget(ceiling);
    const verdict = await reauthorizeStream(record, view, getKeyState, {
      now: NOW,
      budget: metered.budget
    });

    // Terminal through the arms that already existed — no new verdict shape.
    expect(verdict).toEqual({ authorized: false, reason: "unverifiable" });
    // And the work actually charged never exceeded what this tick was allowed.
    expect(metered.spent()).toBeLessThanOrEqual(ceiling);
    expect(metered.budget.remaining).toBeGreaterThanOrEqual(0);
  });

  it("maps a chain refused on cost onto the existing fail-closed default", async () => {
    // The first of the two exhaustion paths. `verifyGrantChain` reports cost as a
    // `*_too_expensive` REASON rather than a throw; that reason is in none of the mapped
    // cases, so it lands on the `default:` arm and terminates as `unverifiable`.
    //
    // WATCHED TO FAIL: add a case mapping `grant_signature_check_too_expensive` (the reason
    // this fixture actually produces, pinned below) to `{ authorized: true }` — the shape a
    // non-terminal cost arm would have — and the last expectation fails. It also fails when
    // `budget` is dropped from the `verifyGrantChain` options, since then nothing constrains
    // the chain at all.
    const { view, getKeyState, record } = delegatedFixture();

    const probe = meteredBudget(100_000);
    await verifyGrantChain(record.chain!, view, { now: NOW, budget: probe.budget });
    const chainCost = probe.spent();

    // One short of what the chain stage alone needs — so this is what the chain reports when
    // it runs out, before the leaf stage is ever reached.
    const chainVerdict = await verifyGrantChain(record.chain!, view, {
      now: NOW,
      budget: meteredBudget(chainCost - 1).budget
    });
    expect(chainVerdict.valid).toBe(false);
    expect(chainVerdict.valid === false ? chainVerdict.reason : "").toMatch(/_too_expensive$/);

    const metered = meteredBudget(chainCost - 1);
    expect(
      await reauthorizeStream(record, view, getKeyState, { now: NOW, budget: metered.budget })
    ).toEqual({ authorized: false, reason: "unverifiable" });
  });

  it("maps a key-state lookup refused on cost onto the same fail-closed default", async () => {
    // The second exhaustion path. A budget-aware `getKeyState` RETHROWS
    // `VerificationBudgetExceeded` to a caller that passed a budget, and this module's
    // catch-all turns it into `unverifiable`.
    //
    // WATCHED TO FAIL: delete the `catch` in `reauthorizeStream` and the throw escapes instead
    // of becoming a verdict, so the call rejects rather than resolving.
    const owner = createIdentity({ currentSeed: seed(31), nextSeed: seed(32) });
    const view: TrustView = {
      getKeyLog: async () => null,
      getRevocations: async () => []
    };
    const getKeyState: CurrentKeyStateFn = () => {
      throw new VerificationBudgetExceeded("replay exceeded its verification budget");
    };

    const verdict = await reauthorizeStream(
      {
        mode: "owner",
        subject: owner.id,
        principal: owner.id,
        satisfiedKey: encodeKeyRef(owner.currentKeys[0]!.publicKey),
        chain: null
      },
      view,
      getKeyState,
      { now: NOW, budget: { remaining: 1 } }
    );

    expect(verdict).toEqual({ authorized: false, reason: "unverifiable" });
  });

  it("still accepts a one-argument key-state accessor", async () => {
    // The widened `CurrentKeyStateFn` stays backward compatible: an accessor that ignores the
    // budget parameter is exactly what every caller passed before the parameter existed.
    const owner = createIdentity({ currentSeed: seed(33), nextSeed: seed(34) });
    const { view } = makeView({ logs: { [owner.id]: owner.log } });
    const current = owner.log[owner.log.length - 1]!;
    const oneArg = async (id: string): Promise<{ id: string; keys: string[] } | null> => ({
      id,
      keys: current.keys
    });

    expect(
      await reauthorizeStream(
        {
          mode: "owner",
          subject: owner.id,
          principal: owner.id,
          satisfiedKey: encodeKeyRef(owner.currentKeys[0]!.publicKey),
          chain: null
        },
        view,
        oneArg,
        { now: NOW, budget: { remaining: 4096 } }
      )
    ).toEqual({ authorized: true });
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, 1.5, "7"])(
    "normalizes malformed explicit remaining=%s to zero before a key-state lookup",
    async (value) => {
      const owner = createIdentity({ currentSeed: seed(35), nextSeed: seed(36) });
      const { view } = makeView({ logs: { [owner.id]: owner.log } });
      const budget = { remaining: value } as unknown as VerificationBudget;
      const budgetAware: CurrentKeyStateFn = async (_id, received) => {
        if (received?.remaining === 0) {
          throw new VerificationBudgetExceeded("zero normalized allowance");
        }
        return { id: owner.id, keys: [encodeKeyRef(owner.currentKeys[0]!.publicKey)] };
      };

      expect(
        await reauthorizeStream(
          {
            mode: "owner",
            subject: owner.id,
            principal: owner.id,
            satisfiedKey: encodeKeyRef(owner.currentKeys[0]!.publicKey),
            chain: null
          },
          view,
          budgetAware,
          { now: NOW, budget }
        )
      ).toEqual({ authorized: false, reason: "unverifiable" });
      expect(budget.remaining).toBe(0);
    }
  );
});
