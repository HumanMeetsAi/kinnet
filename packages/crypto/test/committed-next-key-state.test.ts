/**
 * Spec 003, _The committed next key state_ — reference tests.
 *
 * The pre-rotation commitment covers the next key STATE (ordered key list AND threshold), so a
 * rotation cannot name its own threshold. These are the two rejections that rule exists for,
 * and each was verified to be an ACCEPTANCE before the rule landed:
 *
 *   1. Lowering — a holder of one key in a multi-key committed set reveals that set at
 *      `threshold: "1"`, signs once, and takes sole control of an M-of-N identity.
 *   2. Raising — the same move against an intended threshold RAISE: the committed set is
 *      revealed at "1" instead of the "3" its holder intended, so two of the three principals
 *      never sign.
 *
 * Both are the same defect: before the threshold was committed, ONE commitment admitted EVERY
 * threshold, and the revealing party chose. The third test pins that directly.
 */
import { keyEventSchema, MAX_KEY_EVENT_KEYS, type KeyEvent } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  canonicalBytes,
  commitToKeyState,
  createIdentity,
  deriveParticipantId,
  encodeKeyRef,
  encodeSignature,
  eventDigest,
  generateKeyPair,
  replayKeyLog,
  rotateIdentity,
  sign,
  type KeyPair
} from "../src/index.js";

const seed = (n: number): Uint8Array => {
  const bytes = new Uint8Array(32);
  bytes[31] = n;
  return bytes;
};

function signEvent(unsigned: Omit<KeyEvent, "signature">, signers: KeyPair[]): KeyEvent {
  const bytes = canonicalBytes(unsigned);
  return {
    ...unsigned,
    signature: signers.map((keyPair) => encodeSignature(sign(bytes, keyPair.secretKey)))
  };
}

// The next key set, held in split custody by three principals. C is the attacker: one private
// key of the three, and knowledge of all three public keys — which every committee member has.
const C = generateKeyPair(seed(3));
const D = generateKeyPair(seed(4));
const E = generateKeyPair(seed(5));
const X = generateKeyPair(seed(6));
const committedSet = [
  encodeKeyRef(C.publicKey),
  encodeKeyRef(D.publicKey),
  encodeKeyRef(E.publicKey)
];

/** An inception committing `committedSet` at `committedThreshold`. */
function inceptionCommitting(
  currentKeys: KeyPair[],
  threshold: string,
  committedThreshold: string
): KeyEvent {
  const establishment = {
    seq: "0",
    kind: "icp" as const,
    keys: currentKeys.map((keyPair) => encodeKeyRef(keyPair.publicKey)),
    threshold,
    next: commitToKeyState(committedSet, committedThreshold)
  };
  const id = deriveParticipantId(establishment);
  return signEvent({ ...establishment, id, prior: null }, currentKeys.slice(0, Number(threshold)));
}

/** A rotation revealing `committedSet` at a caller-chosen threshold, signed by `signers`. */
function revealAt(inception: KeyEvent, threshold: string, signers: KeyPair[]): KeyEvent {
  return signEvent(
    {
      id: inception.id,
      seq: "1",
      prior: eventDigest(inception),
      kind: "rot",
      keys: committedSet,
      threshold,
      next: commitToKeyState([encodeKeyRef(X.publicKey)], "1")
    },
    signers
  );
}

describe("a rotation may not restate its committed threshold", () => {
  describe("lowering — a 2-of-2 committing a 2-of-3 next state", () => {
    const A = generateKeyPair(seed(1));
    const B = generateKeyPair(seed(2));
    const inception = inceptionCommitting([A, B], "2", "2");

    it("accepts the reveal at the committed threshold", () => {
      const state = replayKeyLog([inception, revealAt(inception, "2", [C, D])]);
      expect(state.threshold).toBe("2");
      expect(state.keys).toEqual(committedSet);
    });

    it("rejects C acting alone at threshold 1", () => {
      // Accepted before this rule: C alone took sole control of the organization.
      expect(() => replayKeyLog([inception, revealAt(inception, "1", [C])])).toThrow(
        /does not reveal the pre-committed next key state/
      );
    });
  });

  describe("raising — a 1-of-1 committing a 3-of-3 next state", () => {
    const A = generateKeyPair(seed(7));
    const inception = inceptionCommitting([A], "1", "3");

    it("accepts the reveal at the committed threshold, which needs all three principals", () => {
      const state = replayKeyLog([inception, revealAt(inception, "3", [C, D, E])]);
      expect(state.threshold).toBe("3");
    });

    it("rejects the same set revealed at threshold 1 by C alone", () => {
      // Accepted before this rule: the intended raise silently became a 1-of-3.
      expect(() => replayKeyLog([inception, revealAt(inception, "1", [C])])).toThrow(
        /does not reveal the pre-committed next key state/
      );
    });
  });

  it("admits exactly ONE threshold per commitment", () => {
    // The property both cases above are instances of. Before the threshold was committed this
    // list was every threshold the set could satisfy; now it is the single committed one.
    const inception = inceptionCommitting([generateKeyPair(seed(10))], "1", "2");
    const accepted = (["1", "2", "3"] as const).filter((threshold) => {
      const signers = [C, D, E].slice(0, Number(threshold));
      try {
        return (
          replayKeyLog([inception, revealAt(inception, threshold, signers)]).threshold === threshold
        );
      } catch {
        return false;
      }
    });
    expect(accepted).toEqual(["2"]);
  });
});

describe("keyEventSchema requires exactly the threshold in signatures", () => {
  it("rejects an event carrying more signatures than its threshold", () => {
    const A = generateKeyPair(seed(8));
    const B = generateKeyPair(seed(9));
    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: [encodeKeyRef(A.publicKey), encodeKeyRef(B.publicKey)],
      threshold: "1",
      next: commitToKeyState([encodeKeyRef(X.publicKey)], "1")
    };
    const id = deriveParticipantId(establishment);
    const event = signEvent({ ...establishment, id, prior: null }, [A, B]);

    // Two genuine signatures, both verifying, against a declared threshold of one — accepted
    // by this schema before `m = t` landed.
    const result = keyEventSchema.safeParse(event);
    expect(result.success).toBe(false);
    expect(JSON.stringify(result.error)).toMatch(
      /an event must carry exactly its threshold in signatures/
    );
  });

  it("rejects an event carrying fewer signatures than its threshold", () => {
    const A = generateKeyPair(seed(11));
    const B = generateKeyPair(seed(12));
    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: [encodeKeyRef(A.publicKey), encodeKeyRef(B.publicKey)],
      threshold: "2",
      next: commitToKeyState([encodeKeyRef(X.publicKey)], "1")
    };
    const id = deriveParticipantId(establishment);
    const event = signEvent({ ...establishment, id, prior: null }, [A]);

    expect(keyEventSchema.safeParse(event).success).toBe(false);
  });

  it("accepts the 1-of-1 event this codebase mints", () => {
    expect(keyEventSchema.safeParse(createIdentity({ currentSeed: seed(13) }).log[0]).success).toBe(
      true
    );
  });
});

describe("rotateIdentity commits and honours the next threshold", () => {
  it("carries the committed threshold forward, not the outgoing one", () => {
    const identity = createIdentity({ currentSeed: seed(20), nextSeed: seed(21) });
    expect(identity.nextThreshold).toBe("1");

    const rotated = rotateIdentity(identity, { nextSeeds: [seed(22)] });
    expect(rotated.log[1]!.threshold).toBe("1");
    expect(rotated.log[1]!.signature).toHaveLength(1);
    expect(replayKeyLog(rotated.log).seq).toBe("1");
  });

  it("commits a lower threshold, and the reveal carries exactly that many signatures", () => {
    const identity = createIdentity({ currentSeed: seed(40), nextSeed: seed(41) });
    const committee = rotateIdentity(identity, {
      nextSeeds: [seed(42), seed(43), seed(44)],
      nextKeyCount: 3,
      nextThreshold: "3"
    });
    const lowered = rotateIdentity(committee, {
      nextSeeds: [seed(45), seed(46), seed(47)],
      nextKeyCount: 3,
      nextThreshold: "2"
    });
    expect(lowered.nextThreshold).toBe("2");

    const revealed = rotateIdentity(lowered);
    const tip = revealed.log[revealed.log.length - 1]!;
    expect(tip.threshold).toBe("2");
    expect(tip.signature).toHaveLength(2);
    expect(replayKeyLog(revealed.log).threshold).toBe("2");
  });

  it("spec 003's worked example — 1-of-1 grows into a 3-of-3 — replays clean", () => {
    const identity = createIdentity({ currentSeed: seed(50), nextSeed: seed(51) });
    const committing = rotateIdentity(identity, {
      nextSeeds: [seed(52), seed(53), seed(54)],
      nextKeyCount: 3,
      nextThreshold: "3"
    });
    const grown = rotateIdentity(committing, { nextSeeds: [seed(55), seed(56), seed(57)] });

    const tip = grown.log[2]!;
    expect(tip.keys).toHaveLength(3);
    expect(tip.threshold).toBe("3");
    // All three principals had to sign: the raise is authorized by the state it establishes.
    expect(tip.signature).toHaveLength(3);
    expect(grown.log.every((event) => keyEventSchema.safeParse(event).success)).toBe(true);
    expect(replayKeyLog(grown.log).threshold).toBe("3");
  });

  describe("refuses a next state no rotation could ever reveal", () => {
    // Each of these was ACCEPTED before this validation landed, and the mistake only surfaced
    // one rotation later — on the party who could no longer act. A commitment naming an
    // unsatisfiable state is unrecoverable, because the keys it commits to are the only ones
    // that may rotate next.
    const fresh = () => createIdentity({ currentSeed: seed(60), nextSeed: seed(61) });

    it("rejects a threshold above the number of keys being committed", () => {
      expect(() => rotateIdentity(fresh(), { nextSeeds: [seed(62)], nextThreshold: "2" })).toThrow(
        /nextThreshold "2" exceeds the 1 next key\(s\)/
      );
    });

    it.each(["0", "banana", "01", " 1", ""])(
      "rejects the out-of-domain threshold %j",
      (threshold) => {
        expect(() => rotateIdentity(fresh(), { nextThreshold: threshold })).toThrow(
          /is not a decimal string matching/
        );
      }
    );

    it.each([0, 9, 2.5, -1])("rejects nextKeyCount %s", (count) => {
      expect(() => rotateIdentity(fresh(), { nextKeyCount: count })).toThrow(
        /nextKeyCount must be a whole number from 1 to 8/
      );
    });

    it("refuses to silently discard a next state alongside nextCommitment", () => {
      expect(() =>
        rotateIdentity(fresh(), {
          nextCommitment: commitToKeyState([encodeKeyRef(X.publicKey)], "1"),
          nextThreshold: "1"
        })
      ).toThrow(/not both/);
    });
  });

  describe("one domain authority for a committed threshold", () => {
    // `Number()` maps all nine of these to a small integer, so each was a value that could be
    // committed, revealed, and minted into an event `keyEventSchema` and `replayKeyLog` then
    // both refuse — a library building a log it will itself reject, throwing nowhere.
    const COERCIBLE = ["01", " 1", "1 ", "+1", "1.0", "1e0", "0x1", "1\n", "\t1"];

    it.each(COERCIBLE)("commitToKeyState refuses to commit threshold %j", (threshold) => {
      expect(() => commitToKeyState([encodeKeyRef(X.publicKey)], threshold)).toThrow(
        /is not a decimal string matching/
      );
    });

    it.each(COERCIBLE)("rotateIdentity refuses to REVEAL a committed %j", (threshold) => {
      // The reveal side, reached the way the honest custody-exit route reaches it: the holder's
      // Identity carries the committed threshold verbatim, because that is what reproduces the
      // commitment. Built by hand here only because `commitToKeyState` now refuses to mint the
      // commitment in the first place.
      const custodian = createIdentity({ currentSeed: seed(70), nextSeed: seed(71) });
      const userKey = generateKeyPair(seed(72));
      const exited = rotateIdentity(custodian, {
        nextCommitment: commitToKeyState([encodeKeyRef(userKey.publicKey)], "1")
      });
      const holder = { ...exited, nextKeys: [userKey], nextThreshold: threshold };

      // Passing a VALID option must not let the bad committed value through: the option governs
      // what is committed next, the identity's value governs what this event declares.
      expect(() => rotateIdentity(holder, { nextThreshold: "1" })).toThrow(
        /this identity's committed next threshold/
      );
    });

    it("blames the identity, not an option the caller never passed", () => {
      const custodian = createIdentity({ currentSeed: seed(73), nextSeed: seed(74) });
      const userKey = generateKeyPair(seed(75));
      const exited = rotateIdentity(custodian, {
        nextCommitment: commitToKeyState([encodeKeyRef(userKey.publicKey)], "1")
      });
      const holder = { ...exited, nextKeys: [userKey], nextThreshold: "01" };

      expect(() => rotateIdentity(holder)).toThrow(
        /this identity's committed next threshold "01" is not a decimal string/
      );
    });

    it("the replay blames the event for an out-of-domain threshold", () => {
      const identity = createIdentity({ currentSeed: seed(76), nextSeed: seed(77) });
      const rotated = rotateIdentity(identity, { nextSeeds: [seed(78)] });
      const tampered = [...rotated.log];
      tampered[1] = { ...tampered[1]!, threshold: "01" };

      expect(() => replayKeyLog(tampered)).toThrow(/Key event 1 declares a threshold "01" outside/);
    });
  });

  describe("commitToKeyState refuses an unsatisfiable state", () => {
    // Adding the threshold to the commitment is what made `t > n` expressible: before it, the
    // commitment covered only the key list. 015 S1 requires `t <= n`, so such a commitment
    // names a state no conforming event can reveal — and it bricks the RECIPIENT, since the
    // documented custody handover builds its commitment by calling this directly.
    const keyRefs = (count: number) =>
      Array.from({ length: count }, (_, index) =>
        encodeKeyRef(generateKeyPair(seed(90 + index)).publicKey)
      );

    it.each([
      [1, "2"],
      [1, "9"],
      [3, "4"]
    ])("rejects %i key(s) at threshold %j", (count, threshold) => {
      expect(() => commitToKeyState(keyRefs(count), threshold)).toThrow(
        /exceeds its \d+ key\(s\): spec 015 S1 requires t <= n/
      );
    });

    it.each([
      [1, "1"],
      [3, "2"],
      [3, "3"]
    ])("accepts %i key(s) at threshold %j", (count, threshold) => {
      expect(() => commitToKeyState(keyRefs(count), threshold)).not.toThrow();
    });

    it("the replay blames the event for a threshold above its own key count", () => {
      const identity = createIdentity({ currentSeed: seed(96), nextSeed: seed(97) });
      const rotated = rotateIdentity(identity, { nextSeeds: [seed(98)] });
      const tampered = [...rotated.log];
      tampered[1] = { ...tampered[1]!, threshold: "5" };

      expect(() => replayKeyLog(tampered)).toThrow(
        /Key event 1 declares a threshold "5" above its own 1 key\(s\)/
      );
      // The property this guard exists for, asserted rather than left to a message comparison
      // that happens to differ: `commitToKeyState`'s throw must stay unreachable from a replay.
      try {
        replayKeyLog(tampered);
      } catch (error) {
        expect((error as Error).message).not.toMatch(/^Cannot commit to a key state/);
      }
    });
  });

  describe("commitToKeyState refuses a state wider than a key event may be", () => {
    // MAX_KEY_EVENT_KEYS is the schema's bound on `keys`, so a commitment naming more keys is
    // exactly as unrevealable as a `t > n` one: no conforming event can declare it, and the
    // committed keys are the only ones that may rotate next, so it bricks the recipient
    // permanently. `rotateIdentity` bounds its own `nextKeyCount`, so this gap is reachable
    // only through a DIRECT call — which is how the custody and enrollment handovers build
    // their commitments.
    const wideKeyRefs = (count: number) =>
      Array.from({ length: count }, (_, index) =>
        encodeKeyRef(generateKeyPair(seed(110 + index)).publicKey)
      );

    it("accepts the boundary: exactly MAX_KEY_EVENT_KEYS keys", () => {
      expect(MAX_KEY_EVENT_KEYS).toBe(8);
      expect(() => commitToKeyState(wideKeyRefs(MAX_KEY_EVENT_KEYS), "8")).not.toThrow();
      expect(() => commitToKeyState(wideKeyRefs(MAX_KEY_EVENT_KEYS), "1")).not.toThrow();
    });

    it.each([MAX_KEY_EVENT_KEYS + 1, MAX_KEY_EVENT_KEYS + 4])(
      "rejects %i keys, one past the bound and beyond",
      (count) => {
        expect(() => commitToKeyState(wideKeyRefs(count), "1")).toThrow(
          new RegExp(`listing ${count} keys: spec 003 bounds a key event to 8 keys`)
        );
      }
    );

    it("rejects the 9-keys-at-threshold-9 case that t <= n lets through", () => {
      // The exact hole: `t = 9`, `n = 9`, so `t > n` never fires and the threshold is in
      // domain. Asserted against BOTH sibling messages so this cannot pass for the wrong
      // reason.
      const keys = wideKeyRefs(MAX_KEY_EVENT_KEYS + 1);
      let message = "";
      try {
        commitToKeyState(keys, "9");
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toMatch(/listing 9 keys: spec 003 bounds a key event to 8 keys/);
      expect(message).not.toMatch(/is not a decimal string matching/);
      expect(message).not.toMatch(/spec 015 S1 requires t <= n/);
    });

    it("the replay blames the event for an over-wide key list", () => {
      // Tampering `keys` leaves `prior` — which names the PREVIOUS event — intact, so the
      // event reaches the key-count guard with the chain checks already passed.
      const identity = createIdentity({ currentSeed: seed(120), nextSeed: seed(121) });
      const rotated = rotateIdentity(identity, { nextSeeds: [seed(122)] });
      const tampered = [...rotated.log];
      tampered[1] = { ...tampered[1]!, keys: wideKeyRefs(MAX_KEY_EVENT_KEYS + 1) };

      expect(() => replayKeyLog(tampered)).toThrow(
        /Key event 1 lists 9 keys, above the 8 a key event may carry/
      );
      // The property the mirror exists for: `commitToKeyState`'s throw must stay unreachable
      // from a replay.
      expect(() => replayKeyLog(tampered)).toThrow();
      try {
        replayKeyLog(tampered);
      } catch (error) {
        expect((error as Error).message).not.toMatch(/^Cannot commit to a key state/);
      }
    });
  });

  describe("nextSeeds is all-or-nothing against nextKeyCount", () => {
    const fresh = () => createIdentity({ currentSeed: seed(80), nextSeed: seed(81) });

    it("rejects surplus seeds", () => {
      expect(() =>
        rotateIdentity(fresh(), {
          nextKeyCount: 1,
          nextSeeds: [seed(82), seed(83), seed(84)]
        })
      ).toThrow(/carries 3 seed\(s\) for 1 next key\(s\)/);
    });

    it("rejects short seeds, which would otherwise generate RANDOM keys", () => {
      expect(() =>
        rotateIdentity(fresh(), { nextKeyCount: 3, nextThreshold: "1", nextSeeds: [seed(85)] })
      ).toThrow(/carries 1 seed\(s\) for 3 next key\(s\)/);
    });

    it("is deterministic when the counts match — the property fixtures depend on", () => {
      const commit = () =>
        rotateIdentity(fresh(), {
          nextKeyCount: 3,
          nextThreshold: "2",
          nextSeeds: [seed(86), seed(87), seed(88)]
        }).log[1]!.next;
      expect(commit()).toBe(commit());
    });
  });

  describe("commitToKeyState refuses a state that repeats a key", () => {
    // The third unrevealable shape, alongside `t > n` and an over-wide key list. 015 S0 makes a
    // state with a repeated key invalid, and both the schema and the replay refuse the event
    // that would reveal one — so committing `{[K, K], t: 2}` names a state nothing conforming
    // can produce, and the committed keys are the only ones that may rotate next. The identity
    // is bricked at reveal time, permanently, and the caller who built the commitment is not
    // the party who pays.
    const repeated = encodeKeyRef(generateKeyPair(seed(130)).publicKey);
    const other = encodeKeyRef(generateKeyPair(seed(131)).publicKey);

    it.each([
      [[repeated, repeated], "2"],
      [[repeated, repeated], "1"],
      [[other, repeated, repeated], "3"],
      [[repeated, other, repeated], "1"]
    ])("rejects %j at threshold %j", (keys, threshold) => {
      expect(() => commitToKeyState(keys, threshold)).toThrow(
        /lists the same key twice: spec 015 S0/
      );
    });

    it("accepts the neighbouring distinct-key states", () => {
      expect(() => commitToKeyState([repeated, other], "2")).not.toThrow();
      expect(() => commitToKeyState([repeated], "1")).not.toThrow();
    });

    it("compares on key value, not list position", () => {
      // An index-based reading would call `[K, K]` a two-key state and let one private key
      // satisfy a threshold of two — the same reading S2's injectivity rule forbids.
      expect(commitToKeyState([repeated], "1")).not.toBe(commitToKeyState([repeated, other], "1"));
      expect(() => commitToKeyState([repeated, repeated], "2")).toThrow();
    });

    it("the replay still blames the EVENT for a repeated key (state_repeats_key)", () => {
      // The commit-side refusal must not become the only one: a log an attacker hands over was
      // never built by this library. `key-log-rejection-vectors.json` carries the vector; this
      // asserts the two guards stay separate, so neither hides a regression in the other.
      const identity = createIdentity({ currentSeed: seed(132), nextSeed: seed(133) });
      const rotated = rotateIdentity(identity, { nextSeeds: [seed(134)] });
      const tampered = [...rotated.log];
      const key = tampered[1]!.keys[0]!;
      tampered[1] = { ...tampered[1]!, keys: [key, key] };

      let message = "";
      try {
        replayKeyLog(tampered);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toMatch(/state_repeats_key/);
      expect(message).not.toMatch(/^Cannot commit to a key state/);
    });
  });

  it("a handover leaves an identity that cannot rotate", () => {
    const identity = createIdentity({ currentSeed: seed(30), nextSeed: seed(31) });
    const handed = rotateIdentity(identity, {
      nextCommitment: commitToKeyState([encodeKeyRef(generateKeyPair(seed(32)).publicKey)], "1")
    });
    expect(handed.nextThreshold).toBeNull();
    expect(() => rotateIdentity(handed)).toThrow(/no pre-committed next keys/);
  });
});
