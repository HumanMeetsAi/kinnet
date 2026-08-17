import {
  keyEventSchema,
  participantIdSchema,
  MAX_KEY_EVENT_KEYS,
  MAX_KEY_EVENT_SIGNATURES,
  MAX_KEY_LOG_EVENTS
} from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  commitToKeyState,
  createIdentity,
  deriveParticipantId,
  encodeKeyRef,
  eventDigest,
  generateKeyPair,
  replayKeyLog,
  replayKeyLogFor,
  rotateIdentity,
  sign,
  encodeSignature,
  DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS,
  DEFAULT_MAX_SIGNATURE_VERIFICATIONS,
  MAX_PREAUTH_SIGNATURE_VERIFICATIONS,
  KeyLogParticipantMismatch,
  KeyLogWorkBudgetExceeded,
  type Identity,
  type KeyPair
} from "../src/index.js";
import { canonicalBytes } from "../src/jcs.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

/**
 * A signed inception event over an arbitrary key set — `createIdentity` only ever mints
 * 1-of-1, and the work-bound tests need M-of-N shapes it cannot produce. `signers` is what
 * actually signs, so a caller can also produce an event whose signatures are all invalid.
 */
function inceptionEvent(options: {
  keys: KeyPair[];
  threshold: string;
  next: KeyPair[];
  signers: KeyPair[];
  /**
   * The threshold committed alongside `next` — the one the rotation revealing those keys
   * must declare (spec 003's next key STATE). Defaults to a 1-of-1 next state, which is
   * right for every caller whose commitment is never revealed.
   */
  nextThreshold?: string;
  /** Bytes to sign instead of the event itself — yields well-formed, invalid signatures. */
  signOver?: Uint8Array;
}) {
  const establishment = {
    seq: "0",
    kind: "icp" as const,
    keys: options.keys.map((keyPair) => encodeKeyRef(keyPair.publicKey)),
    threshold: options.threshold,
    next: commitToKeyState(
      options.next.map((keyPair) => encodeKeyRef(keyPair.publicKey)),
      options.nextThreshold ?? "1"
    )
  };
  const unsigned = { ...establishment, id: deriveParticipantId(establishment), prior: null };
  const bytes = options.signOver ?? canonicalBytes(unsigned);
  return {
    ...unsigned,
    signature: options.signers.map((keyPair) => encodeSignature(sign(bytes, keyPair.secretKey)))
  };
}

const keyPairs = (count: number, base: number): KeyPair[] =>
  Array.from({ length: count }, (_, index) => generateKeyPair(seed(base + index)));

describe("identity creation (specs 002 + 003)", () => {
  it("creates a self-certifying identity that replays to its own keys", () => {
    const identity = createIdentity();

    expect(participantIdSchema.parse(identity.id)).toBe(identity.id);
    expect(keyEventSchema.parse(identity.log[0])).toBeTruthy();

    const state = replayKeyLog(identity.log);
    expect(state.id).toBe(identity.id);
    expect(state.keys).toEqual([encodeKeyRef(identity.currentKeys[0]!.publicKey)]);
  });

  it("derives the same ID from the same seeds (deterministic)", () => {
    const a = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
    const b = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
    expect(a.id).toBe(b.id);
  });

  it("rejects an ID that does not match the inception event", () => {
    const identity = createIdentity();
    const forged = { ...identity.log[0]!, id: createIdentity().id };
    expect(() => replayKeyLog([forged])).toThrow(/does not match/);
  });
});

describe("rotation and replay (spec 003)", () => {
  it("rotates to the pre-committed keys without changing the ID", () => {
    const identity = createIdentity();
    const rotated = rotateIdentity(identity);

    expect(rotated.id).toBe(identity.id);

    const state = replayKeyLog(rotated.log);
    expect(state.seq).toBe("1");
    expect(state.keys).toEqual([encodeKeyRef(identity.nextKeys[0]!.publicKey)]);

    const again = rotateIdentity(rotated);
    expect(replayKeyLog(again.log).seq).toBe("2");
    expect(again.id).toBe(identity.id);
  });

  it("rejects a rotation that does not reveal the pre-committed key set", () => {
    const identity = createIdentity();
    const attacker = generateKeyPair();
    const previous = identity.log[0]!;

    const unsigned = {
      id: identity.id,
      seq: "1",
      prior: eventDigest(previous),
      kind: "rot" as const,
      keys: [encodeKeyRef(attacker.publicKey)],
      threshold: "1",
      next: commitToKeyState([encodeKeyRef(attacker.publicKey)], "1")
    };
    const forged = {
      ...unsigned,
      signature: [encodeSignature(sign(canonicalBytes(unsigned), attacker.secretKey))]
    };

    expect(() => replayKeyLog([previous, forged])).toThrow(/pre-committed/);
  });

  it("rejects tampered events, broken chains, and gaps", () => {
    const rotated = rotateIdentity(createIdentity());
    const [icp, rot] = rotated.log as [(typeof rotated.log)[0], (typeof rotated.log)[1]];

    expect(() => replayKeyLog([icp, { ...rot, threshold: "2" }])).toThrow();
    expect(() => replayKeyLog([icp, { ...rot, prior: eventDigest(rot) }])).toThrow(/chain/);
    expect(() => replayKeyLog([icp, { ...rot, seq: "5" }])).toThrow(/contiguous/);
    expect(() => replayKeyLog([{ ...icp, kind: "rot" as const }])).toThrow(/inception/);
  });

  it("rejects an event that lists the same key more than once", () => {
    const keyPair = generateKeyPair(seed(9));
    const keyRef = encodeKeyRef(keyPair.publicKey);
    const nextPair = generateKeyPair(seed(10));

    // A forged inception claiming threshold 2 over a duplicated key: without the
    // duplicate check, one signature would satisfy both key entries.
    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: [keyRef, keyRef],
      threshold: "2",
      next: commitToKeyState([encodeKeyRef(nextPair.publicKey)], "1")
    };
    const unsigned = {
      ...establishment,
      id: deriveParticipantId(establishment),
      prior: null
    };
    const forged = {
      ...unsigned,
      signature: [encodeSignature(sign(canonicalBytes(unsigned), keyPair.secretKey))]
    };

    // S0 (spec 015): the STATE is invalid, and so is every record checked against it. The
    // rejection names the rule, so a caller can tell it from every other refusal.
    expect(() => replayKeyLog([forged])).toThrow(/state_repeats_key/);
  });

  it("hands control to an external next-key holder via nextCommitment (custody exit)", () => {
    const custody = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
    const userNext = generateKeyPair(seed(3));

    // Custody rotates, committing to a key state it never holds: the user's single key at
    // the 1-of-1 threshold their rotation will declare.
    const exiting = rotateIdentity(custody, {
      nextCommitment: commitToKeyState([encodeKeyRef(userNext.publicKey)], "1")
    });
    expect(exiting.nextKeys).toEqual([]);
    expect(exiting.nextThreshold).toBeNull();
    expect(replayKeyLog(exiting.log).seq).toBe("1");

    // Custody can no longer rotate — it holds no next keys.
    expect(() => rotateIdentity(exiting)).toThrow(/no pre-committed next keys/);

    // The committed holder completes the handover without ever holding current keys.
    const user = {
      id: exiting.id,
      log: exiting.log,
      currentKeys: [],
      nextKeys: [userNext],
      nextThreshold: "1"
    };
    const owned = rotateIdentity(user);
    const state = replayKeyLog(owned.log);
    expect(state.seq).toBe("2");
    expect(state.keys).toEqual([encodeKeyRef(userNext.publicKey)]);

    // No one else can complete it: a rotation revealing other keys fails replay.
    const attacker = generateKeyPair(seed(4));
    const forged = rotateIdentity({
      id: exiting.id,
      log: exiting.log,
      currentKeys: [],
      nextKeys: [attacker],
      nextThreshold: "1"
    });
    expect(() => replayKeyLog(forged.log)).toThrow(/pre-committed/);
  });

  it("rejects passing both nextSeeds and nextCommitment", () => {
    const identity = createIdentity();
    expect(() =>
      rotateIdentity(identity, {
        nextSeeds: [seed(5)],
        nextCommitment: commitToKeyState([encodeKeyRef(generateKeyPair().publicKey)], "1")
      })
    ).toThrow(/not both/);
  });

  it("rejects an event carrying more signatures than it lists keys", () => {
    const key = generateKeyPair(seed(20));
    const decoy = generateKeyPair(seed(21));
    const next = generateKeyPair(seed(22));

    const honest = inceptionEvent({
      keys: [key],
      threshold: "1",
      next: [next],
      signers: [key]
    });
    // Same event, padded with a second signature it has no key for. It is rejected by the
    // signature-to-key ratio before curve work; under the legacy verifier this was the shape
    // that inflated the key x signature search.
    const { signature, ...unsigned } = honest;
    const padded = {
      ...honest,
      signature: [...signature, encodeSignature(sign(canonicalBytes(unsigned), decoy.secretKey))]
    };

    expect(replayKeyLog([honest]).seq).toBe("0");
    expect(() => replayKeyLog([padded])).toThrow(/signatures but lists only/);
  });

  it("supports M-of-N establishment data in the ID recipe", () => {
    const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const id = deriveParticipantId({
      seq: "0",
      kind: "icp",
      keys: keys.map((keyPair) => encodeKeyRef(keyPair.publicKey)),
      threshold: "2",
      next: commitToKeyState([encodeKeyRef(generateKeyPair().publicKey)], "1")
    });
    expect(participantIdSchema.parse(id)).toBe(id);
  });
});

/**
 * Replay runs on unauthenticated input (spec 004's first-write bootstrap: the submitted
 * log is what resolves the keys the request signature is checked against), so its cost
 * must be bounded by construction rather than by trusting the caller.
 */
describe("replay work bounds", () => {
  /** An M-of-M identity, which `createIdentity` cannot produce (it is always 1-of-1). */
  function thresholdIdentity(count: number): Identity {
    const currentKeys = keyPairs(count, 100);
    const nextKeys = keyPairs(count, 140);
    const event = inceptionEvent({
      keys: currentKeys,
      threshold: String(count),
      next: nextKeys,
      // The committed next state is M-of-M too, so the rotation revealing it declares
      // String(count) and carries that many signatures — the shape these bounds are about.
      nextThreshold: String(count),
      signers: currentKeys
    });
    return { id: event.id, log: [event], currentKeys, nextKeys, nextThreshold: String(count) };
  }

  it("rejects a raw over-wide inception before hashing or curve work and admits K keys", () => {
    const overWideKeys = keyPairs(MAX_KEY_EVENT_KEYS + 1, 470);
    const overWide = inceptionEvent({
      keys: overWideKeys,
      threshold: "1",
      next: keyPairs(1, 490),
      signers: [overWideKeys[0]!]
    });
    let spent = -1;
    const refused = captureThrow(() =>
      replayKeyLog([overWide], { onSignatureVerifications: (count) => (spent = count) })
    );
    expect(refused).toBeInstanceOf(Error);
    expect((refused as Error).message).toBe(
      `Inception key event lists ${MAX_KEY_EVENT_KEYS + 1} keys; spec 003 permits at most ${MAX_KEY_EVENT_KEYS}`
    );
    expect(spent).toBe(0);

    const boundaryKeys = keyPairs(MAX_KEY_EVENT_KEYS, 500);
    const boundary = inceptionEvent({
      keys: boundaryKeys,
      threshold: "1",
      next: keyPairs(1, 520),
      signers: [boundaryKeys[MAX_KEY_EVENT_KEYS - 1]!]
    });
    spent = -1;
    expect(
      replayKeyLog([boundary], { onSignatureVerifications: (count) => (spent = count) }).keys
    ).toHaveLength(MAX_KEY_EVENT_KEYS);
    expect(spent).toBe(MAX_KEY_EVENT_KEYS);
  });

  it("spends at most one verification per listed key, whatever the member count", () => {
    const keys = keyPairs(2, 30);
    const next = keyPairs(1, 40);
    // Three events over the SAME two keys. Under spec 015's greedy forward walk the cost is
    // decided by how far down the KEY list the walk has to travel, and never by how many
    // members the set carries — the walk increments the key cursor on both branches, so it
    // calls `verify` at most `n` times however large `m` is.
    const firstKeySigns = inceptionEvent({
      keys,
      threshold: "1",
      next,
      signers: [keys[0]!]
    });
    const secondKeySigns = inceptionEvent({
      keys,
      threshold: "1",
      next,
      signers: [keys[1]!]
    });
    const bothSign = inceptionEvent({ keys, threshold: "2", next, signers: keys });

    // Member 0 matches key 0 immediately: one verification, and the second key is never
    // touched by the curve.
    expect(replayKeyLog([firstKeySigns], { maxSignatureVerifications: 1 }).keys).toHaveLength(2);

    // The same one-member set signed by the SECOND key must walk past key 0 first, so it
    // costs two. This half is what makes the trio meaningful — it fails against any build
    // where the options argument is ignored, which a bare "replays under a budget of 1"
    // assertion would not.
    expect(() => replayKeyLog([secondKeySigns], { maxSignatureVerifications: 1 })).toThrow(
      KeyLogWorkBudgetExceeded
    );
    expect(replayKeyLog([secondKeySigns], { maxSignatureVerifications: 2 }).keys).toHaveLength(2);

    // Two members against two keys also costs two — one per key, not one per (key, member)
    // pair, which the search this replaces would have made four in the worst case.
    expect(() => replayKeyLog([bothSign], { maxSignatureVerifications: 1 })).toThrow(
      KeyLogWorkBudgetExceeded
    );
    expect(replayKeyLog([bothSign], { maxSignatureVerifications: 2 }).keys).toHaveLength(2);
  });

  it("validates every key in an event, including keys past the satisfying threshold", () => {
    const keys = keyPairs(2, 70);
    // Schema-valid base58btc text that is not a multicodec-tagged ed25519-pub key. Only
    // `decodeKeyRef` rejects this; `keyRefSchema` accepts it.
    const malformed = "z11111111111111111111111111111111";
    const signer = keys[0]!;
    const next = keyPairs(1, 72);

    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: [encodeKeyRef(signer.publicKey), malformed],
      threshold: "1",
      next: commitToKeyState(
        next.map((keyPair) => encodeKeyRef(keyPair.publicKey)),
        "1"
      )
    };
    const unsigned = { ...establishment, id: deriveParticipantId(establishment), prior: null };
    const event = {
      ...unsigned,
      signature: [encodeSignature(sign(canonicalBytes(unsigned), signer.secretKey))]
    };

    // The threshold is satisfied by the FIRST key, so the verification loop never reaches
    // the second. Validation of the key set must not ride on that loop: an event carrying an
    // undecodable trailing KeyRef would otherwise replay clean, be stored, and then throw
    // from every later `verifyRecord` against the stored state.
    expect(keyEventSchema.safeParse(event).success).toBe(true);
    expect(() => replayKeyLog([event])).toThrow(/Unsupported KeyRef/);
  });

  it("spends one verification per event on an honest 1-of-1 log", () => {
    let identity = createIdentity({ currentSeed: seed(50), nextSeed: seed(51) });
    for (let index = 0; index < 4; index += 1) {
      identity = rotateIdentity(identity);
    }
    expect(identity.log).toHaveLength(5);

    expect(replayKeyLog(identity.log, { maxSignatureVerifications: 5 }).seq).toBe("4");
    expect(() => replayKeyLog(identity.log, { maxSignatureVerifications: 4 })).toThrow(
      KeyLogWorkBudgetExceeded
    );
  });

  it("throws KeyLogWorkBudgetExceeded rather than replaying past the budget", () => {
    const identity = createIdentity({ currentSeed: seed(60), nextSeed: seed(61) });
    let thrown: unknown;
    try {
      replayKeyLog(identity.log, { maxSignatureVerifications: 0 });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(KeyLogWorkBudgetExceeded);
    expect((thrown as Error).name).toBe("KeyLogWorkBudgetExceeded");
    expect((thrown as Error).message).toMatch(/budget of 0 signature verifications/);
  });

  it("keeps the generic threshold ceiling at 8192 and derives replay's default as E * K", () => {
    expect(DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS).toBe(
      MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS
    );
    expect(DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS).toBe(1024);
    expect(DEFAULT_MAX_SIGNATURE_VERIFICATIONS).toBe(
      MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS * MAX_KEY_EVENT_SIGNATURES
    );
    expect(DEFAULT_MAX_SIGNATURE_VERIFICATIONS).toBe(8192);
    expect(DEFAULT_MAX_SIGNATURE_VERIFICATIONS).toBeGreaterThan(
      DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS
    );
  });

  // Real Ed25519 work, so the generous timeout keeps a loaded machine from reading as a
  // hang. Nothing here asserts on elapsed time.
  it("replays a tight E-event M-of-M log at the new default and refuses one less", () => {
    let identity = thresholdIdentity(MAX_KEY_EVENT_KEYS);
    for (let index = 1; index < MAX_KEY_LOG_EVENTS; index += 1) {
      identity = rotateIdentity(identity);
    }
    // Under spec 015's walk an M-of-M event signed in key order costs exactly M — one
    // verification per listed key, each matching on its first try. The search this replaces
    // cost M(M+1)/2 = 36 for the same event, because it re-tried every signature against
    // every key.
    const perEvent = MAX_KEY_EVENT_KEYS;
    expect(perEvent).toBe(8);

    expect(identity.log).toHaveLength(MAX_KEY_LOG_EVENTS);
    expect(replayKeyLog(identity.log).seq).toBe(String(MAX_KEY_LOG_EVENTS - 1));
    expect(() =>
      replayKeyLog(identity.log, {
        maxSignatureVerifications: DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS - 1
      })
    ).toThrow(KeyLogWorkBudgetExceeded);
    expect(MAX_KEY_LOG_EVENTS * perEvent).toBe(DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS);
  }, 120_000);

  it("charges only the unproven suffix when a verified prefix is declared", () => {
    let identity = createIdentity({ currentSeed: seed(90), nextSeed: seed(91) });
    for (let index = 0; index < 5; index += 1) {
      identity = rotateIdentity(identity);
    }
    expect(identity.log).toHaveLength(6);

    // Six 1-of-1 events cost six verifications. Declaring the first five already verified
    // leaves exactly one to pay for — which is the property that stops the cost of extending
    // an append-only log growing with the log's length.
    expect(() => replayKeyLog(identity.log, { maxSignatureVerifications: 5 })).toThrow(
      KeyLogWorkBudgetExceeded
    );
    expect(
      replayKeyLog(identity.log, { maxSignatureVerifications: 1, verifiedPrefixLength: 5 }).seq
    ).toBe("5");

    // A fully verified prefix spends nothing at all — the stored-log read path.
    expect(
      replayKeyLog(identity.log, {
        maxSignatureVerifications: 0,
        verifiedPrefixLength: identity.log.length
      }).seq
    ).toBe("5");
  });

  it("still checks structure and key validity across a verified prefix", () => {
    const identity = rotateIdentity(createIdentity({ currentSeed: seed(95), nextSeed: seed(96) }));
    const [icp, rot] = identity.log as [(typeof identity.log)[0], (typeof identity.log)[1]];
    const wholeLogVerified = { verifiedPrefixLength: 2, maxSignatureVerifications: 0 };

    // Skipping signature verification must not skip anything else: a broken chain, a broken
    // pre-rotation commitment, a foreign participant and an undecodable key are all still
    // caught, so a corrupted stored log cannot pass as valid.
    expect(() =>
      replayKeyLog([icp, { ...rot, prior: eventDigest(rot) }], wholeLogVerified)
    ).toThrow(/chain/);
    expect(() => replayKeyLog([icp, { ...rot, seq: "5" }], wholeLogVerified)).toThrow(/contiguous/);
    expect(() => replayKeyLog([{ ...icp, id: createIdentity().id }], wholeLogVerified)).toThrow(
      /does not match/
    );
    // An undecodable KeyRef, in a log whose id and commitment are otherwise consistent so the
    // decode is genuinely what catches it.
    const signer = generateKeyPair(seed(97));
    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: [encodeKeyRef(signer.publicKey), "z11111111111111111111111111111111"],
      threshold: "1",
      next: commitToKeyState([encodeKeyRef(generateKeyPair(seed(98)).publicKey)], "1")
    };
    const unsigned = { ...establishment, id: deriveParticipantId(establishment), prior: null };
    const malformed = {
      ...unsigned,
      signature: [encodeSignature(sign(canonicalBytes(unsigned), signer.secretKey))]
    };
    expect(() =>
      replayKeyLog([malformed], { verifiedPrefixLength: 1, maxSignatureVerifications: 0 })
    ).toThrow(/Unsupported KeyRef/);
  });

  it("falls back to the safe value for any option it cannot trust", () => {
    // Both options gate signature verification, so a malformed one must resolve to "verify
    // everything, spend no more than the default" — never to a value whose comparisons all
    // read false, which is what NaN and Infinity did. A JSON round-trip or Number(header)
    // produces exactly these.
    const identity = rotateIdentity(
      createIdentity({ currentSeed: seed(100), nextSeed: seed(101) })
    );
    const attacker = generateKeyPair(seed(102));
    const last = identity.log[1]!;
    const { signature, ...unsigned } = last;
    // A forged final event: same establishment data, so every structural check still passes,
    // but the signature is the attacker's.
    const forged = [
      identity.log[0]!,
      {
        ...last,
        signature: [encodeSignature(sign(canonicalBytes(unsigned), attacker.secretKey))]
      }
    ];
    expect(signature).toHaveLength(1);
    expect(() => replayKeyLog(forged)).toThrow(/does not verify under a distinct listed key/);

    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, "2" as unknown as number]) {
      // A junk prefix length must not discount a single event.
      expect(() => replayKeyLog(forged, { verifiedPrefixLength: bad })).toThrow(
        /does not verify under a distinct listed key/
      );
      // A junk budget must not disable the budget.
      expect(() =>
        replayKeyLog(identity.log, { maxSignatureVerifications: bad, verifiedPrefixLength: 0 })
      ).not.toThrow();
    }

    // NaN as a budget previously replayed anything; now it is the default, which still bites.
    // `m = t = n` is the widest walk the schema admits, so this is the most expensive event
    // a hostile publisher can offer.
    const wide = keyPairs(MAX_KEY_EVENT_KEYS, 300);
    const decoys = keyPairs(MAX_KEY_EVENT_KEYS, 320);
    const hostile = inceptionEvent({
      keys: wide,
      threshold: String(MAX_KEY_EVENT_KEYS),
      next: keyPairs(1, 340),
      signers: decoys,
      signOver: canonicalBytes({ different: "bytes" })
    });
    expect(() => replayKeyLog([hostile], { maxSignatureVerifications: Number.NaN })).toThrow(
      /does not verify under a distinct listed key/
    );
  });

  it("reports what it spent even when it throws", () => {
    const identity = createIdentity({ currentSeed: seed(110), nextSeed: seed(111) });

    // On success the spend is reported, as before.
    let spent = -1;
    replayKeyLog(identity.log, { onSignatureVerifications: (n) => (spent = n) });
    expect(spent).toBe(1);

    // And on a throw. A caller carrying one allowance across several replays — a grant chain
    // does exactly that — must be charged for work that failed, or a view that can force
    // failures buys the whole allowance again on every attempt.
    spent = -1;
    expect(() =>
      replayKeyLog(identity.log, {
        maxSignatureVerifications: 0,
        onSignatureVerifications: (n) => (spent = n)
      })
    ).toThrow(KeyLogWorkBudgetExceeded);
    expect(spent).toBe(0);

    // The most expensive event the schema still admits under spec 015: `m = t` forces the
    // member count to the threshold, so the widest walk is an 8-of-8 whose members match
    // nothing. It runs the key cursor to the end — MAX_KEY_EVENT_KEYS verifications — and
    // a budget below that is exhausted part-way.
    const wide = keyPairs(MAX_KEY_EVENT_KEYS, 400);
    const decoys = keyPairs(MAX_KEY_EVENT_KEYS, 420);
    const hostile = inceptionEvent({
      keys: wide,
      threshold: String(MAX_KEY_EVENT_KEYS),
      next: keyPairs(1, 440),
      signers: decoys,
      signOver: canonicalBytes({ different: "bytes" })
    });
    spent = -1;
    expect(() =>
      replayKeyLog([hostile], {
        maxSignatureVerifications: 3,
        onSignatureVerifications: (n) => (spent = n)
      })
    ).toThrow(KeyLogWorkBudgetExceeded);
    // The full allowance was consumed before the refusal, and that is what gets charged.
    expect(spent).toBe(3);
  });

  it("gives the pre-auth path its own, far tighter budget", () => {
    // One verification per event at the schema's maximum log length: exactly what a 1-of-1
    // log costs, which is the only shape this codebase can mint.
    expect(MAX_PREAUTH_SIGNATURE_VERIFICATIONS).toBe(MAX_KEY_LOG_EVENTS);
    expect(MAX_PREAUTH_SIGNATURE_VERIFICATIONS).toBeLessThan(DEFAULT_MAX_SIGNATURE_VERIFICATIONS);

    let identity = createIdentity({ currentSeed: seed(80), nextSeed: seed(81) });
    for (let index = 0; index < 5; index += 1) {
      identity = rotateIdentity(identity);
    }
    expect(
      replayKeyLog(identity.log, {
        maxSignatureVerifications: MAX_PREAUTH_SIGNATURE_VERIFICATIONS
      }).seq
    ).toBe("5");
  });

  // Generous timeout for the same reason as the test above: real Ed25519 work, and this
  // suite runs alongside every other package's. Nothing here asserts on elapsed time.
  it("bounds the most expensive schema-valid event at MAX_KEY_EVENT_KEYS verifications", () => {
    const keys = keyPairs(MAX_KEY_EVENT_KEYS, 160);
    const decoys = keyPairs(MAX_KEY_EVENT_KEYS, 200);
    // Every signature is well-formed and over the wrong bytes, so no key ever matches and
    // the walk runs its key cursor to the end. `m = t = n` is what makes this the widest
    // walk the schema still admits: a smaller threshold would fail S1's count rule before
    // any curve work, and a larger member count is unreachable because m must equal t.
    const forged = inceptionEvent({
      keys,
      threshold: String(MAX_KEY_EVENT_KEYS),
      next: keyPairs(1, 240),
      signers: decoys,
      signOver: canonicalBytes({ different: "bytes" })
    });
    expect(keyEventSchema.safeParse(forged).success).toBe(true);

    // The bound is the KEY count alone. The signature count is not a factor at all, where
    // the search this replaces was keys x signatures = 64 for the same event.
    const worstCase = MAX_KEY_EVENT_KEYS;
    expect(worstCase).toBe(8);
    expect(worstCase).toBeLessThan(MAX_KEY_EVENT_KEYS * MAX_KEY_EVENT_SIGNATURES);

    // Budgeted at exactly the worst case, the replay finishes the walk and rejects the
    // event on its merits — proof the work never exceeds the key count.
    expect(() => replayKeyLog([forged], { maxSignatureVerifications: worstCase })).toThrow(
      /does not verify under a distinct listed key/
    );
    // One less, and the budget bites first — proof the count is exactly 8, not fewer by
    // luck, and that the ceiling is what stops it rather than the walk running away.
    expect(() => replayKeyLog([forged], { maxSignatureVerifications: worstCase - 1 })).toThrow(
      KeyLogWorkBudgetExceeded
    );
    // Under the default budget the same event is rejected outright, inside the ceiling.
    expect(() => replayKeyLog([forged])).toThrow(/does not verify under a distinct listed key/);
  }, 120_000);
});

/**
 * Runs `fn` and returns whatever it threw, or `null` when it returned. Callers assert on the
 * RESULT rather than inside a `catch`, so a test that stops throwing fails instead of quietly
 * asserting against its own assertion error.
 */
function captureThrow(fn: () => unknown): unknown {
  try {
    fn();
    return null;
  } catch (error) {
    return error;
  }
}

describe("replayKeyLogFor — binding a log to the participant it was served for", () => {
  it("returns the state when the log's self-derived id is the expected one", () => {
    const identity = createIdentity({ currentSeed: seed(41), nextSeed: seed(42) });
    expect(replayKeyLogFor(identity.id, identity.log)).toEqual(replayKeyLog(identity.log));
  });

  it("rejects another participant's perfectly valid log — the substituted-log attack", () => {
    // The whole point. `attacker.log` replays clean; it simply is not `victim`'s log. Without
    // this binding a host serving it at the victim's path makes every record naming the victim
    // verify under the attacker's keys.
    const victim = createIdentity({ currentSeed: seed(43), nextSeed: seed(44) });
    const attacker = createIdentity({ currentSeed: seed(45), nextSeed: seed(46) });
    expect(replayKeyLog(attacker.log).id).toBe(attacker.id);

    expect(() => replayKeyLogFor(victim.id, attacker.log)).toThrow(KeyLogParticipantMismatch);

    // Captured rather than asserted inside a `catch`. An `expect.unreachable()` in the `try`
    // throws into that same `catch`, where an assertion loose enough to hold for vitest's own
    // error makes the whole test vacuous — it passes with the binding removed. Returning the
    // error means "did not throw" is `null`, which no assertion below accepts.
    const thrown = captureThrow(() => replayKeyLogFor(victim.id, attacker.log));
    expect(thrown).toBeInstanceOf(KeyLogParticipantMismatch);
    expect((thrown as KeyLogParticipantMismatch).expectedId).toBe(victim.id);
    expect((thrown as KeyLogParticipantMismatch).actualId).toBe(attacker.id);
  });

  it("binds a rotated log too — the id is the inception's, not the latest event's", () => {
    const victim = createIdentity({ currentSeed: seed(47), nextSeed: seed(48) });
    const attacker = rotateIdentity(createIdentity({ currentSeed: seed(49), nextSeed: seed(50) }));
    expect(attacker.log).toHaveLength(2);
    expect(() => replayKeyLogFor(victim.id, attacker.log)).toThrow(KeyLogParticipantMismatch);
    expect(replayKeyLogFor(attacker.id, attacker.log).seq).toBe("1");
  });

  it("is not a budget failure — a substituted log must never read as a cost refusal", () => {
    // Callers treat exhaustion as a retryable stall and invalidity as a verdict. A wrong log
    // is a verdict, so it must not arrive wearing the stall's type.
    const victim = createIdentity({ currentSeed: seed(51), nextSeed: seed(52) });
    const attacker = createIdentity({ currentSeed: seed(53), nextSeed: seed(54) });

    const thrown = captureThrow(() => replayKeyLogFor(victim.id, attacker.log));
    // The POSITIVE assertion is what makes this test real. Asserting only that the error is
    // not a budget error, and is an Error, is satisfied by vitest's own assertion failure —
    // so the earlier shape of this test passed against a build with the binding removed.
    expect(thrown).toBeInstanceOf(KeyLogParticipantMismatch);
    expect(thrown).not.toBeInstanceOf(KeyLogWorkBudgetExceeded);
  });

  it("still rejects an invalid log before it ever compares ids", () => {
    const identity = createIdentity({ currentSeed: seed(55), nextSeed: seed(56) });
    const forged = { ...identity.log[0]!, signature: [] };
    expect(() => replayKeyLogFor(identity.id, [forged])).toThrow(/threshold/);
  });
});
