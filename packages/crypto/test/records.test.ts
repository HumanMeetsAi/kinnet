import { readFileSync } from "node:fs";

import {
  conversationSchema,
  messageEnvelopeSchema,
  participantProfileSchema,
  type Conversation,
  type MessageEnvelope,
  type ParticipantProfile
} from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  canonicalDigest,
  createIdentity,
  DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS,
  DEFAULT_MAX_SIGNATURE_VERIFICATIONS,
  deriveParticipantId,
  encodeKeyRef,
  generateKeyPair,
  replayKeyLog,
  replayKeyLogStates,
  signRecord,
  signThresholdRecord,
  verifyRecord,
  verifyAnchoredRecord,
  verifyRecordAgainstAny,
  VerificationBudgetExceeded,
  verifyThresholdRecord
} from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

describe("record signing (spec 001)", () => {
  it("signs and verifies a protocol record round-trip", () => {
    const identity = createIdentity();
    const profile = signRecord(
      {
        id: identity.id,
        type: "person",
        displayName: "An Lu",
        capabilities: [],
        verifiedDomains: [],
        updatedAt: "2026-06-12T00:00:00.000Z"
      },
      identity.currentKeys[0]!.secretKey
    );

    const parsed = participantProfileSchema.parse(profile);
    const signerKeyRef = replayKeyLog(identity.log).keys[0]!;
    expect(verifyRecord(parsed, signerKeyRef)).toBe(true);
  });

  it("fails verification when any field is mutated", () => {
    const identity = createIdentity();
    const record = signRecord({ a: "x", b: ["y"] }, identity.currentKeys[0]!.secretKey);
    const keyRef = encodeKeyRef(identity.currentKeys[0]!.publicKey);

    expect(verifyRecord(record, keyRef)).toBe(true);
    expect(verifyRecord({ ...record, a: "z" }, keyRef)).toBe(false);
  });

  it("is insensitive to key order at signing time", () => {
    const identity = createIdentity();
    const secretKey = identity.currentKeys[0]!.secretKey;
    const keyRef = encodeKeyRef(identity.currentKeys[0]!.publicKey);

    const signedOneWay = signRecord({ a: 1, b: 2 }, secretKey);
    expect(verifyRecord({ b: 2, a: 1, signature: signedOneWay.signature }, keyRef)).toBe(true);
  });

  it("rejects floats in signed records per spec 001", () => {
    const identity = createIdentity();
    expect(() => signRecord({ ratio: 0.5 }, identity.currentKeys[0]!.secretKey)).toThrow(
      /spec 001/
    );
  });

  it("encodes Ed25519 KeyRefs in the did:key-compatible form", () => {
    const identity = createIdentity({ currentSeed: seed(7), nextSeed: seed(8) });
    expect(encodeKeyRef(identity.currentKeys[0]!.publicKey).startsWith("z6Mk")).toBe(true);
  });

  it("meters a multi-key record check and canonicalizes the record once", () => {
    const keys = Array.from({ length: 4 }, () => generateKeyPair());
    const signed = signRecord({ payload: "once" }, keys[3]!.secretKey);
    let payloadReads = 0;
    const observed = { signature: signed.signature } as Record<string, unknown> & {
      signature: string;
    };
    Object.defineProperty(observed, "payload", {
      enumerable: true,
      get() {
        payloadReads += 1;
        return "once";
      }
    });
    let spent = 0;

    expect(
      verifyRecordAgainstAny(
        observed,
        keys.map((key) => encodeKeyRef(key.publicKey)),
        { onSignatureVerifications: (count) => (spent += count) }
      )
    ).toBe(true);
    expect(spent).toBe(4);
    expect(payloadReads).toBe(1);
  });

  it("refuses a fixed record check when its verification meter is removed", () => {
    const identity = createIdentity();
    const record = signRecord({ payload: "metered" }, identity.currentKeys[0]!.secretKey);
    expect(() =>
      verifyRecordAgainstAny(record, [encodeKeyRef(identity.currentKeys[0]!.publicKey)], {
        maxSignatureVerifications: 0
      })
    ).toThrow(VerificationBudgetExceeded);
  });
});

describe("threshold record signing (specs 003/008/009)", () => {
  it("preserves the 8192 generic default independently of key-log replay's 1024 default", () => {
    const runtimeKeys = Array.from(
      { length: DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS + 1 },
      (_unused, index) => {
        const keySeed = new Uint8Array(32);
        keySeed[0] = index & 0xff;
        keySeed[1] = (index >> 8) & 0xff;
        return generateKeyPair(keySeed);
      }
    );
    const record = signThresholdRecord({ purpose: "generic-runtime-sized-key-set" }, [
      runtimeKeys[runtimeKeys.length - 1]!.secretKey
    ]);
    const refs = runtimeKeys.map((key) => encodeKeyRef(key.publicKey));

    expect(DEFAULT_MAX_SIGNATURE_VERIFICATIONS).toBe(8192);
    expect(refs).toHaveLength(DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS + 1);
    expect(() =>
      verifyThresholdRecord(record, refs, "1", {
        maxSignatureVerifications: DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS
      })
    ).toThrow(VerificationBudgetExceeded);
    expect(verifyThresholdRecord(record, refs, "1")).toBe(true);
  }, 30_000);
  it("signs and verifies a signature-set record at threshold 1 and 2", () => {
    const alpha = generateKeyPair(seed(1));
    const beta = generateKeyPair(seed(2));
    const keys = [encodeKeyRef(alpha.publicKey), encodeKeyRef(beta.publicKey)];

    // Spec 015 S1 is exact: a set holds EXACTLY the threshold in members. The two-member
    // set is the conforming record at threshold 2 and is INVALID at threshold 1, where it
    // carries one member more than the state requires — the surplus a passer-by holding no
    // key could strip to produce a second valid record with a different digest.
    const record = signThresholdRecord({ scope: "test" }, [alpha.secretKey, beta.secretKey]);
    expect(verifyThresholdRecord(record, keys, "2")).toBe(true);
    expect(verifyThresholdRecord(record, keys, "1")).toBe(false);

    const single = signThresholdRecord({ scope: "test" }, [alpha.secretKey]);
    expect(verifyThresholdRecord(single, keys, "1")).toBe(true);
    expect(verifyThresholdRecord(single, keys, "2")).toBe(false);
  });

  it("fails verification on tampered fields and foreign signatures", () => {
    const alpha = generateKeyPair(seed(3));
    const intruder = generateKeyPair(seed(4));
    const keys = [encodeKeyRef(alpha.publicKey)];

    const record = signThresholdRecord({ scope: "test" }, [alpha.secretKey]);
    expect(verifyThresholdRecord({ ...record, scope: "other" }, keys, "1")).toBe(false);

    const forged = signThresholdRecord({ scope: "test" }, [intruder.secretKey]);
    expect(verifyThresholdRecord(forged, keys, "1")).toBe(false);
  });

  it("does not let one key satisfy the threshold twice", () => {
    const alpha = generateKeyPair(seed(5));
    const record = signThresholdRecord({ scope: "test" }, [alpha.secretKey]);

    const beta = generateKeyPair(seed(6));
    const distinct = [encodeKeyRef(alpha.publicKey), encodeKeyRef(beta.publicKey)];
    expect(verifyThresholdRecord(record, distinct, "2")).toBe(false);

    // A state that lists the same key twice is invalid outright under S0 — at ANY
    // threshold, including 1, where the old rule accepted it. Comparison is on the key
    // VALUE, so the raw-bytes spelling of the same key is caught too.
    const duplicated = [encodeKeyRef(alpha.publicKey), encodeKeyRef(alpha.publicKey)];
    expect(verifyThresholdRecord(record, duplicated, "2")).toBe(false);
    expect(
      verifyThresholdRecord(record, [encodeKeyRef(alpha.publicKey), alpha.publicKey], "2")
    ).toBe(false);
    expect(verifyThresholdRecord(record, duplicated, "1")).toBe(false);

    // A duplicate signature set does not help either.
    const doubleSigned = signThresholdRecord({ scope: "test" }, [alpha.secretKey, alpha.secretKey]);
    expect(verifyThresholdRecord(doubleSigned, duplicated, "2")).toBe(false);
  });
});

describe("conformance fixture", () => {
  it("verifies the committed signed fixture from bytes alone", () => {
    const fixture = JSON.parse(
      readFileSync(new URL("./fixtures/signed-identity.json", import.meta.url), "utf8")
    ) as {
      log: Parameters<typeof replayKeyLog>[0];
      profile: ParticipantProfile;
    };

    const state = replayKeyLog(fixture.log);
    expect(state.id).toBe(fixture.profile.id);
    expect(verifyRecord(participantProfileSchema.parse(fixture.profile), state.keys[0]!)).toBe(
      true
    );

    const inception = fixture.log[0]!;
    expect(
      deriveParticipantId({
        seq: inception.seq,
        kind: inception.kind,
        keys: inception.keys,
        threshold: inception.threshold,
        next: inception.next
      })
    ).toBe(state.id);
  });
});

describe("message envelope conformance fixture (spec 010)", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/signed-envelope.json", import.meta.url), "utf8")
  ) as {
    log: Parameters<typeof replayKeyLog>[0];
    envelope: MessageEnvelope;
  };

  it("verifies the committed signed envelope from bytes alone", () => {
    // The envelope is a single-signer record signed by `from`'s current key: resolve that key
    // from the committed log, then verify the record signature against it.
    const state = replayKeyLog(fixture.log);
    expect(state.id).toBe(fixture.envelope.from);
    expect(verifyRecord(messageEnvelopeSchema.parse(fixture.envelope), state.keys[0]!)).toBe(true);
  });

  it("fails verification when a field is tampered", () => {
    const state = replayKeyLog(fixture.log);
    const tampered = { ...fixture.envelope, payload: { body: "tampered" } };
    expect(verifyRecord(tampered, state.keys[0]!)).toBe(false);
  });
});

describe("conversation conformance fixture (spec 012)", () => {
  // The fixture is the shared oracle: a third party holding only the committed bytes must
  // re-derive the same conversationId, the same schema-validation verdict, and the same
  // threshold-signature verification result. This test READS the committed file only — if
  // the file is missing or the bytes have drifted, the test MUST fail loudly. Never
  // regenerate the fixture at test time; regenerate it by hand and commit the new bytes.
  const fixture = JSON.parse(
    readFileSync(
      new URL("../../protocol/test/fixtures/signed-conversation.json", import.meta.url),
      "utf8"
    )
  ) as {
    creatorLog: Parameters<typeof replayKeyLog>[0];
    otherLog: Parameters<typeof replayKeyLog>[0];
    conversation: Conversation;
    conversationId: string;
  };

  it("has a schema-valid Conversation record", () => {
    expect(conversationSchema.parse(fixture.conversation)).toBeTruthy();
  });

  it("re-derives conversationId from the committed bytes (bytes -> id pin)", () => {
    // A third party holding the committed conversation JSON alone must arrive at the same
    // conversationId — that is the whole point of the fixture.
    expect(canonicalDigest(fixture.conversation)).toBe(fixture.conversationId);
  });

  it("verifies the creator's signature against the replayed creator log", () => {
    const state = replayKeyLog(fixture.creatorLog);
    expect(state.id).toBe(fixture.conversation.creator);
    expect(verifyThresholdRecord(fixture.conversation, state.keys, state.threshold)).toBe(true);
  });

  it("verifies it as an ANCHORED record: the state it names, and no other (spec 016)", () => {
    // The record is owner mode, so it carries `anchor` and the verifier resolves that one
    // state rather than searching the log.
    const { states } = replayKeyLogStates(fixture.creatorLog);
    const anchored = fixture.conversation as Conversation & { anchor: string };
    expect(anchored.anchor).toBeDefined();
    expect(states.some((state) => state.anchor === anchored.anchor)).toBe(true);
    expect(verifyAnchoredRecord(anchored, states)).toBe(true);
    // Re-pointing the anchor invalidates it: the field is inside the signed bytes.
    expect(
      verifyAnchoredRecord({ ...anchored, anchor: canonicalDigest({ other: "event" }) }, states)
    ).toBe(false);
  });

  it("changes the conversationId when any field is tampered", () => {
    const tampered = { ...fixture.conversation, title: "Tampered" } as Conversation;
    expect(canonicalDigest(tampered)).not.toBe(fixture.conversationId);
  });
});

describe("threshold verification cost (spec 003)", () => {
  const wide = Array.from({ length: 8 }, (_, i) =>
    generateKeyPair(new Uint8Array(32).fill(40 + i))
  );
  const record = { subject: "cost", n: "1" };

  it("stops once the threshold is satisfied", () => {
    // Signed by the FIRST key only, threshold 1: the answer is known after one key. Continuing
    // through the rest cannot change `satisfied.size >= threshold`, so the early exit is free
    // and the boolean is identical — this is a cost change, not a semantic one.
    const signed = signThresholdRecord(record, [wide[0]!.secretKey]);
    const keys = wide.map((k) => encodeKeyRef(k.publicKey));

    let spent = -1;
    expect(
      verifyThresholdRecord(signed, keys, "1", { onSignatureVerifications: (n) => (spent = n) })
    ).toBe(true);
    expect(spent).toBe(1);
  });

  it("reports what it spent, and refuses to spend past a budget", () => {
    // Signed by the LAST key: every earlier key is tried first, so this is the worst case for
    // a threshold-1 record and it is what an attacker picks.
    const signed = signThresholdRecord(record, [wide[7]!.secretKey]);
    const keys = wide.map((k) => encodeKeyRef(k.publicKey));

    let spent = -1;
    expect(
      verifyThresholdRecord(signed, keys, "1", { onSignatureVerifications: (n) => (spent = n) })
    ).toBe(true);
    expect(spent).toBe(8);

    // Budgeted below that, it refuses rather than finishing the search. The spend is reported
    // on the throw too, so a caller carrying one allowance across many records is charged for
    // work that failed.
    spent = -1;
    expect(() =>
      verifyThresholdRecord(signed, keys, "1", {
        maxSignatureVerifications: 3,
        onSignatureVerifications: (n) => (spent = n)
      })
    ).toThrow(VerificationBudgetExceeded);
    expect(spent).toBe(3);
  });

  it("verifies the same records with and without a budget", () => {
    // The metering must not move the line between valid and invalid. Same inputs, same answer.
    const keys = wide.map((k) => encodeKeyRef(k.publicKey));
    const twoOfEight = signThresholdRecord(record, [wide[1]!.secretKey, wide[5]!.secretKey]);

    for (const threshold of ["1", "2", "3"]) {
      expect(verifyThresholdRecord(twoOfEight, keys, threshold)).toBe(
        verifyThresholdRecord(twoOfEight, keys, threshold, { maxSignatureVerifications: 1024 })
      );
    }
    expect(verifyThresholdRecord(twoOfEight, keys, "2")).toBe(true);
    expect(verifyThresholdRecord(twoOfEight, keys, "3")).toBe(false);
  });
});
