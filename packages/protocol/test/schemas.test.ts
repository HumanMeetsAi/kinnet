import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  abilitySchema,
  claimSchema,
  conversationSchema,
  grantSchema,
  keyEventLogSchema,
  keyEventSchema,
  keyRefSchema,
  PN_RESERVED_PREFIX,
  PN_TYPE_CONVERSATION,
  KNOWN_RESERVED_TYPES,
  MAX_GRANT_ABILITIES,
  MAX_GRANT_CHAIN_LINKS,
  MAX_KEY_EVENT_KEYS,
  MAX_KEY_EVENT_SIGNATURES,
  MAX_KEY_LOG_EVENTS,
  MAX_RECORD_SIGNATURES,
  messageEnvelopeSchema,
  nodeTransportSchema,
  parseJsonStrict,
  participantIdSchema,
  participantNodeSchema,
  participantProfileSchema,
  relationshipSchema,
  revocationSchema
} from "../src/index.js";

function omit(object: Record<string, unknown>, key: string): Record<string, unknown> {
  const copy = { ...object };
  delete copy[key];
  return copy;
}

const KEY_REF = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const MULTIHASH = "zQmYwAPJzv5CZsnAzt8auVZRnHEKzKgUEdy3W35nUSpS6kq";
const PARTICIPANT_ID = `pk_${MULTIHASH}`;
const DATETIME = "2026-06-12T00:00:00.000Z";

describe("primitive encodings (spec 005)", () => {
  it("accepts base58btc multibase strings", () => {
    expect(keyRefSchema.parse(KEY_REF)).toBe(KEY_REF);
  });

  it("rejects other multibase prefixes, empty bodies, and non-base58 characters", () => {
    expect(keyRefSchema.safeParse("f6MkhaXg").success).toBe(false);
    expect(keyRefSchema.safeParse("z").success).toBe(false);
    // 0, O, I, and l are not in the base58btc alphabet
    expect(keyRefSchema.safeParse("z0OIl").success).toBe(false);
    expect(keyRefSchema.safeParse("").success).toBe(false);
  });
});

describe("participant ID (spec 002)", () => {
  it("accepts pk_-prefixed multibase IDs", () => {
    expect(participantIdSchema.parse(PARTICIPANT_ID)).toBe(PARTICIPANT_ID);
  });

  it("rejects missing prefix, wrong prefix, and bare multibase", () => {
    expect(participantIdSchema.safeParse(MULTIHASH).success).toBe(false);
    expect(participantIdSchema.safeParse(`pid_${MULTIHASH}`).success).toBe(false);
    expect(participantIdSchema.safeParse("pk_").success).toBe(false);
    expect(participantIdSchema.safeParse(`pk_f${MULTIHASH.slice(1)}`).success).toBe(false);
  });
});

describe("key events and logs (spec 003)", () => {
  const inception = {
    id: PARTICIPANT_ID,
    seq: "0",
    prior: null,
    kind: "icp",
    keys: [KEY_REF],
    threshold: "1",
    next: MULTIHASH,
    signature: [KEY_REF]
  };

  /** Distinct schema-shaped KeyRefs, so a key list can be widened without repeating a key. */
  const keyRefs = (count: number): string[] =>
    Array.from(
      { length: count },
      (_unused, index) => `z${"1".repeat(index + 1)}${KEY_REF.slice(1)}`
    );

  it("accepts an inception event and a rotation event", () => {
    expect(keyEventSchema.parse(inception)).toBeTruthy();
    expect(
      keyEventSchema.parse({
        ...inception,
        seq: "1",
        prior: MULTIHASH,
        kind: "rot",
        // Two keys, because spec 015 S1 makes a threshold above the key count invalid rather
        // than merely unsatisfiable. This event carried `threshold: "2"` over a single key
        // until that rule landed, and was accepted.
        keys: keyRefs(2),
        threshold: "2",
        signature: [KEY_REF, KEY_REF]
      })
    ).toBeTruthy();
  });

  it("rejects an event that lists the same key twice (spec 003, spec 015 S0)", () => {
    // The rule existed in one line of the reference replay and nowhere in the schema, so an
    // implementation built from the schema alone admitted a state the reference rejects —
    // and a repeated key is exactly what would let one signature be counted twice.
    const repeated = keyEventSchema.safeParse({
      ...inception,
      keys: [KEY_REF, KEY_REF],
      threshold: "2",
      signature: [KEY_REF, KEY_REF]
    });
    expect(repeated.success).toBe(false);
    expect(JSON.stringify(repeated.error)).toMatch(/same key twice/);
    // The same event with distinct keys is accepted, so the rejection is the repetition and
    // nothing else about the shape.
    expect(
      keyEventSchema.safeParse({
        ...inception,
        keys: keyRefs(2),
        threshold: "2",
        signature: [KEY_REF, KEY_REF]
      }).success
    ).toBe(true);
  });

  it("rejects a threshold above the event's own key count (spec 015 S1)", () => {
    const unsatisfiable = keyEventSchema.safeParse({ ...inception, threshold: "2" });
    expect(unsatisfiable.success).toBe(false);
    expect(JSON.stringify(unsatisfiable.error)).toMatch(/above its own key count/);
    // At exactly the key count it is accepted: the rule is `t <= n`, not `t < n`.
    expect(
      keyEventSchema.safeParse({
        ...inception,
        keys: keyRefs(2),
        threshold: "2",
        signature: [KEY_REF, KEY_REF]
      }).success
    ).toBe(true);
  });

  it("is a CLOSED schema: an unknown key is rejected, not stripped (spec 015 S6)", () => {
    // A stripped key means one delivered byte string and two different digests — the exact
    // route 015 S6 closes. `keyEventSchema` was a plain `z.object` until this change, so
    // `{...inception, surprise: 1}` parsed successfully and yielded an object without it.
    expect(keyEventSchema.safeParse({ ...inception, surprise: 1 }).success).toBe(false);
    expect(keyEventLogSchema.safeParse([{ ...inception, surprise: 1 }]).success).toBe(false);
  });

  it("rejects malformed sequence numbers and thresholds (string-number rules, spec 001)", () => {
    expect(keyEventSchema.safeParse({ ...inception, seq: "01" }).success).toBe(false);
    expect(keyEventSchema.safeParse({ ...inception, seq: 0 }).success).toBe(false);
    expect(keyEventSchema.safeParse({ ...inception, seq: "-1" }).success).toBe(false);
    expect(keyEventSchema.safeParse({ ...inception, threshold: "0" }).success).toBe(false);
    expect(keyEventSchema.safeParse({ ...inception, threshold: "02" }).success).toBe(false);
  });

  it("rejects unknown kinds, empty key sets, and missing fields", () => {
    expect(keyEventSchema.safeParse({ ...inception, kind: "del" }).success).toBe(false);
    expect(keyEventSchema.safeParse({ ...inception, keys: [] }).success).toBe(false);
    expect(keyEventSchema.safeParse({ ...inception, signature: [] }).success).toBe(false);
    expect(keyEventSchema.safeParse(omit(inception, "next")).success).toBe(false);
  });

  it("requires prior to be a multihash or explicit null", () => {
    expect(keyEventSchema.parse({ ...inception, seq: "1", prior: MULTIHASH })).toBeTruthy();
    expect(keyEventSchema.safeParse(omit(inception, "prior")).success).toBe(false);
    expect(keyEventSchema.safeParse({ ...inception, prior: "" }).success).toBe(false);
  });

  it("accepts a non-empty log and rejects an empty one", () => {
    expect(keyEventLogSchema.parse([inception])).toHaveLength(1);
    expect(keyEventLogSchema.safeParse([]).success).toBe(false);
    expect(keyEventLogSchema.safeParse([{ ...inception, kind: "del" }]).success).toBe(false);
  });

  // Replaying a log costs Ed25519 verifications and runs on an unauthenticated request
  // body (spec 004 first-write bootstrap), so the array sizes are capped at the schema.
  describe("size bounds", () => {
    const repeat = <T>(value: T, count: number): T[] => Array.from({ length: count }, () => value);
    // Distinct key refs: `keys` must not repeat an entry, and a replay rejects duplicates.
    const distinctKeyRefs = (count: number): string[] =>
      Array.from({ length: count }, (_, index) => `z${"1".repeat(index + 1)}${KEY_REF.slice(1)}`);

    it("caps an event's key set at MAX_KEY_EVENT_KEYS", () => {
      expect(MAX_KEY_EVENT_KEYS).toBe(8);
      expect(
        keyEventSchema.safeParse({ ...inception, keys: distinctKeyRefs(MAX_KEY_EVENT_KEYS) })
          .success
      ).toBe(true);
      expect(
        keyEventSchema.safeParse({ ...inception, keys: distinctKeyRefs(MAX_KEY_EVENT_KEYS + 1) })
          .success
      ).toBe(false);
    });

    it("caps an event's signature set at MAX_KEY_EVENT_SIGNATURES", () => {
      expect(MAX_KEY_EVENT_SIGNATURES).toBe(8);
      // On a key set wide enough to justify them, at `m = t = n`: an event carries EXACTLY
      // its threshold in signatures (015 S1), so the only shape that reaches the signature
      // cap at all is a full-width event whose threshold is the cap.
      const wide = {
        ...inception,
        keys: distinctKeyRefs(MAX_KEY_EVENT_KEYS),
        threshold: String(MAX_KEY_EVENT_SIGNATURES)
      };
      expect(
        keyEventSchema.safeParse({
          ...wide,
          signature: repeat(KEY_REF, MAX_KEY_EVENT_SIGNATURES)
        }).success
      ).toBe(true);
      expect(
        keyEventSchema.safeParse({
          ...wide,
          signature: repeat(KEY_REF, MAX_KEY_EVENT_SIGNATURES + 1)
        }).success
      ).toBe(false);
    });

    it("rejects an event carrying more signatures than it lists keys", () => {
      // Spec 003 states this as a validity rule and derives the per-event cost bound from it,
      // so the schema must reach the same verdict as the replay rules. One key with two
      // signatures is inside every length bound and still invalid.
      const oversigned = keyEventSchema.safeParse({
        ...inception,
        signature: repeat(KEY_REF, 2)
      });
      expect(oversigned.success).toBe(false);
      // Named explicitly, because 015 S1's `m = t` would also refuse this event: the point of
      // keeping 003's ratio rule separate is its sharper diagnosis, and asserting only
      // `success === false` would no longer show that the ratio rule ran at all.
      expect(JSON.stringify(oversigned.error)).toMatch(/more signatures than it lists keys/);
      const twoKeys = { ...inception, keys: distinctKeyRefs(2), threshold: "2" };
      expect(keyEventSchema.safeParse({ ...twoKeys, signature: repeat(KEY_REF, 2) }).success).toBe(
        true
      );
      expect(keyEventSchema.safeParse({ ...twoKeys, signature: repeat(KEY_REF, 3) }).success).toBe(
        false
      );
    });

    // The bound has to be cheaper than the work it guards, or it is not a bound. zod's own
    // `.max()` records the length issue and then parses every element anyway, so a
    // wildly-over-length array cost O(n) to reject — measured at 2.3 s for a 1 MiB body,
    // against a replay budgeted for a fraction of a millisecond.
    //
    // Asserting on element COUNT rather than elapsed time: the payload is built so that every
    // element would fail, and a parser that visited them would have to report on them. One
    // issue means the length check refused the array whole.
    it("rejects an over-length array without parsing its elements", () => {
      const many = Array.from({ length: 50_000 }, () => ({ nonsense: true }));
      const result = keyEventLogSchema.safeParse(many);

      expect(result.success).toBe(false);
      expect(result.error!.issues).toHaveLength(1);
      expect(result.error!.issues[0]!.path).toEqual([]);

      // Same for the arrays inside one event.
      const wideKeys = keyEventSchema.safeParse({ ...inception, keys: many });
      expect(wideKeys.success).toBe(false);
      expect(wideKeys.error!.issues).toHaveLength(1);
      const wideSignatures = keyEventSchema.safeParse({ ...inception, signature: many });
      expect(wideSignatures.success).toBe(false);
      expect(wideSignatures.error!.issues).toHaveLength(1);
    });

    it("caps a log at MAX_KEY_LOG_EVENTS events", () => {
      expect(MAX_KEY_LOG_EVENTS).toBe(128);
      expect(keyEventLogSchema.safeParse(repeat(inception, MAX_KEY_LOG_EVENTS)).success).toBe(true);
      expect(keyEventLogSchema.safeParse(repeat(inception, MAX_KEY_LOG_EVENTS + 1)).success).toBe(
        false
      );
    });
  });
});

/**
 * Reference vectors for the size limits normatively stated in spec/003 and spec/009: each
 * bound accepted at its maximum and rejected one past it, so an independent implementation can
 * check its own limits against the same cases.
 */
describe("size-limit conformance vectors (specs 003, 009)", () => {
  const repeat = <T>(value: T, count: number): T[] => Array.from({ length: count }, () => value);
  const distinctKeyRefs = (count: number): string[] =>
    Array.from({ length: count }, (_, index) => `z${"1".repeat(index + 1)}${KEY_REF.slice(1)}`);

  const keyEvent = {
    id: PARTICIPANT_ID,
    seq: "0",
    prior: null,
    kind: "icp",
    keys: [KEY_REF],
    threshold: "1",
    next: MULTIHASH,
    signature: [KEY_REF]
  };
  const grant = {
    subjectId: PARTICIPANT_ID,
    issuerId: PARTICIPANT_ID,
    audienceId: PARTICIPANT_ID,
    abilities: ["directory"],
    caveats: {},
    proof: null,
    issuedAt: DATETIME,
    signature: [KEY_REF]
  };
  const revocation = {
    revokes: MULTIHASH,
    issuerId: PARTICIPANT_ID,
    revokedAt: DATETIME,
    signature: [KEY_REF]
  };

  const cases: [
    string,
    number,
    (count: number) => unknown,
    { safeParse: (v: unknown) => { success: boolean } }
  ][] = [
    [
      "MAX_KEY_EVENT_KEYS",
      MAX_KEY_EVENT_KEYS,
      (n) => ({ ...keyEvent, keys: distinctKeyRefs(n) }),
      keyEventSchema
    ],
    [
      "MAX_KEY_EVENT_SIGNATURES",
      MAX_KEY_EVENT_SIGNATURES,
      // At full key width: an event may not carry more signatures than it lists keys, so the
      // signature cap is only reachable on a key set wide enough to justify it. Built on a
      // one-key base this vector asserted 8 signatures were VALID, which spec 003 calls
      // non-conforming — an implementer following it would have built the wrong validator.
      // `m = t = n`, for the same reason: 015 S1 makes the signature count the threshold, so
      // an event only ever reaches the cap at full key width under a threshold that high.
      (n) => ({
        ...keyEvent,
        keys: distinctKeyRefs(MAX_KEY_EVENT_KEYS),
        threshold: String(MAX_KEY_EVENT_SIGNATURES),
        signature: repeat(KEY_REF, n)
      }),
      keyEventSchema
    ],
    ["MAX_KEY_LOG_EVENTS", MAX_KEY_LOG_EVENTS, (n) => repeat(keyEvent, n), keyEventLogSchema],
    [
      "MAX_GRANT_ABILITIES",
      MAX_GRANT_ABILITIES,
      (n) => ({ ...grant, abilities: repeat("directory", n) }),
      grantSchema
    ],
    [
      "MAX_RECORD_SIGNATURES (grant)",
      MAX_RECORD_SIGNATURES,
      (n) => ({ ...grant, signature: repeat(KEY_REF, n) }),
      grantSchema
    ],
    [
      "MAX_RECORD_SIGNATURES (revocation)",
      MAX_RECORD_SIGNATURES,
      (n) => ({ ...revocation, signature: repeat(KEY_REF, n) }),
      revocationSchema
    ]
  ];

  it.each(cases)(
    "accepts %s at the maximum and rejects one past it",
    (_name, max, build, schema) => {
      expect(schema.safeParse(build(max)).success).toBe(true);
      expect(schema.safeParse(build(max + 1)).success).toBe(false);
    }
  );

  it("rejects a key event with more signatures than keys, as spec 003 requires", () => {
    // The rule the cost bound is derived from. It is a VALIDITY rule, so it belongs in the
    // vectors an independent implementer checks against, not only in this repo's replay code.
    expect(keyEventSchema.safeParse({ ...keyEvent, signature: repeat(KEY_REF, 2) }).success).toBe(
      false
    );
    expect(
      keyEventSchema.safeParse({
        ...keyEvent,
        keys: distinctKeyRefs(2),
        threshold: "2",
        signature: repeat(KEY_REF, 2)
      }).success
    ).toBe(true);
  });

  /**
   * Reads the NORMATIVE TABLES out of the spec files and compares them to the exported
   * constants.
   *
   * The previous version of this test compared the constants to hand-written literals in this
   * file, which is not what its name promised: when `MAX_GRANT_CHAIN_LINKS` moved from 8 to 4,
   * the constant, the literal here and the spec PROSE were all updated together while the
   * spec's normative TABLE was left saying 8 — and this test passed through exactly the drift
   * it is named for. An independent implementer building from that table would have admitted
   * chains this code rejects. Parsing the spec is the only version of this test that can fail
   * for the reason it exists.
   */
  it("pins the normative values, so a spec edit and a code edit cannot drift apart", () => {
    const specDir = new URL("../spec/", import.meta.url);
    const boundsIn = (file: string): Record<string, number> => {
      const text = readFileSync(new URL(file, specDir), "utf8");
      const bounds: Record<string, number> = {};
      // Rows of the form: | `NAME` | 123 | ... |
      for (const [, name, value] of text.matchAll(/^\|\s*`(MAX_[A-Z_]+)`\s*\|\s*(\d+)\s*\|/gm)) {
        bounds[name!] = Number(value);
      }
      return bounds;
    };

    const declared = { ...boundsIn("003-key-history.md"), ...boundsIn("009-grant.md") };

    // Guard against the tables being renamed or reformatted into invisibility: a parse that
    // silently finds nothing would make every assertion below vacuously true.
    //
    // NOTE: adding a new `MAX_*` row to either spec table fails HERE until the name is added
    // below and to the comparison. That is a deliberate false positive — a new normative bound
    // should not be able to appear in a spec without a constant to match it — and it fails
    // loudly rather than silently.
    expect(Object.keys(declared).sort()).toEqual([
      "MAX_GRANT_ABILITIES",
      "MAX_GRANT_CHAIN_LINKS",
      "MAX_KEY_EVENT_KEYS",
      "MAX_KEY_EVENT_SIGNATURES",
      "MAX_KEY_LOG_EVENTS",
      "MAX_RECORD_SIGNATURES"
    ]);

    expect(declared).toEqual({
      MAX_KEY_EVENT_KEYS,
      MAX_KEY_EVENT_SIGNATURES,
      MAX_KEY_LOG_EVENTS,
      MAX_GRANT_CHAIN_LINKS,
      MAX_GRANT_ABILITIES,
      MAX_RECORD_SIGNATURES
    });
  });
});

describe("participant profile", () => {
  const profile = {
    id: PARTICIPANT_ID,
    type: "person",
    displayName: "Ada",
    updatedAt: DATETIME,
    signature: KEY_REF
  };

  it("accepts a minimal profile and defaults list fields", () => {
    const parsed = participantProfileSchema.parse(profile);
    expect(parsed.capabilities).toEqual([]);
    expect(parsed.verifiedDomains).toEqual([]);
  });

  it("rejects unknown types, empty names, and bad timestamps", () => {
    expect(participantProfileSchema.safeParse({ ...profile, type: "robot" }).success).toBe(false);
    expect(participantProfileSchema.safeParse({ ...profile, displayName: "" }).success).toBe(false);
    expect(participantProfileSchema.safeParse({ ...profile, updatedAt: "yesterday" }).success).toBe(
      false
    );
    expect(participantProfileSchema.safeParse(omit(profile, "signature")).success).toBe(false);
  });

  it("accepts only the UTC-Z subset of RFC 3339 (specs 017, 018)", () => {
    // Two offset spellings of one instant are two byte-forms of one digested record, so the
    // offset forms are rejected rather than normalized.
    for (const accepted of ["2026-06-12T00:00:00Z", "2026-06-12T00:00:00.000Z"]) {
      expect(participantProfileSchema.safeParse({ ...profile, updatedAt: accepted }).success).toBe(
        true
      );
    }
    for (const rejected of [
      "2026-06-12T08:00:00+08:00",
      "2026-06-12T00:00:00.000+00:00",
      "2026-06-12T00:00:00"
    ]) {
      expect(participantProfileSchema.safeParse({ ...profile, updatedAt: rejected }).success).toBe(
        false
      );
    }
  });

  it("defaults absent list fields, which is a second byte-form (spec 017)", () => {
    // The delivered bytes carry no arrays; the parsed object carries two. A signature over the
    // delivered form does not verify over the parsed form — 017 records this as an open question.
    const delivered = omit(profile, "capabilities");
    const parsed = participantProfileSchema.parse(delivered);
    expect(Object.keys(delivered)).not.toContain("capabilities");
    expect(parsed.capabilities).toEqual([]);
  });
});

describe("participant node", () => {
  const node = {
    id: "node-1",
    participantId: PARTICIPANT_ID,
    label: "Primary",
    publicKey: KEY_REF,
    transports: ["https", "webrtc"],
    updatedAt: DATETIME,
    signature: KEY_REF
  };

  it("accepts a valid node", () => {
    expect(participantNodeSchema.parse(node)).toBeTruthy();
  });

  it("rejects unknown transports and invalid endpoints", () => {
    expect(participantNodeSchema.safeParse({ ...node, transports: ["smtp"] }).success).toBe(false);
    expect(participantNodeSchema.safeParse({ ...node, endpoint: "not-a-url" }).success).toBe(false);
  });

  it("rejects the websocket transport, dropped by spec 017 (spec 013 rejects WebSocket)", () => {
    expect(participantNodeSchema.safeParse({ ...node, transports: ["websocket"] }).success).toBe(
      false
    );
    expect(
      participantNodeSchema.safeParse({ ...node, transports: ["https", "websocket"] }).success
    ).toBe(false);
  });

  it("pins the advertised transport enum, so a spec edit and a code edit cannot drift apart", () => {
    expect(nodeTransportSchema.options).toEqual(["https", "webrtc"]);
  });

  it("is a CLOSED schema: an unknown key is rejected, not stripped (spec 001)", () => {
    expect(participantNodeSchema.safeParse({ ...node, extra: 1 }).success).toBe(false);
  });
});

describe("signed statements", () => {
  it("accepts and rejects relationships", () => {
    const relationship = {
      id: "rel-1",
      subjectId: PARTICIPANT_ID,
      predicate: "memberOf",
      objectId: PARTICIPANT_ID,
      issuedBy: PARTICIPANT_ID,
      issuedAt: DATETIME,
      signature: KEY_REF
    };
    expect(relationshipSchema.parse(relationship)).toBeTruthy();
    expect(relationshipSchema.safeParse({ ...relationship, predicate: "" }).success).toBe(false);
    expect(relationshipSchema.safeParse({ ...relationship, subjectId: "alice" }).success).toBe(
      false
    );
  });

  it("accepts and rejects claims", () => {
    const claim = {
      id: "claim-1",
      subjectId: PARTICIPANT_ID,
      claimType: "domain",
      value: "example.com",
      issuedBy: PARTICIPANT_ID,
      issuedAt: DATETIME,
      signature: KEY_REF
    };
    expect(claimSchema.parse(claim)).toBeTruthy();
    expect(claimSchema.safeParse({ ...claim, issuedAt: "not-a-date" }).success).toBe(false);
  });

  it("accepts and rejects revocations (spec 008)", () => {
    const revocation = {
      revokes: MULTIHASH,
      issuerId: PARTICIPANT_ID,
      revokedAt: DATETIME,
      signature: [KEY_REF]
    };
    expect(revocationSchema.parse(revocation)).toBeTruthy();
    expect(revocationSchema.parse({ ...revocation, reason: "device lost" })).toBeTruthy();
    expect(revocationSchema.safeParse({ ...revocation, revokes: "not-a-digest" }).success).toBe(
      false
    );
    expect(revocationSchema.safeParse({ ...revocation, signature: [] }).success).toBe(false);
    expect(revocationSchema.safeParse({ ...revocation, signature: KEY_REF }).success).toBe(false);
    expect(revocationSchema.safeParse(omit(revocation, "revokedAt")).success).toBe(false);
    // CLOSED (spec 015 S6.3): a Revocation is digest-addressed by what it names and by its
    // own digest, so an unknown key must be rejected rather than stripped — a stripped key
    // gives one delivered byte string two different digests. This was a plain `z.object`
    // until 015's enforcement change, and `{...revocation, surprise: 1}` parsed cleanly.
    expect(revocationSchema.safeParse({ ...revocation, surprise: 1 }).success).toBe(false);
  });

  it("accepts and rejects abilities and grants (spec 009)", () => {
    expect(abilitySchema.parse("directory/curate")).toBe("directory/curate");
    expect(abilitySchema.parse("msg")).toBe("msg");
    expect(abilitySchema.safeParse("Directory/Curate").success).toBe(false);
    expect(abilitySchema.safeParse("/directory").success).toBe(false);
    expect(abilitySchema.safeParse("directory/").success).toBe(false);
    expect(abilitySchema.safeParse("").success).toBe(false);

    const grant = {
      subjectId: PARTICIPANT_ID,
      issuerId: PARTICIPANT_ID,
      audienceId: PARTICIPANT_ID,
      abilities: ["directory/curate"],
      caveats: {},
      proof: null,
      issuedAt: DATETIME,
      signature: [KEY_REF]
    };
    expect(grantSchema.parse(grant)).toBeTruthy();
    expect(grantSchema.parse({ ...grant, proof: MULTIHASH, expiresAt: DATETIME })).toBeTruthy();
    expect(grantSchema.safeParse({ ...grant, abilities: [] }).success).toBe(false);
    expect(grantSchema.safeParse({ ...grant, abilities: ["Not An Ability"] }).success).toBe(false);
    expect(grantSchema.safeParse(omit(grant, "proof")).success).toBe(false);
    expect(grantSchema.safeParse(omit(grant, "caveats")).success).toBe(false);
    expect(grantSchema.safeParse({ ...grant, audienceId: "alice" }).success).toBe(false);
    // CLOSED (spec 015 S6.3). A Grant is digest-addressed twice over — a child names its
    // parent by `proof`, and 008 keys revocation by the same digest — so a stripped unknown
    // key is a second digest for one delivery, which is the malleability that defeated
    // revocation-by-digest. `caveats` is `z.record`, so extension still has a home.
    expect(grantSchema.safeParse({ ...grant, surprise: 1 }).success).toBe(false);
    expect(grantSchema.safeParse({ ...grant, caveats: { anything: 1 } }).success).toBe(true);
  });

  it("accepts and rejects message envelopes (spec 010)", () => {
    const envelope = {
      id: "msg-1",
      from: PARTICIPANT_ID,
      to: PARTICIPANT_ID,
      createdAt: DATETIME,
      type: "text",
      payload: { body: "hello" },
      signature: KEY_REF
    };
    expect(messageEnvelopeSchema.parse(envelope)).toBeTruthy();
    expect(messageEnvelopeSchema.safeParse({ ...envelope, from: "not-an-id" }).success).toBe(false);
    expect(messageEnvelopeSchema.safeParse({ ...envelope, to: "alice" }).success).toBe(false);
    expect(messageEnvelopeSchema.safeParse({ ...envelope, type: "" }).success).toBe(false);
    expect(messageEnvelopeSchema.safeParse({ ...envelope, createdAt: "yesterday" }).success).toBe(
      false
    );
    expect(messageEnvelopeSchema.safeParse(omit(envelope, "signature")).success).toBe(false);
  });

  it("accepts an envelope with an optional conversationId and rejects a malformed one (spec 012)", () => {
    const envelope = {
      id: "msg-1",
      from: PARTICIPANT_ID,
      to: PARTICIPANT_ID,
      createdAt: DATETIME,
      type: "text",
      payload: { body: "hello" },
      signature: KEY_REF
    };
    // Bare (no conversationId) still valid — 010's machine lane keeps working unchanged.
    expect(messageEnvelopeSchema.parse(envelope).conversationId).toBeUndefined();
    // Optional field, but when present must be a multihash.
    const associated = { ...envelope, conversationId: MULTIHASH };
    expect(messageEnvelopeSchema.parse(associated).conversationId).toBe(MULTIHASH);
    expect(
      messageEnvelopeSchema.safeParse({ ...envelope, conversationId: "not-a-digest" }).success
    ).toBe(false);
  });
});

describe("Conversation record (spec 012)", () => {
  const OTHER_ID = `pk_${KEY_REF}`;

  function conversation(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    // Membership must be sorted ascending — the exact order depends on the two ids.
    const participants = [PARTICIPANT_ID, OTHER_ID].sort();
    return {
      creator: PARTICIPANT_ID,
      participants,
      createdAt: DATETIME,
      signature: [KEY_REF],
      ...overrides
    };
  }

  it("accepts a minimal conversation and a titled one", () => {
    expect(conversationSchema.parse(conversation())).toBeTruthy();
    expect(conversationSchema.parse(conversation({ title: "A thread" }))).toBeTruthy();
  });

  it("rejects unknown keys (strict schema — spec 012 digest identity depends on it)", () => {
    const record = conversation({ extraneous: "field" });
    expect(conversationSchema.safeParse(record).success).toBe(false);
  });

  it("rejects a title that is empty or too long", () => {
    expect(conversationSchema.safeParse(conversation({ title: "" })).success).toBe(false);
    expect(conversationSchema.safeParse(conversation({ title: "x".repeat(257) })).success).toBe(
      false
    );
  });

  it("rejects a participants array that omits the creator", () => {
    // A single-member conversation that does not include the creator — also fails min(2).
    expect(
      conversationSchema.safeParse(conversation({ participants: [OTHER_ID, OTHER_ID] })).success
    ).toBe(false);
    // A well-sized set that simply does not contain the creator.
    const SECOND = `pk_${MULTIHASH}Q`; // synthetic, not necessarily well-formed as an id
    void SECOND;
    // Two distinct participants, neither is the creator (uses a different pk id).
    const alt = `pk_${MULTIHASH.slice(0, -1)}p`;
    expect(
      conversationSchema.safeParse(
        conversation({ creator: alt, participants: [OTHER_ID, PARTICIPANT_ID].sort() })
      ).success
    ).toBe(false);
  });

  it("rejects duplicate participants", () => {
    expect(
      conversationSchema.safeParse(conversation({ participants: [PARTICIPANT_ID, PARTICIPANT_ID] }))
        .success
    ).toBe(false);
  });

  it("rejects an unsorted participants array (canonical ordering — spec 012)", () => {
    const sorted = [PARTICIPANT_ID, OTHER_ID].sort();
    const reversed = [...sorted].reverse();
    expect(conversationSchema.safeParse(conversation({ participants: reversed })).success).toBe(
      false
    );
  });

  it("rejects too-small (<2) and too-large (>256) memberships", () => {
    expect(
      conversationSchema.safeParse(conversation({ participants: [PARTICIPANT_ID] })).success
    ).toBe(false);
    // 257 unique-looking ids — synthesize just enough to be well-formed & unique.
    const big = Array.from(
      { length: 257 },
      (_, i) => `pk_${MULTIHASH.slice(0, -3)}${i.toString().padStart(3, "1")}`
    ).sort();
    // Force creator to be one of them so the membership rule is not the failure cause.
    const first = big[0]!;
    expect(
      conversationSchema.safeParse(conversation({ creator: first, participants: big })).success
    ).toBe(false);
  });

  it("rejects a bad creator id or a non-array participants", () => {
    expect(conversationSchema.safeParse(conversation({ creator: "alice" })).success).toBe(false);
    expect(
      conversationSchema.safeParse(conversation({ participants: PARTICIPANT_ID })).success
    ).toBe(false);
  });

  it("rejects an empty signature array (threshold-signed record — spec 012)", () => {
    expect(conversationSchema.safeParse(conversation({ signature: [] })).success).toBe(false);
    // A bare Signature string (single-signer shape) is also invalid — must be an array.
    expect(conversationSchema.safeParse(conversation({ signature: KEY_REF })).success).toBe(false);
  });

  it("rejects a bad createdAt", () => {
    expect(conversationSchema.safeParse(conversation({ createdAt: "yesterday" })).success).toBe(
      false
    );
  });
});

describe("conversation conformance fixture (spec 012)", () => {
  // Committed bytes live alongside this test. A conforming implementation reading these
  // bytes must arrive at the pinned conversationId — the fixture is the shared oracle.
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/signed-conversation.json", import.meta.url), "utf8")
  ) as { conversation: unknown; conversationId: string };

  it("schema-validates the committed conversation record", () => {
    expect(conversationSchema.parse(fixture.conversation)).toBeTruthy();
  });

  it("commits a well-formed multihash conversationId", () => {
    expect(fixture.conversationId).toMatch(/^zQm/);
  });
});

describe("reserved envelope-type prefix (spec 012)", () => {
  it("names the reserved prefix and the conversation type", () => {
    expect(PN_RESERVED_PREFIX).toBe("pn/");
    expect(PN_TYPE_CONVERSATION).toBe("pn/conversation");
    expect(PN_TYPE_CONVERSATION.startsWith(PN_RESERVED_PREFIX)).toBe(true);
    expect(KNOWN_RESERVED_TYPES.has(PN_TYPE_CONVERSATION)).toBe(true);
    expect(KNOWN_RESERVED_TYPES.has("pn/unknown")).toBe(false);
  });
});

describe("strict JSON parsing (spec 012 — no duplicate keys)", () => {
  it("accepts a well-formed JSON payload with unique keys", () => {
    expect(parseJsonStrict('{"a":1,"b":2}')).toEqual({ a: 1, b: 2 });
    expect(parseJsonStrict('{"outer":{"inner":true}}')).toEqual({ outer: { inner: true } });
    expect(parseJsonStrict('[{"a":1},{"a":2}]')).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("rejects an object with a duplicated key at the top level", () => {
    expect(() => parseJsonStrict('{"a":1,"a":2}')).toThrow(/duplicate key/);
  });

  it("rejects a duplicated key nested inside another object", () => {
    expect(() => parseJsonStrict('{"o":{"x":1,"x":2}}')).toThrow(/duplicate key/);
  });

  it("rejects a duplicated key inside an array element", () => {
    expect(() => parseJsonStrict('[{"a":1,"a":2}]')).toThrow(/duplicate key/);
  });

  it("does not confuse a value string that looks like a key", () => {
    // The colon here is inside a string literal, not a key/value separator; the parser
    // must not attribute "b:c" to the enclosing object as a key repeat.
    expect(parseJsonStrict('{"a":"b:c","d":true}')).toEqual({ a: "b:c", d: true });
    expect(parseJsonStrict('{"a":"one","b":"one"}')).toEqual({ a: "one", b: "one" });
  });

  it("propagates JSON parse errors on malformed input", () => {
    expect(() => parseJsonStrict("not-json")).toThrow();
    expect(() => parseJsonStrict('{"a":')).toThrow();
  });
});

describe("principals and the aud caveat (spec 011)", () => {
  // A second bare KeyRef, distinct from KEY_REF, standing in for a disposable session key.
  const SESSION_KEY = "z6MkSessionKey1abcdefgh";
  // A second participant, distinct from PARTICIPANT_ID, standing in for a verifying service.
  const SERVICE_ID = `pk_${KEY_REF}`;

  const participantAudienceGrant = {
    subjectId: PARTICIPANT_ID,
    issuerId: PARTICIPANT_ID,
    audienceId: PARTICIPANT_ID,
    abilities: ["directory/curate"],
    caveats: {},
    proof: null,
    issuedAt: DATETIME,
    signature: [KEY_REF]
  };

  it("accepts a classic participant-audience grant with no caveats (regression, unchanged shape)", () => {
    expect(grantSchema.parse(participantAudienceGrant)).toBeTruthy();
  });

  it("accepts a participant-audience grant carrying a well-formed aud caveat", () => {
    expect(
      grantSchema.parse({ ...participantAudienceGrant, caveats: { aud: SERVICE_ID } })
    ).toBeTruthy();
    expect(
      grantSchema.parse({
        ...participantAudienceGrant,
        caveats: { aud: [SERVICE_ID, PARTICIPANT_ID] }
      })
    ).toBeTruthy();
  });

  it("accepts a key-audience grant with expiresAt and caveats.aud as a single ParticipantId", () => {
    expect(
      grantSchema.parse({
        ...participantAudienceGrant,
        audienceId: SESSION_KEY,
        expiresAt: DATETIME,
        caveats: { aud: SERVICE_ID }
      })
    ).toBeTruthy();
  });

  it("accepts a key-audience grant with expiresAt and caveats.aud as a non-empty array", () => {
    expect(
      grantSchema.parse({
        ...participantAudienceGrant,
        audienceId: SESSION_KEY,
        expiresAt: DATETIME,
        caveats: { aud: [SERVICE_ID, PARTICIPANT_ID] }
      })
    ).toBeTruthy();
  });

  it("accepts a KeyRef issuerId with a participant audience (the multi-hop tail link)", () => {
    expect(
      grantSchema.parse({
        ...participantAudienceGrant,
        issuerId: SESSION_KEY
      })
    ).toBeTruthy();
  });

  it("rejects a key-audience grant missing expiresAt, missing caveats.aud, or missing both", () => {
    const keyAudience = { ...participantAudienceGrant, audienceId: SESSION_KEY };
    // missing expiresAt, caveats.aud present
    expect(grantSchema.safeParse({ ...keyAudience, caveats: { aud: SERVICE_ID } }).success).toBe(
      false
    );
    // expiresAt present, missing caveats.aud
    expect(
      grantSchema.safeParse({ ...keyAudience, expiresAt: DATETIME, caveats: {} }).success
    ).toBe(false);
    // missing both
    expect(grantSchema.safeParse(keyAudience).success).toBe(false);
  });

  it("rejects malformed caveats.aud, on a key-audience or a participant-audience grant", () => {
    const keyAudience = {
      ...participantAudienceGrant,
      audienceId: SESSION_KEY,
      expiresAt: DATETIME
    };
    expect(grantSchema.safeParse({ ...keyAudience, caveats: { aud: [] } }).success).toBe(false);
    expect(
      grantSchema.safeParse({ ...keyAudience, caveats: { aud: ["not-a-participant"] } }).success
    ).toBe(false);
    // a bare KeyRef as an aud array entry
    expect(grantSchema.safeParse({ ...keyAudience, caveats: { aud: [SESSION_KEY] } }).success).toBe(
      false
    );
    // a bare KeyRef as the whole aud value (not an array, not a ParticipantId)
    expect(grantSchema.safeParse({ ...keyAudience, caveats: { aud: SESSION_KEY } }).success).toBe(
      false
    );
    expect(grantSchema.safeParse({ ...keyAudience, caveats: { aud: 42 } }).success).toBe(false);
    // a present-but-malformed aud is rejected on a participant-audience grant too
    expect(
      grantSchema.safeParse({ ...participantAudienceGrant, caveats: { aud: [] } }).success
    ).toBe(false);
  });

  it("rejects principals matching neither the ParticipantId nor the KeyRef shape, for issuerId and audienceId", () => {
    const malformedPrincipals = [
      "pk_", // pk_-prefixed with no key body
      "pk_z0invalid", // pk_-prefixed, but the body contains an excluded base58 char ("0")
      "z", // bare KeyRef prefix with no body
      "z0OIl", // bare KeyRef prefix, body contains excluded base58 chars (0, O, I, l)
      "" // empty string
    ];
    for (const bad of malformedPrincipals) {
      expect(grantSchema.safeParse({ ...participantAudienceGrant, issuerId: bad }).success).toBe(
        false
      );
      expect(grantSchema.safeParse({ ...participantAudienceGrant, audienceId: bad }).success).toBe(
        false
      );
    }
  });

  it("rejects a subjectId that is a KeyRef (the subject stays a participant)", () => {
    expect(
      grantSchema.safeParse({ ...participantAudienceGrant, subjectId: SESSION_KEY }).success
    ).toBe(false);
  });
});
