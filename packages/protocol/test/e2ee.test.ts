/**
 * Spec 014 — the E2EE lane's protocol surface: the Conversation record's `lane`/`groupNonce`
 * fields, the ConversationUpdate evidence record, the `e2ee` ability predicate and the grant
 * amendments it drives, and the two MLS-carrying reserved types.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  ABILITY_CONVERSATION_SELF_REMOVE,
  ABILITY_E2EE_LEAF,
  abilitySchema,
  conversationPayloadSchema,
  conversationSchema,
  conversationUpdatePayloadSchema,
  conversationUpdateSchema,
  decodeBase64Url,
  grantSchema,
  groupNonceSchema,
  isE2eeAbility,
  PN_RESERVED_PREFIX,
  PN_TYPE_CONVERSATION_UPDATE,
  PN_TYPE_MLS,
  PN_TYPE_WELCOME,
  KNOWN_RESERVED_TYPES,
  mlsPayloadSchema,
  welcomePayloadSchema
} from "../src/index.js";

/**
 * A deliberately independent, dependency-free re-derivation of a record's digest id: sha2-256
 * over the JCS (spec 001) of the record, multihash-tagged (0x12 0x20) and base58btc-multibase
 * encoded (spec 003/005). `@kinnet/crypto` owns the real implementation; this ~20-line second
 * one is what lets the committed fixtures be checked **from bytes alone** inside a package that
 * depends on nothing but zod. Every record it is applied to is ASCII-only, where sorted-key
 * `JSON.stringify` is exactly the JCS form.
 */
function canonicalize(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, propertyValue]) => propertyValue !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, propertyValue]) => `${JSON.stringify(key)}:${canonicalize(propertyValue)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btc(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) {
    value = value * 256n + BigInt(byte);
  }
  let out = "";
  while (value > 0n) {
    out = BASE58BTC_ALPHABET[Number(value % 58n)]! + out;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }
    out = `1${out}`;
  }
  return out;
}

function digestId(record: unknown): string {
  const hash = createHash("sha256")
    .update(Buffer.from(canonicalize(record), "utf8"))
    .digest();
  return `z${base58btc(Uint8Array.from([0x12, 0x20, ...hash]))}`;
}

type ConversationFixture = {
  conversation: Record<string, unknown>;
  conversationId: string;
};

function loadFixture<T>(name: string): T {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8")) as T;
}

const machineLaneFixture = loadFixture<ConversationFixture>("signed-conversation.json");
const e2eeFixture = loadFixture<ConversationFixture>("signed-conversation-e2ee.json");

const KEY_REF = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const OTHER_KEY_REF = "z6MktojHN9D8obak7C9wjpTzCRrdE5zC6cxt5ANUFnQskgbs";
const MULTIHASH = "zQmYwAPJzv5CZsnAzt8auVZRnHEKzKgUEdy3W35nUSpS6kq";
const PARTICIPANT_ID = `pk_${MULTIHASH}`;
const OTHER_ID = `pk_${KEY_REF}`;
const DATETIME = "2026-08-01T00:00:00.000Z";
// 44 base58btc characters — the encoding of 32 random bytes.
const GROUP_NONCE = "zCs8KY3PiWrCMAytMsBRQo8EdGbticVtdvufLnb2UhXh";

describe("the digest re-derivation used by these tests", () => {
  it("reproduces the pinned id of the pre-014 conversation fixture", () => {
    // Sanity: if this second implementation of the digest rule were wrong, every fixture
    // assertion below would be vacuous.
    expect(digestId(machineLaneFixture.conversation)).toBe(machineLaneFixture.conversationId);
  });
});

describe("Conversation lane and groupNonce (spec 014)", () => {
  function conversation(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      creator: PARTICIPANT_ID,
      participants: [PARTICIPANT_ID, OTHER_ID].sort(),
      createdAt: DATETIME,
      signature: [KEY_REF],
      ...overrides
    };
  }

  it("accepts an e2ee record carrying a groupNonce", () => {
    const parsed = conversationSchema.parse(
      conversation({ lane: "e2ee", groupNonce: GROUP_NONCE })
    );
    expect(parsed.lane).toBe("e2ee");
    expect(parsed.groupNonce).toBe(GROUP_NONCE);
  });

  it("rejects an e2ee record with no groupNonce", () => {
    expect(conversationSchema.safeParse(conversation({ lane: "e2ee" })).success).toBe(false);
  });

  it("rejects a machine-lane record carrying a groupNonce", () => {
    // A stray nonce would be a second byte-form of the same logical conversation, which is
    // exactly what 012's digest identity cannot afford.
    expect(conversationSchema.safeParse(conversation({ groupNonce: GROUP_NONCE })).success).toBe(
      false
    );
  });

  it('rejects any lane value other than an omitted field or "e2ee"', () => {
    // The machine lane is the ABSENCE of the field — never "machine", never null.
    expect(conversationSchema.safeParse(conversation({ lane: "machine" })).success).toBe(false);
    expect(
      conversationSchema.safeParse(conversation({ lane: null, groupNonce: GROUP_NONCE })).success
    ).toBe(false);
    expect(conversationSchema.safeParse(conversation({ lane: "E2EE" })).success).toBe(false);
    expect(conversationSchema.safeParse(conversation({ lane: "" })).success).toBe(false);
  });

  it("rejects a malformed groupNonce", () => {
    const bad = [
      "f6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2do", // wrong multibase prefix
      `z${"0".repeat(43)}`, // "0" is not in the base58btc alphabet
      `z${"1".repeat(31)}`, // shorter than any 32-byte encoding
      `z${"z".repeat(45)}`, // longer than any 32-byte encoding
      "z",
      ""
    ];
    for (const nonce of bad) {
      expect(groupNonceSchema.safeParse(nonce).success).toBe(false);
      expect(
        conversationSchema.safeParse(conversation({ lane: "e2ee", groupNonce: nonce })).success
      ).toBe(false);
    }
  });

  it("accepts a canonical nonce at both ends of the textual window", () => {
    // All-zero bytes encode as 32 "1"s — the short end of the window, and canonical.
    expect(groupNonceSchema.safeParse(`z${"1".repeat(32)}`).success).toBe(true);
    // 44 characters is the long end, and GROUP_NONCE is a real 32-byte value at it.
    expect(GROUP_NONCE.length).toBe(44);
    expect(groupNonceSchema.safeParse(GROUP_NONCE).success).toBe(true);
  });

  it("rejects textually-valid nonces that do not decode to 32 bytes", () => {
    // THIS TEST USED TO ASSERT THE OPPOSITE. `z` + 44 "z"s matches the alphabet and the length
    // window and was pinned as accepted; it decodes to 33 bytes. The window is a necessary
    // condition on a 32-byte encoding, never a sufficient one, and pinning it as sufficient is
    // how the wrong behaviour survived a test suite. Both directions are checked here because
    // the window brackets the value, so a decoded length can miss on either side.
    expect(groupNonceSchema.safeParse(`z${"z".repeat(44)}`).success).toBe(false); // 33 bytes
    expect(groupNonceSchema.safeParse(`z${"2".repeat(32)}`).success).toBe(false); // 23 bytes
  });

  it("rejects a canonical nonce perturbed by one trailing character", () => {
    // The boundary, stated as a pair: one accepted value, and the same value one character
    // shorter — 43 characters, still inside the textual window, and 31 bytes. Nothing but the
    // decoded-length check rejects it.
    //
    // Base58btc admits no SECOND textual form of a given byte string (the leading-"1" rule
    // makes the mapping injective both ways), so the non-canonicity that bit here is length;
    // the pad-bit half of the problem belongs to base64url and is pinned on the `pn/mls`
    // payloads below.
    expect(groupNonceSchema.safeParse(GROUP_NONCE).success).toBe(true);
    const shortened = GROUP_NONCE.slice(0, -1);
    expect(shortened.length).toBe(43);
    expect(groupNonceSchema.safeParse(shortened).success).toBe(false);
  });

  it("refuses a non-canonical nonce inside a conversation record", () => {
    // The schema-level rejection is only worth what the record-level one is: a nonce is what
    // makes an E2EE conversation's bytes unique, so a record carrying a second form of one is
    // a second record.
    expect(
      conversationSchema.safeParse(conversation({ lane: "e2ee", groupNonce: `z${"z".repeat(44)}` }))
        .success
    ).toBe(false);
  });

  it("leaves every pre-014 record valid, byte-identical, and pinned to the same id", () => {
    // The backward-compatibility claim, stated as bytes: the committed pre-014 fixture still
    // schema-validates, the validated value carries neither field (so nothing was injected),
    // and the digest of those bytes is still the pinned conversationId.
    const parsed = conversationSchema.parse(machineLaneFixture.conversation);
    expect(parsed.lane).toBeUndefined();
    expect(parsed.groupNonce).toBeUndefined();
    expect(parsed).toEqual(machineLaneFixture.conversation);
    expect(digestId(parsed)).toBe(machineLaneFixture.conversationId);
    expect(machineLaneFixture.conversationId).toBe(
      "zQmW3ubn3FGrQ9uysAEWzZZqLmWcpNgknm77L5QwqikBF1M"
    );
  });
});

describe("E2EE conversation conformance fixture (spec 014)", () => {
  // Committed bytes, checkable by a second implementation with nothing but the file.
  it("schema-validates the committed e2ee record", () => {
    const parsed = conversationSchema.parse(e2eeFixture.conversation);
    expect(parsed.lane).toBe("e2ee");
    expect(parsed.groupNonce).toBeDefined();
  });

  it("re-derives conversationId from the committed bytes (bytes -> id pin)", () => {
    expect(digestId(e2eeFixture.conversation)).toBe(e2eeFixture.conversationId);
    expect(e2eeFixture.conversationId).toMatch(/^zQm/);
  });

  it("cannot be downgraded: dropping the lane changes the id", () => {
    const { lane, ...downgraded } = e2eeFixture.conversation as { lane?: string };
    expect(lane).toBe("e2ee");
    expect(digestId(downgraded)).not.toBe(e2eeFixture.conversationId);
    // …and the downgraded bytes are not even a valid record, since the nonce is still there.
    expect(conversationSchema.safeParse(downgraded).success).toBe(false);
  });

  it("changes the id when the groupNonce changes (byte-uniqueness of the group_id)", () => {
    const renonced = { ...e2eeFixture.conversation, groupNonce: GROUP_NONCE.replace(/.$/, "j") };
    expect(digestId(renonced)).not.toBe(e2eeFixture.conversationId);
  });
});

describe("ConversationUpdate evidence record (spec 014)", () => {
  const LEAF_A = OTHER_KEY_REF < KEY_REF ? OTHER_KEY_REF : KEY_REF;
  const LEAF_B = OTHER_KEY_REF < KEY_REF ? KEY_REF : OTHER_KEY_REF;
  const MEMBER_A = OTHER_ID < PARTICIPANT_ID ? OTHER_ID : PARTICIPANT_ID;
  const MEMBER_B = OTHER_ID < PARTICIPANT_ID ? PARTICIPANT_ID : OTHER_ID;

  function update(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      conversationId: MULTIHASH,
      kind: "add",
      members: [MEMBER_A],
      leaves: [LEAF_A],
      actor: MEMBER_B,
      epoch: "7",
      createdAt: DATETIME,
      signature: [KEY_REF],
      ...overrides
    };
  }

  it("accepts each kind", () => {
    expect(conversationUpdateSchema.parse(update())).toBeTruthy();
    expect(conversationUpdateSchema.parse(update({ kind: "remove" }))).toBeTruthy();
    expect(
      conversationUpdateSchema.parse({
        ...update({ kind: "device-add" }),
        members: [MEMBER_B]
      })
    ).toBeTruthy();
    expect(
      conversationUpdateSchema.parse({
        ...update({ kind: "device-remove" }),
        members: [MEMBER_B]
      })
    ).toBeTruthy();
  });

  it("accepts a record whose actor is not in members (the creator acts on others)", () => {
    const parsed = conversationUpdateSchema.parse(update({ kind: "remove" }));
    expect(parsed.members).not.toContain(parsed.actor);
  });

  it("requires members to be non-empty, unique, and sorted", () => {
    expect(conversationUpdateSchema.safeParse(update({ members: [] })).success).toBe(false);
    expect(
      conversationUpdateSchema.safeParse(update({ members: [MEMBER_A, MEMBER_A] })).success
    ).toBe(false);
    expect(
      conversationUpdateSchema.safeParse(update({ members: [MEMBER_B, MEMBER_A] })).success
    ).toBe(false);
    expect(conversationUpdateSchema.parse(update({ members: [MEMBER_A, MEMBER_B] }))).toBeTruthy();
  });

  it("requires leaves to be non-empty, unique, and sorted", () => {
    expect(conversationUpdateSchema.safeParse(update({ leaves: [] })).success).toBe(false);
    expect(conversationUpdateSchema.safeParse(update({ leaves: [LEAF_A, LEAF_A] })).success).toBe(
      false
    );
    expect(conversationUpdateSchema.safeParse(update({ leaves: [LEAF_B, LEAF_A] })).success).toBe(
      false
    );
    expect(conversationUpdateSchema.parse(update({ leaves: [LEAF_A, LEAF_B] }))).toBeTruthy();
  });

  it("requires a device-* record's members to be exactly [actor]", () => {
    for (const kind of ["device-add", "device-remove"]) {
      // members names someone other than the actor
      expect(
        conversationUpdateSchema.safeParse(update({ kind, members: [MEMBER_A], actor: MEMBER_B }))
          .success
      ).toBe(false);
      // set equality, not containment: the actor plus a smuggled participant
      expect(
        conversationUpdateSchema.safeParse(
          update({ kind, members: [MEMBER_A, MEMBER_B], actor: MEMBER_B })
        ).success
      ).toBe(false);
      // exactly [actor]
      expect(
        conversationUpdateSchema.parse(update({ kind, members: [MEMBER_B], actor: MEMBER_B }))
      ).toBeTruthy();
    }
  });

  it("does not constrain members for add/remove beyond the set rules", () => {
    expect(
      conversationUpdateSchema.parse(update({ kind: "add", members: [MEMBER_A, MEMBER_B] }))
    ).toBeTruthy();
    // A self-authorized departure: members == [actor] is legal for remove too.
    expect(
      conversationUpdateSchema.parse(update({ kind: "remove", members: [MEMBER_B] }))
    ).toBeTruthy();
  });

  it("requires a decimal epoch with no leading zeros", () => {
    expect(conversationUpdateSchema.parse(update({ epoch: "0" }))).toBeTruthy();
    expect(conversationUpdateSchema.parse(update({ epoch: "1024" }))).toBeTruthy();
    for (const epoch of ["01", "007", "-1", "1.0", "three", "", " 1", "1 ", 3]) {
      expect(conversationUpdateSchema.safeParse(update({ epoch })).success).toBe(false);
    }
  });

  it("rejects unknown keys (strict schema — the record is digest-identified)", () => {
    expect(conversationUpdateSchema.safeParse(update({ seq: "1" })).success).toBe(false);
    expect(conversationUpdateSchema.safeParse(update({ prior: MULTIHASH })).success).toBe(false);
  });

  it("rejects malformed or missing required fields", () => {
    expect(conversationUpdateSchema.safeParse(update({ kind: "rename" })).success).toBe(false);
    expect(
      conversationUpdateSchema.safeParse(update({ conversationId: "not-a-digest" })).success
    ).toBe(false);
    expect(conversationUpdateSchema.safeParse(update({ actor: KEY_REF })).success).toBe(false);
    expect(conversationUpdateSchema.safeParse(update({ members: [KEY_REF] })).success).toBe(false);
    expect(conversationUpdateSchema.safeParse(update({ leaves: [PARTICIPANT_ID] })).success).toBe(
      false
    );
    expect(conversationUpdateSchema.safeParse(update({ createdAt: "yesterday" })).success).toBe(
      false
    );
    expect(conversationUpdateSchema.safeParse(update({ signature: [] })).success).toBe(false);
    expect(conversationUpdateSchema.safeParse(update({ signature: KEY_REF })).success).toBe(false);
    const unsigned = update();
    delete unsigned["signature"];
    expect(conversationUpdateSchema.safeParse(unsigned).success).toBe(false);
  });
});

describe("ConversationUpdate conformance vectors (spec 014)", () => {
  const fixture = loadFixture<{
    vectors: { name: string; record: unknown; valid: boolean; reason?: string }[];
  }>("conversation-update-vectors.json");

  it("covers both verdicts", () => {
    expect(fixture.vectors.some((vector) => vector.valid)).toBe(true);
    expect(fixture.vectors.some((vector) => !vector.valid)).toBe(true);
  });

  it.each(fixture.vectors.map((vector) => [vector.name, vector] as const))(
    "vector: %s",
    (_name, vector) => {
      expect(conversationUpdateSchema.safeParse(vector.record).success).toBe(vector.valid);
      if (!vector.valid) {
        // Every reject vector documents why, so the file reads as a spec conformance list.
        expect(vector.reason).toBeTruthy();
      }
    }
  );
});

describe("the (record, chain) unit payloads (spec 014)", () => {
  const NODE_ID = OTHER_ID;

  function grant(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    // A session grant: the participant delegates evidence authorship to a browser session key,
    // aud-bound to the node the delivery will be presented to (011).
    return {
      subjectId: PARTICIPANT_ID,
      issuerId: PARTICIPANT_ID,
      audienceId: KEY_REF,
      abilities: ["msg/conversation-update"],
      caveats: { aud: NODE_ID },
      proof: null,
      issuedAt: DATETIME,
      expiresAt: DATETIME,
      signature: [KEY_REF],
      ...overrides
    };
  }

  function update(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      conversationId: MULTIHASH,
      kind: "add",
      members: [OTHER_ID],
      leaves: [KEY_REF],
      actor: PARTICIPANT_ID,
      epoch: "7",
      createdAt: DATETIME,
      signature: [KEY_REF],
      ...overrides
    };
  }

  const conversation = e2eeFixture.conversation;

  it("accepts a unit with no chain — owner mode", () => {
    expect(conversationUpdatePayloadSchema.parse({ record: update() }).chain).toBeUndefined();
    expect(conversationPayloadSchema.parse({ record: conversation }).chain).toBeUndefined();
  });

  it("accepts a unit carrying a chain — delegated mode", () => {
    const unit = conversationUpdatePayloadSchema.parse({ record: update(), chain: [grant()] });
    expect(unit.chain).toHaveLength(1);
    expect(
      conversationPayloadSchema.parse({ record: conversation, chain: [grant()] }).chain
    ).toHaveLength(1);
  });

  it("rejects a bare record that is not wrapped in the unit", () => {
    // The old wire form. It must fail closed: a reader handed a delegated-signed record with
    // nowhere to look for its authorization can only ever wait.
    expect(conversationUpdatePayloadSchema.safeParse(update()).success).toBe(false);
    expect(conversationPayloadSchema.safeParse(conversation).success).toBe(false);
  });

  it("rejects a present but empty chain", () => {
    expect(conversationUpdatePayloadSchema.safeParse({ record: update(), chain: [] }).success).toBe(
      false
    );
    expect(conversationPayloadSchema.safeParse({ record: conversation, chain: [] }).success).toBe(
      false
    );
  });

  it("rejects a malformed chain entry", () => {
    const noExpiry = grant();
    delete noExpiry["expiresAt"]; // 011: a key-audience grant must carry expiresAt
    const bad = [
      noExpiry,
      grant({ abilities: [] }),
      grant({ subjectId: KEY_REF }),
      MULTIHASH,
      null
    ];
    for (const entry of bad) {
      expect(
        conversationUpdatePayloadSchema.safeParse({ record: update(), chain: [entry] }).success
      ).toBe(false);
      expect(
        conversationPayloadSchema.safeParse({ record: conversation, chain: [entry] }).success
      ).toBe(false);
    }
    // One bad link poisons an otherwise well-formed chain — chains are verified whole.
    expect(
      conversationUpdatePayloadSchema.safeParse({ record: update(), chain: [grant(), noExpiry] })
        .success
    ).toBe(false);
  });

  it("rejects unknown keys at the unit level (strict)", () => {
    // Notably the transport chain, which rides with the *message* per 011: two chain-shaped
    // fields would leave two implementations disagreeing about which authorizes the record.
    expect(
      conversationUpdatePayloadSchema.safeParse({
        record: update(),
        chain: [grant()],
        transportChain: [grant()]
      }).success
    ).toBe(false);
    expect(
      conversationPayloadSchema.safeParse({ record: conversation, updateId: MULTIHASH }).success
    ).toBe(false);
    expect(conversationUpdatePayloadSchema.safeParse({ chain: [grant()] }).success).toBe(false);
  });

  it("rejects a chain smuggled inside the record", () => {
    // The record stays strict underneath the unit. This is the one shape that would change the
    // record's digest id, so it is malformed rather than merely unwelcome.
    expect(
      conversationUpdatePayloadSchema.safeParse({
        record: { ...update(), chain: [grant()] }
      }).success
    ).toBe(false);
    expect(
      conversationPayloadSchema.safeParse({ record: { ...conversation, chain: [grant()] } }).success
    ).toBe(false);
  });

  it("does not soften the record's own rules", () => {
    expect(
      conversationUpdatePayloadSchema.safeParse({ record: update({ epoch: "01" }) }).success
    ).toBe(false);
    expect(
      conversationUpdatePayloadSchema.safeParse({ record: update({ kind: "rename" }) }).success
    ).toBe(false);
    expect(
      conversationPayloadSchema.safeParse({ record: { ...conversation, lane: "machine" } }).success
    ).toBe(false);
  });

  it("pins the self-remove ability outside the msg namespace (spec 014, amended 2026-08-02)", () => {
    expect(ABILITY_CONVERSATION_SELF_REMOVE).toBe("conversation/self-remove");
    expect(abilitySchema.parse(ABILITY_CONVERSATION_SELF_REMOVE)).toBe(
      ABILITY_CONVERSATION_SELF_REMOVE
    );
    // The whole point of the placement: `msg` does not cover it under 009's path-prefix rule,
    // so no exclusion inside the umbrella's cover math is needed.
    expect(ABILITY_CONVERSATION_SELF_REMOVE.startsWith("msg/")).toBe(false);
    expect(ABILITY_CONVERSATION_SELF_REMOVE.startsWith("msg")).toBe(false);
    expect(isE2eeAbility(ABILITY_CONVERSATION_SELF_REMOVE)).toBe(false);
  });
});

describe("(record, chain) unit conformance vectors (spec 014)", () => {
  type UnitVector = {
    name: string;
    schema: "conversation" | "conversation-update";
    valid: boolean;
    reason?: string;
    payload: unknown;
    holdsRecordIdentity?: boolean;
  };
  type IdentityEntry = { record: Record<string, unknown>; recordId: string; chain: unknown[] };

  const fixture = loadFixture<{
    digestIdentity: { conversationUpdate: IdentityEntry; conversation: IdentityEntry };
    vectors: UnitVector[];
  }>("conversation-unit-vectors.json");

  function schemaFor(name: UnitVector["schema"]) {
    return name === "conversation" ? conversationPayloadSchema : conversationUpdatePayloadSchema;
  }

  it("covers both verdicts and both payloads", () => {
    for (const schema of ["conversation", "conversation-update"] as const) {
      const mine = fixture.vectors.filter((vector) => vector.schema === schema);
      expect(mine.some((vector) => vector.valid)).toBe(true);
      expect(mine.some((vector) => !vector.valid)).toBe(true);
    }
  });

  it.each(fixture.vectors.map((vector) => [vector.name, vector] as const))(
    "vector: %s",
    (_name, vector) => {
      expect(schemaFor(vector.schema).safeParse(vector.payload).success).toBe(vector.valid);
      if (!vector.valid) {
        // Every reject vector documents why, so the file reads as a spec conformance list.
        expect(vector.reason).toBeTruthy();
      }
      if (vector.holdsRecordIdentity === true) {
        // …and the smuggled-chain vectors carry their own proof of why they are malformed: the
        // record they contain does not digest to the record it claims to be.
        const smuggled = (vector.payload as { record: Record<string, unknown> }).record;
        const clean = { ...smuggled };
        delete clean["chain"];
        expect(digestId(smuggled)).not.toBe(digestId(clean));
      }
    }
  );

  it("evidence: the record's digest id is identical with and without the chain", () => {
    // The chain sits ALONGSIDE the record. Record identity is a function of `record` alone,
    // which is what makes a re-delivered or relayed unit name the same digest in a commit
    // binding as the authoring delivery did.
    const entry = fixture.digestIdentity.conversationUpdate;
    expect(digestId(entry.record)).toBe(entry.recordId);
    const bare = conversationUpdatePayloadSchema.parse({ record: entry.record });
    const withChain = conversationUpdatePayloadSchema.parse({
      record: entry.record,
      chain: entry.chain
    });
    expect(digestId(bare.record)).toBe(entry.recordId);
    expect(digestId(withChain.record)).toBe(entry.recordId);
    expect(withChain.chain).toHaveLength(2);
    // The unit is not the record: digesting the wrapper would be a different id entirely.
    expect(digestId(withChain)).not.toBe(entry.recordId);
  });

  it("conversation: the record's digest id is identical with and without the chain", () => {
    const entry = fixture.digestIdentity.conversation;
    expect(digestId(entry.record)).toBe(entry.recordId);
    expect(entry.recordId).toBe(e2eeFixture.conversationId);
    const bare = conversationPayloadSchema.parse({ record: entry.record });
    const withChain = conversationPayloadSchema.parse({
      record: entry.record,
      chain: entry.chain
    });
    expect(digestId(bare.record)).toBe(entry.recordId);
    expect(digestId(withChain.record)).toBe(entry.recordId);
  });

  it("pins the evidence unit's record id to committed bytes", () => {
    expect(fixture.digestIdentity.conversationUpdate.recordId).toBe(
      "zQmdcspqb1S5VKcxW94Bq87NDnGtZDg7mJsiux3RoydMt2j"
    );
  });
});

describe("the e2ee ability predicate (spec 014)", () => {
  it("matches the namespace and nothing that merely starts with the letters", () => {
    expect(isE2eeAbility("e2ee")).toBe(true);
    expect(isE2eeAbility("e2ee/leaf")).toBe(true);
    expect(isE2eeAbility("e2ee/anything/deeper")).toBe(true);
    expect(isE2eeAbility("e2ee/")).toBe(true);
    // Prefix confusion guard: a different namespace that shares a prefix is NOT e2ee.
    expect(isE2eeAbility("e2eex")).toBe(false);
    expect(isE2eeAbility("e2eex/leaf")).toBe(false);
    expect(isE2eeAbility("msg/send")).toBe(false);
    expect(isE2eeAbility("msg")).toBe(false);
    expect(isE2eeAbility("")).toBe(false);
    expect(isE2eeAbility("leaf/e2ee")).toBe(false);
  });

  it("names the leaf ability", () => {
    expect(ABILITY_E2EE_LEAF).toBe("e2ee/leaf");
    expect(isE2eeAbility(ABILITY_E2EE_LEAF)).toBe(true);
  });
});

describe("credential links: the grant amendments (spec 014)", () => {
  const SESSION_KEY = "z6MkSessionKey1abcdefgh";
  const SERVICE_ID = `pk_${KEY_REF}`;

  const base = {
    subjectId: PARTICIPANT_ID,
    issuerId: PARTICIPANT_ID,
    audienceId: PARTICIPANT_ID,
    abilities: [ABILITY_E2EE_LEAF],
    caveats: {},
    proof: null,
    issuedAt: DATETIME,
    signature: [KEY_REF]
  };

  it("exempts an all-e2ee key-audience grant from caveats.aud", () => {
    // The leaf link of a credential chain: audience is the MLS leaf's signature key, and there
    // is no request surface to bind an audience to.
    expect(
      grantSchema.parse({ ...base, audienceId: SESSION_KEY, expiresAt: DATETIME })
    ).toBeTruthy();
    expect(
      grantSchema.parse({
        ...base,
        abilities: ["e2ee"],
        audienceId: SESSION_KEY,
        expiresAt: DATETIME
      })
    ).toBeTruthy();
  });

  it("still requires expiresAt on a key-audience credential link", () => {
    // 011's expiry rule is NOT lifted: a bare key has no log, so expiry is its only planned end.
    expect(grantSchema.safeParse({ ...base, audienceId: SESSION_KEY }).success).toBe(false);
  });

  it("rejects any caveat on a credential link, including a well-formed aud", () => {
    expect(
      grantSchema.safeParse({
        ...base,
        audienceId: SESSION_KEY,
        expiresAt: DATETIME,
        caveats: { aud: SERVICE_ID }
      }).success
    ).toBe(false);
    // Participant audience too — the rule is about the link being a credential, not about who
    // the audience is.
    expect(grantSchema.safeParse({ ...base, caveats: { aud: SERVICE_ID } }).success).toBe(false);
    expect(grantSchema.safeParse({ ...base, caveats: { anything: 1 } }).success).toBe(false);
    // The root link of a credential chain, self-issued to the participant: still no caveats.
    expect(grantSchema.parse(base)).toBeTruthy();
  });

  it("gives a MIXED ability set no exemption at all", () => {
    const mixed = { ...base, abilities: [ABILITY_E2EE_LEAF, "msg/send"] };
    // Key audience, no aud: rejected exactly as 011 requires.
    expect(
      grantSchema.safeParse({ ...mixed, audienceId: SESSION_KEY, expiresAt: DATETIME }).success
    ).toBe(false);
    // Key audience with expiresAt and aud: accepted, and its caveats may be non-empty because
    // it is not a credential link.
    expect(
      grantSchema.parse({
        ...mixed,
        audienceId: SESSION_KEY,
        expiresAt: DATETIME,
        caveats: { aud: SERVICE_ID }
      })
    ).toBeTruthy();
  });

  it("treats a prefix-confused ability as non-e2ee, so the mixed rules apply", () => {
    const confusable = { ...base, abilities: ["e2eex"] };
    expect(
      grantSchema.safeParse({ ...confusable, audienceId: SESSION_KEY, expiresAt: DATETIME }).success
    ).toBe(false);
    expect(
      grantSchema.parse({
        ...confusable,
        audienceId: SESSION_KEY,
        expiresAt: DATETIME,
        caveats: { aud: SERVICE_ID }
      })
    ).toBeTruthy();
  });

  it("leaves non-e2ee grants exactly as spec 011 left them (regression)", () => {
    const ordinary = { ...base, abilities: ["msg/send"] };
    expect(grantSchema.parse(ordinary)).toBeTruthy();
    expect(grantSchema.parse({ ...ordinary, caveats: { aud: SERVICE_ID } })).toBeTruthy();
    expect(
      grantSchema.safeParse({ ...ordinary, audienceId: SESSION_KEY, expiresAt: DATETIME }).success
    ).toBe(false);
    expect(
      grantSchema.parse({
        ...ordinary,
        audienceId: SESSION_KEY,
        expiresAt: DATETIME,
        caveats: { aud: SERVICE_ID }
      })
    ).toBeTruthy();
  });
});

describe("E2EE reserved types and payloads (spec 014)", () => {
  it("registers the three new reserved types", () => {
    expect(PN_TYPE_CONVERSATION_UPDATE).toBe("pn/conversation-update");
    expect(PN_TYPE_MLS).toBe("pn/mls");
    expect(PN_TYPE_WELCOME).toBe("pn/welcome");
    for (const type of [PN_TYPE_CONVERSATION_UPDATE, PN_TYPE_MLS, PN_TYPE_WELCOME]) {
      expect(type.startsWith(PN_RESERVED_PREFIX)).toBe(true);
      expect(KNOWN_RESERVED_TYPES.has(type)).toBe(true);
    }
    expect(KNOWN_RESERVED_TYPES.has("pn/unknown")).toBe(false);
  });

  it("accepts and rejects pn/mls payloads", () => {
    expect(mlsPayloadSchema.parse({ mlsMessage: "AAECAw_-" }).mlsMessage).toBe("AAECAw_-");
    expect(mlsPayloadSchema.safeParse({ mlsMessage: "" }).success).toBe(false);
    // padded base64, standard-alphabet base64, and non-base64 characters are all out
    expect(mlsPayloadSchema.safeParse({ mlsMessage: "AAEC==" }).success).toBe(false);
    expect(mlsPayloadSchema.safeParse({ mlsMessage: "AA+C/w" }).success).toBe(false);
    expect(mlsPayloadSchema.safeParse({ mlsMessage: 42 }).success).toBe(false);
    expect(mlsPayloadSchema.safeParse({}).success).toBe(false);
    // strict: no extra keys alongside the opaque MLS bytes
    expect(mlsPayloadSchema.safeParse({ mlsMessage: "AAEC", epoch: "1" }).success).toBe(false);
  });

  it("rejects non-canonical base64url in a pn/mls payload", () => {
    // The canonical form, and the two deviations the alphabet check let through. "AA" is the
    // one encoding of the byte 0x00; "AB" carries four bits past that byte, which a permissive
    // decoder folds onto the same 0x00 — one payload, two textual forms, inside a digest-
    // identified envelope. "A" cannot end a base64 quantum at all, so it encodes no byte string.
    expect(mlsPayloadSchema.safeParse({ mlsMessage: "AA" }).success).toBe(true);
    expect(mlsPayloadSchema.safeParse({ mlsMessage: "AB" }).success).toBe(false);
    expect(mlsPayloadSchema.safeParse({ mlsMessage: "A" }).success).toBe(false);
    // The same rejections this package's own base64url decoder makes, so a schema check and a
    // decode agree about what a valid encoding is rather than each holding its own opinion.
    expect(() => decodeBase64Url("AB")).toThrow(/non-zero trailing bits/);
    expect(() => decodeBase64Url("A")).toThrow(/truncated final quantum/);
    expect(decodeBase64Url("AA")).toEqual(Uint8Array.of(0));
  });

  it("accepts and rejects pn/welcome payloads", () => {
    expect(welcomePayloadSchema.parse({ welcome: "AAECAw_-" }).welcome).toBe("AAECAw_-");
    expect(welcomePayloadSchema.safeParse({ welcome: "" }).success).toBe(false);
    expect(welcomePayloadSchema.safeParse({ welcome: "AAEC==" }).success).toBe(false);
    expect(welcomePayloadSchema.safeParse({ mlsMessage: "AAEC" }).success).toBe(false);
    expect(welcomePayloadSchema.safeParse({ welcome: "AAEC", ratchetTree: "AA" }).success).toBe(
      false
    );
    expect(welcomePayloadSchema.safeParse({ welcome: "AB" }).success).toBe(false);
    expect(welcomePayloadSchema.safeParse({ welcome: "A" }).success).toBe(false);
  });
});
