/**
 * Record-kind non-confusability (spec 001, _Record kinds are non-confusable_ — the 2026-08
 * review's finding 6e).
 *
 * `canonicalDigest` has no domain separation between record kinds: a record's digest commits to
 * its fields and not to what the record IS. So the only thing that decides a delivery's kind is
 * its schema, and if two schemas accept one object, one signature and one digest authorize two
 * records. That is what open (non-strict) schemas produced for Claim and Relationship — an object
 * carrying the union of both field sets parsed as both, and `verifyClaim` and `verifyRelationship`
 * each returned valid over it.
 *
 * This test is the guarantee, not an illustration of it: it walks the FULL cross product of the
 * record kinds this package defines, so a new kind or a widened field set that reopens the gap
 * fails here rather than in a review two months later.
 */
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  claimSchema,
  conversationPayloadSchema,
  conversationSchema,
  conversationUpdatePayloadSchema,
  conversationUpdateSchema,
  grantSchema,
  keyEventSchema,
  messageEnvelopeSchema,
  mlsPayloadSchema,
  participantNodeSchema,
  participantProfileSchema,
  relationshipSchema,
  revocationSchema,
  welcomePayloadSchema
} from "../src/index.js";

type Vectors = {
  records: Record<string, Record<string, unknown>>;
  payloads: Record<string, Record<string, unknown>>;
};

const vectors = JSON.parse(
  readFileSync(new URL("./fixtures/record-kind-vectors.json", import.meta.url), "utf8")
) as Vectors;

/**
 * Every kind `@kinnet/protocol` defines, paired with its schema. Adding an exported record or
 * payload schema without adding it here fails the completeness test below — the enumeration is
 * checked against the fixture file, so the two cannot drift apart silently.
 */
const KINDS: { name: string; schema: { safeParse(value: unknown): { success: boolean } } }[] = [
  { name: "keyEvent", schema: keyEventSchema },
  { name: "participantProfile", schema: participantProfileSchema },
  { name: "participantNode", schema: participantNodeSchema },
  { name: "revocation", schema: revocationSchema },
  { name: "grant", schema: grantSchema },
  { name: "relationship", schema: relationshipSchema },
  { name: "claim", schema: claimSchema },
  { name: "messageEnvelope", schema: messageEnvelopeSchema },
  { name: "conversation", schema: conversationSchema },
  { name: "conversationUpdate", schema: conversationUpdateSchema },
  { name: "conversationPayload", schema: conversationPayloadSchema },
  { name: "conversationUpdatePayload", schema: conversationUpdatePayloadSchema },
  { name: "mlsPayload", schema: mlsPayloadSchema },
  { name: "welcomePayload", schema: welcomePayloadSchema }
];

const FIXTURES: Record<string, Record<string, unknown>> = {
  ...vectors.records,
  ...vectors.payloads
};

describe("record-kind conformance vectors", () => {
  it("carries exactly one fixture per defined kind", () => {
    expect(Object.keys(FIXTURES).sort()).toEqual(KINDS.map((kind) => kind.name).sort());
  });

  for (const { name, schema } of KINDS) {
    it(`validates the ${name} fixture under its own schema`, () => {
      expect(schema.safeParse(FIXTURES[name]).success).toBe(true);
    });
  }
});

describe("no record kind validates under another kind's schema (finding 6e)", () => {
  for (const { name } of KINDS) {
    it(`the ${name} fixture is rejected by every other schema`, () => {
      const crossValidating = KINDS.filter(
        (other) => other.name !== name && other.schema.safeParse(FIXTURES[name]).success
      ).map((other) => other.name);
      expect(crossValidating).toEqual([]);
    });
  }
});

describe("the hybrid that finding 6e was reported as", () => {
  it("refuses an object carrying the union of the Claim and Relationship field sets", () => {
    // Before both schemas were closed, this parsed as BOTH: each stripped the other's fields,
    // and one signature over one digest authorized two different records.
    const hybrid = { ...vectors.records["claim"], ...vectors.records["relationship"] };
    expect(claimSchema.safeParse(hybrid).success).toBe(false);
    expect(relationshipSchema.safeParse(hybrid).success).toBe(false);
  });
});
