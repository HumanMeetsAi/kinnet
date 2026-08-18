import { MAX_GRANT_CHAIN_LINKS, type Grant } from "@kinnet/protocol";
import { base64urlnopad } from "@scure/base";
import { describe, expect, it } from "vitest";

import { decodeGrantsHeader, encodeGrantsHeader } from "../src/index.js";

const textEncoder = new TextEncoder();

function encodePayload(payload: unknown): string {
  return `1:${base64urlnopad.encode(textEncoder.encode(JSON.stringify(payload)))}`;
}

function grantFixture(overrides: Partial<Grant> = {}): Grant {
  return {
    subjectId: "pk_z6MkSubject1111",
    issuerId: "pk_z6MkSubject1111",
    audienceId: "z6MkSessionKey1111",
    abilities: ["msg/send"],
    caveats: { aud: "pk_z6MkVerifier1111" },
    proof: null,
    // Spec 016: this link's issuer is a participant, so it names the key state it was signed
    // under. Shape-valid rather than resolvable — the codec under test decodes, never verifies.
    anchor: "zQmYwAPJzv5CZsnAzt8auVZRnHEKzKgUEdy3W35nUSpS6kq",
    issuedAt: "2026-07-21T12:00:00.000Z",
    expiresAt: "2026-07-28T12:00:00.000Z",
    signature: ["z2SignatureBytes1111"],
    ...overrides
  };
}

describe("PN-Grants header codec (spec 011)", () => {
  it("round-trips a leaf-first chain without reordering", () => {
    const leaf = grantFixture();
    const root = grantFixture({
      audienceId: "pk_z6MkAppKid1111",
      abilities: ["msg"],
      caveats: {}
    });
    const header = encodeGrantsHeader([leaf, root]);

    expect(header.startsWith("1:")).toBe(true);
    expect(decodeGrantsHeader(header)).toEqual([leaf, root]);
  });

  it("rejects an empty chain on encode", () => {
    expect(() => encodeGrantsHeader([])).toThrow(/empty/);
  });

  it("rejects an unknown or missing profile prefix", () => {
    const payload = encodeGrantsHeader([grantFixture()]).slice(2);

    expect(() => decodeGrantsHeader(`2:${payload}`)).toThrow(/unsupported PN-Grants encoding/);
    expect(() => decodeGrantsHeader(payload)).toThrow(/unsupported PN-Grants encoding/);
  });

  it("rejects a payload that is not valid base64url", () => {
    expect(() => decodeGrantsHeader("1:!!!not-base64url!!!")).toThrow(/base64url/);
    // Padding is not part of this profile's base64url alphabet.
    expect(() => decodeGrantsHeader("1:e30=")).toThrow(/base64url/);
  });

  it("rejects JSON payloads that are not arrays", () => {
    expect(() => decodeGrantsHeader(encodePayload(grantFixture()))).toThrow(/array/);
    expect(() => decodeGrantsHeader(encodePayload("chain"))).toThrow(/array/);
    expect(() => decodeGrantsHeader(encodePayload(null))).toThrow(/array/);
  });

  it("accepts a chain at the length cap and rejects one past it", () => {
    // Verifying a chain replays the issuer's key log per link, so depth is work the caller
    // chooses — and the header arrives before the chain has proven anything. The cap is
    // enforced on the DECODED length, before the per-element shape parse, so an overlong
    // chain costs the schema nothing either.
    const atCap = Array.from({ length: MAX_GRANT_CHAIN_LINKS }, () => grantFixture());
    expect(decodeGrantsHeader(encodePayload(atCap))).toHaveLength(MAX_GRANT_CHAIN_LINKS);

    const overCap = Array.from({ length: MAX_GRANT_CHAIN_LINKS + 1 }, () => grantFixture());
    expect(() => decodeGrantsHeader(encodePayload(overCap))).toThrow(/more than the/);
  });

  it("rejects an empty array", () => {
    expect(() => decodeGrantsHeader(encodePayload([]))).toThrow(/array/);
  });

  it("rejects a chain containing a non-grant element", () => {
    expect(() => decodeGrantsHeader(encodePayload([grantFixture(), { not: "a grant" }]))).toThrow();
    // A key-audience grant without expiresAt is shape-invalid per spec 011.
    const invalid = { ...grantFixture(), expiresAt: undefined };
    expect(() => decodeGrantsHeader(encodePayload([invalid]))).toThrow();
  });

  it("rejects a delivery whose JSON carries a duplicate object key (spec 015 S6.1)", () => {
    // ONE delivered byte string, two logical records: `JSON.parse` resolves this last-wins
    // and a first-wins parser resolves it to the other `proof`, so two implementations
    // handed these exact bytes would digest two different Grants. A Grant's digest is what
    // its child's `proof` names and what spec 008 keys its revocation by, so the ambiguity
    // is a second identity for one delivery. 015 S6.1 refuses the delivery rather than
    // picking a winner, because both resolutions are defensible.
    const json = JSON.stringify([grantFixture()]).replace(
      '"proof":null',
      '"proof":null,"proof":"zQmDifferent1111"'
    );
    expect(json).toContain('"proof":null,"proof"');
    // Last-wins is what a plain parse yields, which is the ambiguity being refused.
    expect((JSON.parse(json) as { proof: string }[])[0]!.proof).toBe("zQmDifferent1111");

    const header = `1:${base64urlnopad.encode(textEncoder.encode(json))}`;
    expect(() => decodeGrantsHeader(header)).toThrow(/not valid UTF-8 JSON/);
  });

  it("rejects a grant carrying a key the schema does not define (spec 015 S6.3)", () => {
    // CLOSED schema: an unknown key is rejected, not silently stripped. `grantSchema` was a
    // plain `z.object` until 015's enforcement change, so this decoded successfully and
    // yielded a Grant without the extra key — one delivery, two digests again.
    const withExtra = { ...grantFixture(), surprise: 1 };
    expect(() => decodeGrantsHeader(encodePayload([withExtra]))).toThrow();
  });

  it("rejects a tampered payload", () => {
    const chain = [grantFixture()];
    const json = JSON.stringify(chain).replace('"subjectId"', '"subjectXd"');
    const header = `1:${base64urlnopad.encode(textEncoder.encode(json))}`;

    expect(() => decodeGrantsHeader(header)).toThrow();
  });
});
