/**
 * The chain access token: `"pnc1." + base64url( UTF8( JSON.stringify(chain) ) )`, the OAuth
 * access token that IS the delegation chain.
 *
 * Two suites. The first states the codec's guards directly — the same guards the `PN-Grants`
 * header enforces, in the same order, because the two deliveries share their payload half
 * (`packages/crypto/src/grant-chain-payload.ts`). The second checks the committed fixture,
 * `test/fixtures/chain-token-vectors.json`, which records the same rules as bytes a second
 * implementation can check itself against without running this repository; what this file adds
 * is that the fixture TELLS THE TRUTH — every recorded token, payload, chain, signature and
 * refusal is recomputed here.
 *
 * THE MUTATION THESE TESTS CATCH: relaxing a guard, or reordering two of them. A bearer token is
 * long-lived, widely copied and presented by anyone holding it, so the ordering matters as much
 * as the verdicts — the link cap is checked on the decoded length BEFORE any element is parsed,
 * and the five-link vector is constructed so that an implementation checking elements first
 * refuses it with a different error rather than passing quietly.
 */
import { readFileSync } from "node:fs";

import { grantSchema, MAX_GRANT_CHAIN_LINKS, type Grant, type Principal } from "@kinnet/protocol";
import { base64urlnopad } from "@scure/base";
import { describe, expect, it } from "vitest";

import {
  CHAIN_ACCESS_TOKEN_PREFIX,
  canonicalDigest,
  createIdentity,
  decodeChainAccessToken,
  encodeChainAccessToken,
  encodeGrantsHeader,
  encodeKeyRef,
  keyLogAnchor,
  signThresholdRecord,
  verifyThresholdRecord,
  type Identity
} from "../src/index.js";

const textEncoder = new TextEncoder();

function encodePayload(payload: unknown): string {
  return `pnc1.${base64urlnopad.encode(textEncoder.encode(JSON.stringify(payload)))}`;
}

function grantFixture(overrides: Partial<Grant> = {}): Grant {
  return {
    subjectId: "pk_z6MkSubject1111",
    issuerId: "pk_z6MkSubject1111",
    audienceId: "pk_z6MkResource1111",
    abilities: ["photos/read"],
    caveats: { aud: "pk_z6MkResource1111" },
    proof: null,
    // Spec 016: a participant-issued link names the key state it was signed under. Shape-valid
    // rather than resolvable — the codec under test decodes, it does not verify.
    anchor: "zQmYwAPJzv5CZsnAzt8auVZRnHEKzKgUEdy3W35nUSpS6kq",
    issuedAt: "2026-08-14T09:00:00.000Z",
    expiresAt: "2026-08-14T10:00:00.000Z",
    signature: ["z2SignatureBytes1111"],
    ...overrides
  };
}

describe("chain access token codec", () => {
  it("round-trips a leaf-first chain without reordering", () => {
    const leaf = grantFixture();
    const root = grantFixture({
      audienceId: "pk_z6MkAdmin1111",
      abilities: ["photos"],
      caveats: {}
    });
    const token = encodeChainAccessToken([leaf, root]);

    expect(CHAIN_ACCESS_TOKEN_PREFIX).toBe("pnc1.");
    expect(token.startsWith(CHAIN_ACCESS_TOKEN_PREFIX)).toBe(true);
    expect(decodeChainAccessToken(token)).toEqual([leaf, root]);
  });

  it("encodes the payload exactly as the PN-Grants header does", () => {
    // The profile's claim, as an assertion: one chain has ONE payload encoding, and only the prefix
    // distinguishes the deliveries. A drift here would give a chain two wire forms.
    const chain = [grantFixture()];
    expect(encodeChainAccessToken(chain).slice(CHAIN_ACCESS_TOKEN_PREFIX.length)).toBe(
      encodeGrantsHeader(chain).slice("1:".length)
    );
  });

  it("rejects an empty chain on encode", () => {
    // Nothing decodes an empty chain, so encoding one only mints bytes no verifier can read.
    expect(() => encodeChainAccessToken([])).toThrow(/empty/);
  });

  it("rejects an unknown, missing or differently-cased prefix", () => {
    const payload = encodeChainAccessToken([grantFixture()]).slice(
      CHAIN_ACCESS_TOKEN_PREFIX.length
    );

    expect(() => decodeChainAccessToken(`pnc2.${payload}`)).toThrow(
      /unsupported chain access token encoding/
    );
    expect(() => decodeChainAccessToken(`PNC1.${payload}`)).toThrow(
      /unsupported chain access token encoding/
    );
    expect(() => decodeChainAccessToken(payload)).toThrow(
      /unsupported chain access token encoding/
    );
    // The header form of the same chain: byte-identical payload, different delivery.
    expect(() => decodeChainAccessToken(`1:${payload}`)).toThrow(
      /unsupported chain access token encoding/
    );
  });

  it("rejects a payload that is not valid base64url", () => {
    expect(() => decodeChainAccessToken("pnc1.!!!not-base64url!!!")).toThrow(/base64url/);
    // Padding is not part of this profile's base64url alphabet.
    expect(() => decodeChainAccessToken("pnc1.e30=")).toThrow(/base64url/);
  });

  it("rejects JSON payloads that are not arrays", () => {
    expect(() => decodeChainAccessToken(encodePayload(grantFixture()))).toThrow(/array/);
    expect(() => decodeChainAccessToken(encodePayload("chain"))).toThrow(/array/);
    expect(() => decodeChainAccessToken(encodePayload(null))).toThrow(/array/);
  });

  it("rejects an empty array", () => {
    expect(() => decodeChainAccessToken(encodePayload([]))).toThrow(/array/);
  });

  it("accepts a chain at the length cap and rejects one past it", () => {
    const atCap = Array.from({ length: MAX_GRANT_CHAIN_LINKS }, () => grantFixture());
    expect(decodeChainAccessToken(encodePayload(atCap))).toHaveLength(MAX_GRANT_CHAIN_LINKS);

    const overCap = Array.from({ length: MAX_GRANT_CHAIN_LINKS + 1 }, () => grantFixture());
    expect(() => decodeChainAccessToken(encodePayload(overCap))).toThrow(/more than the/);
  });

  it("checks the length before parsing any element", () => {
    // THE ORDER, not just the verdict. Every element here is structurally invalid, so the two
    // possible orderings give two different refusals and this asserts which one happens.
    // Verifying a chain replays the issuer's key log per link: the depth is work whoever holds
    // the token chooses, and a bearer token is held by whoever it was copied to.
    const malformed = Array.from({ length: MAX_GRANT_CHAIN_LINKS + 1 }, () => ({}));
    expect(() => decodeChainAccessToken(encodePayload(malformed))).toThrow(
      `Chain access token carries ${malformed.length} links, more than the ${MAX_GRANT_CHAIN_LINKS} allowed`
    );
  });

  it("rejects a chain containing an element that is not a shape-valid Grant", () => {
    // Every element, not just the leaf.
    expect(() =>
      decodeChainAccessToken(encodePayload([grantFixture(), { not: "a grant" }]))
    ).toThrow();
    // CLOSED schema (spec 015 S6.3): an unknown key is refused, not stripped — a stripped key
    // would be a second digest for one delivery, and the digest is what revocation keys by.
    expect(() =>
      decodeChainAccessToken(encodePayload([{ ...grantFixture(), surprise: 1 }]))
    ).toThrow();
    // A key-audience grant without expiresAt is shape-invalid per spec 011.
    expect(() =>
      decodeChainAccessToken(
        encodePayload([
          { ...grantFixture(), audienceId: "z6MkSessionKey1111", expiresAt: undefined }
        ])
      )
    ).toThrow();
  });

  it("rejects a delivery whose JSON carries a duplicate object key (spec 015 S6.1)", () => {
    // ONE token, two logical chains: `JSON.parse` resolves this last-wins and a first-wins
    // parser resolves it to the other `proof`, so two resource servers handed these exact bytes
    // would digest two different Grants. A Grant's digest is what its child's `proof` names and
    // what spec 008 keys its revocation by, so the ambiguity is a second identity for one
    // credential — and unlike a request header, a token is stored and replayed for its lifetime.
    const json = JSON.stringify([grantFixture()]).replace(
      '"proof":null',
      '"proof":null,"proof":"zQmDifferent1111"'
    );
    expect(json).toContain('"proof":null,"proof"');
    expect((JSON.parse(json) as { proof: string }[])[0]!.proof).toBe("zQmDifferent1111");

    const token = `pnc1.${base64urlnopad.encode(textEncoder.encode(json))}`;
    expect(() => decodeChainAccessToken(token)).toThrow(/not valid UTF-8 JSON/);
  });

  it("rejects a tampered payload", () => {
    const json = JSON.stringify([grantFixture()]).replace('"subjectId"', '"subjectXd"');
    const token = `pnc1.${base64urlnopad.encode(textEncoder.encode(json))}`;

    expect(() => decodeChainAccessToken(token)).toThrow();
  });

  it("round-trips a genuinely signed two-link chain", () => {
    // The codec is shape-only, but a chain of placeholder strings would not notice a decoder
    // that rewrote a signature or a digest, so the round trip is asserted on real records.
    const org = createIdentity({ currentSeed: new Uint8Array(32).fill(3) });
    const admin = createIdentity({ currentSeed: new Uint8Array(32).fill(5) });
    const resource = createIdentity({ currentSeed: new Uint8Array(32).fill(7) });

    const mint = (issuer: Identity, audienceId: Principal, parent: Grant | null): Grant =>
      grantSchema.parse(
        signThresholdRecord(
          {
            subjectId: org.id,
            issuerId: issuer.id,
            audienceId,
            abilities: ["photos/read"],
            caveats: { aud: resource.id },
            proof: parent === null ? null : canonicalDigest(parent),
            anchor: keyLogAnchor(issuer.log),
            issuedAt: "2026-08-14T09:00:00.000Z",
            expiresAt: "2026-08-14T10:00:00.000Z"
          },
          [issuer.currentKeys[0]!.secretKey]
        )
      );

    const root = mint(org, admin.id, null);
    const leaf = mint(admin, resource.id, root);
    const decoded = decodeChainAccessToken(encodeChainAccessToken([leaf, root]));

    expect(decoded).toEqual([leaf, root]);
    expect(decoded[0]!.proof).toBe(canonicalDigest(decoded[1]!));
    expect(
      verifyThresholdRecord(decoded[0]!, [encodeKeyRef(admin.currentKeys[0]!.publicKey)], 1)
    ).toBe(true);
    expect(
      verifyThresholdRecord(decoded[1]!, [encodeKeyRef(org.currentKeys[0]!.publicKey)], 1)
    ).toBe(true);
  });
});

type Vector = {
  name: string;
  why: string;
  token: string;
  accept: boolean;
  payloadJson: string | null;
  chain: Grant[] | null;
  signerKeys: string[] | null;
  rejection: string | null;
  error: { name: string; message: string } | null;
  invalidElementIndex: number | null;
};

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/chain-token-vectors.json", import.meta.url), "utf8")
) as {
  note: string;
  prefix: string;
  maxChainLinks: number;
  codes: Record<string, string>;
  vectors: Vector[];
};

const { vectors } = fixture;

describe("chain access token conformance vectors", () => {
  it("is not vacuous: both verdicts, distinct tokens, and every class exercised", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(12);
    expect(new Set(vectors.map((vector) => vector.name)).size).toBe(vectors.length);
    // Two vectors sharing a token would mean one of them proves nothing.
    expect(new Set(vectors.map((vector) => vector.token)).size).toBe(vectors.length);
    expect(vectors.filter((vector) => vector.accept).length).toBeGreaterThanOrEqual(3);
    expect(vectors.filter((vector) => !vector.accept).length).toBeGreaterThanOrEqual(9);
    for (const vector of vectors) {
      expect(vector.why.length).toBeGreaterThan(40);
    }

    const documented = new Set(Object.keys(fixture.codes));
    const used = new Set(
      vectors.map((vector) => vector.rejection).filter((code): code is string => code !== null)
    );
    expect([...used].sort()).toEqual([...documented].sort());
    for (const description of Object.values(fixture.codes)) {
      expect(description.length).toBeGreaterThan(40);
    }
  });

  it("records the profile constants this repository implements", () => {
    // A change to either forces the fixture to be regenerated rather than silently diverging.
    expect(fixture.prefix).toBe(CHAIN_ACCESS_TOKEN_PREFIX);
    expect(fixture.maxChainLinks).toBe(MAX_GRANT_CHAIN_LINKS);
  });

  it.each(vectors.filter((vector) => vector.accept).map((v) => [v.name, v] as const))(
    "%s — decodes to the recorded chain, and the recorded bytes are its own",
    (_name, vector) => {
      const { payloadJson, chain, signerKeys } = vector;
      if (payloadJson === null || chain === null || signerKeys === null) {
        throw new Error("An accepted vector must record its payload, chain and signers");
      }

      // The token, recomputed from the payload text: prefix + base64url of its UTF-8, no padding.
      expect(vector.token).toBe(
        `${CHAIN_ACCESS_TOKEN_PREFIX}${base64urlnopad.encode(textEncoder.encode(payloadJson))}`
      );
      // …and the payload text is the JSON of the recorded chain, byte for byte.
      const asDelivered = JSON.parse(payloadJson) as Grant[];
      expect(asDelivered).toEqual(chain);
      expect(encodeChainAccessToken(asDelivered)).toBe(vector.token);

      // What a conforming decode yields — leaf first, unreordered, every element a Grant.
      const decoded = decodeChainAccessToken(vector.token);
      expect(decoded).toEqual(chain);
      expect(decoded.length).toBeLessThanOrEqual(MAX_GRANT_CHAIN_LINKS);

      decoded.forEach((grant, index) => {
        // The chain is genuinely signed: link i's single signature verifies under the recorded
        // key ref, over the spec-001 signing input (the link without its `signature` field).
        expect(verifyThresholdRecord(grant, [signerKeys[index]!], 1)).toBe(true);
        // …and names its parent by the spec-003 digest, which is what makes the order meaningful.
        const parent = decoded[index + 1];
        expect(grant.proof).toBe(parent === undefined ? null : canonicalDigest(parent));
      });
    }
  );

  it.each(vectors.filter((vector) => !vector.accept).map((v) => [v.name, v] as const))(
    "%s — is refused, with the recorded class",
    (_name, vector) => {
      expect(vector.chain).toBeNull();

      let thrown: unknown;
      try {
        decodeChainAccessToken(vector.token);
        throw new Error("The codec accepted a token the fixture records as refused");
      } catch (caught) {
        thrown = caught;
      }
      expect(thrown).toBeInstanceOf(Error);
      const actual = thrown as Error;

      if (vector.error === null) {
        // Only a schema refusal declines to record its text, and only a schema refusal may
        // arrive as a ZodError — that pairing is what stops one guard standing in for another.
        expect(vector.rejection).toBe("element_not_a_grant");
        expect(actual.name).toBe("ZodError");
      } else {
        expect(actual.name).toBe(vector.error.name);
        expect(actual.message).toBe(vector.error.message);
        expect(actual.name).toBe("Error");
      }

      // The element vectors name the element the schema refuses, checkable from the token: every
      // earlier element must parse, so the refusal cannot be blamed on the wrong link — and a
      // `chain_too_long` vector must be refused for its LENGTH even where its elements are also
      // invalid, which is the guard order stated as bytes.
      if (vector.invalidElementIndex !== null) {
        const payload = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            base64urlnopad.decode(vector.token.slice(CHAIN_ACCESS_TOKEN_PREFIX.length))
          )
        ) as unknown[];
        expect(payload.length).toBeLessThanOrEqual(MAX_GRANT_CHAIN_LINKS);
        expect(grantSchema.safeParse(payload[vector.invalidElementIndex]).success).toBe(false);
        for (const earlier of payload.slice(0, vector.invalidElementIndex)) {
          expect(grantSchema.safeParse(earlier).success).toBe(true);
        }
      }
    }
  );

  it("refuses the PN-Grants delivery of a chain it accepts as a token", () => {
    // The pair that states the prefix rule in bytes: one payload, two prefixes, one verdict
    // each. Sharing the payload is deliberate; sharing the delivery is not.
    const accepted = vectors.find((vector) => vector.accept);
    const headerForm = vectors.find(
      (vector) => vector.name === "refused — the PN-Grants header form of the same chain"
    );
    if (!accepted || !headerForm) {
      throw new Error("The prefix pair is missing from the fixture");
    }

    const payload = accepted.token.slice(CHAIN_ACCESS_TOKEN_PREFIX.length);
    expect(headerForm.token).toBe(`1:${payload}`);
    // The payload really is readable — it is only the delivery that is refused.
    expect(decodeChainAccessToken(`${CHAIN_ACCESS_TOKEN_PREFIX}${payload}`)).toEqual(
      accepted.chain
    );
  });
});
