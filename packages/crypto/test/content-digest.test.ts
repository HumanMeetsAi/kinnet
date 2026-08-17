/**
 * The spec 004 write-auth profile's RFC 9530 `Content-Digest`: computed over the CONTENT
 * OCTETS as transmitted, never over a decoded form of them.
 *
 * The fixture is the artifact:
 * `packages/crypto/test/fixtures/content-digest-vectors.json` carries, for each delivery, the
 * raw octets (base64), the exact header value a conforming implementation must produce, what
 * a lenient UTF-8 decode turns those octets into, and the digest a text-normalizing
 * implementation computes instead. A second implementation can check itself against those
 * bytes with a base64 decoder and a SHA-256, without running this file. What this file checks
 * is that the fixture TELLS THE TRUTH — every recorded fact is recomputed here — and that
 * `contentDigest`, `signRequest` and `verifyRequest` behave the way it says.
 *
 * THE MUTATION THESE TESTS CATCH: digesting text instead of octets — either narrowing
 * `contentDigest` back to a `string` parameter (`packages/crypto/src/http-signature.ts`), or
 * leaving it byte-capable while a caller decodes first, which is the shape the defect
 * actually had (`@kinnet/verify`'s adapters called `Request.text()` and `TextDecoder.decode`
 * before handing the body over). WATCHED TO FAIL that way — restore it by making
 * `contentDigest` re-encode a decoded copy of its input, and four assertions here break: the
 * two distinguishing vectors' recomputed digests, `rejects a delivery that decodes to the
 * signed text but is not the signed bytes`, and the tampered half of the binary round trip.
 * The three control vectors do NOT catch that mutation and are not claimed to — they exist so
 * the suite cannot pass vacuously and so "non-ASCII" cannot be mistaken for "the problem".
 */
import { readFileSync } from "node:fs";

import { sha256 } from "@noble/hashes/sha2.js";
import { base64 } from "@scure/base";
import { describe, expect, it } from "vitest";

import {
  ContentDigestMismatchError,
  contentDigest,
  generateKeyPair,
  signRequest,
  verifyRequest,
  encodeKeyRef
} from "../src/index.js";

type Vector = {
  name: string;
  why: string;
  bodyBase64: string;
  contentDigest: string;
  wellFormedUtf8: boolean;
  decodedText: string;
  digestOverDecodedText: string;
  distinguishesTextFromBytes: boolean;
};

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/content-digest-vectors.json", import.meta.url), "utf8")
) as {
  note: string;
  attackPair: { signed: string; delivered: string; sharedDecodedText: string; note: string };
  vectors: Vector[];
};

const { vectors, attackPair } = fixture;

const encoder = new TextEncoder();
const lenient = new TextDecoder("utf-8");
const strict = new TextDecoder("utf-8", { fatal: true });

const byName = (name: string): Vector => {
  const found = vectors.find((vector) => vector.name === name);
  if (!found) {
    throw new Error(`The fixture has no vector named ${JSON.stringify(name)}`);
  }
  return found;
};

const TARGET = "https://api.example.com/participants/z6Mk/records";
const NOW = 1_700_000_000;

describe("content-digest conformance vectors", () => {
  it("is non-vacuous: it contains both agreeing and disagreeing deliveries", () => {
    // A fixture of controls alone would pass under the broken implementation, and a fixture
    // of attacks alone would not prove the fix costs nothing legitimate.
    const distinguishing = vectors.filter((vector) => vector.distinguishesTextFromBytes);
    const agreeing = vectors.filter((vector) => !vector.distinguishesTextFromBytes);
    expect(distinguishing.length).toBeGreaterThanOrEqual(2);
    expect(agreeing.length).toBeGreaterThanOrEqual(2);
    // Every digest is distinct: no two of these deliveries may share a header value.
    expect(new Set(vectors.map((vector) => vector.contentDigest)).size).toBe(vectors.length);
  });

  it.each(vectors.map((vector) => [vector.name, vector] as const))("%s", (_name, vector) => {
    const octets = base64.decode(vector.bodyBase64);

    // Recomputed from the bytes rather than trusted: `sha-256=:<base64 of SHA-256>:`.
    expect(vector.contentDigest).toBe(`sha-256=:${base64.encode(sha256(octets))}:`);
    // …and that is what the implementation produces for those exact octets.
    expect(contentDigest(octets)).toBe(vector.contentDigest);

    // The recorded decode facts.
    expect(lenient.decode(octets)).toBe(vector.decodedText);
    let decodesStrictly = true;
    try {
      strict.decode(octets);
    } catch {
      decodesStrictly = false;
    }
    expect(decodesStrictly).toBe(vector.wellFormedUtf8);

    // What a text-normalizing implementation would compute, and whether it disagrees.
    expect(contentDigest(encoder.encode(vector.decodedText))).toBe(vector.digestOverDecodedText);
    expect(vector.distinguishesTextFromBytes).toBe(
      vector.contentDigest !== vector.digestOverDecodedText
    );

    // String and bytes are the same input whenever the bytes ARE the UTF-8 of the text: the
    // sender-side convenience the profile allows, pinned per vector rather than in prose.
    if (vector.wellFormedUtf8) {
      expect(contentDigest(vector.decodedText)).toBe(vector.contentDigest);
    }
  });

  it("records an attack pair that shares one decoded text and two digests", () => {
    const signed = byName(attackPair.signed);
    const delivered = byName(attackPair.delivered);

    expect(signed.decodedText).toBe(attackPair.sharedDecodedText);
    expect(delivered.decodedText).toBe(attackPair.sharedDecodedText);
    expect(signed.bodyBase64).not.toBe(delivered.bodyBase64);
    expect(signed.contentDigest).not.toBe(delivered.contentDigest);

    // The equality that IS the vulnerability: digesting the decoded text of the substituted
    // delivery reproduces the signed delivery's header value exactly.
    expect(delivered.digestOverDecodedText).toBe(signed.contentDigest);

    // And the substitution really is the one the finding describes: three octets (the UTF-8
    // encoding of U+FFFD) replaced by one that is not UTF-8 at all.
    const signedOctets = base64.decode(signed.bodyBase64);
    const deliveredOctets = base64.decode(delivered.bodyBase64);
    expect(signedOctets.length - deliveredOctets.length).toBe(2);
    expect([...signedOctets]).toContain(0xef);
    expect([...deliveredOctets]).toContain(0xff);
  });
});

describe("signed bytes are the delivered bytes", () => {
  const identity = generateKeyPair();
  const keyId = "z6MkfakeParticipantIdForTests";
  const keys = [encodeKeyRef(identity.publicKey)];

  const sign = (body: string | Uint8Array) =>
    signRequest({
      method: "POST",
      url: TARGET,
      body,
      keyId,
      secretKey: identity.secretKey,
      created: NOW
    });

  const verifyWith = (headers: Record<string, string | undefined>, body: string | Uint8Array) =>
    verifyRequest({ method: "POST", url: TARGET, body, headers, keys, now: NOW });

  it("rejects a delivery that decodes to the signed text but is not the signed bytes", () => {
    // THE REGRESSION TEST FOR THE FINDING. The sender signs a body containing a legitimate
    // U+FFFD; an intermediary replaces those three octets with the single invalid octet FF.
    const signed = base64.decode(byName(attackPair.signed).bodyBase64);
    const delivered = base64.decode(byName(attackPair.delivered).bodyBase64);
    const headers = sign(signed);

    // The premise: the two deliveries are indistinguishable ONCE DECODED. This is what the
    // old implementation compared, and why it could not tell them apart.
    expect(lenient.decode(delivered)).toBe(lenient.decode(signed));
    expect(delivered).not.toEqual(signed);

    expect(() => verifyWith(headers, delivered)).toThrow(ContentDigestMismatchError);
    // The old behaviour, stated as an assertion rather than a comment: had the verifier
    // digested the decoded text, this substitution would have passed.
    expect(contentDigest(lenient.decode(delivered))).toBe(headers["content-digest"]);
  });

  it("accepts the byte-identical delivery", () => {
    // The inverse of the vector above: the fix must reject only the substitution. Same body,
    // same signature, no U+FFFD special-casing anywhere.
    const signed = base64.decode(byName(attackPair.signed).bodyBase64);
    const headers = sign(signed);
    expect(verifyWith(headers, signed)).toMatchObject({ keyId, created: NOW });
  });

  it("round-trips a binary body that is not UTF-8 at all", () => {
    // The half of the defect that needs no attacker: a text-only digest cannot cover binary
    // content, so this could not be signed faithfully before the fix.
    const body = base64.decode(
      byName("binary — all 256 byte values, which is not text at all").bodyBase64
    );
    const headers = sign(body);
    expect(verifyWith(headers, body)).toMatchObject({ keyId });
    // One flipped octet must break it, and the flip is invisible to a decoder: byte 0xC0 at
    // index 192 is malformed UTF-8 and so is 0xC1, so both decode to the same U+FFFD.
    const tampered = Uint8Array.from(body);
    tampered[192] = 0xc1;
    expect(lenient.decode(tampered)).toBe(lenient.decode(body));
    expect(() => verifyWith(headers, tampered)).toThrow(ContentDigestMismatchError);
  });

  it("verifies a string-signed request against its exact UTF-8 bytes, and the reverse", () => {
    // The two input forms are cross-compatible, which is what lets a sender keep passing the
    // string it transmits while every verifier works in octets.
    const text = '{"note":"héllo 世界 🌍"}';
    const octets = encoder.encode(text);

    expect(verifyWith(sign(text), octets)).toMatchObject({ keyId });
    expect(verifyWith(sign(octets), text)).toMatchObject({ keyId });
    expect(contentDigest(text)).toBe(contentDigest(octets));
  });

  it("digests the empty string and zero octets alike", () => {
    // The profile covers `content-digest` unconditionally, GETs included, so the bodyless
    // convention has to agree across adapters — `@kinnet/verify` passes zero octets where the
    // SDK signs `""`.
    expect(contentDigest("")).toBe(contentDigest(new Uint8Array(0)));
    expect(verifyWith(sign(""), new Uint8Array(0))).toMatchObject({ keyId });
  });
});
