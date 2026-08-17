/**
 * The two rejections `verifyRequest` raises with a class of their own, and the base class the
 * rest share. What is under test is the CLASS, not the message: the whole point of the split is
 * that a relying party can narrow without matching on message text, so these assertions are
 * written the way a consumer would have to write them.
 */
import { describe, expect, it } from "vitest";

import {
  ContentDigestMismatchError,
  createIdentity,
  DEFAULT_MAX_SKEW_SECONDS,
  encodeKeyRef,
  generateNonce,
  RequestSignatureError,
  signRequest,
  SignatureStaleError,
  verifyRequest
} from "../src/index.js";

const URL_UNDER_TEST = "http://localhost/participants/pk_z1/key-log";
const NOW = 1_780_000_000;

function signedFixture() {
  const identity = createIdentity();
  const body = JSON.stringify({ hello: "world" });
  const headers = signRequest({
    method: "PUT",
    url: URL_UNDER_TEST,
    body,
    keyId: identity.id,
    secretKey: identity.currentKeys[0]!.secretKey,
    created: NOW,
    nonce: generateNonce()
  });
  return { identity, body, headers, keys: [encodeKeyRef(identity.currentKeys[0]!.publicKey)] };
}

function rejectionOf(options: Parameters<typeof verifyRequest>[0]): unknown {
  try {
    verifyRequest(options);
  } catch (error) {
    return error;
  }
  throw new Error("expected verifyRequest to reject");
}

describe("verifyRequest rejections are typed", () => {
  it("throws SignatureStaleError when created is outside the skew window", () => {
    const { body, headers, keys } = signedFixture();

    // BOTH DIRECTIONS. A caller whose clock runs fast is the same operational problem as one
    // whose receipt sat in a queue, and only the sign of the drift differs; a check written for
    // one direction would let the other keep reporting as a bad signature.
    for (const now of [NOW + DEFAULT_MAX_SKEW_SECONDS + 1, NOW - DEFAULT_MAX_SKEW_SECONDS - 1]) {
      const thrown = rejectionOf({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now
      });

      expect(thrown).toBeInstanceOf(SignatureStaleError);
      expect(thrown).toBeInstanceOf(RequestSignatureError);
      expect(thrown).toBeInstanceOf(Error);
      expect(thrown).not.toBeInstanceOf(ContentDigestMismatchError);
      expect((thrown as Error).message).toMatch(/clock-skew window/);
    }
  });

  it("admits the exact edges of the window: freshness is inclusive at both ends", () => {
    const { body, headers, keys } = signedFixture();

    // Load-bearing for the nonce TTL, which is derived as `2 * skew + 1` precisely because a
    // signature minted at `created = t + skew` is still fresh at `t + 2 * skew`. If either edge
    // rejected here, that derivation would be retaining nonces past any signature's life.
    for (const now of [NOW + DEFAULT_MAX_SKEW_SECONDS, NOW - DEFAULT_MAX_SKEW_SECONDS]) {
      expect(() =>
        verifyRequest({ method: "PUT", url: URL_UNDER_TEST, body, headers, keys, now })
      ).not.toThrow();
    }
  });

  it("honours maxSkewSeconds: the same request is stale or fresh depending on the window", () => {
    const { body, headers, keys } = signedFixture();
    const request = { method: "PUT", url: URL_UNDER_TEST, body, headers, keys, now: NOW + 300 };

    expect(rejectionOf(request)).toBeInstanceOf(SignatureStaleError);
    expect(() => verifyRequest({ ...request, maxSkewSeconds: 600 })).not.toThrow();
  });

  it("throws ContentDigestMismatchError when the body was rewritten under the signature", () => {
    const { headers, keys } = signedFixture();

    const thrown = rejectionOf({
      method: "PUT",
      url: URL_UNDER_TEST,
      // What a re-encoding proxy produces: the same fields, different bytes.
      body: JSON.stringify({ hello: "world!" }),
      headers,
      keys,
      now: NOW
    });

    expect(thrown).toBeInstanceOf(ContentDigestMismatchError);
    expect(thrown).toBeInstanceOf(RequestSignatureError);
    expect(thrown).not.toBeInstanceOf(SignatureStaleError);
    expect((thrown as Error).message).toMatch(/Content-Digest does not match/);
  });

  it("leaves an ordinary signature failure on the base class only", () => {
    const { body, headers } = signedFixture();

    // Fresh, digest-matching, well-formed — and checked against somebody else's key. Neither
    // subclass may claim it, or the two specific diagnoses stop meaning anything.
    const thrown = rejectionOf({
      method: "PUT",
      url: URL_UNDER_TEST,
      body,
      headers,
      keys: [encodeKeyRef(createIdentity().currentKeys[0]!.publicKey)],
      now: NOW
    });

    expect(thrown).toBeInstanceOf(RequestSignatureError);
    expect(thrown).not.toBeInstanceOf(SignatureStaleError);
    expect(thrown).not.toBeInstanceOf(ContentDigestMismatchError);
  });

  it("puts every profile rejection on the base class", () => {
    const { body, headers, keys } = signedFixture();
    const base = { method: "PUT", url: URL_UNDER_TEST, body, keys, now: NOW };

    const cases: Record<string, string | undefined>[] = [
      { ...headers, "content-digest": undefined },
      { ...headers, "signature-input": 'sig1=("@method");created=1;keyid="x";nonce="y"' },
      { ...headers, signature: "sig1=:not-base64!:" }
    ];
    for (const brokenHeaders of cases) {
      expect(rejectionOf({ ...base, headers: brokenHeaders })).toBeInstanceOf(
        RequestSignatureError
      );
    }
  });

  it("checks freshness ahead of any signature work, so a stale request costs nothing", () => {
    const { body, headers, keys } = signedFixture();
    let spent = -1;

    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: NOW + DEFAULT_MAX_SKEW_SECONDS + 1,
        onSignatureVerifications: (count) => (spent = count)
      })
    ).toThrow(SignatureStaleError);

    // The reporting callback lives in the key-probe loop's `finally`, which a stale request
    // never reaches. An unauthenticated caller therefore cannot spend this verifier's Ed25519
    // budget merely by replaying an expired receipt.
    expect(spent).toBe(-1);
  });
});
