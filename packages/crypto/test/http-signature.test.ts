import type { Grant } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  contentDigest,
  createIdentity,
  decodeGrantsHeader,
  encodeGrantsHeader,
  encodeKeyRef,
  generateNonce,
  rotateIdentity,
  signRequest,
  VerificationBudgetExceeded,
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
  const keys = [encodeKeyRef(identity.currentKeys[0]!.publicKey)];
  return { identity, body, headers, keys };
}

describe("RFC 9421 write-auth profile (spec 004)", () => {
  it("round-trips: a signed request verifies against the signer's key", () => {
    const { identity, body, headers, keys } = signedFixture();

    const verified = verifyRequest({
      method: "PUT",
      url: URL_UNDER_TEST,
      body,
      headers,
      keys,
      now: NOW
    });

    expect(verified.keyId).toBe(identity.id);
    expect(verified.created).toBe(NOW);
    expect(verified.nonce).toBeTruthy();
  });

  it("meters every RFC 9421 key probe, including the satisfying key", () => {
    const { body, headers, keys } = signedFixture();
    const decoys = Array.from({ length: 3 }, () =>
      encodeKeyRef(createIdentity().currentKeys[0]!.publicKey)
    );
    let spent = 0;
    expect(
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys: [...decoys, ...keys],
        now: NOW,
        onSignatureVerifications: (count) => (spent += count)
      }).satisfiedKey
    ).toBe(keys[0]);
    expect(spent).toBe(4);
  });

  it("refuses before a request-signature curve check when the meter is zero", () => {
    const { body, headers, keys } = signedFixture();
    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: NOW,
        maxSignatureVerifications: 0
      })
    ).toThrow(VerificationBudgetExceeded);
  });

  it("rejects a tampered body via the content digest", () => {
    const { headers, keys } = signedFixture();

    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body: JSON.stringify({ hello: "tampered" }),
        headers,
        keys,
        now: NOW
      })
    ).toThrow(/Content-Digest/);
  });

  it("rejects a request replayed against a different method or target", () => {
    const { body, headers, keys } = signedFixture();

    expect(() =>
      verifyRequest({ method: "DELETE", url: URL_UNDER_TEST, body, headers, keys, now: NOW })
    ).toThrow(/does not verify/);
    expect(() =>
      verifyRequest({
        method: "PUT",
        url: "http://localhost/participants/pk_z2/key-log",
        body,
        headers,
        keys,
        now: NOW
      })
    ).toThrow(/does not verify/);
  });

  it("rejects a signature from a key outside the current key set", () => {
    const { body, headers } = signedFixture();
    const other = createIdentity();

    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys: [encodeKeyRef(other.currentKeys[0]!.publicKey)],
        now: NOW
      })
    ).toThrow(/does not verify/);
  });

  it("rejects a rotated-away key", () => {
    const identity = createIdentity();
    const body = "{}";
    const headers = signRequest({
      method: "PUT",
      url: URL_UNDER_TEST,
      body,
      keyId: identity.id,
      secretKey: identity.currentKeys[0]!.secretKey,
      created: NOW
    });

    const rotated = rotateIdentity(identity);
    const currentKeys = [encodeKeyRef(rotated.currentKeys[0]!.publicKey)];

    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys: currentKeys,
        now: NOW
      })
    ).toThrow(/does not verify/);
  });

  it("rejects created times outside the clock-skew window", () => {
    const { body, headers, keys } = signedFixture();

    expect(() =>
      verifyRequest({ method: "PUT", url: URL_UNDER_TEST, body, headers, keys, now: NOW + 3600 })
    ).toThrow(/clock-skew/);
    expect(() =>
      verifyRequest({ method: "PUT", url: URL_UNDER_TEST, body, headers, keys, now: NOW - 3600 })
    ).toThrow(/clock-skew/);
  });

  it("rejects missing or malformed signature headers", () => {
    const { body, headers, keys } = signedFixture();
    const base = { method: "PUT", url: URL_UNDER_TEST, body, keys, now: NOW };

    expect(() => verifyRequest({ ...base, headers: {} })).toThrow(/Missing/);
    expect(() =>
      verifyRequest({ ...base, headers: { ...headers, "signature-input": "sig1=bogus" } })
    ).toThrow(/profile/);
    expect(() =>
      verifyRequest({ ...base, headers: { ...headers, signature: "sig1=bogus" } })
    ).toThrow(/profile/);
  });

  it("emits an RFC 9530 content digest", () => {
    expect(contentDigest("{}")).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/);
  });

  it("returns the KeyRef that actually satisfied the signature (spec 013)", () => {
    // Two-key set: only one can verify, and that's the one we should get back so a
    // stream can later check "is this key still in the current state after a rotation".
    const owner = createIdentity();
    const decoy = createIdentity();
    const body = JSON.stringify({ hello: "world" });
    const headers = signRequest({
      method: "PUT",
      url: URL_UNDER_TEST,
      body,
      keyId: owner.id,
      secretKey: owner.currentKeys[0]!.secretKey,
      created: NOW,
      nonce: generateNonce()
    });
    const ownerKey = encodeKeyRef(owner.currentKeys[0]!.publicKey);
    const decoyKey = encodeKeyRef(decoy.currentKeys[0]!.publicKey);

    const verified = verifyRequest({
      method: "PUT",
      url: URL_UNDER_TEST,
      body,
      headers,
      keys: [decoyKey, ownerKey],
      now: NOW
    });

    expect(verified.satisfiedKey).toBe(ownerKey);
  });
});

describe("the request threshold is parsed, never coerced (spec 015 S1, spec 004)", () => {
  function verifyAtThreshold(threshold: string | undefined) {
    const { body, headers, keys } = signedFixture();
    return verifyRequest({
      method: "PUT",
      url: URL_UNDER_TEST,
      body,
      headers,
      keys,
      now: NOW,
      ...(threshold === undefined ? {} : { threshold })
    });
  }

  it.each(["abc", "", "0", "01", "1e1", " 1", "1.0", "+1", "-1", "0x1"])(
    "refuses the malformed threshold %j",
    (threshold) => {
      // `Number()` sends all of these to NaN, 0, 1 or -1, and `NaN > 1` is FALSE — so the old
      // coercion let a request presenting an unparseable threshold verify as if it were 1-of-1.
      // A fail-open shape, refused now rather than argued to be unreachable.
      expect(() => verifyAtThreshold(threshold)).toThrow(
        /is not a decimal string matching \^\[1-9\]\[0-9\]\*\$/
      );
    }
  );

  it("accepts the one threshold this profile supports", () => {
    expect(verifyAtThreshold("1").keyId).toBeTruthy();
    // Absent means 1-of-1, unchanged: the overwhelming majority of callers pass nothing.
    expect(verifyAtThreshold(undefined).keyId).toBeTruthy();
  });

  it("still refuses a well-formed multi-signature threshold as unsupported", () => {
    // The two refusals stay distinct: "2" is a threshold this profile cannot honour, not a
    // malformed one, and the messages must not converge — finding 7 is about "2".
    expect(() => verifyAtThreshold("2")).toThrow(/Multi-signature thresholds are not yet/);
    expect(() => verifyAtThreshold("2")).not.toThrow(/is not a decimal string/);
  });
});

function grantFixture(overrides: Partial<Grant> = {}): Grant {
  return {
    subjectId: "pk_z6MkSubject1111",
    issuerId: "pk_z6MkSubject1111",
    audienceId: "z6MkSessionKey1111",
    abilities: ["msg/send"],
    caveats: { aud: "pk_z6MkVerifier1111" },
    proof: null,
    // Spec 016: a participant-issued link names the key state it was signed under. Shape-valid
    // rather than resolvable — these tests cover request signing, not grant verification.
    anchor: "zQmYwAPJzv5CZsnAzt8auVZRnHEKzKgUEdy3W35nUSpS6kq",
    issuedAt: "2026-07-21T12:00:00.000Z",
    expiresAt: "2026-07-28T12:00:00.000Z",
    signature: ["z2SignatureBytes1111"],
    ...overrides
  };
}

function delegatedFixture(chain: Grant[] = [grantFixture()]) {
  const identity = createIdentity();
  const body = JSON.stringify({ hello: "world" });
  const headers = signRequest({
    method: "PUT",
    url: URL_UNDER_TEST,
    body,
    keyId: identity.id,
    secretKey: identity.currentKeys[0]!.secretKey,
    created: NOW,
    nonce: generateNonce(),
    grants: chain
  });
  const keys = [encodeKeyRef(identity.currentKeys[0]!.publicKey)];
  return { identity, body, headers, keys, chain };
}

describe("freshness inputs are validated, not trusted", () => {
  it("refuses a NaN skew instead of silently disabling the freshness check", () => {
    // `Math.abs(now - created) > NaN` is false for EVERY input, so an unvalidated NaN skew
    // does not widen the window — it removes it. A signature of any age would verify, and
    // the derived nonce TTL would be NaN, so entries would be forgotten as soon as written.
    const { body, headers, keys } = signedFixture();

    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: NOW,
        maxSkewSeconds: Number.NaN
      })
    ).toThrow(/whole number of seconds/);
  });

  it("refuses a non-integer, infinite or negative skew", () => {
    const { body, headers, keys } = signedFixture();
    for (const bad of [Number.POSITIVE_INFINITY, -1, 0.5]) {
      expect(() =>
        verifyRequest({
          method: "PUT",
          url: URL_UNDER_TEST,
          body,
          headers,
          keys,
          now: NOW,
          maxSkewSeconds: bad
        })
      ).toThrow(/whole number of seconds/);
    }
  });

  it("refuses an unusable clock", () => {
    // Same failure shape from the other input: a NaN `now` makes the skew comparison false.
    const { body, headers, keys } = signedFixture();
    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: Number.NaN
      })
    ).toThrow(/whole number of seconds/);
  });

  it("still accepts a zero skew, which is valid and exercised by the TTL derivation", () => {
    const { body, headers, keys } = signedFixture();
    expect(
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: NOW,
        maxSkewSeconds: 0
      }).created
    ).toBe(NOW);
  });
});

describe("delegated requests carry a covered grant chain (spec 011)", () => {
  it("round-trips: a request signed with grants verifies and the chain decodes", () => {
    const { identity, body, headers, keys, chain } = delegatedFixture();

    expect(headers["signature-input"]).toContain('"pn-grants"');
    expect(headers["pn-grants"]).toBeDefined();

    const verified = verifyRequest({
      method: "PUT",
      url: URL_UNDER_TEST,
      body,
      headers,
      keys,
      now: NOW,
      grantsHeader: headers["pn-grants"]
    });

    expect(verified.keyId).toBe(identity.id);
    expect(decodeGrantsHeader(headers["pn-grants"]!)).toEqual(chain);
  });

  it("rejects a chain swapped after signing", () => {
    const { body, headers, keys } = delegatedFixture();
    const otherChain = [grantFixture({ abilities: ["msg/read"] })];

    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: NOW,
        grantsHeader: encodeGrantsHeader(otherChain)
      })
    ).toThrow(/does not verify/);
  });

  it("rejects a grants header the signature does not cover", () => {
    const { body, headers, keys } = signedFixture();

    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: NOW,
        grantsHeader: encodeGrantsHeader([grantFixture()])
      })
    ).toThrow(/not covered/);
  });

  it("rejects a signature claiming pn-grants coverage without the header", () => {
    const { body, headers, keys } = delegatedFixture();

    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: NOW
      })
    ).toThrow(/no PN-Grants header/);
  });

  it("still rejects tampering with the other covered parts", () => {
    const { body, headers, keys } = delegatedFixture();
    const grantsHeader = headers["pn-grants"];

    expect(() =>
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body: JSON.stringify({ hello: "tampered" }),
        headers,
        keys,
        now: NOW,
        grantsHeader
      })
    ).toThrow(/Content-Digest/);
    expect(() =>
      verifyRequest({
        method: "DELETE",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: NOW,
        grantsHeader
      })
    ).toThrow(/does not verify/);
    expect(() =>
      verifyRequest({
        method: "PUT",
        url: "http://localhost/participants/pk_z2/key-log",
        body,
        headers,
        keys,
        now: NOW,
        grantsHeader
      })
    ).toThrow(/does not verify/);
  });

  it("rejects signing with an empty chain", () => {
    const identity = createIdentity();

    expect(() =>
      signRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body: "{}",
        keyId: identity.id,
        secretKey: identity.currentKeys[0]!.secretKey,
        created: NOW,
        grants: []
      })
    ).toThrow(/empty/);
  });

  it("regression: a grant-free request still verifies with grantsHeader undefined", () => {
    const { body, headers, keys } = signedFixture();

    expect(headers["pn-grants"]).toBeUndefined();
    expect(headers["signature-input"]).not.toContain("pn-grants");
    expect(
      verifyRequest({
        method: "PUT",
        url: URL_UNDER_TEST,
        body,
        headers,
        keys,
        now: NOW,
        grantsHeader: undefined
      })
    ).toBeTruthy();
  });
});
