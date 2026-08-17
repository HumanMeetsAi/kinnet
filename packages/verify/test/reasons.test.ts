/**
 * The rejection vocabulary: that it is a CLOSED, classified set, and that the two reasons split
 * out of `signature_invalid` actually reach a caller.
 *
 * The split is the substance. `verifyRequest` throws for a dozen distinct causes and this
 * package caught all of them and answered `signature_invalid`, so a caller whose clock had
 * drifted and a caller whose proxy had re-encoded the body were told the same untrue thing —
 * that their key was wrong. Two of those causes have a different remedy and now have a reason of
 * their own; everything else keeps the old reason, which is the other half of the contract and
 * is asserted here too.
 *
 * The union's own consistency is proved at COMPILE TIME in `errors.ts` (`SameSet` assertions, the
 * convention `@kinnet/trust`'s `CostReasonsAreClassified` established). What a runtime test can
 * add is the part types cannot see: that the value list and the predicate agree with the reasons
 * the verifier actually produces, and that no reason is classified into the wrong HTTP class.
 */
import {
  createIdentity,
  DEFAULT_MAX_SKEW_SECONDS,
  signRequest,
  type Identity
} from "@kinnet/crypto";
import type { KeyEvent } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  createStaticTrustView,
  createVerifier,
  isVerifyAuthReason,
  isVerifyCapacityReason,
  KNOWN_VERIFY_REASONS,
  VERIFY_CAPACITY_REASONS,
  VerifyCapacityError,
  VerifyError,
  type KnownVerifyReason,
  type VerifyReason
} from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const NOW = new Date("2026-06-12T00:00:00.000Z");
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);
const TARGET = "https://api.example.com/quote";

const agent = createIdentity({ currentSeed: seed(11), nextSeed: seed(12) });

/**
 * Offline throughout. These tests are about which REASON comes out, and a discovery fetch stub
 * would only add a second thing that could fail; the static view removes it entirely.
 */
function offlineVerifier(logs: KeyEvent[][] = [agent.log]) {
  return createVerifier({ view: createStaticTrustView({ keyLogs: logs }), now: () => NOW });
}

function signedRequest(signer: Identity, body = '{"want":"quote"}', created = NOW_SECONDS) {
  const headers = signRequest({
    method: "POST",
    url: TARGET,
    body,
    keyId: signer.id,
    secretKey: signer.currentKeys[0]!.secretKey,
    created
  });
  return { method: "POST", url: TARGET, headers: { ...headers }, body };
}

describe("signature_invalid is split into three distinguishable causes", () => {
  it("reports a receipt minted outside the skew window as signature_stale", async () => {
    const verifier = offlineVerifier();

    const rejection = await verifier
      .verify(signedRequest(agent, "{}", NOW_SECONDS - DEFAULT_MAX_SKEW_SECONDS - 1))
      .catch((error: unknown) => error);

    expect(rejection).toBeInstanceOf(VerifyError);
    expect(rejection).not.toBeInstanceOf(VerifyCapacityError);
    expect((rejection as VerifyError).reason).toBe("signature_stale");
    // 401-class: a stale request is still refused. What changed is that the caller can now tell
    // "resign this" from "your credentials are wrong" without parsing a message.
    expect((rejection as VerifyError).status).toBe(401);
    expect(isVerifyCapacityReason("signature_stale")).toBe(false);
  });

  it("reports a future-dated receipt as signature_stale too", async () => {
    // The other sign of the same drift. A verifier that only caught the past-dated arm would
    // still be misreporting the caller whose clock runs fast.
    const verifier = offlineVerifier();

    await expect(
      verifier.verify(signedRequest(agent, "{}", NOW_SECONDS + DEFAULT_MAX_SKEW_SECONDS + 1))
    ).rejects.toMatchObject({ reason: "signature_stale", status: 401 });
  });

  it("stops reporting stale as stale once maxSkewSeconds admits it", async () => {
    // Pins the reason to the CONFIGURED window rather than to the default constant: the same
    // request that is stale at ±120 s verifies at ±600 s.
    const stale = signedRequest(agent, "{}", NOW_SECONDS - 300);
    const view = createStaticTrustView({ keyLogs: [agent.log] });

    await expect(createVerifier({ view, now: () => NOW }).verify(stale)).rejects.toMatchObject({
      reason: "signature_stale"
    });
    await expect(
      createVerifier({ view, now: () => NOW, maxSkewSeconds: 600 }).verify(stale)
    ).resolves.toMatchObject({ agentId: agent.id });
  });

  it("reports a body that does not match its digest as content_digest_mismatch", async () => {
    const verifier = offlineVerifier();
    const request = signedRequest(agent);

    await expect(verifier.verify({ ...request, body: '{"want":"refund"}' })).rejects.toMatchObject({
      reason: "content_digest_mismatch",
      status: 401
    });
  });

  it("still reports an unverifiable signature as signature_invalid", async () => {
    // The regression half. Only the two causes with a different remedy moved; everything else
    // keeps the reason callers already handle, or this change breaks every existing consumer.
    const verifier = offlineVerifier();
    const request = signedRequest(agent);

    await expect(
      verifier.verify({
        ...request,
        headers: { ...request.headers, signature: "sig1=:AAAAAAAAAAAAAAAAAAAAAA==:" }
      })
    ).rejects.toMatchObject({ reason: "signature_invalid", status: 401 });
  });

  it("still reports a malformed Signature-Input as signature_invalid", async () => {
    const verifier = offlineVerifier();
    const request = signedRequest(agent);

    // The keyid stays VALID and stays the agent's. A junk keyid is classified earlier, as
    // `keyid_invalid`, before `verifyRequest` is reached at all — so a header carrying one would
    // test that path instead of this one. What is broken here is the covered-component list,
    // which is what the spec 004 profile pins.
    await expect(
      verifier.verify({
        ...request,
        headers: {
          ...request.headers,
          "signature-input": `sig1=("@method");created=${NOW_SECONDS};keyid="${agent.id}";nonce="abc"`
        }
      })
    ).rejects.toMatchObject({ reason: "signature_invalid" });
  });

  it("pins the order when a request is both stale AND digest-mismatched", async () => {
    // Both are wrong at once, and exactly one reason comes back — so which one is a contract,
    // not an accident. `verifyRequest` checks the digest before it parses `Signature-Input`, so
    // the DIGEST wins; a caller diagnosing a doubly-broken request should not see the answer
    // change because an unrelated check was reordered.
    //
    // Pinned rather than endorsed: both checks precede every Ed25519 verification, so neither
    // order lets an unauthenticated caller spend the signature budget, and the choice between
    // them is a diagnostic one.
    const verifier = offlineVerifier();
    const request = signedRequest(agent, '{"want":"quote"}', NOW_SECONDS - 3600);

    await expect(verifier.verify({ ...request, body: "{}" })).rejects.toMatchObject({
      reason: "content_digest_mismatch"
    });
  });
});

describe("the reason vocabulary is closed and classified", () => {
  it("lists both new reasons, so a consumer enumerating the vocabulary sees them", () => {
    expect(KNOWN_VERIFY_REASONS).toContain("signature_stale");
    expect(KNOWN_VERIFY_REASONS).toContain("content_digest_mismatch");
  });

  it("has no duplicate entries in either list", () => {
    // A duplicate would pass the compile-time `SameSet` proof — a union does not count
    // multiplicity — while making `KNOWN_VERIFY_REASONS.length` a lie for anyone iterating it.
    expect(new Set(KNOWN_VERIFY_REASONS).size).toBe(KNOWN_VERIFY_REASONS.length);
    expect(new Set(VERIFY_CAPACITY_REASONS).size).toBe(VERIFY_CAPACITY_REASONS.length);
  });

  it("makes the capacity list a strict subset of the full list", () => {
    for (const reason of VERIFY_CAPACITY_REASONS) {
      expect(KNOWN_VERIFY_REASONS).toContain(reason);
    }
    expect(VERIFY_CAPACITY_REASONS.length).toBeLessThan(KNOWN_VERIFY_REASONS.length);
  });

  it("classifies every known reason into exactly one of the two HTTP classes", () => {
    // The predicates must partition. A reason matching both, or neither, means a surface
    // answering 401/503 from them has a case it cannot decide.
    for (const reason of KNOWN_VERIFY_REASONS) {
      expect(isVerifyCapacityReason(reason)).toBe(!isVerifyAuthReason(reason));
      expect(isVerifyCapacityReason(reason)).toBe(
        (VERIFY_CAPACITY_REASONS as readonly string[]).includes(reason)
      );
    }
  });

  it("catches cost-shaped reasons the resolver forwards, which no list here enumerates", () => {
    // The suffix arm. `createVerifier` re-throws `@kinnet/trust`'s reasons VERBATIM, and that
    // package grows new `*_too_expensive` reasons on its own schedule — so this arm is a suffix
    // test precisely so it cannot go stale. A consumer classifying only by membership in
    // VERIFY_CAPACITY_REASONS would answer 401 for a chain the verifier refused on cost.
    expect(isVerifyCapacityReason("grant_issuer_key_log_too_expensive")).toBe(true);
    expect(isVerifyCapacityReason("grant_signature_check_too_expensive")).toBe(true);
    expect(isVerifyCapacityReason("a_reason_invented_tomorrow_too_expensive")).toBe(true);
    // ...and does not over-reach: an ordinary resolver rejection stays 401.
    expect(isVerifyCapacityReason("grant_expired")).toBe(false);
    expect(isVerifyCapacityReason("grant_revoked")).toBe(false);
  });

  it("agrees with the status each class of error actually carries", () => {
    for (const reason of KNOWN_VERIFY_REASONS) {
      const error = isVerifyCapacityReason(reason)
        ? new VerifyCapacityError(reason)
        : new VerifyError(reason);
      expect(error.status).toBe(isVerifyCapacityReason(reason) ? 503 : 401);
    }
  });
});

describe("the reason union is usable as a type", () => {
  it("admits both arms and rejects nothing a verifier can produce", () => {
    // A COMPILE-TIME assertion wearing a test's clothes: the value of this block is that it
    // fails `tsc`, not that it fails vitest. Both arms of `VerifyReason` are exercised — this
    // package's own vocabulary and the resolver reasons forwarded verbatim — because typing only
    // the first arm was the version of this that would have compiled while breaking every
    // consumer that switches over a chain rejection.
    const own: VerifyReason = "signature_stale";
    const forwarded: VerifyReason = "grant_audience_not_admitted";
    const known: KnownVerifyReason = "content_digest_mismatch";
    const everyKnown: readonly VerifyReason[] = KNOWN_VERIFY_REASONS;

    expect([own, forwarded, known]).toHaveLength(3);
    expect(everyKnown.length).toBe(KNOWN_VERIFY_REASONS.length);
  });

  it("narrows a caught error to the union without a cast", () => {
    // What the change is FOR. `reason` was `string`, so this function body had nothing to switch
    // over and every consumer wrote its own copy of the vocabulary.
    const classify = (error: unknown): string => {
      if (error instanceof VerifyError) {
        const reason: VerifyReason = error.reason;
        return reason;
      }
      return "not-a-verify-error";
    };

    expect(classify(new VerifyError("signature_stale"))).toBe("signature_stale");
    expect(classify(new Error("nope"))).toBe("not-a-verify-error");
  });
});
