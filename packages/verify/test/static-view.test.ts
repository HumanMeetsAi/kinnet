/**
 * Offline verification: `createStaticTrustView` as a view over records already in hand, and
 * `createVerifier({ view })` as the injection point that lets a whole request be verified without
 * a network.
 *
 * THE ACCEPTANCE TEST IS THE THROWING FETCH. The trust resolver has always been offline-capable
 * on paper — `verifyGrantChain` takes any `TrustView` and fetches nothing — but `createVerifier`
 * built its own discovery-backed view internally and accepted no injection, so the request path
 * had no offline mode at all. A test with a stubbed fetch cannot tell "made no request" from
 * "made a request the stub happened to answer", so the global `fetch` is replaced with a function
 * that throws: any outbound call at all fails the test rather than passing quietly.
 */
import {
  canonicalDigest,
  createIdentity,
  encodeKeyRef,
  signRecord,
  signRequest,
  keyLogAnchor,
  signThresholdRecord,
  type Identity
} from "@kinnet/crypto";
import type { Grant, ParticipantId, Principal, Relationship, Revocation } from "@kinnet/protocol";
import { REPRESENTS_PREDICATE, verifyGrantChain } from "@kinnet/trust";
import { afterEach, describe, expect, it } from "vitest";

import { createStaticTrustView, createVerifier, VerifierConfigurationError } from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const NOW = new Date("2026-06-12T00:00:00.000Z");
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);
const ISSUED_AT = new Date(NOW.getTime() - 11 * 86_400_000).toISOString();
const PAST = new Date(NOW.getTime() - 2 * 86_400_000).toISOString();
const FUTURE = new Date(NOW.getTime() + 19 * 86_400_000).toISOString();
const TARGET = "https://api.example.com/quote";

const org = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
const admin = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
const agent = createIdentity({ currentSeed: seed(5), nextSeed: seed(6) });

type GrantFields = {
  subjectId: ParticipantId;
  issuerId: Principal;
  audienceId: Principal;
  abilities: string[];
  proof: string | null;
  caveats?: Record<string, unknown>;
  expiresAt?: string;
};

function makeGrant(signer: Identity, fields: GrantFields): Grant {
  // Spec 016: every issuer here is a participant signing with its own current keys, so the
  // anchor is the signer's log tip.
  return signThresholdRecord(
    { caveats: {}, issuedAt: ISSUED_AT, anchor: keyLogAnchor(signer.log), ...fields },
    [signer.currentKeys[0]!.secretKey]
  ) as Grant;
}

function revoke(signer: Identity, issuerId: ParticipantId, digest: string): Revocation {
  return signThresholdRecord(
    { revokes: digest, issuerId, anchor: keyLogAnchor(signer.log), revokedAt: PAST },
    [signer.currentKeys[0]!.secretKey]
  ) as Revocation;
}

/** Root: the organization self-issues. Leaf: the admin attenuates down to the agent. */
const rootGrant = makeGrant(org, {
  subjectId: org.id,
  issuerId: org.id,
  audienceId: admin.id,
  abilities: ["directory"],
  proof: null
});
const leafGrant = makeGrant(admin, {
  subjectId: org.id,
  issuerId: admin.id,
  audienceId: agent.id,
  abilities: ["directory/curate"],
  proof: canonicalDigest(rootGrant)
});
/** Leaf-first, the order spec 011 presents a chain in. */
const chain = [leafGrant, rootGrant];

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** Any outbound request at all fails the test. Nothing here is allowed to touch a network. */
function forbidFetch(): void {
  globalThis.fetch = (() => {
    throw new Error("offline verification must not fetch");
  }) as typeof fetch;
}

describe("createStaticTrustView serves the TrustView contract from records in hand", () => {
  it("files a key log under the id the log itself derives, not one the caller asserts", async () => {
    const view = createStaticTrustView({ keyLogs: [org.log, agent.log] });

    expect(view.participantIds().sort()).toEqual([org.id, agent.id].sort());
    expect(await view.getKeyLog(org.id)).toEqual(org.log);
    // The property that makes a caller-keyed map the wrong shape: there is no way to file one
    // identity's log under another's id, so the substitution `getKeyState` guards against
    // cannot be manufactured by a typo in a fixture.
    expect(await view.getKeyLog(admin.id)).toBeNull();
  });

  it("binds getKeyState to the id asked about", async () => {
    const view = createStaticTrustView({ keyLogs: [org.log] });

    await expect(view.getKeyState(org.id)).resolves.toMatchObject({ id: org.id });
    await expect(view.getKeyState(agent.id)).resolves.toBeNull();
  });

  it("answers relationship edges as point lookups on the decision tuple", async () => {
    const edge = signRecord(
      {
        id: "rel-represents-1",
        subjectId: agent.id,
        predicate: REPRESENTS_PREDICATE,
        objectId: org.id,
        issuedBy: org.id,
        issuedAt: ISSUED_AT
      },
      org.currentKeys[0]!.secretKey
    ) as Relationship;
    const view = createStaticTrustView({ keyLogs: [org.log, agent.log], relationships: [edge] });

    await expect(
      view.getRelationshipEdge(org.id, agent.id, org.id, REPRESENTS_PREDICATE)
    ).resolves.toEqual(edge);
    // Every component of the key is load-bearing. A view that answered on a partial match would
    // be exactly the scan `getRelationshipEdge` exists to avoid — an attacker publishing edges
    // naming the subject could then flip an ALLOW into a DENY.
    await expect(
      view.getRelationshipEdge(admin.id, agent.id, org.id, REPRESENTS_PREDICATE)
    ).resolves.toBeNull();
    await expect(view.getRelationshipEdge(org.id, agent.id, org.id, "employs")).resolves.toBeNull();
  });

  it("never returns more revocations than distinct issuers were asked about", async () => {
    // THE HARD CONTRACT. A revocation's identity is (issuer, revoked-digest), so a longer answer
    // describes records that cannot exist and the resolver THROWS on it rather than sifting.
    // Two revocations of one digest by one issuer is an easy fixture to write by accident —
    // two signatures, two `revokedAt` values — and would fail a test with an error about the
    // view instead of about the thing under test.
    const digest = canonicalDigest(leafGrant);
    const duplicateByOrg = [
      revoke(org, org.id, digest),
      signThresholdRecord(
        {
          revokes: digest,
          issuerId: org.id,
          anchor: keyLogAnchor(org.log),
          revokedAt: ISSUED_AT
        },
        [org.currentKeys[0]!.secretKey]
      ) as Revocation
    ];
    const view = createStaticTrustView({
      keyLogs: [org.log, admin.log],
      revocations: [...duplicateByOrg, revoke(admin, admin.id, digest)]
    });

    const both = await view.getRevocations(digest, [org.id, admin.id]);
    expect(both).toHaveLength(2);
    expect(both.map((record) => record.issuerId).sort()).toEqual([admin.id, org.id].sort());

    // Narrowing the issuer set narrows the answer, and never past the bound.
    const orgOnly = await view.getRevocations(digest, [org.id]);
    expect(orgOnly).toHaveLength(1);
    expect(orgOnly[0]!.issuerId).toBe(org.id);

    // Repeated ids are one issuer, so they buy no extra records.
    expect(await view.getRevocations(digest, [org.id, org.id, org.id])).toHaveLength(1);
    expect(await view.getRevocations(digest, [])).toHaveLength(0);
    // A digest nobody revoked.
    expect(await view.getRevocations(canonicalDigest(rootGrant), [org.id, admin.id])).toHaveLength(
      0
    );
  });

  it("serves an unreplayable log and lets the replay be the thing that rejects it", async () => {
    // A log whose inception event is intact but whose signature is not. It still answers for
    // exactly one identity — the id derives from the establishment data, which is untouched — so
    // it is filed and served, and `getKeyState` is where it fails. Dropping it at construction
    // would turn "this log does not replay" into "there is no such participant", which is a
    // different verdict and the wrong one; a test whose subject IS a broken log could not write
    // itself.
    const broken = [{ ...org.log[0]!, signature: ["z11111111111111111111"] }];
    const view = createStaticTrustView({ keyLogs: [broken, agent.log] });

    expect(view.participantIds().sort()).toEqual([org.id, agent.id].sort());
    await expect(view.getKeyLog(org.id)).resolves.toEqual(broken);
    await expect(view.getKeyState(org.id)).resolves.toBeNull();
    // One bad fixture entry does not take the view down.
    await expect(view.getKeyState(agent.id)).resolves.toMatchObject({ id: agent.id });
  });

  it("skips a log with no inception event, which answers for nobody", async () => {
    const view = createStaticTrustView({ keyLogs: [[], agent.log] });
    expect(view.participantIds()).toEqual([agent.id]);
  });
});

describe("verifyGrantChain runs against a static view with no network at all", () => {
  it("verifies a valid two-link chain", async () => {
    forbidFetch();
    const view = createStaticTrustView({ keyLogs: [org.log, admin.log, agent.log] });

    await expect(verifyGrantChain(chain, view, { now: NOW, purpose: "request" })).resolves.toEqual({
      valid: true,
      subjectId: org.id,
      audienceId: agent.id,
      abilities: ["directory/curate"]
    });
  });

  it("denies a chain whose leaf the issuer revoked", async () => {
    forbidFetch();
    const view = createStaticTrustView({
      keyLogs: [org.log, admin.log, agent.log],
      // Revoked by the admin, who issued the leaf and is therefore authorized to revoke it.
      revocations: [revoke(admin, admin.id, canonicalDigest(leafGrant))]
    });

    await expect(verifyGrantChain(chain, view, { now: NOW, purpose: "request" })).resolves.toEqual({
      valid: false,
      reason: "grant_revoked"
    });
  });

  it("honours the per-issuer bound under a multi-issuer chain", async () => {
    forbidFetch();
    // Both authorized revokers publish, and each also publishes a duplicate. The resolver asks
    // about the whole authorized-revoker suffix in ONE call, so this is the shape that trips the
    // "more records than distinct issuers" throw if the view does not dedupe.
    const leafDigest = canonicalDigest(leafGrant);
    const view = createStaticTrustView({
      keyLogs: [org.log, admin.log, agent.log],
      revocations: [
        revoke(org, org.id, leafDigest),
        signThresholdRecord(
          {
            revokes: leafDigest,
            issuerId: org.id,
            anchor: keyLogAnchor(org.log),
            revokedAt: ISSUED_AT
          },
          [org.currentKeys[0]!.secretKey]
        ) as Revocation,
        revoke(admin, admin.id, leafDigest),
        signThresholdRecord(
          {
            revokes: leafDigest,
            issuerId: admin.id,
            anchor: keyLogAnchor(admin.log),
            revokedAt: ISSUED_AT
          },
          [admin.currentKeys[0]!.secretKey]
        ) as Revocation
      ]
    });

    // Resolves to a verdict rather than throwing: had the view over-returned, the resolver would
    // treat the answer as hostile and this would reject with an error instead.
    await expect(verifyGrantChain(chain, view, { now: NOW, purpose: "request" })).resolves.toEqual({
      valid: false,
      reason: "grant_revoked"
    });
  });

  it("ignores a revocation by a party the chain does not authorize to revoke", async () => {
    forbidFetch();
    const view = createStaticTrustView({
      keyLogs: [org.log, admin.log, agent.log],
      // The agent is the AUDIENCE, not an issuer anywhere in the chain, so its revocation of the
      // leaf is not one the resolver ever asks for — and the view must not volunteer it.
      revocations: [revoke(agent, agent.id, canonicalDigest(leafGrant))]
    });

    await expect(
      verifyGrantChain(chain, view, { now: NOW, purpose: "request" })
    ).resolves.toMatchObject({ valid: true });
  });
});

describe("createVerifier accepts an injected view", () => {
  it("verifies a signed request end-to-end with the global fetch replaced by a thrower", async () => {
    forbidFetch();
    const verifier = createVerifier({
      view: createStaticTrustView({ keyLogs: [agent.log] }),
      now: () => NOW
    });

    const headers = signRequest({
      method: "POST",
      url: TARGET,
      body: '{"want":"quote"}',
      keyId: agent.id,
      secretKey: agent.currentKeys[0]!.secretKey,
      created: NOW_SECONDS
    });

    await expect(
      verifier.verify({
        method: "POST",
        url: TARGET,
        headers: { ...headers },
        body: '{"want":"quote"}'
      })
    ).resolves.toMatchObject({
      agentId: agent.id,
      actor: agent.id,
      delegated: false,
      satisfiedKey: encodeKeyRef(agent.currentKeys[0]!.publicKey)
    });
  });

  it("verifies a DELEGATED request offline, chain and all", async () => {
    forbidFetch();
    // The session key: a bare KeyRef principal that lives in no key log (spec 011), which is
    // exactly the case that used to need discovery for the links above it.
    const session = createIdentity({ currentSeed: seed(21), nextSeed: seed(22) });
    const sessionKey = encodeKeyRef(session.currentKeys[0]!.publicKey);
    const sessionGrant = makeGrant(admin, {
      subjectId: org.id,
      issuerId: admin.id,
      audienceId: sessionKey,
      abilities: ["directory/curate"],
      proof: canonicalDigest(rootGrant),
      // Spec 011 makes both mandatory for a key-audience link: a bare key has no log to rotate,
      // so the grant's own expiry is the only bound, and `aud` names the verifier it may be
      // presented to.
      caveats: { aud: org.id },
      expiresAt: FUTURE
    });

    const verifier = createVerifier({
      view: createStaticTrustView({ keyLogs: [org.log, admin.log] }),
      now: () => NOW,
      verifierId: org.id,
      requireAbilities: ["directory/curate"]
    });

    const body = '{"want":"quote"}';
    const headers = signRequest({
      method: "POST",
      url: TARGET,
      body,
      keyId: sessionKey,
      secretKey: session.currentKeys[0]!.secretKey,
      created: NOW_SECONDS,
      grants: [sessionGrant, rootGrant]
    });

    await expect(
      verifier.verify({ method: "POST", url: TARGET, headers: { ...headers }, body })
    ).resolves.toMatchObject({
      agentId: org.id,
      actor: sessionKey,
      delegated: true,
      abilities: ["directory/curate"]
    });
  });

  it("exposes the injected view as-is, so advanced checks reuse it", () => {
    const view = createStaticTrustView({ keyLogs: [agent.log] });
    expect(createVerifier({ view, now: () => NOW }).view).toBe(view);
  });

  it("passes the request allowance through to the injected view", async () => {
    forbidFetch();
    // The injected view must honour the SAME budget protocol as the discovery-backed one, or a
    // cost refusal would come back as `agent_key_log_unresolved` (401, "fix your log") instead of
    // `agent_key_log_too_expensive` (503, "raise the allowance"). Keeping those apart is the
    // whole reason they are two reasons.
    const verifier = createVerifier({
      view: createStaticTrustView({ keyLogs: [agent.log], maxSignatureVerifications: 8 }),
      now: () => NOW
    });
    const headers = signRequest({
      method: "POST",
      url: TARGET,
      body: "{}",
      keyId: agent.id,
      secretKey: agent.currentKeys[0]!.secretKey,
      created: NOW_SECONDS
    });
    const request = { method: "POST", url: TARGET, headers: { ...headers }, body: "{}" };

    await expect(
      verifier.verify(request, verifier.beginRequest({ maxSignatureVerifications: 0 }))
    ).rejects.toMatchObject({ reason: "agent_key_log_too_expensive", status: 503 });
  });
});

describe("view and discoveryUrl are mutually exclusive, and one is required", () => {
  it("refuses both", () => {
    expect(() =>
      createVerifier({
        discoveryUrl: "https://discovery.example.com",
        view: createStaticTrustView({ keyLogs: [agent.log] })
      })
    ).toThrow(VerifierConfigurationError);
    // The message has to name both fields: a caller who passed both cannot tell which one this
    // verifier would have used, which is the ambiguity being refused.
    expect(() =>
      createVerifier({
        discoveryUrl: "https://discovery.example.com",
        view: createStaticTrustView({ keyLogs: [agent.log] })
      })
    ).toThrow(/view.*discoveryUrl|discoveryUrl.*view/s);
  });

  it("refuses neither", () => {
    // FAILS AT CONSTRUCTION, not on the first request. A verifier with no view would otherwise
    // start clean and turn every inbound request into an authentication failure — an outage that
    // looks like a credential problem across an entire fleet.
    expect(() => createVerifier({})).toThrow(VerifierConfigurationError);
  });

  it("is not a VerifyError: a misconfiguration is not a rejected request", () => {
    // If it were, a middleware's catch would swallow it and answer 401 forever.
    const thrown = (() => {
      try {
        createVerifier({});
      } catch (error) {
        return error;
      }
      return null;
    })();
    expect(thrown).toBeInstanceOf(VerifierConfigurationError);
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as { status?: number }).status).toBeUndefined();
  });
});
