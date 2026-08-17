/**
 * Regenerates the worked-example fixture for the OAuth -> chain handback of the OAuth
 * chain-access-token profile — one self-issued, audience-bound, attenuated grant link presented
 * as a bearer credential — as a resource server sees it.
 *
 * The scenario, end to end: a human signs in through an OIDC provider that mints chain access
 * tokens, consents to a set of resource scopes, and the authorization server hands the relying
 * party a `pnc1.` bearer access token. That token IS a one-link delegation chain — the human's
 * self-issued root grant, audience-bound to the resource server's participant id, attenuated to
 * exactly the consented scopes, expiring.
 * There is no introspection endpoint: the resource server reads the token and decides, from the
 * bytes alone, whether to honour it. This fixture pins ONE such worked result so a resource
 * server's verifier tests have a fixed point they can check offline — no live discovery, no
 * authorization server, no network.
 *
 * Everything the resource server needs to reach the verdict is bundled: `subjectKeyLog` is the
 * human's key-event log, so a verifier replays the issuer's keys from the fixture itself. The
 * resource server is only the AUDIENCE of the grant, and a verifier never replays an audience's
 * key log — only ISSUER logs are replayed — so the resource server's own key log is deliberately
 * absent, and its participant id appears purely as a string (`resourceParticipantId`). The
 * audience id is a synthetic resource-server id minted from fixed seeds, not a deployed identity.
 *
 * Determinism: the human identity is minted from FIXED seeds and the grant carries a FIXED
 * `issuedAt`/`expiresAt`, so re-running this script produces a byte-identical fixture. That is
 * what makes the committed `accessToken` and `grantDigest` strings meaningful: they are the exact
 * credential and the exact spec-008 revocation/session marker, reproducible by anyone.
 *
 * Run from the repo root (after `pnpm build`). BOTH commands, in order — this script writes
 * `JSON.stringify(…, null, 2)` and the committed file is prettier-formatted, so skipping the
 * second step leaves a diff that is pure formatting and makes the fixture look non-reproducible:
 *
 *   pnpm exec tsx packages/verify/scripts/generate-consent-handback-fixture.ts
 *   pnpm exec prettier --write packages/verify/test/fixtures/consent-handback.json
 */
import { writeFileSync } from "node:fs";

import {
  canonicalDigest,
  createIdentity,
  decodeChainAccessToken,
  encodeChainAccessToken,
  signThresholdRecord,
  type Identity
} from "@kinnet/crypto";
import { grantSchema, type Grant } from "@kinnet/protocol";
import { verifyGrantChain } from "@kinnet/trust";

import { createStaticTrustView } from "../src/static-view.js";

// --------------------------------------------------------------------------------------------
// Fixed inputs. Seeds and timestamps, never randomness or the wall clock, so the committed
// `accessToken` and `grantDigest` are reproducible byte for byte.
// --------------------------------------------------------------------------------------------

/**
 * The resource server's audience participant id. Minted from fixed seeds, not a deployed
 * identity: this fixture proves a chain bound to THAT id, and the resource server is only the
 * audience — a verifier never replays an audience's key log, so its key log is deliberately not
 * bundled and only the id string is needed to verify.
 */
const resource: Identity = createIdentity({
  currentSeed: new Uint8Array(32).fill(0x21),
  nextSeed: new Uint8Array(32).fill(0x22)
});
const RESOURCE_PARTICIPANT_ID = resource.id;

/**
 * The realistic default-checked consent: `photos/read` and `photos/write` are rendered checked
 * and left ticked; the opt-in `photos/share` and `photos/publish` are unticked and never make it
 * into the chain. Sorted so the leaf's abilities have one canonical order regardless of tick order.
 */
const CONSENTED_SCOPES = ["photos/read", "photos/write"].slice().sort();

const ISSUED_AT = "2026-08-14T00:00:00.000Z";
const TTL_SECONDS = 3600;
const EXPIRES_AT = new Date(new Date(ISSUED_AT).getTime() + TTL_SECONDS * 1000).toISOString();

/** The human whose consent mints the chain, from fixed seeds so the identity is reproducible. */
const human: Identity = createIdentity({
  currentSeed: new Uint8Array(32).fill(0x11),
  nextSeed: new Uint8Array(32).fill(0x12)
});

// --------------------------------------------------------------------------------------------
// Mint the chain: one self-issued link, subject === issuer === the human, participant
// audience (no key in the chain), aud-bound to the resource server, abilities exactly the ticked scopes.
// --------------------------------------------------------------------------------------------

const leaf: Grant = grantSchema.parse(
  signThresholdRecord(
    {
      subjectId: human.id,
      issuerId: human.id,
      audienceId: RESOURCE_PARTICIPANT_ID,
      abilities: CONSENTED_SCOPES,
      caveats: { aud: RESOURCE_PARTICIPANT_ID },
      proof: null,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT
    },
    human.currentKeys.map((pair) => pair.secretKey)
  )
);

const chain: Grant[] = [leaf];
const accessToken = encodeChainAccessToken(chain);
const grantDigest = canonicalDigest(leaf);

// --------------------------------------------------------------------------------------------
// Self-checks. Every recorded fact is recomputed here and the script throws if any stops
// proving its point — a fixture that quietly rots is worse than none.
// --------------------------------------------------------------------------------------------

async function selfCheck(): Promise<{ valid: true; subjectId: string }> {
  // 1. The token round-trips to the exact same chain.
  if (JSON.stringify(decodeChainAccessToken(accessToken)) !== JSON.stringify(chain)) {
    throw new Error("decodeChainAccessToken(accessToken) does not deep-equal the chain");
  }

  // 2. The digest recorded is the digest of the leaf.
  if (canonicalDigest(chain[0]!) !== grantDigest) {
    throw new Error("canonicalDigest(chain[0]) does not equal grantDigest");
  }

  // 3. The leaf is aud-bound to the resource server on BOTH the audience id and the aud caveat.
  if (leaf.audienceId !== RESOURCE_PARTICIPANT_ID) {
    throw new Error("leaf.audienceId is not the resource participant id");
  }
  if (leaf.caveats.aud !== RESOURCE_PARTICIPANT_ID) {
    throw new Error("leaf.caveats.aud is not the resource participant id");
  }

  // 4. The leaf carries exactly the consented scopes, in sorted order.
  if (JSON.stringify(leaf.abilities) !== JSON.stringify(CONSENTED_SCOPES)) {
    throw new Error("leaf.abilities does not deep-equal the sorted consented scopes");
  }

  // 5. The chain verifies end-to-end using ONLY the bundled key log — no network, no live
  //    discovery — with the resource server as the verifier, aud required, request purpose. This
  //    is exactly what the resource server runs on the decoded bearer.
  const view = createStaticTrustView({ keyLogs: [human.log] });
  const verdict = await verifyGrantChain(chain, view, {
    verifierId: RESOURCE_PARTICIPANT_ID,
    requireAud: true,
    purpose: "request",
    now: new Date(ISSUED_AT)
  });
  if (!verdict.valid) {
    throw new Error(
      `verifyGrantChain refused a chain the fixture asserts valid: ${verdict.reason}`
    );
  }
  if (verdict.subjectId !== human.id) {
    throw new Error("verifyGrantChain resolved a subject other than the human");
  }

  return { valid: true, subjectId: verdict.subjectId };
}

const expectedVerdict = await selfCheck();

// --------------------------------------------------------------------------------------------
// Emit the fixture.
// --------------------------------------------------------------------------------------------

const fixture = {
  note:
    "Worked-example fixture for the OAuth -> chain handback of the OAuth chain-access-token " +
    "profile — one self-issued, audience-bound, attenuated grant link presented as a bearer " +
    "credential — as the resource server sees it. A human consents through an OIDC provider " +
    "that mints chain access tokens and " +
    "the relying party receives `accessToken` as its bearer credential — a `pnc1.` string that " +
    "IS the delegation `chain`: one self-issued root grant (subjectId === issuerId === the " +
    "human), audience-bound to the resource server's participant id, attenuated to exactly the " +
    "`consentedScopes`, expiring at `expiresAt`. There is no introspection endpoint; the resource " +
    "server reads the token and verifies it from the bytes alone. Everything needed to do that OFFLINE is " +
    "bundled: `subjectKeyLog` is the human's key-event log, which a verifier replays to recover " +
    "the issuer's keys. The resource server is only the AUDIENCE — verifiers replay ISSUER logs only — so " +
    "the resource server's key log is deliberately absent and `resourceParticipantId` appears purely as a " +
    "string. `grantDigest` is `canonicalDigest(chain[0])`, the spec-008 marker the resource server logs for " +
    "the session and matches a revocation against. `expectedVerdict` is the result of " +
    "verifyGrantChain(chain, createStaticTrustView({ keyLogs: [subjectKeyLog] }), { verifierId: " +
    "resourceParticipantId, requireAud: true, purpose: 'request', now: new Date(verifyAt) }). " +
    "`verifyAt` is a fixed instant inside [issuedAt, expiresAt]: the chain carries a fixed " +
    "expiry, so a verifier MUST evaluate it at verifyAt (not the wall clock) or the fixture " +
    "expires and the check flips to grant_expired. The identity is minted from fixed seeds and " +
    "the grant carries fixed timestamps, so re-running the generator yields a byte-identical " +
    "file. Regenerate with packages/verify/scripts/generate-consent-handback-fixture.ts.",
  subject: human.id,
  subjectKeyLog: human.log,
  resourceParticipantId: RESOURCE_PARTICIPANT_ID,
  consentedScopes: CONSENTED_SCOPES,
  chain,
  accessToken,
  grantDigest,
  issuedAt: ISSUED_AT,
  expiresAt: EXPIRES_AT,
  verifyAt: ISSUED_AT,
  expectedVerdict
};

const target = new URL("../test/fixtures/consent-handback.json", import.meta.url);
writeFileSync(target, `${JSON.stringify(fixture, null, 2)}\n`);

console.log(`Wrote the consent handback fixture to ${target.pathname}`);
console.log(`  subject:     ${human.id}`);
console.log(`  accessToken: ${accessToken}`);
console.log(`  grantDigest: ${grantDigest}`);
