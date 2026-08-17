# `consent-handback.json` — the OAuth → chain handback, offline-verifiable

A single worked result of the OAuth chain-access-token profile — one self-issued,
audience-bound, attenuated grant link presented as a bearer credential — frozen so a resource
server's tests have a fixed point they can check **from bytes alone**: no live discovery, no
authorization server, no network.

## The scenario

A human signs in through an OIDC provider that mints chain access tokens and consents to a set
of resource scopes. The
relying party receives `accessToken` (a `pnc1.` string) as its bearer credential. That token **is**
the delegation `chain`: one self-issued root grant — `subjectId === issuerId ===` the human —
audience-bound to the resource server's participant id, attenuated to exactly the ticked
`consentedScopes` (`photos/read`, `photos/write`; the opt-in `photos/share`/`photos/publish` are left
unticked), expiring one hour after it is issued.

There is no introspection endpoint. The resource server reads the token and decides whether to
honour it. Two facts make that decidable offline:

- `subjectKeyLog` — the human's key-event log — is bundled, so the verifier replays the **issuer's**
  keys from the fixture itself. The resource server is only the **audience**, and verifiers replay
  issuer logs only, so the resource server's own key log is deliberately absent;
  `resourceParticipantId` appears purely as a string.
- `grantDigest` is `canonicalDigest(chain[0])` — the spec-008 marker the resource server logs for
  the session and matches a revocation against.

## What the resource server runs

```ts
import { readFileSync } from "node:fs";

import { canonicalDigest, decodeChainAccessToken } from "@kinnet/crypto";
// Both resolve from @kinnet/verify's entry too (re-exported), if you vendor only verify.
import { createStaticTrustView, verifyGrantChain } from "@kinnet/verify";

const fx = JSON.parse(readFileSync("consent-handback.json", "utf8"));

// 1. The bearer decodes back to the exact chain.
const chain = decodeChainAccessToken(fx.accessToken);
// JSON.stringify(chain) === JSON.stringify(fx.chain)

// 2. The session/revocation marker is the digest of the leaf.
canonicalDigest(chain[0]); // === fx.grantDigest  ("zQmYvffev6MSEbnUsHrruSby78m5AxkdDqUqbAmh47xwokz")

// 3. The chain verifies end-to-end using ONLY the bundled key log — no network.
const view = createStaticTrustView({ keyLogs: [fx.subjectKeyLog] });
const verdict = await verifyGrantChain(chain, view, {
  verifierId: fx.resourceParticipantId, // the resource server's participant id
  requireAud: true,
  purpose: "request",
  // The chain has a real expiresAt; evaluate at the fixture's fixed instant, not the wall
  // clock, or the check flips to grant_expired once the fixture ages past fx.expiresAt.
  // In production you omit `now` (real time is correct); it is only pinned here for the fixture.
  now: new Date(fx.verifyAt)
});
// verdict === { valid: true, subjectId: fx.subject }  === fx.expectedVerdict

// 4. The resource server's own aud check: the leaf is bound to it on both the id and the caveat.
chain[0].audienceId === fx.resourceParticipantId; // true
chain[0].caveats.aud === fx.resourceParticipantId; // true

// 5. Effective abilities = the resource server's allowlist ∩ the leaf's abilities, by EXACT
//    string membership — never abilityCovers, because a bearer credential must not widen an
//    allowlist entry by path prefix. Here: ["photos/read", "photos/write"].
```

Expected outputs:

| check                       | value                                                |
| --------------------------- | ---------------------------------------------------- |
| `subject`                   | `pk_zQmXAnrX8UgzTu1wkKHcm2Fiu8atC5qGVreh4rkpzbnBY5j` |
| `resourceParticipantId`     | `pk_zQmbstH8D9qS8rZ4rvmgCz2yC2HhCGvRoAdgvA8mNTGRiMv` |
| `grantDigest`               | `zQmYvffev6MSEbnUsHrruSby78m5AxkdDqUqbAmh47xwokz`    |
| `expectedVerdict`           | `{ valid: true, subjectId: <subject> }`              |
| `canonicalDigest(chain[0])` | `=== grantDigest`                                    |

## Regenerating

The identity is minted from fixed seeds and the grant carries a fixed `issuedAt`/`expiresAt`, so
re-running the generator produces a byte-identical file. Run **both** commands, in order (the
generator writes `JSON.stringify(…, null, 2)` and the committed file is prettier-formatted):

```bash
pnpm exec tsx packages/verify/scripts/generate-consent-handback-fixture.ts
pnpm exec prettier --write packages/verify/test/fixtures/consent-handback.json
```

The generator self-checks every recorded fact and throws if any stops holding — see
`packages/verify/scripts/generate-consent-handback-fixture.ts`.
