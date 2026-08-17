# @kinnet/crypto

Identity, signing and verification for the Participant Network: Ed25519, JCS canonicalization,
participant-id derivation, key logs with pre-rotation, RFC 9421 HTTP Message Signatures, and
threshold signature sets. It signs and verifies against the record shapes `@kinnet/protocol`
defines; it does not decide who to trust — that is `@kinnet/trust` and `@kinnet/verify`, built on
top of this package.

## Install

```bash
npm install @kinnet/crypto
```

or from a checkout of the repository:

```bash
pnpm install && pnpm build
```

## Create an identity

`createIdentity` generates a fresh Ed25519 identity: a `ParticipantId` self-derived from its
inception key event, plus the key log that proves it. Pre-rotation means the _next_ key is
already committed to (by digest) before it is ever used, so a stolen active key cannot take over
the identity:

```ts
import { createIdentity } from "@kinnet/crypto";

const me = createIdentity();
console.log(me.id); // "pk_z…" — derived from the inception event, not chosen
console.log(me.log.length); // 1 — the inception event
```

`me.currentKeys[0].secretKey` is the raw signing key. `me.nextKeys` and `me.nextThreshold` are
the pre-committed state that a future `rotateIdentity` reveals — keep them in split custody per
spec 003.

## Sign a record, verify against a replayed key state

`signRecord` computes the signature over the JCS canonical form of the record without its
`signature` field. A verifier never trusts a claimed key: it replays the signer's key log to get
the key state that log actually commits to, and checks the signature against that:

```ts
import { createIdentity, replayKeyLog, signRecord, verifyRecord } from "@kinnet/crypto";

const me = createIdentity();
const state = replayKeyLog(me.log); // resolved independently, never trusted from the caller

const claim = signRecord(
  {
    subjectId: me.id,
    claimType: "role",
    value: "operator",
    issuedBy: me.id,
    issuedAt: new Date().toISOString()
  },
  me.currentKeys[0].secretKey
);

verifyRecord(claim, state.keys[0]!); // true
```

Records that carry a signature **set** — `KeyEvent`, `Revocation`, `Grant` — use
`signThresholdRecord` / `verifyThresholdRecord` instead: an M-of-N state where each signature
must verify under a distinct listed key, in increasing key order (spec 015).

## Sign and verify an HTTP request

`signRequest` / `verifyRequest` implement the spec 004 RFC 9421 profile: one signature over
`@method`, `@target-uri`, and `content-digest` (RFC 9530), with `created` freshness and a nonce.
A verifier resolves `keys` and `threshold` from a replayed key log, exactly as with a record — the
request signature never says which keys are current, it only claims to be signed by one of them:

```ts
import { createIdentity, signRequest, verifyRequest } from "@kinnet/crypto";

const me = createIdentity();
const body = JSON.stringify({ want: "quote" });

const headers = signRequest({
  method: "POST",
  url: "https://example.com/quote",
  body,
  keyId: me.id,
  secretKey: me.currentKeys[0].secretKey
});

// A relying party would resolve `keys`/`threshold` from the caller's key log, not from `me`.
const write = verifyRequest({
  method: "POST",
  url: "https://example.com/quote",
  body,
  headers,
  keys: me.log[0]!.keys,
  threshold: "1"
});
console.log(write.satisfiedKey);
```

`@kinnet/verify` wraps this into request-level middleware (Express, and edge runtimes via
`verifyFetch`) that also resolves the key log over the network — reach for that package rather
than calling `verifyRequest` directly in a service.

## Rotate an identity and replay its log

`rotateIdentity` reveals the pre-committed next key state and commits a fresh one; the rotation
event is signed by the newly revealed keys, which is what makes rotation work as a
compromise-recovery path even if the previously active key is stolen or lost. `replayKeyLog`
re-derives the current key state from the log alone — chain digests, pre-rotation commitments,
and every event's signatures:

```ts
import { createIdentity, replayKeyLog, rotateIdentity } from "@kinnet/crypto";

let identity = createIdentity();
identity = rotateIdentity(identity); // reveals the committed next key, commits a fresh one

const state = replayKeyLog(identity.log); // replays and verifies the whole chain, from bytes
console.log(state.seq); // "1"
```

Use `replayKeyLogFor(expectedId, events)` instead of bare `replayKeyLog` whenever an expected
participant id is known — it rejects a log that replays validly but for a _different_ identity,
which a host serving the wrong bytes at the right path would otherwise pass off as your key
state.

## Also in this package

`multibase`/`multihash` helpers (`toMultibase`, `fromMultibase`, `encodeKeyRef`, `decodeKeyRef`,
`encodeSha256Multihash`) implement spec 005's encodings; `canonicalDigest` is the JCS-then-hash
digest used for record ids and the key-log chain. `encodeGrantsHeader` / `decodeGrantsHeader` and
`encodeChainAccessToken` / `decodeChainAccessToken` codec the two carriers a spec-009/011 grant
chain travels over — a request header and a self-contained bearer token — behind one shared,
length-bounded decode path. The MLS profile of spec 014 — `encodePNCredential` /
`decodePNCredential`, `encodeCommitBinding` / `decodeCommitBinding`,
`groupIdFromConversationId`, and the `MlsRuntime` adapter contract an implementation supplies —
binds an MLS group to a Participant Network identity for the end-to-end-encrypted conversation
lane; no MLS runtime is imported here.

## Conformance vectors

Every fixture is checkable from bytes alone — no dependency on this package's internals — and is
regenerated by a script under `scripts/`, never hand-edited:

- `test/fixtures/ed25519-verification-vectors.json` — spec 005's pinned Ed25519 verification
  mode: strict RFC 8032 plus a low-order public-key rejection, which is stricter than
  `@noble/curves`' cofactored default and than plain RFC 8032.
- `test/fixtures/content-digest-vectors.json` — the RFC 9530 `Content-Digest` the spec 004
  profile covers, pinning that the digest is over the delivered octets, never a decoded form of
  them.
- `test/fixtures/key-log-rejection-vectors.json` — spec 003 key-log replay: chaining, sequencing,
  pre-rotation (including the committed threshold), the spec 015 signature-set rules as the log
  applies them, the quorum rule, and the participant-binding check.
- `test/fixtures/signature-set-vectors.json` — spec 015's canonical signature-set rule (S0–S3)
  over `Revocation`/`Grant`/`KeyEvent`-shaped records: exact threshold count, distinct keys,
  increasing key order.
- `test/fixtures/chain-token-vectors.json` — the `pnc1.` bearer-token encoding of a spec 009/011
  grant chain, and every way a presented token can be malformed or refused.
- `test/fixtures/mls-profile-vectors.json` — spec 014's TLS-style (RFC 9420) varint and opaque
  encodings, and the PNCredential / commit-binding shapes built on them.
- `test/fixtures/signed-identity.json`, `test/fixtures/signed-envelope.json` — a replayable key
  log paired with a signed `ParticipantProfile` and a signed `MessageEnvelope`, each checkable
  end to end: replay the log, verify the signature against the resulting key state.

## Specs

- [001 — Canonical serialization (JCS)](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/001-canonical-serialization.md)
- [002 — Participant ID derivation](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/002-participant-id.md)
- [003 — Key-history log (KERI-lite)](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/003-key-history.md)
- [004 — Discovery write authorization](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/004-discovery-write-auth.md)
- [005 — Signature suite & agility](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/005-signature-suite.md)
- [009 — Grant (UCAN-aligned)](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/009-grant.md)
- [011 — Device-key grants](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/011-device-key-grants.md)
- [014 — Two-lane conversations (E2EE)](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/014-e2ee-conversations.md)
- [015 — Canonical signature sets](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/015-signature-sets.md)

The full index is at
[`packages/protocol/spec`](https://github.com/HumanMeetsAi/kinnet/tree/main/packages/protocol/spec).

## Status

Pre-1.0, pre-wire-freeze: record shapes and profiles may still change. Track the spec, not any
one version of this package — the conformance vectors above are the compatibility contract.

## License

Apache-2.0
