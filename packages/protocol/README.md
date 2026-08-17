# @kinnet/protocol

The record types and Zod schemas of the Participant Network — the shared substrate every other
Kinnet package consumes. No crypto, no I/O: this package decides what a record's fields are and
whether a candidate value is shape-valid, and nothing about whether it is signed correctly or
who to trust. `@kinnet/crypto` signs and verifies against these shapes; `@kinnet/trust` and
`@kinnet/verify` resolve identity and authority from them.

## Install

```bash
npm install @kinnet/protocol
```

or from a checkout of the repository:

```bash
pnpm install && pnpm build
```

## Parse and validate a record

Every record kind is a Zod schema. `safeParse` returns a typed result instead of throwing, so a
caller reading untrusted bytes decides what "invalid" means for its own surface:

```ts
import { participantProfileSchema, type ParticipantProfile } from "@kinnet/protocol";

const candidate = {
  id: "pk_zQmYwAPJzv5CZsnAzt8auVZRnHEKzKgUEdy3W35nUSpS6kq",
  type: "agent",
  displayName: "Ordering Agent",
  capabilities: ["orders/create"],
  verifiedDomains: [],
  updatedAt: "2026-08-17T00:00:00.000Z",
  signature:
    "z5rnVTAbdGrtjnu47AiPSJ3rr9iDskEANf6PLXXbEN6tfkP43izwMaLyBii1ZyqGYGdLVTXEBssdja39ZAqoXdjFx"
};

const result = participantProfileSchema.safeParse(candidate);
if (result.success) {
  const profile: ParticipantProfile = result.data;
  console.log(profile.displayName);
} else {
  console.error(result.error.issues);
}
```

This schema only checks shape — field types, formats, the cross-field rules the record's spec
states. It says nothing about whether `signature` actually verifies against the claimed `id`'s
current key; that is `@kinnet/crypto`'s `verifyRecord` against a key state resolved by replaying
the id's key log.

The signed records are `participantProfileSchema`, `participantNodeSchema`, `keyEventSchema` /
`keyEventLogSchema`, `claimSchema`, `relationshipSchema`, `grantSchema`, `revocationSchema`,
`messageEnvelopeSchema`, `conversationSchema`, and `conversationUpdateSchema` — each exports its
inferred TypeScript type alongside it (`ParticipantProfile`, `Grant`, `KeyEvent`, …).

## The strictness rule

Every signed record schema is a Zod `strictObject`: a value carrying a key the schema does not
define is **rejected**, not silently stripped. That matters because these records are digest- or
signature-identified — a permissive parser that drops an unknown key would let one delivered byte
string decode into two different logical records, one with the key and one without, both
claiming the same signature:

```ts
import { participantProfileSchema } from "@kinnet/protocol";

const withStrayKey = {
  id: "pk_zQmYwAPJzv5CZsnAzt8auVZRnHEKzKgUEdy3W35nUSpS6kq",
  type: "agent",
  displayName: "Ordering Agent",
  capabilities: [],
  verifiedDomains: [],
  updatedAt: "2026-08-17T00:00:00.000Z",
  signature:
    "z5rnVTAbdGrtjnu47AiPSJ3rr9iDskEANf6PLXXbEN6tfkP43izwMaLyBii1ZyqGYGdLVTXEBssdja39ZAqoXdjFx",
  extra: "not part of the schema"
};

participantProfileSchema.safeParse(withStrayKey).success; // false — "Unrecognized key: extra"
```

`Claim` and `Relationship` are strict for the same reason and against each other specifically:
open schemas that each strip what they don't define would let one object parse as both kinds
under one signature. Two record kinds must never both accept the same bytes.

## Encoding helpers

Bytes that will become a record — an HTTP body, a stored blob, anything read from outside the
process — need the same care before they reach a schema. `decodeUtf8Strict` refuses malformed
UTF-8 instead of silently substituting U+FFFD (the default `TextDecoder` behavior, which makes
two different byte strings decode to the same text), and `parseJsonStrict` refuses a JSON object
that repeats a key at any depth, since different parsers resolve a duplicate key differently:

```ts
import { decodeUtf8Strict, parseJsonStrict } from "@kinnet/protocol";

const octets: Uint8Array =
  /* the exact bytes that were signed or delivered */ new TextEncoder().encode('{"want":"quote"}');
const record: unknown = parseJsonStrict(decodeUtf8Strict(octets));
```

Use this pair — never `JSON.parse(new TextDecoder().decode(octets))` — anywhere a signature or a
digest covers the delivered octets and the parsed value is about to be checked against a schema
above. `@kinnet/verify`'s discovery client and `@kinnet/crypto`'s grant-chain header decoder both
route through it.

This module also exports `keyRefSchema`, `signatureSchema`, `multihashSchema`, and
`participantIdSchema` for validating identifiers and encoded values on their own, and the ability
vocabulary (`abilitySchema`, `isE2eeAbility`) used by grant chains.

## Conformance vectors

Where a record's bytes are digested or its kind must be distinguishable from every other kind,
the schemas are backed by committed fixtures a third party can check without this package:

- `test/fixtures/record-kind-vectors.json` — one shape-valid instance of every record and payload
  kind; each must validate under its own schema and be rejected by every other one (record kinds
  are non-confusable).
- `test/fixtures/signed-conversation.json`, `test/fixtures/signed-conversation-e2ee.json` — a
  replayable key log paired with a signed `Conversation` record, machine lane and E2EE lane.
- `test/fixtures/conversation-update-vectors.json` — accept/reject cases for
  `conversationUpdateSchema`'s well-formedness rules (spec 014).
- `test/fixtures/conversation-unit-vectors.json` — the `(record, chain)` payload wrapper accept/
  reject cases, and the digest-identity property that the chain travels alongside the record
  without changing its id.
- `test/fixtures/commit-validity-vectors.json` — spec 014's membership-change commit-validity
  rules (apply / wait / invalid) over full evidence sets.

## Specs

- [000 — Protocol scope & evolution](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/000-protocol-scope.md)
- [001 — Canonical serialization (JCS)](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/001-canonical-serialization.md)
- [002 — Participant ID derivation](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/002-participant-id.md)
- [003 — Key-history log (KERI-lite)](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/003-key-history.md)
- [008 — Revocation](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/008-revocation.md)
- [009 — Grant (UCAN-aligned)](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/009-grant.md)
- [010 — Message envelopes & inbox](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/010-message-inbox.md)
- [012 — Conversations](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/012-conversations.md)
- [014 — Two-lane conversations (E2EE)](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/014-e2ee-conversations.md)
- [015 — Canonical signature sets](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/015-signature-sets.md)
- [017 — Participant profile & node](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/017-participant-profile-and-node.md)
- [018 — Claims & relationships](https://github.com/HumanMeetsAi/kinnet/blob/main/packages/protocol/spec/018-claims-and-relationships.md)

The full index is at
[`packages/protocol/spec`](https://github.com/HumanMeetsAi/kinnet/tree/main/packages/protocol/spec).

## Status

Pre-1.0, pre-wire-freeze: `0.x` releases are for early adopters, and record shapes may still
change between them. The wire freezes at 1.0, when the maintainers declare it — not before.
Track the spec, not any one version of this package — the protocol is meant to be implemented
independently, and the conformance vectors are the compatibility contract.

## License

Apache-2.0
