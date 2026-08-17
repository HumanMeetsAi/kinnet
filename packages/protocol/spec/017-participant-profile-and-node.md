# 017 — ParticipantProfile & ParticipantNode

**Status:** Proposed
**Blocks:** the public half of discovery — "who is this participant" and "where do I reach them"

## Context

An identity (002) with a key log (003) is verifiable but unaddressable: nothing in it says what
the participant is, what to call it, or where its traffic goes. Those are two separate
questions, and this spec pins the two records that answer them.

Both live in **discovery**, the public half of the split the network is built on: discovery
holds public identity, profile, key, routing, and verification records, and a participant node
holds the private side — messages, conversations, files, tasks, memories. A profile and a node
record are published to be read by strangers, unauthenticated, before any relationship exists.
Neither carries anything a participant would not put on a business card.

They ship in the reference implementation, are named by 013 (which reads `transports`) and by
006 (which builds module configuration on top of a node), and carry committed record-kind
vectors — but no RFC has ever defined them. This spec is that definition: it transcribes the
shipped records rather than proposing new ones, per the process rule in 000.

## Decision

Two records, both signed by the participant they belong to, both public.

### ParticipantProfile

```
ParticipantProfile {
  id:               ParticipantId    // 002; the participant this profile describes
  type:             ParticipantType  // the enum below
  displayName:      string           // non-empty
  description?:     string
  capabilities?:    string[]         // free-form labels; absent parses as []
  ownerId?:         ParticipantId    // 002; the participant that owns this one
  verifiedDomains?: string[]         // absent parses as []
  updatedAt:        string           // RFC 3339, UTC-Z subset (below)
  signature:        Signature        // scalar (005)
}
```

`ParticipantType` is a closed enum of exactly seven values, and a record carrying any other
value is invalid:

| Value          | Meaning                                      |
| -------------- | -------------------------------------------- |
| `person`       | A human being                                |
| `organization` | A company, community, or other legal body    |
| `team`         | A group inside an organization               |
| `application`  | A client program acting for someone          |
| `service`      | A network service others call                |
| `workflow`     | An automated process                         |
| `agent`        | An autonomous agent acting for a participant |

`capabilities` and `verifiedDomains` are **optional in the delivered bytes and defaulted on
parse**: a body omitting either parses to a record carrying `[]` in its place. That default is
a second byte-form of one logical record — the delivered bytes carry no array and the parsed
object carries an empty one, and the two canonicalize differently, so a signature made over the
omitting form does not verify over the parsed form. A service that stores the **parsed** object
rather than the delivered bytes therefore stores a write that omits either array in a form whose
signature does not verify: it manufactures the second byte-form rather than merely tolerating it.

A signer SHOULD emit both arrays explicitly, so that the delivered, stored, and signed forms are
one form. The alternative — dropping the defaults so an omitting body is simply invalid — is the
cleaner fix and is left to the open question below rather than decided here, because it is a
schema change and this spec transcribes.

`ownerId` names the participant that owns this one — an organization owning an agent, a person
owning an application. It is an unverified assertion by the profile's own signer: nothing in
this record proves the named owner agreed. A verifier that needs a mutual statement uses a
Relationship (018) issued by the owner, which is signed by the party being claimed.

`verifiedDomains` is likewise the participant's own assertion. This spec defines no
domain-verification procedure and no verifier consumes the field; see _Boundaries_.

### ParticipantNode

```
ParticipantNode {
  id:            string          // non-empty; unique within the participant
  participantId: ParticipantId   // 002; whose node this is
  label:         string          // non-empty; operator-facing
  endpoint?:     string          // absolute URL
  servedBy?:     ParticipantId   // 002; the participant hosting this node
  publicKey:     KeyRef          // 005
  transports:    NodeTransport[] // the enum below; may be empty
  updatedAt:     string          // RFC 3339, UTC-Z subset (below)
  signature:     Signature       // scalar (005)
}
```

`NodeTransport` is a closed enum of exactly two values:

| Value    | Meaning                                                       |
| -------- | ------------------------------------------------------------- |
| `https`  | Signed HTTP requests (004, 010, 012) and the SSE stream (013) |
| `webrtc` | Direct device-to-device media, negotiated out of band         |

A record carrying any other value is invalid. **`websocket` was removed by this spec**; see
_Design notes_.

`endpoint` is optional so that a node reachable only device-to-device — `transports` of
`["webrtc"]` — is expressible. When present it MUST be an absolute URL.

`servedBy` names the participant that hosts the node. A hosted node and a self-hosted node are
the same record; the field distinguishes them, and moving hosts rewrites this one record rather
than touching the identity.

`publicKey` is the node's own KeyRef, not the participant's id — a node is an endpoint with a
key, not a second identity. It carries no key log: rotating it means republishing this record
under the participant's signature.

### Timestamps

`updatedAt` on both records is RFC 3339, restricted to the **UTC-`Z` subset**: a numeric offset
is invalid, and so is a local time with no offset at all. `2026-08-01T00:00:00Z` and
`2026-08-01T00:00:00.000Z` are both accepted; `2026-08-01T08:00:00+08:00` is rejected, as is
`2026-08-01T00:00:00.000+00:00`. The restriction is not cosmetic: these records are digested,
and two offset spellings of one instant are two byte-forms of one logical record.

### Signing, digest identity, and the signature set

Both records are signed exactly as 001 and 005 require: one Ed25519 signature over
`UTF-8( JCS( record − signature ) )`, encoded multibase base58btc. The `signature` field is the
only field removed before canonicalization; every other field, including the optional ones when
present, is covered.

A READER resolves the signer's key states from the participant's key log (003) and accepts a
signature that verifies against **any** state the log ever committed, so a rotation does not
orphan a profile or node record already published (015 S5). This is 018's procedure for
statements, applied to these two records.

The WRITE check is deliberately narrower: it is made against the writer's **current** state
alone (_Who may write them_). The two are not in tension. Publishing is an act performed now, so
it must be authorized by whoever holds the keys now; reading is an assessment of a record that
may long predate the reader, so orphaning it at every rotation would make rotation destructive.
A record admitted under the state current at its write therefore continues to verify afterwards
under S5, which is exactly the intended relationship between the two checks.

The `signature` field is a **scalar**, not an array. It is nonetheless a signature set of one
member and 015 governs it: a verifier MUST lift it into a one-member set and apply 015 in full
(015 §Scope names `ParticipantProfile` and `ParticipantNode` among the scalar-signature records
it covers). The consequence of 015's `m = t` is stated plainly under _Open questions_: a
one-member set satisfies only a threshold of 1.

A record's **digest identity** is 003's digest rule: the multihash of the JCS of the
**complete signed record**, `signature` included. That digest is what a Revocation (008) names.
It is not the storage key of either record; see _Where these records live_.

Both schemas are **closed**: a record carrying a key the schema does not define is invalid, not
silently stripped. That is 001's non-confusability requirement, and it is what keeps a profile
from parsing as a node or as any other record kind. The enforcement is the committed cross
product in `packages/protocol/test/fixtures/record-kind-vectors.json`, not this paragraph.

### Who may write them

Both are **self-records**: a profile is signed by the participant it describes, and a node
record by the participant whose node it is. There is no third-party form of either.

Discovery writes are authorized per 004 — an RFC 9421 signature over the request, verified
against the writer's current key state. On top of that:

- A `ParticipantProfile` write MUST be refused unless `profile.id` equals the authenticated
  writer's participant id.
- A `ParticipantNode` write MUST be refused unless `node.participantId` equals the
  authenticated writer's participant id.
- A write of either record MUST be refused unless the record's own scalar `signature` — lifted
  to a one-member set per 015 §Scope and checked at the writer's key-state **threshold** —
  verifies against that key state. This is 004's _Two signatures, two jobs_ in full: the request
  signature authorizes the write action, and the record signature authenticates the content and
  is the only one that persists and re-verifies afterwards. Accepting the request signature
  alone stores a record that is not independently re-verifiable from its own bytes, which is
  what makes a discovery record worth anything to a third party. The refusal codes are
  `profile_signature_invalid` and `node_signature_invalid`, both 422.

The record signature is checked against **the same key state the request signature was verified
against**, not against a state resolved independently for the purpose. "The record is self-signed
by the same identity" is then one statement about one key set, rather than an inference from two
lookups happening to agree.

Neither record may name another participant as its signer, so the ownership rule is exactly
"the record's subject is the writer".

A reader of either record MUST re-establish that binding itself — the record's `id` /
`participantId` is the identity whose key log resolves the signature, and no other identity's
signature over it is meaningful.

### Where these records live

Discovery serves both, unauthenticated, on the participant-scoped surface:

| Route                                 | Effect                                                    |
| ------------------------------------- | --------------------------------------------------------- |
| `GET /participants/:id`               | The participant's profile, or `404 participant_not_found` |
| `PUT /participants/:id`               | Publish the profile                                       |
| `GET /participants/:id/nodes`         | The participant's node records, paged                     |
| `PUT /participants/:id/nodes/:nodeId` | Publish one node record                                   |

A **profile is a per-participant singleton**, keyed by `id` and replaced wholesale on write. A
participant has exactly zero or one profile, and there is no history: the previous bytes are
gone from discovery, though a copy anyone kept remains independently verifiable and separately
revocable.

**Node records are a collection**, keyed by the pair `(participantId, id)`. A participant may
publish many, and `id` is unique only within that participant — the same `id` under two
participants is two records. There is no ordering, no primary-node marker, and no cap on how
many a participant publishes; the read surface is paged rather than the write surface bounded.

Refusals a conforming discovery service emits:

| Code                        | Status | Condition                                                                                          |
| --------------------------- | ------ | -------------------------------------------------------------------------------------------------- |
| `invalid_profile`           | 400    | The profile body fails the schema                                                                  |
| `invalid_node`              | 400    | The node body fails the schema                                                                     |
| `participant_id_mismatch`   | 400    | `profile.id` is not the `:id` written to                                                           |
| `node_id_mismatch`          | 400    | **Either** `node.participantId` is not `:id` **or** `node.id` is not `:nodeId` — one code for both |
| `invalid_query`             | 400    | A paged or filtered read carries an unusable query                                                 |
| `invalid_cursor`            | 400    | A paged read carries a cursor this service did not issue                                           |
| `profile_signature_invalid` | 422    | The profile's own `signature`, lifted to a one-member set, fails at the writer's threshold         |
| `node_signature_invalid`    | 422    | The node record's own `signature`, lifted the same way, fails at the writer's threshold            |
| `participant_not_found`     | 404    | No profile is stored for `:id`                                                                     |
| `unauthorized_write`        | 401    | 004 request verification failed                                                                    |
| `key_log_too_expensive`     | 413    | Resolving the writer's key log would cost more than an unauthenticated request may spend           |
| `temporarily_unavailable`   | 503    | Replay-nonce tracking is at capacity or the clock is unusable — transient, not an auth failure     |

The 422s are deliberately **not** 401s. The request was authenticated — the caller does hold the
writing key — so the fault is in the record's own bytes, and telling a client its request
signature failed sends it to fix the one thing that was correct.

The 413 and 503 are deliberately **not** folded into the 401: a caller reading 401 concludes its
signature or key log is wrong and re-publishes the very thing that was refused, and a capacity
condition disappears into an authentication-failure metric.

A profile that is not stored is a 404; an empty node collection is an empty page, not a 404.

Neither record carries an `expiresAt`. The only planned end is replacement by a later write;
the only unplanned one is a Revocation (008) naming the record's digest. Discovery does not
filter revoked records out of reads and does not compare an incoming `updatedAt` against the
stored one — see _Open questions_ for both.

### Consequential amendments

Landing with this spec, the 011 and 014 pattern:

- **013** — §1's remark that `transports` "carries a `websocket` value that no route ever
  defined" is amended: the value is removed by this spec, so the observation that motivated
  013's rejection of WebSocket now has no dangling enum member behind it. 013's rejection itself
  is unchanged and is the reason for the removal; only the statement of the present situation
  needs revising.

No other spec's normative text is affected.

## Boundaries

- **Profile rendering is not protocol.** Avatars, banners, pronouns, localized names, rich
  text, ordering of fields in a UI, and how a client truncates a long `displayName` are client
  concerns. The protocol fixes what is signed, not what is drawn.
- **Human-readable naming is not protocol.** `displayName` is a label, not an identifier: it is
  unverified, non-unique, and mutable. Handles, namespaces, and their scarcity are a layer
  above (002 says the same about names).
- **Node hosting policy is not protocol.** Who may host a node, uptime, capacity, pricing,
  migration procedure, and what a host may see are operator concerns. `servedBy` records the
  fact of hosting and confers no authority — a host that wants to act for the participant needs
  a Grant (009).
- **The `capabilities` and `verifiedDomains` vocabularies are not protocol.** Both are
  free-form label lists. A registry, a matching rule, or a namespace convention for either
  belongs to whatever module consumes it, on 009's pattern for ability strings.
- **Domain verification is not protocol.** Nothing here defines how a domain comes to be in
  `verifiedDomains`, and no verifier treats the field as evidence. A checkable domain statement
  is a Claim (018) issued by whoever performed the check.
- **Transport negotiation is not protocol.** `transports` advertises what a node speaks; how a
  client picks one, falls back, or negotiates media parameters is above this record.

## Non-goals

- **Profile versioning and history.** One current profile per participant; no `seq`, no `prior`,
  no chain. Anyone who needs an audit trail keeps the signed bytes they received.
- **Per-field visibility or selective disclosure.** Every field of a published record is public
  to everyone. A participant who does not want a field public omits it.
- **Directory search and discovery by attribute.** Reading a profile requires knowing the id.
  Search over profiles is a module (006), not a protocol surface.
- **Node liveness, health, and reachability.** A published node record asserts an address, not
  that anything is listening. Probing is the client's job.
- **A node as an identity.** A node has a key and an address; it has no participant id, no key
  log, and no relationships. Anything that needs to act as a participant is one.

## Open questions

- **Threshold-1 issuance.** A scalar signature is a one-member set, and 015's `m = t` means a
  one-member set satisfies only a threshold of 1. A participant whose current key state
  declares a threshold above 1 therefore cannot publish a valid profile or node record at all.
  That matches 004's threshold-1 restriction on request signing today, so nothing is currently
  unreachable — such a participant cannot authenticate a write at all, and the write check
  above would refuse the record if it could — but 004 states its restriction as a version limit
  to be lifted, and lifting it would leave these two records still unissuable. Whether they
  grow an array `signature` like the signature-set records, or stay scalar deliberately, is
  open. What the write check settles is only that the failure is loud at publication rather
  than silent until the first reader.
- **Where the READ-side check belongs.** The write side is closed: a conforming discovery
  service refuses a profile or node record whose own `signature` does not verify at the
  writer's threshold, with the two 422s tabled above. That check is a floor and not a
  substitute: a reader that trusts the discovery host rather than the bytes gets nothing a
  signed record is for, and a record obtained from a mirror, an export bundle, or a compromised
  host has passed nobody's check. What the rules above fix is what a reader checks and against
  which key states, not which component checks it; which consumer performs the read-side check
  is open, since the natural place differs per caller.
- **Rollback.** Nothing compares an incoming `updatedAt` against the stored record's, so an
  older but validly signed profile or node record replaces a newer one. `updatedAt` is
  descriptive, not a monotonic counter, and this spec does not make it one. Whether replacement
  should require a strictly later `updatedAt` — and what that would mean under clock skew — is
  open. The same question applies to 008's freshness open question from the other side.
- **Revoked records are still served.** Discovery serves a revoked profile or node record
  exactly like a live one; a reader must digest what it received and ask the revocation surface
  separately. Whether discovery should mark or omit revoked records is open, and is a question
  about the discovery surface rather than about these records.
- **Unconsumed fields.** `ownerId`, `verifiedDomains`, `capabilities`, and `description` are
  carried, signed, and served, but nothing in the protocol reads any of them today. Each is
  either waiting for a consumer or a candidate for removal before the wire-freeze; per 000 #6, a
  field with no running code behind it has not earned its place.
- **Node record identity.** `node.id` is issuer-chosen and unconstrained, while the record's
  revocation name is its digest — two identities for one record. Republishing the same `id`
  with different bytes leaves the old bytes independently valid and separately revocable.
  Whether `id` should be the digest (as 012 does for conversations) is open.
- **The parse defaults manufacture a second byte-form.** `capabilities` and `verifiedDomains`
  default to `[]`, and a service that stores the parsed object stores an omitting write in a
  form whose signature cannot verify. The SHOULD above is a workaround, not
  a fix. Dropping both defaults — making an omitting body invalid, so delivered, stored, and
  signed forms are necessarily one form — is the cleaner resolution and would be a small
  breaking schema change; taking it is open.
- **Unbounded fields.** `capabilities`, `verifiedDomains`, and `transports` carry no maximum
  length, and `displayName`, `description`, node `id`, and node `label` carry no maximum size —
  only a non-empty minimum where one applies. Both records are written through an authenticated
  route, which bounds who can spend the service's memory but not how much any one of them
  spends, and both are then served on an unauthenticated read. Every bound in the protocol
  carries a named constant and a derivation (003, 009); these have neither. Choosing them is
  open and must be settled before the wire-freeze.

## Design notes

- **Why two records and not one.** "What is this participant" changes rarely and has one
  answer; "where do I reach it" changes with every host migration and has several answers at
  once. Folding routing into the profile would make every endpoint change rewrite the identity
  record, and would force a singleton on something that is naturally a list.
- **Why a scalar signature.** Both records predate the signature-set form, and both are
  self-assertions by a single identity rather than committee acts — the shapes 015 was written
  for (key events, revocations, grants, conversation records) are the ones where M-of-N is
  meaningful. Under 015 a scalar signature is exactly a 1-of-1 set, so nothing is outside the
  rule; only the encoding differs. The cost of that choice is the threshold-1 limit above.
- **Why the profile is a singleton and the node list is not.** The profile answers a question
  with one correct answer, and a set of profiles would immediately raise "which one is current"
  — a question no field answers. Routing genuinely has several simultaneous answers: a personal
  proxy and a direct media path are both true at once.
- **Why WebSocket is absent from `transports`.** 013 chose Server-Sent Events for the live
  surface and rejected WebSocket in its non-goals: SSE is a signed GET, so it inherits 004 and
  011 request verification unchanged, whereas a WebSocket upgrade's handshake and framing would
  need their own signing profile to carry the same authorization — a second regime for nothing
  the surface needs. The enum carried a `websocket` value that no route ever defined, so
  advertising it named a transport no conforming node serves. This spec removes it. Narrowing an
  enum is breaking, and it is taken now precisely because there is no
  wire-freeze yet (000, Stage 0).
- **Why `publicKey` is a KeyRef and not a participant id.** Giving a node an identity would give
  it a key log, rotation, relationships, and revocation — the whole participant apparatus — for
  an address. The thinner form (000 #7) is a key inside a record the participant signs: the
  participant's own signature is what makes the node key trustworthy, and rotating it is a
  republish.
- **Why `servedBy` is a participant and not a URL.** A host that is a participant can be
  checked: it has a key log, it can be named in a Relationship, and a Grant can be issued to it.
  A hostname can only be read.

## History

- 2026-06-06 — `ParticipantProfile` and `ParticipantNode` first shipped in `@kinnet/protocol`.
- 2026-06-12 — `servedBy` added to `ParticipantNode`, aligning the records with 001–005.
- 2026-08-13 — both schemas closed, so no record kind cross-validates as another (001).
- 2026-08-16 — this RFC written, transcribing the shipped records; `websocket` removed from
  `ParticipantNode.transports`.
- 2026-08-16 — the record-signature write check enforced for both records
  (`profile_signature_invalid`, `node_signature_invalid`), against the same key state that
  authenticated the request. The open question narrows to the read side.

## References

- Spec 001 (canonical serialization; record kinds are non-confusable), 002 (participant ids),
  003 (key-state resolution and the digest rule), 004 (discovery write authorization), 005
  (signature suite and KeyRef encoding), 008 (revocation by digest), 013 (the SSE live surface
  and its rejection of WebSocket), 015 (canonical signature sets), 018 (claims and
  relationships — the checkable form of what a profile only asserts)
- RFC 3339 — timestamps; RFC 8785 — JCS
- Conformance vectors: `packages/protocol/test/fixtures/record-kind-vectors.json` (one
  shape-valid instance of each record, checked against every other record kind's schema)
- Signed byte-level fixture: `packages/crypto/test/fixtures/signed-identity.json` (a
  `ParticipantProfile` signed under a committed key log, replayed by the record sign/verify
  suite)
