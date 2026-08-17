# The Participant Network — protocol specifications

The Participant Network is an open communication and relationship layer for humans,
organizations, applications, and AI agents. Identities are self-certifying public keys with an
append-only key history; representation, delegation, and revocation are signed records that
anyone can verify offline; a directory is a convenience, never a trusted party. The question the
protocol exists to answer is: _does this agent really act for that organization, and what is it
allowed to do?_

This directory **is** the protocol. Each numbered document specifies one primitive; together
with the conformance vectors committed under `packages/*/test/fixtures` they are the complete
statement of what an independent implementation must agree on. The code alongside them is the
reference implementation: where it and a spec disagree, one of them has a bug, and the vectors
decide which.

## The specifications

| #                                            | Spec                          | Defines                                                                             | Status   |
| -------------------------------------------- | ----------------------------- | ----------------------------------------------------------------------------------- | -------- |
| [000](./000-protocol-scope.md)               | Protocol scope & evolution    | What belongs in the protocol, how it changes, and when it freezes                   | Accepted |
| [001](./001-canonical-serialization.md)      | Canonical serialization (JCS) | The exact bytes that are signed and hashed                                          | Accepted |
| [002](./002-participant-id.md)               | Participant ID derivation     | How a participant's identifier is derived from its key                              | Accepted |
| [003](./003-key-history.md)                  | Key-history log (KERI-lite)   | Rotation, recovery, and resolving an ID to its current key                          | Accepted |
| [004](./004-discovery-write-auth.md)         | Discovery write authorization | How a write to a discovery service proves control of the participant's key          | Accepted |
| [005](./005-signature-suite.md)              | Signature suite & agility     | The signature algorithms and how new ones are introduced without a format break     | Accepted |
| [006](./006-module-config.md)                | ModuleConfig                  | The general configuration record for the typed content modules a node hosts         | Proposed |
| [007](./007-asset-ref.md)                    | AssetRef                      | An integrity-checked reference to a file, image, or attachment                      | Proposed |
| [008](./008-revocation.md)                   | Revocation                    | How a signed record is revoked, and how "not revoked" is checked from bytes         | Accepted |
| [009](./009-grant.md)                        | Grant (UCAN-aligned)          | Scoped, attenuating, expiring, revocable delegation of authority                    | Accepted |
| [010](./010-message-inbox.md)                | Message envelopes & inbox     | How a message is signed, delivered to a participant's node, and read                | Accepted |
| [011](./011-device-key-grants.md)            | Device-key grants             | Per-device session keys acting under a participant's root identity                  | Accepted |
| [012](./012-conversations.md)                | Conversations                 | Conversation records: membership, message-to-thread association, ordering           | Accepted |
| [013](./013-realtime.md)                     | Realtime delivery (SSE)       | Push delivery from a node, and how a long-lived subscription stays authorized       | Accepted |
| [014](./014-e2ee-conversations.md)           | Two-lane conversations (E2EE) | End-to-end encrypted human conversations alongside the authenticated-plaintext lane | Accepted |
| [015](./015-signature-sets.md)               | Canonical signature sets      | Which signatures a record's digest covers; M-of-N and digest-addressed identity     | Accepted |
| [017](./017-participant-profile-and-node.md) | Participant profile & node    | The public records that say what a participant is and where to reach it             | Proposed |
| [018](./018-claims-and-relationships.md)     | Claims & relationships        | Signed assertions by one participant about another; the represents chain            | Proposed |

Numbering is by order of adoption, not importance. [000](./000-protocol-scope.md) is the
meta-spec: the placement test that decides whether something belongs in the protocol at all, and
the lifecycle that decides how freely it may change. 001–005 are the foundational format
decisions every signed record depends on. 006 onward are further primitives admitted through the
000 process; some amend earlier specs, and a spec amended by a later one says so in its header.
Number 016 is reserved: 015 proposes it as _Record anchoring_, and it is not yet written.

## The five foundations

A record is _signed and verified_ only once five things are pinned: the **bytes** to sign
(001), the **identity** doing the signing (002), how a verifier learns the signer's
**current key** (003), how a write **proves key ownership** to discovery (004), and the
**suite** that does the signing (005). Everything else in this directory builds on those five.

## Reading a spec

Each spec opens with a header — `# NNN — Title`, `**Status:**`, a one-line scope marker
(usually `**Blocks:**`, what depends on this spec being settled; `**Governs:**` or
`**Supersedes:**` where that fits better), and `**Amended by:**` when a later spec changes it.
The body's common spine, as applicable, is `Context`, `Decision`, `Threat model`, `Boundaries`,
`Non-goals`, `Open questions`, `Design notes`, `History`, `References`; a spec adds sections of
its own where its subject needs them.

`Decision` is the normative body: the only place MUST/SHOULD/MAY rules and wire shapes live.
Everything else is context and rationale and binds nothing. When a later spec changes a rule, an
italic _Amended by 0NN: …_ pointer marks the rule in place and the later spec carries the new
text under `Consequential amendments`. Conformance vectors are cited by their path in this
repository, which ships them.

**Status** is one of:

- **Draft** — being written; nothing in it is settled.
- **Proposed** — complete and open for review; not yet adopted.
- **Accepted** — adopted; a change goes through the process in 000.
- **Superseded** — replaced by a later spec, which the header names.

## Stability

The protocol is pre-wire-freeze. 000 defines the stages: today (Stage 0) any spec, Accepted or
not, may still change without a deprecation cycle when a cleaner design has the rationale for
it; the wire-freeze (Stage 1) is triggered by the first external implementation or the first
network carrying third-party-signed data, and from then on change is additive-only. Until then,
implementations should track the spec, not the code, and should expect record shapes to move.

## Changing the protocol

Every change to a record, field, enum, or wire-format element — addition, removal, or
replacement — is proposed as a numbered spec or as an amendment carried by one, and passes the
placement test in 000. It lands together with a reference implementation and reference tests:
schema accept/reject cases and, wherever bytes are signed or hashed, conformance vectors a third
party can check from bytes alone. A vector that seems wrong, underspecified, or missing is a
protocol issue by definition. The repository's contribution guide has the filing mechanics.
