# Protocol specs

[000](./000-protocol-scope.md) is the meta-spec — how it is decided what belongs in the
protocol and how it evolves. 001–005 are the foundational format decisions: the byte-level and
identity rules every signed record depends on. 006+ are later proposals raised through the
`000` process. Per 000 everything here is replaceable now (Stage 0) and only becomes fixed at
the wire-freeze.

Each spec is an ADR-style proposal; its `Decision` section is the normative body, everything
else is context and rationale. Status is one of **Draft**, **Proposed**, **Accepted**, or
**Superseded**. Until a spec is Accepted, its record shapes and rules may change without a
deprecation cycle; implementations should track the spec, not the code.

| #                                            | Spec                          | Blocks                                             | Status   |
| -------------------------------------------- | ----------------------------- | -------------------------------------------------- | -------- |
| [000](./000-protocol-scope.md)               | Protocol scope & evolution    | Governs every change                               | Accepted |
| [001](./001-canonical-serialization.md)      | Canonical serialization (JCS) | Every signature                                    | Accepted |
| [002](./002-participant-id.md)               | Participant ID derivation     | Every identity                                     | Accepted |
| [003](./003-key-history.md)                  | Key-history log (KERI-lite)   | Rotation, recovery, ID→key resolution              | Accepted |
| [004](./004-discovery-write-auth.md)         | Discovery write authorization | Authenticated discovery writes                     | Accepted |
| [005](./005-signature-suite.md)              | Signature suite & agility     | The crypto primitives every signature depends on   | Accepted |
| [006](./006-module-config.md)                | ModuleConfig                  | Community modules beyond the directory             | Proposed |
| [007](./007-asset-ref.md)                    | AssetRef                      | Files, media, attachments across modules           | Proposed |
| [008](./008-revocation.md)                   | Revocation                    | The trust resolver — revoked-status checks         | Accepted |
| [009](./009-grant.md)                        | Grant (UCAN-aligned)          | The trust resolver — delegation chains             | Accepted |
| [010](./010-message-inbox.md)                | Message envelopes & inbox     | The participant-node inbox surface                 | Accepted |
| [011](./011-device-key-grants.md)            | Device-key grants             | Browser/device session keys                        | Accepted |
| [012](./012-conversations.md)                | Conversations                 | The interaction plane's threads                    | Accepted |
| [013](./013-realtime.md)                     | Realtime delivery (SSE)       | The interaction plane's live surfaces              | Accepted |
| [014](./014-e2ee-conversations.md)           | Two-lane conversations (E2EE) | Human-private chat; group membership change        | Accepted |
| [015](./015-signature-sets.md)               | Canonical signature sets      | Revocation by digest; digest identity; M-of-N      | Accepted |
| [017](./017-participant-profile-and-node.md) | Participant profile & node    | Discovery's identity and routing records           | Proposed |
| [018](./018-claims-and-relationships.md)     | Claims & relationships        | The trust layer's assertions; the represents chain | Proposed |

## Why these five, and only these five

A record is _signed and verified_ only once five things are pinned: the **bytes** to sign
(001), the **identity** doing the signing (002), how a verifier learns the signer's
**current key** (003), how a write **proves key ownership** to discovery (004), and the
**suite** that does the signing (005). Everything else in this directory builds on those five.
