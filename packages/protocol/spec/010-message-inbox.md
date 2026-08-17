# 010 — Message envelopes & inbox delivery

**Status:** Accepted
**Blocks:** the participant-node inbox — the first private, node-to-node communication surface
**Amended by:** 011, 012, 014

## Context

Discovery settles _who a participant is_ (001–005) and _what they may do_ (008, 009); it holds
public records only. The network's point, though, is private communication: a participant sends
a message and the recipient's node holds it until read. That surface — a participant node's
**inbox** — needs its own rules, because unlike a discovery write (a public record anyone may
re-verify forever) a message is private data delivered to one node.

This spec pins how a `MessageEnvelope` is signed, how a node authenticates delivery and reads,
and where a node draws the line between _accept and store_ and everything deferred to later
specs. It fixes mechanism, not message semantics: the protocol says what makes an envelope
verifiable and an inbox authenticated, and leaves conversation shape and payload meaning to the
layers above (000 #3).

## Decision

### Envelope signing

A `MessageEnvelope` is a **single-signer record** (001 + 005), signed exactly as every other
single-signer record in the protocol:

```
MessageEnvelope {
  id:              string          // unique per sender; the node's per-inbox dedup key
  from:            ParticipantId   // the signer
  to:              ParticipantId   // the intended recipient
  createdAt:       string          // RFC 3339
  type:            string          // sender-defined message type, e.g. "text"
  payload:         unknown         // sender-defined body (plaintext to the node — see non-goals)
  conversationId?: Multihash       // 012: optional association to a Conversation (under the signature)
  signature:       Signature       // over JCS(envelope − signature), by a current key of `from`
}
```

The signed bytes are the JCS canonicalization (001) of the envelope minus its `signature`
field, signed by a **current key of `from`** resolved through `from`'s key-history log (003,
005). This is the existing `signRecord` / `verifyRecord` convention — no new signing regime.
The record signature authenticates _content and authorship_ and is re-verifiable by anyone
holding the envelope bytes and `from`'s log.

`envelope.id` MUST be **unguessable by anyone other than the sender**: at least 128 bits drawn
from a cryptographically secure random source (a UUIDv4 satisfies this). The field is an
identifier, not a counter or a sender-chosen label.

_Amended by 012:_ envelope `type` is sender-defined **except** the reserved `pn/` prefix naming
protocol-defined payloads (the first being `pn/conversation`), which fail closed — a node MUST
reject a `pn/*` envelope whose name it does not recognize rather than store it as opaque
payload — and the optional `conversationId` field is a Multihash naming a Conversation record's
digest id, whose membership gates association but not delivery in general.

### Delivery

A node accepts `POST /messages` only when **both** signatures check out — the same
two-signatures-two-jobs split as discovery write-auth (004):

1. The HTTP request carries a spec-004 RFC 9421 signature whose `keyid` equals `envelope.from`
   and verifies against `from`'s **current key state** (003). This authenticates the _delivery
   action_ (this sender, now) and defeats replay.
2. The envelope's own record signature verifies against that **same key state**. This
   authenticates the _content_.

A node **deduplicates by `envelope.id` per inbox**: the first delivery of an id is stored and
assigned a per-inbox sequence; any redelivery of the same id is idempotent and returns the
already-stored message unchanged. Delivery is therefore safe to retry.

_Amended by 012:_ that idempotency is for **identical canonical bytes only** — a delivery
presenting an `envelope.id` the inbox already holds under different canonical bytes is rejected
with `409 envelope_id_conflict` rather than deduplicated; see 012 §"Fan-out and envelope ids".

_Amended by 012 and 014:_ a delivery from a sender the recipient's inbox has blocked is
accepted with a uniform 2xx and is neither stored nor indexed anywhere, except for the
group-mechanics envelopes 014 exempts; see 012 §"Consent: pending conversations and blocking"
and 014 §"The wire: MLS messages ride the inbox".

_Amended by 011:_ a request signed by a delegated chain may also deliver, in one of exactly two
modes (owner mode, unchanged above, or delegated mode); see 011's inbox section for the full
rule and the `msg/send` / `msg/read` ability vocabulary it defines.

### Enrollment

An inbox exists only after its owner **enrolls** it: a spec-004-signed `PUT /inboxes/:id` whose
`keyid` equals `:id` and verifies against that participant's current key state. Enrollment is
idempotent. A node **delivers only to enrolled inboxes** — either the recipient's inbox (the
`to` participant, for inbound delivery) or the sender's own inbox (the `from` participant, for a
sent-copy). Delivery addressed to a participant with no enrolled inbox on this node is refused;
the protocol fixes the enrollment gate, not the node's hosting or routing policy.

_Amended by 011:_ enrollment also accepts a delegated request whose presented chain is a
**single root grant self-issued by `:id` to a `KeyRef`** carrying the exact ability
`inbox/enroll` (not a covering prefix); see 011's inbox section for the full rule.

### Reads

`GET /inboxes/:id/messages` requires a spec-004 signature whose `keyid` equals `:id` and
verifies against that participant's current key state — an inbox is readable only by the
participant who controls it. Reads return the inbox's stored envelopes in per-inbox sequence
order; pagination and filtering are the node's surface, not a protocol record.

_Amended by 011:_ read authorization is grant-based (settling the open question below); for
each stored delegated envelope, reads return the (envelope, chain) pair 011 defines, not the
envelope alone.

_Amended by 012:_ the read route gains a `?conversation=<digest>` filter composing with
`with`/`after`/`limit`, its default response **excludes reserved-type envelopes** (which still
consume a per-inbox `seq`, so two clients agree on order whether or not they request them), and
the full conversation surface — list active/pending, accept, per-conversation read cursor —
lives at `/inboxes/:id/conversations/…` (012).

## Boundaries

- **Two signatures, two jobs (004).** The record signature persists with the message and is
  re-verifiable forever; the HTTP signature authorizes the delivery or read request and is not
  stored. Both are required, and both resolve against the same current key state — so write and
  read authority track key rotation automatically (004).
- **Node data is private.** Inbox contents never enter discovery. Discovery holds public
  identity/key/routing records; the inbox holds private messages, on the node.
- **Dedup is per inbox, by `id`.** `envelope.id` is unique per sender and is the node's
  idempotency key within one inbox — not a global content address (that is the 003 digest rule,
  used for revocation and proof chains, not for message identity). _Amended by 012:_ the key is
  `(inbox, id)` across senders and the idempotency is for identical canonical bytes only — a
  same-id delivery whose canonical bytes differ is rejected with `409 envelope_id_conflict`.

## Non-goals

Deliberately out of scope for this spec, each deferred to a later spec:

- ~~**End-to-end encryption.**~~ Lifted by 014: payload confidentiality lives there, on the
  **E2EE lane**, where the payload is an MLS ciphertext the node stores and forwards but cannot
  read. What this spec decided is not overturned — it is **named**: authenticated plaintext,
  operator-readable, is the definition of the **machine lane**, which 014 keeps as the right
  default for agent and workflow traffic (and which is never presented as private). An envelope
  is machine-lane unless the Conversation record it names declares `lane: "e2ee"` (014, amending
  012); retrofitting encryption onto the machine lane is 014's own non-goal.
- ~~**Threading / conversation records.**~~ Lifted by 012: the Conversation record and the
  optional `conversationId` field on this envelope now stand for threading; message
  `type`/`payload` remain sender-defined except for the reserved `pn/` prefix.
- **Multi-device fan-out.** One enrolled inbox per participant on a node; delivering one
  message to a participant's several devices is deferred.
- **Store-and-forward between nodes.** A node accepts delivery to inboxes it hosts; inter-node
  relay and routing are deferred.

## Open questions

- **Retention and deletion.** Whether the protocol fixes any retention or deletion semantics, or
  leaves them entirely to node policy.
- **Anti-abuse.** Rate-limiting and spam defense at `POST /messages` — a separate concern from
  authentication, shared with the deferred discovery anti-abuse decision (004).

## Design notes

**Why `envelope.id` must be unguessable.** The dedup key is `(inbox, id)` and it spans senders:
a node holds one envelope per id per inbox no matter who delivered it, and rejects a same-id
delivery whose canonical bytes differ (`409 envelope_id_conflict`). That makes the id a
shared namespace, and a guessable id hands two attacks to any third party who can deliver to
the target inbox. First, an **existence oracle**: delivering a candidate id and reading
409-versus-2xx reveals whether that id is already present in an inbox the attacker cannot
read — which, for ids derived from a counter, a timestamp, or anything about the message,
leaks the recipient's traffic. Second, **suppression**: because the first writer of an id owns
it, an attacker who predicts the id a legitimate sender will use can pre-write it and make the
real delivery fail as a conflict. Entropy is the whole defence — with ≥128 bits from a CSPRNG
neither guess succeeds better than chance, and the id carries no information about its message.

## History

- 2026-07-15 — Initial: envelope signing as a single-signer record, the two-signature delivery
  rule, per-inbox dedup by `envelope.id`, inbox enrollment, and owner-only reads.
- 2026-07-22 — Amended by 011: a delegated chain may deliver and read, in owner or delegated
  mode; the read-authorization open question is thereby answered grant-based.
- 2026-07-28 — Amended by 012: the reserved envelope-type prefix and its fail-closed rule, the
  optional `conversationId` field, the filtered read and its reserved-type exclusion, and the
  same-id-conflict rule; the threading non-goal is lifted.
- 2026-08-01 — Amended by 014: the end-to-end-encryption non-goal is lifted, and this spec's
  authenticated-plaintext stance is named as the definition of the machine lane.
- 2026-08-03 — Amended by 011: enrollment also accepts a single self-issued grant carrying the
  exact ability `inbox/enroll`.
- 2026-08-13 — The reserved envelope-type prefix cited here took its brand-neutral `pn/` form
  (000).
- 2026-08-16 — `envelope.id` gained a normative unguessability rule (≥128 bits from a CSPRNG),
  because the cross-sender dedup key otherwise yields an existence oracle and a suppression
  attack; pointers added for 012's same-id-conflict rule and the blocked-sender uniform 2xx.

## References

- Spec 001 (canonical serialization / JCS), 002 (participant ID), 003 (current-key resolution),
  004 (RFC 9421 request auth, two-signatures split), 005 (signature suite), 011 (delegated
  requests, amends delivery and reads), 012 (conversations, amends envelope type/payload and
  read defaults), 014 (the E2EE lane — lifts the encryption non-goal and makes this spec's
  plaintext stance the machine lane's definition)
- RFC 9421 — HTTP Message Signatures
