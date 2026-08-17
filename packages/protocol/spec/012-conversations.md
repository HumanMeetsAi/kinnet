# 012 — Conversations

**Status:** Accepted
**Blocks:** the container every later interaction record (tasks, proposals, approvals) flows
through
**Amended by:** 013, 014

## Context

010 fixes how a message is delivered and 011 fixes who may deliver and read; neither says how
messages relate. 010 defers threading explicitly ("No conversation, thread, or reply-linkage
record is defined here"). Without a conversation record a client can only approximate threads
by grouping the flat inbox on the `(from, to)` pair — enough for pairwise chat and nothing
more: no groups, no titles, no read state, and nothing a second client implementation would
derive the same way. Any real client requires the real thing: conversation records,
membership, message-to-thread association, ordering, read state, listing.

Run the placement test (000): two independent nodes — and, under federation, two nodes that
have never coordinated — must agree on what a conversation _is_ and which messages belong to
it. That is interop-necessity for exactly two things: a **conversation record** (membership is
stored fact, not derivable from traffic) and a **message-to-conversation association** (a
signed field, or a forged one is undetectable). Everything else here — listing, filtering,
read state — is surface behavior of the inbox, pinned the way 010 pins routes: mechanism a
client can rely on, no new records. Read state in particular is between a participant and
their own node; it fails interop-necessity as a record and is deliberately not one.

## Decision

### The Conversation record

A `Conversation` is a record (001 + 005) that speaks for exactly one participant — its
creator — and is signed either by that participant or, per the signing rules below, by a
session key delegated to act for them:

```
Conversation {
  creator:      ParticipantId    // the subject the record speaks for
  participants: ParticipantId[]  // the fixed member set; MUST include creator; MUST be unique;
                                 // MUST be sorted by codepoint; 2..256 members
                                 // 014: on the e2ee lane this is the founding set — membership
                                 //   changes there by evidence record; on the machine lane it
                                 //   stays fixed for the life of the conversation
  createdAt:    string           // RFC 3339, creator-chosen, informational (same stance as 010)
  title?:       string           // optional; if present 1..256 characters; meaning is above the protocol
  lane?:        "e2ee"           // 014: absent = machine lane; MUST be omitted, never "machine", never null
  groupNonce?:  string           // 014: multibase 32 random bytes; REQUIRED iff lane == "e2ee"
  signature:    Signature[]      // over JCS(record − signature), per the signing convention
}
```

`signature` is an **array** because the creator's key state carries a threshold (003): a
participant whose current state requires _m_ of _n_ keys requires _m_ signatures here, exactly
as grants and key events do. A single key of a threshold organization cannot mint a
conversation that speaks for it.

**The conversation id is not a field.** It is the spec-003 digest of the complete signed
record (signature included) — the same rule revocation targets use. Every member holds the
same record bytes, so every member — and every node, including nodes that have never spoken to
each other — derives the same id with no coordination and no minting authority. An id field
would be derivable (000 #4) and forgeable; the digest is neither.

**The digested bytes are the schema-validated bytes, and the schema is closed.** A digest id
is only an identity if two implementations digest the same bytes for the same logical record.
Two ways that breaks, both closed here:

1. **Unknown keys.** The `Conversation` schema is **strict**: a record carrying any key not
   defined above is invalid, not silently stripped. A permissive schema that drops unknown
   keys would let a sender ship `{…, "x": 1}` to one node and `{…}` to another and have both
   accept, under two different ids — or, worse, have one node digest the bytes it received and
   another digest the bytes it parsed.
2. **Duplicate keys.** A JSON object with a repeated key is rejected before parsing rather
   than resolved last-wins, since last-wins differs across parsers.

Concretely: a node MUST derive the id by digesting `JCS(record)` computed from the
**schema-validated** record, and MUST reject the delivery if that id does not match the id the
record was delivered under. A committed conformance fixture pins bytes → id so a second
implementation can check itself from bytes alone. (The strictness rule is stated here because
this is the first record whose _identity_ depends on it; it likely belongs in 001 as a general
convention — see open questions.)

_Amended by 014:_ two optional fields declare the **lane**, and they are under the signature
like everything else that must not be forgeable.

- **`lane` MUST be omitted for the machine lane** — never `"machine"`, never `null`. That is
  the strictness rule above applied to a new field: one logical conversation must have one
  byte-form and therefore one digest. It also means **every conversation record written before
  014 stays valid and keeps its id**; the machine lane is the absence of a marker, not a
  migration.
- Because the lane is digested, it is **immutable for the life of the conversation**: "the same
  conversation, downgraded" is not expressible, since tampering with the lane changes the id. A
  client MUST render the lane from the verified record, never from message traffic.
- **`groupNonce` (required iff `lane == "e2ee"`) makes every E2EE record byte-unique.** 014
  derives the MLS `group_id` from the conversation's digest id; Ed25519 is deterministic and
  `createdAt` is creator-chosen, so without a nonce a creator could re-sign byte-identical
  records and hand two distinct groups the same `group_id`.

Membership is **fixed at creation**. There is no membership-change record in this spec — not
because groups don't change, but because the E2EE lane (014) must solve group membership change
for ciphertext, and defining a plaintext-lane change record first would either constrain that
design or diverge from it. One mechanism, designed once. Until then: a changed group is a new
conversation.

_Amended by 014:_ that mechanism now exists — a `ConversationUpdate` **evidence** record
travelling as `pn/conversation-update`, authorizing a change that **MLS** orders — and it
is lifted **for the E2EE lane only**. On the machine lane, "a changed group is a new
conversation" is no longer provisional: it stands **permanently**. The reason is 014's design
rule, that the record layer never orders anything. Membership change needs an arbiter; MLS is
the arbiter 014 uses, and MLS exists only on the E2EE lane, so a machine-lane mechanism would
have to make the record layer one — which does not work, since any member can author records
for free and a contestable order splits the group. Accordingly a node MUST reject a
`pn/conversation-update` naming a machine-lane conversation (`lane_mismatch`).

The consequence is stated here rather than left to be discovered later: a machine-lane
conversation **cannot add or remove a participant, ever**. A changed group is a new
conversation, with a new id and no history. Machine-lane membership change waits on federation
defining cross-node ordering, or on nothing at all (014's open question).

### Creation is delivery — the reserved envelope type

No new write surface. A conversation reaches an inbox the way everything reaches an inbox:
`POST /messages` (010/011, both modes). This spec reserves the envelope `type` prefix
**`pn/`** for protocol-defined payloads — 010's "sender-defined `type`" becomes
"sender-defined, except the `pn/` prefix" — and defines the first reserved type:

- **`type: "pn/conversation"`** — `payload` is a complete signed `Conversation` record.

On delivery of a `pn/conversation` envelope, in addition to 010/011's rules, the node
MUST:

1. validate the payload against the `Conversation` schema and verify the record signature per
   the signing rules below — owner mode against any key state the **creator's** log replays
   to, or delegated mode against the accompanying chain's leaf key — the embedded record is
   the authority; the envelope merely transports it;
2. require `envelope.from` and `envelope.to` to both be members of the conversation — any
   member may (re)deliver the record, not only the creator, so a conversation survives its
   creator going quiet before every member has it;
3. require the delivered id to equal the id derived from the schema-validated bytes (above);
4. index the conversation for the recipient inbox under its digest id (and for the sender's
   inbox via the sent-copy, 010), subject to the consent rules below.

**The membership check is per target inbox.** A delivery writes two inboxes — the recipient's
and the sender's sent-copy (010) — and the check above is evaluated **for each inbox written**,
against that inbox's owner. Stating it as "from and to are members" is only correct because
both are written; a node that generalizes this rule to a route writing one inbox must check
that inbox's owner. **Self-delivery** (`from == to`) is the degenerate, legitimate case: a
participant delivering a conversation to their own inbox writes one inbox and checks one
membership.

Reserved-type envelopes **are envelopes**: a `pn/conversation` delivery is stored, is
deduplicated by `envelope.id` per inbox, and takes a per-inbox `seq` like any other. It is
**excluded from the default `GET /inboxes/:id/messages` response** — a client rendering a chat
should not have to filter protocol payloads out of the message stream — and is returned when
explicitly requested by type. Ordering is unaffected: the `seq` is consumed either way, so two
clients agree on sequence whether or not they ask for reserved types.

Failing 1, 2, or 3 rejects the delivery (`invalid_conversation` / `not_a_member` /
`conversation_id_mismatch`). Redelivering a conversation an inbox already holds is idempotent
— the digest id makes that natural — except that suppression survives redelivery (below).
A `pn/`-prefixed type the node does not recognize is rejected (`unknown_reserved_type`):
reserved types fail closed rather than being stored as opaque payloads a later node version
would have skipped validating.

_Amended by 014:_ the reserved list gains three E2EE-lane types, each of which MUST carry
`conversationId`, and each of which takes its ability by the generative rule below:

- **`type: "pn/mls"`** — `payload` is `{ "mlsMessage": base64url(MLSMessage) }`, an MLS
  `PrivateMessage` carrying a commit or an application message. Ability `msg/mls`.
- **`type: "pn/welcome"`** — `payload` is `{ "welcome": base64url(Welcome) }`, delivered to
  a newly added participant. Ability `msg/welcome`.
- **`type: "pn/conversation-update"`** — `payload` is a signed `ConversationUpdate`
  membership-evidence record, validated like `pn/conversation` (strict schema, duplicate
  JSON keys rejected, digest-checked, signature per the two modes below). Ability
  `msg/conversation-update`.

The MLS payloads are the one place the fail-closed rule above stops at the envelope: the node
rejects a `pn/` **type** it does not know, but MUST NOT reject an `MLSMessage` it cannot
parse — the ciphertext is opaque to it by design, and a node is not a member.

### Message-to-conversation association

`MessageEnvelope` (010) gains one optional field, **under the record signature** so the
association is exactly as tamper-proof as the message:

```
MessageEnvelope {
  ...                          // 010 unchanged
  conversationId?: Multihash   // the 003 digest id of a Conversation record
}
```

An envelope without `conversationId` is a bare message, exactly as today — the machine lane
keeps working unchanged. When `conversationId` is present, the node MUST, in addition to
010/011's rules:

- reject delivery if the recipient inbox does not hold that conversation
  (`unknown_conversation`) — delivery is retry-safe (010), so the fix is to deliver the
  conversation record first and retry;
- reject delivery unless `envelope.from` and `envelope.to` are both members
  (`not_a_member`).

_Amended by 014:_ two additions to these gates, both of which the node can enforce because it
holds the verified Conversation record and therefore knows the lane.

- **Lane/type consistency.** An envelope naming an `e2ee` conversation MUST be rejected
  (`lane_mismatch`) unless its type is `pn/mls`, `pn/welcome`, or
  `pn/conversation-update`; a `pn/mls` or `pn/welcome` envelope naming a
  machine-lane conversation MUST be rejected the same way, as MUST a
  `pn/conversation-update` naming one (membership there is fixed, above). This is not left
  to client goodwill: without it a buggy client, an SDK regression, or a delegate holding only
  `msg/send` — a _different_ ability from `msg/mls` — could associate cleartext into an E2EE
  conversation and the node would store it in the clear forever. Unknown reserved types already
  fail closed here; the lane gets the same treatment. **The lane check runs after the
  membership check**, which settles that much of the error-oracle question below for this route:
  `lane_mismatch` then discloses nothing to a non-member that `not_a_member` did not already.
- **Evidence records are gated against the union of pre- and post-change membership**, per
  target inbox. A `pn/conversation-update` carries the change it authorizes, so reading
  membership at either instant alone breaks it: an `add` must reach a participant who is not
  yet a member, and a `remove` must reach the participant it removes — which is the only way
  they learn of it. On that lane the node's "members" are no longer just the record's
  `participants`: they are that set plus the evidence records the node has **accepted**, where
  accepted means it checked the record's authority (014 rule 2) rather than merely stored it —
  an unchecked filter is one any sender could grow. The view is add-monotone (a `remove` record
  never shrinks it, so removal's teeth stay cryptographic and the removal notice stays
  deliverable), so the union only ever does work for `add`.

Membership gates **association**, not delivery in general: two participants can always
exchange bare messages; they cannot attach messages to a conversation that doesn't name them
both. Group delivery is sender-side fan-out — one envelope per recipient, each signed
separately (010 has no multi-recipient envelope), tied together by the shared
`conversationId`.

**Fan-out and envelope ids.** A sender MAY reuse one `envelope.id` across the fan-out, since
010 deduplicates per inbox and each recipient sees one copy; that is the natural way to say
"one logical message". A node MUST reject a delivery presenting an `envelope.id` it already
holds for that inbox with **different bytes** (`envelope_id_conflict`) rather than treating it
as an idempotent redelivery — 010's idempotency is for identical bytes, and without this rule
a sender could overwrite, or a node could silently keep whichever copy arrived first.

Two honest limits, stated rather than implied:

- **Cross-member consistency is not proven.** Nothing here stops a sender putting different
  payloads in different members' envelopes under one `conversationId`. That is an
  honest-sender property in v1 and a real question for the E2EE lane's transcript-consistency
  work.
- **Membership is not delivery evidence.** That a participant is named in a conversation says
  nothing about whether they ever received the record, accepted it, or read it. Members'
  nodes can and will diverge — one member may hold a conversation another has never seen.
  A client MUST NOT present membership as "everyone here has this".

### Consent: pending conversations and blocking

A delivered conversation record creates **surface in the recipient's client** — a thread
appears. Without a consent rule any participant can place a thread, and later an
approval-request, into a stranger's interface, with no action by that stranger and no way to
stop it. Membership is asserted unilaterally by the creator (that is what makes the record
work), so consent cannot live in the record; it lives in the recipient's node.

Two **node-local index states**. Neither is a record — same footing as the read cursor: never
signed, never relayed, never re-verified, no interop-necessity (000).

- **Pending.** On delivery of a `pn/conversation` envelope, the node indexes the
  conversation as `pending` for the recipient inbox unless that inbox has **prior contact**
  with `envelope.from` — defined as: the inbox has previously delivered a message to that
  participant, or the recipient has explicitly accepted. A pending conversation is stored and
  readable but MUST NOT appear in the default listing. It becomes `active` when the recipient
  first sends into it, or via the accept route.
- **Blocked.** An inbox may hold a node-local block list. A delivery from a blocked
  participant — of any type — is **accepted with a normal 2xx and indexed nowhere.**
  Suppression **survives redelivery**: re-delivering a blocked or rejected conversation does
  not resurrect it, so blocking cannot be undone by the blocked party retrying.

Cold contact still works, which the machine lane needs: an agent can always place a _pending_
conversation with a service it has never met. What consent removes is the ability to occupy
the recipient's primary surface without their action.

The blocked-sender rule is a **deliberate departure** from this protocol's fail-closed
honesty, and is recorded as such: a 2xx here does not mean "stored". Rejecting instead would
disclose the recipient's block decision to the sender, which hands a harasser a probe. The
recipient's protection is judged to outrank the sender's feedback; 010's retry-safety is
unaffected, since retries behave identically.

_Amended by 014:_ blocking must not silently destroy an E2EE group's state. Applied to an MLS
commit, "accepted and indexed nowhere" would permanently desynchronize the blocker's own epoch
with no in-profile recovery — external joins and external commits are banned — so the block
would harm the blocker most. Three rules, and each one is doing separate work:

- A node MUST NOT suppress a `pn/mls`, `pn/welcome`, or `pn/conversation-update`
  envelope from a sender its delivery-filter view holds as a member of the named conversation
  **and** whose highest-`epoch` evidence record is not a `remove` naming them (an `add` wins an
  epoch tie: a participant re-added at the epoch they were removed is present). The exception is
  keyed on evidence rather than on the add-monotone filter so that a departed member does not
  inherit a permanent, unsuppressable channel into every member's inbox — it exists to protect
  the group mechanics of current members, and someone who has authorized their own departure has
  no group mechanics left to protect. Keying on the _highest_ epoch rather than on "any accepted
  `remove`" is what keeps the condition from becoming a permanent mark on anyone who ever left.
  Reading the highest epoch off the records is not the record layer ordering anything: MLS
  assigned those epochs.
- A node MUST NOT emit a 013 event for a blocked sender's envelope, exception or not. A
  contentless poke is still an unsolicited attention channel, which is what blocking removes.
- A node MUST return the uniform 2xx to a blocked sender **regardless of the validation
  outcome**, so the exception does not turn the response into a probe of the recipient's state.
  Recovery for the recipient is a read, which is exactly what 013 says events are not needed
  for.

### Listing, filtered reads, read state

Three surface rules, same footing as 010's read rules — mechanism a client can rely on, no
new records:

- **`GET /inboxes/:id/conversations`** — lists the inbox's **active** conversations: for each,
  the conversation record, its digest id, the highest associated per-inbox `seq`, and the
  inbox's read cursor for it. `?state=pending` lists the pending ones instead. Ordering,
  pagination, and unread-count sugar are node surface. When a conversation was **created** in
  delegated mode the response includes **the chain stored with the conversation record** — the
  (record, chain) unit that authorizes the record itself (011), not the chain of whichever
  envelope last transported it, which is a different claim about a different act.
- **`PUT /inboxes/:id/conversations/:cid/accept`** — moves a pending conversation to active.
  Authorized by `msg/consent`, not `msg/cursor`: admitting a channel is a consent decision,
  not read-state.
- **`GET /inboxes/:id/messages?conversation=<digest>`** — the 010 read route gains a filter
  by `conversationId`, composing with the existing `with`/`after`/`limit` filters.

  _Amended by 014:_ for an `e2ee` conversation this filtered read **returns** the
  `pn/mls`, `pn/welcome`, and `pn/conversation-update` envelopes associated with
  it. The exclusion above exists so a chat client need not filter protocol payloads out of the
  message stream — but on the E2EE lane those payloads _are_ the conversation, and excluding
  them would leave the lane with no message surface at all. The **unfiltered default read is
  unchanged** and still excludes every reserved type, so a client that asks for the whole inbox
  still gets only ordinary messages. `highestSeq` and the read cursor work unchanged; commits
  and evidence consume a `seq` like any envelope, so unread counts over-report by the (low)
  group-mechanics rate — disclosed rather than papered over.

- **`PUT /inboxes/:id/conversations/:cid/read`** — sets the inbox's read cursor for a
  conversation: a per-inbox, per-conversation `lastReadSeq` (a past-or-present per-inbox
  `seq`). One cursor per conversation per inbox, shared across the owner's sessions — read on
  one device is read on all. This is node-local state, not a record: it is never signed,
  never relayed, never re-verified.

### Ability vocabulary (amends 011's inbox surface)

011 defines `msg/send` and `msg/read` for the inbox surface. This spec extends that vocabulary
and fixes the **rule that generates it**:

> A delivery of an envelope whose `type` is `pn/<name>` requires the ability
> `msg/<name>`. A delivery of any other envelope requires `msg/send`.

| Ability            | Authorizes                                                  |
| ------------------ | ----------------------------------------------------------- |
| `msg/send`         | deliver an ordinary (non-reserved) message                  |
| `msg/conversation` | deliver a `pn/conversation` payload — create, or re-deliver |
| `msg/read`         | read messages; list conversations                           |
| `msg/cursor`       | write a conversation read cursor                            |
| `msg/consent`      | accept a pending conversation; edit the inbox's block list  |
| `msg`              | umbrella — covers all of the above by 009 path-prefix cover |

_Amended by 013:_ the vocabulary also carries `msg/subscribe` (013 §2.3), a route ability
authorizing a realtime stream over an inbox — covered by the `msg` umbrella above, and by
nothing narrower.

_Amended by 014:_ the rule generates three more — `msg/mls`, `msg/welcome`, and
`msg/conversation-update`, from the reserved types above — and 014 adds one that the rule does
**not** generate: **`msg/keypackage`**, authorizing `PUT /participants/:id/keypackages`. It is a
route ability in this namespace, like `msg/read` and `msg/cursor`, which is why 013's namespace
reservation forbids ever minting a `pn/keypackage` envelope type. `msg/conversation-update`
deserves reading twice before it is granted: 014 makes `members == [actor]` self-authorizing, so
a delegate holding it can remove its subject from any conversation, and since add authority is
creator-only the subject cannot restore themselves.

Three things this rule buys, each answering a way the obvious alternative fails:

- **Sending is not creating.** 009 cover is path-prefix, so `msg/send` does not cover
  `msg/conversation`: a grant that lets an agent send messages cannot silently confer the
  authority to open threads in its principal's name.
- **It generalizes.** Every reserved payload a later spec adds — `task`, `proposal`,
  `approval-request` — arrives as a `pn/` envelope on this same route, and each gets its
  ability by the rule (`pn/task` → `msg/task`) rather than by a fresh negotiation. `msg`
  keeps meaning "all messaging authority".
- **Cursor writes are their own authority.** A delegate holding `msg/read` can already read
  everything, but cursor-writing lets it shape what the owner's _other_ clients surface as
  unread — suppressing a thread the owner would otherwise notice. That composes with the
  approval-request record to come: suppress, then ask. `msg/cursor` is a sibling, so
  `msg/read` does not confer it.

The cursor ability is deliberately **not** named `msg/read-state`: cover is by path segment,
so `msg/read-state` would be a sibling of `msg/read` that _reads_ like a child of it. Names
whose authority relationship must be reasoned out are how prefix-confusion bugs enter
verifiers; `msg/cursor` cannot be misread.

### Signing a Conversation: two modes, and any replay-valid key state

A `Conversation` verifies in the **same two modes 011 defines for envelopes**, and for the
same reason: custody's signing surface is a closed enumeration of protocol operations, so a
custodial participant signs through session keys or not at all. A creator-signed-only record
would mean **no participant under custody could ever create a conversation** — the feature
would exist only for participants holding raw root keys.

1. **Owner mode.** The record's signatures verify against the creator's key state (003),
   meeting that state's threshold.
2. **Delegated mode.** The record is signed by a session key, and it travels as a
   **(record, chain) unit** (011): the accompanying chain's subject is `creator`, its
   abilities cover **`msg/conversation`**, and the record's signature verifies against the
   chain's leaf key. The node stores the chain with the record, exactly as 011 stores a
   chain with a delegated envelope.

The transporting envelope's mode is **independent** of the record's mode: any member may
re-deliver a conversation, in either mode, whatever mode created it.

Against a given key state, the signature set is checked per **015**: exactly `threshold` members —
the "requires _m_ signatures here" above, read exactly — every one verifying against a distinct
listed key, in that state's key order, before the digest is taken as the conversation id. 015's
S5 states how strictness composes with the any-state rule below — the existential is over
states, so a stricter per-state check does not orphan a record signed under an older state.

**Verification is against any key state the creator's log replays to (008), not merely the
current one.** Verifying against current state would mean a creator's first key rotation
silently invalidates every conversation they ever created — the records are immutable and
already delivered, so there is nothing to re-sign. This is the rule grants already
follow (008); conversations inherit it rather than inventing a stricter one.

Two consequences worth stating plainly. A conversation created in delegated mode does **not**
re-verify from bytes alone with no time window — it carries 011's residual windows and needs
its chain, like any delegated record; only owner-mode records have that property. And a
revoked session key does not retroactively unmake the conversations it created: creation is a
completed act at a point in time, judged against the key state and chain valid then.

## Boundaries

- **Membership is not read authority.** `msg/read` on an inbox — not conversation
  membership — governs who reads that inbox, exactly as 010/011 left it. Membership scopes
  what may be _associated_, not who may _access_: a conversation member has no standing to
  read another member's inbox, and an inbox delegate sees every conversation in that inbox,
  member or not. Conflating the two would smuggle an access-control system into a grouping
  record.
- **Conversation records are private node data** (010). They never enter discovery. Who is in
  a conversation is at least as sensitive as that a grant exists, and is likewise never
  published.
- **Payload semantics stay above.** `title` display, reply-linkage conventions inside
  payloads, and every typed interaction record to come (tasks, proposals) live in the layers
  above; this spec fixes the container only.
- **Revocation does not unmake a conversation.** 008 revocation targets a record by digest,
  and a `Conversation` has a digest — but revoking one is defined to have **no protocol
  effect**: membership is not a capability, so there is nothing to withdraw, and a node that
  dropped conversations on revocation would let a creator silently unmake other members' view
  of a shared history. Leaving a conversation is a consent action on the recipient's node
  (blocking), not a record the creator can author on everyone else's behalf. What a creator
  _can_ revoke is a grant that let a session key act for them — which, as above, does not
  retroactively unmake completed acts.
- **One node's view.** All ordering here is 010's per-inbox `seq`; a conversation spanning
  nodes has one view per node. Cross-node ordering, and what "the conversation" means when
  members' nodes disagree, is a future federation spec's problem — deliberately not solved here.

## Non-goals

- ~~**Membership change**~~ Lifted by 014 **for the E2EE lane only**: evidence records
  authorize, MLS orders (see Decision). On the machine lane it is no longer a deferral but a
  standing non-goal — a changed group is a new conversation, permanently.
- **Shared read receipts, typing indicators, presence** — the cursor is private to the inbox;
  telling _other participants_ what you've read is a disclosure decision that deserves its own
  design.
- **Message edit, deletion, reactions** — message semantics, above the protocol.
- ~~**E2EE**~~ Lifted by 014: the encryption fork is specified there, and this record is where
  the lane is declared (`lane` / `groupNonce` above). A conversation with no `lane` is
  machine-lane — authenticated plaintext, by design and not by omission.
- **Conversation metadata mutation** (rename, etc.) — same mechanism shape as membership
  change; deferred with it. Still deferred on both lanes: 014's evidence record carries
  membership and device changes only, and defines no mutation of `title` or any other field.

## Open questions

- **Does record strictness belong in 001?** This spec requires strict schemas and rejects
  duplicate JSON keys because it is the first record whose _identity_ is its digest. Every
  other digest-addressed record has the same exposure; the rule probably belongs in 001 as a
  general convention, with this spec merely citing it.
- **Error codes are an oracle.** `not_a_member`, `unknown_conversation`, and
  `invalid_conversation` tell an unauthenticated-to-this-inbox sender something about a
  conversation they may not be in — including, by elimination, that a given conversation id
  exists. Check order determines what leaks. Implementations SHOULD fix the order (authorize
  the delivery, then membership, then conversation existence), and MAY collapse the
  distinctions to a single code where their disclosure is not worth the diagnostic value.
- **Cross-member consistency.** Fan-out lets a sender show different members different
  payloads under one conversation id. Transcript-consistency (hash-linking, or the E2EE lane's
  group agreement) would close it; is it worth anything in the plaintext lane?

  _Amended by 014:_ answered for the E2EE lane, by MLS's group agreement — members in the same
  epoch agree on group state and membership, so divergent fan-out is not expressible there
  (014 claims nothing beyond that: transcript-consistency _proofs_ past group agreement are an
  explicit non-goal). The question stands as written for the machine lane, which keeps this
  spec's honest-sender limit.

- **Conversation-scoped retention.** 010's retention open question, now per conversation.
- **Very large memberships.** Sender-side fan-out is O(members) signatures per message;
  whether a future federation spec wants a relay/queue answer or the protocol wants nothing.

## History

- 2026-07-28 — Accepted: the `Conversation` record and its digest identity, the reserved `pn/`
  envelope-type prefix and `pn/conversation`, message-to-conversation association, the consent
  states, the listing, filtered-read and cursor routes, and the ability-generating rule.
- 2026-08-01 — Amended by 014: the `lane` and `groupNonce` fields, three reserved E2EE-lane
  envelope types, the lane/type gate, the evidence-record membership view, the block-list
  exception, and the filtered read returning E2EE-lane payloads.
- 2026-08-08 — Signature-set checking pinned to 015: exactly `threshold` signatures, each
  verifying against a distinct listed key in that state's key order, checked before the digest
  is taken as the conversation id.
- 2026-08-13 — Reserved envelope types took the brand-neutral `pn/` prefix (000).

## References

- Spec 000 (placement test), 001 (JCS), 002 (participant id), 003 (digest rule, key
  resolution), 005 (signature suite), 008 (revocation), 009 (grants), 010 (inbox surface —
  amended by this spec: threading non-goal lifted, reserved `pn/` type prefix, read-route
  filter), 011 (delegated requests, (record, chain) unit), 013 (realtime — mirrors this spec's
  visibility rules), 014 (the E2EE lane — amends this spec: `lane`/`groupNonce`, membership
  change for that lane, three reserved types, the lane gate, the filtered read, the block-list
  exception), 015 (canonical signature sets)
