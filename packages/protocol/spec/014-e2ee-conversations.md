# 014 — Two-lane conversations: the E2EE lane

**Status:** Accepted
**Blocks:** human-private conversations — the interaction plane's encryption fork, and the
membership-change mechanism 012 deferred here

## Context

Every message in the network today is authenticated plaintext: signed, tamper-proof, and
readable by the node operator — a stated 010 non-goal, and the **right default for the machine
lane**. Agent and workflow traffic wants auditability and operator visibility; the machine lane
is deliberately authenticated plaintext and is never presented as private (010). It is not
acceptable for private human conversation, which requires a **two-lane design**: the machine lane
as it stands, with retrofitting E2EE onto it an explicit non-goal, and a **human-private lane**
that is end-to-end encrypted — unreadable by every node operator on the path, and surviving a
member adding a second device.

The substrate this lands on was laid deliberately:

- **005** already decided the crypto: MLS (RFC 9420) is named for group messaging. This spec
  composes with MLS; it does not mint cryptography (000 #5).
- **012** gives the container: a signed Conversation record with a digest id, delivered
  through the inbox, with consent, listing, cursors — all of it lane-agnostic. 012 deferred
  membership change to this spec so the mechanism would be designed once, for ciphertext,
  not retrofitted from a plaintext-first design.
- **013**'s events are **contentless** — a poke names no payload — so the realtime surface
  carries an E2EE conversation without disclosing anything new. It does need two amendments
  (§"Consequential amendments"): 013 suppresses events for reserved-type envelopes, and on
  this lane the content _is_ a reserved type.
- **011** gives devices _signing_ keys under expiring, revocable grants — but no encryption
  keys, and custody signs only a closed enumeration of operations, so a custodial human's root
  key can never touch message encryption. That constraint is load-bearing below.

Three tensions, faced here rather than deferred:

1. **Multi-device.** Sessions give devices signing keys; E2EE needs per-device encryption
   state, key agreement across a member's devices, and a story for adding and losing devices.
2. **Custody must not read.** A custodial participant's messages must be unreadable by the
   custody service holding their root key — which bounds history recovery and is documented
   below as a stated trade-off, not smoothed over. What custody _can_ still do, because it
   holds the root key, is stated just as plainly (§"Custody").
3. **Group membership change** — deferred from 012 v1 to be co-designed with the ciphertext
   mechanism, and the hardest thing here. §"Membership change" states the design rule the
   whole mechanism follows: **the record layer never orders anything.**

Run the placement test (000) on what this spec adds to the protocol: the **lane marker** (two
implementations must agree which conversations are E2EE — interop, and the downgrade defense),
the **credential profile** binding an MLS leaf to a participant (members from different
implementations must verify each other's leaves the same way), the **wire profile** for MLS
messages riding the inbox (reserved types, same footing as `pn/conversation`), the
**membership-evidence record** (an authorization that must validate identically at every
member and travel between nodes), and the **KeyPackage surface** (a member cannot be added
without fetching key material from somewhere both sides agree on). MLS itself is adopted, not
specified — this spec pins a profile of it, the way 004 pins a profile of RFC 9421, and pins it
to the byte level for the same reason.

## Decision

### One mechanism: every E2EE conversation is an MLS group

An E2EE conversation is backed by exactly one MLS group (RFC 9420). A 1:1 conversation is a
2-member group; there is no separate pairwise protocol. One mechanism, one set of security
properties, one implementation to review — and group membership change, the hardest deferred
problem, arrives as MLS's native Add/Remove/Update commits instead of a second design.

MLS runs **only in clients** — client SDKs and the runtimes above them. The node never joins a
group, never holds group state, and never decrypts: it stores and forwards opaque MLS payloads
and enforces record-level gates. 005's open question — whether MLS runs in the node runtime or a
sidecar — is answered: neither.

#### The profile, pinned

A profile that is not pinned to the byte level is not interop (004's precedent). For v1, and
additively extensible later (000 #6):

| Element                 | Pinned value                                                                                                                                                                                                                                                                                                                                  |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Ciphersuite             | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420 mandatory-to-implement; Ed25519 matches the signature suite pinned by 005)                                                                                                                                                                                                           |
| Protocol version        | `mls10`                                                                                                                                                                                                                                                                                                                                       |
| `group_id`              | the **raw multihash bytes** of the conversation's digest id (012) — not its multibase string                                                                                                                                                                                                                                                  |
| Credential type         | `0xF001`, a private-use `CredentialType`; IANA registration is a wire-freeze follow-up                                                                                                                                                                                                                                                        |
| Credential encoding     | `struct { opaque chain<V>; } PNCredential;` — TLS presentation syntax, variable-length-prefixed. `chain` is the UTF-8 of 011's `1:`-prefixed chain encoding                                                                                                                                                                                   |
| `capabilities`          | every LeafNode MUST list credential type `0xF001` in `capabilities.credentials`, and MUST NOT list any other credential type                                                                                                                                                                                                                  |
| `required_capabilities` | the group MUST carry a `required_capabilities` extension naming credential type `0xF001` (that extension carries credential/extension/proposal types only — no ciphersuite; the ciphersuite is already fixed in GroupContext)                                                                                                                 |
| Framing                 | `PrivateMessage` only; a client MUST reject a `PublicMessage`                                                                                                                                                                                                                                                                                 |
| `authenticated_data`    | on a Commit, MUST be exactly the minimal evidence binding defined in §"Membership change"; on an application message, MUST be empty. (No other framed type reaches this field in profile — Welcome has none, and standalone Proposals are out of profile.)                                                                                    |
| Padding                 | application messages MUST be padded to a multiple of **256 bytes**; handshake messages MUST NOT be padded (their sizes are already structural)                                                                                                                                                                                                |
| Welcome                 | MUST carry the `ratchet_tree` extension, so a joiner needs no out-of-band tree fetch                                                                                                                                                                                                                                                          |
| KeyPackage `lifetime`   | REQUIRED on the LeafNode of every published KeyPackage, with `not_after` no later than the earliest `expiresAt` in that leaf's credential chain. (RFC 9420 carries `lifetime` only on `key_package`-sourced LeafNodes, so this binds at publication and join — it is not, and cannot be, a per-epoch check; §"Eviction" says what that costs) |
| Out of profile          | external joins, external proposals, external commits, PSKs, reinit, subgroup branching, `GroupContextExtensions` proposals, **proposals by reference** and standalone Proposal messages (every proposal MUST be by value inside its Commit, so a commit is self-sufficient to validate and to re-deliver) — a client MUST reject each         |

Committed conformance fixtures pin credential bytes ↔ chain, `group_id` bytes ↔ conversation
id, and the commit evidence binding, so a second implementation checks itself from bytes alone.

### The lane is declared in the signed record

The `Conversation` record (012) gains two optional fields, under the signature:

```
Conversation {
  ...                       // 012 unchanged
  lane?: "e2ee"             // absent = machine lane (authenticated plaintext, as today)
  groupNonce?: string       // multibase 32 random bytes; REQUIRED iff lane == "e2ee"
}
```

- **`lane` MUST be omitted for the machine lane** — never `"machine"`, never `null`. One
  logical conversation must have one digest (012's strictness rule); an explicit machine value
  would create two byte-forms for the same thing.
- **`groupNonce` makes every E2EE conversation record byte-unique.** Ed25519 is deterministic
  and `createdAt` is creator-chosen, so without a nonce a creator could re-sign byte-identical
  records and obtain the same `group_id` for two distinct MLS groups — a joiner would then
  receive a Welcome for a group it already holds state for. The nonce closes it at the record
  layer; belt-and-braces, a client MUST refuse a Welcome whose `group_id` names a group it
  already holds state for.
- The lane is **immutable for the life of the conversation** — it is part of the digested
  bytes, so "the same conversation, downgraded" is not expressible: tampering with the lane
  changes the id. A client MUST render the lane from the verified record, never from message
  traffic.

The node enforces lane/type consistency; this is **not** left to client goodwill. The node
holds the verified Conversation record, so it knows the lane, and it sees `envelope.type`:

- an envelope carrying an `e2ee` conversation's `conversationId` MUST be rejected
  (`lane_mismatch`) unless its type is `pn/mls`, `pn/welcome`, or
  `pn/conversation-update`;
- an envelope of type `pn/mls` or `pn/welcome` naming a machine-lane conversation MUST
  be rejected (`lane_mismatch`).

The lane check runs **after** the membership check, so the code discloses nothing to a
non-member that membership did not already disclose (012's error-oracle open question governs
the order for every code on this route).

Without this gate a buggy client, a client-library regression, or a delegate holding only
`msg/send` (a _different_ ability from `msg/mls`) could associate cleartext into an E2EE
conversation and the node would store it in the clear forever. 012 already fails closed on
unknown reserved types; the lane rule gets the same treatment.

What the marker cannot prevent is a **counterparty** starting a machine-lane conversation and
a user not noticing; that is a surface obligation — clients MUST visibly distinguish the lanes
(the machine lane's "never presented as private" stance is the other half of the same rule).
Note also that re-delivery takes a fresh per-inbox `seq` (010) while `createdAt` is
informational, so an operator can make an old machine-lane conversation surface as new next to a
live E2EE thread: clients SHOULD order by first-seen, not by re-delivery.

### Members are participants; leaves are devices

An MLS leaf belongs to a **device**, not a participant. A member with three devices holds
three leaves; every leaf decrypts every application message (that is what group encryption
buys), so multi-device needs no fan-out change — one inbox per participant (010), every device
reads it (011 `msg/read`), each device processes what it holds keys for.

The binding from leaf to participant is the **credential**: a Grant chain (009/011), leaf-first,
whose leaf audience is the MLS leaf's signature public key encoded as a `KeyRef` (005), carried
as credential type `0xF001` in the encoding pinned above.

- The chain's `subjectId` is the member participant. The root link is self-issued by the
  participant (009) — signed by the root key directly, or issued through custody's session
  mechanism exactly like every other session grant (011). **Custody signs a grant naming the
  device's public keys; it never sees, generates, or stores the device's private MLS keys.**
- **The chain's abilities MUST lie entirely within the `e2ee` namespace**, where "within" is
  the pinned predicate: every ability `a` in every link satisfies
  `a === "e2ee" || a.startsWith("e2ee/")`. A credential chain carrying any other ability is
  **malformed** — a validity rule, not policy, so independent verifiers agree (011's precedent
  for cross-field grant rules), enforced by schema and fixtures. The ability that means "hold
  an MLS leaf that speaks for the subject" is **`e2ee/leaf`**. Every link MUST also carry
  **empty `caveats`**, for the reason rule 3 gives: a caveat a verifier cannot evaluate fails
  closed, which in a group is a split.
- **`e2ee` abilities are member-verified and never request-valid.** A verifier MUST reject a
  request whose presented chain contains **any** ability satisfying the predicate — the
  whole-chain reading, pinned so two verifiers cannot differ: a chain that could serve as a
  credential is never also a request authorization. Consequently 011's rule "key-audience
  grants MUST carry `caveats.aud`" is amended: a key-audience grant whose abilities satisfy the
  predicate MAY omit `caveats.aud`. There is no request surface to bind it to, the set of
  future counterparty verifiers is unknowable at issuance, and a stolen credential authorizes
  **zero requests anywhere** — the namespace rule is the bound the caveat would have been.
  Because the exemption predicate and the never-request-valid predicate are the same function
  over the same chain, no chain lands in a gap between them.
- **The MLS leaf signature key MUST NOT be a key used for request signing** (011 session keys
  included). Credentials are handed to counterparties and, via KeyPackages, to strangers; a
  shared key would publish a request-signing identity and breach 011's "chains disclose"
  boundary wholesale. The MUST is cheap to obey and unverifiable in general, so it gets one
  enforcement point: a verifier MAY reject a credential whose leaf `audienceId` it has ever
  seen as a request `keyid`, and a counterparty MAY reject a request `keyid` it has seen as a
  leaf audience.
- Clients SHOULD use a **fresh leaf signature keypair per conversation**. Reuse across
  conversations publishes a cross-conversation device graph (see §"claims"); a per-conversation
  key costs one extra credential issuance — for custodial participants, one custody round-trip
  — and removes the linkage.
- A member MUST verify every other leaf's credential chain — at join, and on every commit that
  adds or updates a leaf — resolving participant issuers through their key logs (discovery,
  003). §"Eviction" says what happens when verification fails, because "don't encrypt to it" is
  not a thing MLS can do.

The result is one identity system, not two: the same grant chains, the same revocation, the
same key logs answer "may this device speak for this participant" whether the device is signing
an HTTP request or holding an MLS leaf.

### Membership change: evidence, not ordering

012 deferred membership change so it would be designed once, here. The design rule, stated
first because everything below follows from it:

> **The record layer never orders anything. MLS is the only orderer.** A record can say _"the
> participant authorizes this change"_; it may not say _"this change came after that one"_.

The alternative — a hash-chained, replayed log at the record layer, with MLS made to follow it —
breaks in one way: any member can author records for free, so any ordering rule over them is
contestable, and wiring a contestable order into MLS — where commits
are irreversible and external joins are out of profile — converts a recoverable index problem
into a permanently split group. MLS already linearizes (epochs are total), already agrees on
membership within an epoch, and is the one layer here an attacker cannot extend for free. So it
orders, and the record layer only carries **evidence** it validates against.

#### The evidence record

```
ConversationUpdate {
  conversationId: Multihash        // the conversation's digest id (012)
  kind:           "add" | "remove" | "device-add" | "device-remove"
  members:        ParticipantId[]  // affected participants; non-empty, unique, sorted.
                                   //   device-*: exactly [actor]
  leaves:         KeyRef[]         // affected MLS leaf signature keys; non-empty, unique, sorted
  actor:          ParticipantId    // the participant whose authority this record carries
  epoch:          string           // decimal, no leading zeros: the MLS epoch this record
                                   //   authorizes a commit to extend (see below)
  createdAt:      string           // RFC 3339, informational (010 stance)
  signature:      Signature[]      // 012's signing convention: owner mode (actor's key state at
                                   //   threshold) or delegated mode as a (record, chain) unit
                                   //   with abilities covering msg/conversation-update
}
```

No `seq`, no `prior`, no chain. There is no chain to fork, no tip to resolve, and nothing to
grind: each record is an independent, self-contained authorization, signed **by the
participant** (root key, custody, or a session key per 012's two modes) — never by an MLS leaf.
That last point is what makes eviction survivable: a participant who has lost every device can
still author `device-remove` for the lost leaves.

**`epoch` makes a record one-shot without making it an orderer.** The design rule says a record
may not state that one change came after another; it says nothing against a record **naming the
MLS state it authorizes a change to**, which is referencing MLS's order rather than defining a
competing one. The field is load-bearing: without it an authorization is replayable forever, so
a self-`remove` could be re-cited to evict a member who had legitimately rejoined, and an old
`add` could be re-cited to force a departed member back in — leaving would not be durable, and
a member's own past departure would become a permanent eviction warrant in anyone's hands. With
it, a record authorizes exactly one commit at exactly one point in MLS's own linear history.

A participant with no surviving device can still read the current epoch — it is cleartext in
MLS framing (§"claims") — so authoring `device-remove` after total device loss remains possible
from inbox access alone. Under commit contention a record may need re-authoring at the new
epoch; that is ordinary optimistic concurrency, and it is the price of one-shot semantics. One
case deserves a client rule rather than a shrug: a member who authors a self-`remove`, loses the
race, and goes offline **has not left**, and nobody can re-author for them. A leaving client
SHOULD therefore author its self-`remove` for a short run of epochs _N..N+k_ before going quiet
— each record stays one-shot, and departure stops depending on the leaver still being around.
A lower bound (`minEpoch`) would not do: it leaves the rejoin-then-replay window open. Nor
would a node- or client-side "consumed digests" set, which is exactly the view-dependent state
this design exists to avoid — a member who joined between the original and the replay would
reach a different verdict and the group would split.

The epoch run has a dead end, stated so no implementer commits into it: a `remove` record names
the leaves known **when it was authored**, but rule 1's complete-removal check is evaluated against
the tree **the commit extends**. If the departing participant's leaf set changes in between —
their other device commits a `device-add` during the run — the later-epoch records of the run
become uncoverable: removing the union of named and actual leaves fails "every named record
covers a proposal" (the new leaf is uncovered), and removing only the named leaves fails
complete removal. Both verdicts are correct; the record is simply unusable at that epoch. A
committer MUST therefore refuse to build a commit from a `remove` record that does not name
every leaf its members currently hold, rather than guess — the commit it would build is invalid
at every peer while self-applied locally, which is a self-inflicted split. The remedy is
re-authoring at the current epoch, and the practical consequence is a client rule: a device
SHOULD NOT author `device-add` for a participant whose pending self-`remove` evidence it holds.

It travels as **`type: "pn/conversation-update"`** (ability `msg/conversation-update` by
012's generative rule) and is validated like `pn/conversation`: strict schema, duplicate
JSON keys rejected, digest-checked, signature per 012's two modes against any replay-valid key
state (008).

**Delivery gate.** A `pn/conversation-update` envelope is gated against the **union of
membership before and after the record it carries**, evaluated per target inbox (012's per-inbox
rule). This is not a special case bolted on — it is what the gate must be for the mechanism to
function at all: an `add` must reach a participant who is not yet a member, and a `remove` must
reach the participant it removes, which is the only way they learn of it (and which
§"Reconciliation" makes a client-rendering MUST). A gate read at the wrong instant would make
onboarding impossible and removal silent.

#### The `(record, chain)` unit is the wire form

A delegated-signed record must travel with the chain that authorizes it. The `signature` field
above says "delegated mode as a `(record, chain)` unit", and §Boundaries promises federation
records that are self-contained and re-verify per 011; a bare-record payload satisfies neither.
It would carry the authorizing chain to a reader only as the _transport_ chain of the authoring
delivery, so a delegated-signed record would be verifiable by nobody who did not receive it from
the exact session key that signed it. That makes the two re-delivery paths this spec declares
normative — "any member may re-deliver any evidence record" (the stall recovery above) and the
adder relaying history to a joiner (§"The wire") — impossible for precisely the population that
cannot sign any other way: custodial participants, whose custody signs grants and never records.
So the unit is the wire form.

**The payload of a `pn/conversation-update` envelope is `{ record, chain? }`** — the evidence
record, and, when the record is delegated-signed, the leaf-first grant chain that authorizes it.
The **`pn/conversation` payload takes the same shape**, for the same reason and on both
lanes: 012's record has the same two signing modes and the same custodial population, and
`addParticipant`'s first step is a member re-delivering that record to a non-member, which a
custodial creator on a later session could otherwise never do.

- **Digest identity is over `record` alone.** The chain travels _alongside_ the record, never
  inside it — the same placement as a KeyPackage's credential (§"KeyPackages"). A record
  therefore has exactly one id whether or not a chain accompanies it, so a re-delivered or
  relayed unit names the same digest in a commit binding as the authoring delivery did. Both
  record schemas are strict, so a `chain` key _inside_ a record — the one shape that would change
  its id — is malformed, not merely unwelcome.
- **`chain` MUST be present, and MUST verify per the profile below, whenever owner-mode
  verification of `record` fails.** A unit satisfying neither mode is invalid.
- **A unit carrying a chain that does not verify is invalid even if the record owner-verifies.**
  Fail closed: there is exactly one reason a unit is valid, and a presented chain is never
  decoration. The alternative — silently ignoring a malformed chain because the record happened
  to owner-verify — makes the verdict depend on evaluation order and hands an attacker a free
  field to grind.
- **When `chain` is present it is non-empty.** An empty array claims delegated mode and then
  names no delegation; no verifier can distinguish that from a truncation.
- **Any member may re-deliver the unit, in either transport mode** — owner-signed envelope or
  delegated one, from any of their devices. **The unit, not the envelope, is what re-verifies**,
  so a receiver never couples the record's authorization to the delivery's. The envelope is still
  gated normally (010/011 plus this spec's union-membership gate); it just no longer decides
  whether the record inside it is authentic.

#### What verifies a unit — the profile, pinned

Members and nodes evaluate the same unit, so the rules are pinned here rather than left to each
implementation. Two of them are deliberate deviations from 011's bytes-alone profile; both are
stated with their reasons, and the residual is disclosed rather than papered over.

**Owner mode (`chain` absent):** resolve the actor's key **log** (003), replay it, and accept the
record's threshold signature against **any replay-valid key state** — not only the current one. A
current-state-only check silently invalidates every record a participant signed before their last
rotation, which 012 already forbids for conversation records and which here would retroactively
un-authorize committed membership.

**Delegated mode (`chain` present):**

1. **Structure**, per 009/011: the root link is self-issued, `proof` digests chain, each non-root
   issuer equals its parent's audience, `subjectId` is constant, abilities only attenuate.
2. **Subject is the actor**: the chain's `subjectId` equals `record.actor`, and every
   participant-issued link's signature resolves through **that** issuer's key log, at any
   replay-valid state; key-issued links self-certify (011). Resolution failure is a **WAIT, never
   a rejection** — the same rule, for the same reason, as an unresolvable evidence signature
   above: key logs are monotone, so an honest member's verdict converges, and rejecting on a
   cache miss would split the group.
3. **Leaf binding**: the leaf `audienceId` is a `KeyRef`, and the record's single signature
   verifies against exactly that key.
4. **Abilities**: the leaf's abilities cover `msg/conversation-update` under 009's path-prefix
   rule — except for a self-departure, which needs its own ability (below).
5. **Expiry is checked against the record's `createdAt`**, which MUST fall inside every link's
   `[issuedAt, expiresAt]` window. **Wall-clock expiry is never applied**, at a member or at a
   node re-delivering. This is 011's bytes-alone position ("an expired grant does not
   retroactively unauthenticate the messages sent under it"), and on this lane it is load-bearing
   in a way it was not there: a wall-clock check makes the verdict depend on _when_ a member
   verifies, so an early member marks the record verified while a joiner — or a member
   re-verifying old evidence after a rejoin — never can. The same commit would then apply for
   some members and stall forever for others, which is exactly the view-dependent divergence the
   wait-uniformity argument above exists to exclude.
6. **Caveats are not evaluated by members**, `aud` included. Session grants are `aud`-bound to the
   _node_ the delivery is presented to; a verifying member is never the named audience, so a
   fail-closed `aud` check would reject every well-formed custodial chain. 011 already pins this
   for stored chains ("caveats are delivery-time-only… not re-checked"). The delivering node
   evaluated `aud` in real time; members skip caveat evaluation entirely.
7. **Revocation is not a member-side verification input.** The **node** checks revocation at
   delivery time — real time, non-consensus, the same check the request verifier already runs —
   and refuses the delivery. Members do not. This is the second deliberate deviation from 011,
   and the reason is uniformity, not convenience: 011's bytes-alone re-verifier answers a _local_
   question about a stored message, while this verifier feeds a **group-uniform** wait/apply
   decision, and a revocation one member's discovery view holds and another's does not (013's
   T13 — a host can withhold one) would make one member apply a commit and another wait forever.
   Key-log stalls clear because key logs are monotone; revocation views are not. A member that
   _does_ independently know a chain revoked MUST refuse to author or commit on top of it and
   SHOULD warn — exactly revocation's role for credentials in §"Eviction". Already-verified
   evidence is never demoted; demotion would be the view-dependent divergence again.

**A self-departure needs its own ability**, pinned as `conversation/self-remove`. A `remove`
record whose `members` is exactly `[actor]` is self-authorizing under rule 2, and any member will
commit it — so a delegated signer holding `msg/conversation-update` can expel its own subject
from every conversation they are in, and,
since add authority is creator-only, the victim cannot restore themselves. A delegated-signed
self-departure therefore requires a chain covering **`conversation/self-remove`**; bare
`msg/conversation-update` does **not** suffice, and neither does the bare `msg` umbrella. The
string sits deliberately **outside** the `msg` namespace: 009's cover rule is path-prefix, so a
sibling namespace needs no exclusion carved into the umbrella's cover math — `msg` covers
`msg/conversation-update` exactly as before, and covers `conversation/self-remove` not at all.
Owner-mode self-departures are unaffected; abilities gate delegation, not the participant.

The consequence for custody, stated because it changes what an everyday grant means: a routine
session grant — the kind a web client mints on every login — no longer carries self-expulsion
authority. Issuing a self-remove-capable grant is a deliberate act, and a client that wants to
offer "leave conversation" from a session key must ask for that ability by name.

The ability split holds only if the **device** path cannot reach the same outcome, and by itself
the device path does not: a `device-remove` naming every leaf its actor holds expels that actor
while needing nothing beyond the `msg` umbrella. That is closed as a commit-validity rule rather
than an ability — a `device-remove` MUST leave its actor a leaf (rule 2's device clause below) —
because whether a removal takes the last leaf is a question about group state, and this profile
is bytes-alone by design. The abilities above stand as written; the guarantee "an everyday `msg`
grant cannot expel its own subject" is the two rules together.

**A delegated-signed record carries exactly one signature.** In delegated mode the chain names
exactly one authorized signer, so rule 3's "the record's single signature verifies against that
key" is a length rule too: a `signature` array with any other cardinality is **invalid**.
Threshold verification accepts on any matching member of the set and ignores extras, while the
record's digest covers the `signature` array — so without the length rule, appending a junk
signature to a valid record yields a second, distinct, equally-valid record for the same logical
change. It
confers no new authority (the epoch one-shot pins the change to one commit at one point in
history), but it forges a second identity for it, and identity-by-digest is what "records are
idempotent by digest", commit bindings, and held-evidence maps all rest on. Owner mode is
unaffected: there a signature set really is a threshold.

**The residual, disclosed.** `createdAt` is chosen by the signer, so a session key stolen after
its grant expired can backdate a record into the grant's window and pass rule 5 — 011's disclosed
backdating window, inherited here. Expiry does not close it and this spec does not pretend
otherwise. Two things bound it: the delivering node's **delivery-time revocation gate** (so 011's
standing rule holds — a device that may be in someone else's hands is revoked, never merely left
to expire), and the **epoch one-shot** above, which limits a backdated record to authorizing
exactly one commit at exactly one point in MLS's history.

#### Binding evidence to the commit

A Commit's `authenticated_data` MUST be exactly:

```
struct { opaque digest<V>; } Evidence;
struct { Evidence evidence<V>; } PNCommitBinding;
```

— the multihash digests of the `ConversationUpdate` records authorizing this commit, sorted by
codepoint. `authenticated_data` is signed by the committer (it is inside `FramedContent`, so it
is covered by `FramedContentTBS`) and passed as AEAD associated data, so the binding is
tamper-proof; and the evidence records themselves are already delivered in cleartext as
envelopes, so binding their digests discloses nothing new to the operator.

**The binding MUST be minimal and exact**, or the field is a covert channel in cleartext on
every commit: every named digest MUST name a record that covers a proposal in this commit, and
every Add or Remove proposal in this commit MUST be covered by a named record — **except in the
founding commit, whose coverage is the Conversation record itself and whose binding is empty**
(below). A commit that changes no membership and no leaf set MUST likewise carry the empty list.
A binding with an unused entry or a missing entry is invalid — "fully specified shape" is not
enough when the contents are attacker-chosen bytes.

A digest naming a record the validator does not hold is **not** invalid; it is a wait
condition. No member can distinguish "this names nothing" from "this has not reached me yet",
so treating it as invalid would make one member apply what another rejects — the exact
view-dependence these rules exist to exclude. A member that does not yet hold a named evidence
record MUST NOT apply the commit and MUST wait for it: any member may re-deliver any evidence
record, records are idempotent by digest, and a missing record is a delivery gap that closes
monotonically once filled. Everyone stalls uniformly, and someone else commits at that epoch.

**An evidence record whose own signature cannot yet be verified is on exactly that footing:
wait.** Checking a record's signature means resolving `actor`'s key log (owner mode) or the
presented chain's issuers (delegated mode), which is the same resolution dependency rule 3
carves out for credentials — but the safe answer is the opposite one, and the asymmetry is the
point. For a **credential**, failing open is right: the leaf is in the tree whatever this member
decides, so refusing costs the group and buys nothing. For **evidence**, failing open would mean
applying an authorization nobody checked, which is precisely what rule 2 exists to prevent. Wait
is safe because it is uniform — every member lacking the resolution stalls, none of them
diverges, and the stall clears as key logs advance (they are monotone). A member MUST NOT reject
the commit on an unresolved evidence signature, and MUST NOT apply it either.

**Commit validity** is then a function of the commit's own bytes, the named evidence records,
and — for the one check that cannot be pure, rule 3's signature verification — the issuer key
states each member resolves. Everything else is excluded by construction: no clock, no
revocation view, no branch choice.

The rules, exhaustively. A Commit is valid under this profile iff, in addition to RFC 9420's
own validity — with one carve-out, since RFC 9420's own validity includes a wall-clock check:
**an elapsed KeyPackage `lifetime` MUST NOT invalidate a Commit.** The lifetime pinned in the
profile table is enforced where it is safe to enforce a clock, at publication and at claim; a
member rejecting a commit because a lifetime lapsed between the claim and the commit would split
the group on a clock skew, and short lifetimes (which §"Eviction" recommends) make that boundary
more reachable, not less.

1. Every Add or Remove proposal it contains is **covered by named evidence** — except in the
   founding commit (below), where the Conversation record is the coverage. Covered means all of,
   evaluated per record:
   - **Same conversation.** The record's `conversationId` equals the conversation id whose
     multihash bytes are this group's `group_id`. Without this a record travels between groups:
     a departure from one conversation would evict its author from every other, and a
     `device-add` harvested anywhere would insert that leaf here.
   - **Same point in history.** The record's `epoch` equals the epoch of the group state this
     commit extends (its pre-commit epoch). This is the one-shot rule above.
   - **Matching kind and leaves.** The added or removed leaves appear in the record's `leaves`,
     with `kind` `add`/`device-add` for Adds and `remove`/`device-remove` for Removes.
   - **Exact participant set.** The participants affected by the proposals **this record
     covers** equal that record's `members` **exactly** — set equality, not containment,
     evaluated per record so a commit may carry several records, for every kind including
     `device-*` (whose `members` is `[actor]`, so a `device-add` can never introduce a
     participant). Containment would let a committer smuggle extra participants in alongside a
     legitimate record.
   - **Complete removal.** For a `remove`, the commit MUST remove **every** leaf of the named
     participants present in the tree. A partial removal would let "X left" render at every
     client while one of X's leaves — a stolen or ghost device, chosen by whoever authored the
     record — keeps decrypting. Checkable from commit bytes plus group state, so it stays
     inside the allowed input set.
2. Each named record is **authorized**, by its own bytes plus the group state the commit
   extends:
   - `add` — `actor` is the conversation's creator, and the creator is a member of the group
     the commit extends.
   - `remove` — `actor` is the creator, **or** `members == [actor]` (a participant authorizing
     their own removal — this is what lets anyone commit a departure, including the creator's,
     since MLS forbids committing your own Remove). Commit authorization does not turn on the
     self-remove ability split: what a **delegated** signer must hold to author the record in the
     first place is `conversation/self-remove` (§"What verifies a unit"), and a record that
     verifies is authorized here on its own terms.
   - `device-add` / `device-remove` — `members == [actor]`, every named leaf's credential has
     `subjectId == actor`, **and `actor` already holds at least one leaf in the group the commit
     extends**. A participant governs their own device set; no one else does — but governing
     your device set is not a way _in_. Without the last clause a `device-add` becomes an
     unbounded membership bypass: any participant, including one who left or was never a
     member, could author one for their own device and have any member commit it, defeating
     creator-only add authority and the creator-less-conversation rule together.

     A `device-remove` MUST additionally **leave its actor holding at least one leaf** in the
     group the commit extends. A commit whose `device-remove` records would take their actor's
     last leaf is **invalid at every peer**, measured against every Remove the commit carries — not
     only the ones a single record covers, or the victim's leaves could be split across two
     records in one commit, each retaining what the other takes.

     This closes the device path around the self-remove ability. Full departure is a `remove`,
     and a delegated signer may only author one for its own subject with
     `conversation/self-remove` (§"What verifies a unit") — but a `device-remove` needs no more
     than the bare `msg` umbrella, and the leaf key refs it names are public. Without this rule
     an everyday session grant still carries unilateral self-expulsion authority, spelled
     `device-remove` instead of `remove`, with the same irreversibility: add authority is
     creator-only, so a non-creator victim cannot restore themselves. The rule is not a member's
     ability check but a **commit-validity** one, because "does this removal take the actor's
     last leaf" is a question about group state, which the bytes-alone unit profile has no way
     to answer and must not acquire; every member reads the same pre-commit tree, so the verdict
     stays uniform. It also forbids nothing legitimate: a zero-leaf member decrypts nothing, and
     `device-add` requires a leaf pre-commit, so they could never re-add a device either.

3. Every leaf the commit **adds or updates** carries a credential chain that satisfies the
   **structural** half of 009's chain rules — proof digests chain, the root is self-issued
   (`issuerId == subjectId`), each non-root issuer equals its parent's audience, `subjectId` is
   constant and equals the participant the evidence names, abilities and caveats only attenuate,
   and the leaf audience is that leaf's signature key. These are pure functions of the chain
   bytes, so every member decides them identically.

   Two exclusions, both because they are not pure, and both fail-**open** rather than
   fail-closed:
   - **009 rule 6 is excluded in its entirety** — expiry, revocation, _and_ its fail-closed
     caveat rule — on the same footing as 011's bytes-alone re-verification carve-out. Expiry
     and revocation are wall-clock- and registry-dependent. The caveat rule is worse: a verifier
     that cannot evaluate a caveat MUST reject, so one stray caveat would split the group
     between implementations that understand it and implementations that do not. Rather than
     leave that to a literal reading of an exclusion, the shape is closed at the schema: **every
     link of a credential chain MUST carry empty `caveats`** — malformed otherwise, exactly like
     the `e2ee`-only ability rule above and with the same accept/reject fixtures. A credential is
     presented to no verifier and exercised against no surface, so it has nothing to narrow.
   - **Signature verification against a resolved issuer key state is not a validity
     condition.** 009's rule 1 resolves a participant issuer through its key log, which every
     member reads from a cache with a TTL (013 §2.4.4) and which a discovery host can withhold
     (013's T13). A member who cannot resolve an issuer's key state, or whose log is stale,
     MUST treat that leaf as **unverified** — surface it, retry resolution, and re-check when
     the log advances — and MUST NOT reject the commit. Key logs are monotone, so an honest
     member's verdict converges; a _commit_ decision does not, so making it depend on
     resolution would split the group on a cache miss.

   This is the same fail-open the joiner rule takes for pre-join leaves, and for the same
   reason: a member gains nothing by refusing a commit the rest of the group applied, and loses
   the group. What an unverified leaf does buy is a warning, and grounds to author
   `device-remove` — which is where a bad leaf is actually dealt with (§"Eviction").

4. An **Update** proposal MUST preserve the leaf's signature key: a re-issued credential chain
   for the same key is exactly what credential refresh means. Rotating a device's signature key
   is a `device-remove` + `device-add` pair with its own evidence, not an Update — which
   removes the contradiction between "Updates are valid from any leaf" and "added or updated
   leaves must be covered by evidence".

   The same rule, and the same argument, apply to the leaf's **credential subject**, and for
   update-path commits as well as Update proposals: an updated leaf — including the committer's
   own leaf as rewritten by a commit's UpdatePath — MUST carry a credential whose `subjectId`
   equals the pre-commit leaf's. Without that rule the gap is exploitable: rule 3 deliberately
   excludes signature verification from validity, so a member could install a
   structurally-valid self-issued chain naming **any** participant on its own unchanged leaf
   via an otherwise-empty PCS commit — no membership change, empty binding, valid under rule 5
   — and every member would uniformly render that device as the named participant's. That
   forges exactly the device-set surface §"Custody" makes a MUST. Subject continuity is a pure
   function of the commit bytes and the pre-commit tree, so it is a validity rule on the same
   footing as the rest of this list: a leaf whose participant changes is a leaf entering the
   group for that participant, and that is a `device-remove` + `device-add` with evidence.

5. Update-path/PCS commits that touch no membership and no leaf set are valid from any leaf
   with an empty binding. Clients SHOULD commit an Update on a schedule; MLS's forward secrecy
   and post-compromise security are per-epoch, so the schedule is the granularity.

Note what is _not_ in the list: expiry and revocation status. Those are wall-clock- and
registry-dependent, so making them validity conditions would let two honest members reach
different verdicts on the same commit and split the group irreparably (013's T13 — a discovery
host can withhold a revocation — applies with full force). They survive as **client-surfaced
warnings, as grounds for a member to refuse to author or commit evidence, and as a check a node
MAY apply when a KeyPackage is published** — registry-dependent where it costs nothing, because
publication is not consensus. Never as commit validity. §"Eviction" makes that concrete.

**The founding commit.** The commit that creates the group and adds the initial members is
covered by **the Conversation record itself**, at epoch 0: its `participants` are the founding
`members` and its signature is the creator's authorization, so no separate `add` records are
minted for bytes that already exist and already say exactly this (000 #7). The founding leaves
are those of the KeyPackages claimed for each initial member, and rule 3 applies to them
unchanged. The binding on the founding commit is the empty list.

**Add authority ends when the creator leaves.** A creator-less conversation is closed to new
participants; removals, device changes, and messaging continue. Inventing succession would be a
new authority concept with no consumer; a group that wants a new member after the creator
leaves starts a new conversation, which is 012's pre-014 answer for every membership change. A
richer policy (admin sets, member-adds, quorum) is an additive future rule **declared in the
inception record** and read wherever rule 2 is evaluated — one place, now that only one layer
judges authority.

**Device changes are records, deliberately.** A leaf add or removal for your _own_ participant
changes no participant set, so MLS alone could carry it. That is precisely the custodial hole
(§"Custody"): required evidence gives every member an auditable, renderable, revocable trail,
and gives the affected participant the credential digest that 008 revocation needs. Rule 1
makes it enforceable rather than advisory — a leaf with no evidence cannot enter the group.

**Membership change is an E2EE-lane mechanism in v1.** On the machine lane, 012's rule stands
unchanged: membership is fixed at creation and a changed group is a new conversation. The
reason is the design rule at the top of this section — the machine lane has no arbiter, so a
membership mechanism there would need the record layer to order, which is the thing that does
not work. The machine lane gets membership change when federation defines ordering, or not at
all. A node MUST reject a `pn/conversation-update` naming a machine-lane conversation
(`lane_mismatch`).

### Reconciliation: what each layer's membership means

- **MLS group state is the truth**, and the only thing confidentiality depends on.
- **The node's membership view is a delivery filter, nothing more.** It cannot read commits, so
  it derives a view from the Conversation record's `participants` plus the evidence records it
  has accepted. **Accepted means authorized**: before admitting a record to its filter the node
  MUST evaluate rule 2 — trivial at the record layer, since it holds the Conversation record
  (so it knows the creator) and the record names its own actor, with the creator's presence in
  its own filter standing in for "member of the group the commit extends". Without that check
  the filter is writable by anyone: an `add` naming arbitrary participants would grow it, and
  the block-list exception below would then protect the inserted party's deliveries by
  construction.
- That view is **add-monotone**: a `remove` record does **not** shrink the node's filter.
  Removal's teeth are cryptographic (the removed leaves cannot decrypt after the commit), and a
  filter that shrank on a record would (a) silently suppress a member whose removal was never
  committed and (b) make the removal notice undeliverable to the person removed. Monotonicity
  also means the union gate above only ever does work for `add` — stated so no implementer
  derives a shrinking filter from the union wording.
- A departed member who keeps sending is handled by 012's block list, per inbox, like any other
  unwanted sender. For that remedy to exist, the block-list exception below is keyed on evidence
  rather than on the filter — a participant named by an accepted `remove` is blockable again,
  even though the filter still carries them.
- **A member's _displayed_ membership and device set follow the evidence they hold**, so a
  change is visible as soon as it is authorized.
- **A member's _cryptographic_ reality follows commits.** Evidence authorizes; only the commit
  changes who can read.
- **Clients MUST surface the gap.** Evidence that is not yet realized by a commit MUST be
  rendered as pending, naming what is still true cryptographically. Hiding the two-stage nature
  is how "X left" comes to mean "X is still reading this".
- **Any member may close the gap**, because a self-authorized removal is committable by anyone.
  There is no liveness dependency on one party for departures or device removals.

### Eviction: what revocation does, and what it cannot do

Stated plainly, because the tempting formulation is false: **in MLS there is no way to encrypt
to a group while excluding one leaf.** Application messages use the epoch's shared key schedule.
Therefore:

- **Revoking a leaf credential (008) has no cryptographic effect, and no effect on commit
  validity.** Until a Remove commit lands, a stolen device decrypts everything. Revocation's
  role is threefold, all outside consensus: it is grounds for a member to **refuse to author or
  commit** evidence adding that leaf, grounds for every client to **warn**, and a check a node
  **MAY** apply when a KeyPackage carrying that credential is published — which keeps the
  registry dependence at the one point where members never have to agree. What revocation
  deliberately does _not_ do is make a commit invalid; that would be the view-dependent validity
  rule §"Membership change" excludes.
- **The Remove commit is the only eviction, and it needs evidence.** Device loss is: the
  participant authors `device-remove` for the lost leaves (signed by root, custody, or a
  surviving session key — never by the lost device), revokes the credential (008), and any
  member commits the Remove. Because the evidence is self-authorizing under rule 2, eviction
  waits on nobody: not the creator, not a surviving device of the victim.
- **Interim behavior is pinned, and it is not "go silent".** On observing a leaf whose
  credential is expired, revoked, or unverifiable, a client MUST surface it prominently and
  SHOULD prompt the affected participant to author `device-remove`; it MAY continue sending.
  Requiring silence would hand any member a conversation-wide denial of service — revoke your
  own credential and every conforming member stops — and, since a discovery host can withhold a
  revocation (013's T13), would make two conformant clients disagree about whether the group is
  sendable. The honest property is: **eviction is fast because anyone can commit it, not
  instantaneous because MLS has no per-leaf exclusion.**
- When several members observe the same warrant, each MUST wait a randomized delay before
  committing and MUST abort on observing the epoch advance — MLS linearizes commits, so an
  unthrottled MUST would fan out *n*−1 doomed commits to every member.
- **Credential expiry gates publication and claim, not the epoch and not a commit.** RFC 9420
  carries `lifetime` only on KeyPackage-sourced LeafNodes, so the binding pinned in the profile
  table holds where a clock is safe to consult: when a KeyPackage is published and when it is
  claimed. It is deliberately not a commit check (rule 1's carve-out) — a commit rejected on an
  elapsed lifetime would split the group on clock skew — and it is not a join check either, since
  a joiner fails open on everything it cannot verify (§"The wire"). Between those points an
  expired credential simply persists in the group.
  Combined with the absent `aud` (justified above) this means a stolen leaf key is a group
  member until someone notices and a Remove commits. Leaf credentials SHOULD therefore be
  short-lived and refreshed by Update commits carrying re-issued chains for the same signature
  key (rule 4).

### KeyPackages live on the participant's node

Adding a member — at creation or later — requires a fresh MLS KeyPackage per device of the
added participant. KeyPackages are consumable pre-key material, private-plane data with a short
life; they belong on the participant's node, not in discovery's public, permanent records:

- **`PUT /participants/:id/keypackages`** — replaces/replenishes the caller's pool. Owner mode,
  or delegated with the ability **`msg/keypackage`**. Each KeyPackage embeds its leaf credential;
  the node MUST parse that credential chain far enough to check `subjectId == :id` and reject
  otherwise — a node does not serve key material binding someone else's identity under this
  participant's id. (The node parses the _credential chain_; it still validates no MLS internals.
  "Opaque" applies to the MLS structures, not to the kinnet grant chain inside them.)

  "Embeds" is where those two rules meet awkwardly: the credential is inside the KeyPackage's
  LeafNode, and reaching it there needs exactly the MLS parser this spec forbids the node to
  have. So the publication carries the credential **alongside** the package rather than only
  inside it, and the node checks the copy it was handed. The node therefore cannot confirm the
  two agree — but nothing rests on it doing so: a mismatch is caught by every member at add time
  under rule 3, which verifies the credential actually carried in the leaf. The check here is an
  anti-squatting guard on the publishing route, not an authorization, and it is stated as the
  shallow check it is.

- **`POST /participants/:id/keypackages/claim`** — returns **at most one KeyPackage per device**,
  where the device is keyed by the credential chain's leaf `audienceId` (the `KeyRef`), and
  **deletes what it returns**. The take MUST be atomic under concurrent claims. Any
  spec-004-authenticated participant may claim — cold contact requires it, and authentication
  makes draining attributable. An exhausted pool yields `keypackages_exhausted`.
- **The node MUST reserve at least one package per device for claims authenticated as the pool
  owner.** Without this, a stranger draining the pool denies the owner their _own_ second
  device — the multi-device guarantee defeated by any participant at will. Self-add must not
  depend on strangers' restraint.
- **Serve-once is not trustable from the node**, which this design declares untrusted. The
  enforcing rule is client-side and normative: **a joiner MUST delete a KeyPackage's private
  init key on processing the first Welcome that uses it**, and MUST reject a second Welcome for
  the same KeyPackage. A malicious node re-serving a package then achieves nothing beyond a
  failed add.
- Beyond the reservation, claim rate limiting is node policy (010's anti-abuse posture). A drain
  remains a cheap availability attack on _cold contact_ specifically; the open questions record
  the last-resort-package alternative.
- Pools are not pruned by revocation, so an adder may claim a package for a retired device. The
  chain check at add time (rule 3, plus 009 revocation checking at join) is the backstop;
  clients SHOULD replenish and prune on connect.

### The wire: MLS messages ride the inbox

No new delivery surface. MLS messages travel as envelopes (010/011, both modes, unchanged),
under two new reserved types (012's `pn/` rule, abilities by the generative rule):

- **`type: "pn/mls"`** — `payload` is `{ "mlsMessage": base64url(MLSMessage) }`: a
  PrivateMessage carrying a commit, proposal, or application message. The envelope MUST carry
  `conversationId`; the node applies 012's association gates against its delivery-filter view.
  Requires ability `msg/mls`.
- **`type: "pn/welcome"`** — `payload` is `{ "welcome": base64url(Welcome) }`, delivered to a
  newly added participant, and MUST carry the `conversationId`. Requires ability `msg/welcome`.
  Each of the joiner's devices reads the inbox and consumes the Welcome matching its KeyPackage;
  Welcomes for its other devices are ignored, not errors.

**Onboarding order is normative**: the conversation record, then the `add` evidence, then the
Welcome. The joiner is inside the node's add-monotone filter by the time the Welcome arrives, so
`pn/welcome` needs no gate exemption of its own; a Welcome to a non-member is rejected
`not_a_member` and the sender retries in order, exactly as 010's retry-safety intends. The
adder MUST also deliver the evidence records covering **every leaf currently in the group**, so
the joiner can evaluate as much of the tree as it can. A joiner missing evidence for an existing
leaf MUST surface it as unverified rather than fail the join: fail-closed here would make honest
joins hostage to one undelivered record, and the joiner gains nothing by refusing — it is the
group's existing state either way.

**A joiner MUST verify the conversation `(record, chain)` unit itself, per §"What verifies a
unit", before processing any Welcome for that conversation.** Holding the record is not holding
a verified record: the `group_id` a joiner derives from a record in its own hands matches that
record by construction, so the
digest→`group_id` binding authenticates nothing on its own — a fabricated record and a group
created under its digest pass every such check together. The wait rule applies intact: a unit
whose resolution is stalled MAY be retried — key logs are monotone, so an honest stall clears —
but the joiner MUST NOT join while the unit is unresolved, and MUST NOT join on a unit that
fails verification. Sourcing the record from the node (an inbox listing) does not substitute:
the node verified the unit at write time, but this design declares the node untrusted, and the
record's authenticity is exactly what this lane refuses to rest on an honest operator. Contrast
the fail-open rule for missing leaf _evidence_ above, which is not in tension: evidence
describes the group's existing state, which the joiner gets either way; the conversation record
is the identity of the thing being joined.

**The first step needs one gate exemption, and only on this lane**, because the surrounding rules
are otherwise circular. 012 gates a `pn/conversation` delivery on `envelope.from` and
`envelope.to` both being
members, and a joiner is by construction not in `participants` — while the `add` evidence that
would make them one cannot reach them either, because 012 rejects an envelope naming a
conversation the recipient's inbox does not hold (`unknown_conversation`). Those are two
different checks — the union-membership gate above answers the second's _membership_ half but
not its _existence_ half — so implemented literally, record-first and evidence-first **both
deadlock and onboarding is impossible.**

So, on the E2EE lane only: **a member MAY deliver the conversation record to a non-member.** The
record lands `pending` under 012's consent rules exactly as a cold-contact conversation does,
and it confers nothing — the recipient can associate no message and read no group traffic until
an authorized `add` admits them to the node's filter. This is not new sender capability: any
participant could already place a thread in a stranger's inbox by creating a fresh conversation
naming them, which is the case 012's consent rules were written for. The machine lane is
unchanged, and keeps 012's both-members rule verbatim.

The alternative fix — exempting the `add` evidence from the existence check so evidence may
arrive first — was considered and rejected: it leaves an inbox holding evidence about a
conversation it does not have, and it contradicts the onboarding order this section already
declares normative.

**What a joiner can and cannot check, stated because it bounds a security claim.** A Welcome
carries `GroupInfo` — group context, confirmed transcript hash, ratchet tree, confirmation tag —
and **not** the commits that built the group, so the joiner never sees the `authenticated_data`
of the commit that added them or of any commit before it. Pre-join membership authorization is
therefore **unverifiable to a joiner by construction**: they verify the _authenticity_ of every
leaf's credential (rule 3's checks, against each participant's key log) and the _authorization_
of membership only from their join epoch forward. For pre-join leaves, the evidence the adder
relays plus the unverified-leaf warning is the whole signal — and the adder is exactly the party
a ghost-device attacker controls. §"Custody"'s "an uncovered leaf cannot enter the group" is a
guarantee to members present at the commit, not to joiners about the past.

Inside the ciphertext, the application content carries its own type — the machine lane's
sender-defined envelope `type` moves inside the encryption, along with everything else the
operator must not read. The envelope-level sender (`from`) authenticates _transport_; the MLS
leaf signature inside authenticates _authorship to the group_. A member MUST render authorship
from the MLS layer, and SHOULD surface a mismatch between the leaf's credential subject and the
envelope `from` (any member's device may re-deliver, so a mismatch is legitimate; unexplained
mismatch patterns are worth surfacing).

**Commits are re-deliverable and idempotent-by-epoch.** Any member may re-deliver a
`pn/mls` envelope; a client MUST ignore a commit for an epoch it has already passed and MUST
NOT treat it as an error. MLS processing is not itself idempotent, so the epoch check — not
envelope dedup — is what makes re-delivery safe. This is the recovery path for a member who
missed a commit.

**Blocking cannot silently destroy group state, and must not become an attention channel.**
012's block list accepts a delivery with a uniform 2xx and indexes it nowhere. Applied to a
commit, that would permanently desynchronize the blocker's epoch with no in-profile recovery
(external joins and commits are banned). So the node MUST NOT suppress a `pn/mls`,
`pn/welcome`, or `pn/conversation-update` envelope from a participant who is a member of
the named conversation by its delivery-filter view **and whose highest-`epoch` record is not a
`remove` naming them** (an `add` wins an epoch tie, since a participant re-added at the same
epoch they were removed is present) — **and** it MUST NOT emit a 013 event for a blocked sender's envelope, and MUST return
the uniform 2xx to a blocked sender regardless of the validation outcome. The exception is keyed
on evidence rather than on the add-monotone filter precisely so a departed member does not
inherit a permanent, unsuppressable channel into every other member's inbox: the exception
exists to protect the group mechanics of current members, and someone who has authorized their
own departure has no group mechanics left to protect. Keying on the **highest-epoch** record
rather than on "any accepted `remove`" is what keeps the condition from being a permanent mark:
a participant who left and was later re-added is a current member again, and a monotone flag
would leave anyone who has ever left permanently suppressible by any member who blocks them —
their commits dropped, their epoch silently desynchronized, which is the failure this exception
exists to prevent. Reading the highest epoch off the records is not the record layer ordering
anything: the epochs were assigned by MLS. The first rule keeps group mechanics flowing; the second keeps 013's T4
closed (a contentless poke is an unsolicited attention channel, and a blocked party must not
ring the recipient's devices); the third keeps the response from becoming a probe of the
recipient's state. Recovery for the recipient is a read, which is exactly what 013 says events
are not needed for.

One amendment to 012's read rules: 012 excludes reserved types from the **default** message read
so chat clients don't filter protocol payloads — but on this lane the reserved types _are_ the
conversation. The rule becomes: the unfiltered default read keeps excluding reserved types; the
**conversation-filtered read (`?conversation=`) returns `pn/mls`, `pn/welcome`, and
`pn/conversation-update` envelopes** for that conversation. `highestSeq` and the read cursor
work unchanged; commits and evidence consume a seq like any message, so unread counts
over-report by the (low) group-mechanics rate — disclosed, not hidden.

### What the node can and cannot see — the claims, stated exactly

Protected, against both node operators and any network observer, for an `e2ee` conversation:

- **Content.** Application payloads and the inner sender-defined types — everything inside MLS
  PrivateMessages, padded to 256-byte multiples. Forward secrecy and post-compromise security
  are MLS's, at MLS's per-epoch granularity.
- **Which _device_ authored a message, at the MLS layer.** The leaf signature is inside the
  ciphertext. This is a narrower claim than it looks — see the next list.

Not protected — visible to the operator exactly as on the machine lane, listed because hiding
the list would be the lie this protocol doesn't tell:

- **The conversation record and every evidence record**: who talks with whom, membership and its
  changes, **each member's device count and every device change**, `title` (an E2EE conversation
  wanting a private title omits the field and names itself inside the ciphertext), creator,
  timing.
- **A cross-conversation device graph, if leaf keys are reused.** Evidence records name leaf
  `KeyRef`s in cleartext, are delivered to every member, stored by every node, and designed to
  travel. The same leaf key in two conversations links them, and links a participant's device
  across nodes under federation — the durable, multi-party form of the linkage 011's Boundaries
  already flagged. The per-conversation-leaf-key SHOULD above is the mitigation; a client that
  ignores it publishes the graph.
- **The delivering device, in delegated mode.** 011 stores the presented chain with the envelope,
  and its leaf is the sending device's session key. Custodial participants — precisely this
  lane's target population — cannot use owner mode at all (custody's closed signing list has no
  envelope-signing operation; 012 makes this argument). So for custodial members the node learns
  which device delivered each message even though the MLS layer hides authorship. Device-level
  unlinkability is **not** claimed on this lane.
- **The authorizing chain of every delegated-signed record, to every member.** Since the
  `(record, chain)` unit is the payload, a delegated-signed conversation or evidence
  record carries its chain to **every member it reaches** — every operator on every
  hop, and joiners receiving relayed history — not only to the operator of the authoring
  delivery. What that discloses is 011's chain linkage: the actor's evidence-signing session-key
  `KeyRef`, its ability set, and its issuance/expiry cadence. Marginal beyond what a bare-record
  payload would disclose — members already receive transport chains on delegated deliveries, and
  the authoring hop's operator already stores the record's chain — with one genuinely new item: a
  joiner learns the historical device-delivery metadata of records that predate them. It is the
  price of records that re-verify wherever they travel, and it is paid in the same currency as
  the bullet above.
- **MLS framing.** `group_id`, `epoch`, and `content_type` are outside MLS's encryption, so the
  operator reads the group binding, the current epoch, and **whether each message is handshake or
  application** — exact group-churn and key-refresh cadence. A commit's `authenticated_data`
  additionally names the evidence it realizes, which the operator already holds.
- **Traffic**: envelope `from`/`to`, sizes (padded), cadence, seq. 013's contentless events add
  nothing beyond this (that was 013's design point).
- **The leaf credential chains**, which are handed to counterparties and served to any
  authenticated claimer: device `KeyRef`s, ability sets, issuance and expiry cadence. A
  deliberate inversion of 011's "capabilities are presented, not published" for this one
  namespace, bounded by the `e2ee`-only ability rule — the chain grants nothing exercisable.
- **KeyPackage claims**, which announce to the node who is about to be added to a conversation
  before any record exists.
- **Revocation of a leaf credential**, which publishes a digest to a public registry (008) and is
  thus publicly correlatable as "this participant retired a device at time T".

Deliberately out of scope for v1, recorded as non-goals: sealed sender, metadata-hiding routing,
deniability, and transcript-consistency _proofs_ beyond MLS's group agreement — which is
substantial: members in the same epoch agree on group state and membership, closing 012's
cross-member consistency question for this lane. The machine lane keeps 012's honest-sender
limit.

### Custody: what it cannot do, what it can, and what that costs

For a custodial participant (011), custody issues the leaf credential chain — a signing act over
**public** keys, inside its existing closed signing surface — and never holds MLS private state.

**Custody cannot decrypt**, and neither can a custody compromise, for any group it is not a
member of. There is no escrowed group state and this spec forbids adding one.

**Custody can mint a device.** Stated without softening, because the closed signing list —
custody signs only key events, root-issued grants, revocations, and the discovery writes that
publish them, never arbitrary payloads — is the enabling condition, not a protection: custody
holds the root key and
may issue root grants. It can generate its own MLS leaf keypair, self-issue (as the participant)
an `e2ee/leaf` credential naming it, sign a `device-add` for it, publish a KeyPackage under a
`msg/keypackage` grant it also mints, and be added as what looks like an ordinary device. The
same shape generalizes past custody: **any member can add a leaf of their own participant and
hand its private key to a third party.** No protocol can prevent this — whoever controls the
root controls what speaks for the participant. What this spec does is make it **visible and
revocable** rather than silent:

- every leaf is covered by signed evidence, delivered to every member and re-verifiable from
  bytes, so the trail exists and cannot be skipped — rule 1 makes an uncovered leaf
  uncommittable **for every member present when it is committed**. A participant who joins later
  cannot re-check that history (§"The wire", onboarding): they see authentic credentials and an
  unverified-leaf warning, not proof of authorization. The trail is strongest exactly where it
  matters most — the affected participant's own devices, since they are present for their own
  group's commits;
- **clients MUST render each member's device set and every change to it** — the affected
  member's own set most prominently. A ghost device is an unexplained entry in a list the user
  can see, and the evidence record hands them the credential digest 008 revocation needs;
- revocation plus self-authorized `device-remove` (§"Eviction") means the user, or any member,
  can evict it.

Two residual weaknesses, disclosed:

- **Rotation and custody exit do not retroactively kill minted credentials.** Grants verify
  against any replay-valid key state (012), so a previously-minted credential stays valid until
  `expiresAt` even after a custody-exit ceremony — which is a pre-rotation ceremony leaving a
  stated window of residual custody, not an instant cut-off. Short leaf lifetimes are the
  mitigation; the exit ceremony SHOULD be followed by `device-remove` for every leaf the
  participant does not recognize.
- **Visibility depends on a surface.** The protocol makes device sets renderable; whether a given
  client renders them well is above the protocol, and this is the one place where a client's UI
  is load-bearing for a security property. It is stated as a MUST above so a client that skips it
  is non-conformant, not merely unfriendly.

**The recovery trade-off**, stated once and binding on any surface built on this lane:

- **History lives only on devices.** A participant who loses every device loses their E2EE
  history. Custody-based recovery restores the _identity_ (root key, 003 log); it cannot restore
  conversation history, because anything custody could restore, custody could read.
- **A new device sees forward only.** MLS admits a leaf into the current epoch; it does not
  replay the past. History reaching a new device is a device-to-device transfer between a
  participant's own devices, or a member re-sharing content — both above the protocol, never via
  custody or the node.
- **The E2EE lane trades recoverability for confidentiality.** The machine lane makes the
  opposite trade. That is why there are two lanes and a marker, rather than one lane and an
  apology.

### Design limitation: leaf-credential attribution is advisory

This is a limitation of this protocol version rather than a defect to be patched: it follows
from rule 3's fail-open, a choice this spec makes deliberately and argues for above. What the
rules below add is the disclosure, and the MUSTs that go with it.

**Commit validity is independent of credential verification.** Rule 3 excludes signature
verification against a resolved issuer key state from commit validity in its entirety, and the
exclusion is load-bearing: a member that refused a commit the rest of the group applied would
lose the group rather than protect it. Everything below follows from that.

**Leaf-credential attribution is ADVISORY.** The participant a leaf's `PNCredential` names —
the value an implementation surfaces as the sending participant of an MLS-authenticated message,
and the participant a device is rendered under — is a **claim carried by the credential**, not an
authenticated fact, until that credential chain has been verified against the subject's key log
(003) by the party relying on it. Structural validity is not verification: the pure checks of
rule 3 establish that the chain is well formed, self-consistent, `e2ee`-only, and bound to this
leaf's signature key, and they say nothing whatever about whether the named subject ever issued
it.

**A member who can authorize an `add` can install a credential naming any participant.** The
creator (rule 2) can claim a KeyPackage whose credential names a victim as `subjectId` and
`issuerId`, carrying signatures that are shape-valid and verify under nothing, sign the covering
`add` evidence itself, and commit. The node checks a published KeyPackage's credential subject
only (Open questions, "KeyPackage validation depth"), and rule 3 will not refuse the commit. Every
member then holds a leaf whose credential says "victim", and MLS authenticates each message that
leaf sends — as that leaf, which is exactly the claim MLS makes and no more. Rule 4's subject
continuity closes the variant where an _existing_ leaf renames itself; it does not close this one,
because a new leaf entering the group with evidence is the authorized path.

Normatively, therefore:

- An application **MUST NOT** treat unverified leaf-credential attribution as authentication of
  the named participant: not to authorize anything, not to attribute authorship in a security
  decision, and not to render an identity in a form a user would read as confirmed.
- An implementation that surfaces attribution **MUST** surface its verification state alongside
  it — the three-valued one §"Custody"'s device-set MUST already implies (verified, not verified,
  no answer yet) — and **MUST** default to the unverified reading when it has no answer.
- A party that needs authenticated attribution **MUST** verify the leaf's chain itself against the
  subject's key log, per 009 rule 1 resolved through 003, and **MUST** treat the attribution as
  unverified until that succeeds. It **SHOULD** re-run verification when the log advances: key
  logs are monotone, so an honest stalled answer converges rather than being final.
- Verification failure remains **not** grounds to reject a commit (rule 3). It is grounds to warn,
  to refuse to author or commit further evidence, and to author `device-remove` (§"Eviction").
  **Attribution fails closed; commit application does not** — that split is the whole rule.

**TRUSTED-DISCOVERY GAP.** Verification is only ever as strong as the discovery view that answers
the key-log lookup. Key-log resolution runs against a discovery host the protocol declares
untrusted, and pure replay cannot establish freshness or completeness: a host can withhold a
rotation (013's T13), serve a valid prefix that reads as current state, serve one of two forked
histories, or
answer "not revoked" for a revocation it is hiding — 003 and 008 carry these as open questions,
with witnessing and signed checkpoints as the unbuilt remedy. Log **substitution** is closed by
binding: a resolver **MUST** reject a key log whose self-derived participant id is not the id it
asked for. Origin substitution is not: a compromised, impersonated, or simply wrong discovery
origin can vouch for keys the attacker holds, and a verifier that reached the wrong origin cannot
tell from the bytes.

So a deployment **MUST** pin and authenticate the discovery origin it resolves key logs through —
a pinned origin over authenticated transport, and, where the deployment can, a pinned key or
issuance for that origin — and **MUST NOT** present credential verification as stronger than the
trust it places in that origin. A verified credential means "the trusted discovery view says this
participant's key log authorizes this device", not "this participant authorized this device".
Until witnessing or signed checkpoints land (003), that residue is the protocol's rather than any
implementation's, and it **MUST** be disclosed wherever this lane's guarantees are published.

### Consequential amendments

These amendments to other specs take effect when this spec is implemented:

- **010** — the E2EE non-goal is lifted by reference: payload confidentiality lives here; 010's
  plaintext stance becomes the machine lane's definition.
- **011** — the `caveats.aud` cross-field rule gains the `e2ee`-namespace exemption (key audience
  ⇒ `expiresAt` always; `caveats.aud` unless every ability satisfies the pinned predicate);
  verifiers reject a presented chain containing any `e2ee` ability; the E2EE non-goal points here.
- **012** — `lane` and `groupNonce` join the Conversation schema (absence of `lane` = machine
  lane, so every existing record stays valid and keeps its digest); membership-fixed-at-creation
  is lifted **for the E2EE lane only** — 012's "until then: a changed group is a new
  conversation" is amended to say that sentence stands **permanently** on the machine lane, not
  provisionally, so machine-lane chat is the surface that can now never change membership; the
  reserved-type list gains `pn/conversation-update`, `pn/mls`, `pn/welcome`; the
  filtered-read amendment; the
  lane/type node gate and its place in the check order; the union-membership gate for evidence
  records; the block-list amendments; the cross-member-consistency open question gains the
  E2EE-lane answer.
- **013** — the `message`-event rule is amended to key on the **conversation-filtered read view**
  rather than on the reserved-type prefix, so E2EE traffic produces events (without the
  amendment, 013 would silently degrade this lane to polling); and no event is emitted for an
  envelope from a sender the inbox has blocked, which keeps T4 closed under this spec's
  block-list exception. 013's
  normative namespace reservation gains `msg/keypackage`. And, as 013 did for `msg/subscribe`, it
  is stated plainly that the `msg` umbrella grows: every already-issued `msg` grant gains
  `msg/mls`, `msg/welcome`, `msg/keypackage`, and `msg/conversation-update` — including the
  authority to author membership evidence for conversations its subject created. Grantors relying
  on `msg` should narrow. Called out specifically, because it is the sharpest of these:
  `msg/conversation-update` would otherwise carry **unilateral self-expulsion authority** — rule
  2 makes `members == [actor]` self-authorizing and any member will commit it, so a stolen
  session key could remove its subject from every conversation they are in, and since add
  authority is creator-only the victim could not restore themselves. This is 012's `msg/cursor`
  argument with a destructive tail. A delegated-signed self-departure therefore requires
  `conversation/self-remove`, pinned outside the `msg` namespace, so the umbrella confers no
  self-expulsion authority and 013's cover math is untouched; 013 §2.3 carries the matching
  amendment.
- **`@kinnet/protocol`** — the Conversation schema gains `lane` and `groupNonce` with the
  cross-field rule, and a ConversationUpdate record schema is added (strict, closed) — the
  schema enforces well-formedness only; the
  lane-conditional rules (E2EE-lane-only, `leaves` semantics) are delivery/validation rules
  evaluated where the conversation record is held, not schema rules, since the schema cannot see
  the conversation. Digest-pinned fixtures: evidence accept/reject vectors
  (`packages/protocol/test/fixtures/conversation-update-vectors.json`), and commit-binding
  vectors (`packages/protocol/test/fixtures/commit-validity-vectors.json`) covering each
  authorization case in rule 2, set-equality, complete-removal, epoch
  mismatch (the replay cases: re-add after leave, re-remove after rejoin, device churn),
  cross-conversation replay, `device-add` by a non-member, a `device-remove` taking its actor's
  last leaf, uncovered leaves, non-minimal and over-full bindings, a non-empty binding on a
  membership-free commit, Update key-preservation and subject continuity, the PCS commit, the
  founding commit, and the empty binding. Each commit-binding vector states the verdict — valid,
  invalid with its reason, or wait with what it waits for — so the wait/invalid split is pinned
  in bytes rather than left to each implementation's reading.

  Plus the `(record, chain)` unit: payload schemas for the conversation and
  conversation-update units (both strict, `chain` optional and non-empty when present, the
  record strict underneath so a smuggled chain is malformed), an exported
  `conversation/self-remove` ability constant, and unit vectors — accept with and without a
  chain, reject a bare record, an empty chain, a malformed chain link, an unknown unit-level
  key, and a chain inside the record — with a digest-identity fixture pinning that
  `digest(record)` is unchanged by the presence of `chain`.

- **`@kinnet/crypto`** — the 005 MLS runtime behind an interface; the credential
  encode/verify profile (`PNCredential` TLS bytes ↔ chain), `group_id` derivation, and the
  `PNCommitBinding` encoding, with vectors.
- **Node implementations** are where the record-layer rules are enforced: the KeyPackage routes
  (atomic take, owner reservation, credential-subject check), the `pn/mls*` gates, lane/type
  consistency and its place in the check order, the add-monotone delivery-filter view fed by
  evidence, the union-membership gate, the block-list and event amendments, and the
  conversation-filtered read.
- **Client implementations** are where MLS itself runs: create/join/send/receive, device
  add/remove, leave, eviction, device-set rendering, evidence assembly, and commit binding. Every
  confidentiality claim in §"claims" rests here, since the node never holds group state.

## Boundaries

- **The protocol pins the profile, not the library.** Any MLS implementation is interchangeable
  behind RFC 9420 plus the profile above; conformance is to those, never to a particular library.
- **The node is not a member.** Every gate it enforces is record-level (its delivery-filter view,
  lane, abilities, signatures, credential subject). It never validates MLS internals; a node that
  cannot parse an `MLSMessage` is conformant, and a node that _rejects_ one it cannot parse is
  not — the MLS payload is opaque by design, in deliberate contrast to `pn/` _types_, which
  fail closed when unknown.
- **Lane is not a privacy policy.** The marker says which mechanism carries the payload; it does
  not promise metadata privacy (see the claims) and does not restrict who may be a member — an
  agent can hold leaves. Whether that belongs in a given application's "private chat" is policy.
- **Federation must not be precluded, and is not solved.** Everything here is per-node state plus
  records designed to travel: evidence records are self-contained and order-free, so a receiving
  node needs no history to validate one, and `(record, chain)` units re-verify per 011.
  Cross-node relay of MLS traffic and cross-node KeyPackage claiming are the federation spec's
  problems, explicitly inherited by it — as is machine-lane membership change, which waits on
  federation's ordering work.
- **Custody's signing list stays closed**: issuing an `e2ee/leaf` credential is a grant
  issuance — already on custody's closed list of signable operations — not a new operation.
  See §"Custody" for why that is a disclosure, not a reassurance.

## Non-goals

- **Retrofitting E2EE onto the machine lane** — it stays authenticated plaintext by design (010).
- **Machine-lane membership change** — 012's fixed membership stands there; see §"Membership
  change".
- **Sealed sender / metadata-hiding routing** — envelope `from`/`to` stay visible.
- **Device-level unlinkability** — delegated mode discloses the delivering device (claims).
- **Deniability** — MLS leaves sign; its absence is not hidden.
- **Escrowed history, custody-readable backup, or any recovery path that hands custody
  plaintext** — forbidden above, not merely unbuilt.
- **Cross-device history sync protocol** — the seam is named; the protocol is not designed here.
- **Preventing a root-key holder from minting a device** — impossible; made visible instead.
- **Push delivery** — 013's contentless seam is unchanged and already privacy-safe.

## Open questions

- **Last-resort KeyPackages.** Serve-once pools exhaust; MLS contemplates a reusable last-resort
  package with degraded forward secrecy for the add. v1 says exhausted-means-wait (with the owner
  reservation protecting self-add); running code will say whether the degradation is worth buying
  cold-add availability against a determined drainer.
- **Membership-policy vocabulary.** Rule 2 is creator-managed adds plus self-authorized removals,
  with the extension point declared in the inception record. Design the richer vocabulary (admin
  sets, member-adds, quorum removes) when a consumer needs it, in 006's configured-not-hardcoded
  style.
- **Epoch-gap recovery.** A member who missed a commit can be re-delivered one by any member, but
  no member knows which epoch they are stuck at and there is no request surface. An "I am at
  epoch N" hint is probably an SDK concern; if it turns out to need a wire shape, it belongs
  here.
- **History re-share and device-to-device transfer.** Named above as above-protocol; whether the
  transfer format deserves a spec (it crosses implementations) or stays an SDK concern.
- **Credential lifetime policy.** Short lifetimes are the mitigation for the
  expiry-gates-joins-only weakness, but every reissue is a commit and, for custodial
  participants, a custody round-trip. What the right cadence is — and whether self-custodied
  renewal without touching the root is possible (011's open question, sharpened here) — needs
  running code.
- **Per-conversation leaf keys as a MUST.** The SHOULD trades one credential issuance per
  conversation against a cross-conversation device graph. If custody round-trips prove cheap, it
  should harden.
- **Authenticated attribution without splitting the group.** §"Design limitation" pins the
  disclosure and the MUSTs, not a fix: attribution stays advisory because commit validity must
  stay resolution-free. What a fix would need is a way for a relying party to reach a fail-closed
  attribution verdict that is _also_ uniform across members — witnessed key logs (003), or an
  attribution surface that is explicitly not the commit surface. Neither exists yet, and neither
  should be invented before a consumer needs it.
- **KeyPackage validation depth.** The node checks the credential's subject only. Full chain
  verification would cost discovery resolution on the write path and reject broken chains
  earlier; members reject them at add time regardless. Currently shallow.
- **IANA registration** of credential type `0xF001` and whether a kinnet MLS extension registry
  is worth opening at the wire-freeze.

## Design notes

**The ordering invariant is the thing to preserve.** Everything in §"Membership change" follows
from one rule: the record layer never orders anything, and MLS is the only orderer. Designs that
put an ordered, replayed record chain at the record layer and made MLS follow it were tried and
rejected; each fix inside that frame produced a new way for two honest members to disagree,
because any member can author records for free while MLS commits are irreversible and external
joins are out of profile. A revision of this spec that reintroduces record-layer ordering
reintroduces that failure mode.

**Fail-open and fail-closed are assigned by whether the answer must be uniform.** That question,
rather than a general preference for strictness, is what decides each of the
resolution-dependent checks above. A check that feeds a group-uniform decision — commit
validity — either excludes the dependency (credentials: rule 3 fails open) or waits on it
uniformly (evidence signatures and unheld evidence records: wait, never reject). A check that
feeds a purely local decision — what a client renders, whether a
member authors or commits further evidence, whether a node accepts a publication — may consult
clocks, revocation registries, and its own discovery view, because two members disagreeing there
costs nobody the group. Wall-clock expiry, revocation, and caveat evaluation sit on the local
side throughout for exactly this reason.

**`@kinnet/protocol` and `@kinnet/crypto` are the reference implementation**; the conformance
vectors under `packages/protocol/test/fixtures/` (`conversation-unit-vectors.json`,
`conversation-update-vectors.json`, `signed-conversation-e2ee.json`,
`commit-validity-vectors.json`) are what a second implementation checks against. The last of
those is the one that pins agreement rather than well-formedness: commit validity is where two
implementations reaching different verdicts split a group, so every vector carries the commit's
`authenticated_data`, the leaves it adds and removes, the pre-commit tree, the cited evidence
records with their digests and per-record verification state, and the expected verdict.

## History

- 2026-08-01 — Reached Proposed. Earlier designs that ordered membership at the record layer
  were rejected; MLS orders, and records carry evidence only.
- 2026-08-01 — Added the E2EE-lane exemption letting a member deliver a conversation record to a
  non-member, without which onboarding deadlocks.
- 2026-08-01 — Required a committer to refuse a `remove` record that does not name every leaf
  its members currently hold.
- 2026-08-01 — Extended Update key-preservation to the leaf's credential subject, for
  update-path commits as well as Update proposals.
- 2026-08-01 — Required a KeyPackage publication to carry its leaf credential alongside the
  package.
- 2026-08-02 — Made `{ record, chain? }` the wire payload of `pn/conversation-update` and
  `pn/conversation`, with digest identity over `record` alone.
- 2026-08-02 — Pinned the unit verification profile: owner and delegated modes, expiry against
  `createdAt`, no member-side caveat or revocation evaluation.
- 2026-08-02 — Required `conversation/self-remove` for a delegated-signed self-departure.
- 2026-08-02 — Disclosed that a delegated-signed record's chain reaches every member it travels
  to, not only the operator of the authoring delivery.
- 2026-08-03 — Required a `device-remove` to leave its actor at least one leaf, closing the
  device path around the self-remove ability.
- 2026-08-03 — Pinned a delegated-signed record to exactly one signature.
- 2026-08-04 — Required a joiner to verify the conversation `(record, chain)` unit before
  processing any Welcome for that conversation.
- 2026-08-13 — Recorded leaf-credential attribution as advisory and the trusted-discovery gap,
  with the MUSTs that accompany them (external security review).
- 2026-08-16 — Closed the machine-lane membership-change open question: this spec's amendment to
  012 already makes fixed membership permanent there, so the question was settled where it was
  asked.
- 2026-08-16 — Added the commit-validity conformance vectors
  (`packages/protocol/test/fixtures/commit-validity-vectors.json`), pinning the valid/invalid/wait
  verdict of each commit-binding case.

## References

- RFC 9420 — Messaging Layer Security (MLS); the mandatory ciphersuite, credential, KeyPackage,
  `RequiredCapabilities`, LeafNode sources, framing and `authenticated_data`, Welcome and
  ratchet-tree extension
- Spec 003 (digest rule, key resolution), 005 (suite, the E2EE runtime decision), 008
  (revocation), 009/011 (grant chains, key principals, `aud`, (record, chain) units), 010
  (inbox), 012 (conversations — the container, the deferred membership question, the generative
  ability rule, the error-oracle open question), 013 (contentless events, T4, T13, namespace
  reservation)
