# 011 — Device-key grants (key principals & delegated requests)

**Status:** Accepted
**Blocks:** browser/device session keys and the delegate keys of applications acting for a
participant — clients that never hold the root key
**Amended by:** 014

## Context

A browser client that holds the root identity in local storage makes clearing site data
identity loss, and signs every request with the root key from the least trustworthy runtime
the identity will ever touch. The custody model wants the opposite split — a durable, rarely
touched root; a disposable per-device **session key** with narrow, expiring authority; loss a
non-event, theft one revocation.

The pieces nearly exist. Grants (009) delegate scoped, attenuating, expiring, revocable
authority; revocation (008) withdraws by digest; request auth (004, 010) verifies a signature
against a key resolved from the signer's log (003). But a grant's audience must be a
participant, and 004/010 accept only keys in the acting participant's own log. Forcing every
browser session to become a participant — a public key log in discovery, with a pre-rotation
commitment, for a key designed to be thrown away — is the wrong shape: a session key is
replaced, never rotated, and nothing about it belongs in public records.

The protocol also still carries a `DeviceKey` record (003's boundary) that binds a device key
to a participant with no scope, no expiry, and mandatory publication. No running code uses it.
Per 000, replace it with the general form rather than accreting alongside it.

## Decision

### Key principals

A Grant's **audience and issuer** widen from participants to **principals**; `subjectId`
remains a participant id, and because the root link is self-issued (`issuerId == subjectId`,
009), the root issuer is always a participant:

```
Principal = ParticipantId | KeyRef       // 002 `pk_`-prefixed id, or a bare 005 key;
                                         //   the shapes are disjoint by construction
Grant.issuerId   : Principal
Grant.audienceId : Principal
```

This is the UCAN model 009 already aligns to — principals are keys; a participant id is the
rotation-stable principal, a `KeyRef` the disposable one. Three rules keep bare keys
disposable:

- **Key principals may re-delegate, and their signatures are self-certifying.** The multi-hop
  chain is user → session key → backend service: a session key
  issues an attenuated sub-grant to the service acting on the user's behalf. 009's chain rule 3 is
  unchanged (each link's `issuerId` equals its parent's `audienceId`, now over principals);
  rule 1 gains a branch — a **participant** issuer's signature resolves through its log
  (003, at threshold), a **key** issuer's signature verifies against the key itself, exactly
  one signature. Attenuation is unchanged: abilities prefix-covered, caveats only narrow.
- **Keys sign grants and requests, nothing else.** A key principal cannot author a
  Revocation — `Revocation.issuerId` stays a participant id (008 unchanged). A key-issued
  link is revoked by any participant upstream in its chain (the subject at minimum), and
  revoking any ancestor link severs the whole subtree at use time. "Sign out everywhere" is
  revoking the root-issued links.
- **Key-audience grants MUST carry `expiresAt`.** A bare key has no log: it cannot rotate and
  commits to no next key, so an expiry bound is the only _planned_ end it can have. 009's
  "absent = until revoked" remains valid only for participant audiences. This is a validity
  rule, not policy (000 #3): independent verifiers must agree that such a grant is malformed,
  so the schema enforces it cross-field (`expiresAt` required iff `audienceId` is a `KeyRef`),
  with accept/reject fixtures. How _short_ the expiry should be stays policy. A key-_issued_
  link needs no rule of its own: at use time no link may be expired (009), so a subtree never
  outlives the key-audience link above it. Revocation (008, naming the grant's digest) is the
  _unplanned_ end — theft is one revocation.

### The `aud` caveat — the first standard caveat

009 left a standard caveat vocabulary open "until running code shows recurrence". Grant
visibility is that running code: capabilities are presented, not published, and an explicit
audience narrows both misuse and who may ever see the grant. This spec defines the first
entry:

- **`caveats.aud`** — a `ParticipantId` or non-empty array of them, naming the verifiers the
  link may be presented to. A verifier MUST reject a chain whose effective `aud` does not
  include the verifier's own participant id. Absent means unrestricted; a child's `aud` must
  be covered by its parent's effective `aud` — narrowing only, like every caveat (009).
- **A key-audience grant MUST carry an `aud` caveat.** Same validity-rule footing as the
  expiry requirement above, and the conservative default for a bearer credential:
  a delegate grant lost or stolen is exercisable only against the services it names, and no
  other service ever has cause to see it. Consequence, stated plainly: a surface that
  accepts delegated requests must itself be an identified participant, so callers have an
  id to bind `aud` to.
- Like every caveat, `aud` is evaluated at use time and is delivery-time-only for stored
  chains (see re-verification below).

_Amended by 014:_ the `aud` requirement gains one exemption, the `e2ee` namespace. `expiresAt`
is still required on **every** key-audience grant, without exception; `caveats.aud` is required
unless **every ability of that grant** satisfies the pinned predicate
`a === "e2ee" || a.startsWith("e2ee/")`, in which case it MAY be omitted. That shape is 014's
MLS **leaf credential** — a grant whose audience is a device's MLS signature key, proving the
leaf speaks for the subject. It is exempt because there is nothing to bind it to: `e2ee`
abilities are never request-valid (below), the counterparty set is unknowable at issuance, and a
stolen credential authorizes **zero requests anywhere** — the namespace is the bound the caveat
would have been. In practice the exemption is not optional: 014 also requires every link of a
credential chain to carry **empty `caveats`** (a caveat a group member cannot evaluate fails
closed, which inside an MLS group is a split), so an `e2ee` chain carrying `aud` is malformed
there. The exemption is evaluated per grant, as the schema must; 014's rule that a credential
chain's abilities lie entirely in `e2ee` at **every** link is what keeps the per-grant and
per-chain readings from diverging.

### Delegated requests (extends 004)

A spec-004 signed request may be signed by the holder of a delegated chain, presenting it:

- **`keyid`** is the leaf's audience principal — the session key itself (a `KeyRef`, in no
  log), or a participant id when the leaf was re-delegated to a participant (the multi-hop
  tail: the backend service exercising its sub-grant signs with its own current key). The
  verifier MUST classify `keyid` by validating it against exactly one of the two principal
  shapes and reject anything that matches neither; the `pk_` prefix makes the shapes
  disjoint.
- **`PN-Grants`** header: `"1:" + base64url( UTF8( JSON array of Grant records, leaf
first ) )`. The `1:` prefix names the encoding so a future profile (chain-in-body,
  chain-by-digest) is additive (000 #6). Whenever the header is present it MUST be a covered
  component of the request signature — the authorization decision hangs on it, so it is
  signed like everything else the decision hangs on; an uncovered chain is rejected.

The verifier accepts iff:

1. the HTTP signature (004) verifies against `keyid` — the key itself for a `KeyRef`, the
   participant's current key state (003) for a participant id — with `pn-grants` among
   the covered components;
2. the chain verifies per 009 — participant issuers resolved through their logs (003), key
   issuers against the key itself, the root self-issued by the subject;
3. the leaf's `audienceId` equals the `keyid` principal;
4. the chain's abilities cover the request per the receiving surface's ability vocabulary,
   and every caveat is understood and satisfied — including `aud` admitting this verifier;
   caveats fail closed (009);
5. at request time no link is expired and no link is revoked (008).

_Amended by 014:_ one chain shape is rejected outright, before any surface's vocabulary is
consulted: a verifier MUST reject a presented chain containing **any** ability satisfying
`a === "e2ee" || a.startsWith("e2ee/")` — in **any** link, whatever else that link carries. The
reading is deliberately whole-chain and deliberately blunt, so two verifiers cannot differ: a
chain that could serve as an MLS leaf credential is never also a request authorization. This is
what makes the `aud` exemption above safe. Credentials are handed to counterparties and served
to strangers through KeyPackages (014), so they must buy nothing on any request surface;
because the exemption predicate and this rejection predicate are the same function over the same
chain, no chain lands in a gap between them. 014 also requires that an MLS leaf signature key
never be a request-signing key (an 011 session key included), with one enforcement point each
way: a verifier MAY reject a credential whose leaf `audienceId` it has seen as a request
`keyid`, and a counterparty MAY reject a request `keyid` it has seen as a leaf audience.

The request then counts as **the subject acting**, bounded by the chain's abilities. Nothing
else changes: replay defense and the two-signatures split are 004's.

### The inbox surface (amends 010)

009 leaves ability vocabularies to the surfaces that enforce them; the inbox surface (010)
defines its own:

- **`msg/send`** — authorizes `POST /messages` where `envelope.from` equals the chain's
  subject.
- **`msg/read`** — authorizes `GET /inboxes/:id/messages` where `:id` equals the chain's
  subject. This settles 010's open question: reads beyond the owner are grant-based.
- **`inbox/enroll`** — authorizes `PUT /inboxes/:id` where `:id` equals the chain's
  subject; single-hop key-audience chains only, exact ability string required. Top-level
  deliberately: `msg` never covers it, and an `inbox` umbrella buys nothing here.

010's delivery rules, in their amended form — **both signatures come from the same key, in
one of exactly two modes**:

1. **Owner mode (010 unchanged):** the request signature's `keyid` is `envelope.from` and
   verifies against `from`'s current key state (003); the envelope's record signature
   verifies against that same key state.
2. **Delegated mode:** the request signature verifies per this spec with a chain whose
   subject is `envelope.from` and whose abilities cover `msg/send`; the envelope's record
   signature verifies against **the presented chain's leaf key** — the same session key that
   signed the request.

Delivery is deliberately narrower than the general mechanism: **single-hop only, one
delivery, one key, one chain.** Mixed modes (root-signed request with session-signed
envelope, or vice versa, or two different session keys) are rejected, as is a
participant-id `keyid` arriving with a `PN-Grants` header on this route — on general
surfaces that combination is the legitimate multi-hop tail, but for delivery the signals
must agree on one of the two modes or the request fails closed. Multi-hop delivery (a
service relaying on the sender's behalf) stays deferred with the delegated-relay open
question. In delegated mode the node MUST store the presented chain with the envelope —
they persist and travel together as one unit (next section). Enrollment
(`PUT /inboxes/:id`) is governed by the rule immediately below: creating an inbox is an
identity-level act, not a session-level one.

**Enrollment.** Owner mode is unchanged. Enrollment also accepts delegated requests in
delivery's key-audience shape, tightened one notch — **exactly one link**:
`PUT /inboxes/:id` accepts a delegated request iff the presented chain is a **single
root grant self-issued by `:id` to a `KeyRef`**, and that grant's abilities **contain
`inbox/enroll` — the exact string, not a covering prefix**. Each rule carries its
reason. Single-hop is what makes the authority bound real rather than presented: a
key-audience grant covering a non-`e2ee` ability must carry `expiresAt` and `caveats.aud`
(011 as amended by 014 — the `aud` exemption applies only to all-`e2ee` grants, which an
enrollment grant can never be), and with no upstream link there is nothing to re-mint a
fresh bounded leaf from — a multi-hop chain bounds only the request, not the capability,
because a participant-audience ancestor may lawfully carry neither expiry nor `aud`. The
documented multi-hop tail (user → session key → backend service) is therefore **not
accepted on this route**: a signup service enrolls with a grant the subject's root issues
directly to the service's key. And the exact-string rule makes the vocabulary discipline
enforceable at the wire instead of exhorted in prose: `inbox/enroll` is top-level,
outside `msg`, by the same segment-boundary rule as `conversation/self-remove` (014), so
no everyday grant covers it by accident — and because the route demands the exact string,
a bare `inbox` umbrella grant buys enrollment nothing either.

Creating an inbox **is** an identity-level act, and the delegated form changes what may
_express_ that act, not whose act it is. For a fully custodial participant the root key
never leaves custody, so the only identity-level consent such a participant can express is
a grant rooted at their key naming the act. Stated precisely, that is deliberateness of the
**client author**, not of the human: a custody ceremony can bind each assertion
cryptographically to the exact ability list — single-use challenge, user verification
required — while displaying none of it, so a hostile or compromised client can request the
ability during any expected touch. What the protocol guarantees is protection against
_accidental_ coverage; protection against a hostile client is the custody surface's own UI,
out of protocol scope.

What a stolen enrollment-capable grant buys, stated without euphemism: a **permanent**
inbox row for the grant's subject — enrollment has no inverse — at any node the grant's
`aud` admits, until it expires or is revoked. That node will thereafter accept, store,
and serve deliveries addressed to the subject there. The bound is schema-guaranteed
(`aud` and `expiresAt` are mandatory on this grant shape), and a subject who never minted
an enrollment-capable grant is untouchable — the grant must be self-issued at their root,
by any key state their log has held (003), so a compromised **retired** root key is
answered by revocation (008), not by rotation.
One separation is enforced already and is stated so nobody relies on it accidentally: a
chain carrying any `e2ee` ability is never request-valid (014), so enrollment authority
and a leaf credential can never share a grant — a custodial device needs them separately.

A node's enrollment **policy** is untouched (Boundaries): anti-abuse gating, allow-lists,
or refusing delegated enrollment outright remain the resource holder's call. What the
delegated form does change is the population the eventual anti-abuse gate must reason
about: enrollment-capable credentials include session grants living in browser storage, not
only root keys. Prerequisites, stated: delegated enrollment requires the node to run as
an identified participant (`aud` must name it; a node with no participant id fails
closed, correctly), and the client must know that id out of band — no protocol mechanism
supplies it, consistent with this spec's scope.

### Reads and re-verification of stored delegated envelopes

A delegated envelope is unverifiable without its chain — the envelope names `from` but is
signed by a key only the chain ties to `from`. So the **(envelope, chain) pair is the
re-verifiable unit**: reads (010) return the stored chain alongside each delegated envelope,
and any relay or export carries the pair, not the envelope alone.

014's **records** adopt the same unit, one layer in: the payload of a
`pn/conversation-update` and of a `pn/conversation` envelope is `{ record, chain? }`,
carrying the chain that authorizes the **record** — which is a
different chain from the transport one this section describes, and travels with the record rather
than with the delivery. That is what lets any member re-deliver a delegated-signed record in
either transport mode. 014 pins the verifier profile for those units, including two deliberate
deviations from the bytes-alone profile below (members skip revocation; expiry is checked against
the record's `createdAt` and never the wall clock, at the node as well); see 014, §"What verifies
a unit".

Delivery-time verification (the rules above) is the authoritative gate: the node checked the
chain unexpired and unrevoked _at delivery_. Re-verification from bytes alone proves less,
and the spec pins exactly what:

- **Bytes-alone re-verification** checks the envelope signature against the leaf key, the
  chain per 009 rules 1–5 with the leaf audience equal to the signing key, subject equal to
  `from`, abilities covering `msg/send`, **no link revoked** (008), and `envelope.createdAt`
  within every link's `[issuedAt, expiresAt]` window — a link without `expiresAt` (allowed
  for participant audiences, 009) leaves its window open above. It does **not** apply
  wall-clock expiry — an expired grant does not retroactively unauthenticate the messages
  sent under it. **Caveats are delivery-time-only**: they bound the request the delivering
  node gated, cannot be re-evaluated from bytes, and are not re-checked — 009's fail-closed
  rule applies at use time, not to storage.
- **The residual window is stated, not hidden:** `createdAt` is chosen by the signer, so a
  session key stolen even _after_ expiry can mint envelopes backdated into the grant's
  window that pass bytes-alone re-verification. Only the delivering node's gate (which uses
  real time) stops them. A lost device whose key may be hostile is therefore **revoked**
  (008), never merely left to expire.
- **Revocation is retroactive for bytes-alone verifiers, and that is the traded cost:**
  a re-verifier that sees a revocation of any link rejects the pair, including honest
  pre-theft messages — from bytes alone, a backdated forgery and an honest pre-revocation
  message are indistinguishable. Root keys don't pay this (rotation preserves old records,
  003); session keys do, and "theft is one revocation" buys its simplicity with the revoked
  session's stored history. A node-signed delivery attestation (a trustworthy `deliveredAt`
  anchor) would remove the asymmetry and is deferred with 008's sign-time-anchoring open
  question — whose stakes this spec raises, since grants become an everyday auth path.

### Replaces `DeviceKey`

The `DeviceKey` record is removed. A key-audience grant is the thinner form (000 #7): key
binding, scope, and expiry in one bearer record, presented at request time and published
nowhere — where `DeviceKey` bound a key with no scope, no expiry, and a mandatory public
listing in discovery. Losing a device lets its grant expire _only if the key is known
destroyed_; a key that may be in someone else's hands is revoked (see above). A public device
listing, should one ever be wanted, is derivable from records the owner chooses to publish —
derived, so not a primitive (000 #4).

Because session grants are published nowhere, their revocations name digests discovery has
never seen. The registry therefore accepts a revocation for an **unknown digest** from any
authenticated participant (004) and serves it by digest; revoker _authority_ is judged
verifier-side against the presented chain (008/009), as the trust resolver already does. If
discovery instead demanded the revoked record on write, session grants would be unrevocable.

### Consequential amendments

This spec changes the following earlier specs:

- **003 Boundaries** — the DeviceKey sentences become: device subkeys are key-audience
  grants (011); losing a device revokes its grant.
- **004** — "DeviceKeys" leaves the record list in Context; the undefined "optionally plus a
  key thumbprint" `keyid` clause is deleted (keyid is a participant id or, per 011, a
  `KeyRef` — nothing else); the pinned covered-component set admits `pn-grants` for
  delegated requests, so an implementation's HTTP-signature component grammar must admit
  that component.
- **008** — Context's device example points at grants; the "Replaces `DeviceKey.revokedAt`"
  section gains a note that 011 later removed the record entirely.
- **009** — the Grant shape's `issuerId`/`audienceId` become principals with the key-issuer
  branch in chain rule 1, and the caveat-vocabulary open question gains its first standard
  entry, `aud`, defined here.

In the reference schemas, the `DeviceKey` record is removed and the Grant schema's issuer and
audience widen with the cross-field rules (key audience ⇒ `expiresAt` and `caveats.aud` required),
with accept/reject fixtures both ways.

## Boundaries

- **Root custody is above the protocol.** Where the root key lives between grant issuances —
  export file, node custody, passkey-wrapped backup — is app/node policy. This spec fixes
  only what makes a delegated request verifiable.
- **Which surfaces accept delegation is the resource holder's policy** (009's enforcement
  boundary). This spec pins the mechanism and the inbox vocabulary; other surfaces adopt the
  mechanism with their own vocabularies when running code needs it — and inherit the
  covered-component requirement, which is what keeps a chain from being swapped under a
  signature.
- **A session key is not an identity.** It has no participant id, no log, no relationships,
  no records of its own; the only bytes that reference it are the grants naming it as
  audience and the sub-grants it issues.
- **Chains disclose.** A stored chain hands the counterparty's node the sender's session-key
  cadence and ability set, forever; and one `KeyRef` audienced by several subjects' grants
  links those subjects in every stored chain. Clients present minimal chains and mint one
  session key per subject.

  _Amended by 014:_ for the `e2ee` namespace this inverts — leaf credentials are **published**,
  not merely presented: they ride inside KeyPackages served to any authenticated claimer and
  inside MLS leaves every member reads. The disclosure is bounded by the rule above (such a
  chain grants nothing exercisable), but the linkage is worse than the one flagged here: a leaf
  key reused across conversations builds a durable, multi-party device graph out of records
  designed to travel. 014's mitigation is a SHOULD — a fresh leaf keypair per conversation.

## Non-goals

- ~~**End-to-end encryption.**~~ Lifted by 014, and the sentence above still holds inside it:
  session keys remain **signing** keys. 014 does not give them encryption duty — an MLS leaf is
  a separate keypair, forbidden from request signing, and key agreement is MLS's. What this spec
  supplies to that design is its chain machinery: the leaf credential binding a device to a
  participant is an ordinary key-audience grant chain, with the `e2ee` amendments above.
- **Multi-device fan-out.** Several session keys may hold `msg/read` on one inbox today;
  delivering to per-device inboxes stays deferred (010).
- **Root recovery.** Social recovery, backup escrow, and custodial root storage are custody
  features above the protocol.

## Open questions

- **Renewal.** Every reissue touches the root, and short expiries multiply the touches —
  in tension with "durable, rarely touched." A custody service is the likely answer for
  custodial participants (an authenticated user gesture triggers a custody re-signature);
  whether a renewal path exists short of root/custody for self-custodied roots stays open.
- **Delivery attestation.** A node-signed `(envelope digest, deliveredAt)` would give
  bytes-alone re-verifiers a time anchor, closing the backdating window and the revocation
  retroactivity above; deferred with 008's sign-time anchoring.
- **`aud` semantics.** Three items are open: whether an intermediate service in a multi-hop
  chain counts as an audience of the upstream links, pairwise identifiers vs whole-chain
  disclosure, and revocation-registry correlation (note the 003 digest is over the complete
  signed record, signature included, so the registry key is high-entropy by construction — to
  be confirmed, not assumed). Until they are settled, implementations take the conservative
  reading.
- **Discovery-write vocabulary.** A session key editing a profile needs abilities for the
  discovery surface (004); deferred until a client needs to edit public records from a session
  key.
- **Delegated relay of owner-signed envelopes.** Mixed-mode rejection also forbids a session
  key delivering an envelope the root signed offline — a real capability, excluded for v1's
  one-key-one-chain simplicity; revisit if a composed-offline flow demands it.

## Design notes

- **Terminology.** A delegate key is the grant's **audience**, never its subject:
  `subjectId` is, and remains, the participant whose authority the chain delegates.
- **Reference implementation.** In the Kinnet reference implementation the widened principal
  types, the key-issuer signature branch, and `aud` enforcement live in `@kinnet/protocol`
  and `@kinnet/trust`; the classify-then-reject `keyid` parse and the covered-component
  requirement live in `@kinnet/verify`. The schema-level cross-field rules ship with
  accept/reject fixtures both ways.

## History

- 2026-07-21 — Multi-hop re-delegation from a session key (user → session key → backend
  service) and exercise-audience binding (`caveats.aud`) added.
- 2026-08-02 — Recorded that 014's records adopt the same re-verifiable-unit shape one layer
  in, with the record-authorizing chain distinct from the transport chain.
- 2026-08-03 — Enrollment widened: `PUT /inboxes/:id` accepts a single self-issued
  key-audience grant carrying the exact ability `inbox/enroll`, which enters the inbox
  vocabulary; the open question on delegable enrollment is thereby answered.

## References

- Spec 002 (participant id), 003 (logs, digest rule), 004 (request auth), 005 (KeyRef),
  008 (revocation), 009 (grant chains), 010 (inbox surface), 014 (the E2EE lane — MLS leaf
  credentials as key-audience chains, the `e2ee` `aud` exemption, and the never-request-valid
  rule that pays for it)
- UCAN delegation 1.0 — principals as keys (`did:key`), delegation and attenuation by
  key principals
