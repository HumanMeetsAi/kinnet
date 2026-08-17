# 013 — Realtime delivery

**Status:** Accepted
**Blocks:** the live surfaces of the interaction plane, and the seam every later
push/notification transport hangs off
**Amended by:** 014, 017

## 1. Context

010 fixes delivery and reads; 011 makes reads grant-based; 012 gives messages a container.
Every one of those surfaces is **pull**: a client learns that something happened by asking.
The push half is missing: a subscription surface on the node (SSE or
WebSocket) authorized by the same request verification as reads, owner keys and spec-011
delegated chains alike — with polling retained as the fallback and a push-notification seam
designed but not implemented.

No streaming surface existed before this spec: `ParticipantNode.transports` carried a
`"websocket"` value that no route ever defined. _Amended by 017: the `websocket` transport value is removed from
`ParticipantNode.transports`; the enumeration is `https` and `webrtc` (017)._

The reason it needs one is a single structural mismatch. Every authorization in this protocol
is evaluated **at one instant**: 011's rule 5 is "at request time no link is expired and no
link is revoked", and a chain is walked once per HTTP request, evaluating expiry and revocation
against a `now` captured on entry. There is no re-check of anything after that. A subscription
inverts the shape: one authorization instant, then hours of authorized data flow. **A grant
revoked at minute three of a four-hour stream is, on that mechanism, not revoked at all.**

So the placement test (000) is worth running before anything else. Almost nothing here is
protocol in the record sense: no new signed record, no new signature regime, no new wire
format two independent implementations must agree on byte-for-byte. What two implementations
_do_ have to agree on is (a) what authority a stream requires and how long that authority
survives, and (b) that a stream never surfaces something a read would not have. Those are
interop-necessary because they are security properties a grantor reasons about when issuing a
grant — a delegate's authority must not mean something different depending on whose node
holds the inbox. Everything else — heartbeats, buffer sizes, fan-out mechanics — is node
surface, pinned the way 010 and 012 pin routes: mechanism a client can rely on, no new
records.

This spec composes with 012 and amends none of it. 012 is Accepted and unchanged by this spec:
membership is fixed at creation, consent is pending-by-default with accepted-and-discarded suppression surviving
redelivery, the ability rule is generative, and cursor writes and conversation creation each
hold their own ability. Realtime delivery adds one ability, one route, and one piece of
node-local ephemeral state, and changes no rule above.

_Amended by 014:_ 012 has since gained a second lane, on which membership _does_ change (by
evidence records MLS orders) and on which reserved-type envelopes are returned by the
conversation-filtered read. This spec still amends nothing in 012 — but two of its own rules
were keyed on the facts that changed, and are amended below (§2.2, §2.5).

## 2. Decision

### 2.1 One route, SSE, one direction

```
GET /inboxes/:id/events
```

Server-Sent Events over HTTPS. Response `200` with `Content-Type: text/event-stream`,
`Cache-Control: no-store`, and `X-Accel-Buffering: no` (intermediaries that buffer defeat the
surface entirely). The stream is **unidirectional**: a subscriber never writes over it. Every
write stays on its existing signed route (`POST /messages`, the 012 cursor and consent PUTs),
because a frame sent up a stream carries no per-request signature and admitting one would
require a new signing regime — exactly what 011 avoided by keeping delegation on RFC 9421
requests. WebSocket is rejected for the same reason plus a smaller one: SSE is a signed GET,
so it inherits 004/011 verification unchanged, whereas the WebSocket handshake's `Upgrade`
dance and framing would need their own profile for nothing this surface needs.

Polling remains fully supported and is the fallback. A client that cannot hold a stream MUST
lose no capability, only latency: `GET /inboxes/:id/messages` (010/011) and 012's listing and
filtered reads are unchanged, and a node MAY refuse streams entirely (resource policy) without
becoming non-conformant.

**Check order on this route is pinned**, matching the read route's order exactly:
(1) verify the request (`401` on any verification failure);
(2) subject match — `verified.agentId` MUST equal `:id`, else `403 not_inbox_owner`;
(3) abilities — a delegated request MUST cover `msg/subscribe`, else
`403 grants_abilities_insufficient`; (4) inbox existence, else `404 unknown_inbox`. The order
matters for the same reason 012 flags it: existence is disclosed only after authority is
established, so an unauthorized caller cannot use the route to probe which inboxes a node
hosts.

### 2.2 Events are notifications, not deliveries — the view-parity rule

**An event carries no content.** The `data` field of every event is a small JSON object whose
informative content is a `kind`, plus the two flags other rules require: `"state":"pending"` on
the pending view (§2.5) and `reason` on `close` (§2.4.6). No envelope, no payload, no `from`,
no `conversationId`, no `seq`, and (per §2.6) no id. To learn _what_ changed, the subscriber performs an ordinary
read on the routes that already exist, where 010/011's `(envelope, chain)` unit and its
bytes-alone re-verification apply unchanged.

This is the central decision of the spec, and four things fall out of it:

- **No new verification surface.** The alternative — streaming full envelopes — makes the
  stream a second delivery path, and every property 010/011 pin for reads (the stored chain
  travelling with the envelope, re-verification from bytes, the residual-window honesty in 011) would have to be restated and re-tested for it. Two code paths that must agree about
  what is authorized are how consent bypasses and verification gaps enter a system. Here
  there is exactly one content path and one place to test it.
- **Nothing on the stream is signed, and nothing on it is evidence.** A client MUST NOT treat
  an event as proof that anything happened; an event is a hint to read. A node that emitted a
  fabricated event would accomplish nothing an operator cannot already accomplish by
  withholding reads (010's stated non-goal: the operator sees plaintext). No event is a
  record; no event is ever relayed, stored as history, or re-verified.
- **At-least-once becomes free.** Duplicate events are harmless because the response to an
  event is an idempotent read. Exactly-once is not attempted and not needed.
- **The push seam is privacy-safe by construction** (§2.9): a contentless poke is exactly
  what a third-party push service should be handed.

The governing invariant, which every other rule in this spec is measured against:

> **View parity.** Every stream view mirrors a read view. A stream view MUST NOT signal any
> state change that its mirrored read view would not surface, and MUST NOT be served to a
> chain that lacks the authority for that mirrored read view.

| Stream view      | Mirrored read view                                    | Authority to receive it         |
| ---------------- | ----------------------------------------------------- | ------------------------------- |
| default          | default message read + active conversation listing    | `msg/subscribe`                 |
| `?state=pending` | `GET /inboxes/:id/conversations?state=pending`        | `msg/subscribe` + `msg/read`    |
| consent          | none exists — baseline inferred (§7, open question 5) | `msg/subscribe` + `msg/consent` |

_Amended by 014:_ the default view's mirrored read also includes, for each `e2ee` conversation
the inbox holds active, that conversation's filtered read (`?conversation=`) — which 014 makes
the E2EE lane's only message surface. Same route, same authority, no widening of reach; §2.5
gives the reasoning.

The invariant is stated per _view_ rather than as one global baseline. A single baseline — "a
`msg/read`-holder's default read of that inbox" — read literally forbids two of §2.5's own
MUSTs, since a default read surfaces neither pending conversations nor consent transitions, and
an invariant that outlaws the spec's own rules gets resolved by an implementer in whichever
direction is convenient.

Two things the per-view form buys. First, **visibility is a property of the view, not of the
caller.** Within a view the node never filters by the subscriber's ability set; if it did,
two delegates would see different event _timing_ on the same inbox, which is a side channel
leaking the ability set. Access is granted or refused a whole view at a time. Second, the
authority clause is what stops a **subscribe-only** delegate reaching a suppressed view: it
must hold the authority for the mirrored read, not merely for streaming (§2.5).

The consent view is the one exception and is flagged as such: 012 defines no read route for
the block list, so its baseline is inferred from the write authority (`msg/consent`) rather
than mirrored from an existing read. See §7 and open question 5.

View parity is what makes the stream safe to reason about: it introduces no new disclosure
decision, so 012's consent model needs no amendment and no realtime-specific exception.

The cost, stated plainly: a message arrival costs one extra round trip (event, then read)
before a client can render it. On an already-open HTTP/2 connection that is small, and it is
the price of having one content path instead of two.

### 2.3 Ability: `msg/subscribe`

Opening a stream requires the ability **`msg/subscribe`** over the inbox `:id`, where `:id`
equals the chain's subject — the same subject rule 011 fixes for `msg/read`. Owner-mode
subscription (a request whose `keyid` is `:id`, verifying against that participant's current
key state) needs no grant, exactly as for reads.

| Ability         | Authorizes                                                          |
| --------------- | ------------------------------------------------------------------- |
| `msg/subscribe` | open an event stream on an inbox; receive contentless notifications |

This **adds** to 012's vocabulary and amends nothing in it. No existing ability changes
meaning, and 012's generative rule (`pn/<name>` envelope → `msg/<name>`) is untouched,
because there is no `pn/subscribe` envelope type.

**Namespace reservation (normative).** 012's generative rule mints delivery abilities from
envelope type names into the same namespace as the inbox's read-side abilities. A future
reserved envelope type MUST NOT be named such that the rule produces `msg/subscribe`,
`msg/read`, `msg/cursor`, or `msg/consent`. A `pn/subscribe` envelope type would generate
`msg/subscribe` and silently give a _delivery_ ability the meaning of a read-side one — a
delegate granted the authority to deliver a payload would acquire the authority to stream.
This is a forward constraint on later interaction-plane specs, not a change to 012;
012's rule is correct as written, and this reservation is what keeps it correct as the
vocabulary grows.

_Amended by 014:_ the reserved list gains **`msg/keypackage`**, on the same footing and for the
same reason. 014 defines it as a _route_ ability (`PUT /participants/:id/keypackages`), so a
later `pn/keypackage` envelope type would hand a delivery ability the meaning of a
key-material write. The three abilities 014 does mint from envelope types — `msg/mls`,
`msg/welcome`, `msg/conversation-update` — are the generative rule working as intended and
reserve nothing.

Why a new sibling rather than riding `msg/read` — with 012's cursor precedent as the model
and its honest limits kept in view:

- **A stream is a standing authorization; a read is a discrete one.** This is the substantive
  difference and it is a _security_ difference, not an ergonomic one. Granting `msg/read`
  authorizes reads each of which is individually verified, with expiry and revocation
  evaluated per request. Granting a stream authorizes a window during which authorization is
  re-evaluated on a timer, at whatever cadence the node chose (§2.4). A grantor who does not
  want to accept that staleness must be able to say so without also denying reads.
- **It is a resource commitment.** A stream pins a connection, a buffer, and an instance
  affinity. Whether a delegate may occupy those is a distinct decision from whether it may
  read.
- **The 012 precedent points the same way.** `msg/cursor` exists because a delegate holding
  `msg/read` could already see everything, yet cursor writes let it _shape what the owner's
  other clients surface_. Streaming is the mirror image: it changes the delegate's temporal
  relationship to the inbox, not its content reach. In both cases the extra authority is
  invisible inside `msg/read` and would be conferred silently.
- **The caveat alternative does not work on this stack.** The obvious cheaper shape — no new
  ability, just a `caveats.stream` on `msg/read` — fails closed at every verifier that has no
  evaluator for it: by 009's fail-closed caveat rule a verifier rejects any link carrying a
  caveat other than `aud` unless it is supplied with an evaluator that returns true for it
  (`grant_caveat_rejected`). A chain carrying `caveats.stream` would therefore stop verifying
  at every _existing_ verifier — including relying applications and the discovery surface —
  turning a narrowing intent into a global breakage. 009's fail-closed caveat rule is right; it
  just makes caveats the wrong instrument for adding a capability, as opposed to restricting
  one.

The honest counterargument, retained because it did not go away:
**`msg/subscribe` closes nothing that `msg/read` leaves open.** A delegate holding `msg/read`
can poll every 200ms and approximate a stream, learning the same timing and volume signal at
higher cost. `msg/subscribe` is therefore not a confidentiality boundary. It is (a) an
explicit, separately-grantable acceptance of the extended staleness window, (b) a resource
control, and (c) a strictly-weaker capability in its own right — a subscribe-only delegate
(a notifier that pings a device but may not read the mail) is a real and useful shape that
does not exist if subscription rides `msg/read`.

Two consequences to state rather than let a reader discover:

- **`msg` covers it.** By 009 path-prefix cover, every already-issued grant carrying the bare
  `msg` umbrella will confer streaming authority the day a node implements this route.
  Grantors relying on `msg` should know that its meaning grows with the vocabulary; this is
  inherent in the umbrella, not new here, but realtime is the first ability added after grants
  had already been issued.

  _Amended by 014:_ it grows again, and further than streaming did. Every already-issued `msg`
  grant now also confers `msg/mls`, `msg/welcome`, `msg/keypackage`, and
  `msg/conversation-update` — the last of which includes the authority to author membership
  evidence for conversations its subject created, covering device management and creator-side
  adds. Authoring a **self-departure** — a `remove` record whose `members` is exactly
  `[actor]` — is deliberately not in that set: 014 pins it to the ability
  **`conversation/self-remove`**, _outside_ the `msg` namespace, so by the same path-prefix rule
  that makes `msg` cover `msg/subscribe` and `msg/conversation-update`, `msg` does not cover
  `conversation/self-remove` at all. A bare `msg` grant therefore confers no unilateral
  self-expulsion authority — which matters because add authority is creator-only, so a subject
  removed by a stolen session key could not restore themselves — and a client that wants "leave
  conversation" from a session key must ask for that ability by name. Grantors relying on the
  bare umbrella should still narrow.

- **A subscribe-only delegate still learns activity timing and volume** for whatever the
  view-parity rule lets through. That is a genuine disclosure — traffic analysis of when a
  participant is being talked to. It is not nothing, and a grantor should not read
  `msg/subscribe` as "harmless".

**Session-key (key-audience) chains MAY subscribe.** They are, in fact, the best-bounded
streams on the surface: 011 requires `expiresAt` on every key-audience link, so rule 1 of
§2.4.2 always derives a hard deadline from the chain's own bytes for exactly the credential
most likely to be lost. Forbidding them would push clients toward long-lived
participant-audience chains with no mandatory expiry — strictly worse.

### 2.4 A stream is a continuing exercise of authority

This is the section the surface exists to get right.

**The principle.** 011 and 012 both establish that a _completed act_ is judged against the
authority valid when it happened: a revoked session key does not retroactively unmake the
conversations it created (012), and bytes-alone re-verification does not apply wall-clock
expiry (011). A stream is the opposite kind of thing. It is not a completed act; it is an
authority being **exercised continuously**. So the rule inverts: a stream MUST be authorized
by authority that is valid _now_, for every value of now that it is open.

#### 2.4.1 The re-authorization contract

Re-authorization is not simply "re-run the request verification". The decision an ordinary
request takes is bound to that request, and one of its inputs is not otherwise available:

- The delegated half is reachable through chain verification, but the checks that surround it —
  keyid classification, leaf-audience matching, `aud` enforcement, nonce and skew — are
  properties of an HTTP request, and there is no new request to check.
- The owner-mode half needs a fact ordinary request verification need not expose: **which key
  satisfied the signature**. A verifier that tries every key in the participant's current state
  and reports only that some key matched leaves an owner-mode re-check with nothing to test —
  "some key of this participant signed, once" stays true after the signing key has been rotated
  out, and the re-check would silently pass forever. In owner mode the request's `keyid` is the
  _participant id_, not a key, so it does not supply the fact either. **A node serving this
  route MUST therefore obtain, at open, the key reference that satisfied the signature, and
  retain it for the stream's life.**

This spec pins a named contract:

```
reauthorizeStream(record: StreamAuthRecord, now: Date) -> Authorized | Terminated(reason)

StreamAuthRecord (captured at open, immutable for the stream's life):
  mode:         "owner" | "delegated"
  inboxId:      ParticipantId         // the :id being streamed
  subject:      ParticipantId         // owner mode: == inboxId; delegated: chain subject
  principal:    Principal             // the request's keyid principal (011): the participant
                                      //   id in owner mode, the leaf audience when delegated
  satisfiedKey: KeyRef                // the key that actually satisfied the signature
  chain?:       Grant[]               // delegated mode only, as presented
  filters:      { conversation?, state? }
  deadline:     Date                  // §2.4.2 rule 1
```

`reauthorizeStream` MUST, for both modes, re-resolve state through the trust view at `now`,
and MUST return `Terminated` — never `Authorized` — if any step cannot be completed.

- **Owner mode:** `satisfiedKey` MUST be a member of `subject`'s **current** key state (003).
  Not "any replay-valid state": the current one. This is the whole reason the crypto layer
  must return the satisfying `KeyRef`.
- **Delegated mode:** the full 009/011 chain decision at `now` — every link unexpired, no link
  revoked (008), abilities still covering `msg/subscribe`, leaf audience still equal to the
  request's principal, subject still equal to `inboxId`, and effective `aud` still admitting
  this node's participant id. Additionally, when the leaf principal is a participant,
  `satisfiedKey` MUST still be in that participant's current key state, by the owner-mode rule
  above.
- **Fail closed on unverifiable.** Store error, unreachable key log, unreachable revocation
  view, or any thrown exception ⇒ `Terminated("unverifiable")`. The previous decision is never
  extended on the grounds that nothing was proven wrong.
- The contract takes no HTTP request and re-checks no signature, nonce, or skew — see §2.4.5.

#### 2.4.2 The four rules

A node serving a stream MUST enforce all four. All four fail closed.

1. **Deadline at open.** On accepting a subscribe request the node computes
   `deadline = min(openedAt + maxStreamLifetime, earliestLinkExpiry)`, where
   `earliestLinkExpiry` is the earliest `expiresAt` among all links of the presented chain
   (owner mode: absent, so the lifetime bound alone applies; 011 requires `expiresAt` on every
   key-audience link, so a session-key chain always contributes one). The node MUST terminate
   the stream at `deadline`. Expiry therefore needs no polling and has **zero** staleness: it
   is a timer computed from the chain's own bytes.
2. **Periodic re-authorization.** At least every `recheckInterval`, the node MUST call
   `reauthorizeStream` and MUST terminate on anything but `Authorized`. `recheckInterval`
   **MUST NOT exceed 120 seconds**; RECOMMENDED ≤ 30 seconds. This is a normative ceiling
   rather than pure node policy because a grantor issuing `msg/subscribe` needs to know the
   worst case its grant is exposed to at _any_ conformant node; leaving it open would make the
   same grant mean materially different things on different hosts.
3. **Best-effort immediate termination.** A node that learns of a revocation out of band
   (its own revocation write path, a registry push, a cache invalidation) SHOULD terminate
   affected streams immediately rather than waiting for the next re-check. This is a latency
   improvement, never a substitute for rule 2: correctness rests on the timer, not on the
   event reaching the right process.
4. **Unverifiable is unauthorized**, per the contract above.

#### 2.4.3 Key rotation, and whose streams it kills

Owner-mode reads verify against the participant's _current_ key state (010, 011); so does
owner-mode re-check. A rotation that drops the subscribing key from the current state
therefore kills that stream, and a routine rotation kills the owner's live streams as a side
effect. That availability cost is accepted: the client reconnects with a key in the new state,
and the alternative — honouring any replay-valid state, as 012 rightly does for stored
records — would mean a rotated-out key keeps streaming, which is precisely the compromise case
rotation exists to answer.

**Rotating the root key does NOT kill delegates' live streams.** A chain link issued by a
participant verifies against _any_ state that participant's key log replays to (008: a rotation
does not orphan previously issued records), so a delegated chain survives its issuer's rotation
by design. Only **revocation** ends a delegated stream early. Rotation-driven termination is a
property of owner-mode streams, where the signing key itself is what must remain current. An
operator rotating a root key to contain a compromise MUST also revoke the affected grants;
rotation alone leaves delegated streams running.

#### 2.4.4 The staleness window, as arithmetic

Both cached-view terms below have the same origin: a verifier resolves key logs, relationships,
and revocation lookups through one cached discovery view, and that cache's TTL is the staleness
each term contributes.

```
W_revocation = recheckInterval + revocationViewStaleness + terminationLatency
W_rotation   = recheckInterval + keyLogViewStaleness     + terminationLatency
```

Rotation is no cheaper than revocation: current key state resolves through the same cached view,
so a rotation is invisible to the node for up to the cache TTL exactly as a revocation is. Both
windows carry a view term.

Three properties of these windows, stated so they are not assumed away:

- Both view-staleness terms are **not new** — a polled read has them too, since each request
  resolves through the same cache. The delta streaming introduces over polling is exactly
  `recheckInterval + terminationLatency`.
- Only **expiry** is free: rule 1 is exact and depends on no external view.
- A node SHOULD refresh **both** the revocation view and the key-log view no coarser than
  `recheckInterval`; otherwise the view term silently dominates and the 120s ceiling on
  `recheckInterval` buys much less than it appears to.

**The residual trust model, stated rather than implied.** Failing closed on an _unreachable_
revocation view is real: a non-404 error response from the revocation lookup propagates and the
request fails. But a discovery host that answers **404** on the revocations path is
indistinguishable from a host reporting "no revocation exists", and that negative answer is
cached for the full TTL. So a hostile or broken discovery host can _withhold_ a revocation,
though it cannot _forge_ one. Streams inherit exactly this — no better and no worse than the
read path — and merely hold the consequence open for longer. Closing it is an 008-level question
(signed "no revocation exists" responses, or a signed revocation-set root), not something this
spec can fix locally.

#### 2.4.5 What re-checking cannot do

There is no new request, so there is no new HTTP signature: re-authorization re-checks the
_authority_, not the _peer_. If the transport is hijacked mid-stream the re-checks do not
notice. That is true of any long-lived authenticated connection and is TLS's job, but it means
a stream is strictly weaker than N discrete signed requests with respect to peer
authentication, and that weakness is part of what `msg/subscribe` asks a grantor to accept.

#### 2.4.6 Close semantics

Termination MUST be observable, not a bare socket close:

1. The node emits a terminal event `{"kind":"close","reason":"<code>"}`.
2. The node closes the connection immediately after; it MUST NOT keep serving events after
   emitting `close`, and MUST NOT wait for acknowledgement.
3. A client MUST NOT depend on receiving `close` — a network drop is indistinguishable from
   termination, so a client treats any disconnect as "reconnect and find out". The terminal
   event exists to stop a revoked client from reconnect-looping, not to make correctness
   depend on delivery.
4. On a reconnect whose authorization no longer holds, the node MUST answer the subscribe
   request itself with `401`/`403`, not with a `200` stream that immediately closes. A
   non-`200` is what stops a reconnect loop, and it keeps the authorization answer on the
   request, where it belongs.

Reason codes:

| Code                     | The node terminated the stream because…                                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `expired`                | a link in the presented chain has passed its `expiresAt`.                                                                                                    |
| `revoked`                | a link in the presented chain is revoked (008).                                                                                                              |
| `rotated`                | the key that satisfied the signature at open is no longer in the subject's current key state (003).                                                          |
| `abilities_insufficient` | the chain no longer covers the abilities this stream was admitted under (§2.3, §2.5).                                                                        |
| `audience_not_admitted`  | the chain's `aud` caveat no longer admits this node, or an `aud` this node requires is absent (011).                                                         |
| `subject_drift`          | the chain now resolves to a subject other than the inbox the stream is scoped to.                                                                            |
| `unverifiable`           | the re-check could not be completed to a verdict — an unreachable trust view, an exhausted allowance, a malformed or incoherent chain. Fail-closed (§2.4.1). |
| `lifetime`               | the stream reached its deadline: `maxStreamLifetime`, or the earliest link expiry (§2.4.2 rule 1).                                                           |
| `capacity`               | the node reclaimed resources — a subscriber that filled its buffer (§2.8), or node-level pressure.                                                           |
| `shutdown`               | the node is stopping.                                                                                                                                        |

These disclose nothing the peer cannot already determine — it holds the chain, key logs are
public (003), and the revocation registry is public (008) — and they let a client distinguish
"get fresh authority" from "retry later", which a generic code would not.

`reason` is an **open enum**. A client MUST tolerate a code it does not know, treating it the
way it treats `unverifiable`: the stream is over, and whether to reconnect is decided by
re-establishing authority, not by parsing the code. A node MUST NOT rely on a client
distinguishing any particular code, since a `close` may never arrive at all (rule 3).

### 2.5 Scope: whole inbox, filtered, never widened by membership

A stream is scoped to **one inbox** and authorized at inbox granularity. Two optional query
filters mirror the read surface exactly:

- `?conversation=<digest>` — only events concerning that conversation (mirrors 012's
  `GET /inboxes/:id/messages?conversation=`).
- `?state=pending` — see below.

Filters **narrow, never widen**. A per-conversation stream is not a per-conversation
authorization: the subscriber still needs `msg/subscribe` on the whole inbox, and a
conversation member with no authority over this inbox gets nothing. This follows 012's
boundary verbatim — "Membership is not read authority… a conversation member has no standing
to read another member's inbox, and an inbox delegate sees every conversation in that inbox,
member or not" (012, _Boundaries_). Realtime does not get to reinterpret that; a stream scoped
by membership would smuggle in exactly the access-control system 012 refused to build.

Because filters live in the query string and `@target-uri` is a covered component of the
spec-004 signature, the filter set is signed: an intermediary cannot broaden a subscription by
rewriting the URL. Where a node reconstructs the request URI behind a proxy it trusts, that
forwarded-aware reconstruction is what the signature is checked against, so a proxy that
path-rewrites must preserve the query string or the signature fails — correctly, and loudly, at
open rather than silently mid-stream.

**Consent gating.** 012 makes a delivered conversation `pending` unless the inbox has prior
contact, and a pending conversation "is stored and readable but MUST NOT appear in the default
listing" (012, _Consent_). View parity applied to that:

- A node MUST NOT emit a default-stream event for a `pn/conversation` delivery that lands
  `pending`, nor for messages associated with a `pending` conversation. If it did, a stranger
  who cannot appear in the recipient's listing could still ring the recipient's client on
  demand — a notification channel that bypasses exactly the suppression 012 built. Even a
  contentless poke is an unsolicited attention channel and a covert timing channel.
- A delivery from a **blocked** participant is "accepted with a normal 2xx and indexed
  nowhere" (012, _Consent_). It produces **no event, ever, on any stream, under any filter.**
  This is not a default the subscriber can opt out of.

  _Amended by 014:_ the rule is unchanged, but its premise no longer holds in one case, so it
  is restated to stand on its own. 014 makes the node **store** a blocked sender's
  `pn/mls`, `pn/welcome`, or `pn/conversation-update` envelope when that sender is
  still a member of the named E2EE conversation — suppressing group mechanics would
  desynchronize the _blocker's_ own MLS epoch beyond in-profile recovery. The no-event rule is
  therefore keyed on **the sender being blocked**, not on the delivery being indexed nowhere:
  a blocked sender's envelope emits no event even when it is stored and readable. Recovery is
  a read, which is what this spec says events are not needed for; letting the exception ring
  the recipient's devices would reopen T4 by the back door.

- **`?state=pending` requires `msg/read`.** A stream carrying this filter MUST be owner mode
  or present a chain that also covers `msg/read`. The reason is view parity: the pending view
  is exactly `GET /inboxes/:id/conversations?state=pending`, which 012 authorizes under
  `msg/read` ("read messages; list conversations"). Without this rule a **subscribe-only**
  delegate could mine the timing of suppressed stranger traffic that it has no authority to
  list — the one place where a subscribe-only chain would learn something the `msg/read`
  default view deliberately hides. Events under this filter MUST carry `"state":"pending"` in
  their data so a client cannot render one as ordinary activity by omission. (On why
  `msg/consent` alone does **not** admit this filter, see §7.)
- **Acceptance is itself an event.** When a pending conversation becomes `active` (the owner
  accepts via `msg/consent`, or sends into it), the node MUST emit a `conversation` event on
  default streams. Otherwise the owner's other devices never learn, and the consent transition
  becomes the one state change realtime cannot carry.
- **Other consent transitions emit too, on the consent view.** A pending conversation being
  rejected or discarded, and any block-list edit, MUST emit a `consent` event — but only to
  streams that are owner mode or whose chain covers `msg/consent`, since that is the authority
  which can observe or alter that state. Without this the owner's second device silently
  disagrees with the first about what has been blocked or dismissed. The `consent` event, like
  every other, is contentless: it names no participant and no conversation. This rule cannot be
  exercised yet: 012 defines no route that rejects or discards a pending conversation and none
  that writes the block list, so a conformant node has nothing to publish it from until 012
  defines those transitions (open question 5).
- Reserved-type envelopes are "excluded from the default `GET /inboxes/:id/messages` response"
  (012, _Creation is delivery_), so they produce no `message` event; conversation visibility is
  carried by the `conversation` kind instead.

  _Amended by 014:_ this rule keys on the wrong thing, and the amendment fixes what it keys
  on rather than carving out an exception. **A `message` event is emitted when an envelope
  becomes visible in a read view this stream mirrors** — not when its type lacks the `pn/`
  prefix. The two coincided until 014, because every reserved type was invisible in every
  message read view. They stop coinciding on the E2EE lane, where 014 makes the
  conversation-filtered read (`?conversation=`) return `pn/mls`, `pn/welcome`, and
  `pn/conversation-update`, and where those types _are_ the conversation. Left unamended,
  this bullet would emit no event at all for an E2EE conversation and silently degrade the lane
  to polling — the one outcome view parity is not permitted to produce, since the mirrored read
  does surface the change.

  Concretely: those three types emit a `message` event on a `?conversation=` stream for an
  `e2ee` conversation, and on the default stream for that inbox — the default view's mirrored
  read widens to include the filtered read of each `e2ee` conversation the inbox holds active,
  which grants no reach (the filter is the same route under the same `msg/read` authority, over
  a conversation already in the subscriber's listing) and keeps the client's follow-up read from
  coming back empty. Everything else is unchanged: `pn/conversation` still emits no
  `message` event on either lane — it is not returned by the filtered read either, and
  conversation visibility is still carried by the `conversation` kind — and the unfiltered
  default _read_ still excludes every reserved type.

**Bare messages from strangers still produce events.** 012's consent model gates conversation
_surface_, not bare inbox delivery — a cold `msg/send` lands in the inbox and a default read
returns it. View parity therefore says: event. This is consistent rather than accidental, but
it means realtime makes cold contact _louder_ than polling did. A node **MAY coalesce** events
(§2.6), which blunts the ringing without losing anything, because a coalesced event carries
the same information as the events it replaces: none. Rate-limiting beyond coalescing is
deferred with 010's anti-abuse open question.

### 2.6 Events, fan-out, and catch-up — no resumption in v1

**There are no event ids on the wire.** The SSE `id:` field is not used, `Last-Event-ID` is
neither sent nor honoured, and there is no resume point. Every connect — first or
thousandth — begins with a `sync` event, and the client establishes its baseline with an
ordinary catch-up read.

This is the largest simplification available to the design and it is taken deliberately. The
alternative is a durable per-inbox event log with ids, a `logId` for detecting truncation, a
retention window, and a bound so a fresh delegate cannot resume backwards into pre-grant
history. Every one of those exists to make resumption safe; none of them buys anything a
catch-up read does not already buy, **because the events are contentless**.
Resuming a stream of pokes saves at most one read. Deleting the mechanism deletes, at once:
the id scheme and its cross-node comparability trap, the `logId` divergence problem under
multi-process fan-out, the retention knob, the pre-grant timing-history bound, the durability
question, and — see §2.7 — any need to touch the pinned RFC 9421 covered-component set in
order to sign a `Last-Event-ID` header.

**Ordering guarantee, weakened accordingly.** With no ids there is no cross-connection
ordering claim. Within one connection, `message` events are emitted in per-inbox `seq` order.
Across a disconnect a client makes no ordering assumption at all: it reads. That weaker
guarantee is sufficient, because the read routes — not the stream — are the source of truth for
order (010's per-inbox `seq`, 012's listing).

**The event log survives as an implementation object, not a wire concept.** A node still needs
somewhere to fan out from: an in-process buffer of pending notifications per stream, which is
also what the push seam (§2.9) consumes. It is not addressable, not durable, not resumable,
and not part of the client contract. It is node-local ephemeral state on the same footing as
012's read cursor and consent index — never signed, never relayed, never re-verified, never in
discovery.

**Event kind vocabulary (normative, and closed for v1).**

| `kind`         | Meaning                                                        | Visible on which view (§2.2)                            |
| -------------- | -------------------------------------------------------------- | ------------------------------------------------------- |
| `sync`         | establish the baseline with a catch-up read                    | every stream, first event always                        |
| `message`      | a visible message changed this inbox                           | default view; pending view carrying `"state":"pending"` |
| `conversation` | a conversation became visible, or moved pending → active       | default view; pending view carrying `"state":"pending"` |
| `cursor`       | this inbox's read cursor changed                               | every stream on the inbox                               |
| `consent`      | a pending conversation was rejected, or the block list changed | consent view only (owner mode or `msg/consent`)         |
| `close`        | the stream is terminating; carries `reason`                    | every stream, terminal                                  |

The pending view is the `?state=pending` filter of §2.5, gated on `msg/read`; a `message` or
`conversation` event reaching a subscriber through it carries `"state":"pending"` and is the
same kind it would be on the default view, not a distinct one. `sync`, `cursor`, and `close`
are view-independent.

A client MUST treat an **unknown `kind` as a generic "something changed, catch up"** rather
than ignoring it, so that adding a kind later degrades to a redundant read rather than to
silent data loss. This is why every event shares one SSE `event:` name (`pn`) with the
kind in `data`, instead of using named SSE events a client must register for individually: a
client cannot fail to hear a kind it has never heard of.

**The open-then-read ordering rule.** A client MUST open the stream (and receive `sync`)
**before** performing its catch-up read. A client that reads first and opens second loses
every change occurring between the two, until some later unrelated event happens to wake it.

**The emit-after-commit rule.** A node MUST NOT emit an event before the state it announces is
durably readable through the read routes. Emitting first produces the worst failure this
design can have: a client reacts, reads, sees nothing, and — because events are at-least-once
and never retried — never learns.

**Delivery guarantee: at-least-once, never exactly-once.** Duplicates and coalesced events are
harmless. A client MUST be able to lose the stream entirely and recover by reading; a client
that cannot is misusing the surface.

**Multi-process (mirrors the nonce requirement in §2.7).** A message delivered on one process
must reach a stream held by another, or subscribers silently miss events they were entitled
to — a correctness failure invisible in single-process tests, and invisible in production
until someone notices missing messages.

> A node serving streams from more than one process MUST either use a shared event log with
> cross-process append notification, or pin each inbox's streams **and** its writes to a
> single process. A node that can do neither MUST NOT serve this route from more than one
> process.

**Reintroducing resumption later** is an additive change: an opt-in query parameter (e.g.
`?resume=<opaque>`) plus the `id:` field. The query string is signed automatically because
`@target-uri` is already covered. It MUST NOT be reintroduced as a request _header_, which
would require amending 004's pinned covered-component list and the rigid signature-input
grammar that admits exactly that list — a change to the 004 profile for a convenience feature.
Any reintroduction must also carry a pre-grant history bound: a delegated resume must not reach
events emitted before the chain's latest link `issuedAt`.

### 2.7 Signing a long-lived GET

**The subscribe request is signed exactly like a read — no profile change, and none needed.**
The covered components are 004's fixed triple `@method`, `@target-uri`, `content-digest`, with
`pn-grants` appended when a chain is presented, and the signature-input grammar admits exactly
that shape and no other. `content-digest` is pinned **unconditionally**, including on GETs: a
GET carries an empty body and signs the digest of the empty string, and a subscribe request
does the same. With resumption dropped (§2.6) nothing in the 004 profile changes for this route.

- **Freshness and skew** are checked once, at open, against the `created` signature parameter,
  with `maxSkewSeconds` defaulting to 120. The signature authorizes _opening_ the stream;
  continued authorization is §2.4's problem.
- **The nonce** is consumed once, like any request. A reconnect is a **new request with a new
  nonce and a fresh `created`**; a client MUST NOT replay a stored subscribe signature to
  reconnect, and a node MUST reject it (`nonce_replayed`).

**Nonce TTL — `maxSkewSeconds * 2` is INSUFFICIENT and MUST NOT be used.** That value is off by
one and leaves every signature replayable at the last second of its validity. Freshness is
inclusive at both ends (`Math.abs(now - created) <= maxSkewSeconds`), so for a fixed
`created = c` a signature is presentable across the **closed** interval `[c - S, c + S]` where
`S = maxSkewSeconds`: first presentable at `c - S`, still fresh at `c + S`, i.e. `2S` later. A
store that forgets a nonce once its TTL has elapsed therefore has already dropped it at
`c + S`, while the freshness check still admits the signature — so it replays. Implementations
MUST use:

> `nonceTtlSeconds = maxSkewSeconds * 2 + 1`

The `+ 1` is the minimum sufficient margin, not padding: at `c + S + 1` the freshness check
rejects the signature on its own, so nothing longer is required. A verifier MUST also sample
its clock **once** per request and use that same value for both the freshness check and the
nonce lookup — reading it twice lets it tick between them and reopens the identical
one-second hole.

**Durations MUST be measured on a monotonic clock, not the wall clock.** Wall time is
legitimate for exactly one thing here: comparing against the signer-supplied `created`. Every
DURATION — nonce retention, cache TTLs, ephemeral credential lifetimes, sweep cadence — MUST be
measured on a monotonic source that NTP corrections and snapshot restores cannot move.
Measuring a duration on the wall clock is a security defect in both directions: a forward jump
prematurely forgets live nonces and expires cached state, and a backward jump revalidates
credentials and cache entries that have genuinely expired.

Because a nonce must survive both, an implementation SHOULD retain each nonce until BOTH its
monotonic deadline and its wall-clock deadline have passed. Implementations MUST NOT refuse
requests while behind a wall-clock high-water mark: such a mark is never lowered, so a single
forward spike wedges the surface into permanent refusal even after the clock is corrected.

> RESIDUAL, which implementers MUST NOT assume is closed: a backward wall step LARGER than the
> retention window still re-opens replay, because the nonce was by then legitimately forgotten.
> No bounded nonce store can prevent this. Such a step also puts the wall clock more than
> `maxSkewSeconds` out, so throughout the exposure the freshness check rejects every legitimate
> signature — the condition is a loud outage, not a silent one.

**Operational requirement: a backward clock step is a security event.** The residual above is a
property of the DEPLOYMENT, not something an implementation can code around, so it is stated
here as an operator obligation rather than left in a code comment.

Two mechanisms were considered to close it and both were rejected, for reasons an operator
should know rather than rediscover:

- Refusing while the wall clock is behind a high-water mark wedges permanently on a forward
  spike, because the mark is never lowered (see the MUST NOT above).
- Refusing for a bounded period and then re-baselining does not close the hole: the clock is
  still rewound after re-baselining, so signatures from the rewound-to period pass freshness
  again and replay resumes. Only refusing until the clock is corrected closes it, which is the
  unbounded wedge.

Furthermore, the realistic way a production clock moves backward by more than the retention
window is a **VM snapshot restore, which restarts the process and empties the nonce store
entirely**. With no memory of any nonce, replay inside the freshness window is possible
regardless of what the store does — so no in-memory mechanism helps in the scenario that
actually produces the condition.

Therefore a deployment MUST:

- treat **restoring a host from a snapshot**, or **stepping the wall clock backward by any
  amount**, as a security event — the same way an operator would treat restoring a machine
  holding old session state. Signatures captured from the rewound-to period can be replayed
  once each against that host.
- prefer NTP **slewing** over stepping for routine correction, and where a step is unavoidable,
  drain the surface first so no captured signature is in flight across it.

**The exposure begins at a one-second step, and it is silent.** A backward step of `d` seconds
re-admits roughly a `d`-wide band of captured signatures — those whose retention has just
elapsed — for about `d` seconds. A signature first presented at `created - S` is retained until
`created + S + 1` and reclaimed there, correctly, because freshness rejects it from that second
onward; rewinding one second to `created + S` makes freshness accept it again with the nonce
already forgotten. Meanwhile signatures minted at the true current time are still within
`maxSkewSeconds` of the rewound clock, so **legitimate traffic continues to verify normally and
there is no outage to alert on.** Only a step larger than `maxSkewSeconds` produces the loud
authentication failure described in the RESIDUAL above; the exposure starts far below that
threshold and gives no such signal.

**Freshness inputs MUST be validated.** `maxSkewSeconds` and the sampled clock MUST each be a
finite, non-negative safe integer, checked before any comparison uses them. `NaN` is the
dangerous case: every comparison against it is false, so an unvalidated `NaN` skew does not
widen the window but REMOVES it — signatures of any age verify. Fractional values MUST also be
rejected, because the `2S + 1` derivation above is a statement about whole seconds. A surface
whose own clock is unusable MUST report a transient server-side failure (`503`), NOT an
authentication failure: reporting `401` tells the caller its credentials are wrong when the
fault is entirely the server's, and hides a clock incident inside auth-failure metrics.

**Expiry reclamation MUST NOT depend on insertion order.** A bounded store that decides
"is anything reclaimable" by inspecting only its oldest-inserted entry is correct only while
insertion order equals expiry order. That does not hold whenever a deadline is sampled before
an `await` and the entry inserted after it, nor whenever lifetimes are caller-supplied. An
implementation MUST either derive deadlines from a clock it samples at insertion time under a
single TTL (making the ordering a property of the code), or track the minimum deadline
explicitly. Getting this wrong wedges the store at capacity while it still holds reclaimable
entries.

**Replay amplification — a realtime-specific escalation of an existing weakness.** A nonce store
held per verifier instance and not shared across processes retains each nonce for the TTL above
(241 seconds at the default skew) but only locally. On the request path, replaying a captured
signed GET against a second instance within that window buys an attacker **one read**. On this
route it buys a **stream**, whose value is bounded by `maxStreamLifetime`, not by the replay
window. The amplification is the point: the same defect that is a nuisance for reads is a
serious hole for subscriptions. Therefore:

> A node that serves streams from more than one process or replica MUST use a shared,
> consistent nonce store. A node that cannot MUST NOT serve this route.

The second sentence is not a formality, and an implementation MUST make it visible to whoever
deploys it. A node whose nonce guard is the obvious one — per-process in-memory state, with no
seam through which a shared store can be supplied — satisfies the rule above **only** by being
served from a single process: adding a
second process or replica silently converts a captured subscribe signature into a stream, with
no error, no log line, and no behavioural difference an operator would notice. An implementation
whose nonce store is process-local MUST state that constraint where its operator will read it
(deployment documentation and the configuration surface, not only a source comment), and a
deployment that scales this route horizontally MUST supply a shared store first.

**Nonce-store capacity.** The store MUST be bounded, and on reaching its bound the node MUST
reject new requests (`503` with `Retry-After`) rather than evict entries to admit them:
evicting a live nonce restores the replay window it exists to close, so an attacker able to
fill the store could otherwise unlock replay on demand. Note also that TTL sweeps scanning the
whole store cost O(size) CPU per sweep, which a reconnect storm can drive; a cheap
per-connection admission gate (per-IP or per-principal connection accounting) SHOULD run
_before_ signature verification, so a flood is rejected before it costs a signature check or a
store insertion.

**Requests behind a proxy.** Where a node is configured to trust its proxy, the verified target
URI is the forwarded-aware reconstruction from `X-Forwarded-Proto`/`X-Forwarded-Host` (first hop
only), and a node that does not trust its proxy falls closed to the literal request URL.
Reconstruction happens once, at open — correct, since the signature covers one request. What
long-lived GETs add is a set of _operational_ proxy constraints that belong in this spec because
ignoring them produces a surface that silently doesn't work:

- Response buffering MUST be disabled at every hop.
- `heartbeatInterval` MUST be shorter than the shortest intermediary idle timeout, or every
  stream dies at that timeout with no diagnosis.
- A proxy that rewrites the path or drops the query string breaks signature verification at
  open. That is the right failure (loud, immediate) but it must be in the deployment runbook,
  not a mystery.

**Browser clients cannot use `EventSource`.** The `EventSource` API cannot set request headers,
so it cannot carry `Signature-Input`, `Signature`, or `PN-Grants`. Browser clients MUST use
a streaming `fetch` and parse the SSE framing themselves (or a non-browser SSE client that
supports headers). This spec **explicitly refuses the obvious workaround**: signatures, chains,
or any credential MUST NOT be carried in query parameters. A credential in a URL leaks into
access logs, proxy logs, browser history, and `Referer`; it is replayable for the full nonce
window by anyone who reads any of those; and it would trade the one genuinely hard property of
this stack — that authority is presented, not published — for client convenience. If
`EventSource` compatibility is ever required, the answer is a short-lived, single-use,
node-issued stream ticket bound to the verified request (§6), never a signed URL.

**CORS.** A delegated browser request carries its chain in `PN-Grants`, so a node serving
browser clients needs `pn-grants` in its CORS request-header allowlist alongside
`content-type`, `content-digest`, `signature-input`, and `signature`; an allowlist omitting it
blocks **every browser use of this route in delegated mode**. With resumption dropped,
`pn-grants` is the only addition this route requires.

### 2.8 Resource bounds

A stream is the first surface on this node that a client can hold open, so it is the first one
where a bad or hostile client costs the node something continuously. This spec names the knobs
and the rules that govern them; numbers are node policy except where §2.4.2 fixes a ceiling.

Knobs a node MUST expose in configuration: `maxStreamsPerInbox`, `ownerReservedStreamsPerInbox`,
`maxStreamsPerDelegationTree`, `maxStreamsPerNode`, `maxStreamLifetime`, `recheckInterval`
(≤ 120s), `heartbeatInterval`, and `maxBufferedEventsPerStream`.

A node MAY send an SSE `retry:` hint; clients control their own backoff. Nothing in this spec
depends on a client honouring it — a client that ignores `retry:` entirely is conformant — so it
is a courtesy, not a control. What bounds reconnect pressure is stated below and in §2.7: the
pre-verification admission gate, the stream budgets, and refusals that carry their own retry
signal (`429`, or `503` with `Retry-After`).

Rules:

- **Delegated budgets are keyed by the chain's root-grant digest — the delegation tree — not
  by the leaf principal.** Keying on the leaf is trivially evaded: 011 lets a key principal
  re-delegate, so a delegate can mint unlimited sub-grants to fresh session keys, each a
  distinct leaf principal with its own budget, from one grant the owner issued once. The root
  grant's 003 digest is the invariant across that whole subtree, and is what the owner
  actually authorized. Owner-mode streams have no chain and are budgeted per participant.
- **Re-check work counts inside the same budget.** Periodic re-authorization is per-stream
  work against the trust view; if it sat outside the budget, a delegation tree at its stream
  limit could still impose unbounded verification load. Budget the streams _and_ the recurring
  cost they create.
- **Admission never evicts.** A node MUST NOT terminate an existing stream to admit a new one
  from a _different_ delegation tree or principal. Otherwise the weakest delegate on an inbox
  can evict the owner's client at will — a denial-of-service handed to the least-trusted
  holder. Over-budget subscribe requests are refused (`429`, or `503` with `Retry-After` at
  node capacity), never traded against someone else's stream.
- **Delegates get their own, smaller budget.** The owner's ability to connect MUST NOT be
  consumable by delegates. The reservation is an explicit knob,
  `ownerReservedStreamsPerInbox`: that many of `maxStreamsPerInbox` are held for owner-mode
  streams and are never admissible to any delegation tree.
- **Slow consumers are closed, not buffered.** If un-acked writes exceed
  `maxBufferedEventsPerStream` the node MUST close the stream (reason `capacity`). Unbounded
  per-connection buffering is a memory exhaustion primitive. Closing is safe precisely because
  events are contentless and recovery is a read. Coalescing (§2.5) is the cheaper first
  response.
- **Heartbeats are SSE comment lines** (`: ka`), not events: they do not wake application
  handlers.
- **Idle is not a failure.** A stream with no events is the normal case; only a stalled
  _reader_ (backpressure) or a missed heartbeat is a fault.

### 2.9 The push seam (designed, not implemented)

A push transport is a **node-local consumer of the same fan-out the streams consume**. It sees
the same notifications, filtered by the same view-parity and consent rules (because it
consumes the filtered event stream, not the raw store), and emits a contentless poke to a
device. Nothing in the push path may originate content, because there is no content to
originate.

That is the whole seam, and the contentless event model is what makes it safe: a push
provider — Apple, Google, a self-hosted relay — sees that _something_ happened for a device
token and learns no participant id, conversation id, or payload. Authorization for registering
a push endpoint, device-token custody, and every transport detail are out of scope here (mobile
is out of scope for this surface), and a push registration will need its own ability when it is
specified.

## 3. Threat model

Each vector, the mechanism that closes it, and the residue that remains open.

**T1 — Revoked-grant streaming.** An attacker holding a stolen session key opens a stream; the
owner revokes. _Closed by:_ §2.4's periodic re-authorization under a 120s ceiling, the
open-time deadline, and fail-closed on unverifiable. _Residue:_ the attacker keeps receiving
events for at most `W_revocation = recheckInterval + revocationViewStaleness +
terminationLatency`, of which only the first and last terms are new relative to polling. The
events are contentless, so what leaks in that window is _activity timing_; content requires
`msg/read`, whose reads are gated per request. This asymmetry — the stream stales, the reads
do not — is a direct consequence of §2.2 and the strongest argument for contentless events.

**T2 — Expiry outliving the stream.** _Closed by:_ rule 1's deadline, computed from the
chain's own `expiresAt` values, with zero dependence on any external view. 011 requires
`expiresAt` on every key-audience link, so this bound always exists for session-key chains.

**T3 — Rotated-out key streaming.** The owner rotates to retire a compromised key; a stream
signed by the retired key continues. _Closed by:_ owner-mode re-check requiring the **recorded
satisfying KeyRef** to be in the _current_ key state (§2.4.1) — which is why the node must
capture it at open. A node that cannot tell which key signed leaves this vector **open by
construction**. _Residue:_ `W_rotation`, which carries the key-log view
term; the accepted cost that ordinary rotations drop the owner's live streams; and the fact
that root rotation alone does **not** end delegated streams (§2.4.3) — containing a compromise
requires revocation, not rotation.

**T4 — Consent bypass via events.** A stranger creates a conversation that lands `pending` and
sends into it repeatedly, using the recipient's stream as the notification channel 012's
listing suppression denies. _Closed by:_ view parity (§2.5) — pending conversations and their
messages emit no default-stream event, blocked senders emit none under any filter, and the
`?state=pending` view requires `msg/read`. _Residue:_ bare messages from strangers still emit,
because 012 lets them into default reads; coalescing blunts it, and anti-abuse remains
deferred. _Amended by 014:_ still closed. 014's block-list exception makes a blocked member's
group-mechanics envelope _storable_, which would have reopened this vector had the no-event
rule stayed keyed on "indexed nowhere"; §2.5 rekeys it on the sender being blocked, so the
blocked party gains storage and no poke.

**T5 — Cross-conversation leakage in a whole-inbox stream.** _Closed by:_ there is no
per-conversation authorization to leak out of — authorization is always whole-inbox, and
`?conversation=` narrows over authority already held. Conversation membership never grants a
stream. _Residue:_ the inverse, inherited from 012 and not introduced here — an inbox delegate
sees every conversation in that inbox.

**T6 — Event-id probing and enumeration.** _Closed by construction:_ there are no event ids on
the wire (§2.6). Nothing to probe, nothing to enumerate, no `seq` gaps to count, and no resume
point through which a newly-granted delegate could reach pre-grant activity history. The vector
exists only for a design that carries resumption; dropping resumption removes it along with the
three separate mechanisms that would have to defend it.

**T7 — Resource exhaustion.** Many streams, slow readers, reconnect storms, or sub-grant
minting to multiply budgets. _Closed by:_ delegation-tree budgets that cannot be evaded by
re-delegation, re-check cost counted inside the budget, admission that never evicts, bounded
per-stream buffers with close-on-overflow, bounded lifetimes forcing turnover, and the damping
that does not depend on client cooperation: the pre-verification admission gate (§2.7), the
budgets themselves, and refusals that state their own retry terms — `429`, or `503` with
`Retry-After` at node capacity — plus a non-`200` on an unauthorized reconnect, which stops the
one loop a revoked client would otherwise run forever (§2.4.6, §2.8). _Residue:_ reconnect
storms still cost nonce-store insertions and TTL-sweep CPU; the bounded store with
reject-when-full and the admission gate ahead of signature verification (§2.7) is the answer,
and its sizing is node policy.

**T8 — Subscribe-request replay.** A captured signed subscribe replayed against another
process. _Closed by:_ the shared-nonce-store MUST (§2.7). _Residue:_ none if honoured; if not,
the attacker gets a full stream from one captured request, which is why it is a MUST.

**T9 — Missed events under multi-process fan-out.** A write on one process, a stream on
another; the subscriber silently never learns. _Closed by:_ the shared-log-or-pin MUST (§2.6).
A correctness vector rather than a security one, but it fails silently, which is why it is
normative.

**T10 — Credential leakage via URL.** _Closed by:_ the flat prohibition on query-parameter
credentials (§2.7), at the cost of `EventSource` incompatibility, which is accepted.

**T11 — Traffic analysis by a subscribe-only delegate.** A delegate holding only
`msg/subscribe` learns when the participant is active, how much, and (with `?conversation=`)
which threads move. _Not closed — accepted and disclosed._ It is the inherent content of the
capability, and `msg/subscribe` exists partly so a grantor makes this choice explicitly rather
than inheriting it inside `msg/read`. Bounded, though: the suppressed views are out of reach
without `msg/read` (§2.5), so a subscribe-only delegate sees the inbox's ordinary activity and
not the traffic 012 hides.

**T12 — Suppress-then-notice.** 012 identified that a delegate with `msg/cursor` can shape
what the owner's other clients surface as unread, composing with future approval-requests.
Realtime propagates that manipulation to the owner's other devices _faster_. _Not newly
closed:_ the authority boundary is still `msg/cursor`, unchanged from 012. Noted so propagation
speed is not mistaken for a new grant.

**T13 — Withheld revocation.** A hostile or broken discovery host answers 404 on the
revocations path; the node caches `null` and cannot distinguish it from "no revocation exists"
(§2.4.4). _Not closed here:_ streams inherit exactly the read path's trust model — a host can
withhold a revocation but cannot forge one — and merely hold the consequence open longer. An
008-level fix (signed negative responses, or a signed revocation-set root) is the only real
answer.

**T14 — The node operator.** Sees everything, as in 010. Streaming changes nothing:
contentless events tell the operator strictly less than the plaintext it already stores.

## 4. Boundaries

- **Same authorization as reads, no new mechanism.** The subscribe request is verified exactly
  as any other request, signs the identical covered-component set, and presents 011 chains in
  `PN-Grants` with `aud` enforced against the node's own participant id. The one thing this
  spec adds is _when_ that decision is re-taken.
- **No new records, no new signed bytes.** Nothing here is a protocol record, and no fixture
  is required for the event format because no event is ever verified. The conformance
  obligation is behavioural — route-level tests: revocation mid-stream terminates within the
  ceiling, owner-mode rotation terminates, pending conversations emit nothing on the default
  view, `?state=pending` refuses a subscribe-only chain, budgets never evict — not byte-level.
- **The fan-out buffer is node-local ephemeral state**, on the same footing as the read cursor
  and consent index (012): never signed, never relayed, never re-verified, never in discovery,
  and — with resumption dropped — not addressable by clients at all.
- **One node's view.** All ordering is per-inbox and per-node. Two members of one conversation
  on two nodes have unrelated streams. Cross-node realtime is the federation spec's problem
  (012's boundary, unchanged).
- **012 is untouched.** No ability changes meaning, membership rules are unchanged, consent
  states are unchanged, and the generative ability rule is unchanged. This spec reads 012's
  visibility rules and mirrors them; it never re-decides them.

## 5. Non-goals

- **Resumption, event ids, and `Last-Event-ID`** — dropped for v1 (§2.6); reintroducible as an
  additive query parameter, never as a covered header.
- **WebSocket and bidirectional streams.** Writes stay on signed requests; a stream frame has
  no signature and admitting one would need a new signing regime.
- **Push notification delivery, and mobile.** The seam is specified (§2.9); the transport,
  device registration, and its ability are not.
- **Streaming content.** Events carry no envelopes; the read routes remain the only content
  surface. _Amended by 014:_ that still holds on the E2EE lane — a contentless poke carries a
  ciphertext lane with no new disclosure, and the push seam needs nothing — but _which_ changes
  are announced needed amending, since keying the `message` event on the reserved-type prefix
  would have left the E2EE lane eventless (§2.5).
- **Exactly-once delivery, durable event history, and cross-connection ordering guarantees.**
- **Presence, typing indicators, and read receipts to other participants.** 012 makes these a
  non-goal and realtime makes them tempting; they stay out. The `cursor` and `consent` events
  go only to subscribers of the _same_ inbox, never to other conversation members.
- **Cross-node / federated event streams.** Deferred to the federation spec.
- **Server-signed events or delivery attestation.** Deferred with 008/011's sign-time
  anchoring question; note that if attestation ever lands it would give a subscriber something
  worth verifying, which would reopen §2.2's contentless decision.
- **Anti-abuse beyond resource limits and coalescing.** Deferred with 010's anti-abuse
  question.

## 6. Open questions

1. **The `EventSource` ticket.** If browser `EventSource` support is ever required, the shape
   is a single-use, short-TTL, node-issued ticket bound to a verified signed request — never a
   signed URL. Unspecified here, and named so nobody reaches for query parameters. Whether it
   is needed at all depends on whether streaming `fetch` proves sufficient for browser clients.
2. **Cold-contact notification volume.** Bare messages from strangers ring the recipient in
   real time (T4 residue). Coalescing is permitted and helps; whether per-sender caps, or
   deferring un-consented bare messages to a digest, belongs at the protocol layer or above it
   is still open, and is entangled with 010's anti-abuse question rather than separable from
   it.
3. **Whether the 120s ceiling belongs in this spec or in 004.** It is a property of how long
   _any_ long-lived authorization may go unchecked, and a later federation spec will face the
   same question for node-to-node connections. Fixing it here risks two specs disagreeing
   later.
4. **Multi-process shape.** §2.6 permits either a shared event log or per-inbox pinning. These
   have very different operational profiles (pinning implies sticky routing and complicates
   rolling deploys; a shared log implies a broker). The spec deliberately does not choose; the
   deployment that first needs two processes should, and should record the choice in its own
   operational documentation.
5. **Does the `consent` event's visibility rule hold up? — deferred; owned by 012.** §2.5 emits
   it to owner-mode and `msg/consent` chains, reasoning that consent state is what that ability
   governs. But 012 defines no _read_ route for the block list at all, so there is no existing
   default view to take parity from — this is the one event kind whose baseline is inferred
   rather than mirrored. The same gap decides whether a `msg/consent`-only chain should ever be
   admitted to the `?state=pending` stream, which §2.5 refuses today (§7). It is not answerable
   here: the missing piece is a consent surface in 012 — the reject/discard transition and the
   block-list write and read routes — and the answer follows from whatever views those define.
   Until 012 defines them the rule has no publisher to exercise it (§2.5), so it is deferred
   with 012 as its owner rather than settled either way here.

## 7. Design notes

**The satisfying key on the read path.** Reporting which key satisfied a signature (§2.4.1) is
required for streams, and the read path exposes it too: the satisfying key is reported on **every**
verified request, not only on a subscribe, so this spec's requirement is a use of an existing result
rather than an extension of it. Nothing outside streams depends on it today — the stream re-check's
rotation test (§2.4.3) is the only consumer, and no read route, record, or other spec reads it. The
counterargument stands as a caution rather than a refusal: a second consumer would make the
satisfying key part of what verification promises, which is 004's contract to widen, not this
spec's.

**Why `?state=pending` requires `msg/read`, and not `msg/consent`.** A reading under which the
pending stream should also admit a chain covering `msg/consent` — on the grounds that a
consent-holder needs pending visibility to act meaningfully — is deliberately not taken. Under
012, `msg/read` authorizes "read messages; list conversations", while `msg/consent` authorizes
"accept a pending conversation; edit the inbox's block list" and confers no listing authority
(012, _Ability vocabulary_). Admitting a `msg/consent`-only chain to the pending _stream_ would
let it observe timing for a view it cannot list, which is exactly the view-parity violation
§2.5 exists to close. Widening it is therefore not a realtime decision at all: the gap, if it is
one, is in 012's ability vocabulary, and closing it belongs to 012. This spec takes the
conservative half and leaves the vocabulary question open (open question 5).

**The satisfying key is a scalar, and that is an assumption with a date on it.** §2.4.1 records
_the_ key that satisfied the request signature, and §2.4.3 re-checks _that_ key against the
subject's current key state. Both are singular because request authentication is singular: the
request-signing profile this route inherits (004) accepts one signature by one key, so "which
key satisfied it" has exactly one answer. It is not a claim that authorization is single-key —
grant chains are already multi-party — only that the request-auth step is. A future
multi-signature request-auth profile (M-of-N signing a request, as 015 does for records) breaks
that: the satisfying party becomes an ordered set of signers, and this spec's scalar must become
one too, with the rotation re-check restated over the set — every satisfying signer still
current, or the stream terminates `rotated`. Whichever profile defines multi-signature request
auth owns that amendment; it is named here so the scalar is read as a consequence of today's
profile rather than as a property of streams.

## 8. History

- 2026-07-28 — Accepted. Resumption, event ids, and `Last-Event-ID`
  dropped for v1; `msg/subscribe` kept as an ability separate from `msg/read`; the 120-second
  ceiling on `recheckInterval` made normative; the nonce store required to be bounded and to
  reject rather than evict; the namespace reservation made a MUST.
- 2026-07-28 — View parity restated per view rather than as one global baseline, which as
  written forbade the spec's own pending and consent rules; the rotation staleness window
  corrected to carry a cached-view term, like revocation; the subscribe request confirmed to
  sign the empty-body `content-digest` like any other GET, so the 004 profile is unchanged.
- 2026-08-01 — Amended by 014: the `message` event keys on the mirrored read view rather than on
  the reserved-type prefix, so the E2EE lane is not left eventless; no event for a blocked
  sender even when the envelope is stored; `msg/keypackage` added to the namespace reservation;
  the reach of the bare `msg` umbrella restated as the vocabulary grew.
- 2026-08-02 — Amended by 014: self-departure pinned to `conversation/self-remove`, outside the
  `msg` namespace, so a bare `msg` grant confers no unilateral self-expulsion authority.
- 2026-08-04 — Nonce TTL corrected to `maxSkewSeconds * 2 + 1`; `maxSkewSeconds * 2` left every
  signature replayable at the last second of its validity. Durations pinned to a monotonic
  clock, freshness inputs required to be validated (with `503` rather than `401` on an unusable
  clock), and a backward wall-clock step recorded as an operator obligation with its residual
  stated — including that the exposure begins at a one-second step and is silent.
- 2026-08-13 — Wire identifiers de-branded to the `pn` prefix (the SSE event name, `PN-Grants`,
  the reserved `pn/` envelope types this spec refers to).
- 2026-08-16 — Close reasons grown from seven to ten: `abilities_insufficient`,
  `audience_not_admitted`, and `subject_drift` name distinctions a client can act on that
  `unverifiable` hid, and `reason` is stated as an open enum clients MUST tolerate unknown
  values in.
- 2026-08-16 — The SSE `retry:` hint dropped from the knobs a node MUST expose and demoted to a
  MAY; reconnect damping rests on the admission gate, the stream budgets, and `429`/`503` with
  `Retry-After`, none of which depend on client cooperation.
- 2026-08-16 — The shared-nonce-store rule given an implementation obligation: a process-local
  nonce store makes single-process serving the conformance condition, and that constraint must
  be stated where an operator reads it.
- 2026-08-16 — The satisfying-key question settled (the satisfying key is reported on every verified
  request, and streams remain its only consumer); the consent-visibility open question deferred with
  012 as owner, and the `consent`-event rule marked unexercisable until 012 defines the
  reject/discard and block-list routes. The scalar satisfying key recorded in Design notes as a
  consequence of the single-signature request-auth profile. ## 9. References
- Spec 003 (current-key resolution), 004 (RFC 9421 request auth, covered components), 008
  (revocation), 009 (grant chains, path-prefix cover, fail-closed caveats), 010 (inbox
  surface, per-inbox `seq`, operator-visible plaintext), 011 (delegated requests,
  `PN-Grants`, `aud`, mandatory `expiresAt` on key-audience links, request-time
  expiry/revocation check, `msg/read`), 012 (conversations — consent states, ability
  vocabulary and its generative rule, "membership is not read authority", one node's view), 014
  (the E2EE lane — amends this spec: the `message`-event rule keys on the mirrored read view,
  no event for a blocked sender, `msg/keypackage` reserved, the `msg` umbrella grows again),
  015 (canonical signature sets — M-of-N over records, the shape a multi-signature request-auth
  profile would follow; see Design notes on the scalar satisfying key)
- WHATWG HTML — Server-Sent Events (`text/event-stream`)
- RFC 9421 — HTTP Message Signatures (the request-signing profile 004 pins)
