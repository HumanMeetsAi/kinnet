# 018 — Claim & Relationship

**Status:** Proposed
**Blocks:** the trust resolver's assertion half — "who vouches for this participant, and how"

## Context

A profile (017) says what a participant asserts about itself, and a Grant (009) says what
authority one participant has delegated to another. Neither answers the question a stranger
actually asks: **does anyone else vouch for this?** An agent's own profile claiming it works
for an organization is worth nothing; the organization saying so, over its own signature, is
worth everything.

Two records carry that. A **Claim** is a signed statement _about_ a participant — a typed
attribute with a value. A **Relationship** is a signed _edge_ between two participants — a
predicate joining a subject to an object. Both are one-hop assertions by an issuer, both are
public, both expire and revoke, and both are checkable offline from bytes by anyone who can
resolve the issuer's key log.

They live in **discovery**, the public half of the split the network is built on: discovery
holds public identity, profile, key, routing, and verification records, while a participant
node holds private data. An assertion nobody can read vouches for nothing, so these records are
published to be read by strangers, unauthenticated, before any relationship exists.

Both ship in the reference implementation, carry committed record-kind vectors, and one of them
— the `represents` edge — is the first link of the trust resolver's headline check. Neither has
ever had an RFC. This spec transcribes the shipped records rather than proposing new ones, per
the process rule in 000.

## Decision

Two records, both signed by an **issuer** making a statement about someone.

### Claim

```
Claim {
  id:         string          // non-empty; chosen by the issuer, unique within the issuer
  subjectId:  ParticipantId   // 002; who the claim is about
  claimType:  string          // non-empty; the issuer's vocabulary, not enumerated here
  value:      unknown         // any I-JSON value (001's number rule applies)
  issuedBy:   ParticipantId   // 002; who asserts and signs
  issuedAt:   string          // RFC 3339, UTC-Z subset (below)
  expiresAt?: string          // RFC 3339, UTC-Z subset; absent = until revoked
  signature:  Signature       // scalar (005)
}
```

### Relationship

```
Relationship {
  id:         string          // non-empty; chosen by the issuer
  subjectId:  ParticipantId   // 002; one end of the edge
  predicate:  string          // non-empty; the edge label
  objectId:   ParticipantId   // 002; the other end
  issuedBy:   ParticipantId   // 002; who asserts and signs
  issuedAt:   string          // RFC 3339, UTC-Z subset (below)
  expiresAt?: string          // RFC 3339, UTC-Z subset; absent = until revoked
  signature:  Signature       // scalar (005)
}
```

An edge reads subject-predicate-object: `subjectId` `represents` `objectId`.

`subjectId` is who the statement is _about_; `issuedBy` is who _asserts_ it. The two are
unrelated by the record schema — a self-issued claim (`subjectId == issuedBy`) and a
third-party claim are the same shape, and the record layer does not privilege either.
Authorization rules that _do_ relate them are stated per use, not per record; the one this spec
defines is under _The represents chain_.

`value` is an arbitrary I-JSON value: string, number, boolean, null, array, or object. 001's
number rule applies to it like any other signed field — no floats, and integers that may exceed
2^53 are encoded as strings.

### Timestamps

`issuedAt` and `expiresAt` are RFC 3339, restricted to the **UTC-`Z` subset**: a numeric offset
is invalid, and so is a local time with no offset at all. `2026-08-01T00:00:00Z` and
`2026-08-01T00:00:00.000Z` are both accepted; `2026-08-01T08:00:00+08:00` is rejected, as is
`2026-08-01T00:00:00.000+00:00`. The restriction is not cosmetic: these records are digested and
revoked by digest, and two offset spellings of one instant are two byte-forms of one logical
record — hence two digests, of which a revocation names only one.

### Non-confusability

Both schemas are **closed**: a record carrying a key the schema does not define is invalid, not
silently stripped. For this pair that is not hygiene, it is the whole guarantee. Open, each
schema stripped what the other defined, so one object carrying the union of the two field sets
parsed as **both** — and since the signing input commits to a record's fields and not to what
kind of record they are (001), one signing act produced two valid records over one signature
and one digest. Closed, `predicate`/`objectId` are unknown keys to the Claim schema and
`claimType`/`value` are unknown keys to the Relationship schema, so the hybrid is rejected by
both.

The enforcement is the committed cross product in
`packages/protocol/test/fixtures/record-kind-vectors.json`, over every record kind this
protocol defines — not this paragraph, and not only this pair.

### Signing, digest identity, and the signature set

One Ed25519 signature over `UTF-8( JCS( record − signature ) )`, encoded multibase base58btc
(001, 005). The `signature` field is the only field removed before canonicalization; every
other field, including `expiresAt` when present, is covered.

The `signature` field is a **scalar**. It is nonetheless a signature set of one member: a
verifier MUST lift it into a one-member set and apply 015 in full, as 015 §Scope requires for
`Claim` and `Relationship` by name.

A record's **digest identity** is 003's digest rule: the multihash of the JCS of the
**complete signed record**, `signature` included. That digest is what a Revocation (008) names,
and it is _not_ the same bytes as the signing input — the signing input omits `signature`, the
digest does not.

### Verifying a statement

Claim and Relationship verify by one procedure, in this order. The order is normative: expiry
is a local comparison and must not cost a key-log replay, and a revocation lookup that cannot be
completed must never read as "not revoked".

1. **Shape.** The record validates against its own closed schema.
   Reasons: `claim_malformed`, `relationship_malformed`.
2. **Expiry.** If `expiresAt` is present and is at or before the verification instant, the
   record is expired. The comparison is inclusive: a record expires _at_ its `expiresAt`, not
   after it. An absent `expiresAt` never expires.
   Reasons: `claim_expired`, `relationship_expired`.
3. **Issuer key states.** Resolve `issuedBy`'s key log (003) and replay it. The log MUST be
   bound to `issuedBy` — a replay-valid log for a different participant is a mismatch, not a
   pass. The result is **every key state the log ever committed**, most-recent first.
   Reasons: `issuer_key_log_unresolved`, `issuer_key_log_participant_mismatch`,
   `issuer_key_log_too_expensive`.
4. **Signature.** Lift the scalar into a one-member set and check it as a canonical signature
   set (015) against each resolved state at that state's threshold. A record is valid if it
   verifies under **any** state the log ever committed (015 S5), so a rotation does not orphan
   already-issued statements.
   Reasons: `claim_signature_invalid`, `relationship_signature_invalid`.
5. **Revocation.** Compute the record's digest and look it up against `issuedBy` as the
   authorized revoker (008). A candidate revocation returned by the lookup is itself
   re-validated — shape, that it names this digest, that its issuer was among those asked, and
   that it satisfies its own issuer's threshold — before it is believed. A lookup that exceeds
   the verifier's budget is an error, never an absence.
   Reasons: `claim_revoked`, `relationship_revoked`.

Only `issuedBy` may revoke a statement. The subject of a statement cannot withdraw it; 008
records subject renunciation as an open question and this spec inherits it rather than
answering it.

### Vocabulary: exactly one reserved predicate

`claimType` and `predicate` are non-empty strings and the protocol enumerates neither. Both are
issuer vocabulary, on the pattern 009 sets for ability strings: the protocol fixes the record
and the check, not the words.

**One predicate is reserved: `represents`.** It is reserved because a verifier acts on it — it
is the one predicate with a normative meaning and a normative authorization rule (below). A
conforming implementation MUST NOT assign `represents` any other meaning, and MUST NOT treat
any other string as equivalent to it: matching is exact byte equality over the field, with no
case folding, no trimming, and no path-prefix cover. 009's segment-boundary cover rule is about
abilities and does not reach predicates.

No `claimType` is reserved. No claim participates in any authorization decision the protocol
defines today; see _Open questions_.

### The represents chain

"This agent represents Acme" is the check the whole trust layer exists to answer, and it is the
one place a Relationship carries normative weight. A represents verification takes an agent id,
an organization id, the edge, and — optionally — a bounding Grant chain (009, 011).

It succeeds only if all of the following hold:

1. The **agent's key log resolves** and is bound to the agent id. This is an existence and
   binding check on the agent; the agent's keys sign nothing here.
   Reasons: `agent_key_log_unresolved`, `agent_key_log_participant_mismatch`,
   `agent_key_log_too_expensive`.
2. `edge.predicate` is exactly `represents` — `edge_predicate_mismatch`.
3. `edge.subjectId` is the agent — `edge_subject_mismatch`.
4. `edge.objectId` is the organization — `edge_object_mismatch`.
5. **`edge.issuedBy` is the organization** — `edge_not_issued_by_represented`. Only the
   represented party may assert representation. Without this rule an agent self-issues its way
   into representing anyone, and the edge means nothing.
6. The edge verifies as a statement, by the five steps above.
7. If a Grant chain is supplied, it verifies per 009 and 011, its `subjectId` is the
   organization — `grant_subject_not_organization` — and its leaf `audienceId` is the agent —
   `grant_audience_not_agent`.

The edge contributes exactly one bit: an organization-signed, unexpired, unrevoked assertion of
that one tuple. It carries **no abilities**. Abilities come only from the Grant chain, and a
verification without one answers "does this agent represent the organization", never "what may
it do".

A represents verification is **one hop and non-recursive**. Edges do not chain: there is no
transitive closure, no path search, and therefore no relationship depth bound. The only depth
bound in the check belongs to the Grant half — `MAX_GRANT_CHAIN_LINKS`, 4 (009).

Rule 5 is also what makes the read safe. A relying party that needs representation performs a
**point lookup on the decision tuple** `(issuedBy, subjectId, objectId, predicate)` — fully
determined, because the issuer and the object are both the required organization and the
subject is the agent — rather than scanning everything published about the agent. Both
statement collections are attacker-growable (below), so a scan is a surface an attacker can
flood; a point lookup on a key nobody else can write is not.

### Who may write them

Both are **issuer records**: a statement is written by the participant that asserts it.
Discovery writes are authorized per 004 — an RFC 9421 signature over the request, verified
against the writer's current key state. On top of that, a conforming discovery service MUST
refuse a write unless:

- `issuedBy` equals the authenticated writer's participant id, and
- the record's own `signature`, lifted to a one-member set per 015 §Scope and checked at that
  key state's **threshold**, verifies against that state.

Both records therefore carry 004's two independent signatures in full: the request signature
authorizes the write action, and the record signature authenticates the content and is what
re-verifies forever afterwards.

The check is made against **the same key state that authenticated the request**, so "the issuer
signed this" and "the issuer is authorized to write it" are one statement about one key set
rather than two lookups that happen to agree.

The scalar signature is lifted and decided at the state's threshold, like every other record
here. Asking instead whether the signature verifies against _any_ key the current state lists,
without comparing the one-member set against the threshold, is a different check — the same
question for a threshold-1 issuer, and not the same question for any other. Under it a
threshold-2 issuer's statement is accepted at write and stored, and then rejected by every
conforming resolver forever afterwards under 015's `m = t`, because a one-member set cannot
satisfy a threshold of 2: durable, published, unrevokable in any useful sense, and unverifiable
by anyone, with no error anywhere on the path that produced it. A discovery service is the one
participant that must not read the signature rule differently from the readers it publishes to.

`subjectId` and `objectId` are **unconstrained**. Any participant may publish a claim about any
participant, and an edge naming any two. That is deliberate — a third-party assertion is the
entire point of the record, and requiring the subject's consent would make an organization
unable to state facts about an agent that has gone silent. The consequence is that the set of
statements naming a given participant is a set an attacker can grow, and no reader may treat
"something was published about X" as meaning anything on its own. What means something is a
statement on a key the reader chose, by an issuer the reader trusts.

Refusals a conforming discovery service emits:
`invalid_claim` / `invalid_relationship` (400, schema rejection); `claim_id_mismatch` /
`relationship_id_mismatch` (400, the record does not match the path it was written to);
`invalid_query` (400, a filtered read carries a partial decision tuple); `invalid_cursor` (400,
a paged read carries a cursor this service did not issue); `claim_signature_invalid` /
`relationship_signature_invalid` (422, the record signature does not verify against the
issuer's current key state); `unauthorized_write` (401, 004 verification failed);
`key_log_too_expensive` (413) and `temporarily_unavailable` (503), which 017 describes and which
are shared by every authenticated discovery write.

### Where these records live

| Route                                                            | Effect                                            |
| ---------------------------------------------------------------- | ------------------------------------------------- |
| `GET /participants/:id/claims`                                   | Claims whose **subject** is `:id`, paged          |
| `PUT /participants/:id/claims/:claimId`                          | Publish a claim; `:id` is the **issuer**          |
| `GET /participants/:id/relationships?issuer=&object=&predicate=` | The one edge on that decision tuple, or none      |
| `GET /participants/:id/relationships`                            | Edges whose subject **or** object is `:id`, paged |
| `PUT /participants/:id/relationships/:relationshipId`            | Publish an edge; `:id` is the **issuer**          |

The read and write paths are asymmetric on purpose: a statement is written under its issuer and
read under its subject, because the reader knows who it is asking about and rarely knows in
advance who spoke.

A **Claim is keyed by `(issuedBy, id)`** — the issuer's own chosen `id`, scoped by the issuer,
so two issuers may use the same `id` for unrelated claims.

A **Relationship's `id` is not its identity.** An edge is keyed by the decision tuple
`(issuedBy, subjectId, objectId, predicate)`: an issuer holds at most one edge per tuple, and
republishing that tuple under a different `id` replaces the existing edge rather than adding a
second. That is what makes the point lookup in _The represents chain_ a single-answer read.

The targeted relationship read requires **all three** of `issuer`, `object`, and `predicate` or
**none** of them; a partial tuple is refused with `invalid_query` (400) rather than silently
widened into a scan.

Neither expiry nor revocation is applied at the discovery surface: an expired or revoked
statement is stored and served exactly like a live one, and both checks happen where they
belong — in the resolver, against the reader's own clock and the reader's own choice of
authorized revokers. Discovery is a directory, not a verifier.

## Boundaries

- **Claim vocabularies are not protocol.** Beyond the one reserved predicate, `claimType` and
  `predicate` strings, their value shapes, and their semantics belong to whoever issues and
  consumes them. A registry earns a place in the protocol when two independent implementations
  must agree on a string to interoperate, and `represents` is currently the only one that does.
- **Reputation is not protocol.** Scoring, aggregating, weighting, or ranking issuers over a
  pile of claims is a trust-layer product built _on_ these records. The protocol fixes what a
  single statement is and how it verifies; what a body of statements is worth is policy.
- **Enforcement is the relying party's job.** A verified claim is a verified assertion, not a
  permission. Whether to act on it — and how much an issuer's word is worth — is the resource
  holder's decision, exactly as 009 says for abilities (000 #3, mechanism not policy).
- **Relationship vs Grant.** A Relationship is a public, discoverable, one-hop _assertion_ that
  a stranger can check from discovery alone. A Grant (009) is transferable, attenuable
  _authority_, possibly multi-hop, presented at request time and not required to be public.
  They compose — the represents chain uses an edge to establish the affiliation and a chain to
  bound the authority — and neither substitutes for the other: an edge grants nothing, and a
  chain vouches for nothing.
- **Domain and organization verification procedures are not protocol.** How an issuer
  establishes that a subject controls a domain before issuing a claim about it is the issuer's
  method, and a reader's willingness to believe it is a judgement about the issuer.
- **Freshness is not protocol here.** "Not revoked" is as fresh as the query, and a superseded
  edge remains independently valid until it expires or is revoked. 008 carries the open
  question; nothing here adds a mechanism.

## Non-goals

- **Multi-hop and transitive relationships.** Edges do not compose into paths. "A represents B,
  B represents C" implies nothing about A and C, and no verifier walks it.
- **Subject countersignature.** A statement carries one signature, the issuer's. A protocol for
  the subject to accept or disavow one is not defined; a relying party that wants mutual
  assent requires two statements and checks both.
- **Selective disclosure and zero-knowledge presentation.** Statements are public records in
  full. A verifiable-credential projection of a Claim is derivable from these bytes and is
  therefore not a primitive (000 #4).
- **Typed claim schemas.** `value` is `unknown` and stays that way. Constraining it per
  `claimType` is a job for whoever defines the type.
- **Private statements.** Both records are public by construction. An assertion that must stay
  private is not a discovery record.

## Open questions

- **Threshold-1 issuance, and the silent write that hides it.** A scalar signature is a
  one-member set, and 015's `m = t` means a one-member set satisfies only a threshold of 1. A
  participant whose current key state declares a threshold above 1 therefore cannot issue a
  valid Claim or Relationship — including the `represents` edge the represents chain requires.
  Organizations are exactly the participants most likely to hold an M-of-N state and most likely
  to need to issue edges, so this is the sharpest edge of the scalar form. The write check is
  threshold-aware, so the failure is loud at publication rather than silent, but that does not
  make the record issuable: such an issuer is refused at write, consistently with every resolver
  that would refuse it later, instead of being told the statement was published. What remains
  open is the
  substance — whether these records grow an array `signature` like the signature-set records, or
  stay scalar deliberately and M-of-N issuers are expected to state things some other way.
  Nothing in 004's threshold-1 restriction on request signing makes the question moot, because
  that restriction is stated as a version limit to be lifted.
- **No lower bound on `issuedAt`.** A statement dated in the future verifies today: only
  `expiresAt` is compared against the clock. Grants acquired a not-yet-issued check for exactly
  this hazard when they are evaluated as records; statements never did. Whether to add one, and
  what skew allowance it needs, is open.
- **Predicate and claimType normalization.** Nothing namespaces, normalizes, or reserves a
  prefix for either field, so `Represents`, `represents ` with a trailing space, and
  `represents/all` are three distinct strings none of which is the reserved predicate — a
  correctness property that currently rests on every issuer spelling it exactly. Every other
  reserved wire token in the protocol lives behind a prefix and a registry; predicates have
  neither. Whether they should is open.
- **`id` is issuer-chosen, not a digest.** Every other digest-identified record in the protocol
  derives its identity from its bytes; these two carry a free-form `id` that is a storage key
  for a Claim and decoration for a Relationship, while revocation names the digest. An issuer
  republishing the same `id` with different bytes leaves the previous bytes independently valid
  and separately revocable, and a reader holding the old copy cannot tell it was superseded.
- **Claim relocation by overwrite.** Because a Claim is keyed by `(issuedBy, id)` and its
  `subjectId` is part of the stored record rather than the key, an issuer republishing an
  existing `id` about a **different** subject moves it: the original subject's listing silently
  loses the claim, with no revocation and no trace. Whether the subject should be part of the
  key, or whether relocation should be refused, is open.
- **Claims have no targeted read and no consumer.** There is no point lookup for
  "did issuer X claim type Y about subject Z" — only the paged, attacker-growable listing by
  subject — and no verifier in the protocol reads a claim during a decision. Until a claim
  participates in an authorization decision, the record is publish-and-store, and the read
  surface it would need has not been designed.
- **Unbounded fields.** `claimType`, `predicate`, `id`, and `value` carry no length or size
  bound. The protocol bounds the arrays that a hostile caller can make expensive to _verify_ —
  key lists, signature sets, grant chains, conversation membership (003, 009, 012), each with a
  named constant and a derivation — but bounding is not uniform: `ParticipantProfile`'s
  `capabilities` and `verifiedDomains`, `ParticipantNode`'s `transports` (017), and
  `ConversationUpdate`'s `members` and `leaves` (014) are unbounded arrays reachable from a
  request body, and these fields are unbounded strings and an unbounded value. Whether the rule
  should be "everything reachable from a body is bounded" or "everything whose length multiplies
  verification cost is bounded" is itself unsettled, and settling it — then choosing the numbers
  — has to happen before the wire-freeze.

## Design notes

- **Why two records and not one typed record.** A Claim's `value` is an attribute and a
  Relationship's `objectId` is a participant, and collapsing them would mean either a Claim
  whose value is sometimes an id that a verifier must know to resolve, or a Relationship with
  an object that is sometimes not a participant. Keeping the participant-to-participant edge
  distinct is what lets the represents check be a tuple lookup with typed ends instead of a
  scan with a value comparison.
- **Why the issuer, and only the issuer, may revoke.** Revocation authority follows issuance
  authority: the party whose signature made the statement is the party whose signature can
  withdraw it, checked against its **current** key state so the authority survives rotation and
  works after a compromise rotation (008). Letting a subject revoke would let a subject erase
  an unwelcome true statement, which is the opposite of what a vouching record is for.
- **Why a scalar signature.** Both records predate the signature-set form, and both are
  single-issuer assertions rather than committee acts. Under 015 a scalar signature is exactly a
  1-of-1 set, so nothing is outside the rule; only the encoding differs. The cost is the
  threshold-1 limit above, and it is stated as an open question rather than defended.
- **Why `represents` is reserved and nothing else is.** A reserved word is a promise that two
  independent implementations agree on its meaning, and that promise costs something to keep.
  It is worth paying where a verifier acts on the string — the represents check is a security
  decision — and not worth paying for vocabulary that only humans read. Growing the reserved
  set is a spec change, which is the right friction for it (000 #6, driven by running code).
- **Why the represents check resolves the agent's log without using the agent's keys.** The
  edge is the organization's statement, so the organization's signature is the only one that
  could be there. Resolving the agent's log still buys something: it establishes that the
  subject is a real participant with a replay-valid history rather than an id nobody ever
  minted, which is the difference between "Acme vouches for this agent" and "Acme vouches for a
  string".
- **Why the edge carries no abilities.** Affiliation and authority are separate questions with
  separate lifetimes: an agent can represent an organization for years while the set of things
  it may do changes weekly. Merging them would make every scope change an edge rewrite, and
  would put attenuation semantics into a record with no chain to attenuate along.

## History

- 2026-06-06 — `Claim` and `Relationship` first shipped in `@kinnet/protocol`.
- 2026-08-13 — both schemas closed. Open, an object carrying the union of the two field sets
  validated as both records over one signature and one digest; closing them is what makes the
  pair non-confusable (001).
- 2026-08-16 — this RFC written, transcribing the shipped records.
- 2026-08-16 — the write-side record-signature check made threshold-aware: the scalar signature
  is lifted to a one-member set and decided at the issuer's threshold (015 `m = t`), against the
  key state that authenticated the request. An M-of-N issuer is now refused at write rather than
  told a statement no resolver will accept was published.

## References

- Spec 001 (canonical serialization; record kinds are non-confusable), 002 (participant ids),
  003 (key-state resolution and the digest rule), 004 (discovery write authorization), 005
  (signature suite), 008 (revocation by digest; subject renunciation), 009 (Grant — authority,
  and the assertion/delegation boundary), 011 (bare-key principals in a bounding chain), 015
  (canonical signature sets — the one-member lift and `m = t`), 017 (participant profile and
  node — the self-asserted form of what these records make checkable)
- RFC 3339 — timestamps; RFC 8785 — JCS; RFC 7493 — I-JSON
- Conformance vectors: `packages/protocol/test/fixtures/record-kind-vectors.json` (one
  shape-valid instance of each record kind, checked against every other kind's schema over the
  full cross product). The Claim/Relationship hybrid is not a committed vector: the test
  constructs it by merging the fixture Claim and the fixture Relationship, and asserts both
  schemas reject the result.
- Signed byte-level fixture: `packages/trust/test/fixtures/represents-chain.json` (a
  `represents` edge signed under a pre-rotation key state, a Claim, and the Revocation that
  withdraws it, replayed by the resolver suite)
