# 016 — Record anchoring

**Status:** Accepted
**Blocks:** 015's uniqueness guarantee, extended across key states; the retirement of 003's
interim quorum rule; the M-of-N rotation flexibility 003 gave up to close routes 3 and 4
**Amends:** 003, 005, 008, 009, 011, 012, 014, 015

## Context

015 settled how a signature set is checked **given** a key state, and proved a uniqueness
property from it: for a fixed record content, a fixed accepting key state and a fixed set of
signature values, the conforming record — and therefore its digest — is unique. The hedge in
that sentence is the whole of this spec's subject. S5 composes the per-state rules with an
existential over **any** state the issuer's log ever committed, and that existential re-opens
across states what `m = t` closed within one: routes 3 and 4 under 015's _What this guarantees_
are keyless edits — delete a member, permute two — that fail against the state the record was
signed under and conform against a different state of the same log. The same existential is the
`E` factor in verification cost: a record check runs the S3 walk once per committed state, up to
`MAX_KEY_LOG_EVENTS` times. The correctness hole and the cost factor are one fact wearing two
hats.

003 adopted the intersection rule as the interim closure. It works — a log that would enable
routes 3 or 4 is invalid, so no conforming log commits two states an edit can move between — but
it closes them **conditionally**: on a cryptographic assumption (that a signature verifies under
exactly one key, which holds only under the verification mode 005 pins) and on every verifier
enforcing a log-shape rule that travels nowhere near the record it protects. It also buys the
closure with rotation flexibility: two states may not share a quorum, so a 2-of-3 may retain at
most one key across a rotation. 015 evaluated four options against that and decided option (a),
an explicit anchor naming the key event that established the accepting state, on exactly four
record types, leaving the mechanism to this spec. This spec specifies that mechanism: the field
and its value, its placement on each record type and the general rule that governs later ones,
the verification rule that replaces S5's existential, mode discrimination for the two-mode
records, producer and freshness rules, the retirement of the interim, and the migration. It does
**not** re-open the choice of option, the digest rule, the signing input, or the suite.

## Decision

### The anchor field

A record anchored under this spec carries one new field:

```
anchor: Multihash    // the 003 digest of one KeyEvent of the issuer's key log
```

The value is the multihash of the JCS of the **complete signed key event**, signatures included
— 003's digest rule for events, and the same value that event's successor carries in `prior`. It
is encoded exactly as `prior` (003), `proof` (009) and `revokes` (008) are, and is subject to
005's _Canonical encodings — one value, one text_ like every other encoded string in a signed
record.

**The state an anchor names is the state the named event carries** — its `keys` and its
`threshold`, together. For a rotation those are the values the previous event committed, since
replay has already established that they reproduce `next`; for an inception they are the
self-declared values the participant ID hashes. 003's _Resolving the current key_ fixes that
correspondence, and this spec adds nothing to it: there is one candidate state per event, so
naming an event names a state without ambiguity.

Nothing is minted (000 #5). The anchor composes an existing primitive — a key-event digest,
already defined and already used for chaining — into a new position.

### Placement

| Record                                     | `anchor`                                                |
| ------------------------------------------ | ------------------------------------------------------- |
| `Revocation` (008)                         | **required** — the issuer is always a participant (011) |
| `Grant`, participant issuer (009)          | **required**                                            |
| `Grant`, bare-key issuer (011)             | **MUST be absent** — self-certifying against `issuerId` |
| `Conversation` (012)                       | present **iff** owner mode; absent iff delegated mode   |
| `ConversationUpdate` (014)                 | present **iff** owner mode; absent iff delegated mode   |
| `KeyEvent` (003)                           | **no field** — self-anchored by `prior` and `seq`       |
| Scalar-`signature` records (010, 017, 018) | **no field in this spec** — see the general rule below  |

The `Grant` rule is a cross-field rule, enforceable from the record alone: `anchor` is REQUIRED
iff `issuerId` is a `ParticipantId`, and MUST be absent iff `issuerId` is a `KeyRef`. The two
principal shapes are disjoint by construction (011), so a validator decides the branch without
resolving anything.

**The general rule, stated normatively because later specs inherit it:**

> **Every record whose signature set is verified against a participant's key state carries an
> anchor naming that state's key event.** A record verified against a single constructive key —
> a bare key, a chain leaf, or a key event's own committed state — carries none.

The four record types above are the ones the rule reaches today. A later spec that turns a
scalar-`signature` record into a signature-set record verified against a participant's key state
MUST give it this field under this rule, rather than restating the requirement or minting a
second mechanism. Scalar-signature records are outside the rule today for the reason given under
_Boundaries_, not by exemption.

The four shapes as they now stand, unchanged fields elided:

```
Revocation {
  revokes:   string             // 008
  issuerId:  ParticipantId      // 008
  anchor:    Multihash          // 016: the key event whose state signs this record
  revokedAt: string             // 008
  reason?:   string             // 008
  signature: Signature[]        // exactly the anchored state's threshold (015)
}

Grant {
  …                             // 009, 011 — subjectId, issuerId, audienceId, abilities,
                                //   caveats, proof, issuedAt, expiresAt
  anchor?:   Multihash          // 016: required iff issuerId is a ParticipantId,
                                //   absent iff issuerId is a KeyRef
  signature: Signature[]
}

Conversation {
  …                             // 012, 014 — creator, participants, createdAt, title,
                                //   lane, groupNonce
  anchor?:   Multihash          // 016: present iff owner mode
  signature: Signature[]
}

ConversationUpdate {
  …                             // 014 — conversationId, kind, members, leaves, actor,
                                //   epoch, createdAt
  anchor?:   Multihash          // 016: present iff owner mode
  signature: Signature[]
}
```

Every one of these schemas stays **closed** (001, 015 S6): the field is added to the schema, so a
record carrying it is not a record carrying an unknown key, and a record of these four types
lacking it where the table requires it is invalid.

### Verification — the lookup that replaces 015 S5

A record carrying `anchor` is **validly signed by its issuer** iff all three of the following
hold:

1. the issuer's key log replays valid per 003;
2. that log contains an event whose digest equals `anchor`;
3. the record's signature set satisfies 015 S0–S3 against the key state that event carries.

**No other state is tried.** A verifier MUST NOT accept a record against a state its anchor does
not name, even where that state would satisfy S0–S3. A record whose anchor names no event of the
issuer's log is **invalid**, and a verifier MUST report that outcome distinguishably from a
signature-set failure — the two call for different responses (_Log freshness_ below), and
collapsing them turns a stale cache into a permanent rejection.

The event MUST belong to **the issuer's own** log. The issuer is fixed by the record — `issuerId`
for a `Revocation` or `Grant`, `creator` for a `Conversation`, `actor` for a `ConversationUpdate`
— so an event of any other participant's log is an unknown anchor whatever its digest, and no
verifier resolves a second log to decide a record's signature.

Records that carry **no** `anchor` field verify against their single constructive state, exactly
as before this spec:

- a bare-key `Grant` issuer (011) against the key named by `issuerId`, `n = 1`, `t = 1`, `m = 1`;
- a delegated-mode `Conversation` or `ConversationUpdate` (012, 014) against its chain's leaf key,
  with the single-signature rule 014 pins;
- a `KeyEvent` against the state 003 fixes for it (_The committed next key state_).

015 S4 is unchanged and now applies with the anchor **inside** the digested bytes: the signature
set MUST be checked before the record's digest is used as an identity, a chain pointer, or a
revocation key. Because the anchor is inside the signing input, it is covered by every member of
the set — rewriting it to name another state invalidates the record rather than moving it. 015 S6
is likewise unchanged: one delivered byte string, one record.

### Owner and delegated mode declare themselves

For `Conversation` and `ConversationUpdate` travelling as a `(record, chain)` unit (014):

> **`record.anchor` is present if and only if the unit's `chain` is absent.**

A unit carrying **both**, or **neither**, is invalid (`mode_conflict`). The record therefore
declares its own mode, and a verifier knows the mode — and, in owner mode, the key state — before
it verifies anything.

This replaces 014's rule that `chain` MUST be present whenever owner-mode verification of
`record` fails. That rule made the mode a residue of a failed verification and legislated an
evaluation order around it; the structural rule needs neither. 014's other unit rules are
unchanged: a unit carrying a chain that does not verify is invalid even where the record would
owner-verify; a present `chain` is non-empty; a delegated-signed record carries exactly one
signature; digest identity is over `record` alone, so a unit's id does not depend on whether a
chain accompanies it.

### Producer rules

- A producer **SHOULD** anchor to the **tip** of its own log at the moment of signing — the state
  it currently holds.
- A producer **MAY** anchor to any earlier committed state whose keys it still holds. A verifier
  cannot distinguish the two cases and does not need to: it applies the same lookup either way.
- A producer signing under a state of threshold `t` **MUST** carry exactly `t` signatures, in that
  state's key order (015 S1–S3).

A producer that anchors to a state it cannot satisfy produces a record that fails verification.
Nothing else follows from it: the anchor selects the state a record is judged against, and
selecting one the producer does not hold is a self-inflicted rejection, not an attack.

### Log freshness

The anchor tells a verifier whether its cached view of the issuer's log is sufficient:

- If the anchored event lies in the verifier's cached **replay-valid prefix**, the signature
  verdict is **final**. A later rotation cannot change it, because the log is append-only and the
  named event stays where it is. This is why anchoring does not orphan records: an anchor names a
  historical state, never the current one.
- If it does not, the verifier **SHOULD** refetch the log once before concluding.

What an unknown anchor means after that refetch depends on the path:

- On 014's member-side unit profile it is a **WAIT, never a rejection** — the same rule, for the
  same reason, as an unresolvable evidence signature there: key logs are monotone, so an honest
  member's verdict converges, and rejecting on a cache miss would split the group.
- On request-time paths — node delivery, discovery writes, and standalone verifiers — it is a
  **rejection**, reported with the unknown-anchor reason above.

### Retiring the interim

**003's _No two states may share a quorum_ is removed.** A replay MUST NOT reject a log on the
ground that two of its committed states share a quorum, and a log previously rejected on that
ground is valid. A 2-of-3 may again retire one key and retain two; a state may re-reveal an
earlier key set; a `1-of-n` log is no longer refused for sharing its single key across a rotation.

The rule protected one thing: that a keyless edit of a record signed against state A could not
land in state B. After this spec no record is judged against two states — a record carries an
anchor or has exactly one constructive state — so there is no second state for an edit to land in
and the rule protects nothing. It was never free: it cost rotation flexibility precisely where
M-of-N needs it, it rested on a cryptographic assumption rather than a structural property, and
it bound only verifiers that check log shape as well as signatures. Anchoring needs no such
assumption under any verification mode, and travels inside the record it protects.

005's pinned verification mode — strict RFC 8032 plus low-order public-key rejection — **remains
required**, and this spec relaxes nothing about it. What ends is only its second role: it is a
prerequisite for **determinism** (015 _Terms_), not for the soundness of a rule that no longer
exists.

### Cost

A record check costs the issuer's log **replay**, bounded by 003's _Size limits_ at
`MAX_KEY_LOG_EVENTS × MAX_KEY_EVENT_KEYS` — work a verifier performs anyway to resolve the issuer
— plus, for the record itself, **at most `K = MAX_KEY_EVENT_KEYS` verifications**: one run of
015's S3 walk against one state. That is 8 at the schema maxima, against the 1024 015's `E · K`
allows and the 8192 of the search that preceded it. The `E` factor is gone, not reduced: the
lookup is by digest, and exactly one state is tried.

A verifier's concrete budget MUST be **re-derived** from this shape rather than copied from the
arithmetic here or carried over from a budget sized on `E · K` per candidate record. Chain
verification (009) still performs several checks per link, and a grant chain remains
attacker-influenced work, so caller budgets remain necessary even though the per-record cost is
now linear in one key list.

### Consequential amendments

These amendments to other specs take effect when this spec is implemented.

- **003** — _No two states may share a quorum_ is **removed**; its section states the removal and
  why, so cross-references still resolve. _Resolving the current key_ drops "and that no two
  committed states share a quorum" from the replay steps, and its statement that records verify
  against any state the log ever committed becomes: records verify against the state their anchor
  names. _Design notes_' account of what the pinned verification mode rejects loses its
  dependency on the removed rule and keeps the mode as a determinism requirement (005, 015).
- **005** — the _Why this is normative_ paragraph no longer names the pin a prerequisite for
  003's quorum rule; the pin's remaining basis is determinism, and the small-order construction
  is unchanged and still normative.
- **008** — `Revocation` gains a required `anchor`. "Verified against its **current** key set"
  becomes "verified against the state its anchor names"; revocation authority still survives
  rotation, because an issuer anchors to whatever state it currently holds. The _Sign-time
  anchoring_ open question is reworded: this spec anchors a record to a key **state** and narrows
  the window — a forgery must name a state whose keys the attacker holds — without closing
  signing into the past.
- **009** — `Grant` gains `anchor`, required iff `issuerId` is a `ParticipantId`. Chain rule 1's
  participant branch resolves the issuer's log **at the state the link's anchor names**. _Size
  limits_' cost paragraph keeps its bounds, with a pointer that the per-link search over the
  issuer's entire key history collapses to at most `MAX_KEY_EVENT_KEYS` verifications beyond the
  replay.
- **011** — a bare-key issuer takes **no** anchor: its signature is self-certifying against the
  key `issuerId` names, which is one state by construction. The self-issued enrollment grant is
  valid at the state **its anchor names** rather than at any state the subject's log has held; the
  conclusion is unchanged — a compromised retired root key is answered by revocation (008), not by
  rotation.
- **012** — `Conversation` gains `anchor`, present iff owner mode. _Signing a Conversation_ becomes
  two modes and **one named key state**: owner mode is anchor-present and verifies against the
  anchored state; the any-state paragraph is replaced by the anchored state plus the
  non-orphaning guarantee it preserves. The delivery rule for `pn/conversation` follows. Every
  conversation record is re-signed under this spec, so every conversation **id** moves.
- **014** — `ConversationUpdate` gains `anchor`, present iff owner mode. The unit profile's owner
  mode becomes "`anchor` present, `chain` absent" and verifies against the state the anchor names
  rather than any replay-valid state; delegated mode becomes "`anchor` absent, `chain` present";
  the chain-presence rule is replaced by the structural rule above (`mode_conflict`). Rule 2's
  participant-issued links resolve at the state **each link's** anchor names. The wait-not-reject
  rule extends to an unknown anchor. §"Custody"'s residual — that rotation and custody exit do not
  retroactively kill minted credentials — holds against the anchored state, with the same
  conclusion. The `group_id` derivation rule is unchanged, but the ids it derives from move with
  the conversation ids.
- **015** — S5's existential is replaced by this spec's lookup, and the section is retitled
  accordingly. Routes 3 and 4 under _What this guarantees_ are closed **structurally**, not merely
  in practice. _Anchoring_ keeps its options analysis as the rationale and points here for the
  mechanism; _Key events anchor themselves_, _Re-issuance under anchoring_ and _This deserves its
  own spec_ condense to pointers. _Terms_ drops the intersection-rule clause. _Cost_ takes
  `E = 1`.

### Migration and impact

**Stage 0 (000), no dual-accept phase.** One release moves the schemas, the verifiers and the
producers together. From that release an unanchored `Revocation`, an unanchored participant-issued
`Grant`, and an owner-mode `Conversation` or `ConversationUpdate` without an anchor are **invalid**
everywhere; there is no window in which both shapes verify, because a window in which an
unanchored record is accepted is a window in which routes 3 and 4 are open.

What must be re-issued, because the field sits inside the signed bytes and there is no in-place
repair:

- every stored `Revocation`, **re-signed by its original issuer**;
- every participant-issued `Grant`; a chain is re-issued **root-down**, since each child names its
  parent by digest and every parent's digest moves;
- every owner-mode `Conversation` and `ConversationUpdate`. **Conversation ids move**, and with
  them the MLS `group_id`s derived from them (014). This is the heaviest consequence: it is a
  migration of live conversation state, not a paperwork exercise.

What does **not** change: key logs and every `KeyEvent` in them; participant identifiers (002
hashes inception establishment data, which is untouched); scalar-`signature` records; request
signing (004 authenticates against the current key state and carries no anchor); the digest rule;
the signing input (001); and the signature suite (005). Identity survives the migration intact,
which is what makes it a migration rather than a restart.

The interim's removal cuts the other way and is free: logs previously rejected for sharing a
quorum become valid, and **nothing that was already valid becomes invalid** by that change alone.

## Threat model

**What anchoring closes.** 015's routes 3 and 4, and variants G and P under _Why the narrow forms
of (d) do not work_ — the keyless cross-state edits, in which an attacker holding no private key
deletes or permutes members of a signed record so that it conforms against a different state of
the issuer's log. Every one of them needs two states in play for one record. With exactly one
state named, and the name itself covered by every signature, there is no second state for an edit
to land in. The closure is **structural**: it does not depend on the verifier also checking log
shape, and it does not depend on the assumption that a signature verifies under exactly one key.

**What it narrows but does not close.** 008's _signing into the past_: a stolen key can still
sign records until its forgeries are revoked, and it can name the state it belongs to. Anchoring
raises the bar — a forgery must name a state whose keys the attacker actually holds, so a key
compromised today cannot mint records that appear to have been signed under a state it never had
— but a compromised retired state still requires revocation by digest, and rotation alone does not
withdraw what was signed under it.

**What it does not address.** 015's residual routes 1 and 2 — the signers' choice of which `t` of
`n` keys sign, and Ed25519's non-uniqueness of signature per (key, message) — both of which
require the private keys and neither of which any counting, ordering or anchoring rule can remove.
Nor key-log resolution: every guarantee here is evaluated against the log the verifier resolved
for the issuer; that the log is the issuer's is 002's and 003's binding (the identifier hashes the
inception event, and a replay is judged for a named participant), which this spec relies on and
does not restate. Nor 008's freshness question: "not revoked" is still as fresh as the registry queried.

## Boundaries and non-goals

- **Not sign-time or timestamp anchoring.** An anchor names a **state**, not a moment. Option (b)
  in 015 — deriving the state from a record's timestamp — was rejected there and is not revisited:
  `KeyEvent` has no timestamp, and a producer-set instant is the wrong shape for an input that
  selects the verifying key state.
- **Not witnessing or duplicity detection.** 003 defers those, and this spec depends on neither:
  the anchor is a digest **precisely because** `seq` is unambiguous only within one replay-valid
  log, and two forks could carry different events at the same `seq`.
- **Not a `proof` object, and not record-kind domain separation.** Both remain 001's open
  questions. The anchor is a bare digest field in the record, like `prior` and `proof`.
- **Not an extension to scalar-signature records.** A scalar signature is a one-member set with no
  keyless edit available — nothing to delete, nothing to reorder — so it carries no malleability of
  the kind this spec closes, and `MessageEnvelope` verification (010) runs after request
  authentication. The general rule above reaches those records if and when they become
  signature-set records verified against a key state.

## Open questions

- **Revocation monotonicity.** Anchoring makes a rule expressible that could not be stated before:
  _a `Revocation` MUST NOT be anchored earlier than the record it revokes, where both are anchored
  in the same log_ — which would stop the holder of a retired state's keys revoking records the
  participant issued after rotating away. It is partial: a revoker upstream in a grant chain (009)
  anchors in a different log, and a revoked record may be scalar-signed and carry no anchor at all.
  It changes 008's semantics and deserves its own attack analysis; it is 008's to decide.
- **State-scoped revocation.** Likewise newly expressible — "everything anchored to state _k_",
  which is the shape a compromise-and-rotate response wants, against the per-digest revocations it
  needs today. Also 008's.
- **Whether `MessageEnvelope` owner mode should anchor for cost alone.** It has no malleability to
  close, and its verification runs after request authentication, so the case would be the `E`
  factor on a hot path and nothing else. Left open rather than decided by silence.

## Design notes

Non-normative.

**Why presence is the mode discriminator.** The weaker rule — keep chain-presence as the sole
discriminator and merely require an anchor in owner mode — would have left the two signals free to
disagree, and a verifier would still have to decide which one it believed. Requiring them to agree
costs a producer nothing (it knows its own mode) and removes the try-owner-then-fall-back
evaluation order 014 had to legislate around, along with the class of bugs that live in it: a unit
whose owner verification fails for an unrelated reason is now invalid rather than silently
reinterpreted as delegated.

**Why an event digest rather than a state commitment.** A commitment to the state itself —
`multihash({keys, threshold})` — would be shorter and would name the thing verification actually
uses. It also collides: with the interim rule gone, a log may legally commit the same state twice,
and a commitment could then name two events. The event digest names exactly one event of one log
and is already a defined primitive (003 `prior`), so it composes rather than invents (000 #5).

**Why the tip is a SHOULD and not a MUST.** A verifier cannot check it. Whether a producer held
the tip's keys at signing time is not observable from the record, and a rule no verifier can
enforce is a recommendation whatever word it uses. What matters is enforced: the record verifies
against the state it names, or it does not verify.

**The soundness argument, restated.** 015 established that within one key state, and with `m = t`,
the set of conforming byte-forms per (content, state, signature values) has exactly one element.
This spec makes "one key state" a property of the record rather than a hedge in the theorem: the
anchor selects the state, the anchor is inside the signed and digested bytes, and no other state
is tried. So the unqualified statement 015 had to disclaim as false — no byte-level transformation
of a conforming record yields a second conforming record — holds.

## Conformance vectors

`packages/crypto/test/fixtures/record-anchoring-vectors.json`, generated from deterministic seeds.
Each vector carries the record, the issuer's key log, the anchored event's digest and state, the
record's canonical digest and the expected verdict with the reason for it, so an independent
implementation can check every case from the bytes alone. The suite covers, at minimum:

- **Route 3** (a later state whose key list is a subset of an earlier one's) and **route 4** (the
  same keys permuted), each in two variants: the **edit** rejected against the anchored state, and
  the **anchor rewrite** — the same edit re-anchored to the state that would accept it — rejected
  because the anchor is inside the signed bytes.
- **Variants G and P**, whose logs are now **valid** under the retired interim rule, with the
  keyless edit rejected all the same. These are the cases that show the closure is structural: the
  log shape that used to be the defence is legal again, and the attack is still refused.
- **Unknown anchor** — a well-formed digest naming no event of the issuer's log.
- **Cross-log anchor** — a digest naming a real event of a **different** participant's log.
- **Non-tip anchor after a later rotation** — valid, pinning that anchoring does not orphan.
- **A set satisfying the issuer's current state but anchored to an earlier one** — invalid, pinning
  that no other state is tried.
- **A 2-of-3 retaining two keys across a rotation** — the log is valid, which the interim rule
  refused.

`packages/crypto/test/fixtures/key-log-rejection-vectors.json` carries the interim's retirement
from the log side: the quorum-sharing logs it rejected are now accepted, with every other rejection
ground unchanged.

The four record schemas' accept/reject fixtures under `packages/protocol/test/fixtures/` pin the
field itself: `anchor` required and absent, the `Grant` issuer-shape cross-field rule in both
directions, the owner/delegated mode rule for conversation and conversation-update units
(`mode_conflict` on both and on neither), and the digests the new shapes produce.

## Placement test (000)

1. **Interop-necessity** — pass. Two implementations must agree on whether a record is validly
   signed, and without a named state they can disagree by choosing different states from the same
   log. The verdict feeds identity (012) and revocation (008), so the agreement is protocol-level.
2. **Primitive, not feature** — pass. It names which key state verifies a signature set; it names
   no application behaviour and no record's purpose.
3. **Mechanism, not policy** — pass. Which state a producer anchors to is the producer's business;
   the spec fixes only how the named state is found and that no other is tried.
4. **Stored, not derivable** — pass. The accepting state is **not** derivable: 015 established
   that up to `E` states of one log may accept a given record's bytes, and the record carries
   nothing else that distinguishes them. That is precisely why a field is required here where 015
   needed none.
5. **Compose, not invent** — pass. The value is 003's key-event digest, already defined and already
   used for chaining; the field is a pointer in the same encoding as `prior`, `proof` and `revokes`.
6. **Driven by running code** — pass. The routes it closes were found against the reference
   implementation and are committed as vectors; the interim rule that it retires was written and
   shipped first, and its cost in rotation flexibility is what running code showed.
7. **No thinner form** — pass, after the four options 015 evaluated. Binding the state into the
   signing input with no field (c) leaves the verifier unable to tell which state to try, so it
   fixes correctness and not cost while changing every digest anyway. Forbidding key reuse or its
   narrower intersection form (d) needs no field but keeps the `E` factor and rests on a
   cryptographic assumption; it was taken as the interim and is retired here. A `seq` in place of a
   digest is thinner by ~45 characters and ambiguous across forks, which is not a trade an
   identity-bearing field may make.

## History

- 2026-08-18 — Accepted. Four record types gain `anchor`, the 003 digest of one key event of the
  issuer's log; a record is verified against the state that event carries and against no other;
  anchor presence discriminates owner from delegated mode for conversation records; 003's interim
  quorum rule is retired, restoring M-of-N rotation flexibility; every record of the four types is
  re-issued and conversation ids move.

## References

- Spec 000 (placement test, Stage 0), 001 (JCS signing input; closed schemas), 002 (participant id
  derivation), 003 (_Events_ — the digest rule; _The committed next key state_; _Resolving the
  current key_; _No two states may share a quorum_, retired here; _Size limits_), 004 (request
  signing — current-state, unanchored), 005 (suite; _Canonical encodings — one value, one text_;
  _Verification mode_), 008 (revocation by digest, revocation authority), 009 (chain verification,
  `proof`, size limits), 011 (key principals, bare-key issuers), 012 (conversations — digest as
  identity, the two signing modes), 014 (evidence records, the `(record, chain)` unit profile,
  `group_id` derivation), 015 (S0–S6; _Anchoring_ — the requirement, the options and the decision
  this spec implements; _Cost_)
- RFC 8785 — JSON Canonicalization Scheme (the digested bytes of a key event)
- Conformance vectors: `packages/crypto/test/fixtures/record-anchoring-vectors.json`;
  `packages/crypto/test/fixtures/key-log-rejection-vectors.json`; the four record schemas'
  accept/reject fixtures under `packages/protocol/test/fixtures/`
