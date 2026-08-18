# 015 — Canonical signature sets

**Status:** Accepted
**Blocks:** revocation-by-digest (008), digest-addressed record identity (012), M-of-N
multi-signature (003, 004)
**Amended by:** 016

## Context

Every signature-set record in the protocol carries `signature: Signature[]`, and every one of
them is digested with its signatures **inside** the digested bytes: 003 fixes an event's digest
as "the multihash of the JCS of the **complete signed event**, signatures included" (_Events_),
and 008 names a revoked record by that same digest. 012 goes further and makes the digest a
record's _identity_ — a conversation id is the digest of the complete signed record.

003 and 009 bound how many members a signature set may hold, and 009 declined to settle what
those members must be: its `MAX_RECORD_SIGNATURES` paragraph "bounds the COUNT only" and left
"whether every member of the set must verify" as a separate, undecided question. This spec
decides it.

Leaving it undecided is not neutral. A threshold check that iterates the **key** set and counts
satisfied keys answers "at least `threshold` distinct listed keys have _some_ valid signature in
the array". Under that reading a signature array may contain duplicates, may contain members that
verify against nothing at all, and may appear in any order — and the record still verifies.
Because the array is digested, each of those variants is a **different digest that still
verifies**. Every signature-set record then carries a large family of valid digests — one for
every distinct well-formed signature string that can be appended, up to the record's
signature-count bound — and producing a member of that family needs no key at all, only the
ability to touch the bytes.

The consequences differ only in what else happens to pin the digest:

| Record type                                     | What the digest is used for                     | Severity | Why                                                                           |
| ----------------------------------------------- | ----------------------------------------------- | -------- | ----------------------------------------------------------------------------- |
| **Grant**, leaf link (009)                      | revocation lookup (008)                         | Critical | every non-leaf digest is pinned by the child's `proof`; nothing pins the leaf |
| **Conversation / ConversationUpdate** (012/014) | conversation id, MLS `group_id`, evidence dedup | High     | one signed conversation yields several ids and several MLS groups             |
| **KeyEvent** (003)                              | the `prior` chain link                          | Low      | the chain check and discovery's append-only conflict close every route        |

The grant case is the sharpest. Appending one arbitrary, non-verifying signature to a **revoked**
leaf grant yields a chain that still verifies, because the revocation is keyed to the honest
digest and the mutant has a different one; the mutation survives a `PN-Grants` header round trip
byte for byte. A revoked delegate can restore its own authority without holding any of the
issuer's keys, and can do it again for every fresh revocation, so revocation-by-digest can never
catch up.

One root cause, one fix. The digest-includes-signatures rule is normative and load-bearing, so
the correction belongs in the **verification rule**, not in `canonicalDigest`.

## Decision

A signature set is valid only if it holds **exactly `threshold` members**, **every** one of which
verifies, each against a **distinct** listed key, in a **deterministic order** — and the check is
made **before** the record's digest is computed or relied on.

### Scope

This spec governs every record whose `signature` field is an array:

- `KeyEvent` (003)
- `Revocation` (008)
- `Grant` (009), for both participant issuers and bare-key issuers (011)
- `Conversation` and `ConversationUpdate` (012, amended by 014)

and every signature-set record added later. Records with a scalar `signature`
(`ParticipantProfile`, `ParticipantNode`, `Relationship`, `Claim`, and `MessageEnvelope` (010))
are outside the record shape but not outside the rule: a verifier that lifts such a record into a
one-member set MUST apply this spec to the lifted set.

Nothing here changes the signing input (001), the digest rule (003, 008), the suite (005), or any
record's fields. No field is added, removed, or re-encoded. The change is a validity rule over
bytes that already exist.

### Terms

- **Key state** — an ordered key list `K = [K₀ … K_{n−1}]` together with a threshold `t`, as
  committed by one event of a key log (003). `n ≥ 1`. For a bare-key issuer (011) the state is
  that single key with `t = 1`.
- **Signature set** — `S = [S₀ … S_{m−1}]`, the record's `signature` array **in the order it
  appears in the record**. That order is the digested order: JCS preserves array order, so the
  order is part of the signed and digested bytes.
- **Signing input** — `UTF-8( JCS( record − signature ) )` (001). One input for the whole set;
  every member is verified over the same bytes.
- **`verify(σ, input, K)`** — Ed25519 verification per 005, in the mode 005's _Verification mode_
  section pins: **strict RFC 8032 plus low-order public-key rejection**, which rejects low-order
  public keys, non-canonical `S`, and non-canonically encoded points. The low-order rejection is
  005's own addition, **not** an RFC 8032 requirement — the RFC's cofactored equation admits
  small-order keys — so an implementation built on a stock RFC 8032 library must add it
  explicitly. Ed25519 verification is not one function: strict RFC 8032, ZIP-215 and libsodium
  disagree about small-order points, non-canonical encodings and cofactor clearing, and they
  disagree about specific signature/key pairs. Every determinism claim in this spec — "two
  implementations that run the procedure agree on every input", and the uniqueness property under
  _What this guarantees_ — is conditional on `verify` being **one agreed function**, which is why
  005 pins the mode rather than leaving it to a runtime's default. A conforming implementation
  MUST use the mode 005 pins rather than its runtime's default; one that does not can still
  conform to every counting rule below and disagree with a conforming verifier — on inputs no
  honest producer emits, but disagree. The pin was **also** a prerequisite for the soundness of
  003's intersection rule, because cofactored verification makes one signature verify under many
  distinct keys with no secret key involved; 016 removed that rule, and with it that second role,
  so determinism is what the pin now carries — and it carries it alone. See _Soundness basis_
  under _Anchoring_ for the construction, and
  `packages/crypto/test/fixtures/ed25519-verification-vectors.json` for the committed vectors.

### S0 — The key state must be well-formed

Every rule below is stated against a key state, so the state itself has to be sound before any of
them mean anything. A key state is well-formed iff:

1. **Its key list holds no repeated key.** `Kᵢ = K_j` for `i ≠ j` makes the state invalid, and
   every record checked against it invalid with it.
2. Its threshold satisfies S1.

**Why distinctness is stated normatively.** A repeated key is exactly what would let one signature
be counted twice under S2, so the rule has to bind wherever a key state is formed and not only
inside a replay procedure. 003 states it where the record is defined (_Events_ — "An event's
`keys` list MUST NOT contain the same `KeyRef` twice") and its schema enforces it, comparing on
key VALUE, so schema and replay agree rather than the replay standing alone. 014 already demands
"non-empty, unique, sorted" of its `leaves`, so this brings key lists into line with the
convention the protocol already uses for key arrays.

### S1 — Threshold domain

`threshold` MUST be a decimal string matching `^[1-9][0-9]*$` — no sign, no leading zero, no
fraction, no whitespace, no empty string. Let `t` be its integer value; `t ≥ 1` follows.

A key state MUST additionally satisfy `t ≤ n`. A threshold larger than the number of keys the
state lists is unsatisfiable by construction, so accepting it only defers the failure to every
record ever checked against that state, and it is a shape no correct producer emits.

A key state that violates either rule is **invalid**, and so is every record checked against it.
A verifier MUST NOT coerce a non-conforming threshold to a number and compare: there is no
threshold value that an empty signature set satisfies, and "the threshold parsed to zero, so zero
signatures suffice" is a fail-open outcome this spec forbids explicitly.

Given a conforming state, the set size MUST be **exactly the threshold**: `m = t`. Not "at least
`t`", and not "at most `n`" — exactly `t`. A record carrying more signatures than its threshold
requires is **invalid**, for the reason set out under _Exactly the threshold_ below: a surplus
member can be deleted by anyone holding no key at all, yielding a second conforming record with a
different digest, which is precisely the property revocation-by-digest depends on.

`m = t ≤ n` therefore also satisfies 003's "an event's `signature` count MUST NOT exceed its `keys`
count", which this rule generalizes to every signature-set record and strengthens. It is a length
comparison, so it MUST be checked first, before any curve work, for the reason 003 gives about
length checks.

### S2 — Every member verifies, against a distinct key

A conforming signature set admits an **injective** assignment of its members to listed keys such
that each member verifies under the key assigned to it:

1. **Total.** Every `Sᵢ` MUST be assigned a key it verifies under. A member that verifies under
   no key of the state makes the record **invalid** — it is not ignored, not skipped, and not
   merely uncounted.
2. **Injective on key VALUE, not on list position.** No two members may be assigned the same key.
   "Same key" means the same `KeyRef` bytes, not merely the same index — the distinction is only
   observable against a state that repeats a key, which S0 makes invalid, but it MUST be stated on
   value because an index-only reading would let one signature be counted twice against
   `K = (K₀, K₀, K₁)` and defeat the threshold entirely. A verifier that enforces S0 may implement
   the check by index; one that does not, MUST compare values.

Together with `m = t` from S1 this subsumes the threshold check, and makes it exact: a conforming
set witnesses **exactly `t` distinct signing keys** — no fewer, and none surplus.

### S3 — Order

The assignment MUST be **strictly increasing in key index**: if `Sᵢ` is assigned `K_a` and `S_j`
is assigned `K_b` with `i < j`, then `a < b`.

The canonical form a producer MUST emit follows: **a signature set is ordered by the position, in
the state's key list, of the key that satisfies it.** The key order is the one the key event
commits to — 003 hashes the ordered key list into `next`, so it is fixed protocol data, not a
verifier's choice.

That producer rule is a **consequence** of the increasing-assignment rule, not a restatement of
it, and it is well defined only when "the key that satisfies a member" is unique. Two things could
make it ambiguous: a state that lists the same key twice, which S0 rejects outright; and a single
signature that verifies under two distinct listed keys, which is **not** excluded by the
mathematics and, under a cofactored verification mode, is not even difficult — see the low-order
note under _Soundness basis_. The **normative** rule is therefore the increasing assignment and the
procedure below, never the producer-side paraphrase.

A set whose members verify and are distinct but appear in any other order is **invalid**. That is
the point: without S3 a co-signed record would have `m!` valid byte-forms and therefore `m!`
valid digests, which is the same malleability S2 closes, wearing a different hat.

**Normative decision procedure.** A conforming verifier MUST decide S1–S3 as follows, and the
procedure is the tie-break: two implementations that run it agree on every input, including
inputs where more than one assignment exists.

```
given K = [K₀ … K_{n−1}], t, S = [S₀ … S_{m−1}], input:

  if K contains a repeated key:                      REJECT   (S0)
  if t is not a conforming threshold, or t > n:      REJECT   (S1)
  if m ≠ t:                                          REJECT   (S1)

  j ← 0
  for i in 0 … m−1:
      while j < n and not verify(Sᵢ, input, K_j):
          j ← j + 1
      if j = n:                                      REJECT   (S2/S3)
      j ← j + 1                                      // Kⱼ consumed by Sᵢ
  ACCEPT
```

Greedy earliest-match is not merely _one_ way to search: if any strictly increasing injective
assignment exists, this walk finds one, by the usual exchange argument (replacing a first
assignment by an earlier admissible key never blocks a later one). So no implementation needs
backtracking, and "the greedy walk rejected it" and "no conforming assignment exists" are the
same statement.

The walk performs **at most `n` verifications** — one per listed key, and never more, whatever `m`
is. Every call to `verify` is followed by `j ← j + 1`, on both branches: a failure increments
inside the `while`, and a success exits the `while` and is incremented immediately after. Since
`j` starts at 0, never decreases, and is bounded above by `n`, the number of `verify` calls cannot
exceed `n`. The signature count is not a factor at all. Compare the search it replaces, which is
`n × m` in the worst case. See _Cost_ below. A verifier's concrete verification budget MUST be
derived from its own implementation of this procedure, and MUST NOT be copied from the arithmetic
in _Cost_.

### S4 — The check precedes the digest

A verifier MUST establish S1–S3 **before** it treats the record's digest as meaningful. Concretely,
for an untrusted record a verifier MUST NOT, until the signature set has been checked and accepted:

- use the digest as the record's identity (a conversation id, 012);
- store, index, cache, or forward the record under its digest;
- compare the digest to a `prior` (003) or `proof` (009) pointer as proof of chaining;
- treat the absence of a revocation for that digest as "not revoked" (008).

Order of checks on an untrusted record is therefore: schema and length bounds (003, 009, 012) →
signature set (this spec) → digest use. The middle step is the one this spec adds; the outer two
already exist.

Walking a chain is not an exception. A verifier may follow a child's `proof` pointer to _fetch_ a
candidate parent — the pointer is a lookup key, not yet an assertion — but it MUST check the
parent's own signature set before accepting the parent, and before treating `digest(parent) ==
proof` as a verified link. The same distinction applies to holding a record: an implementation
MAY retain a not-yet-verified record keyed by its digest purely as a lookup key (014's evidence
store waits on exactly such records), provided nothing is asserted from that key — no identity,
no chaining, no revocation reasoning — until the signature set has been checked.

### S5 — Composition with the anchored key state

_Amended by 016: the existential over every state the issuer's log ever committed is replaced by
the lookup below._

008 and 012 fix that a rotation must not orphan records a participant already signed, so a record
is **not** verified against the issuer's current key state. 016 supplies the state it _is_ verified
against, and the rules compose as a lookup rather than a search:

> A record is validly signed by a participant iff the issuer's key log replays valid (003), that
> log contains a key event whose digest equals the record's `anchor`, and the record's signature
> set satisfies S0–S3 in full against the key state that event carries.

No other state is tried. A record whose set fails against the anchored state is invalid even where
another state would accept it, and a record whose anchor names no event of the issuer's log is
invalid for that distinct reason. Records with no `anchor` field have exactly one constructive
state — a bare key, a chain leaf, or a key event's own committed state — and are checked against
it; 016 fixes which records carry the field.

Consequences worth stating, because each is a place an implementation could get it wrong:

- It is **not** "conforming against the current state". Records signed before a rotation stay
  valid, exactly as 008 and 012 require: the anchor names a historical event, and the log is
  append-only.
- S3's ordering is relative to **the key order of the anchored state**, which is now the only key
  order in play for the record at all.
- "Extra" is judged against the anchored state and nowhere else. A junk member verifies under no
  key of that state, so the record is invalid — which is precisely the attack in _Context_.
- **`m = t` now binds where it needs to.** The member count is fixed by the bytes and the state is
  fixed by the anchor, so a keyless edit has no second state to be judged against: it is judged
  against the anchored state, where S1–S3 refuse it, or it is invalid. Routes 3 and 4 under
  _What this guarantees_ are exactly the cases the old existential left open here, and they are
  closed by that fact.
- A verifier performs **one** run of the S3 walk, not one per committed state. The `E` factor in
  _Cost_ is gone.

### S6 — One delivered byte string, one record

Every property in this spec is stated over the **parsed** record, because that is what gets
canonicalized, signed over and digested. A rule about the signature array is worth nothing if two
implementations can turn one delivered byte string into two different objects — the digest then
differs before the signature set is ever examined. So the precondition is normative here rather
than assumed. A verifier receiving a signature-set record MUST:

1. **Reject the delivery outright if its JSON contains a duplicate object key**, at any depth,
   before parsing resolves it. Last-wins and first-wins are both defensible and parsers disagree,
   so the only interoperable answer is to refuse.
2. **Digest the schema-validated record**, not whatever object it happened to parse, and reject the
   delivery if a digest it was delivered under does not match.
3. Treat the record's schema as **closed**: a record carrying a key the schema does not define is
   invalid, not silently stripped.

None of this is new — 012 states all three, and states why, for `Conversation`. What is new is that
015 makes them apply to **every** signature-set record, because every one of them is
digest-addressed: a `Grant` by its `proof` and by its revocation key, a `Revocation` by what it
names, a `KeyEvent` by `prior`. 012 raised generalizing the rule into 001 as an open question;
until that lands, this section is where it binds for signature-set records.

## What this guarantees, and what it does not

**It guarantees:** for a fixed record content, a fixed accepting key state, and a fixed set of
signature values, **the conforming record is unique — and therefore so is its digest.** Under
`m = t` the signature array has no slack in any direction. It cannot be lengthened (S1: `m ≠ t`),
cannot be shortened (S1 again), cannot be reordered (S3), cannot have a member replaced or
perturbed (S2), and cannot have any other field altered without invalidating every member at once
(the signing input is the whole record less the signature array). The set of conforming byte-forms
therefore has exactly one element per (content, state, signature values).

**The hedge in that sentence was load-bearing, and 016 discharged it.** "A fixed accepting key
state" was a real precondition, not throat-clearing: S5 once let a record be judged against _any_
state the issuer's log ever committed, while the uniqueness argument above is stated **within one
state**. Across states it did not hold, and the keyless attacks below lived in exactly that gap.

_Amended by 016: the record now names the one state it is judged against, and the anchor is inside
the signed and digested bytes, so there is no second state for an edit to land in. The unqualified
form — no byte-level transformation of a conforming record yields a second conforming record —
holds._

**What is still not guaranteed.** The residual routes fall into two groups: the first two are
properties of the signers, which no counting or ordering rule can remove; the rest are **keyless**
— an attacker with no private key at all produces a second valid record — and those are defects,
tracked below with their fixes.

1. **The signers still choose which `t` of `n` keys sign.** With `t < n` there are `C(n, t)` signer
   subsets, and each is a different record with a different digest. Every one of them requires a
   genuine signature from each key it names, so no party can produce a variant without the
   corresponding private keys — but "one logical authorization" still maps to more than one
   possible record. This is inherent to M-of-N and is not closable by an ordering or counting rule.
2. **Ed25519 signatures are not unique per (key, message).** RFC 8032 signing is deterministic, so
   an honest signer emits one signature; a **key holder** can pick a different nonce and produce
   another value that verifies. A verifier cannot distinguish the two without the secret key, so
   this spec cannot require the deterministic one. Producing such a variant requires the private
   key — an outsider cannot, since finding a second valid signature without the key is a forgery.
3. **KEYLESS — cross-state deletion.** S5's existential defeats `m = t` whenever a later state's
   key list is a subset of an earlier one's. Take the log `icp [K₀,K₁,K₂] t=3` →
   `rot [K₀,K₂] t=2`, which was schema-valid and replay-accepted before 003 gained the
   intersection rule. A record signed `[σ₀,σ₁,σ₂]` is conforming against state A. Strip `σ₁` — no
   key required — and `[σ₀,σ₂]` is **not** conforming
   against A (`m = 2 ≠ 3`) but **is** conforming against B: two members, distinct keys, increasing
   order, `m = t = 2`. Two valid records, two digests, one keyless edit. **Closed structurally by
   016**: the record names one state, so state B is never tried and the edit is judged — and
   refused — against A. The interim closure, 003's intersection rule making that log invalid, was
   retired with 016 and the log shape is legal again.
4. **KEYLESS — cross-state reorder.** The same shape against S3. `icp [K₀,K₁] t=2` →
   `rot [K₁,K₀] t=2`, the same two keys permuted, which 003 permitted before the intersection rule
   and which the ordered-list commitment in `next` distinguishes. `[σ₀,σ₁]` conforms against A and
   `[σ₁,σ₀]` conforms against B, so S3's "a set in any other order is invalid" is true **within** a
   state and false **across** them.
   Note this one also defeats the `m = t` narrowing claimed under S5 — both states have threshold
   2, so equal thresholds are no protection. **Closed structurally by 016**, for the same reason as
   route 3; 003's intersection rule, which closed it in practice, was retired with 016.
5. **KEYLESS — member replacement through a repeated key entry.** Against state `[K₀,K₀,K₁]` with
   `t = 2`, both the honest `[σ₀,σ₁]` and the mutant `[σ₀,σ₀]` satisfy an index-based reading of
   S2, giving two digests from one keyless edit. **Closed in this spec** by S0 (a state with a
   repeated key is invalid) and by S2's injectivity being on key value rather than list position.
6. **KEYLESS — the digest is over the parsed record, so parser disagreement is a route to two
   digests.**
   S1–S3 constrain the signature array; they say nothing about how the delivered octets become the
   object that gets canonicalized. If two implementations parse one delivered byte string into two
   different objects — the duplicate-JSON-key case, resolved last-wins by some parsers and
   first-wins by others — they compute two different digests for one delivery, and S1–S3 do not
   stop them. Concretely: one delivered byte string with a duplicated JSON key yields two
   different `revokes` values and therefore two different digests, depending only on whether the
   parser keeps the first or the last. 012 stated the closing rule (reject duplicate keys before
   parsing, digest the schema-validated record) for `Conversation` alone. **S6 above makes the
   rule general**, for every signature-set record.
7. **Non-canonical encodings are a validity question this spec inherits.** S2 operates on _decoded_
   signature bytes, so any encoding that decodes to the same bytes under a different textual form
   would be a second conforming record. Probed directly for `Signature` strings: base58btc
   length-prefix mutations (`z1…`, trailing `1`) decode to 65 bytes rather than 64 and therefore
   fail verification, so those specific forms are not a route. That is a probe, **not a proof that
   base58btc admits no non-canonical form for a 64-byte value**. **Closed as a general rule** by
   005's _Canonical encodings — one value, one text_ (decode, re-encode, exact textual equality,
   required decoded length): it binds `groupNonce` and the MLS payload fields, which were the
   reachable cases. What it does NOT yet bind is the `Signature` and `KeyRef` strings themselves —
   those are decoded during verification, where a wrong length fails verification rather than
   validation, so the canonicity check for them belongs alongside S2 and is the remaining piece.

**Two things that look like malleability and are not**, checked explicitly because both are easy
to mistake for it:

- **More than one assignment may satisfy a given (set, state).** If some member verified under two
  listed keys, several strictly-increasing assignments could exist. The greedy walk picks one
  deterministically, so the _verdict_ never depends on the choice and two implementations always
  agree — and the record's bytes are untouched either way, so no second record arises. What the
  ambiguity does cost is attribution: S2 establishes that `t` distinct keys signed, not _which_ key
  produced which member. Nothing in this spec depends on attribution; a future rule that does (a
  per-signer audit trail, per-signer revocation) would need to state it separately. Such a member
  is not hypothetical — see the low-order construction under _Soundness basis_ — but it costs this
  spec nothing, because the verdict does not depend on which assignment the walk chooses.
- **Two different key states may both accept the same record's bytes.** It yields one record, not
  two, so it was never malleability — and it must not be confused with routes 3 and 4, which turn
  on state A accepting the **original** while state B accepts an **edit**, a different proposition
  entirely. _Amended by 016: under the lookup only the anchored state is ever tried, so the
  question no longer arises for a verifier; the distinction is kept because conflating the two
  propositions is how the routes were missed._

**One assumption this spec rests on and does not establish:** that the verifier is judging the
record against the _right participant's_ key log. If an attacker can make a verifier resolve
someone else's log, every guarantee above is evaluated against the wrong key state and says
nothing. That is key-log substitution; it is closed by binding key-log replay to the participant id
the record names, which 015 assumes.

One further consequence of (1) and (2), rather than of the rule. 008 keys revocation by digest, so
a record's **own issuer** can re-sign the same content and present a digest an existing revocation
does not name. Where the issuer is also the revoker this is uninteresting — an issuer that wants a
record alive simply issues a fresh one (008 says authority is restored that way). It bites in the
009 case where an _upstream_ ancestor revokes a _downstream_ link whose issuer is the delegate: that
delegate can re-sign its own link. The available remedy today is the one 008 already gives —
revoke the delegate's own inbound link, which is signed by a key the delegate does not hold, and
the whole subtree dies with it. Narrowing this further (issuer-scoped or content-scoped
revocation) is out of scope here; see _Open questions_.

## Anchoring — closing the existential

_The requirement and the options analysis below are the rationale for **016**, which specifies the
mechanism: the field, its placement, the verification rule, the vectors and the migration. This
section is kept because it is where the choice was made and argued; where the two overlap, 016 is
the normative text._

**Requirement.** A signature-set record MUST be verifiable against **exactly one** key state, known
before verification begins. The existential of S5 becomes a lookup: not "does some state accept
this?", but "does _the_ state this record names accept it?".

That single sentence closes routes 3 and 4 — both need two states in play — and collapses the `E`
factor in _Cost_ from up to `MAX_KEY_LOG_EVENTS` to one, because the correctness hole and the cost
factor were always the same fact wearing two hats.

**Goal, stated precisely, since it is what the options are judged against:** at most one committed
key state may accept a given record, and a verifier must be able to identify that state from the
record without trying any other.

### Options considered

Four constraints decide it: does it close routes 3 **and** 4; does it orphan records after a later
rotation (the property 012 protects); does it change existing digests; and is any input it depends
on attacker-influenceable.

| Option                                              | Closes 3 & 4 | Orphans on rotation | Digests change | Collapses `E` |
| --------------------------------------------------- | ------------ | ------------------- | -------------- | ------------- |
| **(a) Explicit anchor field naming the state**      | yes          | **no**              | yes            | yes           |
| (b) Derive from the record's timestamp              | —            | —                   | no             | yes           |
| (c) Bind the state into the signing input, no field | yes          | no                  | yes            | **no**        |
| (d) Forbid key reuse across events                  | yes          | no                  | **no**         | **no**        |

**(a) An explicit anchor field**, naming the key event that established the accepting state. Two
sub-forms: its `seq`, or the multihash of the key event itself.

- Closes both routes: one named state, so there is no second state for an edit to land in.
- **Does not orphan.** This is the point that has to be got right, because it is where the idea
  looks superficially like the rule 012 forbids. 012 forbids verifying against the **current**
  state, which would invalidate a record every time its issuer rotates. An anchor names a
  **historical** state, and the log is append-only, so the named event is still there after any
  number of later rotations and the record stays verifiable forever. Anchoring is not "current
  state only"; it is "the state that was current when this was signed, named explicitly".
- Changes digests: yes — a new field inside the signed bytes changes every affected record's bytes.
  See _Re-issuance_ below; this is the whole cost of the option.
- Attacker-influenceable: no. The anchor sits inside the signing input, so it is covered by every
  member of the set; changing it invalidates the record. A malicious **producer** could name a
  state it does not satisfy, but then verification simply fails.
- `seq` vs digest: **digest**. A `seq` is unambiguous only within one replay-valid log, and 003
  defers witnessing and duplicity detection, so two forks could carry different events at the same
  `seq`. A key-event digest pins the exact event bytes and is already a defined primitive — 003
  uses it for `prior` — so it composes rather than invents (000 #5). It costs ~46 characters
  against 1–2, which is not a reason to accept ambiguity in an identity-bearing field.

**(b) Derive the anchor from the record's timestamp** — "the state current at `issuedAt`". Rejected,
and decisively: **`KeyEvent` has no timestamp field at all** (`id`, `seq`, `prior`, `kind`, `keys`,
`threshold`, `next`, `signature`), so there is no way to map a wall-clock instant to a key state
from the log alone. The option cannot even be evaluated on the other criteria without first adding
timestamps to key events and finding a reason to trust them — and they would not be trustworthy:
`issuedAt` is producer-set, and 012 explicitly calls `createdAt` "creator-chosen, informational".
An attacker-influenceable input selecting the verifying key state is the wrong shape regardless.

**(c) Bind the state into the signing input** without adding a field — sign over the anchor
concatenated with `JCS(record − signature)`. It closes both routes, since signatures made for state
A's input do not verify under state B's. But the verifier still cannot tell which state to try, so
the existential and its `E` cost survive intact — it fixes the correctness hole and not the cost
one. It changes every signature value and therefore every digest anyway, so it is not cheaper than
(a). And it changes 001's signing input, which touches every record type and the RFC 9421 request
path rather than the four record types (a) touches. Strictly worse than (a) on cost and blast
radius, equal on everything else.

**(d) Forbid key reuse across a log's events**, so no two states share a key. Both keyless
cross-state routes need overlapping key sets — route 3 needs B's keys to be a subset of A's, route
4 needs the same keys permuted — so disjointness closes both. It is by far the cheapest option: no
new field, no signing-input change, **no digest changes and no re-issuance at all**. Two reasons it
is not the answer, though it is the right stopgap:

- It does not collapse `E`. A verifier still tries every state; it just cannot be fooled.
- Its soundness rests on a **cryptographic** assumption rather than a structural one — with
  disjoint key sets, a set valid under both states would need one signature verifying under two
  distinct keys, which is an assumption about Ed25519 rather than a fact about the record, and one
  that does **not** hold under a cofactored verification mode (see _Soundness basis_). The strict
  mode 005 pins makes the assumption hold; anchoring needs no such assumption under any mode.

It is also a real restriction: pre-rotation reveals a fresh key set at every rotation, so reuse is
already abnormal, but 003 permits it today.

### Decision

**Adopt (a) with a key-event-digest anchor**, specified as 016. The interim measure was the
intersection rule, adopted normatively in 003 and retired by 016 once the anchor landed. The
obvious narrow forms of (d) are unsound, for the reason set out next, and the sound forms cost
more than they first appear; the analysis below is the basis for the intersection rule and for
why it was only ever an interim.

### Why the narrow forms of (d) do not work

A deliberately narrow form of (d) — _reject a key state whose key list is a subset or a permutation
of an earlier committed state's_ — looks sufficient, on the reasoning that routes 3 and 4 use
exactly those two shapes (route 3 a subset, route 4 a permutation) while a partial rotation that
introduces at least one new key stays legal. That reasoning does not hold. Two further variants
defeat it against the S0–S3 procedure with genuine Ed25519 signatures; both are keyless, and both
produce two conforming records with different digests.

| Log                                             | Attack                                   | subset/permutation, one-way | subset/permutation, symmetric | intersection rule | no key reuse |
| ----------------------------------------------- | ---------------------------------------- | --------------------------- | ----------------------------- | ----------------- | ------------ |
| **Route 3** `[K₀,K₁,K₂] t=3 → [K₀,K₂] t=2`      | drop `σ₁`; valid vs A **and** vs B       | rejects                     | rejects                       | rejects           | rejects      |
| **Route 4** `[K₀,K₁] t=2 → [K₁,K₀] t=2`         | swap members                             | rejects                     | rejects                       | rejects           | rejects      |
| **Variant G** `[K₀] t=1 → [K₀,K₁] t=2`          | drop `σ₁` from the m=2 record valid vs B | **ACCEPTS**                 | rejects                       | rejects           | rejects      |
| **Variant P** `[K₀,K₁,K₂] t=3 → [K₀,K₁,K₃] t=2` | drop `σ₂`                                | **ACCEPTS**                 | **ACCEPTS**                   | rejects           | rejects      |

**Variant G** shows the one-way form is the wrong shape: the attack does not care which state came
first, so a rule that only looks "backwards" misses the case where the key set _grows_. Making the
rule symmetric fixes that.

**Variant P is the one that changes the decision.** Its rotation retires `K₂`, introduces `K₃`, and
keeps `K₀,K₁` — a partial rotation introducing a new key, which is precisely what the narrow rule
was designed to keep legal. It is also a working attack. The two goals are therefore in direct
conflict, and not by accident:

> An edit can only delete and rearrange members, so every member of the edited record verifies
> under a key the original's signers held. For the edit to conform against another state, those
> keys must also be listed there, and there must be at least that state's threshold of them.
> **The attack exists exactly when two states share a quorum.** "Partial rotation that keeps a
> quorum of old keys" and "two states share a quorum" are the same sentence.

So no rule about key lists can both close this class and permit a rotation that leaves a quorum of
old keys intact. The minimal sound rule of the family is the **intersection rule**:

> For any two key states `A`, `B` committed by one log:
> `|keys(A) ∩ keys(B)| < min(t_A, t_B)`.

It rejects all four rows above. It is strictly narrower than "no key reuse" — reuse stays legal as
long as the states do not share a quorum, so a 3-of-5 may retain two old keys — but it does **not**
deliver the case that motivated the narrow form: a 2-of-3 retiring one key and keeping two shares
two keys against a threshold of two, so it is illegal. Only anchoring gives that back.

**Soundness basis, stated exactly.** The intersection rule rests on the **same** cryptographic
assumption as "no key reuse", not a weaker one: the argument above says each surviving member
verifies under a key its original signer held, which is only true if a signature verifies under
exactly one key. If one signature verified under two distinct listed keys, a member could satisfy a
key outside the intersection and the counting argument fails. It is an assumption about Ed25519,
not a structural property of the record. Anchoring needs no such assumption, which is the deeper
reason it is the real fix rather than the expensive one.

**And the assumption is false under a cofactored verification mode.** It would be comfortable to
call a counterexample a forgery and therefore infeasible; it is neither. Under cofactored
(ZIP-215) verification, a signature of `R = ` the identity point and `S = 0` verifies under
**every** small-order public key, for any message, and involves **no secret key at all**:
small-order points have no discrete log to know. All 8 canonical small-order points accept it, and
all 8 encode as `KeyRef`s a conforming decoder accepts; strict RFC 8032 with low-order public-key
rejection rejects all 8. So the verification mode this spec requires of 005 under _Terms_ was a
**prerequisite for the intersection rule's soundness**, not merely for determinism — a dependency
that ended with the rule, since anchoring assumes nothing of the kind. 005's
_Verification mode_ section makes the mode normative and the construction is committed as
conformance vectors, including the record-layer case where one keyless signature satisfies a 3-of-3
threshold under the forbidden mode. The assumption therefore held **under the pinned mode** and not
as a fact about Ed25519, which is why a verifier that ignored the pin reopened the hole silently
while still accepting every honest record. Bounded, and
worth saying: exploiting it needs the issuer's own state to list two or more small-order keys,
which only that issuer can publish and which gains it nothing it could not get by setting
`threshold: "1"` — self-harm, not an outsider attack.

**Migration cost.** A 1-of-1 log cannot violate either candidate rule: a 1-of-1 rotation that
shared its single key would not be a rotation at all, since `|I| = 0 < 1 = min(t_A, t_B)`. Both
rules are therefore free for single-key logs, and the cost of either falls only on later M-of-N
rotations.

**Decided: the intersection rule was adopted as the interim**, stated normatively in 003 under _No
two states may share a quorum_. It was chosen over the blanket ban on key reuse because it is
strictly more permissive at identical soundness and identical migration cost — a 3-of-5 may retain
two old keys where a blanket ban allows none — and over shipping no interim because a keyless
malleability in the revocation path should not stay open for the length of a record-shape change.

**What the interim changed, and what it did not.** With 003's rule in force, routes 3 and 4 were
closed **in practice**: a log that would enable them was invalid, so no conforming log committed
two states an edit could move between. That was a real closure. It was not the same thing as
anchoring, and the three differences are why 016 retired it rather than keeping both:

- It was **conditional on the cryptographic assumption** above; anchoring is structural.
- It was **conditional on the verifier enforcing 003's log rule**. A verifier that checks signature
  sets but not log shape got none of it, whereas an anchor travels inside the record it protects.
- It **bought the closure with rotation flexibility** — a 2-of-3 could not retain two keys — which
  anchoring gives back.

So the interim closed the routes; 016 made them impossible, and the rule went with it.

### Key events anchor themselves

A key event needs **no anchor field**, and adding one would be circular. Its signatures are checked
against a state determined entirely by its own position in the chain: `prior` already names the
previous event by digest, and `seq` orders it. 003 fixes which state that is — the one the
previous event committed, keys and threshold together — and it is a function of data the
event already carries, so exactly one state applies to a key event and the existential never
arises. That is why route 3 and route 4 attack records _about_ a log rather than events _in_ one.

The same is true, for a different reason, of the two record shapes that have no key state at all: a
bare-key issuer (011) is self-certifying against the single key named by `issuerId`, and a
delegated-mode record (011, 012) verifies against its chain's leaf key. Both have exactly one
candidate "state" — one key, `t = 1`, `m = 1` — so both are already anchored by construction and
neither takes a field.

Anchoring therefore adds a field to exactly four record types: `Revocation`, `Grant` with a
participant issuer, `Conversation`, and `ConversationUpdate`. **016 carries the normative
placement rule**, including the general rule that governs record types added later.

### Re-issuance under anchoring

S0–S6 require no re-issuance. **Anchoring does**: a field inside the signed bytes changes the
signing input, so there is no in-place repair for a record of the four types — every stored
`Revocation`, participant-issued `Grant`, owner-mode `Conversation` and owner-mode
`ConversationUpdate` is re-signed by its original issuer, conversation ids move (and with them the
MLS `group_id`s derived from them), and grant chains re-issue root-down because every parent's
digest moves. Key logs and participant identifiers are untouched. **016 §_Migration and impact_
carries the accounting**; Stage 0 has no external implementations, which is what makes it
affordable.

### This deserves its own spec

Anchoring is a **record-shape** change: a new field on four record types, a new verification rule,
its own conformance vectors, and a migration with an ordering constraint. 015 is about how a
signature set is checked **given** a state; anchoring is about **which** state, and folding it in
would give one spec two decisions and make neither reviewable on its own.

**That spec is `016 — Record anchoring`.** It carries the field and its placement, the verification
rule replacing S5's existential, the treatment of key events, bare-key issuers and delegated mode
as implicitly anchored, the vectors including routes 3 and 4 as rejection cases, and the migration
— including the retirement of the interim rule this section argued for. 015 states the requirement
and the analysis; 016 specifies the mechanism.

## Placement test (000)

1. **Interop-necessity** — pass. Two implementations must agree on whether a record is valid _and_
   on its digest. Without a canonical form for the signature set they can disagree; S0–S3's
   decision procedure and 005's pinned verification mode close that disagreement. The digest is an
   identity (012) and a revocation key (008), which is why the agreement is protocol-level.
2. **Primitive, not feature** — pass. It is the verification rule of the signature primitive, and
   it applies to every signature-set record without naming any of them specially.
3. **Mechanism, not policy** — pass. It fixes _how_ a set is checked. Who may sign, and what a
   threshold should be, remain the participant's and the trust layer's business.
4. **Stored, not derivable** — pass, in the applicable direction: the rule adds no stored data at
   all. It constrains existing bytes rather than introducing a field, which is the stronger form of
   this test.
5. **Compose, not invent** — pass. Requiring a multi-signature set to be ordered by the position of
   its key in a fixed key list is the standard shape (Bitcoin's multisig ordering rule is the same
   discipline); the alternative composition — tagging each signature with the key it belongs to,
   JOSE `kid`-style — is what 005 already rejected for signatures, and would add a field to solve a
   problem an ordering rule solves with none.
6. **Driven by running code** — pass. The defect was found in running code, not theorized.
7. **No thinner form** — pass, after considering the three alternatives:
   - _Exclude signatures from the digest._ Considered and **rejected**: it contradicts 003's
     _Events_ digest rule and 008's revocation-by-digest rule, and would change every digest
     already computed in the system, including conversation ids.
   - _Carry a key index or `kid` per signature._ Adds a field, contradicts 005's rationale for not
     tagging signatures, and the index is derivable from the ordering rule — strictly thicker.
   - _Keep the count bound only (status quo)._ Demonstrably broken.

## Migration and impact

**Stage 0 (000) is pre-wire-freeze.** There are no external implementations and no installed base,
so this is a breaking verification change taken at the stage where breaking changes are free and
preferred to accretion.

What these rules make invalid, relative to a count-only threshold check:

1. **A record whose signature array contains any member that verifies against no key of the state
   under test.** This is the exploitable case, and no honest producer emits it.
2. **A record whose signature array contains the same signature twice**, or two distinct
   signatures by the same key. A producer that emits one signature per supplied secret key emits
   this only if it is handed the same key twice.
3. **A record whose signatures are not in the key order of the state that satisfies them.** For
   `m = 1` there is nothing to order, so no single-signature record is affected. For `m > 1` a
   producer that signs in key-list order already conforms.
4. **A key state whose `threshold` exceeds its key count**, and every record checked against it. A
   schema that bounds `keys` and constrains `threshold`'s lexical form but carries no cross-field
   rule admits such a state; S1 makes such a state invalid.
5. **A threshold outside `^[1-9][0-9]*$`** presented to a verification API directly. A schema that
   bounds `threshold`'s form already makes these unrepresentable in a stored key log, so this
   closes an API surface rather than invalidating stored data: a threshold-verification call made
   with an empty signature set, an empty key list and threshold `"0"` returns true under a
   coercing implementation and false under S1.
6. **A record carrying more signatures than the accepting state's threshold** — the `m = t` rule.
   This is the class added by the strict-count decision, and it is the one worth reading twice: a
   record that previously verified because it over-satisfied a low threshold now fails against that
   state. _Amended by 016: such a record was also accepted by any other state whose threshold
   equalled its member count; only the anchored state is tried now, so there is no second chance._

### `m = t` checked against each record type

Stated record by record, because a count rule that any honest producer routinely violates would be
the wrong rule:

- **`Grant`, bare-key issuer (011).** The state is one key at `t = 1`, so `m = t = 1`. 009's chain
  rule already says "exactly one signature" for that branch, so `m = t` generalizes a check the
  protocol had already made in the one place it had been written down.
- **`Grant`, participant issuer.** `t` comes from the accepting key state. Nothing in 009 asks an
  issuer to over-sign.
- **`Revocation` (008).** Signed "per the issuer's current threshold" — `m = t` is that sentence
  read exactly.
- **`Conversation` / `ConversationUpdate` (012, 014).** Owner mode uses the creator's key state;
  delegated mode is a single session key at `t = 1`. 012 already describes the intent as
  "a participant whose current state requires _m_ of _n_ keys requires _m_ signatures here" — which
  is `m = t`, stated in 012 before this spec existed.
- **`KeyEvent` (003).** Schema and replay require exactly the event's threshold in signatures, and
  replay assigns them with the same greedy S2/S3 walk. The rule this replaces required only
  `signature.length ≤ keys.length` plus enough valid signatures to meet the threshold. Which
  threshold that is — and therefore which state a key event is checked against — is 003's
  question, answered in _The committed next key state_: the pre-rotation commitment covers the
  next key state's threshold as well as its keys, so exactly one threshold applies and `m = t` is
  unambiguous.

**Re-issuance required by S0–S6: none — stated explicitly rather than implied.** A 1-of-1 log —
`n = 1`, `t = 1`, `m = 1` at every event — satisfies `m = t` with no surplus to strip, no ordering
to get wrong, no repeated key to trip S0, and no threshold change between events, so every such
key event and every record signed under it conforms under S0–S6 unchanged and keeps its exact
bytes and exact digest. Any record that does violate these rules must be re-signed by its issuer;
there is no in-place repair, because the fix changes the bytes and therefore the digest.

**Anchoring is the exception, and it flips this claim — and it is now in force.** 016 adds the
field to four record types, so every stored `Revocation`, participant-issued `Grant`, owner-mode
`Conversation` and owner-mode `ConversationUpdate` is re-issued, conversation ids and MLS group ids
move, and grant chains are re-issued root-first. Key logs and participant IDs are untouched. The
full accounting is 016's; it is noted here because "re-issuance: none" would otherwise read as
covering the whole spec, and it does not.

What does **not** change: signing inputs, the digest rule, the encoding of keys or signatures,
every field of every record, and the digest of any record that was already conforming. A record
that satisfies S1–S3 keeps its exact bytes and digest.

## Conformance vectors

`packages/crypto/test/fixtures/signature-set-vectors.json`, generated from deterministic seeds.
Each vector carries the record, the key state it is judged against, a per-signature/per-key
verification matrix, the record's canonical digest, the expected verdict, and a sentence saying
why. An independent implementation can check every vector from the bytes alone.

The suite covers, at minimum: a valid single-signature record; a valid M-of-N set at exactly the
threshold; a duplicate member at threshold 2 and **a duplicate member at threshold 1**, the latter
being the shape a count-only check accepts and the one that pins the duplication half of the
defect; **a key state listing the same key twice** (S0), where an index-based reading
of S2 would let one signature satisfy a threshold of two; a non-verifying extra member (the case
that defeated revocation) both outside 009's count bound and inside every count rule; a mis-ordered
set; a member verifying under a key the state does not list; a set below the threshold; a state
whose threshold exceeds its key count; and a degenerate threshold.

**The cross-state routes are covered by a second vector set**, `logRuleVectors` in the same file,
because they are attacks on log **shape** rather than on any one signature set: each vector is a
sequence of key states and a verdict under 003's intersection rule, checkable by intersecting key
lists with no signatures involved.

_Amended by 016: the intersection rule is retired, so these vectors no longer state a validity
verdict for a log — every one of these logs is valid now. They are kept as the record of what the
interim rule refused and why, and the same attacks appear as record-level rejections against the
anchored state in
`packages/crypto/test/fixtures/record-anchoring-vectors.json`;
`packages/crypto/test/fixtures/key-log-rejection-vectors.json` pins the acceptances._

Eight vectors, both verdicts represented:

- **Rejections:** route 3 (later state a subset), route 4 (later state a permutation), variant G
  (the key set grows, which a backwards-looking rule misses), **variant P** (partial rotation with a
  lowered threshold — neither key set contains the other, so subset and permutation rules in both
  the one-way and symmetric forms accept it, and it remains a working attack against those narrow
  candidate rules; kept because it is the case that decided the rule's shape), and a non-adjacent
  pair whose every consecutive pair is legal, pinning that the rule is over **all** pairs.
- **Acceptances**, pinning the boundary from the permissive side: a 1-of-1 rotation, a 3-of-5
  retaining two old keys, and a 2-of-3 retaining exactly one — the most it may keep.

Three vectors carry the `m = t` decision specifically, as an explicit **deletion family**: one
unsigned record, one 2-of-3 key state, and three signature arrays that are subsequences of each
other, differing only in which members are present.

| Family member | Set            | `m` | Verdict     | Why                                    |
| ------------- | -------------- | --- | ----------- | -------------------------------------- |
| 1 of 3        | all three keys | 3   | **invalid** | over-signed: `m ≠ t`                   |
| 2 of 3        | keys 0 and 2   | 2   | **valid**   | the conforming record — `m = t`        |
| 3 of 3        | key 0 only     | 1   | **invalid** | a member deleted from a conforming set |

Deleting the middle member of (1) yields exactly (2); deleting a member of (2) yields exactly (3).
All three digests differ, and the vectors record all three. **Exactly one of the three is valid** —
that is the decision, in bytes.

Under the rule 015 replaces, (1) and (2) were **both** valid with different digests, so anyone at
all could convert a revoked over-signed grant into an unrevoked one by deleting a signature they
did not have to produce. Under `m = t` there is no conforming record anywhere in the family to
convert _from_ or _to_ except (2), and (2) cannot be edited into anything conforming.

A note on the shape of this evidence, because it is easy to state wrongly: it is **not** the case
that the over-signed record and its deleted form are both invalid. Deleting a surplus member from
(1) produces (2), which is valid — and correctly so, since (2) is precisely the record the signers
authorized and manufactures no authority. The property `m = t` delivers is that the family contains
**at most one** conforming member, so no edit carries a verifier from one valid record to another.

Every recorded byte-level fact — signing input, digest, and each cell of the verification matrix —
is recomputable from the record itself, and every `valid` label follows from S0–S3's decision
procedure, so a vector cannot claim something the bytes do not support.

## Non-goals

- Not a change to `canonicalDigest` or the signing input.
- **Not the anchor mechanism itself.** 015 establishes that a record MUST resolve to exactly one
  key state, evaluates the options and decides the shape; the field, its placement, its vectors and
  its migration are 016's, and S5 above states the composed rule as 016 left it.
- Not a rule about **which** state a key event is checked against — that is 003's (_The
  committed next key state_); this spec says only how a set is checked once a state is chosen.

## Open questions

- **Where S6's parse-strictness rule finally lives.** S6 binds it for signature-set records, which
  is where the need is provable. 012 raised moving it into 001 as a general convention, and that is
  probably right — a rule about how JSON becomes a record belongs with the serialization spec, not
  restated per record family. Half-answered already: 001's _Record kinds are non-confusable_
  requires closed schemas for **every** record kind, on the non-confusability argument rather than
  the digest-stability one. What is still stated only here is the duplicate-JSON-key rule (S6.1)
  and the digest-the-validated-record rule (S6.2), because both are about BYTES reaching a parser
  rather than about a schema, and 001 has no call-site vocabulary for them yet.
- **Sign-time anchoring versus signing "into the past".** _Anchoring_ decides that a record names
  the state that verifies it. That is not the same question as 008's: whether a stolen key may keep
  signing records dated into the past until they are revoked. An anchor names a state, not a moment,
  and a compromised key can name the state it belongs to. Anchoring narrows 008's window (a
  forgery must name a state whose keys the attacker holds) without closing it; 008's question
  stands.
- **Issuer re-signing around a revocation.** See _What this guarantees_: 008's digest-keyed
  revocation is not stable against the record's own issuer re-signing it. Whether the answer is
  issuer-scoped revocation, content-scoped revocation, or "revoke the link above it" as a matter of
  operator practice is left to 008.
- **The multi-signature wire profile.** This spec fixes the canonical form of a signature set
  inside a record. RFC 9421 request signing at threshold > 1 is a separate profile and a separate
  spec; it should adopt the same ordering discipline rather than mint a second one.

## Design notes

Non-normative. `@kinnet/crypto` is the reference implementation of S0–S6. A signing helper that
emits one signature per secret key it is handed cannot itself diagnose a caller that supplied more
signing keys than the intended threshold, so a producer is responsible for passing exactly the
conforming signer subset, in key-list order.

### Exactly the threshold

`m = t` makes a set larger than the threshold invalid even when every member verifies against a
distinct listed key in the right order. The case for the weaker `t ≤ m ≤ n` is not worthless — it
is simply outweighed. M-of-N is real (003 already carries `threshold`; the multi-signature profile
is the follow-on work), and a 2-of-3 committee where all three principals sign is an honest
artifact. Requiring `m = t` makes a record's validity depend on someone stopping the collection of
signatures at the right moment, and turns the choice of which surplus member to drop from a
preference into a correctness requirement on every producer. It also does not deliver digest
uniqueness on its own: a 2-of-3 state still admits three valid signer pairs, so `C(n, t)` records
remain possible either way.

What overrules that: permitting `m > t` leaves a hole the whole spec exists to close. A conforming
set of size `m > t` **stays conforming when a member is deleted** — the remainder still verifies,
is still distinct, is still in key order, and is still at least `t` long. So any passer-by holding
**no key at all** can strip a surplus signature and produce a second valid record with a different
digest. That is the same class of attack as the appended-junk bypass in _Context_, reached by
subtraction instead of addition, and it defeats revocation-by-digest in exactly the same way. A
rule that stops attackers adding bytes but not removing them has not made the digest stable; it has
made it stable against half the alphabet of edits.

The counter-arguments do not survive that:

- "It forbids ordinary co-signing" — it does not. **M-of-N is untouched: a 2-of-3 record still
  carries two signatures.** What is forbidden is carrying _more_ than the threshold requires, which
  authorizes nothing extra. A committee that collects three signatures for a 2-of-3 state has
  collected one more than its own policy asks for.
- "Choosing which surplus member to drop is now a correctness requirement" — the producer chooses
  which `t` keys sign, which it must do anyway; there is no second decision. `C(n, t)` records were
  already possible.
- "It does not deliver uniqueness on its own" — true, and irrelevant. It removes the only variant an
  **outsider** can produce, which is the variant that matters.

So "extras are rejected" means, precisely: a member beyond what the threshold requires; a member
that verifies against **no** listed key; a member satisfied by a key another member already
consumed; and a member that sits out of order. All four are invalid.

### Cost

The rule this spec replaces is a **search**: for each of `K` listed keys, ask whether _any_ of the
`S` signatures verifies under it — up to `K × S` verifications per state — repeated against up to
`E` committed states, so verification cost scales as `E · K · S`. Without an ordering rule the
search cannot be avoided, because nothing in the record says which key a signature belongs to.

At the schema maxima (`E = MAX_KEY_LOG_EVENTS = 128`, `K = MAX_KEY_EVENT_KEYS = 8`,
`S = MAX_RECORD_SIGNATURES = 8`) that product is `128 × 8 × 8 = 8192` for a **single** record
check. Two things that figure is **not**: it is not a measurement — it is the schema-maxima product
— and it is not what a conforming record costs, since an honest 1-of-1 link is on the order of two
verifications, `n` being 1 and the log two events. 8192 is the **ceiling an adversary can drive the
old search to**, the number that matters on genuinely pre-authentication paths such as participant
key-log resolution and discovery's signed first-write bootstrap, and never a typical cost.

The S3 walk changes the **shape** of that cost, not just its constant. Pairing becomes a single
forward pass that performs **at most `K` verifications per state** — one per listed key, regardless
of how many signatures the record carries. The signature count `S` is no longer a dimension of the
cost, and `K` drops from a multiplicand to the whole of it. Against every committed state that
would be at most `E · K`: 1024 at the maxima, a factor of `S` below the old search.

Anchoring removes the last factor, and 016 landed it. **`E = 1`**: a record is verified against
exactly one state, so a record check costs **at most `K` verifications** — 8 at the schema maxima,
against the former 8192 — beyond the issuer's log replay, which a verifier performs anyway. The two
changes are complementary: the walk removes `S`, the anchor removes `E`.

All of these are consequences of the rules, derived from the procedure under S3 and **not**
measurements. A verification interface that accepts runtime-sized key lists is not bounded by this
spec's `K` at all and needs its own ceiling; key-log replay is bounded here, so `E · K = 1024`
bounds it. A grant chain performs several checks per link (the link itself, plus revocation
candidates), and chain authorization remains attacker-influenced work even where it runs only after
the request has been authenticated and any replay check has passed — a valid signing key does not
earn an unbounded chain — so caller budgets remain necessary even though the per-state procedure is
linear — which is why concrete budgets have to be re-derived against the implementation that
enforces these rules rather than copied from the arithmetic here.

The cost argument is _why now_, not _why strict_: correctness alone settles the rule. But it is the
reason the rule cannot be bolted on after the multi-signature profile ships, because that profile
is what makes `S > 1` reachable in practice and would bake the search in.

## History

- 2026-08-08 — Accepted. A signature set holds exactly `threshold` members, each verifying against a
  distinct listed key in key order (S1–S3), checked before the record's digest is used (S4), and
  composing with the any-state rule by existential quantification (S5).
- 2026-08-08 — S0 added: a key state listing the same key twice is invalid, and S2's injectivity is on
  key value rather than list position. 003 gained the matching distinctness rule for `keys`.
- 2026-08-08 — S6 added: the duplicate-JSON-key, digest-the-validated-record and closed-schema rules,
  stated by 012 for `Conversation` only, generalized to every signature-set record.
- 2026-08-08 — _Anchoring_ added: the requirement that a record resolve to exactly one key state, the
  options analysis, and the proposal of 016 to specify the mechanism.
- 2026-08-10 — External security review: the keyless routes recorded under _What this guarantees_.
  003 adopted the intersection rule as the interim closure of routes 3 and 4, and 005 pinned strict
  RFC 8032 with low-order public-key rejection, on which the intersection rule's soundness depends.
- 2026-08-13 — 001 required closed schemas for every record kind, half-answering S6's placement
  question.
- 2026-08-16 — §Scope's scalar-`signature` enumeration completed with `ParticipantNode` and
  `MessageEnvelope` (010); the lifting rule was always meant to reach them.
- 2026-08-16 — S4 clarified: digest-keyed retention of an unverified record as a lookup key is
  permitted; assertion from the digest is not, until the set is checked.
- 2026-08-18 — Amended by 016: S5's existential over every committed key state became a lookup on
  the state a record's `anchor` names, closing routes 3 and 4 structurally and taking `E` to 1;
  003's intersection rule, and the pinned verification mode's second role as that rule's soundness
  prerequisite, were retired with it.

## References

- Spec 000 (placement test, Stage 0), 001 (JCS signing input; _Record kinds are non-confusable_),
  003 (_Events_ — key distinctness and the digest rule; _The committed next key state_; _Resolving
  the current key_; _No two states may share a quorum_; _Size limits_), 005 (suite; why signatures
  are not separately tagged; _Verification mode_ — strict RFC 8032 plus low-order public-key
  rejection; _Canonical encodings — one value, one text_), 008 (revocation by digest, any-state
  verification), 009 (chain verification, `MAX_RECORD_SIGNATURES` and the question it deferred),
  011 (bare-key issuers), 012 (digest as identity, threshold intent, parse strictness), 014
  (`leaves` uniqueness), 016 (record anchoring — amends this spec: the `anchor` field, S5's
  lookup, `E = 1`, and the retirement of the interim rule this spec's _Anchoring_ section argued
  for)
- RFC 8032 — Ed25519, deterministic signing
- ZIP-215 — Zcash's explicit Ed25519 validation criteria (the cofactored convention this spec
  names and does not adopt)
- RFC 8785 — JSON Canonicalization Scheme (array order is preserved, and therefore signed)
- Conformance vectors: `packages/crypto/test/fixtures/signature-set-vectors.json` (signature sets,
  and the log-shape vectors recording the retired intersection rule);
  `packages/crypto/test/fixtures/ed25519-verification-vectors.json` (verification mode);
  `packages/crypto/test/fixtures/record-anchoring-vectors.json` (the same cross-state routes as
  record-level rejections against the anchored state, 016)
