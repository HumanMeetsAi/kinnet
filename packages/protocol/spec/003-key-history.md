# 003 — Key-history log (KERI-lite)

**Status:** Accepted
**Blocks:** rotation, recovery, and ID→current-key resolution
**Amended by:** 011

## Context

The ID binds to the inception event (002), but the _active_ signing key must be able to rotate —
on compromise, on upgrade, or on a transfer of organization ownership — without the identity
or its relationships moving. A verifier therefore needs a trustworthy way to go from an ID to
the **current** key. That is a key-history log: an append-only, signed record of key state.

## Decision

Each participant has an **append-only, hash-chained, signed key-event log**, KERI-lite, with
**pre-rotation**.

### Events

```
KeyEvent {
  id:        ParticipantId      // the participant (002); fixed across the log
  seq:       string             // "0" = inception, then "1", "2", … (string per 001)
  prior:     string | null      // multihash of the previous event; null at inception
  kind:      "icp" | "rot"      // inception | rotation
  keys:      KeyRef[]           // current signing key(s)
  threshold: string             // e.g. "1" or "2" (of N) for organizations
  next:      string             // multihash commitment to the NEXT key STATE (pre-rotation)
  signature: Signature[]        // signed per threshold (see 005)
}
```

- **Inception (`icp`, seq 0)** establishes the inception key set; its establishment data
  (`seq`, `kind`, `keys`, `threshold`, `next` — the event minus `id` and `signature`) is
  exactly what the ID hashes (002). It commits to the next key **state** via `next` but does
  not reveal it. An inception's own `threshold` is self-declared, which is what inception
  means: there is no earlier event to constrain it, and the ID hashes the result.
- **Rotation (`rot`)** reveals the previously-committed key state — its `keys` **and** its
  `threshold` must together reproduce the prior event's `next`, per _The committed next key
  state_ below — is signed by the **newly revealed** key set at that committed threshold, and
  commits to a new `next`. The hash chain (`prior`) makes the log tamper-evident. Signing with
  the newly revealed keys rather than the outgoing ones is KERI semantics: continuity is already
  proven by the pre-rotation commitment, and signing with the new keys is what lets a participant
  whose active key was stolen or lost still rotate — the whole point of pre-rotation. Requiring
  the outgoing keys to sign would make a lost active key unrecoverable.
- An event's `keys` list MUST NOT contain the same `KeyRef` twice. A repeated key is meaningless
  under threshold semantics — a key can only ever count once — and it is actively dangerous: a
  verifier pairing signatures against key _positions_ rather than key _values_ would let one
  signature satisfy a threshold of two. This is a **validity** rule at the record layer, like the
  size limits below: a validator built from this section alone MUST reject such an event, not only
  a replay implementation.
- An event's digest (for `prior` chaining) is the multihash of the JCS of the **complete
  signed event**, signatures included. Because the signature array is inside the digested
  bytes, the array itself must be canonical: **015** requires an event to carry exactly its
  threshold in signatures, every one verifying against a distinct listed key, in key order, and
  requires that check to precede any use of the digest.

### The committed next key state

**The pre-rotation commitment covers the next key _state_ — its ordered key list and the
threshold that state will require — not the key list alone.**

```
next = multihash( JCS( { keys: KeyRef[], threshold: string } ) )
```

A rotation MUST reproduce that commitment exactly:

```
commit(event.keys, event.threshold) == prior_event.next
```

So a rotation's `threshold` is **not the rotating party's to choose**. It was fixed one event
earlier, by whoever held the state now being retired. Combined with 015's `m = t`, a rotation
carries exactly the number of signatures the _previous_ event demanded, from exactly the keys
the previous event named.

**A participant therefore chooses its next threshold when it commits, not when it rotates.** To
move from 1-of-1 to 3-of-3, the event before the change commits `{keys: [K₀,K₁,K₂],
threshold: "3"}`, and the rotation that reveals that set must declare `"3"` and carry three
signatures. Threshold changes have a one-event lead time. This is the whole of the mechanism;
an implementation that enforces the commitment equality above and 015's `m = t` has implemented
it, and there is no second rule to discover.

Committing the threshold, rather than the key list alone, is what makes "the event's own
threshold" and "the threshold the prior event required" name the same number; _Design notes_ sets
out the two properties a rotation must have and why no signature count can deliver both if the
threshold is self-attested.

#### What a record-layer validator can and cannot decide

This split is normative, and stating it is half the point of this section.

A record-layer validator sees **one event in isolation**. It therefore enforces 015's `m = t`
against the event's own `threshold` — a **necessary** condition on every key event, inception and
rotation alike, and a sound one, because for a rotation that declared threshold is the committed
threshold.

Two limits follow from that, and they have different causes. A **record-layer** validator checks
shape and counts and performs no curve operation, so S2 and S3 — every member verifies, under a
distinct key, in key order — are simply not its to decide. And **no** validator holding a single
event, however much work it does, can decide that the declared threshold is the committed one,
because that needs the prior event's `next`. So such a validator is entitled to conclude:

- **Yes:** _"this event lists no key twice, declares a threshold within its own key count, and
  carries exactly that many signatures"_ (015 S0 and S1).
- **No:** _"those signatures verify"_ (S2, S3) — that requires the signing input and the curve.
- **No:** _"this rotation was authorized."_ That requires the prior event's `next`, which one
  event does not contain.

The commitment equality is therefore a **log-level** validity rule, like the quorum rule below:
a replay MUST enforce it, and a record-layer validator cannot. An implementation that validates
key events but never replays a log **will accept a rotation revealing a key state the prior event
never committed**, including the single-member takeover set out in _Design notes_. Key events are
not independently checkable records, and anything that treats them as such is incomplete.

### No two states may share a quorum

A log's events are not independent: **records verify against any state the log ever committed**
(008, 012), so every pair of committed states is simultaneously live for verification purposes.
That makes overlap between them a validity question rather than a matter of taste.

A conforming log MUST satisfy, for **every pair** of key states `A`, `B` it commits — not merely
consecutive ones, since the any-state rule makes every pair reachable:

```
|keys(A) ∩ keys(B)| < min(threshold(A), threshold(B))
```

In words: **no two key states of one log may share enough keys to satisfy the lower of their two
thresholds.** A replay MUST reject a log that violates this, and MUST do so as a log-level check
after each event's own structure is validated — it is a set intersection over already-bounded key
lists, so it costs nothing next to the signature work.

**Why.** An attacker who holds no key can still delete and rearrange the members of a signed
record's signature array. Every member that survives such an edit verifies under a key one of the
original signers held — a key of the state the record was signed against. For the edited record to
verify against a _different_ state, each of its members must verify under a distinct key listed
there too, so those keys lie in the intersection of the two states, and there must be at least that
state's threshold of them. **The attack exists exactly when two states share a quorum.** Forbidding
that closes it: an edit can never land in another state, so a record that verifies at all verifies
against exactly one committed state, and no keyless edit of it verifies anywhere.

**What this does not give you.** It is a real restriction on rotation, and an operator should learn
it here rather than by hitting a rejection:

- A **1-of-1** rotation is unaffected — it shares zero keys, which is what makes it a rotation.
- A **3-of-5** may retire three keys and retain two: `2 < 3`.
- A **2-of-3 may retain at most one key.** Retiring one compromised key and keeping the other two
  shares two keys against a threshold of two, and is **illegal**. There is no way to both keep a
  quorum of old keys across a rotation and close the attack above — those are the same
  configuration described twice. Restoring that flexibility needs record anchoring (015), which
  binds a record to one named state and so removes the reason the rule exists.
- **The rule is deliberately conservative, and rejects some logs that admit no attack.** It tests
  key sets and thresholds, not reachability, so it refuses configurations that are in fact safe.
  The clearest case is **any `1-of-n` state**: with `t = 1` a conforming record carries exactly one
  signature, so there is nothing to delete and nothing to reorder and no edit exists — yet
  `[K₀,K₁] t=1 → [K₁,K₂] t=1` shares one key against `min(t) = 1` and is rejected. A log that
  re-reveals its own current key set is likewise illegal, though the pre-rotation commitment alone
  would permit it. Over a universe of five keys, states being ordered key lists of at most three
  keys with every threshold and pairs unordered, roughly a fifth of the state pairs the rule
  rejects admit no attack in either direction, and four fifths of those are the `t = 1` case.
  Over-refusal is the right failure direction for an interim rule; a precise rule would have to
  reason about which subsets are reachable in which order, which is exactly the complexity
  anchoring removes.

**Soundness basis, stated exactly.** This rule rests on the assumption that **a signature verifies
under exactly one key**. The counting argument above says each surviving member verifies under a
key its original signer held; if one signature verified under two distinct listed keys, a member
could satisfy a key outside the intersection and the argument fails. That is the **same**
assumption a blanket ban on key reuse would rest on — no weaker — and it is an assumption about
Ed25519 rather than a structural property of the record. Anchoring (015) needs no such assumption,
which is why this rule is an interim measure and anchoring is the real fix.

**The assumption holds only under a verification mode that rejects low-order public keys, and 005
pins one.** This is a hard prerequisite of the rule above, not a footnote. Under cofactored
(ZIP-215) verification a signature whose `R` is the identity point and whose `S` is zero verifies
under **every** small-order public key, for any message, so one such signature could satisfy
several distinct listed keys and the counting argument fails. 005's _Verification mode_ section
therefore requires low-order public-key rejection explicitly, with committed conformance vectors
at `packages/crypto/test/fixtures/ed25519-verification-vectors.json`. A verifier that ignores that
pin and uses its runtime's cofactored default breaks this rule's soundness argument, and does so
silently, because every record an honest issuer ever published still verifies for it. _Design
notes_ states what that mode rejects and why RFC 8032 alone does not supply it.

### Resolving the current key

Replay from inception: check the hash chain, that each rotation reproduces the prior event's
pre-rotation commitment (_The committed next key state_), that each event satisfies its own
threshold, that seq is contiguous, and that no two committed states share a quorum (above). The
latest event's `keys` are the **current** signing keys. This is what discovery serves and what
verifiers cache.

**The state an event is judged against is the state the event carries** — its `keys` and its
`threshold`. For a rotation those are the prior event's committed values, because the commitment
check above has already established that they reproduce `next`; for an inception they are what
the participant ID hashes (002). There is one candidate state per event and no ambiguity about
which one applies. Order matters: a replay MUST establish the commitment **before** treating the
event's declared threshold as authoritative, since an unchecked rotation can declare anything.

"Satisfies the threshold" means what **015** defines: the event's signature set is checked as a
canonical signature set against the key state in question, and carries **exactly** that state's
threshold in members — not merely at least it. 015 also fixes the admissible threshold domain — a
decimal `^[1-9][0-9]*$` whose value is at most the state's key count — so an event declaring a
threshold above its own key count is invalid, not merely unsatisfiable.

### Size limits

A verifier reaches a key log before it has authenticated anything: spec 004's first-write
bootstrap resolves the writer's keys from the log carried in the request body, and a verifier
reaches an issuer's log from a header. Replay cost is therefore an unauthenticated caller's
choice unless the shape is bounded. Under 015's canonical signature-set rule, threshold
checking performs a greedy walk bounded by the listed keys, but an unauthenticated caller still
chooses both the number of events and the keys in each event.

A conforming implementation MUST reject a key event or log outside these bounds:

| Bound                      | Value | Applies to                         |
| -------------------------- | ----- | ---------------------------------- |
| `MAX_KEY_EVENT_KEYS`       | 8     | entries in one event's `keys`      |
| `MAX_KEY_EVENT_SIGNATURES` | 8     | entries in one event's `signature` |
| `MAX_KEY_LOG_EVENTS`       | 128   | events in one log                  |

It MUST also reject an event whose `signature` count exceeds its `keys` count. Under threshold
semantics a signature can only ever count once, against one of the event's own keys, so a
larger set is meaningless. Spec 015 also requires a conforming signature set to carry exactly
the state's threshold in members, and its S3 ordered greedy walk performs at most one curve
verification per listed key. A conforming event therefore costs at most `keys` verifications,
and a whole conforming log at most
`MAX_KEY_LOG_EVENTS x MAX_KEY_EVENT_KEYS` = `128 x 8` = 1024. An implementation may apply the
width guards on an inception and on a rotation before participant-id hashing, key decoding, or
curve work; that is early enforcement of the bounds above, not another rule.

Rationale for the values. 8 keys admits an M-of-N committee far larger than any this protocol
anticipates. 128 events is roughly a decade of monthly rotations, and a log is append-only, so
this is the bound that decides how long an identity may live before it can no longer record a
rotation — it is deliberately generous and deliberately finite, because "grows for the life of
an identity" and "replayed by strangers" cannot both be unbounded.

The three LENGTH checks MUST be applied **before** the elements are validated. A validator
that reports the length violation but still parses every element makes rejecting an over-long
log more expensive than replaying a legal one, which inverts the purpose of the bound. The
signature-to-key ratio rule MAY be checked afterwards, because by then both arrays are already
bounded to 8 and the comparison is free.

All four rules are **validity** rules and belong at the record layer, not only in a replay
implementation: a validator built from this section alone MUST reach the same verdict as one
built from the replay rules above. Conformance vectors pin each bound accepted at its maximum
and rejected one past it, and pin the ratio rule.

Implementations MAY additionally cap the verification work one replay performs. Such a cap is
a local resource policy, not a validity rule: a log within the bounds above is valid, and an
implementation that refuses it for cost MUST say so distinguishably from "invalid", so a
publisher is not told to fix a log that is already correct.

## Pre-rotation is the security property

The next key set is committed (by hash) one event ahead and kept offline until used. So even
an attacker who steals the _current_ key cannot rotate control to their own key — they do not
hold the pre-committed next key. Compromise of the active key is recoverable; it is not game
over.

Because the commitment also fixes the next **threshold** (_The committed next key state_), the
property survives partial compromise of the next set: an attacker holding fewer than the
committed threshold of the next keys cannot rotate either, and cannot lower the bar to the
number of keys they do hold. Without it, one key of a committed M-of-N set would be enough.

## Custody of the next key set

Pre-rotation is only as strong as the **separation** between the active key and the
pre-committed next keys. If both live on the same device — or in the same backup under the
same protection — an attacker who compromises one holds both, and pre-rotation adds nothing.
The custody profile is therefore part of the spec, not a deployment detail:

- **Organizations (full-strength profile):** next keys are generated in a key ceremony and
  held offline (hardware token or air-gapped store), separate from the active admin keys.
  Recommended wherever an organization's key state is relied on by third parties.
- **People (consumer profile):** the active root key lives on-device (secure element where
  available); the next key is generated at inception and stored **only** in the
  passphrase-locked encrypted recovery backup — never on a daily device. Compromising the
  device yields the active key but not the next; compromising the backup yields ciphertext
  without the passphrase. Recovery from device compromise: restore the next key from backup,
  rotate, re-commit.
- **Honest degradation:** where a deployment cannot split custody (single device, no
  passphrase), pre-rotation degrades from compromise-_recovery_ to tamper-_evidence_, and the
  threat model must claim only the weaker property.

## Boundaries (what this is and is not)

- **Identity/root keys** live in this log. **Device subkeys** do **not**: device subkeys are
  key-audience grants (011), revocable on their own, and are not a rotation event. Losing a
  device revokes its grant; it does not rotate the identity. _Amended by 011: device
  subkeys were a `DeviceKey` record; 011 replaced them with key-audience grants._
- **Organization ownership transfer** is a rotation to the new owner's key set at the threshold
  the outgoing owner **committed** for it (_The committed next key state_) — identity, members,
  and history persist. The outgoing state is what sets the bar: a transfer cannot be authorized
  more weakly than the party handing over decided, and the incoming owner cannot restate it. A
  pluggable policy (single, M-of-N, and later weighted/DAO) decides who holds the keys that sign
  a rotation; the log records the result either way.

## Open questions

- Full KERI witnessing / receipts (duplicity detection across witnesses) — deferred; this
  version resolves logs from a discovery registry rather than a witness set.
- Recovery flows (social recovery for people, admin-quorum + timelock for orgs) — layered on
  top later; the log shape already supports a threshold rotation.

## Design notes

**Why the commitment covers the threshold, not the key list alone.** A rotation must have two
properties: it must be **authorized** by the outgoing policy, and it must **prove possession** of
the incoming one. If the commitment covered only the key list, the threshold a rotation is judged
against would be self-attested, and — under 015's `m = t`, where an event carries exactly one
signature count — neither answer to "which threshold applies" delivers both properties.

Judging a rotation against the threshold the event itself declares allows a takeover by one
committee member. An attacker who holds ONE private key of a multi-key committed next set — one
member of an M-of-N committee, who also knows the set's public keys — reveals that committed set
at `threshold: "1"`, signs once, and takes sole control of the identity. The reveal matches a
key-list-only commitment, and nothing else refuses it: the quorum rule compares key sets, and a
rotation to a disjoint set shares nothing. The effective authorization for **any** rotation would
then be one signature from any one committed key, whatever the committee's size — precisely the
guarantee M-of-N exists to provide.

Judging it against the prior event's threshold blocks that attack, since that number is not
attacker-chosen, but it leaves a threshold **raise** under-authorized: a 1-of-1 committing a
three-key next set would rotate into a 3-of-3 on **one** signature, and two of the three
principals would never demonstrate possession of a key the state now depends on.

Each answer preserves one of the two properties and no single signature count delivers both, which
locates the defect in the commitment rather than in how it is read. Committing the threshold gives
both properties at once and makes the question moot: the state the event carries _is_ the state
the prior event committed, so "the event's own threshold" and "the threshold the prior event
required" name the same number and can no longer disagree. KERI, which this spec cites as its
basis, has the same rule: a KERI establishment event commits a next threshold alongside the next
key digests, and a rotation must satisfy both it and the event's own signing threshold. Widening
the commitment was preferred over layering a second rule over the old one: a commitment that
under-specifies what it commits to cannot be repaired from outside.

**What the pinned verification mode rejects.** _No two states may share a quorum_ depends on a
signature verifying under exactly one key, and that holds only under a verification mode that
rejects low-order public keys. Under cofactored (ZIP-215) verification, a signature whose `R` is
the identity point and whose `S` is zero verifies under **every** small-order public key, for any
message; all eight canonical small-order points accept it, and all eight encode as well-formed
`KeyRef`s. **No secret key is involved** — small-order points have no discrete log to know — so
this is not a forgery and nothing about it is infeasible. Rejecting all eight requires an explicit
low-order public-key rejection, which **RFC 8032 does not mandate**: its §5.1.7 step 3 endorses
the cofactored equation, so a conformant RFC 8032 verifier still accepts small-order keys. 005's
_Verification mode_ section requires the rejection as an addition to RFC 8032 rather than a
reading of it. Severity is bounded in any case: exploiting the gap requires the issuer's own key
state to list two or more small-order keys — a state only that issuer can publish, and an issuer
willing to publish it could set `threshold: "1"` and achieve the same effect directly. It is
self-harm rather than an outsider attack. What it means for this spec is that the quorum rule's
guarantee is conditional on 005's pinned mode in a way an implementer reading that section alone
would otherwise not discover, which is why the dependency is written down there.

**Reach of M-of-N today.** 004 restricts request signing to threshold-1 key states, so a
participant whose current key state has a threshold above 1 cannot perform discovery writes at
all. That restriction is incidental to write authentication rather than a defence against
under-authorized rotation: it does not cover verifiers that replay a log obtained by any other
route, and it disappears when the restriction is lifted. Committing the threshold is what makes
M-of-N safe to publish once it is.

## History

- 2026-06-12 — A rotation is signed by the newly revealed key set rather than by the outgoing one,
  so a participant whose active key is lost or stolen can still rotate.
- 2026-08-07 — The size limits became validity rules at the record layer, and a refusal on cost
  grounds became distinguishable from a verdict of invalidity.
- 2026-08-08 — Added: an event's `keys` list MUST NOT repeat a `KeyRef`; no two key states of one
  log may share a quorum; and the quorum rule's dependency on 005's pinned verification mode.
- 2026-08-09 — The pre-rotation commitment was widened from the next key list to the next key
  **state**, ordered keys plus threshold, so a rotation's threshold is fixed one event ahead;
  every event digest and participant ID derived under the earlier commitment changes.
- 2026-08-11 — The replay-cost bound was restated in terms of 015's canonical signature sets.

## References

- KERI — key event logs, establishment events, pre-rotation
- Spec 002 (ID derivation), 005 (signature suite / KeyRef encoding)
