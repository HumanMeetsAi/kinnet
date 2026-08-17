# 005 — Signature suite & crypto agility

**Status:** Accepted
**Blocks:** the crypto primitives every signature depends on

## Context

The records need a concrete signing suite, and the system needs to be able to add suites later
(new curves, post-quantum) without a format break. Naming a curve does not settle it: the
verification mode has to be pinned as well, or independent verifiers disagree about which
records are signed.

## Decision

### Suite

- **Signatures:** Ed25519.
- **Hashing / ID derivation:** SHA-256 (002, 003).
- **Encoding & agility:** keys and digests are **multicodec-tagged** (`ed25519-pub` `0xed`;
  multihash for digests) and multibase-encoded. A new suite is a new codec, added alongside —
  never a reinterpretation of existing bytes. A `KeyRef` is therefore self-describing:

```
KeyRef    = multibase( multicodec(keyType) ‖ publicKeyBytes )
Signature = multibase( signatureBytes )
```

- **Signatures are not separately tagged.** A signature is never verified except against a
  key, so its suite is named by the verifying `KeyRef`'s codec; tagging the signature too
  would duplicate that and fail 000's no-thinner-form test (there is also no established
  multicodec signature registry to adopt — one would have to be minted). Multi-suite records stay
  possible: each signature pairs with a tagged key.

The same encoding lets a single key be expressed as `did:key` when handing out a raw key (002).

### Canonical encodings — one value, one text

Every encoded string in a record is part of that record's signed and digested bytes, so an
encoding that admits two textual forms for one value admits two records for one authorization. A
validator MUST therefore treat an encoded field as valid only when it is the **canonical** form of
a value the field admits:

1. **Decode** the text under the field's encoding, rejecting anything outside its alphabet or
   framing.
2. **Re-encode** the decoded bytes and require the result to equal the delivered text **exactly**.
3. Require the **decoded byte length** the field specifies — an exact length where the field names
   one (a `groupNonce` is 32 bytes), and at least one byte otherwise.

Steps 2 and 3 are independent and both are required. Alphabet-and-length checking is neither:
`z` followed by 32 `"2"`s matches the base58btc alphabet and the character window a 32-byte value
falls in, and decodes to **23 bytes**; unpadded base64url `"AB"` is one byte plus four bits that a
permissive decoder folds onto the byte `"AA"` encodes, and `"A"` ends no base64 quantum at all.

Re-encoding rather than enumerating deviations is deliberate: it needs no per-encoding catalogue
of the ways a form can be non-canonical, so an encoding whose quirks an implementation has not
enumerated is still held to exactly one form per value. Padded base64 is not a second form of the
house encoding — `=` is outside the alphabet — and base58btc's leading-`1` rule makes its mapping
injective in both directions, so for base58btc fields the rule bites as the length requirement.

**Breaking, and deliberately pre-wire-freeze**: it can only ever _reject_ inputs a lenient
validator accepted.

Conformance vectors for the canonical-encoding check are committed in `@kinnet/protocol`.

### Verification mode — strict RFC 8032 plus low-order public-key rejection

"Ed25519" does not name one verification function. Strict RFC 8032, ZIP-215 and libsodium
disagree about small-order points, non-canonical encodings and cofactor clearing, and they
disagree about specific signature/key pairs. Naming the curve alone would leave every downstream
determinism claim resting on whichever mode an implementation's library happened to default to,
so the mode is pinned here.

**This mode is RFC 8032 plus one addition, and the difference matters to anyone implementing
from the RFC.** Rules 2 and 3 below are RFC 8032 as written (§5.1.7 step 1 for the `S` range,
§5.1.3 for canonical point decoding). **Rule 1 is an addition this spec makes**, adopted from
libsodium and SBS-hardening practice: RFC 8032 §5.1.7 contains no low-order-public-key rejection,
and its step 3 explicitly endorses the **cofactored** equation `[8][S]B = [8]R + [8][k]A′`, which
accepts small-order public keys. So an implementer who reaches for a conformant RFC 8032 library
and stops will be **non-conforming to this spec**. Verifiers in wide use do import all 8 torsion
points as public keys and do accept a public key encoded as `y = 1 + p`; rule 1 closes the first
and rule 3 the second, and both must be implemented explicitly rather than inherited.

A conforming verifier MUST implement RFC 8032 verification **and** rule 1 below. Specifically, it
MUST reject a signature when any of the following holds, and MUST do so regardless of the
verifying library's default:

1. **The public key is a low-order (small-order) point.** All 8 points of the Ed25519 torsion
   subgroup MUST be rejected as public keys. They are well-formed `KeyRef`s — the encoding above
   checks length and multicodec tag only — so the rejection belongs to verification, not decoding.
   **This rule is not in RFC 8032**; see the paragraph above.
2. **`S` is not canonical**, i.e. not reduced: `S` MUST satisfy `0 ≤ S < L`, where `L` is the
   prime order of the base-point subgroup. A verifier MUST NOT reduce `S` mod `L` and continue;
   `S ≥ L` is a rejection.
3. **The public key or `R` is not canonically encoded**, i.e. its y-coordinate is not in `[0, p)`
   for the field modulus `p = 2²⁵⁵ − 19`. ZIP-215 decodes y in `[0, 2²⁵⁵)`; a conforming verifier
   MUST NOT.

**Cofactored / ZIP-215 acceptance is non-conforming.** A verifier that accepts any signature the
rules above reject does not conform to this spec, even though such a verifier is correct for
Zcash consensus, which is what ZIP-215 was written for.

**What the pin governs.** These rules bind **kinnet record and request signatures**: everything
verified against a `KeyRef` under 003's key-event logs, 004's discovery write-auth, 008/009/011/012's
records and chains, and RFC 9421 HTTP message signatures. They do **not** reach **MLS group
cryptography**. Spec 014's E2EE groups run RFC 9420 ciphersuite 1, whose signature scheme is also
Ed25519 and whose leaf keys 014 encodes as `KeyRef`s — but leaf, commit and proposal signatures are
verified **inside the MLS implementation**, in whatever mode that implementation uses, and an MLS
implementation is not obliged to offer a choice of mode. Bringing MLS signature verification under
this pin needs either upstream support or a verifier interposed at the implementation's crypto
boundary, and is a separate change. A consumer that interposes a conforming verifier into an MLS
implementation MUST prove interception for every verification path and establish that no API in
use constructs its own provider internally, re-derived against the depended-on version at every
upgrade (see _Design notes_). Nothing else in the protocol is exempt.

**Why this is normative and not a quality-of-implementation note.** Under cofactored verification
a signature of `R` = the identity point and `S` = 0 verifies under **every** small-order public
key, for any message, and involves **no secret key at all** — small-order points have no discrete
log to know, so this is not a forgery and nothing about it is infeasible. That makes one signature
verify under many distinct keys, which is precisely the case 003's "no two states may share a
quorum" rule excludes by assumption: its soundness argument counts surviving signature-set members
against a key intersection, and that count is only valid if a signature verifies under exactly one
key. 015's determinism and uniqueness properties inherit the same dependency. Both specs name this
pin as their prerequisite; with it in place, the assumption they rest on holds **under the pinned
mode**, which is the only sense in which it can hold.

**What this pin does not settle.** Rules 1–3 fix point decoding, the `S` range, and the treatment
of small-order public keys. They do **not** fix the form of the verification **equation**, which
rules 1–3 leave open. So two conforming verifiers that differ on the equation form could still
differ on adversarially-constructed inputs carrying a torsion component in `R`. Rules 1–3 are what
this spec pins; the equation form is left open rather than silently claimed, and closing it is a
separate change.

Conformance vectors covering all three rules, including the `R` = identity, `S` = 0 construction
against each of the 8 small-order keys and the record-layer case where one keyless signature
satisfies a 3-of-3 threshold under the forbidden mode, are committed at
`packages/crypto/test/fixtures/ed25519-verification-vectors.json`.

**The pin is breaking, and lands pre-wire-freeze for that reason**: it can only ever _reject_
inputs an unpinned verifier accepted, so no legitimate signature changes verdict, but a verifier
that follows a library default may accept records a conforming one refuses.

### Reference implementation (non-normative)

The reference implementation uses **`@noble/curves`** (Ed25519) and **`@noble/hashes`**
(SHA-256). Any library that implements the verification mode pinned above is conforming; which
library an implementation reaches for is not part of the protocol.

MLS runs in clients only (014). Spec 014 pins the MLS profile, and the runtime stays replaceable
behind RFC 9420 plus that profile. Because 014 makes every E2EE conversation an MLS group, no
pairwise protocol (X3DH / Double Ratchet) is adopted at all.

## Design notes

- Ed25519 + SHA-256 are fast, small, ubiquitous, and the defaults across did:key, COSE, and
  KERI.
- Multicodec tagging makes agility additive, which is the only realistic post-quantum migration
  path — new codecs can coexist with old signatures during a transition.
- Adopting an established MLS implementation rather than reimplementing it avoids the
  highest-risk crypto work and inherits years of review.

**Why the verification mode has to be pinned rather than inherited.** Ed25519 verifiers differ in
whether they accept a non-canonical `S`, a non-canonically encoded point, or a small-order public
key, and the differences show up on specific signature/key pairs — so two verifiers that both
call themselves Ed25519 can disagree about whether a record is signed. Pinning the mode is what
makes "the signature verifies" a statement about the bytes rather than about the verifier. Two
properties of unpinned verification are worth knowing when reading rule 1. First, under a
cofactorless equation with no small-order rejection, acceptance of a small-order public key
requires the key's order to divide the scalar derived from the message, so whether a given
small-order key accepts a given message depends on the message: any single acceptance count for
such a verifier is a sample, not a property of the implementation. The identity key is the
exception — it accepts every message, with no variance, which is the operationally important
case. Second, a library flag named after ZIP-215 is not a reliable proxy for rules 1–3: such a
flag may govern point decoding and small-order rejection (rules 3 and 1) while leaving the
verification equation unchanged. `@kinnet/crypto` is the reference implementation of the pinned
mode and exposes no way to override it; `@kinnet/protocol` is the reference implementation of the
canonical-encoding check.

**Interposing a conforming verifier in an MLS implementation.** Where an MLS implementation
accepts an injectable crypto provider, bringing its signature verification under this pin takes
more than covering each verification call site. Proving interception per path is necessary but
not sufficient, and the gap is not another path: an API that constructs a **fresh** provider
internally — rather than using the caller's — runs a stock verifier however carefully the caller
built its context, and per-path proof is structurally incapable of detecting that, because a path
proved through an injected provider says nothing about a code path that builds its own. The
obligation is therefore twofold: prove interception for every verification path **and** establish
that no API in use constructs its own provider internally. Both limbs are version-specific, and
completeness of a verification-path enumeration is not something libraries publish as a contract,
so a consumer that interposes has to re-derive both against the version it actually depends on, at
every upgrade, per the rule above. A shim that covers some paths while looking complete is worse
than none.

**Rule 1 has no upstream source.** Rules 2 and 3 compose RFC 8032 directly. Rule 1 is **minted
here**: no existing standard states it, because RFC 8032 endorses the cofactored equation and
therefore admits small-order public keys. It is not invented from nothing — it is the rejection
libsodium performs and the property the SBS/non-repudiation literature calls for — but this spec
is its normative source, which matters to anyone tracing the rule back to a standard and finding
none. What is bought with it is a soundness dependency that 003's quorum rule and 015's
uniqueness property cannot otherwise discharge.

## Open questions

- AEAD/KEM for the zero-knowledge at-rest backup of root keys.
- Post-quantum suite selection (additive when it comes).

## History

- 2026-08-08 — Verification mode pinned (strict RFC 8032 plus low-order public-key rejection),
  with conformance vectors; previously the spec named the curve and left the mode to the
  verifying library. Breaking in one direction only: it can only reject inputs an unpinned
  verifier accepted. The pin's scope over MLS group signatures is stated at the same time.
- 2026-08-13 — Canonical-encoding rule added (decode, re-encode, require exact textual equality,
  require the field's decoded byte length), after an external security review (2026-08) found
  validators disagreeing about which textual forms of one value to accept.

## References

- RFC 8032 — EdDSA (Ed25519); §5.1.7 verification
- ZIP-215 — Explicitly Defined Validity Criteria for Ed25519 Signatures (the mode this spec
  forbids, and why it exists: Zcash consensus)
- RFC 9420 — Messaging Layer Security (MLS)
- Signal — X3DH, Double Ratchet
- noble cryptography; multiformats multicodec
