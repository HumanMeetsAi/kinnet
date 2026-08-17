# 001 — Canonical serialization

**Status:** Accepted
**Blocks:** every signature in the system

## Context

Every Kinnet record is signed, and a signature is over _bytes_. If two runtimes serialize the
same record to different bytes, they compute different signatures and verification fails. So
before any record can be _actually_ signed and verified, there must be exactly one byte
representation of a given record — a canonical serialization — that every implementation
agrees on.

## Decision

Sign over the **JSON Canonicalization Scheme (JCS, RFC 8785)** of the record.

- The signing input is `UTF-8( JCS( record without its signature field ) )`.
- The `signature` (or `proof`) field is **detached**: excluded from canonicalization, then
  attached to the record afterward. Verification strips it, re-canonicalizes, and checks.
- JCS fixes, deterministically: object keys sorted by UTF-16 code unit, no insignificant
  whitespace, and ECMAScript-compatible number formatting.

### Example

Record as authored (key order and spacing irrelevant):

```json
{ "type": "person", "id": "pk_z6Mk…", "displayName": "Bob Tan" }
```

Canonical signing input (sorted keys, minimal separators):

```
{"displayName":"Bob Tan","id":"pk_z6Mk…","type":"person"}
```

The signature is computed over the UTF-8 bytes of that string and attached as `signature`.

### Number rule (the JCS footgun)

JCS canonicalizes numbers via the ECMAScript number-to-string algorithm, which is only safe
for IEEE-754 doubles. To avoid cross-runtime ambiguity:

- **No floats in signed records.** Timestamps are RFC 3339 strings (already the convention).
- Integers that may exceed 2^53 (counters, sizes) are encoded as **strings**, not numbers.
- Treat signed records as I-JSON (RFC 7493).

### Record kinds are non-confusable

The signing input above is the record's fields and **nothing else**: it does not commit to what
kind of record they are. `canonicalDigest` has no domain separation between record kinds, so
nothing in the bytes distinguishes a Claim from a Relationship — only the schema a verifier
happens to validate against does.

Therefore: **distinct record kinds MUST NOT cross-validate.** For every pair of record kinds this
protocol defines, an instance of one MUST be rejected by the other's validator. Two properties
give this, and an implementation MUST have both:

- Every record schema is **closed**: a record carrying a key the schema does not define is
  invalid, not silently stripped (015 S6.3 states this for signature-set records; it holds for
  every record kind, and for the same reason).
- Each kind's required field set is **distinguishable** from every other kind's. Where two kinds
  would otherwise overlap, one of them carries a structural discriminator.

Without the first property, two open schemas each strip what they do not define, so a single
object carrying the union of two field sets parses as both — and one signature over one digest
authorizes two different records.

**The enforcement is a committed conformance test, not this paragraph.** Committed vectors carry
one shape-valid instance of every record and payload kind
(`packages/protocol/test/fixtures/record-kind-vectors.json`); over the full cross product, each
instance validates under its own schema and is rejected by every other. A conforming
implementation's record kinds MUST all appear in those vectors. No pair of the record kinds this
protocol currently defines
cross-validates, and no kind needs a discriminator.

A signed `type` discriminator per record — the stronger fix, which would give the digest itself
domain separation — remains the open question below rather than the rule: it changes every record's
bytes, and closure by disjoint field sets is what the committed test can enforce today.

## Design notes

- The trust layer adopts **SD-JWT / W3C VC** and identities can be projected as **did:\***,
  both JSON-shaped — JCS keeps the whole system in one serialization world.
- JCS output is human-readable, which keeps records inspectable by hand.
- It is a stable, narrow RFC with implementations across runtimes.

## Alternatives considered

- **dag-cbor (deterministic CBOR, RFC 8949 §4.2).** More compact, ideal for
  content-addressing, and what KERI/IPLD use. Rejected as the _default_ because it pushes
  everything out of the JSON/VC/did ecosystem and is harder to inspect. May be added later as
  an optional wire profile for size-sensitive transports (see open questions).
- **Protobuf canonical / SignedBytes.** Schema-coupled and not self-describing; worse fit for
  an open, evolving record set.

## Open questions

- An optional CBOR profile for large binary payloads (media, files), kept signature-compatible
  by signing the same logical fields.
- Whether to adopt a `proof` object (VC Data Integrity style) instead of a bare `signature`
  string, for multi-signature and suite metadata. Leaning yes for org M-of-N (see 003/005).
- Whether the digest should carry **domain separation** by record kind — a signed `type` field, or
  a kind label mixed into the hash input — so that a record's digest commits to what the record
  is. _Record kinds are non-confusable_ above closes the reachable half by making the schemas
  disjoint and closed; it does not make the BYTES self-describing, which is what a digest-level
  separator would do.

## History

- 2026-08-13 — Added _Record kinds are non-confusable_: distinct record kinds MUST NOT
  cross-validate, obtained through closed schemas and distinguishable required-field sets, with
  committed cross-product conformance vectors. Added following an external security review
  (2026-08).

## References

- RFC 8785 — JSON Canonicalization Scheme
- RFC 7493 — I-JSON
- RFC 8949 §4.2 — Deterministically Encoded CBOR (the alternative)
