# 002 — Participant ID derivation

**Status:** Accepted
**Blocks:** every identity; referenced by every other record

## Context

A participant ID must be **self-certifying** (anyone can check the ID matches a key with no
lookup) and **stable forever** (it must survive key rotation, or rotation would cost the
identity and all its relationships). These two requirements point at one well-understood
construction, and the exact recipe — hash, encoding, length — is unchangeable once IDs exist,
so it has to be pinned now.

## Decision

The participant ID is a **self-addressing identifier derived from the inception event's
establishment data**, not from the current key — and not from a bare key at all.

```
id = "pk_" + multibase_base58btc( multihash( sha2-256, UTF8( JCS( inceptionData ) ) ) )
```

- **inceptionData** is the inception event's establishment data (003): the event's
  `{ seq: "0", kind: "icp", keys, threshold, next }` fields — i.e. the inception `KeyEvent`
  minus its `id` (which would be circular) and `signature` fields — canonicalized per 001.
  The ID binds to inception, so rotating the active key never changes the ID.
- A single-key person is the **degenerate case** (`keys` of one, `threshold` `"1"`); an
  organization's M-of-N inception uses the same recipe with no special casing. One rule, no
  fork between person and org IDs.
- Because `next` is part of the establishment data, the ID also **commits to the first
  pre-rotation**: even an attacker who later steals the inception private key cannot mint a
  divergent log under the same ID, because the ID already pins the next-key commitment. That
  commitment covers the next key **state** — the ordered key list _and_ its threshold (003) — so
  the ID pins how strongly the first rotation must be signed as well as which keys may sign it.
  The adversary that clause defends against is a different one from the sentence before it: the
  inception-key thief cannot rotate at all, holding no next key, whereas a holder of _some but
  not all_ of the next keys does hold material the first rotation needs. Pinning the threshold is
  what stops that holder revealing the committed set at a threshold they alone can satisfy.
- **multihash** (`0x12 0x20 ‖ digest`) makes the hash function self-describing, so a future
  move to e.g. BLAKE3 is additive, not a format break.
- **multibase base58btc** (prefix `z`) gives a compact, URL-safe, copy-pasteable string.
- The `pk_` prefix is a human-facing namespace marker only; the bytes after it are the
  multibase value.

Example: `pk_zQ3shaf7…` (the full digest; UI may truncate for display only).

### Verifying an ID

Given an ID and a candidate **inception event**, recompute the multihash over its
establishment data and compare. That proves the **ID ↔ inception** binding locally, with no
network. Proving the **current** signing key requires replaying the key-history log (003); the
ID alone does not name the current key. The inception event is self-contained and is the first
entry of the log discovery serves, so a resolver always has it in hand.

## Design notes

- Hash-of-inception-event is the KERI **AID** model: self-certifying _and_ rotation-stable. A
  raw-key identifier (like `did:key`) is self-certifying but **cannot rotate** — it _is_ the
  key — which is disqualifying here.
- Hashing the bare inception key — the obvious alternative — could not represent M-of-N
  inception, would not commit to pre-rotation, and would force a second recipe for
  organizations. Hashing the establishment data fixes all three for the cost of canonicalizing
  one small object.
- multihash/multibase/multicodec make hash and encoding agility a tag change, not a migration.
- Full 32-byte digest: no truncation. Truncation trades collision resistance for a shorter
  string the protocol does not need, since display truncation is a UI concern.

## Relationship to DIDs

This ID is **not** `did:key`. External DID interop is a _projection_ of the identity and a
separate, deferrable decision: expose the ID under a custom `did:pn:<id>` method (or align
with did:webs/KERI) when an external system needs it. The method name is reserved
brand-neutral now (000: wire identifiers are brand-neutral) but is **not** registered: `pn`
MUST NOT be used as a DID method until it is registered with the W3C DID method registry, since
an unregistered method name that collides is an interop break of this protocol's own making.
When handing out a single _key_ (not the identity), that key may be expressed as `did:key`
using the same multicodec key encoding (005).

## Open questions

- Final spelling of the `did:pn` method (or adopt did:webs).

## References

- KERI — Self-addressing identifiers (AIDs) and inception events
- W3C DID Core; did:key; did:webs
- multiformats: multihash, multibase, multicodec
