# 007 — AssetRef

**Status:** Proposed
**Blocks:** files, media, and attachments across every module

## Context

Modules need files: a library doc, an event flyer, an image on a board post, a message
attachment, a member's portfolio on their portable profile. The blob itself is just bytes and
can live anywhere (the node's store, a relay), but a **reference** to it must travel between
participants with integrity — and the same reference shape is needed in every module, in
messages, and in profiles. That recurrence and that cross-the-wire integrity requirement are
what earn it a place in the protocol (placement test #1, #2, #7).

## Decision

Add a single thin primitive: a **content-addressed pointer** to a blob.

```
AssetRef {
  hash:      string        // multihash of the blob — the content address (002/005 encoding)
  mediaType: string        // e.g. "application/pdf", "image/png"
  size:      string        // bytes (string per 001's number rule)
  locations: string[]      // fetch hints (node endpoints, relays); advisory, not identity
  createdAt: string        // RFC 3339
}
```

- **Content-addressed:** the `hash` _is_ the identity of the asset, so integrity is
  self-verifying — fetch from any `location`, hash it, compare. A hostile host cannot
  substitute content.
- **Location is advisory:** where to fetch is a hint, not a trust dependency — same principle
  as discovery records being portable across servers.
- **Encryption:** for private/E2E assets the blob is encrypted; the key is shared over the
  existing message channel (like any message key), **not** carried in the `AssetRef`. The node
  or relay stores ciphertext it cannot read.

## Why a primitive (and the thinnest one)

- It is referenced everywhere — every module item, every message attachment, every profile
  portfolio — so independent implementations must agree on it to interoperate (#1).
- It is a generic pointer, not a `Document` or `Image` type (#2, #7). The semantic type lives
  in the referring item's schema (a library item _has_ an `AssetRef`); the protocol only fixes
  hash + locator + integrity.
- **No signature field** (#7). Integrity comes from the content hash, and attribution comes
  from the signed record that carries the ref — an `AssetRef` never travels bare. A standalone
  signature would duplicate both.
- Assets referenced from a member's **portable profile** become portable exactly as the profile
  is — one more thing the member carries between communities.

## Open questions

- The blob **transfer protocol** itself (range requests, resumable transfer, dedup, garbage
  collection) — a transport-layer concern, not this record.
- Whether to support multi-hash / multiple encodings of the same asset (thumbnails, transcodes)
  as linked `AssetRef`s.

## History

- The signed form of `AssetRef` this spec first carried was replaced by the unsigned pointer
  above: integrity comes from the content hash and attribution from the signed record that
  carries the ref, so a signature field would duplicate both (000 #7).

## References

- Spec 002 / 005 (multihash + multibase encoding), 001 (number rule), 006 (module item schemas)
