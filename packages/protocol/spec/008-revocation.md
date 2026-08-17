# 008 — Revocation

**Status:** Accepted
**Blocks:** the trust resolver — "not expired or revoked" needs a checkable meaning
**Amended by:** 011

## Context

Claims, relationships, and grants are signed records with optional expiry. Expiry handles the
_planned_ end of authority; revocation handles the _unplanned_ one — an employee leaves, an
agent is decommissioned, a device is lost (its key-audience grant revoked, 011), a grant is
abused, or a record was issued by an attacker in the window before a compromise rotation. Every
trust check promises verifiers a record that is signed, not expired, and not revoked — but no
record makes "revoked" checkable from bytes.

The only revocation in the protocol today is `DeviceKey.revokedAt` — a mutable field _inside_ a
signed record, so revoking means re-signing and replacing the record, and every future record
type would need its own copy of the field. Per 000, replace that with the general form.
_Amended by 011: the device example above (a lost device's key-audience grant) is 011's;
`DeviceKey` itself no longer exists — see the note under_ Replaces `DeviceKey.revokedAt`.

## Decision

One **Revocation** record withdraws any signed record, named by digest.

```
Revocation {
  revokes:   string             // multihash digest of the revoked record (003 digest rule:
                                //   multihash of the JCS of the complete signed record — so the
                                //   record's signature set must be canonical per 015, or the
                                //   same record has many valid digests and none can be revoked)
  issuerId:  ParticipantId      // who revokes (002)
  revokedAt: string             // RFC 3339
  reason?:   string             // non-normative; for operators and audit, never for logic
  signature: Signature[]        // per the issuer's current threshold (003, 005)
}
```

- **Who may revoke:** the participant that issued the revoked record, verified against its
  **current** key set (003) — not the key that signed the original — so revocation authority
  survives rotation and works _after_ a compromise rotation. For Grants (009), additionally any
  participant upstream in the proof chain may revoke a downstream link.
- **Permanent and monotonic.** A revocation cannot be undone or itself revoked; authority is
  restored by issuing a fresh record. Verifiers and caches may treat "revoked" as terminal,
  which keeps offline verification sound — a cached revocation never goes stale.
- **Expiry vs revocation:** `expiresAt` is the in-record, planned end; revocation is the
  out-of-band, unplanned end. A verifier checks both, always.
- **Distribution:** discovery stores revocations keyed by the revoked digest and serves them
  with the records they revoke; resolvers check the registry during chain verification.
  Writes are authenticated like any discovery write (004).
- **Out of scope — key events.** The key-history log is append-only; keys leave by rotation
  (003), never by revocation. A Revocation naming a `KeyEvent` digest is invalid.

### Replaces `DeviceKey.revokedAt`

`DeviceKey` loses its `revokedAt` field; a device is revoked by a Revocation record naming the
DeviceKey's digest. One mechanism for every record type, and DeviceKey records become
immutable like everything else that is signed.

_Amended by 011: the `DeviceKey` record is removed entirely; a device subkey is a key-audience
grant, revoked like any other grant by naming its digest, so this section describes a record
that no longer exists and the mechanism it introduced is what survives._

## Why a digest registry, not a status list

Composing before minting (000 #5): the W3C Bitstring Status List exists to hide _which_
credential was revoked and to compress millions of statuses into one bitstring — properties
bought with issuer-managed list state and index allocation. Discovery records are public by
construction, so the privacy property buys nothing here, and a digest-keyed lookup is the
thinner form (#7). UCAN revocation does exactly this — revoke by content address, signed by a
chain principal — so the shape composes with the standard the Grant record (009) aligns to.
When claims are projected as SD-JWT VCs, a status-list projection can be derived from the
registry; derived, so not a primitive (#4).

## The compromise story (with 003)

Rotation and revocation split the work of recovering from a stolen key: **rotation** (003)
kills the key's future — it can no longer sign records or writes — and **revocation** kills the
forgeries in its past — records the attacker issued before the rotation are withdrawn by
digest. Without this record, rotation alone would leave attacker-issued claims, edges, and
grants verifying forever.

## Open questions

- **Sign-time anchoring.** Verifiers accept a record signed by _any_ key state in the
  issuer's replay-valid log (so rotation does not orphan issued records), which means a
  stolen key can keep signing "into the past" until its forgeries are revoked. Anchoring
  records to a log seq at issuance (KERI-style) would close that window; deferred until
  running code needs it.
- **Freshness.** "Not revoked" is a statement about the registry queried, as fresh as the
  query. Stapled short-lived status proofs (a signed "unrevoked as of T") for verifiers that
  cannot reach discovery — deferred with the witnessing/duplicity questions of 003.
- **Subject renunciation.** Whether the _subject_ of an edge (the agent named in a
  `represents`) may disavow it with a Revocation of its own, or whether renunciation stays a
  policy of the trust layer. Leaning policy: verifiers that care can require subject
  countersignatures above the protocol.

## References

- Spec 003 (digest rule, rotation), 004 (write auth), 005 (signatures), 009 (Grant chains)
- UCAN revocation — revoke-by-content-address, chain-principal authority
- W3C Bitstring Status List — the considered-and-not-adopted alternative
