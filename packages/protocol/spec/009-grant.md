# 009 — Grant (capability delegation, UCAN-aligned)

**Status:** Accepted
**Blocks:** the trust resolver — represents chains, and "what may this agent do"
**Amended by:** 011

## Context

Relationships state _affiliation_ — `member-of`, `operates`, `represents` — but a verifier also
needs _authority_: a community's concierge agent holds `onboard`, `curate`, and `moderate` but
**not** `remove-member`, and an organization can delegate through an admin to an agent without
the organization's root key touching daily operations. That requires scoped, attenuating,
expiring, revocable delegation that a third party can verify offline from the records alone.
This is a solved shape — object capabilities as certificate chains — and UCAN is the standard
that solves it for exactly this setting (principals as keys, delegation by signature,
attenuation by subsetting, revocation by content address).

## Decision

A **Grant** record is one link in a capability-delegation chain, carrying UCAN delegation
semantics in the protocol's record format (001, 005).

```
Grant {
  subjectId:  ParticipantId     // whose authority the chain delegates; constant along the chain
  issuerId:   Principal         // who signs this link; at the root, issuerId == subjectId, so
                                //   the root issuer is always a participant (self-issued, 011)
  audienceId: Principal         // who receives the capability — a participant or, per 011, a
                                //   bare key (KeyRef); a key audience MUST carry expiresAt and
                                //   caveats.aud (011)
  abilities:  string[]          // namespaced paths, e.g. "directory/curate", "msg"
  caveats:    object            // constraints; {} = none; caveats only ever narrow
  proof:      string | null     // multihash digest of the parent Grant (003 digest rule);
                                //   null at the root
  issuedAt:   string            // RFC 3339
  expiresAt?: string            // RFC 3339; absent = until revoked (participant audiences only,
                                //   011)
  signature:  Signature[]       // per the issuer's current threshold (003, 005)
}
```

### Chain verification

A presented Grant is valid iff, walking `proof` digests from the leaf to the root:

1. Every link's `signature` verifies against its issuer **as a canonical signature set (015)**:
   a **participant** issuer resolves through its log (003, at threshold); a **key** issuer (011)
   is self-certifying — the signature verifies against the key itself, exactly one signature.
2. The root link is self-issued: `issuerId == subjectId`.
3. Each non-root link's `issuerId` equals its parent's `audienceId` — authority is exercised
   only by the one it was granted to.
4. `subjectId` is constant along the chain.
5. Each link's `abilities` are covered by its parent's (path-prefix cover: `directory` covers
   `directory/curate`), and each link's `caveats` only narrow the parent's — attenuation,
   never amplification.
6. At use time, no link is expired and no link is revoked (008). A verifier that cannot
   evaluate a caveat MUST reject the grant — caveats fail closed.

### Size limits

A chain is presented in a request header and verified before the request has proven anything,
and verifying it costs a key-log replay per distinct participant issuer (003). Its depth is
therefore an unauthenticated caller's choice unless bounded.

A conforming implementation MUST reject a chain or link outside these bounds:

| Bound                   | Value | Applies to                        |
| ----------------------- | ----- | --------------------------------- |
| `MAX_GRANT_CHAIN_LINKS` | 4     | links in one presented chain      |
| `MAX_GRANT_ABILITIES`   | 32    | entries in one link's `abilities` |
| `MAX_RECORD_SIGNATURES` | 8     | entries in one link's `signature` |

As in 003, the length check MUST precede element validation, and the chain length MUST be
checked before any link is verified — otherwise the rejection costs more than the work it is
there to prevent.

`MAX_RECORD_SIGNATURES` equals `MAX_KEY_EVENT_KEYS` for the reason 003 gives: a signature can
only count once, against one of the issuer's own keys, and an issuer cannot hold more keys
than an event may list. The same bound applies to every signature-set record — revocations
(008), conversations (012), device-set records (014). It bounds the COUNT only; whether every
member of the set must verify was left open here and is now **decided by 015**: a set holds
exactly `threshold` members, every one of which must verify against a distinct listed key, in key
order, before the digest is relied on. 015's exact-count rule makes this bound a ceiling that a
conforming record reaches only when its issuer's threshold is 8.

4 links carries every shape this spec and 011 describe — subject to application to service is
three — with one spare. Verifying a chain costs a key-log replay AND a search over the issuer's
entire key history per link, so the link cap multiplies directly into what a verifier must spend
before a request has proven anything. The base cost of a no-candidate chain is
`MAX_GRANT_CHAIN_LINKS * 2 * MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS` = `8A` = 8192
verifications, where `A = MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS`. An honest view may instead
return one genuine revocation signed under the oldest state of a maximum-length log; checking it
adds `A` before the chain returns revoked, giving the `9A` honest-denial ceiling. No shape this
spec or 011 describes needs more depth than that, and more depth is not worth seconds of blocked
CPU per inbound request.

32 abilities is far above any observed grant, given that a parent path already covers its
descendants.

### UCAN-aligned, not UCAN-encoded

Test #5 says compose, and the composition here is **semantic**: subject/issuer/audience roles,
proof chains by content address, prefix-covered abilities, fail-closed caveats, and revocation
authority for chain ancestors are UCAN's model, adopted as-is. The **envelope** is not: UCAN's
wire format brings DIDs, IPLD encoding, and varsig — a second canonical-bytes and signature
regime parallel to 001/005 for no second capability. One record format for every signed byte
in the protocol is the thinner form (#7). A UCAN projection of a Grant chain (for tooling that
speaks it) is derivable the same way `did:key` is a projection of the ID (002) — derived, so
not a primitive (#4).

## Boundaries

- **Relationship vs Grant.** A Relationship is a public, discoverable, one-hop _assertion_
  ("this agent represents Acme" — what a stranger can check from discovery alone). A Grant is
  transferable, attenuable _authority_, possibly multi-hop, presented at request time and
  publishable to discovery but not required to be public. The trust resolver verifies both the
  same way: signature, chain, expiry, revocation.
- **Enforcement is the resource holder's job.** The node or service receiving a request decides
  whether a verified chain's abilities admit the action; the protocol fixes only what makes the
  chain verifiable — mechanism, not policy (000 #3).
- **Ability strings are namespaced, not enumerated.** The protocol fixes the path-cover rule,
  not an ability vocabulary; vocabularies belong to the modules and services that enforce them
  (006's pattern).

## Open questions

- **Caveat vocabulary.** Caveat semantics are defined per ability namespace; the first standard
  entry exists — `aud`, an audience-narrowing caveat defined in 011 — and whether a further
  standard set (rate, resource pattern) earns a place in the spec stays open until running
  code shows recurrence.
- **M-of-N grant issuers.** The record carries `Signature[]` per the issuer's threshold and 015
  fixes how such a set is counted, but an implementation may support only threshold `"1"` at
  first, matching the 004 write-auth restriction; the limit is lifted when organization chains
  require M-of-N.
- **Invocations and receipts.** UCAN also specifies invocation (exercising a capability) and
  receipts. Request-time exercise is already covered by RFC 9421 signing (004) plus a presented
  chain; a receipt record is deferred until running code demands it.

## References

- UCAN delegation 1.0 — the semantic model (subject/issuer/audience, attenuation, proofs)
- Spec 001/005 (record format), 003 (digest rule, key resolution), 008 (revocation)
