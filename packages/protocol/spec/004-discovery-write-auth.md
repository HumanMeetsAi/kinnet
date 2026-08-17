# 004 — Discovery write authorization

**Status:** Accepted
**Blocks:** authenticated discovery writes

## Context

Discovery accepts public records — profiles, nodes, claims, public edges, key events. The hard
rule is that a record for participant `X` may only be written by whoever controls `X`'s
current key ("proof of key ownership on every write"). Reads are public and unauthenticated;
writes are not. This needs a concrete request-authentication protocol.

## Decision

Authenticate every write with **HTTP Message Signatures (RFC 9421)**, signed by the
participant's current key.

- **Covered components:** `@method`, `@target-uri`, `content-digest` (RFC 9530), `@created`,
  and a `nonce` — plus `pn-grants` when a spec-011 grant chain is presented (the header
  MUST then be covered).
- **`keyid`:** the participant ID (002) or, per spec 011, a bare `KeyRef` (005) — nothing
  else.
- **Verification:** discovery resolves the claimed participant's **current key set** from the
  key-history log (003) and verifies the HTTP signature against it. Unsigned or wrongly-signed
  writes are rejected. This protocol version restricts request signing to **threshold-1 key
  states** — see _Threshold-1 request signing_ below, which is normative.
- **Replay defense:** `@created` must be within a small clock-skew window and the `nonce` must
  be unseen (short-lived cache). Equivalent to short-lived request tokens.

## Two signatures, two jobs

These are independent and both required:

1. **Record signature** (001 + 005) — over the canonical record. Authenticates _content_ and
   is what persists and is re-verifiable by anyone, forever.
2. **HTTP Message Signature** (this spec) — over the _request_. Authenticates the _write
   action_ (this caller, now, to this path) and defeats replay. Not stored with the record.

Discovery checks both: the request is authorized to write, and the record is internally valid
and self-signed by the same identity.

## The content digest covers the delivered octets

**The `content-digest` component is computed over the raw content octets as transmitted.** A
verifier **MUST** digest the bytes it received, exactly as received, and **MUST NOT** decode,
transcode, re-serialize, or otherwise normalize the body before digesting it. Representing the
body as text is a **sender-side convenience only**: a signer that holds its body as a string
may digest that string's UTF-8 encoding precisely because it goes on to transmit that same
encoding, and the two are then the same octets.

The rule is not cosmetic, because UTF-8 decoding is **not injective**: a decoder replaces every
malformed sequence with U+FFFD rather than failing, so the three octets `EF BF BD` — a body that
legitimately contains U+FFFD — and the single octet `FF` decode to the same text. A verifier that
digests decoded text therefore authenticates a **normalization** of the request rather than the
request: an intermediary may substitute one delivery for the other and the signature still
verifies, while the application is handed octets no signature ever covered. The same defect makes
binary bodies unsignable in principle, since a text-normalized digest cannot distinguish them.

Consequences a conforming implementation must observe:

- Application-level decoding, JSON parsing, and schema validation happen **after** verification,
  and **from the same octets that were verified** — not from a second read of the request, which
  a framework, a decoder setting, or a proxy could answer differently.
- A verifier that can only obtain a decoded body from its framework is **not conforming** for
  that deployment, and should refuse rather than digest what it was given.
- Committed conformance vectors for this rule live at
  `packages/crypto/test/fixtures/content-digest-vectors.json`: raw octets in base64, the exact
  `Content-Digest` header value each must produce, and the attack pair — two deliveries with one
  decoded text and two digests.

## Threshold-1 request signing

**This protocol version restricts request signing to threshold-1 key states.** Concretely:

- A request signature is **one** RFC 9421 signature — the wire profile carries exactly one
  `sig1` label — verified against exactly one key of the resolved key state.
- A verifier **MUST refuse** a request whose resolved key state declares a threshold greater than
  1, and MUST refuse it as an authentication failure rather than accepting one signature as if
  the threshold were 1. Accepting a single signature against an M-of-N state is the failure this
  rule exists to forbid: it would silently reduce an organization's committee to any one of its
  members for every write.
- The threshold **MUST** be read in 015 S1's domain (`^[1-9][0-9]*$`) rather than coerced. A
  verifier that coerces gets `NaN` for a malformed value, and `NaN > 1` is false — the fail-open
  direction, and precisely the shape 015 S1 forbids for records.
- The refusal is **designed, not an omission**: it is checked on the resolved key state before
  any signature verification work. Stating it normatively is what keeps an independent
  implementation from reading the single-`sig1` wire profile as license to invent its own
  M-of-N convention.

**Higher thresholds remain valid everywhere else.** A key log MAY commit and rotate to an M-of-N
key state (003, 015): those states are well formed, they govern **records** — key events,
revocations, grants, conversation records — and 015's canonical signature set applies to them in
full. The restriction here is about **requests** only. The operational consequence, stated
plainly: a participant whose current key state has a threshold above 1 cannot perform discovery
writes in this protocol version at all. That is a real limitation of the version, not a bug to be
worked around by a verifier that relaxes the rule locally.

**The pre-rotation prerequisite, which MUST outlive this restriction.** Lifting the restriction
depends on the pre-rotation commitment covering the **threshold**, not only the ordered key list.
Without it a rotation chooses the threshold that authorizes it: a holder of one key from a
committed M-of-N set could reveal exactly the committed keys, declare `threshold: "1"`, sign once,
and take sole control of the identity. That rule is in force — 003's _The committed next key
state_ commits `{keys, threshold}`, and replay checks each rotation against the **prior** event's
commitment and threshold. Any future version that specifies multi-signature requests **MUST**
keep the prior-event commitment rule as a precondition, and MUST NOT ship M-of-N request signing
against a replay rule that lets a rotation restate its own threshold.

**What a future version has to specify**, so this reads as deferred rather than forgotten: a
deterministic RFC 9421 multi-signature profile — how multiple signatures are labeled and ordered
on the wire, which signature-base components each covers, how the set is counted against the key
state (015's `m = t`, distinct keys, canonical order, applied to a request rather than a record),
and how replay defense composes when several signers each contribute a `nonce`/`created`. Until
such a version exists, threshold-1 is the rule.

## Deployment note: reverse proxies

`@target-uri` is the **absolute** URL the client signed, so a verifier must reconstruct
exactly that URL. Behind a TLS-terminating reverse proxy the server sees a plain HTTP socket
and rebuilds `http://…` while the client signed `https://…`, and every signed write fails.

A proxy reports the original scheme and host in `X-Forwarded-Proto` / `X-Forwarded-Host`, but
those headers are client-supplied and trivially forged: honoring them on a directly reachable
service would let any caller choose the URL its own signature is checked against. So honoring
forwarded headers is **opt-in per deployment and off by default**: a deployment MUST NOT trust
them unless it is reachable exclusively through a trusted proxy, and a verifier that does not
opt in keeps the socket-derived URL, which fails closed.

## Design notes

- RFC 9421 is the same signing primitive already used at the edge by Web Bot Auth, so verifiers
  and tooling interoperate and nothing new is invented.
- RFC 9530 already defines the digest over the message content; _The content digest covers the
  delivered octets_ restates it as a rule of this spec because implementations drift toward
  digesting a decoded copy of the body, and only the stated rule makes an independent
  implementation reproduce the intended behavior.
- Binding `keyid` to the participant ID and resolving through the key-history log means write
  authority tracks rotation automatically — rotate your key and old keys stop being able to
  write, with no extra revocation step.

## Open questions

- Anti-abuse / rate-limiting at the endpoint (sybil, write floods) — a separate concern from
  authentication, and deferred.
- First-write bootstrap: an inception event is self-authenticating (it _is_ the key state), so
  the very first publish is verified against the record it carries, not a prior log.

## History

- 2026-08-13 — Added _The content digest covers the delivered octets_: `content-digest` is
  computed over the raw content octets as transmitted, with committed conformance vectors.
  Added following an external security review (2026-08).
- 2026-08-13 — Added _Threshold-1 request signing_: request signing is restricted to threshold-1
  key states, with the pre-rotation commitment rule as the prerequisite for lifting it. Added
  following an external security review (2026-08).

## References

- RFC 9421 — HTTP Message Signatures
- RFC 9530 — Digest Fields (`content-digest`)
- Spec 003 (current-key resolution; the committed next key state, which any future
  multi-signature profile depends on)
- Spec 015 (canonical signature sets — the threshold domain, and the `m = t` counting rule a
  multi-signature request profile would have to reproduce)
