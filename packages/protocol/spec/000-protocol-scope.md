# 000 — Protocol scope & evolution

**Status:** Accepted
**Governs:** every other spec, and every change to `@kinnet/protocol`

## Purpose

This is the meta-spec: how it is decided what belongs in the protocol, and how the protocol
changes over time. The format specs (001–005) decide _what the bytes are_; this one decides
_what earns a place in the substrate at all_ and _how freely it may change_.

## Prime directive

Bias toward the **cleanest, most future-proof design** — never toward leaving things as they
are for their own sake. A young protocol's job is to get _better_, fast, while it still can.
Two corollaries:

- **Minimal is not static.** Keep the shared substrate thin _and_ keep improving it. Thinness
  is about what is in scope; evolution is about getting the in-scope things right.
- **Replace, don't accrete.** Before the wire-freeze, prefer ripping out a flawed primitive and
  replacing it with the right one over layering compatibility cruft on top. With sufficient
  rationale, a removal is as welcome as an addition.

## Two axes, kept separate

The common mistake is to fuse these. They are independent:

1. **Scope — which layer?** Does this belong in the protocol, or above it (SDK / node / app)?
   This discipline is **permanent**: the substrate stays thin at every stage.
2. **Stability — how freely may it change?** This is **stage-gated**, not fixed. Pre-freeze the
   protocol is fluid and breaking changes are free; post-freeze, change becomes additive and
   migration-bound.

"Keep it thin" (scope) and "change it freely toward clean" (stability, pre-freeze) are allies,
not opposites — both fight bloat and drift.

## The placement test

For anything proposed _into_ `@kinnet/protocol` — a record, field, enum, or wire-format element
— decide where it belongs and in what form. It earns a place only if it passes all of:

1. **Interop-necessity** — two independent implementations must agree on it to interoperate. If
   it works above the protocol and they still interoperate, it lives above.
2. **Primitive, not feature** — a general, composable primitive, not a specific feature.
3. **Mechanism, not policy** — encodes _how_ (rotation, thresholds), not _what should be true_
   (who is trusted, what a role means). Policy lives in the trust layer and apps.
4. **Stored, not derivable** — cannot be computed from existing primitives. (Reputation is
   derived from claims, so it is not a primitive.)
5. **Compose, not invent** — no existing standard (DID, VC/SD-JWT, MLS, A2A, MCP) already
   solves it. Adopt before minting.
6. **Driven by running code** — the need is demonstrated by a reference implementation, not
   theorized. Future-proofing is bought through _extension mechanisms_ (versioning, multicodec
   tags, namespaced extensions), not through speculative features.
7. **No thinner form** — there is no smaller primitive plus an extension point that would serve.

This is a _placement and minimalism_ test — "what is the right layer, and the thinnest correct
shape?" — not a change-resistance test. A change that _removes_ or _replaces_ to land something
cleaner is encouraged, and is judged by the same test plus the strength of its rationale.

## Evolution lifecycle — where "it's forever" actually applies

Rigidity is **earned, not default.** The permanence warnings in 001–005 describe the
post-freeze world; they do not bind the protocol now.

- **Stage 0 — Unstable (today).** No external implementers; live signed data is first-party
  only. Optimize purely for correct and clean. Breaking changes, removals, and replacements are
  free and expected. 001–005 are Accepted and, at this stage, still replaceable with rationale.
- **Stage 1 — Wire-freeze (v1).** Triggered by the first external implementation, or by the
  first production network carrying third-party participants or third-party-signed data. A
  first-party network — one whose participants are all operated by the reference implementer,
  who can migrate its own data — is Stage 0. From here: additive-only, capability-negotiated,
  with migrations and deprecation cycles for anything that must change. _This_ is where "a
  record's bytes are forever" starts to bind.

The discipline flips at the freeze. Before it, conservatism is the enemy; reversibility is a
Stage-0 asset to spend deliberately.

## Wire identifiers are brand-neutral

Every spec-defined byte sequence an independent implementation must emit or match — reserved
envelope-type prefixes, HTTP signature components and header names, SSE event names, export
format ids, TLS struct names — uses **`pn`** (Participant Network), never a product name. The
product brand is an application-layer concern with its own lifetime; the wire is not. Binding
them together would make a rename a protocol revision, and after the Stage-1 wire-freeze that
revision would be unpayable. So the substrate names the network, not the vendor: `pn/…`
envelope types, `PN-Grants`, `pn.discovery.participant-export/1`, `PNCredential`.

Package names, npm scope, CLI binary, domains, internal edge headers (`X-…`), and prose are
**not** wire identifiers and stay branded — they are replaceable without touching a byte any
other implementation sees.

## Process

- **RFC + reference implementation.** Every protocol change — addition, removal, or replacement
  — is an RFC under `spec/` and is proven in the reference implementation before it is real.
  "Rough consensus and running code." `ParticipantProfile` and `ParticipantNode` are specified
  in 017 (participant profile & node); `Relationship` and `Claim` in 018 (claims &
  relationships).
- **The gate is the quality of the rationale, not caution.** "Enough rationale to rip it out and
  replace it" is exactly the bar: a clear argument, a cleaner resulting design, and code that
  demonstrates it.

## Failure modes to steer between

- **Kitchen sink (XMPP).** Too many yeses → the substrate ossifies, no second implementation can
  keep up, interop fragments.
- **Under-specified (ActivityPub).** Core too thin and no agreed extensions → everyone builds
  incompatible things above the line; interop is nominal.
- **Premature ossification.** Freezing a young protocol, or refusing to replace a known-flawed
  primitive out of misplaced caution, so it can never reach clean. The risk a reflexive "bias to
  no" would create — and the one this directive explicitly rejects.

## Applied to Kinnet today

These show the _placement_ discipline; all remain revisable at Stage 0:

- **Reputation** — out; derived from relationships and claims (test #4).
- **Governance (single / quorum / weighted / DAO)** — the protocol holds key-rotation and
  thresholds (mechanism); the policy is pluggable and lives above (test #3).
- **Directory** — mostly an application, and one node-hosted module among others (006); at most
  `DirectoryEntry` / `ModuleConfig` / `InviteToken` are thin primitives, and even the schema and
  roles are _configured_, not hardcoded (tests #2, #3). Of the three, only `ModuleConfig` has a
  spec (006).
- **DID method** — deferred as a projection of the ID, not baked into it (tests #5, #7). 002
  reserves the brand-neutral method name `did:pn:<id>` for that projection; it may not be used
  until `pn` is registered in the W3C DID method registry, the precondition 002 states.

## Open questions

- Whether the RFC requirement extends to the **removal** of a record kind, or whether a removal
  is adequately covered by the RFC of the change that replaces it.

## History

- 2026-06-10 — Created: the placement test, the two axes, and the evolution lifecycle.
- 2026-08-13 — Added _Wire identifiers are brand-neutral_: spec-defined bytes name the network
  (`pn`), never a product, so a rename can never become a protocol revision.
- 2026-08-16 — Stage-1 trigger sharpened so a first-party network does not trip the wire-freeze;
  017 and 018 named as the specs for the four record kinds.

## References

- Every numbered spec in this directory — the decisions this one governs
- IETF "rough consensus and running code"; Rust RFCs; Python PEPs — process precedents
