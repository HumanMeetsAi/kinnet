# 006 — ModuleConfig

**Status:** Proposed
**Blocks:** the configuration frame for every typed content module a node hosts — directory,
events, library, board, and later ones

## Context

A participant node operated for a community — an organization, an interest group, a
neighbourhood — hosts applications for its members. A member directory is only one of them.
The same node also runs **events, a knowledge library, an offers/asks board, forums, polls,
tasks** — and each is the same shape: a set of typed, signed, node-scoped content items with a
schema, a per-role query policy, roles, and (sometimes) an admission rule. A directory-only
configuration record would be the config for _one_ module type, and would be followed by a
parallel `EventsConfig`, `LibraryConfig`, and so on. Per `000`, the protocol carries the general
form once instead.

## Decision

A single `ModuleConfig` record configures any module a node hosts. A directory is
`moduleType: "directory"`; events, library, and board are further module types.

```
ModuleConfig {
  nodeId:      ParticipantId      // the participant node this module runs on
  moduleType:  string            // "directory" | "events" | "library" | "board" | …
  schema:      FieldSpec[]        // the item fields for this module (core + custom)
  queryPolicy: PolicyRule[]       // per-field, per-role visibility (the visibility model)
  roles:       RoleSpec[]         // roles the query policy keys off
  admission?:  AdmissionRule      // optional; how items/members are added
  enabled:     boolean
  signature:   Signature          // admin-signed (owner-delegated)
}
```

### What is NOT a protocol primitive

The **items** a module holds — an event, a doc, an offer, a post, a poll — are **application
records on the node**, typed by their `ModuleConfig.schema`. They are not protocol primitives:
they are local to the node that hosts them, so independent implementations do not need to agree
on an `EventRecord` to interoperate (placement test #1, #2, #7). The protocol standardizes the
_frame_ (a module, its schema, its policy), not every body.

### What stays outside this record

- **Membership** — the edge between a member and the community, referencing the member's
  portable profile — is a separate primitive, not module config. That portability is why
  membership is a primitive while module items are not.
- The **visibility / query-policy** model applies uniformly to every module. Two control
  surfaces intersect: the member sets disclosure (the outer gate — an unshared field is
  invisible to everyone, the operator included), and the operator sets schema and per-role
  query policy (the inner gate). The intersection yields four tiers: **public** (published to
  discovery, visible to the whole network), **node-scoped** (visible to the node's members per
  its query policy, and to the operator hosting it), **peer-to-peer** (shared 1:1 with one
  member, never visible to the operator), and **private** (never shared).

## Rationale

- One mechanism for every module keeps the substrate thin while the module suite grows above it
  — exactly the scope discipline in `000`.
- Reuses the existing primitives: items are authored as signed records; RSVPs, votes, and
  assignments are `Relationship`s; badges and roles are `Claim`s and `Grant`s.

## Open questions

- Whether modules are declared as independent `ModuleConfig` records or listed in one per-node
  manifest. Leaning independent records, keyed by `(nodeId, moduleType)`.
- A small **standard schema vocabulary** per common module (event: title/time/location; library
  item: title/asset/tags) so items stay portable where portability is wanted.

## References

- Spec 000 (scope: replace toward clean), 007 (AssetRef, used by item schemas)
