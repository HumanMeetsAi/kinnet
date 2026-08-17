# 006 — ModuleConfig (generalize DirectoryConfig)

**Status:** Proposed
**Supersedes:** `DirectoryConfig`, a directory-only config record that was never implemented

## Context

A community node hosts applications; a directory is only one of them. Communities also run
**events, a knowledge library, an offers/asks board, forums, polls, tasks** — and each is the
same shape: a set of typed, signed, node-scoped content items with a schema, a per-role query
policy, roles, and (sometimes) an admission rule. `DirectoryConfig` is really the config for
_one_ module type. Per `000`, the clean move at Stage 0 is to **replace it with the general
form** rather than add a parallel `EventsConfig`, `LibraryConfig`, and so on.

## Decision

Replace `DirectoryConfig` with a single `ModuleConfig`. The directory becomes
`moduleType: "directory"`; events, library, and board are further module types.

```
ModuleConfig {
  nodeId:      ParticipantId      // the community node this module runs on
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
they are community-local, so independent implementations do not need to agree on an
`EventRecord` to interoperate (placement test #1, #2, #7). The protocol standardizes the
_frame_ (a module, its schema, its policy), not every body.

### What stays

- **DirectoryEntry** is unchanged: it is _membership_ (the member↔community edge plus a
  `profileRef`), not module config. It references the portable profile; that portability is why
  it is a primitive while module items are not.
- The whole **visibility / query-policy** model now applies uniformly to every module, not just
  the directory. Two control surfaces intersect: the member sets disclosure (the outer gate —
  an unshared field is invisible to everyone, the operator included), and the operator sets
  schema and per-role query policy (the inner gate). The intersection yields four tiers:
  **public** (published to discovery, visible to the whole network), **directory** (visible to
  the community per its query policy, and to the operator hosting it), **peer-to-peer** (shared
  1:1 with one member, never visible to the operator), and **private** (never shared).

## Rationale

- One mechanism for every module keeps the substrate thin while the module suite grows above it
  — exactly the scope discipline in `000`.
- Reuses the existing primitives: items are authored as signed records; RSVPs, votes, and
  assignments are `Relationship`s; badges and roles are `Claim`s and `Grant`s.

## Open questions

- Whether modules are declared as independent `ModuleConfig` records or listed in one per-node
  manifest. Leaning independent records, keyed by `(nodeId, moduleType)`.
- A small **standard schema vocabulary** per common module (event: title/time/location; library
  item: title/asset/tags) so items stay portable where portability is wanted, mirroring the
  directory's standard-core-field idea.

## References

- Spec 000 (scope: replace toward clean), 007 (AssetRef, used by item schemas)
