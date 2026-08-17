# Kinnet

Kinnet is the reference implementation of the
[Participant Network](./packages/protocol/spec/README.md): an open communication and
relationship layer for humans, organizations, applications, and AI agents.

The question this protocol answers is **does this agent really act for that organization, and
what is it allowed to do?** Identities are self-certifying public keys with append-only key
history; representation and delegation are signed records that anyone can verify offline; a
directory is a convenience, never a trusted party. Every check runs locally from signed bytes.

## What is what

- **The Participant Network** is the protocol: the numbered specifications in
  [`packages/protocol/spec`](./packages/protocol/spec) together with the committed conformance
  vectors that back them. It is defined by those documents and bytes, not by this code, and it
  is written to be implemented independently: everything a compatible implementation must agree
  on is in the specs and checkable against the vectors alone.
- **Kinnet** is the reference implementation — the packages in this repository. Where the spec
  and this code disagree, that is a bug in one of them, and the conformance vectors decide
  which.
- **The network** is whatever participants operate. Nothing here grants this repository's
  authors a privileged position in it: a directory built from these packages is a convenience
  anyone can run, and every guarantee a verifier relies on is checked from signed bytes, not
  from trusting an operator.

## About this repository

This is the **published surface** of Kinnet: the protocol specs, the record schemas, and the
verification code a third party needs in order to check a Kinnet identity, represents chain or
grant chain without trusting anyone. It is exported per release from a private upstream
repository.

That means the export is one-directional: development happens upstream, history here is the
export history, and a pull request is never merged in place — but it is reviewed here, and an
accepted change is ported upstream with your authorship preserved and ships in the next export.
Per-package changelogs are not mirrored; each release's notes are published on this
repository's GitHub release for its tag.
[CONTRIBUTING.md](./CONTRIBUTING.md) has the mechanics for bug reports, protocol proposals, and
pull requests; anything security-sensitive goes through [SECURITY.md](./SECURITY.md), never a
public issue.

## Packages

| Package                                   | What it is                                                                                             |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`@kinnet/protocol`](./packages/protocol) | Record types and Zod schemas: identities, key-event logs, claims, relationships, grants, revocations   |
| [`@kinnet/crypto`](./packages/crypto)     | Ed25519, JCS canonicalization, participant-ID derivation, key logs with pre-rotation, RFC 9421 signing |
| [`@kinnet/trust`](./packages/trust)       | The resolver: represents chains, claims, and UCAN-aligned grant chains, verifiable offline             |
| [`@kinnet/verify`](./packages/verify)     | Inbound-request verification for services receiving agent traffic (Node/Express and edge runtimes)     |
| [`@kinnet/a2a`](./packages/a2a)           | Bridge between Kinnet participant records and A2A agent cards                                          |

The packages are `0.x` and carry `"private": true` until the protocol substrate has been
through external security review; consume them from source for now.

## Specs and interoperability

The normative protocol lives in [`packages/protocol/spec`](./packages/protocol/spec) — one
numbered RFC per primitive, starting with
[000, which governs what may enter the protocol at all](./packages/protocol/spec/000-protocol-scope.md).
Where bytes are signed or hashed, the spec is backed by committed conformance vectors under
`packages/*/test/fixtures` that an independent implementation can check from bytes alone.

Those vectors are the compatibility contract. The protocol is meant to be implemented widely,
and two implementations that produce and accept the committed vectors — the accepting and the
rejecting cases both — interoperate by construction; nothing about compatibility is negotiated
against this codebase or any operator. If you are building an implementation and a vector seems
wrong, underspecified, or missing, that is a protocol issue and exactly the kind of issue this
repository wants.

The protocol is pre-wire-freeze: the specs may still change, and spec 000 defines what a change
requires (an RFC, a reference implementation, and reference tests, together). After the wire
freeze the discipline becomes additive-only.

## Try it live

A live discovery instance operated by the maintainers answers at
`https://discovery.kinnet.humanmeetsai.com`. It is one instance among any — running your own
from these packages is the point, not the exception — and it is **experimental, best-effort
infrastructure**: rate-limited, no SLA, and it may reset before 1.0. Don't build anything you
can't afford to re-enroll.

Prove which build it runs — the commit is stamped at image build time and matches a release
tag of this repository:

```bash
curl -s https://discovery.kinnet.humanmeetsai.com/version
```

Resolve a real identity from bytes — a test participant whose append-only key-event log you
can fetch and verify offline with `@kinnet/crypto`, trusting no one:

```bash
curl -s https://discovery.kinnet.humanmeetsai.com/participants/pk_zQmb7tc1nmwe4p1kTsE3TTVVZtjVF4yBSMaCQcP81QxoTjo/key-log
```

Create your own identity — self-custodial, the keys never leave your machine. From a checkout
of this repository after `pnpm install && pnpm build`, save this as `me.mts` at the repository
root (the `.mts` extension matters) and run `pnpm exec tsx me.mts`:

```ts
import { createIdentity, signRequest } from "@kinnet/crypto";

const me = createIdentity();
const url = `https://discovery.kinnet.humanmeetsai.com/participants/${me.id}/key-log`;
const body = JSON.stringify(me.log);
const headers = signRequest({
  method: "PUT",
  url,
  body,
  keyId: me.id,
  secretKey: me.currentKeys[0].secretKey
});
const response = await fetch(url, {
  method: "PUT",
  headers: { "content-type": "application/json", ...headers },
  body
});
console.log(response.status, me.id);
```

Then resolve yourself with the same `curl` as above, substituting your id — and keep the
secret key if you want the identity to stay yours: rotation, recovery, and everything else in
the specs works from it.

## Build and test

Requires Node 22+ and pnpm (the version is pinned in `package.json` via `packageManager`;
`corepack enable` will honour it).

```bash
pnpm install
pnpm check     # build, typecheck, and run every package's suite
```

Individually:

```bash
pnpm build     # tsc per package, in dependency order
pnpm typecheck # build, then type-check sources and tests
pnpm test      # build, then vitest per package
```

Packages resolve each other through their built `dist/`, which is why `build` runs first.

## License

Apache-2.0. See [LICENSE](./LICENSE).
