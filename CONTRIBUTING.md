# Contributing to Kinnet

This repository is the published surface of Kinnet, exported per release from a private
upstream repository (see [README](./README.md#about-this-repository)). That shape changes the
mechanics of contributing, not the welcome: everything below is read, and protocol-level input
is exactly what this stage of the project needs most.

## Bugs and protocol issues

Open a GitHub issue. The most valuable reports are the most checkable ones:

- **A conformance vector that seems wrong, underspecified, or missing.** The vectors under
  `packages/*/test/fixtures` are the compatibility contract, so a vector dispute is a protocol
  issue by definition — include the bytes you expected and the spec passage you read.
- **A spec/implementation disagreement.** Name the spec section and the code path; one of them
  has a bug, and the report is the start of deciding which.
- **Ordinary defects** in the packages: a minimal reproduction against the released source
  beats prose.

Anything security-sensitive goes through [SECURITY.md](./SECURITY.md) — never a public issue.

## Pull requests

Pull requests are welcome **as proposals**. Because this repository is replaced wholesale by
each export, a PR is never merged in place. What actually happens:

1. A maintainer reviews it here, in the open.
2. An accepted change is ported to the upstream monorepo as a commit that preserves your
   authorship (your name and email in the commit's author field).
3. The next export carries it; the PR is then closed with a pointer to the export commit.

Versions stay in `0.x` until the protocol substrate (`@kinnet/protocol`, `@kinnet/crypto`)
survives an external security review. Semver discipline applies within `0.x`: a breaking change
bumps the minor, a fix bumps the patch.

Sign off your commits (`git commit -s`). The sign-off certifies the
[Developer Certificate of Origin](https://developercertificate.org/) — there is no CLA, by
design: no single party accumulates the right to relicense contributors' work.

## Protocol changes

The protocol is pre-wire-freeze and governed by
[spec 000](./packages/protocol/spec/000-protocol-scope.md): a change to a record, field, enum,
or wire-format element requires an RFC under `spec/`, a reference implementation, and reference
tests — landing together. For anything at that level, open an issue describing the problem and
the placement-test reasoning first; the RFC discipline is cheap to start and expensive to
retrofit.

## License

Apache-2.0. Contributions are accepted under the same license.
