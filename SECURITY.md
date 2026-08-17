# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** These packages are identity and
verification code: a public report is a working exploit note for every deployment that has not
patched yet.

Report privately to **an@humanmeetsai.com**. Please include:

- what you found, and which package and version (or commit) it affects,
- the steps or the minimal input that reproduces it,
- what an attacker gets out of it, as concretely as you can put it.

You will get an acknowledgement within 3 business days and an assessment — accepted, needs more
information, or not a vulnerability, with reasons — within 10 business days. If you would like
credit in the fix's release notes, say so and how you want to be named; anonymous reports are
equally welcome.

Please give us a reasonable window to ship a fix before publishing. We will tell you when the
fix is released rather than leaving you to guess.

## Scope

In scope: anything in this repository — the protocol specs, the record schemas, and the signing
and verification code. Findings that are especially wanted:

- a signature, key-log replay, or canonicalization result that a conforming implementation
  should reject and this code accepts (or the reverse),
- a chain — represents, claim, or grant — that verifies without the authority it claims,
- a revocation or expiry that fails to take effect,
- a committed conformance vector that does not match the specification it pins.

Out of scope here: hosted services and deployments, which are not part of this repository.
Send those to the same address and say which host you were looking at.

## Status

These packages are `0.x` and have not yet completed an external security review. Treat them as
pre-release: suitable for experimentation and review, not yet for protecting anything you
cannot afford to lose.
