# @kinnet/verify

Verify an inbound agent request in a few lines: the request's HTTP Message Signature
(RFC 9421) proves the caller controls a participant identity, and the agent's published
`represents` edges are verified through the trust resolver (specs 008/009) to answer
**who this agent acts for**. Key logs are replayed locally — discovery is a directory,
not a trusted party.

## Node / Express

```ts
import express from "express";
import { createVerifier } from "@kinnet/verify";
import "@kinnet/verify/express"; // opt-in: types `req.verifiedAgent` on Express's Request

const app = express();
const kinnet = createVerifier({ discoveryUrl: "https://discovery.example.com" });

app.use(express.raw({ type: "*/*" })); // the middleware needs the raw body bytes, not text
app.use(kinnet.middleware());
app.post("/quote", (req, res) => res.json({ agent: req.verifiedAgent }));
```

A request rejected on its merits ends with `401 { "error": "unauthorized_agent", "reason": ... }`
— but not every rejection is an auth failure: replay-tracking capacity and an unusable server
clock end with `503 { "error": "temporarily_unavailable", ... }` (see [Rejection
reasons](#rejection-reasons)), and a client should retry those rather than re-authenticate.
An accepted request carries `req.verifiedAgent = { agentId, actor, delegated, abilities, ... }`.

The middleware emits both statuses for you; a custom handler should read `error.status` rather
than assume 401.

### The `@kinnet/verify/express` type import

Typing `req.verifiedAgent` on Express's `Request` needs a global declaration merge, so it is
kept out of the main entry — importing `@kinnet/verify` must not push `Express` types into the
global scope of consumers that never use Express. Import the subpath once anywhere in your
program (the entry module or a `*.d.ts` both work) and the property is typed everywhere:

```ts
import "@kinnet/verify/express";
```

It emits no runtime code and is purely a typing convenience. The middleware itself types its
request structurally, so it behaves identically without the import — only the
`req.verifiedAgent` property access needs it. Consumers that prefer not to augment a global
can read the value through their own cast or wrapper instead.

## Composing a whole request

`verify()` keeps its own normalized per-operation allowance. A handler that performs more
signature-bearing checks after authenticating the HTTP request can also give them one outer
request context:

```ts
const context = kinnet.beginRequest({ maxSignatureVerifications: 18_432 });
const agent = await kinnet.verify(inbound, context);
// Pass `context` to the trust or record-unit checks performed by this handler.
```

Every curve verification then charges both meters: the outer context bounds their composition,
while the operation allowance still prevents a larger request policy from widening one hostile
trust decision. A malformed explicit context allowance fails closed at zero, and an explicit
context takes precedence over the older bare-budget option. Successful signer-state work is
coalesced only within that context and is isolated by both the exact trust view and participant
id; current-key membership, expiry, revocation, verdicts, and stream-tick authority are never
memoized.

## Edge runtimes (Cloudflare Workers, Deno, Bun)

```ts
import { decodeUtf8Strict, parseJsonStrict } from "@kinnet/protocol";
import { createVerifier, VerifyCapacityError, VerifyError } from "@kinnet/verify";

const kinnet = createVerifier({
  discoveryUrl: "https://discovery.example.com",
  requireRepresents: "pk_z..." // optional: only admit agents verified for this org
});

export default {
  async fetch(request: Request): Promise<Response> {
    try {
      const { octets, ...agent } = await kinnet.verifyFetch(request);
      // `octets` are the exact bytes the signature covered. Parse THOSE — never re-read the
      // request. See "Parse the octets you were handed" below.
      const record = parseJsonStrict(decodeUtf8Strict(octets));
      return Response.json({ hello: agent.agentId, delegated: agent.delegated, record });
    } catch (error) {
      const reason = error instanceof VerifyError ? error.reason : "verification_failed";
      // Use `error.status`, don't hardcode 401. Not every rejection is an auth failure:
      // a `VerifyCapacityError` (replay-nonce tracking full, or an unusable clock) carries
      // 503, and telling a caller "unauthorized" for a transient capacity condition makes
      // it re-authenticate or give up instead of retrying.
      const status = error instanceof VerifyError ? error.status : 401;
      const label =
        error instanceof VerifyCapacityError ? "temporarily_unavailable" : "unauthorized_agent";
      return Response.json({ error: label, reason }, { status });
    }
  }
};
```

### Parse the octets you were handed

`verifyFetch` returns the verified agent **and** `octets`: the exact request body bytes the
signature's `content-digest` covered. Use them.

The reason is the one that made the adapter read bytes in the first place. A signature covers a
digest of the delivered octets (RFC 9530), not of any decoded form of them, and UTF-8 decoding is
not injective — `TextDecoder` replaces every malformed sequence with U+FFFD rather than failing,
so the single octet `FF` and the three octets that legitimately encode U+FFFD decode to the same
text. A consumer that verifies and then reaches for `request.text()` or `request.json()` is
parsing a normalization of the request, not the request: two different deliveries produce one
parsed record, and the one the application acts on is not necessarily the one the signature
covered. That defect used to live inside this package (an external security review found it in
2026-08); handing
the octets back is what stops a consumer from rebuilding it in its own code.

So, after `verifyFetch` returns:

```ts
import { decodeUtf8Strict, parseJsonStrict } from "@kinnet/protocol";

const { octets, ...agent } = await kinnet.verifyFetch(request);
const record = parseJsonStrict(decodeUtf8Strict(octets)); // fatal decode, then strict parse
```

`decodeUtf8Strict` throws on any byte sequence that is not well-formed UTF-8 instead of
substituting U+FFFD, and `parseJsonStrict` refuses duplicate JSON keys (spec 015 S6.1), which
different parsers resolve differently. **Never re-read the request after verification** — not
`.text()`, not `.json()`, not a fresh `.clone()`. The Express middleware needs no equivalent: it
requires `req.body` to be the raw bytes already, and those are the bytes it verified.

### Express 4 vs Express 5: bodiless requests

The middleware's handling of a request with no body targets **Express 5** semantics, and this is
a real limitation rather than a footnote.

The middleware treats `req.body === undefined` as an empty body — the correct digest input for a
bodiless request, whose `content-digest` is the SHA-256 of zero octets — and refuses anything
that is neither `undefined` nor a `Uint8Array` with `body_not_raw`, fail-closed, because it
cannot tell what a decoded or parsed value did to the bytes. Under Express 5, `express.raw()`
leaves `req.body` as `undefined` when no body was sent, so a signed GET verifies.

Under **Express 4**, `express.raw()` sets `req.body = {}` for a bodiless request. An empty object
is not `undefined` and not raw bytes, so the middleware refuses it: **signed GET and HEAD requests
through Express 4 are rejected with `body_not_raw`.** Requests that carry a body are unaffected on
either version. If you are on Express 4 and need signed bodiless requests, upgrade to Express 5,
or interpose your own middleware that clears `req.body` when the request genuinely carried no
body — having satisfied yourself that nothing else in your stack populated it.

The middleware will not guess this for you, and that is deliberate: `{}` is also what a JSON body
parser leaves behind, so treating it as "no body" would admit a parsed body as an unparsed one at
every verifier that ever runs behind one. A refused signed GET is a visible, fixable
misconfiguration; a silently accepted parsed body is the class of defect this package exists to
refuse.

## What is checked

1. **The request** — RFC 9421 signature over `@method`, `@target-uri`, and
   `content-digest`, with `created` freshness and single-use nonces (spec 004 profile),
   verified against the agent's **current** key state replayed from its key log.
2. **The chain**, but only when `requireRepresents` names an organization — there is no
   ambient "who does this agent represent" answer, because producing one means scanning
   every edge published about the agent, a set anyone can grow. Instead the edge for the
   exact (organization, agent, organization, `represents`) tuple is looked up by name and
   verified end to end: issued and signed by the represented organization, not expired,
   not revoked (spec 008). Anything short of that is
   `represents_chain_unverified`.

Without `requireRepresents` no relationship read happens at all. For scoped authority
(grant chains, spec 009), use `verifyGrantChain` from `@kinnet/trust` with the exposed
`verifier.view`.

## Delegated requests: bind the audience

A request may present a grant chain (`PN-Grants`, spec 011) instead of acting with
root authority. Two options bound what this surface accepts:

```ts
const kinnet = createVerifier({
  discoveryUrl: "https://discovery.example.com",
  verifierId: "pk_z...", // this service's own participant id
  requireAud: true, // only accept chains that name an audience
  requireAbilities: ["quotes/write"]
});
```

`verifierId` gates **aud-restricted** chains only: a chain carrying `caveats.aud` is
rejected unless it names this id. It does not gate a chain that carries no `aud` at all —
spec 011 requires `aud` only on key-audience links, so a chain delegated between
participants may legally omit it, and an unrestricted chain is admitted at every
verifier. **`requireAud: true` is what makes audience binding mandatory here**, rejecting
such a chain with `grant_audience_required`. It defaults to false.

`requireAbilities` is checked with the spec-009 path-prefix cover rule, exported as
`abilityCovers(granted, required)` for services enforcing their own vocabulary against
`verifiedAgent.abilities` — `directory` covers `directory/curate`, not `directory-admin`.

### MCP tool names as abilities

Abilities are `^[a-z0-9-]+(/[a-z0-9-]+)*$` (spec 009). MCP tool names are conventionally
snake_case and frequently carry capitals, so `tool_call` is **not** a valid ability and a grant
naming one is rejected by the schema at mint time. The charset is not the thing to change — it is
what makes `abilityCovers` a segment-boundary test rather than a string-prefix one — so the
resolution is a mapping applied identically at both ends:

```ts
import { mcpToolAbility } from "@kinnet/verify";

mcpToolAbility("tool_call"); // "mcp/tool-call"
mcpToolAbility("searchDocs"); // "mcp/searchdocs"
mcpToolAbility("tool_call", "vendor"); // "vendor/tool-call"
mcpToolAbility("tool_call", ""); // "tool-call" (bare, no namespace segment)
mcpToolAbility("☃"); // throws AbilityMappingError
```

It lower-cases and maps `_` to `-`, then validates the result against `abilitySchema`; anything
that still is not a legal ability throws `AbilityMappingError` rather than being silently
mangled. The namespace is a **segment**, so a grant of the bare `mcp` ability covers every tool
by path-prefix cover, and `mcp/tool-call` covers exactly one.

> **The mapping is not injective.** `tool_call` and `tool-call` both map to `mcp/tool-call`, as do
> `Tool_Call` and `TOOL-CALL`. A server exposing two tools that differ only by case or by `_`
> versus `-` cannot authorize one without authorizing the other. Because of this, **the minting
> side and the verifying side must apply this same function** — a hand-written ability on one end
> and `mcpToolAbility` on the other will eventually disagree, and the disagreement fails closed.

## Verifying offline

`createVerifier` takes either a `discoveryUrl` (it builds a discovery-backed view for you) or a
`view` you built — never both, and never neither; passing both or neither throws
`VerifierConfigurationError` at construction rather than failing every request later.

`createStaticTrustView` is a view over records already in hand, so a whole request can be
verified with no network at all — a test, an air-gapped relying party, a service verifying from
committed bytes:

```ts
import { createStaticTrustView, createVerifier } from "@kinnet/verify";

const view = createStaticTrustView({
  keyLogs: [orgLog, agentLog], // each log is filed under the id it answers for
  revocations: [...],
  relationships: [...]
});

const kinnet = createVerifier({ view, verifierId: "pk_z..." });
await kinnet.verify(inbound); // no fetch, ever
```

Key logs are **keyed by nothing**: the id each answers for is derived from the log's own
inception event (spec 002), so a fixture cannot file one identity's log under another's id — the
substitution `getKeyState` exists to catch. A log that does not replay is still served, and
`getKeyState` is where it fails, exactly as it would against a discovery host serving the same
bytes. The view implements the full
`DiscoveryView` surface, so it also works directly with `verifyGrantChain` from `@kinnet/trust`,
and it observes the same contracts the discovery-backed view does — most importantly the
issuer-targeted revocation bound (at most one record per distinct issuer). Any object satisfying
`DiscoveryView` can be injected, including a `createDiscoveryView` you configured yourself or a
wrapper that instruments one.

## Signing a request (the agent side)

Both signer inputs come from the agent's identity — the `Identity` that `createIdentity()` from
`@kinnet/crypto` returns, however the agent persists it between runs: `keyId` is the participant
id (`id`, the `pk_…` string), and the signing key is `currentKeys[0].secretKey`, the raw bytes
`signRequest` expects. (If the identity is stored with its keys as multibase strings,
`fromMultibase` from `@kinnet/crypto` decodes them back to bytes.)

```ts
import { signRequest } from "@kinnet/crypto";
import type { Identity } from "@kinnet/crypto";

const identity: Identity = loadIdentity(); // however this agent persists its createIdentity() result

const headers = signRequest({
  method,
  url, // the full URL the server will see — scheme, host, and path are all signed
  body,
  keyId: identity.id,
  secretKey: identity.currentKeys[0].secretKey
});
await fetch(url, { method, headers: { "content-type": "application/json", ...headers }, body });
```

## Rejection reasons

Every rejection names its cause in `reason` (and `VerifyError.reason`):

- `keyid_invalid` — the `keyid` is neither a participant id nor a decodable `KeyRef`
- `missing_signature` — no RFC 9421 `Signature-Input` header with a `keyid`
- `delegation_required` — a bare-`KeyRef` `keyid` arrived without a `PN-Grants` chain
- `agent_key_log_unresolved` — no replay-valid key log resolves for the claimed id
- `signature_invalid` — the signature fails against the agent's current keys, or the request
  does not match the spec 004 profile
- `signature_stale` — the **receipt expired**: the signature's `created` time is outside the
  clock-skew window, in either direction. The signature itself is usually perfectly valid, so
  the remedy is the caller's clock or a fresh request — never its keys. Governed by
  [`maxSkewSeconds`](#freshness-and-the-skew-window)
- `content_digest_mismatch` — the `Content-Digest` header does not match the body presented
  (RFC 9530). Far more often a body-rewriting intermediary — a re-encoding proxy, a framework
  that reserialized a parsed body before the verifier saw it — than an attacker
- `nonce_replayed` — the request nonce was already used at this verifier. Only a request that
  FULLY AUTHORIZES records its nonce: the guard is asked early, so a replay is still refused
  before any grant-chain work, but the entry is written after every authorization stage, so
  traffic this verifier rejects cannot fill the bounded map on legitimate callers' behalf
- `grants_malformed` — the `PN-Grants` header failed to decode
- `grants_leaf_audience_mismatch` — the chain's leaf audience is not the signing principal
- `grants_abilities_insufficient` — the chain does not cover `requireAbilities`
- `represents_chain_unverified` — `requireRepresents` is set and no verified chain
  from that organization exists (unset, no representation is read or reported)
- `body_not_raw` — the middleware saw something other than the raw body bytes; mount
  `express.raw({ type: "*/*" })` before it. A decoded `string` body counts as parsed and is
  refused too: the digest the signature covers is over the octets that arrived, and a charset
  decode has already folded every malformed sequence to U+FFFD, so the middleware can no
  longer tell one delivery from another. Decode after `req.verifiedAgent` is set
- `discovery_response_too_large` — a discovery response carried more bytes than
  `maxResponseBytes` allows (declared in `content-length`, or observed while streaming). A 401
  rather than a 503 because retrying buys the same oversized answer: the host chose to send it
- `discovery_redirect_refused` — discovery answered with a redirect. The view follows none — a
  redirect from an untrusted host is an address the operator never configured — so the lookup is
  refused and no second request is issued

These are **not** authentication failures. They are thrown as `VerifyCapacityError`
with `status: 503`, and a client should retry rather than re-authenticate:

- `nonce_capacity` — replay-nonce tracking is full and nothing has expired; the verifier
  refuses rather than admit a request it cannot record (which would disable replay
  protection). Self-healing as the window drains.
- `clock_invalid` — the verifier's clock is not a usable integer second count.
- `request_signature_too_expensive` — the RFC 9421 key search exhausted the operation or outer
  request allowance.
- `agent_key_log_too_expensive` — replaying the caller's key log would exceed the allowance.
- `discovery_fetch_capacity` / `discovery_fetch_timeout` — the view's outbound fetch throttle
  is saturated, or a lookup did not get a slot before its deadline.
- `discovery_fetch_deadline` — a discovery exchange got its slot and then did not complete
  (connect, headers **and** body) within `fetchDeadlineMs`. Distinct from
  `discovery_fetch_timeout`, which never opened a socket: this one is the upstream stalling,
  not this process being busy.

### Classifying a reason

`VerifyError.reason` is typed as `VerifyReason`, a closed union of this package's own vocabulary
(`KnownVerifyReason`) plus the resolver reasons forwarded verbatim (`ResolverReason`), so a
`switch` over it can be exhaustive. Both are exported, along with the value list and a predicate:

```ts
import {
  isVerifyCapacityReason,
  KNOWN_VERIFY_REASONS,
  VERIFY_CAPACITY_REASONS,
  VerifyError,
  type VerifyReason
} from "@kinnet/verify";

try {
  await kinnet.verify(inbound);
} catch (error) {
  if (error instanceof VerifyError) {
    const reason: VerifyReason = error.reason; // narrowed, not `string`
    const retryable = isVerifyCapacityReason(reason); // 503 vs 401
  }
}
```

Prefer `isVerifyCapacityReason` over a hand-written list. Only some capacity reasons end in
`_too_expensive` — `nonce_capacity`, `clock_invalid` and the two discovery-fetch reasons do not —
so a suffix test alone answers 401 for cases that should be 503. The predicate applies both rules:
membership in `VERIFY_CAPACITY_REASONS` for this package's reasons, and the suffix for the
resolver's, which grows on its own schedule and so cannot be enumerated here without going stale.

### Freshness and the skew window

A request signature is fresh when `|now - created| <= maxSkewSeconds`, **inclusive at both ends**.
The default is `DEFAULT_MAX_SKEW_SECONDS`, re-exported from this package: **±120 seconds** around
the `created` parameter the signer chose. Outside it, the request is rejected as
`signature_stale` — whether the receipt is too old or dated too far ahead.

```ts
import { createVerifier, DEFAULT_MAX_SKEW_SECONDS } from "@kinnet/verify";

createVerifier({ discoveryUrl, maxSkewSeconds: 300 }); // widen to ±5 minutes
```

Three things follow from that number, and they are worth knowing before changing it:

- **Replay-nonce retention is derived from it**, as `2 * skew + 1` seconds. Freshness is
  inclusive, so one signature is presentable across the whole closed interval
  `[created - skew, created + skew]` — a `2 * skew` window — and the nonce must be remembered for
  at least as long, or the same signature becomes replayable at the far edge. Widening the skew
  therefore lengthens nonce retention and raises the steady-state size of the nonce map
  (arrival rate × TTL); it is one knob, not two.
- **It is a transport bound, not an authority bound.** It is unrelated to grant expiry: a chain's
  `[issuedAt, expiresAt]` window is evaluated by the trust resolver and says how long the
  _authority_ lasts, while this says how long one signed _request_ stays presentable. A
  long-lived grant does not widen this, and a wide skew does not extend a grant.
- **Freshness is checked before any signature verification**, so a stale request costs this
  verifier no Ed25519 work.

There is deliberately no reason for a _backward_ clock step. Nonce retention is measured on a
monotonic clock, so a wall-clock step cannot cut retention short or strand entries; the verifier
does not refuse on one. A backward step does leave a residual — freshness compares against a
signer-chosen wall-clock value, so it can re-admit a recently-reclaimed signature — which
`packages/protocol/spec/013-realtime.md` documents as an operational requirement rather than
something this library refuses its way out of.

A presented grant chain adds the trust resolver's own reasons verbatim, among them:

- `grant_audience_not_admitted` — the chain's effective `aud` does not name `verifierId`
  (or none was configured)
- `grant_audience_required` — `requireAud` is set and no link of the chain carries `aud`
- `grants_abilities_insufficient` — the chain does not cover `requireAbilities`
