# @kinnet/discovery-client

Publish to and read from a Kinnet discovery service — the public directory of participants, key
logs, profiles, node records, claims, relationships and revocations. Every write carries **two
signatures** (spec 004): the record's own, which travels with the bytes, and an RFC 9421 HTTP
Message Signature over the exact body octets, which authenticates the writer.

```bash
npm install @kinnet/discovery-client
```

## Mint an identity and publish it

```ts
import { createIdentity } from "@kinnet/crypto";
import { createDiscoveryClient, createProfileRecord } from "@kinnet/discovery-client";

const me = createIdentity(); // self-custodial: the secret key never leaves this process
const discovery = createDiscoveryClient({ discoveryUrl: "https://discovery.example.com" });

// The key log FIRST, always: every other write is authenticated against it.
const state = await discovery.publishKeyLog(me);

await discovery.publishProfile(
  me,
  createProfileRecord(me, { type: "organization", displayName: "Acme" })
);

console.log(state.id); // your participant id
```

Keep the secret key if you want the identity to stay yours — rotation and recovery work from it.

## Publish an issued record

Issuing and publishing are separate jobs. [`@kinnet/trust`](../trust) mints the record and signs
it at the issuer's current keys; this package puts it where a stranger can find it.

```ts
import { issueRelationship, issueRevocation } from "@kinnet/trust";
import { canonicalDigest } from "@kinnet/crypto";

const edge = issueRelationship(org, {
  id: "represents-1",
  subjectId: agent.id,
  predicate: "represents",
  objectId: org.id
});

// Published under the ISSUER's path — discovery keys a record by who asserted it, not by
// whom it is about. The listing is the other way round: reads are by SUBJECT.
await discovery.publishRelationship(org, edge);

// Withdrawing it later is one signed record, keyed by the digest of what it revokes.
await discovery.publishRevocation(org, issueRevocation(org, canonicalDigest(edge)));
```

The two **self-records** — a participant's profile and its node record — are built here rather
than in `@kinnet/trust`, because their subject is their signer and there is no third party to
issue them: `createProfileRecord(identity, …)` and `createNodeRecord(identity, …)`.

### Schema defaults are not signed bytes

`createProfileRecord` writes `capabilities` and `verifiedDomains` into the record **explicitly**,
empty arrays included. `participantProfileSchema` defaults them on parse, so a profile signed
without them gains two fields the signature never covered — the stored record and the signed
bytes would differ, and the record's own signature would stop verifying for everyone who reads
it back. Anything you hand-build for these routes needs the same care.

## Reads

```ts
const profile = await discovery.getProfile(id); // null when there is none
const events = await discovery.getKeyLog(id); // null when there is none
const state = await discovery.getKeyState(id); // replayed locally from the log
const { records, nextCursor } = await discovery.getClaims(id);
const edges = await discovery.getRelationships(id, { issuer, object, predicate });
const revocations = await discovery.getRevocations(digest, [issuerId]);
const bundle = await discovery.getExport(id); // the whole public footprint
```

Reads are anonymous — every discovery read is public. Listings are **bounded** by the service, so
they answer a page and a `nextCursor`; the export bundle names any collection it had to shorten
in `truncated`. `getRelationships` takes either paging options or the full
`{ issuer, object, predicate }` tuple, which names one decision tuple and answers zero or one
records rather than a list whose size somebody else controls.

`getKeyState` never reads the service's computed answer: it fetches the log and replays it
locally, bound to the id that was asked for. A replayed id is derived from the log's own
inception event, so binding the two is what stops a host serving one participant's valid log at
another's path.

## This is a plain client, not a verifier

Reads here are strictly parsed (a duplicate JSON key is refused, not resolved) and schema-checked,
which keeps a malformed delivery out of your process. That is **not** enough to decide
authorization from: a record served here has not had its own signature checked against its
issuer's replayed key log, and nothing bounds what a slow or enormous response can cost you.

For verification-grade reads — the ones an authorization decision rests on — use
`createDiscoveryView` from [`@kinnet/verify`](../verify). It treats the host as hostile: key logs
are replayed locally, every record it is handed is re-checked including its issuer and signature,
and the delivery itself is bounded by a deadline, a byte cap and a refusal to follow redirects.

## Errors

Anything that is not a success throws `DiscoveryClientError`:

```ts
import { DiscoveryClientError } from "@kinnet/discovery-client";

try {
  await discovery.publishProfile(me, profile);
} catch (error) {
  if (error instanceof DiscoveryClientError) {
    error.status; // 400, 401, 409, 422, …
    error.code; // the service's own `error` field: "profile_signature_invalid", "key_log_conflict", …
    error.body; // the parsed body, or the raw text when it was not JSON
  }
}
```

`code` is the value worth branching on. A `404` on a single-record read is not an error at all —
`getProfile`, `getKeyLog` and `getKeyState` return `null`.
