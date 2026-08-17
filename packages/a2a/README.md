# @kinnet/a2a

Bridge between Kinnet participant records and [A2A](https://a2a-protocol.org) agent cards.
The card stays a plain A2A card any client can consume; a `urn:pn:participant:v1`
extension carries a pointer (participant ID + discovery URL) that lets a Kinnet-aware
counterparty verify the agent's identity and represents chain from **signed records** —
which an agent card alone cannot prove.

## Serve: publish your card with a verifiable identity

```ts
import { AGENT_CARD_PATH, buildAgentCard } from "@kinnet/a2a";

const card = buildAgentCard({
  name: "Acme Sales Agent",
  url: "https://agent.acme.example/a2a",
  participantId: agentId,
  discoveryUrl: "https://discovery.example.com",
  organizationId: acmeId // the represents claim a counterparty can verify
});

app.get(AGENT_CARD_PATH, (_req, res) => res.json(card)); // Express
```

`agentCardFromProfile(profile, options)` derives name, description, and skills from a
published `ParticipantProfile` instead.

## Consume: fetch a card, verify the chain

```ts
import { consumeAgentCard } from "@kinnet/a2a";

const { card, kinnet } = await consumeAgentCard("https://agent.acme.example");
// kinnet.status: "verified" | "unverified" | "no_kinnet_extension"
// kinnet.participantId / kinnet.discoveryUrl on a verified card
```

Verification resolves the agent's key log from discovery (replayed locally — discovery
is a directory, not a trusted party). When the card claims an `organizationId`, the
`represents` edge for that exact (issuer, subject, object, predicate) tuple is looked up
by name — never by scanning every edge published about the agent — and verified through
the trust resolver: issued and signed by the organization, not expired, not revoked
(specs 008/009). If it does not verify, the result is `unverified` with
`reason: "represents_chain_unverified"`. A card that claims no organization asks no
representation question, and none is read.

A card without the extension reports `no_kinnet_extension` rather than failing — it is
still a valid A2A card, just an unverifiable one.
