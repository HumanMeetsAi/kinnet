import { canonicalDigest, createIdentity, signRecord, signThresholdRecord } from "@kinnet/crypto";
import type { KeyEvent, ParticipantProfile, Relationship, Revocation } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  AGENT_CARD_PATH,
  agentCardFromProfile,
  buildAgentCard,
  consumeAgentCard,
  PN_EXTENSION_URI,
  parseKinnetExtension,
  verifyAgentCard
} from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const NOW = new Date("2026-06-12T00:00:00.000Z");
const ISSUED_AT = "2026-06-01T00:00:00.000Z";
const AGENT_ORIGIN = "https://agent.acme.example";
const DISCOVERY_URL = "https://discovery.example.com";

const org = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
const agent = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });

function representsEdge(): Relationship {
  return signRecord(
    {
      id: "rel-represents-1",
      subjectId: agent.id,
      predicate: "represents",
      objectId: org.id,
      issuedBy: org.id,
      issuedAt: ISSUED_AT
    },
    org.currentKeys[0]!.secretKey
  ) as Relationship;
}

const card = buildAgentCard({
  name: "Acme Sales Agent",
  description: "Quotes and orders on behalf of Acme",
  url: `${AGENT_ORIGIN}/a2a`,
  participantId: agent.id,
  discoveryUrl: DISCOVERY_URL,
  organizationId: org.id
});

type WorldData = {
  card?: unknown;
  logs?: Record<string, KeyEvent[]>;
  relationships?: Record<string, Relationship[]>;
  revocations?: Record<string, Revocation[]>;
};

/** One fetch stub serving the agent's well-known card and the discovery read surface. */
function worldFetch(data: WorldData): typeof fetch {
  return async (input) => {
    const url = new URL(
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url
    );

    if (url.origin === AGENT_ORIGIN && url.pathname === AGENT_CARD_PATH) {
      return data.card
        ? Response.json(data.card)
        : Response.json({ error: "not_found" }, { status: 404 });
    }

    const keyLog = /^\/participants\/([^/]+)\/key-log$/.exec(url.pathname);
    if (keyLog) {
      const log = data.logs?.[decodeURIComponent(keyLog[1]!)];
      return log
        ? Response.json({ events: log })
        : Response.json({ error: "key_log_not_found" }, { status: 404 });
    }
    const relationships = /^\/participants\/([^/]+)\/relationships$/.exec(url.pathname);
    if (relationships) {
      // Only the TARGETED form is served. A consumer that asked for the listing gets the
      // route's 400, which throws in the client — so a test cannot pass by scanning.
      const subjectId = decodeURIComponent(relationships[1]!);
      const issuer = url.searchParams.get("issuer");
      const object = url.searchParams.get("object");
      const predicate = url.searchParams.get("predicate");
      if (issuer === null || object === null || predicate === null) {
        return Response.json({ error: "invalid_query" }, { status: 400 });
      }
      const edge = (data.relationships?.[subjectId] ?? []).find(
        (row) =>
          row.issuedBy === issuer &&
          row.subjectId === subjectId &&
          row.objectId === object &&
          row.predicate === predicate
      );
      return Response.json({ relationship: edge ?? null });
    }
    const revocations = /^\/revocations\/([^/]+)$/.exec(url.pathname);
    if (revocations) {
      return Response.json({
        revocations: data.revocations?.[decodeURIComponent(revocations[1]!)] ?? []
      });
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  };
}

const happyWorld: WorldData = {
  card,
  logs: { [org.id]: org.log, [agent.id]: agent.log },
  relationships: { [agent.id]: [representsEdge()] }
};

describe("serving agent cards", () => {
  it("builds a plain A2A card carrying the Kinnet extension", () => {
    expect(card.name).toBe("Acme Sales Agent");
    expect(card.protocolVersion).toBe("0.3.0");
    expect(card.capabilities.extensions).toEqual([
      expect.objectContaining({
        uri: PN_EXTENSION_URI,
        params: {
          participantId: agent.id,
          discoveryUrl: DISCOVERY_URL,
          organizationId: org.id
        }
      })
    ]);
  });

  it("merges card overrides last", () => {
    const custom = buildAgentCard({
      name: "Agent",
      url: `${AGENT_ORIGIN}/a2a`,
      participantId: agent.id,
      discoveryUrl: DISCOVERY_URL,
      card: { version: "2.0.0", provider: { organization: "Acme" } }
    });
    expect(custom.version).toBe("2.0.0");
    expect(custom.provider).toEqual({ organization: "Acme" });
  });

  it("derives a card from a participant profile", () => {
    const profile: ParticipantProfile = {
      id: agent.id,
      type: "agent",
      displayName: "Acme Sales Agent",
      description: "Quotes and orders",
      capabilities: ["quote", "order"],
      verifiedDomains: [],
      updatedAt: ISSUED_AT,
      signature: agent.log[0]!.signature[0]!
    };
    const derived = agentCardFromProfile(profile, {
      url: `${AGENT_ORIGIN}/a2a`,
      discoveryUrl: DISCOVERY_URL,
      organizationId: org.id
    });

    expect(derived.name).toBe("Acme Sales Agent");
    expect(derived.skills.map((skill) => skill.id)).toEqual(["quote", "order"]);
    expect(parseKinnetExtension(derived)).toEqual({
      participantId: agent.id,
      discoveryUrl: DISCOVERY_URL,
      organizationId: org.id
    });
  });

  it("parses no extension from foreign or malformed cards", () => {
    expect(parseKinnetExtension({ name: "Plain A2A", capabilities: {} })).toBeNull();
    expect(parseKinnetExtension(null)).toBeNull();
    expect(
      parseKinnetExtension({
        capabilities: {
          extensions: [
            { uri: PN_EXTENSION_URI, params: { participantId: "not-an-id", discoveryUrl: "x" } }
          ]
        }
      })
    ).toBeNull();
  });
});

describe("consuming agent cards", () => {
  it("fetches the well-known card and verifies the represents chain end to end", async () => {
    const consumed = await consumeAgentCard(AGENT_ORIGIN, {
      fetch: worldFetch(happyWorld),
      now: () => NOW
    });

    expect(consumed.card.name).toBe("Acme Sales Agent");
    expect(consumed.kinnet).toEqual({
      status: "verified",
      participantId: agent.id,
      discoveryUrl: DISCOVERY_URL
    });
  });

  it("reports a card without the extension instead of failing", async () => {
    const consumed = await consumeAgentCard(AGENT_ORIGIN, {
      fetch: worldFetch({ card: { name: "Plain A2A Agent", capabilities: {} } }),
      now: () => NOW
    });
    expect(consumed.kinnet).toEqual({ status: "no_kinnet_extension" });
  });

  it("reports unverified when no key log resolves for the claimed participant", async () => {
    const verdict = await verifyAgentCard(card, {
      fetch: worldFetch({ logs: { [org.id]: org.log } }),
      now: () => NOW
    });
    expect(verdict).toEqual({
      status: "unverified",
      participantId: agent.id,
      reason: "agent_key_log_unresolved"
    });
  });

  it("reports unverified when the only published edge is issued by someone else", async () => {
    // A stranger publishing "this agent represents Acme" is not on the decision key: the
    // lookup names Acme as issuer, so this edge is never returned, let alone believed.
    const stranger = createIdentity({ currentSeed: seed(5), nextSeed: seed(6) });
    const forged = signRecord(
      {
        id: "rel-forged-1",
        subjectId: agent.id,
        predicate: "represents",
        objectId: org.id,
        issuedBy: stranger.id,
        issuedAt: ISSUED_AT
      },
      stranger.currentKeys[0]!.secretKey
    ) as Relationship;

    const verdict = await verifyAgentCard(card, {
      fetch: worldFetch({
        logs: { ...happyWorld.logs, [stranger.id]: stranger.log },
        relationships: { [agent.id]: [forged] }
      }),
      now: () => NOW
    });
    expect(verdict).toEqual({
      status: "unverified",
      participantId: agent.id,
      reason: "represents_chain_unverified"
    });
  });

  it("reports unverified when the claimed represents chain is revoked", async () => {
    const edge = representsEdge();
    const revocation = signThresholdRecord(
      { revokes: canonicalDigest(edge), issuerId: org.id, revokedAt: ISSUED_AT },
      [org.currentKeys[0]!.secretKey]
    ) as Revocation;

    const verdict = await verifyAgentCard(card, {
      fetch: worldFetch({
        logs: happyWorld.logs,
        relationships: { [agent.id]: [edge] },
        revocations: { [revocation.revokes]: [revocation] }
      }),
      now: () => NOW
    });
    expect(verdict).toEqual({
      status: "unverified",
      participantId: agent.id,
      reason: "represents_chain_unverified"
    });
  });

  it("verifies a card claiming no organization, reading no relationship at all", async () => {
    // No organization claim, no representation question — and so no relationship read. The
    // stub answers a listing request with the route's 400, which would throw here.
    const unclaimed = buildAgentCard({
      name: "Agent",
      url: `${AGENT_ORIGIN}/a2a`,
      participantId: agent.id,
      discoveryUrl: DISCOVERY_URL
    });
    const verdict = await verifyAgentCard(unclaimed, {
      fetch: worldFetch(happyWorld),
      now: () => NOW
    });
    expect(verdict).toEqual({
      status: "verified",
      participantId: agent.id,
      discoveryUrl: DISCOVERY_URL
    });
  });

  it("throws on a missing or malformed card document", async () => {
    await expect(
      consumeAgentCard(AGENT_ORIGIN, { fetch: worldFetch({}), now: () => NOW })
    ).rejects.toThrow(/agent card request failed/i);

    await expect(
      consumeAgentCard(AGENT_ORIGIN, {
        fetch: worldFetch({ card: { nope: true } }),
        now: () => NOW
      })
    ).rejects.toThrow(/no valid agent card/i);
  });
});
