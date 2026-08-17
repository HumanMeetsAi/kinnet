/**
 * The client against a real HTTP service (`node:http` on an ephemeral port) that enforces the
 * discovery contract: RFC 9421 request verification against the stored key log, the record's
 * own signature at the issuer's threshold, path-to-record id binding, strict parsing, and JSON
 * error codes. Nothing between the client and the socket is stubbed.
 */
import { canonicalDigest, createIdentity, signRecord, signThresholdRecord } from "@kinnet/crypto";
import type { Claim, Relationship, Revocation } from "@kinnet/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createDiscoveryClient,
  createNodeRecord,
  createProfileRecord,
  DiscoveryClientError,
  type DiscoveryClient
} from "../src/index.js";
import { startFakeDiscovery, type FakeDiscovery } from "./fake-discovery.js";

let discovery: FakeDiscovery;
let client: DiscoveryClient;

const org = createIdentity();
const agent = createIdentity();

function relationship(id: string, predicate: string): Relationship {
  return signRecord(
    {
      id,
      subjectId: agent.id,
      predicate,
      objectId: org.id,
      issuedBy: org.id,
      issuedAt: "2026-07-01T00:00:00.000Z"
    },
    org.currentKeys[0]!.secretKey
  ) as Relationship;
}

function claim(id: string): Claim {
  return signRecord(
    {
      id,
      subjectId: agent.id,
      claimType: "role",
      value: "operator",
      issuedBy: org.id,
      issuedAt: "2026-07-01T00:00:00.000Z"
    },
    org.currentKeys[0]!.secretKey
  ) as Claim;
}

function revocation(revokes: string): Revocation {
  return signThresholdRecord(
    { revokes, issuerId: org.id, revokedAt: "2026-07-02T00:00:00.000Z", reason: "superseded" },
    org.currentKeys.map((keyPair) => keyPair.secretKey)
  ) as Revocation;
}

beforeAll(async () => {
  discovery = await startFakeDiscovery();
  client = createDiscoveryClient({ discoveryUrl: discovery.url });
});

afterAll(async () => {
  await discovery.close();
});

describe("publishKeyLog", () => {
  it("bootstraps a participant on its first write and returns the replayed key state", async () => {
    const state = await client.publishKeyLog(org);
    expect(state.id).toBe(org.id);
    expect(state.keys.length).toBeGreaterThan(0);
    expect(discovery.store.keyLogs.get(org.id)).toEqual(org.log);

    await client.publishKeyLog(agent);
  });

  it("reads the stored log back and replays it to the id that was asked for", async () => {
    const events = await client.getKeyLog(org.id);
    expect(events).toEqual(org.log);
    const state = await client.getKeyState(org.id);
    expect(state?.id).toBe(org.id);
  });

  it("answers null for a participant nobody published", async () => {
    const stranger = createIdentity();
    expect(await client.getKeyLog(stranger.id)).toBeNull();
    expect(await client.getKeyState(stranger.id)).toBeNull();
    expect(await client.getProfile(stranger.id)).toBeNull();
  });
});

describe("createProfileRecord and publishProfile", () => {
  it("signs the schema's defaults into the bytes, so the stored record still verifies", async () => {
    const profile = createProfileRecord(org, {
      type: "organization",
      displayName: "Acme",
      description: "A test organization."
    });
    // The 017 default gotcha: `participantProfileSchema` fills these on parse, so a record
    // signed without them would gain two fields its signature never covered.
    expect(profile.capabilities).toEqual([]);
    expect(profile.verifiedDomains).toEqual([]);

    const stored = await client.publishProfile(org, profile);
    expect(stored).toEqual(profile);
    expect(await client.getProfile(org.id)).toEqual(profile);
  });

  it("carries explicit capabilities and verifiedDomains through to the stored record", async () => {
    const profile = createProfileRecord(agent, {
      type: "agent",
      displayName: "Acme Sales Agent",
      capabilities: ["sales/quote"],
      verifiedDomains: ["acme.example"]
    });
    await client.publishProfile(agent, profile);
    const read = await client.getProfile(agent.id);
    expect(read?.capabilities).toEqual(["sales/quote"]);
    expect(read?.verifiedDomains).toEqual(["acme.example"]);
  });
});

describe("createNodeRecord and publishNode", () => {
  it("defaults the label to the node id and the transports to https", async () => {
    const node = createNodeRecord(agent, {
      nodeId: "node-1",
      endpoint: "https://node.acme.example"
    });
    expect(node.label).toBe("node-1");
    expect(node.transports).toEqual(["https"]);

    await client.publishNode(agent, node);
    const nodes = await client.getNodes(agent.id);
    expect(nodes.records).toEqual([node]);
    expect(nodes.nextCursor).toBeNull();
  });
});

describe("issued records are published under the issuer", () => {
  it("puts a relationship at the issuer's path and lists it under the subject", async () => {
    const edge = relationship("represents-1", "represents");
    const stored = await client.publishRelationship(org, edge);
    expect(stored).toEqual(edge);

    // The path is the ISSUER's; the listing is the SUBJECT's.
    const listed = await client.getRelationships(agent.id);
    expect(listed.records.map((row) => row.id)).toContain("represents-1");

    const targeted = await client.getRelationships(agent.id, {
      issuer: org.id,
      object: org.id,
      predicate: "represents"
    });
    expect(targeted.records).toEqual([edge]);
    expect(targeted.nextCursor).toBeNull();
  });

  it("answers an empty page for a tuple nobody published", async () => {
    const targeted = await client.getRelationships(agent.id, {
      issuer: org.id,
      object: org.id,
      predicate: "employs"
    });
    expect(targeted.records).toEqual([]);
  });

  it("puts a claim at the issuer's path and lists it under the subject", async () => {
    const record = claim("role-1");
    expect(await client.publishClaim(org, record)).toEqual(record);
    const listed = await client.getClaims(agent.id);
    expect(listed.records).toEqual([record]);
  });

  it("puts a revocation at the issuer's path, keyed by the digest it revokes", async () => {
    const edge = relationship("member-of-1", "member-of");
    await client.publishRelationship(org, edge);
    const digest = canonicalDigest(edge);

    const record = revocation(digest);
    expect(await client.publishRevocation(org, record)).toEqual(record);

    const found = await client.getRevocations(digest, [org.id]);
    expect(found).toEqual([record]);
    // An issuer that revoked nothing gets an empty answer, not somebody else's revocation.
    expect(await client.getRevocations(digest, [agent.id])).toEqual([]);
    expect(await client.getRevocations(digest, [])).toEqual([]);
  });
});

describe("getExport", () => {
  it("returns the participant's public footprint with its truncation flags", async () => {
    const bundle = await client.getExport(agent.id);
    expect(bundle.id).toBe(agent.id);
    expect(bundle.profile?.id).toBe(agent.id);
    expect(bundle.keyLog).toEqual(agent.log);
    expect(bundle.nodes).toHaveLength(1);
    expect(bundle.claims.map((row) => row.id)).toContain("role-1");
    expect(bundle.truncated).toEqual([]);
  });
});

describe("failures surface as DiscoveryClientError", () => {
  it("reports the service's own error code when the signed body was tampered with in flight", async () => {
    // The request signature covers the body octets, so a proxy that rewrites one byte breaks
    // the signature — which is the whole point of signing it. The tamper is applied AFTER the
    // client signed, by a fetch that swaps the body on its way out.
    const tampering = createDiscoveryClient({
      discoveryUrl: discovery.url,
      fetch: (input, init) => {
        const body = typeof init?.body === "string" ? init.body : "";
        return fetch(input, { ...init, body: body.replace("Acme", "Acmf") });
      }
    });
    const profile = createProfileRecord(org, { type: "organization", displayName: "Acme" });

    const error = await tampering.publishProfile(org, profile).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(DiscoveryClientError);
    const failure = error as DiscoveryClientError;
    expect(failure.status).toBe(401);
    expect(failure.code).toBe("invalid_signature");
    expect(failure.body).toEqual({ error: "invalid_signature" });
  });

  it("reports the record-signature refusal when the record itself was altered after signing", async () => {
    const profile = createProfileRecord(org, { type: "organization", displayName: "Acme" });
    const forged = { ...profile, displayName: "Not Acme" };

    const error = await client.publishProfile(org, forged).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(DiscoveryClientError);
    const failure = error as DiscoveryClientError;
    expect(failure.status).toBe(422);
    expect(failure.code).toBe("profile_signature_invalid");
  });

  it("refuses to publish for a participant whose key log the service does not hold", async () => {
    const stranger = createIdentity();
    const profile = createProfileRecord(stranger, { type: "person", displayName: "Nobody" });

    const error = await client.publishProfile(stranger, profile).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(DiscoveryClientError);
    expect((error as DiscoveryClientError).code).toBe("unknown_participant");
  });
});

describe("discoveryUrl", () => {
  it("strips trailing slashes so a configured base URL cannot double the separator", () => {
    expect(createDiscoveryClient({ discoveryUrl: `${discovery.url}//` }).discoveryUrl).toBe(
      discovery.url
    );
  });
});
