/**
 * `explainParticipant` against a discovery host this test writes every byte of.
 *
 * The host is a route table behind an injected `fetch`, not a running service, and that is the
 * point: a check that only ever sees an honest server proves nothing about a tool whose whole
 * claim is that a lying host cannot pass a line. So the same table is used to serve a correct
 * answer and, one case later, a substituted or forged one, and the assertions are on the verdict
 * each line came back with.
 */
import {
  canonicalDigest,
  createIdentity,
  signRecord,
  keyLogAnchor,
  signThresholdRecord,
  type Identity
} from "@kinnet/crypto";
import type { Claim, Grant, ParticipantProfile, Relationship, Revocation } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import { explainParticipant, type ExplainLine, type ExplainResult } from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const org = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
const agent = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
const stranger = createIdentity({ currentSeed: seed(5), nextSeed: seed(6) });

const ISSUED_AT = "2026-06-01T00:00:00.000Z";
const EXPIRED_AT = "2026-06-02T00:00:00.000Z";
const DISCOVERY = "https://discovery.example.com";

function profileOf(
  identity: Identity,
  type: "organization" | "agent",
  displayName: string
): ParticipantProfile {
  return signRecord(
    {
      id: identity.id,
      type,
      displayName,
      capabilities: [] as string[],
      verifiedDomains: [] as string[],
      updatedAt: ISSUED_AT
    },
    identity.currentKeys[0]!.secretKey
  ) as ParticipantProfile;
}

const orgProfile = profileOf(org, "organization", "HumanMeetsAI");
const agentProfile = profileOf(agent, "agent", "HMAI Sales Agent");

/** `member-of`, signed by the ORG — so the line is decided against the org's key state. */
function memberEdge(signer: Identity, over: { expiresAt?: string } = {}): Relationship {
  return signRecord(
    {
      id: "rel-member-1",
      subjectId: agent.id,
      predicate: "member-of",
      objectId: org.id,
      issuedBy: org.id,
      issuedAt: ISSUED_AT,
      ...over
    },
    signer.currentKeys[0]!.secretKey
  ) as Relationship;
}

const claim: Claim = signRecord(
  {
    id: "claim-1",
    subjectId: agent.id,
    claimType: "sales/quote",
    value: true,
    issuedBy: org.id,
    issuedAt: ISSUED_AT
  },
  org.currentKeys[0]!.secretKey
) as Claim;

const rootGrant = signThresholdRecord(
  {
    subjectId: org.id,
    issuerId: org.id,
    audienceId: agent.id,
    abilities: ["sales/quote"],
    caveats: {},
    anchor: keyLogAnchor(org.log),
    proof: null,
    issuedAt: ISSUED_AT
  },
  [org.currentKeys[0]!.secretKey]
) as Grant;

const grantRevocation = signThresholdRecord(
  {
    revokes: canonicalDigest(rootGrant),
    issuerId: org.id,
    anchor: keyLogAnchor(org.log),
    revokedAt: ISSUED_AT
  },
  [org.currentKeys[0]!.secretKey]
) as Revocation;

type Host = {
  /** Key logs, keyed by the id they are SERVED at — which is not always the id they answer for. */
  keyLogs?: Record<string, unknown>;
  profiles?: Record<string, unknown>;
  relationships?: Record<string, Relationship[]>;
  claims?: Record<string, Claim[]>;
  revocations?: Revocation[];
};

/**
 * A discovery host as a route table. Anything not in the table 404s with an empty body, which is
 * what a real service answers for a participant it has never heard of.
 */
function serving(host: Host): typeof fetch {
  return ((input: RequestInfo | URL): Promise<Response> => {
    const href = input instanceof URL ? input.href : typeof input === "string" ? input : input.url;
    const url = new URL(href);
    const path = url.pathname;
    const json = (body: unknown): Promise<Response> => Promise.resolve(Response.json(body));
    const missing = (): Promise<Response> => Promise.resolve(new Response("", { status: 404 }));

    let match = /^\/participants\/([^/]+)\/key-log$/.exec(path);
    if (match) {
      const events = host.keyLogs?.[match[1]!];
      return events === undefined ? missing() : json({ events });
    }
    match = /^\/participants\/([^/]+)\/relationships$/.exec(path);
    if (match) {
      return json({ relationships: host.relationships?.[match[1]!] ?? [] });
    }
    match = /^\/participants\/([^/]+)\/claims$/.exec(path);
    if (match) {
      return json({ claims: host.claims?.[match[1]!] ?? [] });
    }
    match = /^\/revocations\/(.+)$/.exec(path);
    if (match) {
      const digest = decodeURIComponent(match[1]!);
      const issuers = url.searchParams.getAll("issuer");
      return json({
        revocations: (host.revocations ?? []).filter(
          (record) => record.revokes === digest && issuers.includes(record.issuerId)
        )
      });
    }
    match = /^\/participants\/([^/]+)$/.exec(path);
    if (match) {
      const profile = host.profiles?.[match[1]!];
      return profile === undefined ? missing() : json(profile);
    }
    return missing();
  }) as typeof fetch;
}

/** The honest host: both identities, both profiles, the member edge and the claim. */
const honest: Host = {
  keyLogs: { [org.id]: org.log, [agent.id]: agent.log },
  profiles: { [org.id]: orgProfile, [agent.id]: agentProfile },
  relationships: { [agent.id]: [memberEdge(org)] },
  claims: { [agent.id]: [claim] }
};

function explain(host: Host, over: { tamper?: boolean; grants?: Grant[] } = {}) {
  return explainParticipant(agent.id, {
    discoveryUrl: DISCOVERY,
    fetch: serving(host),
    ...over
  });
}

/** The one line whose text contains `needle`, so an assertion names what it is about. */
function lineWith(result: ExplainResult, needle: string): ExplainLine {
  const found = result.lines.filter((line) => line.text.includes(needle));
  expect(found, `no line containing ${JSON.stringify(needle)} in:\n${render(result)}`).toHaveLength(
    1
  );
  return found[0]!;
}

const render = (result: ExplainResult): string =>
  result.lines
    .map((line) => `${line.ok === null ? "·" : line.ok ? "✔" : "✘"} ${line.text}`)
    .join("\n");

describe("the identity line", () => {
  it("passes when the key log replays and derives the id it was served at", async () => {
    const result = await explain(honest);
    const line = lineWith(result, "derives from its inception keys");

    expect(line.ok).toBe(true);
    expect(line.text).toContain(`${agent.log.length} event(s)`);
    expect(line.text).toContain("threshold 1");
  });

  it("rejects a key log served at the wrong participant's path, and stops there", async () => {
    // What `replayKeyLogFor` buys: the log is impeccable — it is the STRANGER's own, and it
    // replays — but it answers for a different identity than the one it was served for. A tool
    // that replayed it bare would report the stranger's keys as this participant's.
    const result = await explain({ ...honest, keyLogs: { [agent.id]: stranger.log } });

    expect(result.ok).toBe(false);
    // Nothing below the identity is reported: every later check is decided against a key state
    // this run does not have.
    expect(result.lines).toHaveLength(1);
    expect(result.lines[0]!.ok).toBe(false);
    expect(result.lines[0]!.text).toContain("derives from its inception keys");
  });

  it("reports a participant discovery has no key log for", async () => {
    const result = await explain({ profiles: honest.profiles ?? {} });

    expect(result.ok).toBe(false);
    expect(result.lines).toHaveLength(1);
    expect(result.lines[0]).toMatchObject({ ok: false });
    expect(result.lines[0]!.text).toContain("has a key log — discovery serves none");
  });
});

describe("the profile line", () => {
  it("verifies the published profile against the participant's own current key", async () => {
    const line = lineWith(await explain(honest), "profile signed by the current key");

    expect(line.ok).toBe(true);
    expect(line.text).toContain('"HMAI Sales Agent"');
    expect(line.text).toContain("(agent)");
  });

  it("fails the profile line under --tamper, and says so", async () => {
    const result = await explain(honest, { tamper: true });

    expect(lineWith(result, "profile signed by the current key").ok).toBe(false);
    expect(lineWith(result, "--tamper")).toMatchObject({
      ok: null,
      text: "--tamper: one byte of the fetched displayName was flipped"
    });
    expect(result.ok).toBe(false);
  });

  it("treats no published profile as information, not a failure", async () => {
    const result = await explain({ ...honest, profiles: { [org.id]: orgProfile } });

    expect(lineWith(result, "no profile published")).toMatchObject({ ok: null });
    // An identity with no profile is still fully verifiable, so the run passes.
    expect(result.ok).toBe(true);
  });
});

describe("statements others signed about the participant", () => {
  it("verifies a relationship against the ISSUER's key state, and names the issuer", async () => {
    const line = lineWith(await explain(honest), "member-of");

    expect(line.ok).toBe(true);
    // The subject and object are labelled by their profiles; the issuer is named with its id too.
    expect(line.text).toContain('"HMAI Sales Agent" member-of "HumanMeetsAI"');
    expect(line.text).toContain('issued by "HumanMeetsAI"');
    expect(line.text).toContain(org.id.slice(0, 14));
    expect(line.text).toContain("(signature valid, not expired)");
  });

  it("fails an edge the named issuer did not sign", async () => {
    // Signed by the STRANGER while naming the org as issuer — the shape a host would use to
    // manufacture a membership. The subject's key state is irrelevant to it; the issuer's is what
    // decides, and the issuer never signed this.
    const result = await explain({
      ...honest,
      keyLogs: { ...honest.keyLogs, [stranger.id]: stranger.log },
      relationships: { [agent.id]: [memberEdge(stranger)] }
    });

    const line = lineWith(result, "member-of");
    expect(line.ok).toBe(false);
    expect(line.text).toContain("the issuer's signature does not verify");
    expect(result.ok).toBe(false);
  });

  it("fails an expired edge, naming the instant it expired", async () => {
    const result = await explain({
      ...honest,
      relationships: { [agent.id]: [memberEdge(org, { expiresAt: EXPIRED_AT })] }
    });

    const line = lineWith(result, "member-of");
    expect(line.ok).toBe(false);
    expect(line.text).toContain(`expired at ${EXPIRED_AT}`);
    expect(result.ok).toBe(false);
  });

  it("verifies a claim the same way", async () => {
    const line = lineWith(await explain(honest), "claim sales/quote");

    expect(line.ok).toBe(true);
    expect(line.text).toContain('issued by "HumanMeetsAI"');
  });
});

describe("a presented grant chain", () => {
  it("lists the abilities of a chain that verifies", async () => {
    const result = await explain(honest, { grants: [rootGrant] });

    const line = lineWith(result, "grant chain");
    expect(line.ok).toBe(true);
    expect(line.text).toContain("(1 link(s))");
    expect(line.text).toContain("abilities sales/quote — valid");
    expect(result.ok).toBe(true);
  });

  it("fails a chain the issuer revoked", async () => {
    const result = await explain(
      { ...honest, revocations: [grantRevocation] },
      { grants: [rootGrant] }
    );

    const line = lineWith(result, "grant chain");
    expect(line.ok).toBe(false);
    expect(line.text).toContain("grant_revoked");
    expect(result.ok).toBe(false);
  });
});
