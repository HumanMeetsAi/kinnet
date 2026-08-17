/**
 * A discovery service, small enough to read and strict enough to be worth testing against.
 *
 * It implements the CONTRACT of the routes this client speaks to, not a mock of them: the
 * request signature is verified with `verifyRequest` against the key log this server has
 * stored, the record's own signature is verified at the issuer's threshold, the path id is
 * bound to the record's issuer, bodies are parsed strictly and schema-checked, and every
 * refusal is a JSON `{ error }` with the code the real service uses.
 *
 * Deliberately NOT a dependency on `@kinnet/discovery-api`. The mirror exports this package
 * with its dependency closure, and the exporter checks devDependencies as well as
 * dependencies — a test-only edge onto an app would take the whole app with it, or fail the
 * export. Re-stating the contract here is the price of the closure, and it has a benefit: a
 * change to the service that this client would not survive shows up as a disagreement between
 * two implementations rather than as both of them moving together.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  replayKeyLogFor,
  verifyRequest,
  verifyThresholdRecord,
  type KeyState
} from "@kinnet/crypto";
import {
  claimSchema,
  decodeUtf8Strict,
  keyEventLogSchema,
  parseJsonStrict,
  participantNodeSchema,
  participantProfileSchema,
  relationshipSchema,
  revocationSchema,
  type Claim,
  type KeyEvent,
  type ParticipantNode,
  type ParticipantProfile,
  type Relationship,
  type Revocation
} from "@kinnet/protocol";

export type FakeDiscovery = {
  url: string;
  close(): Promise<void>;
  store: {
    keyLogs: Map<string, KeyEvent[]>;
    profiles: Map<string, ParticipantProfile>;
    nodes: Map<string, ParticipantNode[]>;
    claims: Map<string, Claim[]>;
    /** Keyed by SUBJECT — a listing answers "what has been said about this participant". */
    relationships: Map<string, Relationship[]>;
    /** Keyed by revoked digest. */
    revocations: Map<string, Revocation[]>;
  };
};

type Reply = { status: number; body: unknown };

const json = (status: number, body: unknown): Reply => ({ status, body });
const refuse = (status: number, error: string): Reply => ({ status, body: { error } });

/** A record whose `signature` is a scalar, checked at its issuer's threshold as a one-member set. */
function signedAtThreshold(record: { signature: string }, state: KeyState): boolean {
  const { signature, ...unsigned } = record;
  return verifyThresholdRecord(
    { ...unsigned, signature: [signature] },
    state.keys,
    state.threshold
  );
}

export async function startFakeDiscovery(): Promise<FakeDiscovery> {
  const store: FakeDiscovery["store"] = {
    keyLogs: new Map(),
    profiles: new Map(),
    nodes: new Map(),
    claims: new Map(),
    relationships: new Map(),
    revocations: new Map()
  };

  function keyState(id: string): KeyState | null {
    const events = store.keyLogs.get(id);
    if (events === undefined) {
      return null;
    }
    try {
      return replayKeyLogFor(id, events);
    } catch {
      return null;
    }
  }

  function append<T extends { id: string }>(map: Map<string, T[]>, key: string, record: T): void {
    const rows = map.get(key) ?? [];
    map.set(key, [...rows.filter((row) => row.id !== record.id), record]);
  }

  /**
   * Spec 004's REQUEST signature, over the exact octets delivered. The keys come from the
   * stored log, except on a key-log write, where the submitted log IS the bootstrap — there is
   * no prior state to authenticate a first publish against.
   */
  function verifyWrite(
    method: string,
    url: string,
    headers: Record<string, string | undefined>,
    octets: Uint8Array,
    bootstrap: KeyState | null
  ): { ok: true; keyId: string } | { ok: false; reply: Reply } {
    const state = bootstrap;
    if (state === null) {
      return { ok: false, reply: refuse(401, "unknown_participant") };
    }
    try {
      const verified = verifyRequest({
        method,
        url,
        body: octets,
        headers,
        keys: state.keys,
        threshold: state.threshold
      });
      return { ok: true, keyId: verified.keyId };
    } catch {
      return { ok: false, reply: refuse(401, "invalid_signature") };
    }
  }

  function handle(
    method: string,
    path: string,
    query: URLSearchParams,
    url: string,
    headers: Record<string, string | undefined>,
    octets: Uint8Array
  ): Reply {
    const segments = path.split("/").filter((part) => part.length > 0);

    if (method === "GET" && path === "/health") {
      return json(200, { ok: true });
    }

    // ---- reads -------------------------------------------------------------------------
    if (method === "GET" && segments[0] === "participants") {
      const id = decodeURIComponent(segments[1] ?? "");
      const tail = segments[2];
      if (tail === undefined) {
        const profile = store.profiles.get(id);
        return profile === undefined ? refuse(404, "participant_not_found") : json(200, profile);
      }
      if (tail === "key-log") {
        const events = store.keyLogs.get(id);
        return events === undefined ? refuse(404, "key_log_not_found") : json(200, { events });
      }
      if (tail === "nodes") {
        return json(200, { nodes: store.nodes.get(id) ?? [], nextCursor: null });
      }
      if (tail === "claims") {
        return json(200, { claims: store.claims.get(id) ?? [], nextCursor: null });
      }
      if (tail === "relationships") {
        const issuer = query.get("issuer");
        const object = query.get("object");
        const predicate = query.get("predicate");
        const rows = store.relationships.get(id) ?? [];
        if (issuer !== null && object !== null && predicate !== null) {
          const edge = rows.find(
            (row) =>
              row.issuedBy === issuer && row.objectId === object && row.predicate === predicate
          );
          return json(200, { relationship: edge ?? null });
        }
        if (issuer !== null || object !== null || predicate !== null) {
          return refuse(400, "invalid_query");
        }
        return json(200, { relationships: rows, nextCursor: null });
      }
      if (tail === "export") {
        return json(200, {
          format: "pn.discovery.participant-export/1",
          id,
          profile: store.profiles.get(id) ?? null,
          keyLog: store.keyLogs.get(id) ?? null,
          nodes: store.nodes.get(id) ?? [],
          claims: store.claims.get(id) ?? [],
          relationships: store.relationships.get(id) ?? [],
          truncated: []
        });
      }
      return refuse(404, "not_found");
    }

    if (method === "GET" && segments[0] === "revocations") {
      const digest = decodeURIComponent(segments[1] ?? "");
      const rows = store.revocations.get(digest) ?? [];
      const issuers = query.getAll("issuer");
      if (issuers.length === 0) {
        return json(200, { revocations: rows, nextCursor: null });
      }
      if (issuers.length > 64) {
        return refuse(400, "too_many_issuers");
      }
      return json(200, {
        revocations: rows.filter((row) => issuers.includes(row.issuerId))
      });
    }

    // ---- writes ------------------------------------------------------------------------
    if (method !== "PUT" || segments[0] !== "participants") {
      return refuse(404, "not_found");
    }
    const pathId = decodeURIComponent(segments[1] ?? "");
    const kind = segments[2];

    let body: unknown;
    try {
      body = parseJsonStrict(decodeUtf8Strict(octets));
    } catch {
      return refuse(400, "invalid_body");
    }

    if (kind === "key-log") {
      const parsed = keyEventLogSchema.safeParse(body);
      if (!parsed.success) {
        return refuse(400, "invalid_key_log");
      }
      let submitted: KeyState;
      try {
        submitted = replayKeyLogFor(pathId, parsed.data);
      } catch {
        return refuse(422, "key_log_rejected");
      }
      const auth = verifyWrite("PUT", url, headers, octets, submitted);
      if (!auth.ok) {
        return auth.reply;
      }
      if (auth.keyId !== pathId) {
        return refuse(403, "writer_mismatch");
      }
      store.keyLogs.set(pathId, parsed.data);
      return json(201, { id: submitted.id, state: submitted });
    }

    const stored = keyState(pathId);
    const auth = verifyWrite("PUT", url, headers, octets, stored);
    if (!auth.ok) {
      return auth.reply;
    }
    if (auth.keyId !== pathId) {
      return refuse(403, "writer_mismatch");
    }
    const writer = stored!;

    if (kind === undefined) {
      const parsed = participantProfileSchema.safeParse(body);
      if (!parsed.success) {
        return refuse(400, "invalid_profile");
      }
      if (parsed.data.id !== pathId) {
        return refuse(400, "participant_id_mismatch");
      }
      if (!signedAtThreshold(parsed.data, writer)) {
        return refuse(422, "profile_signature_invalid");
      }
      store.profiles.set(pathId, parsed.data);
      return json(201, parsed.data);
    }

    if (kind === "nodes") {
      const parsed = participantNodeSchema.safeParse(body);
      if (!parsed.success) {
        return refuse(400, "invalid_node");
      }
      const node = parsed.data;
      if (node.participantId !== pathId || node.id !== decodeURIComponent(segments[3] ?? "")) {
        return refuse(400, "node_id_mismatch");
      }
      if (!signedAtThreshold(node, writer)) {
        return refuse(422, "node_signature_invalid");
      }
      append(store.nodes, pathId, node);
      return json(201, node);
    }

    if (kind === "claims") {
      const parsed = claimSchema.safeParse(body);
      if (!parsed.success) {
        return refuse(400, "invalid_claim");
      }
      const claim = parsed.data;
      if (claim.issuedBy !== pathId || claim.id !== decodeURIComponent(segments[3] ?? "")) {
        return refuse(400, "claim_id_mismatch");
      }
      if (!signedAtThreshold(claim, writer)) {
        return refuse(422, "claim_signature_invalid");
      }
      // Listed under the SUBJECT, keyed by the issuer's write.
      append(store.claims, claim.subjectId, claim);
      return json(201, claim);
    }

    if (kind === "relationships") {
      const parsed = relationshipSchema.safeParse(body);
      if (!parsed.success) {
        return refuse(400, "invalid_relationship");
      }
      const edge = parsed.data;
      if (edge.issuedBy !== pathId || edge.id !== decodeURIComponent(segments[3] ?? "")) {
        return refuse(400, "relationship_id_mismatch");
      }
      if (!signedAtThreshold(edge, writer)) {
        return refuse(422, "relationship_signature_invalid");
      }
      append(store.relationships, edge.subjectId, edge);
      return json(201, edge);
    }

    if (kind === "revocations") {
      const parsed = revocationSchema.safeParse(body);
      if (!parsed.success) {
        return refuse(400, "invalid_revocation");
      }
      const revocation = parsed.data;
      if (
        revocation.issuerId !== pathId ||
        revocation.revokes !== decodeURIComponent(segments[3] ?? "")
      ) {
        return refuse(400, "revocation_id_mismatch");
      }
      if (!verifyThresholdRecord(revocation, writer.keys, writer.threshold)) {
        return refuse(422, "revocation_signature_invalid");
      }
      const rows = store.revocations.get(revocation.revokes) ?? [];
      store.revocations.set(revocation.revokes, [
        ...rows.filter((row) => row.issuerId !== revocation.issuerId),
        revocation
      ]);
      return json(201, revocation);
    }

    return refuse(404, "not_found");
  }

  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const octets = new Uint8Array(Buffer.concat(chunks));
      const address = server.address() as AddressInfo;
      const absolute = new URL(request.url ?? "/", `http://127.0.0.1:${address.port}`);
      const headers: Record<string, string | undefined> = {};
      for (const [name, value] of Object.entries(request.headers)) {
        headers[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
      }
      let reply: Reply;
      try {
        reply = handle(
          request.method ?? "GET",
          absolute.pathname,
          absolute.searchParams,
          absolute.href,
          headers,
          octets
        );
      } catch (error) {
        reply = json(500, { error: "internal", detail: String(error) });
      }
      response.writeHead(reply.status, { "content-type": "application/json" });
      response.end(JSON.stringify(reply.body));
    });
  });

  const address = await new Promise<AddressInfo>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address() as AddressInfo));
  });

  return {
    url: `http://127.0.0.1:${address.port}`,
    store,
    close: () => new Promise<void>((resolve) => server.close(() => resolve()))
  };
}
