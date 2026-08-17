/**
 * The public-directory client: everything a participant does *to* a discovery service.
 *
 * Two signatures, and neither substitutes for the other (spec 004):
 *
 *  - the RECORD's own signature, which travels with the bytes and is what a third party
 *    re-checks later — discovery verifies it at the issuer's threshold before storing;
 *  - the REQUEST signature, an RFC 9421 HTTP Message Signature over the method, target and the
 *    exact body octets, which authenticates the writer to the service.
 *
 * The request signature is a statement about ONE byte string, so every write here serializes
 * once and reuses that text for the signature and the body. Re-serializing for the send would
 * sign one string and deliver another, and the service would refuse it — correctly.
 *
 * THIS IS A PLAIN CLIENT, NOT A VERIFIER. Reads are schema-checked and strictly parsed, which
 * is enough to keep a malformed delivery out of your process; it is NOT enough to decide
 * authorization from. A record served here has not had its own signature checked against its
 * issuer's replayed key log, the host has not been treated as hostile, and nothing is bounded
 * against a host that answers slowly or enormously. For verification-grade reads — the ones an
 * authorization decision rests on — use `createDiscoveryView` from `@kinnet/verify`, which
 * replays key logs locally, re-checks every record it is handed, and bounds what a hostile host
 * can spend of your process.
 *
 * Publishing is this package; ISSUING the records is `@kinnet/trust` (`issueClaim`,
 * `issueRelationship`, `issueRevocation`, `issueGrant`). The two self-records — a participant's
 * profile and its node record — are built here, because their subject is their signer and there
 * is no third party to issue them.
 */
import {
  encodeKeyRef,
  replayKeyLogFor,
  signRecord,
  signRequest,
  type Identity,
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
  type ParticipantId,
  type ParticipantNode,
  type ParticipantProfile,
  type ParticipantType,
  type Relationship,
  type Revocation
} from "@kinnet/protocol";

/**
 * Issuer parameters one `/revocations/:digest` request may carry.
 *
 * The service REFUSES an over-long issuer list with a 400 rather than truncating it, because a
 * silently shortened revocation answer reads as "not revoked". So a larger ask is split here
 * and the answers unioned; the number mirrors the service's own bound and the two must move
 * together. A legitimate ask is chain-length bounded and single-digit, so this splitting is a
 * safety net rather than a hot path.
 */
export const MAX_ISSUERS_PER_REQUEST = 64;

export type DiscoveryClientOptions = {
  /** Base URL of the discovery service, e.g. "https://discovery.example.com". */
  discoveryUrl: string;
  /**
   * Injected for tests, custom runtimes, and in-process services. Defaults to the global
   * `fetch`, wrapped so it is never invoked with a foreign receiver (browsers reject that).
   */
  fetch?: typeof fetch;
};

/**
 * A discovery request that did not succeed.
 *
 * `code` is the service's own machine-readable `error` field when the response carried one
 * (`profile_signature_invalid`, `key_log_conflict`, `participant_id_mismatch`, …) — that is the
 * value worth branching on. `body` is whatever came back, parsed as JSON when it parsed and
 * kept as text when it did not, so a failure from a proxy in front of the service is still
 * legible rather than swallowed.
 */
export class DiscoveryClientError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly body: unknown;

  constructor(context: string, status: number, code: string | undefined, body: unknown) {
    super(`${context}: ${status}${code === undefined ? "" : ` ${code}`}`);
    this.name = "DiscoveryClientError";
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

/** One bounded page of a discovery listing, and the cursor to continue from. */
export type DiscoveryPage<T> = {
  records: T[];
  /** Pass as `after` to read the next page, or `null` when this page ends the collection. */
  nextCursor: string | null;
};

/** Paging controls every listing read accepts. The service clamps `limit` to its own ceiling. */
export type PageQuery = {
  limit?: number;
  after?: string;
};

/**
 * The targeted relationship lookup: the four values name ONE decision tuple, so the answer is
 * one record or none — not a list whose size is set by however many edges anyone published
 * about the subject. A partial tuple is refused by the service rather than served as a listing.
 */
export type RelationshipEdgeQuery = {
  issuer: ParticipantId;
  object: ParticipantId;
  predicate: string;
};

/**
 * A participant's public footprint as one bundle of signed records (the portability read).
 *
 * Its collections are BOUNDED, so `truncated` names any the service had to shorten. Anything
 * that depends on completeness must check it rather than assume it.
 */
export type ParticipantExportBundle = {
  format: string;
  id: string;
  profile: ParticipantProfile | null;
  keyLog: KeyEvent[] | null;
  nodes: ParticipantNode[];
  claims: Claim[];
  relationships: Relationship[];
  truncated: string[];
};

export type CreateProfileOptions = {
  type: ParticipantType;
  displayName: string;
  description?: string;
  /** Defaults to `[]`. Present in the signed bytes either way — see the note below. */
  capabilities?: string[];
  /** Defaults to `[]`. Present in the signed bytes either way — see the note below. */
  verifiedDomains?: string[];
};

export type CreateNodeOptions = {
  nodeId: string;
  endpoint: string;
  label?: string;
  servedBy?: ParticipantId;
  /**
   * Derived from the record schema rather than restated, so narrowing the enum is a compile
   * error here instead of a runtime schema rejection at sign time. Defaults to `["https"]`.
   */
  transports?: ParticipantNode["transports"];
};

/**
 * Signs a participant profile: how the participant presents itself in the public directory.
 *
 * A SELF-RECORD — its subject is its signer — which is why it is built here rather than issued
 * by a third party through `@kinnet/trust`.
 *
 * `capabilities` and `verifiedDomains` are written EXPLICITLY even when they are empty, and
 * that is not tidiness. `participantProfileSchema` defaults them on parse, so a record signed
 * without them and then parsed by the service gains two fields the signature never covered —
 * the signed bytes and the stored record would differ, and the record's own signature would no
 * longer verify against what a third party later reads back. A schema default is not in the
 * bytes; only what is signed is.
 */
export function createProfileRecord(
  identity: Identity,
  options: CreateProfileOptions
): ParticipantProfile {
  return signRecord(
    {
      id: identity.id,
      type: options.type,
      displayName: options.displayName,
      ...(options.description === undefined ? {} : { description: options.description }),
      capabilities: options.capabilities ?? [],
      verifiedDomains: options.verifiedDomains ?? [],
      updatedAt: new Date().toISOString()
    },
    identity.currentKeys[0]!.secretKey
  ) as ParticipantProfile;
}

/**
 * Signs a ParticipantNode record: where to reach this participant. `label` defaults to the node
 * id and `transports` to `["https"]`. The participant's own key stands in as the node key
 * (the custodial model), so the record is a self-record exactly like the profile.
 */
export function createNodeRecord(identity: Identity, options: CreateNodeOptions): ParticipantNode {
  return signRecord(
    {
      id: options.nodeId,
      participantId: identity.id,
      label: options.label ?? options.nodeId,
      endpoint: options.endpoint,
      ...(options.servedBy === undefined ? {} : { servedBy: options.servedBy }),
      publicKey: encodeKeyRef(identity.currentKeys[0]!.publicKey),
      transports: options.transports ?? ["https"],
      updatedAt: new Date().toISOString()
    },
    identity.currentKeys[0]!.secretKey
  ) as ParticipantNode;
}

export type DiscoveryClient = {
  /** The base URL, with any trailing slashes removed. */
  readonly discoveryUrl: string;

  /**
   * Publishes the participant's key log and returns the state the service resolved from it.
   *
   * FIRST, ALWAYS. Every other write is authenticated against the writer's stored key log, so a
   * profile published before its log is refused. The log is append-only: a re-publish that
   * extends the stored log is accepted, one that forks or shortens it is a `key_log_conflict`.
   */
  publishKeyLog(identity: Identity): Promise<KeyState>;
  publishProfile(identity: Identity, profile: ParticipantProfile): Promise<ParticipantProfile>;
  publishNode(identity: Identity, node: ParticipantNode): Promise<ParticipantNode>;
  /** Published under the ISSUER's path — discovery keys a claim by who asserted it. */
  publishClaim(issuer: Identity, claim: Claim): Promise<Claim>;
  /** Published under the ISSUER's path, not the subject's. */
  publishRelationship(issuer: Identity, relationship: Relationship): Promise<Relationship>;
  /** Published under the ISSUER's path, keyed by the digest it revokes. */
  publishRevocation(issuer: Identity, revocation: Revocation): Promise<Revocation>;

  /** The participant's key-event log, or null when the service holds none. */
  getKeyLog(id: ParticipantId): Promise<KeyEvent[] | null>;
  /**
   * The participant's current key state, REPLAYED LOCALLY from the log and bound to `id`. The
   * service's own `/keys` answer is not read: a key state is derived, and deriving it here is
   * the difference between reading a directory and trusting one.
   */
  getKeyState(id: ParticipantId): Promise<KeyState | null>;
  getProfile(id: ParticipantId): Promise<ParticipantProfile | null>;
  getNodes(id: ParticipantId, query?: PageQuery): Promise<DiscoveryPage<ParticipantNode>>;
  getClaims(id: ParticipantId, query?: PageQuery): Promise<DiscoveryPage<Claim>>;
  /**
   * Relationships published about `id` as their SUBJECT — a bounded listing, or, when the full
   * `{ issuer, object, predicate }` tuple is given, the single edge that tuple names (a page of
   * zero or one records, with no cursor).
   */
  getRelationships(
    id: ParticipantId,
    query?: PageQuery | RelationshipEdgeQuery
  ): Promise<DiscoveryPage<Relationship>>;
  /**
   * Revocations of `revokesDigest` published by any of `issuerIds`. Issuer-targeted by
   * construction: anyone may publish a revocation naming any digest, so the unfiltered set is
   * attacker-growable and a truncated answer would read as "not revoked".
   */
  getRevocations(revokesDigest: string, issuerIds: readonly string[]): Promise<Revocation[]>;
  getExport(id: ParticipantId): Promise<ParticipantExportBundle>;
};

/** The service's own `error` code, when the body carried one. */
function errorCode(body: unknown): string | undefined {
  if (typeof body === "object" && body !== null) {
    const value = (body as { error?: unknown }).error;
    if (typeof value === "string") {
      return value;
    }
  }
  return undefined;
}

function toQueryString(query: PageQuery | RelationshipEdgeQuery | undefined): string {
  if (query === undefined) {
    return "";
  }
  const params = new URLSearchParams();
  if ("issuer" in query) {
    params.set("issuer", query.issuer);
    params.set("object", query.object);
    params.set("predicate", query.predicate);
  } else {
    if (query.limit !== undefined) {
      params.set("limit", String(query.limit));
    }
    if (query.after !== undefined) {
      params.set("after", query.after);
    }
  }
  const text = params.toString();
  return text === "" ? "" : `?${text}`;
}

/** Splits an issuer set into requests the service will answer rather than refuse. */
function chunk(values: readonly string[], size: number): string[][] {
  const chunks: string[][] = [];
  for (let index = 0; index < values.length; index += size) {
    chunks.push(values.slice(index, index + size));
  }
  return chunks;
}

export function createDiscoveryClient(options: DiscoveryClientOptions): DiscoveryClient {
  const discoveryUrl = options.discoveryUrl.replace(/\/+$/, "");
  // Wrapped rather than stored directly: browsers reject `window.fetch` invoked with a foreign
  // receiver ("Illegal invocation"), and `this.fetch(...)` would be one.
  const fetchImpl: typeof fetch =
    options.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));

  /**
   * Reads a response body as bytes and parses it STRICTLY (spec 015 S6.1).
   *
   * Every record here is digest-addressed — a key event by its `prior`, a revocation by what it
   * names and by its own digest, a profile by 008's "any signed record" rule — so a delivery
   * whose JSON carries a duplicate object key is a delivery with two identities: it resolves
   * last-wins in one parser and first-wins in another, and two implementations handed one byte
   * string build two different records. `z.strictObject` cannot catch it, because a schema
   * inspects an already-resolved object; the bytes are parsed strictly instead, and
   * `decodeUtf8Strict` closes the same hazard one layer down in the byte-to-text step.
   *
   * A body that is not JSON at all comes back as text, so a proxy's HTML error page reaches the
   * caller as itself rather than as a parse crash.
   */
  async function readBody(response: Response): Promise<unknown> {
    const octets = new Uint8Array(await response.arrayBuffer());
    if (octets.byteLength === 0) {
      return undefined;
    }
    try {
      return parseJsonStrict(decodeUtf8Strict(octets));
    } catch {
      try {
        return decodeUtf8Strict(octets);
      } catch {
        return undefined;
      }
    }
  }

  async function request(
    method: string,
    path: string,
    init: RequestInit | undefined,
    context: string
  ): Promise<{ status: number; body: unknown }> {
    const response = await fetchImpl(`${discoveryUrl}${path}`, init);
    const body = await readBody(response);
    if (!response.ok) {
      throw new DiscoveryClientError(
        `${context} (${method} ${path})`,
        response.status,
        errorCode(body),
        body
      );
    }
    return { status: response.status, body };
  }

  /** Anonymous GET. Every discovery read is public; nothing here is signed. */
  async function get(path: string, context: string): Promise<unknown> {
    const { body } = await request("GET", path, undefined, context);
    return body;
  }

  /** As {@link get}, but a 404 is an answer ("no such record") rather than a failure. */
  async function getOrNull(path: string, context: string): Promise<unknown> {
    try {
      return await get(path, context);
    } catch (error) {
      if (error instanceof DiscoveryClientError && error.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * A signed write. The body is serialized ONCE and that exact text is both signed and sent —
   * the RFC 9421 signature covers the body's octets, so signing a different serialization than
   * the one transmitted produces a request the service refuses on its merits.
   */
  async function signedPut(
    signer: Identity,
    path: string,
    record: unknown,
    context: string
  ): Promise<unknown> {
    const url = `${discoveryUrl}${path}`;
    const body = JSON.stringify(record);
    const headers = signRequest({
      method: "PUT",
      url,
      body,
      keyId: signer.id,
      secretKey: signer.currentKeys[0]!.secretKey
    });
    const { body: responseBody } = await request(
      "PUT",
      path,
      {
        method: "PUT",
        headers: { "content-type": "application/json", ...headers },
        body
      },
      context
    );
    return responseBody;
  }

  function page<T>(body: unknown, key: string, parse: (value: unknown) => T): DiscoveryPage<T> {
    const rows = (body as Record<string, unknown> | undefined)?.[key];
    const cursor = (body as { nextCursor?: unknown } | undefined)?.nextCursor;
    return {
      records: (Array.isArray(rows) ? rows : []).map(parse),
      nextCursor: typeof cursor === "string" ? cursor : null
    };
  }

  /** Shared by `getKeyLog` and `getKeyState`, so the two cannot read the route differently. */
  async function readKeyLog(id: ParticipantId): Promise<KeyEvent[] | null> {
    const body = await getOrNull(
      `/participants/${id}/key-log`,
      `Could not read the key log for ${id}`
    );
    if (body === null) {
      return null;
    }
    return keyEventLogSchema.parse((body as { events?: unknown }).events);
  }

  return {
    discoveryUrl,

    async publishKeyLog(identity) {
      await signedPut(
        identity,
        `/participants/${identity.id}/key-log`,
        identity.log,
        "Discovery rejected the key log"
      );
      // The service answers `{ id, state }`, and the state is re-derived here from the log that
      // was just published rather than read off that answer: a publisher that takes back a key
      // state it did not compute has published into a directory it is also trusting. For an
      // honest service the two are the same object; for any other one, this is the one that is
      // true.
      return replayKeyLogFor(identity.id, keyEventLogSchema.parse(identity.log));
    },

    async publishProfile(identity, profile) {
      const body = await signedPut(
        identity,
        `/participants/${identity.id}`,
        profile,
        "Discovery rejected the profile"
      );
      return participantProfileSchema.parse(body);
    },

    async publishNode(identity, node) {
      const body = await signedPut(
        identity,
        `/participants/${identity.id}/nodes/${encodeURIComponent(node.id)}`,
        node,
        "Discovery rejected the node record"
      );
      return participantNodeSchema.parse(body);
    },

    async publishClaim(issuer, claim) {
      const body = await signedPut(
        issuer,
        `/participants/${issuer.id}/claims/${encodeURIComponent(claim.id)}`,
        claim,
        "Discovery rejected the claim"
      );
      return claimSchema.parse(body);
    },

    async publishRelationship(issuer, relationship) {
      const body = await signedPut(
        issuer,
        `/participants/${issuer.id}/relationships/${encodeURIComponent(relationship.id)}`,
        relationship,
        "Discovery rejected the relationship"
      );
      return relationshipSchema.parse(body);
    },

    async publishRevocation(issuer, revocation) {
      const body = await signedPut(
        issuer,
        `/participants/${issuer.id}/revocations/${encodeURIComponent(revocation.revokes)}`,
        revocation,
        "Discovery rejected the revocation"
      );
      return revocationSchema.parse(body);
    },

    getKeyLog: readKeyLog,

    async getKeyState(id) {
      const events = await readKeyLog(id);
      if (events === null) {
        return null;
      }
      // Bound to the id that was ASKED FOR. A replayed id is derived from the log's own
      // inception event, so a bare replay says which identity a log describes and never which
      // identity it was served for — binding the two is what stops a host serving A's valid log
      // at B's path.
      return replayKeyLogFor(id, events);
    },

    async getProfile(id) {
      const body = await getOrNull(`/participants/${id}`, `Could not read the profile for ${id}`);
      return body === null ? null : participantProfileSchema.parse(body);
    },

    async getNodes(id, query) {
      const body = await get(
        `/participants/${id}/nodes${toQueryString(query)}`,
        `Could not read the nodes for ${id}`
      );
      return page(body, "nodes", (value) => participantNodeSchema.parse(value));
    },

    async getClaims(id, query) {
      const body = await get(
        `/participants/${id}/claims${toQueryString(query)}`,
        `Could not read the claims for ${id}`
      );
      return page(body, "claims", (value) => claimSchema.parse(value));
    },

    async getRelationships(id, query) {
      const body = await get(
        `/participants/${id}/relationships${toQueryString(query)}`,
        `Could not read the relationships for ${id}`
      );
      if (query !== undefined && "issuer" in query) {
        const edge = (body as { relationship?: unknown }).relationship;
        return {
          records: edge === null || edge === undefined ? [] : [relationshipSchema.parse(edge)],
          nextCursor: null
        };
      }
      return page(body, "relationships", (value) => relationshipSchema.parse(value));
    },

    async getRevocations(revokesDigest, issuerIds) {
      if (issuerIds.length === 0) {
        return [];
      }
      const found: Revocation[] = [];
      for (const issuers of chunk(issuerIds, MAX_ISSUERS_PER_REQUEST)) {
        const params = new URLSearchParams();
        for (const issuer of issuers) {
          params.append("issuer", issuer);
        }
        const body = await get(
          `/revocations/${encodeURIComponent(revokesDigest)}?${params.toString()}`,
          `Could not read revocations of ${revokesDigest}`
        );
        const rows = (body as { revocations?: unknown }).revocations;
        for (const row of Array.isArray(rows) ? rows : []) {
          found.push(revocationSchema.parse(row));
        }
      }
      return found;
    },

    async getExport(id) {
      const body = (await get(
        `/participants/${id}/export`,
        `Could not read the export bundle for ${id}`
      )) as Record<string, unknown>;
      const keyLog = body["keyLog"];
      const profile = body["profile"];
      return {
        format: String(body["format"]),
        id: String(body["id"]),
        profile:
          profile === null || profile === undefined
            ? null
            : participantProfileSchema.parse(profile),
        keyLog: keyLog === null || keyLog === undefined ? null : keyEventLogSchema.parse(keyLog),
        nodes: (Array.isArray(body["nodes"]) ? body["nodes"] : []).map((value) =>
          participantNodeSchema.parse(value)
        ),
        claims: (Array.isArray(body["claims"]) ? body["claims"] : []).map((value) =>
          claimSchema.parse(value)
        ),
        relationships: (Array.isArray(body["relationships"]) ? body["relationships"] : []).map(
          (value) => relationshipSchema.parse(value)
        ),
        truncated: (Array.isArray(body["truncated"]) ? body["truncated"] : []).map((value) =>
          String(value)
        )
      };
    }
  };
}
