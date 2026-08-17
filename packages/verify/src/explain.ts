/**
 * Explain a Kinnet participant from bytes, trusting nothing.
 *
 * {@link explainParticipant} resolves a participant against a discovery service and returns one
 * line per check, each carrying its own verdict. Discovery is a convenience here, never an
 * authority: it is asked for bytes and every answer is re-decided locally. The key log is
 * replayed from its inception event and must derive the id that was asked for; every record's
 * signature is checked against the key state its ISSUER's own log resolves to. A lying host
 * fails a line; it cannot pass one.
 *
 * The function prints nothing, reads no files and reads no argv — a caller decides how to render
 * the lines and what to do about `ok`. `kinnet-verify` (this package's bin) is one such caller.
 */
import { replayKeyLogFor, verifyThresholdRecord, type KeyState } from "@kinnet/crypto";
import {
  claimSchema,
  keyEventLogSchema,
  parseJsonStrict,
  participantProfileSchema,
  relationshipSchema,
  type Grant,
  type ParticipantProfile
} from "@kinnet/protocol";
import { verifyGrantChain } from "@kinnet/trust";

import { createDiscoveryView } from "./discovery-view.js";

/** The public discovery service {@link explainParticipant} reads from when none is named. */
export const DEFAULT_EXPLAIN_DISCOVERY_URL = "https://discovery.kinnet.humanmeetsai.com";

export interface ExplainLine {
  /** true = check passed, false = check failed, null = informational (no verdict). */
  ok: boolean | null;
  text: string;
}

export interface ExplainResult {
  lines: ExplainLine[];
  /** true iff no line has ok === false. */
  ok: boolean;
}

export interface ExplainOptions {
  /** Defaults to {@link DEFAULT_EXPLAIN_DISCOVERY_URL}. Trailing slashes are stripped. */
  discoveryUrl?: string;
  /**
   * An already-parsed grant chain to verify too (spec 009). Grants are BEARER records —
   * discovery stores none — so reading and parsing the chain the holder gave you is the
   * caller's job, not this function's.
   */
  grants?: Grant[];
  /** Flip one byte of the fetched displayName before checking the profile signature. */
  tamper?: boolean;
  /** Injected fetch, for tests and for callers with their own transport. Defaults to the global. */
  fetch?: typeof fetch;
}

/**
 * Every check this tool makes about `id`, as lines with verdicts.
 *
 * Order is the order a reader needs it in: the identity first, because everything below is
 * decided against the key state it produces; then the participant's own profile; then what
 * OTHERS have signed about it; then a presented grant chain, when one is supplied.
 */
export async function explainParticipant(
  participantId: string,
  options: ExplainOptions = {}
): Promise<ExplainResult> {
  const discovery = (options.discoveryUrl ?? DEFAULT_EXPLAIN_DISCOVERY_URL).replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? fetch;

  const lines: ExplainLine[] = [];
  let failures = 0;
  const ok = (line: string): void => {
    lines.push({ ok: true, text: line });
  };
  const bad = (line: string, reason: string): void => {
    failures += 1;
    lines.push({ ok: false, text: `${line} — ${reason}` });
  };
  const note = (line: string): void => {
    lines.push({ ok: null, text: line });
  };
  const short = (id: string): string => (id.length > 14 ? `${id.slice(0, 14)}…` : id);
  const result = (): ExplainResult => ({ lines, ok: failures === 0 });

  /** A JSON read from discovery. Strict parsing: a duplicate key is one delivery, two records. */
  async function read(path: string): Promise<{ status: number; body: unknown }> {
    const response = await fetchImpl(`${discovery}${path}`);
    const text = await response.text();
    return { status: response.status, body: text === "" ? undefined : parseJsonStrict(text) };
  }

  /** Records here carry ONE signature; the key state still decides how many are needed. */
  function signedByIssuer(record: { signature: string }, issuer: KeyState): boolean {
    const { signature, ...unsigned } = record;
    return verifyThresholdRecord(
      { ...unsigned, signature: [signature] },
      issuer.keys,
      issuer.threshold
    );
  }

  /** Replayed key state and the log it came from, memoized so each issuer is resolved once. */
  const identities = new Map<string, { state: KeyState; events: unknown[] } | null>();
  async function identityOf(id: string): Promise<{ state: KeyState; events: unknown[] } | null> {
    if (!identities.has(id)) {
      const response = await read(`/participants/${id}/key-log`);
      if (response.status !== 200) {
        identities.set(id, null);
      } else {
        const events = keyEventLogSchema.parse((response.body as { events: unknown }).events);
        // `replayKeyLogFor`, not a bare replay: a log's replayed id is derived from its own
        // inception event, so it says which identity the log describes and never which identity
        // it was served for. Binding the two is what stops a host serving A's valid log at B's path.
        identities.set(id, { state: replayKeyLogFor(id, events), events });
      }
    }
    return identities.get(id) ?? null;
  }

  const keyStateOf = async (id: string): Promise<KeyState | null> =>
    (await identityOf(id))?.state ?? null;

  const profiles = new Map<string, ParticipantProfile | null>();
  async function profileOf(id: string): Promise<ParticipantProfile | null> {
    if (!profiles.has(id)) {
      const response = await read(`/participants/${id}`);
      profiles.set(
        id,
        response.status === 200 ? participantProfileSchema.parse(response.body) : null
      );
    }
    return profiles.get(id) ?? null;
  }

  /** How a participant is named in a line: its self-declared display name, or its id. */
  async function label(id: string): Promise<string> {
    const profile = await profileOf(id);
    return profile === null ? short(id) : `"${profile.displayName}"`;
  }

  /**
   * One statement somebody else signed about this participant — a relationship or a claim. The
   * ISSUER named in the record decides which keys must have signed it, so its log is resolved and
   * replayed here rather than the subject's.
   */
  async function checkStatement(
    record: { issuedBy: string; expiresAt?: string; signature: string },
    line: string
  ): Promise<void> {
    const issuer = await keyStateOf(record.issuedBy).catch(() => null);
    if (issuer === null) bad(line, "the issuer's key log does not resolve");
    else if (!signedByIssuer(record, issuer)) bad(line, "the issuer's signature does not verify");
    else if (record.expiresAt !== undefined && Date.parse(record.expiresAt) <= Date.now()) {
      bad(line, `expired at ${record.expiresAt}`);
    } else ok(`${line} (signature valid, not expired)`);
  }

  // 1. The identity itself. Everything below is checked against the key state this produces.
  const identity = await identityOf(participantId).catch((error: Error) => {
    bad(`${short(participantId)} derives from its inception keys`, error.message);
    return null;
  });
  if (identity === null) {
    if (failures === 0) bad(`${short(participantId)} has a key log`, "discovery serves none");
    return result();
  }
  const state = identity.state;
  ok(
    `${short(participantId)} derives from its inception keys (${identity.events.length} event(s), threshold ${state.threshold})`
  );

  // 2. The profile: a self-record, so it is checked against the participant's own keys.
  const served = await profileOf(participantId);
  if (served === null) {
    note("no profile published (the identity is still fully verifiable without one)");
  } else {
    if (options.tamper) note("--tamper: one byte of the fetched displayName was flipped");
    const first = served.displayName.slice(0, 1);
    const profile = options.tamper
      ? { ...served, displayName: `${first === "X" ? "Y" : "X"}${served.displayName.slice(1)}` }
      : served;
    const line = `profile signed by the current key: "${profile.displayName}" (${profile.type})`;
    if (profile.id !== participantId) bad(line, `the profile names ${profile.id}`);
    else if (signedByIssuer(profile, state)) ok(line);
    else bad(line, "the signature does not verify against this key log");
  }

  // 3. What OTHERS have signed about this participant. Both listings are keyed by SUBJECT: they
  //    answer "what has been said about this participant", never "what does it say about itself".
  for (const kind of ["relationships", "claims"] as const) {
    const response = await read(`/participants/${participantId}/${kind}`);
    const rows = ((response.body ?? {}) as Record<string, unknown[]>)[kind] ?? [];
    for (const raw of rows) {
      if (kind === "relationships") {
        const edge = relationshipSchema.parse(raw);
        await checkStatement(
          edge,
          `${await label(edge.subjectId)} ${edge.predicate} ${await label(edge.objectId)}, issued by ${await label(edge.issuedBy)} ${short(edge.issuedBy)}`
        );
      } else {
        const claim = claimSchema.parse(raw);
        await checkStatement(
          claim,
          `claim ${claim.claimType} = ${JSON.stringify(claim.value)}, issued by ${await label(claim.issuedBy)} ${short(claim.issuedBy)}`
        );
      }
    }
  }

  // 4. A presented grant chain (spec 009). Grants are BEARER records — discovery stores none —
  //    so the chain arrives as a file the holder gave you, and revocation is what discovery adds.
  const chain = options.grants;
  if (chain !== undefined) {
    const leaf = chain[0]!;
    const root = chain[chain.length - 1]!;
    const line = `grant chain (${chain.length} link(s)): ${short(root.issuerId)} → ${short(leaf.audienceId)}`;
    // Zero TTL so a revocation published a moment ago is visible to this run rather than to the
    // one after the cache expires.
    const verdict = await verifyGrantChain(
      chain,
      createDiscoveryView({
        discoveryUrl: discovery,
        cacheTtlSeconds: 0,
        ...(options.fetch ? { fetch: options.fetch } : {})
      })
    );
    if (verdict.valid) ok(`${line}, abilities ${verdict.abilities.join(", ")} — valid`);
    else bad(line, verdict.reason);
  }

  return result();
}
