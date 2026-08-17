/**
 * Inbound-request verification for services receiving agent traffic: an HTTP Message
 * Signature (RFC 9421, the spec 004 profile) proves the caller controls a participant
 * identity — or, per spec 011, a session key exercising a presented grant chain — and
 * published represents edges are verified through the trust resolver (specs 008/009)
 * to answer "who does this agent act for".
 */
import {
  ContentDigestMismatchError,
  createNonceGuard,
  decodeGrantsHeader,
  decodeKeyRef,
  DEFAULT_MAX_SKEW_SECONDS,
  replayTtlSeconds,
  safeVerificationCount,
  SignatureStaleError,
  VerificationBudgetExceeded,
  verifyRequest,
  type KeyState,
  type MonotonicClock
} from "@kinnet/crypto";
import {
  keyRefSchema,
  participantIdSchema,
  type Grant,
  type KeyRef,
  type ParticipantId,
  type Principal
} from "@kinnet/protocol";
import {
  abilityCovers,
  beginVerificationOperation,
  createVerificationContext,
  REPRESENTS_PREDICATE,
  verifyGrantChain,
  verifyRepresentsChain,
  verificationWorkOptions,
  type VerificationContext,
  type VerifyOptions
} from "@kinnet/trust";

import {
  createDiscoveryView,
  type DiscoveryView,
  type DiscoveryViewOptions
} from "./discovery-view.js";
import {
  VerifyCapacityError,
  VerifyError,
  type KnownVerifyCapacityReason,
  type VerifyReason
} from "./errors.js";

// Re-exported from their own module so `discovery-view.ts` can throw a capacity error without
// importing this file back. See `errors.ts` for why that cycle had to go. Consumers importing
// either class from here are unaffected.
export { VerifyCapacityError, VerifyError } from "./errors.js";

/**
 * Construction helpers that PIN the reason, mirroring `invalid()` in `@kinnet/trust`'s resolver
 * and in `record-unit.ts`.
 *
 * `VerifyError` itself is generic in its reason so a surface layered above this package can
 * carry a vocabulary of its own (see `errors.ts`), which means the class alone would accept a
 * typo written here. These two close that inside the package: every reason this module raises
 * has to be a member of {@link VerifyReason}, and every 503 has to be a member of the capacity
 * subset, or it does not compile.
 */
function deny<R extends VerifyReason>(reason: R, message: string): VerifyError<R> {
  return new VerifyError(reason, message);
}

function refuse<R extends KnownVerifyCapacityReason>(
  reason: R,
  message: string
): VerifyCapacityError<R> {
  return new VerifyCapacityError(reason, message);
}

/**
 * A resolver verdict as a thrown failure, keeping a COST refusal out of the 401 bucket.
 *
 * The resolver reports running out of allowance with a `..._too_expensive` reason precisely so
 * it stays separable from "invalid", and flattening it back into a `VerifyError` here would
 * undo that at the last step: the caller would read 401, conclude its credentials are wrong,
 * and re-present the same chain forever. It is not an authentication failure — this verifier
 * declined to spend enough to judge something that may be entirely valid.
 *
 * Constructs the capacity class DIRECTLY rather than through {@link refuse}: the branch is
 * decided at run time from a suffix test, so nothing static can narrow `reason` to the capacity
 * subset here. The suffix test is the classification — see `isVerifyCapacityReason`, which
 * applies the same rule to the same reasons from the outside.
 */
function asVerifyFailure(reason: VerifyReason, message: string): VerifyError<VerifyReason> {
  return reason.endsWith("_too_expensive")
    ? new VerifyCapacityError<VerifyReason>(reason, message)
    : new VerifyError<VerifyReason>(reason, message);
}

export type InboundRequest = {
  method: string;
  /** The full target URI as the client signed it. */
  url: string;
  /**
   * Header lookup by lower-cased name. Delegated requests (spec 011) carry the raw
   * grant chain in `pn-grants`, passed here exactly like `signature-input`.
   */
  headers: Record<string, string | undefined>;
  /**
   * The body as DELIVERED. Prefer raw octets: the RFC 9530 digest the signature covers is
   * computed over the bytes on the wire, and a body decoded to text before it reaches here
   * can no longer establish that (`TextDecoder` folds every malformed sequence to U+FFFD,
   * so distinct byte strings arrive indistinguishable — see `contentDigest`). A `string`
   * remains accepted for callers that hold the body as text by construction and is digested
   * as its UTF-8 encoding; it is a convenience, not the safe default.
   */
  body?: string | Uint8Array;
};

export type VerifiedAgent = {
  /**
   * The subject the request counts as: the grant chain's subject when delegated
   * (spec 011 — "the request counts as the subject acting"), otherwise the keyid
   * participant itself.
   */
  agentId: ParticipantId;
  /** The signing principal (the request keyid): a participant id or a session KeyRef. */
  actor: Principal;
  /** True when the request presented a verified grant chain (spec 011). */
  delegated: boolean;
  /** The chain's leaf abilities when delegated; null for root-authority requests. */
  abilities: string[] | null;
  /**
   * The KeyRef that satisfied the RFC 9421 request signature (spec 013 §4). Passed
   * through from `@kinnet/crypto`'s `verifyRequest` so a continuing-authority
   * surface can later re-check that this key is still in the signing participant's
   * current key state — the owner-mode arm of the `reauthorizeStream` contract.
   */
  satisfiedKey: KeyRef;
  /**
   * The presented grant chain in delegated mode; null otherwise. Retained on the
   * result so `reauthorizeStream` can re-run the 009/011 chain check at `now`
   * without re-parsing headers — a stream captures the record once at open, and
   * re-check reads it verbatim.
   */
  chain: Grant[] | null;
  /**
   * The participant actor's current replayed state, returned so a same-request content check
   * can reuse the result rather than replaying the identical log. Bare-KeyRef actors have no
   * key log and therefore return `null`.
   */
  actorKeyState: KeyState | null;
};

/**
 * What {@link Verifier.verifyFetch} returns: the verified agent, plus the exact octets the
 * request signature's `content-digest` covered.
 *
 * The octets are handed back rather than left for the caller to re-read, and that is the whole
 * point of the field. `verifyFetch` reads the body as BYTES precisely so the digest is computed
 * over what was delivered; a caller who then reaches for `request.text()` or `request.json()`
 * decodes those bytes with U+FFFD replacement and gets a body nobody sent — reintroducing, in
 * application code, exactly the split this adapter was changed to close. There is also no second
 * read to get wrong: the request stream may already be consumed, and a clone is a copy whose
 * relationship to the verified bytes the caller has to argue for.
 *
 * Parse them with a fatal decoder — `decodeUtf8Strict` from `@kinnet/protocol`, then
 * `parseJsonStrict` — after verification returns, never before.
 *
 * Additive: every existing field of {@link VerifiedAgent} is unchanged, so code that ignores
 * `octets` keeps working.
 */
export type VerifiedFetch = VerifiedAgent & {
  /**
   * The request body as delivered — the same bytes the signature covered. Empty for GET and
   * HEAD, which carry no body and digest as the SHA-256 of zero octets.
   */
  octets: Uint8Array;
};

export type VerifierOptions = Omit<DiscoveryViewOptions, "discoveryUrl"> & {
  /**
   * Base URL of the discovery service. Required UNLESS {@link VerifierOptions.view} is supplied,
   * and forbidden when it is — the two are the same decision made two ways, and accepting both
   * would silently ignore one of them.
   *
   * Optional in the TYPE rather than modelled as a discriminated union so that adding `view`
   * breaks nothing that already constructs these options programmatically; the exclusivity is
   * enforced at construction instead, where it fails loudly with a message naming both fields.
   */
  discoveryUrl?: string;
  /**
   * A pre-built view to verify against, INSTEAD of one this verifier builds from `discoveryUrl`.
   *
   * Without it `createVerifier` could only ever verify online: it constructed its own
   * discovery-backed view internally, so a caller holding the key logs already — a test, an
   * air-gapped relying party, a service verifying from committed bytes — had no way in. The
   * trust resolver has always been offline-capable (`verifyGrantChain` takes any `TrustView`);
   * this closes the same gap one layer up. See `createStaticTrustView` for a view built from
   * records in hand.
   *
   * Anything satisfying {@link DiscoveryView} works, so a caller may also pass a
   * `createDiscoveryView` it configured itself, or a wrapper that instruments or caches one.
   */
  view?: DiscoveryView;
  maxSkewSeconds?: number;
  /**
   * Hard ceiling on simultaneously tracked replay nonces. The map is attacker-influenced
   * (any party holding a valid key can mint unlimited distinct nonces), so it is bounded
   * rather than left to grow with request volume. A nonce is a replay control, so the
   * ceiling never evicts a live nonce: expired entries are pruned and, if the map is still
   * full, the new request is refused with `nonce_capacity` — a bounded availability cost
   * instead of unbounded memory growth. See `createNonceGuard` in `@kinnet/crypto` for the
   * sizing rationale; the default is far above any legitimate steady-state cardinality
   * (arrival rate x nonce TTL).
   *
   * Only a request that FULLY AUTHORIZES spends an entry. The guard is asked about the nonce
   * early — so a replay is refused before any grant-chain work — but written to only after
   * every authorization stage has passed, so traffic this verifier rejects cannot fill the map
   * and turn the ceiling into a denial of service for everyone else.
   */
  maxTrackedNonces?: number;
  /**
   * Monotonic source for replay-nonce RETENTION. Retention is a duration since the nonce was
   * seen, so it never rides the wall clock. Injectable so a test can drive reclamation
   * without sleeping; defaults to the platform monotonic clock.
   */
  monotonicNowMs?: MonotonicClock;
  /** Reject requests without a verified represents chain from this organization. */
  requireRepresents?: ParticipantId;
  /**
   * This surface's own participant id, checked against the chain's `aud` caveat
   * (spec 011). Services accepting delegated traffic MUST set it: without it any
   * aud-restricted chain is rejected (caveats fail closed).
   *
   * It gates AUD-RESTRICTED chains only. A chain that carries no `aud` caveat on any
   * link is unrestricted by spec 011 and is admitted at every verifier regardless of
   * this id — `aud` is mandatory only for key-audience links, so a chain delegated
   * between participants may legally omit it. Set `requireAud` to close that door.
   */
  verifierId?: ParticipantId;
  /**
   * Demand that presented chains be audience-bound: a chain no link of which carries an
   * `aud` caveat is rejected with `grant_audience_required`. This — not `verifierId`
   * alone — is what makes audience binding mandatory at this surface. Defaults to false
   * so existing deployments are unaffected.
   */
  requireAud?: boolean;
  /**
   * Abilities this surface requires of delegated requests. Every listed ability must
   * be covered by the presented chain's granted abilities (path-prefix cover, spec
   * 009). Non-delegated requests pass trivially — the participant acts with root
   * authority.
   */
  requireAbilities?: string[];
  /**
   * Caveat evaluation hook, passed through to the trust resolver. Caveats fail
   * closed (spec 009): without an evaluator, any grant carrying caveats other than
   * `aud` is rejected.
   */
  evaluateCaveats?: (grant: Grant) => boolean;
};

type NodeStyleRequest = {
  method?: string;
  url?: string;
  originalUrl?: string;
  protocol?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  get?(name: string): string | undefined;
  verifiedAgent?: VerifiedAgent;
};

type NodeStyleResponse = {
  status(code: number): { json(body: unknown): unknown };
};

export type Verifier = {
  /** The discovery-backed view, exposed for advanced checks (grant chains, claims). */
  view: DiscoveryView;
  /** Core verification over a plain request shape; throws VerifyError on rejection. */
  beginRequest(options?: { maxSignatureVerifications?: number }): VerificationContext;
  verify(request: InboundRequest, context?: VerificationContext): Promise<VerifiedAgent>;
  /**
   * Fetch-API adapter for edge runtimes (Cloudflare Workers, Deno, Bun). Returns the
   * {@link VerifiedAgent} **and the verified octets** — see {@link VerifiedFetch}.
   */
  verifyFetch(request: Request, context?: VerificationContext): Promise<VerifiedFetch>;
  /** Express-style middleware; attaches the result as req.verifiedAgent or ends 401. */
  middleware(): (req: NodeStyleRequest, res: NodeStyleResponse, next: () => void) => Promise<void>;
};

function singleHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/**
 * The body of a request that carries none. Shared so "no body" is one value rather than a
 * choice between `""` and empty bytes at each adapter — they digest identically (the SHA-256
 * of zero octets), and the spec 004 profile covers `content-digest` unconditionally, GETs
 * included, so every adapter must produce the same digest for an absent body.
 */
const EMPTY_BODY = new Uint8Array(0);

type ActorPrincipal = { kind: "participant"; id: ParticipantId } | { kind: "key"; id: KeyRef };

/**
 * Classifies a request keyid against exactly the two principal shapes (spec 011):
 * a participant id, or a bare KeyRef that also decodes as a supported key. Anything
 * matching neither is rejected — never cast through.
 */
function classifyKeyId(keyId: string): ActorPrincipal {
  if (participantIdSchema.safeParse(keyId).success) {
    return { kind: "participant", id: keyId };
  }
  if (keyRefSchema.safeParse(keyId).success) {
    try {
      decodeKeyRef(keyId);
      return { kind: "key", id: keyId };
    } catch {
      // Shape-valid multibase that is not a supported key falls through to rejection.
    }
  }
  throw deny(
    "keyid_invalid",
    "The signature keyid is neither a participant id nor a decodable KeyRef"
  );
}

/**
 * Thrown when the options given to {@link createVerifier} cannot be honoured as written.
 *
 * A configuration mistake, not a request rejection, so it is deliberately NOT a `VerifyError`:
 * `VerifyError` means "this request is refused" and carries an HTTP status a surface answers
 * with, and a misconfigured verifier has no request to refuse. It also fails at CONSTRUCTION
 * rather than on the first request, so the mistake surfaces at deploy time instead of as a
 * uniform authentication outage.
 */
export class VerifierConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerifierConfigurationError";
  }
}

export function createVerifier(options: VerifierOptions): Verifier {
  // EXACTLY ONE source of truth for the view. Both is ambiguous — one of the two would be
  // silently discarded, and the one discarded would be whichever this function happened to
  // check second; neither leaves nothing to verify against. Refusing here means the failure
  // names the actual mistake, rather than arriving later as every request failing to resolve a
  // key log against `undefined`.
  if (options.view !== undefined && options.discoveryUrl !== undefined) {
    throw new VerifierConfigurationError(
      "createVerifier accepts either `view` or `discoveryUrl`, not both: pass `view` to verify " +
        "against a view you built, or `discoveryUrl` to have one built for you"
    );
  }
  let view: DiscoveryView;
  if (options.view !== undefined) {
    // Used AS GIVEN — no discovery view is built alongside it, so a verifier constructed this
    // way makes no outbound request at all. That is the property the offline case needs, and it
    // holds only because nothing below falls back to a default view.
    view = options.view;
  } else if (options.discoveryUrl !== undefined) {
    view = createDiscoveryView({ ...options, discoveryUrl: options.discoveryUrl });
  } else {
    throw new VerifierConfigurationError(
      "createVerifier needs a view to verify against: pass `discoveryUrl`, or `view` for an " +
        "offline or pre-built one"
    );
  }
  const now = options.now ?? (() => new Date());
  // `2 * skew + 1`, not `2 * skew`: freshness is inclusive at both ends, so a signature
  // minted at `created = t + skew` is still fresh at `t + 2 * skew`. See `replayTtlSeconds`.
  const nonceTtlSeconds = replayTtlSeconds(options.maxSkewSeconds ?? DEFAULT_MAX_SKEW_SECONDS);
  const nonceGuard = createNonceGuard({
    ttlSeconds: nonceTtlSeconds,
    ...(options.maxTrackedNonces !== undefined ? { maxEntries: options.maxTrackedNonces } : {}),
    ...(options.monotonicNowMs !== undefined ? { monotonicNowMs: options.monotonicNowMs } : {})
  });

  function beginRequest(
    contextOptions: {
      maxSignatureVerifications?: number;
    } = {}
  ): VerificationContext {
    const fallback = view.maxSignatureVerifications ?? 0;
    return createVerificationContext({
      remaining: safeVerificationCount(contextOptions.maxSignatureVerifications, fallback)
    });
  }

  async function verify(
    request: InboundRequest,
    context?: VerificationContext
  ): Promise<VerifiedAgent> {
    // One LOCAL operation allowance plus, when supplied, one OUTER request allowance. Every
    // curve check below charges both; nested trust calls receive the operation so they cannot
    // refresh the local 13A meter merely because the request's outer ceiling is larger.
    const operation = beginVerificationOperation(view, context ? { context } : {});
    const shared: VerifyOptions = { operation, ...(context ? { context } : {}) };
    const inputHeader = request.headers["signature-input"];
    const keyIdMatch = inputHeader ? /keyid="([^"]+)"/.exec(inputHeader) : null;
    if (!keyIdMatch) {
      throw deny("missing_signature", "No RFC 9421 Signature-Input header with a keyid was found");
    }
    const actor = classifyKeyId(keyIdMatch[1]!);
    const grantsHeader = request.headers["pn-grants"];

    // The keys the request signature must verify against: a bare KeyRef keyid is the
    // key itself (spec 011 — it lives in no log), a participant keyid resolves
    // through its key log (spec 003).
    let keys: KeyRef[];
    let threshold: string;
    let actorKeyState: KeyState | null = null;
    if (actor.kind === "key") {
      if (grantsHeader === undefined) {
        throw deny(
          "delegation_required",
          "A KeyRef keyid must present a PN-Grants chain that authorizes it"
        );
      }
      keys = [actor.id];
      threshold = "1";
    } else {
      let state;
      try {
        state = await view.getKeyState(actor.id, undefined, operation);
      } catch (error) {
        if (error instanceof VerificationBudgetExceeded) {
          // Not an authentication failure: this verifier declined to spend enough to judge a
          // log that may be entirely valid. Reporting it as `agent_key_log_unresolved` would
          // be a 401 telling the caller to fix something that is not broken, on the very
          // first stage of the request path and the one likeliest to exhaust.
          throw refuse(
            "agent_key_log_too_expensive",
            `Resolving the key log for ${actor.id} would exceed this verifier's allowance`
          );
        }
        throw error;
      }
      if (!state || state.id !== actor.id) {
        throw deny("agent_key_log_unresolved", `No replay-valid key log resolves for ${actor.id}`);
      }
      keys = state.keys;
      threshold = state.threshold;
      actorKeyState = state;
    }

    const nowSeconds = Math.floor(now().getTime() / 1000);
    // Classify an unusable clock BEFORE signature verification. `verifyRequest` also
    // validates it, but it throws a plain Error that this function maps to
    // `signature_invalid`/401 — blaming the caller for our own broken clock, and making the
    // `clock_invalid` reason unreachable in practice.
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) {
      throw refuse(
        "clock_invalid",
        "This surface's clock is not a usable time source; retry shortly"
      );
    }
    let nonce: string;
    let satisfiedKey: KeyRef;
    try {
      const verified = verifyRequest({
        method: request.method,
        url: request.url,
        body: request.body ?? EMPTY_BODY,
        headers: request.headers,
        keys,
        threshold,
        now: nowSeconds,
        maxSkewSeconds: options.maxSkewSeconds,
        // Whenever the header is present the signature MUST cover it (spec 011);
        // coverage and header/coverage agreement are enforced in the crypto layer.
        grantsHeader,
        ...verificationWorkOptions(operation)
      });
      nonce = verified.nonce;
      satisfiedKey = verified.satisfiedKey;
    } catch (error) {
      if (error instanceof VerificationBudgetExceeded) {
        throw refuse(
          "request_signature_too_expensive",
          "Checking the RFC 9421 request signature would exceed this verifier's allowance"
        );
      }
      // Two of `verifyRequest`'s rejections are NOT "your signature is wrong", and reporting
      // them as if they were sends the caller to fix something that is not broken. Both are
      // narrowed by CLASS rather than by message text, so the messages stay diagnostics rather
      // than becoming a wire contract.
      if (error instanceof SignatureStaleError) {
        // The receipt expired (or was minted ahead of this clock). The signature itself is
        // typically valid; the remedy is the caller's clock or a fresh retry, never its keys.
        // Still 401 — a stale request is not admitted — but a distinguishable one, so a client
        // can resign instead of re-authenticating and an operator can see clock drift as clock
        // drift. Governed by `maxSkewSeconds`.
        throw deny("signature_stale", error.message);
      }
      if (error instanceof ContentDigestMismatchError) {
        // The body presented here is not the body that was signed. Far more often a
        // body-rewriting intermediary (a re-encoding proxy, a framework that reserialized a
        // parsed body before this verifier saw it) than an attacker — and under
        // `signature_invalid` that diagnosis was unavailable to everyone downstream.
        throw deny("content_digest_mismatch", error.message);
      }
      throw deny(
        "signature_invalid",
        error instanceof Error ? error.message : "signature verification failed"
      );
    }
    // Replay control (spec 004), phase 1 of 2: ASK, do not record.
    //
    // The commit used to happen right here, and that let an unauthorized caller spend the
    // one resource this verifier fails closed on. The nonce map is bounded and never evicts a
    // live entry, so at the ceiling every signed request on the process is refused
    // `nonce_capacity` for up to a full retention window — and a self-minted keypair is enough
    // to mint valid signatures, so filling it required no authority whatsoever. A request that
    // the grant chain goes on to reject now leaves no trace in the map at all.
    //
    // The QUESTION stays here rather than moving down with the commit, deliberately: it is
    // what keeps a captured-and-replayed request cheap to refuse. Deferring the whole check
    // would make every replay pay for a full grant-chain verification first, trading one
    // amplification for another.
    const peeked = nonceGuard.peek(nonce, nowSeconds);
    if (peeked === "replayed") {
      throw deny("nonce_replayed", "The request nonce has already been used");
    }
    if (peeked === "clock_invalid") {
      throw refuse(
        "clock_invalid",
        "This surface's clock is unusable for replay tracking; retry shortly"
      );
    }

    // Spec 011: a presented chain must verify per 009/011 and its leaf audience must
    // be the signing principal; the request then counts as the subject acting. The
    // resolver's rejection reason is the VerifyError reason verbatim — including
    // `grant_audience_not_admitted` and, under `requireAud`, `grant_audience_required`.
    //
    // This is a request surface, so the chain is verified at request purpose: spec 014's
    // "`e2ee` abilities are ... never request-valid" rejects any chain carrying an `e2ee`
    // ability in any link, surfacing as `grant_e2ee_not_request_valid`. The purpose is
    // stated rather than defaulted — an MLS credential must never be exercised here.
    let subjectId: ParticipantId;
    let delegated = false;
    let abilities: string[] | null = null;
    let capturedChain: Grant[] | null = null;
    if (grantsHeader !== undefined) {
      let chain: Grant[];
      try {
        chain = decodeGrantsHeader(grantsHeader);
      } catch (error) {
        throw deny(
          "grants_malformed",
          error instanceof Error ? error.message : "the PN-Grants header failed to decode"
        );
      }
      const verdict = await verifyGrantChain(chain, view, {
        now: now(),
        purpose: "request",
        verifierId: options.verifierId,
        requireAud: options.requireAud,
        evaluateCaveats: options.evaluateCaveats,
        ...shared
      });
      if (!verdict.valid) {
        throw asVerifyFailure(verdict.reason, "The presented grant chain was rejected");
      }
      if (verdict.audienceId !== actor.id) {
        throw deny(
          "grants_leaf_audience_mismatch",
          "The chain's leaf audience is not the signing keyid principal"
        );
      }
      subjectId = verdict.subjectId;
      abilities = verdict.abilities;
      delegated = true;
      capturedChain = chain;
    } else {
      subjectId = actor.id;
    }

    if (options.requireAbilities && delegated && abilities) {
      const granted = abilities;
      const missing = options.requireAbilities.filter(
        (required) => !granted.some((ability) => abilityCovers(ability, required))
      );
      if (missing.length > 0) {
        throw deny(
          "grants_abilities_insufficient",
          `The presented chain does not cover: ${missing.join(", ")}`
        );
      }
    }

    // Representation is read ONLY when this surface demands one, and then as a POINT LOOKUP
    // keyed by the decision's own key rather than a scan of everything published about the
    // agent. The decision key includes the authorized writer, and here it is fully determined:
    // only the represented party may assert representation (`verifyRepresentsChain` enforces
    // `edge.issuedBy === organizationId`), so the issuer AND the object are both the required
    // organization and the subject is the agent. That is why an attacker cannot flip this
    // ALLOW to a DENY by publishing edges naming the agent — none of them are on the key that
    // is read. Without `requireRepresents` no relationship read happens at all.
    if (options.requireRepresents !== undefined) {
      const organizationId = options.requireRepresents;
      const edge = await view.getRelationshipEdge(
        organizationId,
        subjectId,
        organizationId,
        REPRESENTS_PREDICATE
      );
      // The lookup narrows; it does not authorize. Signature, expiry and revocation are still
      // checked here, on the returned record, exactly as they were on a scanned candidate.
      const verdict = edge
        ? await verifyRepresentsChain({ agentId: subjectId, organizationId, edge }, view, {
            now: now(),
            ...shared
          })
        : null;
      if (verdict?.valid !== true) {
        // The generic reason is preserved for ordinary rejections — callers depend on it —
        // and only a COST refusal is passed through, because that one must not read as an
        // authentication failure.
        throw asVerifyFailure(
          verdict?.valid === false && verdict.reason.endsWith("_too_expensive")
            ? verdict.reason
            : "represents_chain_unverified",
          `No verified represents chain from ${organizationId}`
        );
      }
    }

    // Replay control, phase 2 of 2: COMMIT, now that the request has fully authorized.
    //
    // Last statement before the return, and it must stay last: every check above is a way for
    // this request to be refused, and a refused request must not have cost a nonce slot. The
    // guard is still the authority on the verdict — `peek` above reserved nothing, so two
    // concurrent presentations of one nonce both reach here and exactly one of them gets
    // `fresh`. The loser is refused as a replay, which is the guarantee that matters: a
    // request this function returns successfully can never be replayed.
    //
    // At the ceiling the guard refuses rather than evicting a live nonce — accepting an
    // unrecorded nonce would silently disable replay protection — so `nonce_capacity` is a 503
    // raised after the authorization work rather than before it. That is the intended cost of
    // the reorder: capacity is now spent only on requests that earned it.
    //
    // RESIDUAL, stated because the reorder is easy to over-read: this stops UNAUTHORIZED
    // traffic from consuming the map, not all cheaply-obtained traffic. A self-minted identity
    // presenting no grants chain authorizes AS ITSELF and still commits a nonce, so a surface
    // that admits unknown participants is bounded by its admission and rate controls (W1/W3)
    // exactly as `createNonceGuard`'s own comment says. The nonce ENCODING and LENGTH are also
    // still unbounded here; finding 10's second half is not addressed by this ordering change.
    const committed = nonceGuard.check(nonce, nowSeconds);
    if (committed === "replayed") {
      throw deny("nonce_replayed", "The request nonce has already been used");
    }
    if (committed === "at_capacity") {
      throw refuse(
        "nonce_capacity",
        "Replay-nonce tracking is at capacity; retry once the current window drains"
      );
    }
    if (committed === "clock_invalid") {
      throw refuse(
        "clock_invalid",
        "This surface's clock is unusable for replay tracking; retry shortly"
      );
    }

    return {
      agentId: subjectId,
      actor: actor.id,
      delegated,
      abilities,
      satisfiedKey,
      chain: capturedChain,
      actorKeyState
    };
  }

  /**
   * Fetch-API adapter. Reads the body as BYTES (`arrayBuffer`), never `.text()`: the
   * signature covers a digest of the content octets, and `Request.text()` decodes them
   * with U+FFFD replacement first, which makes distinct deliveries digest alike and hands
   * the application bytes the signature never covered. Application-level decoding and
   * parsing belong after this function returns — over the `octets` it returns, not over a
   * second read of the request. See {@link VerifiedFetch}.
   */
  async function verifyFetch(
    request: Request,
    context?: VerificationContext
  ): Promise<VerifiedFetch> {
    const body =
      request.method === "GET" || request.method === "HEAD"
        ? EMPTY_BODY
        : new Uint8Array(await request.clone().arrayBuffer());
    const headers: Record<string, string | undefined> = {};
    request.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    const agent = await verify(
      { method: request.method, url: request.url, headers, body },
      context
    );
    // The same array that was digested and verified, by identity — not a copy, and not a second
    // read of the request. A consumer that parses these bytes is parsing what the signature
    // covered, which is the only way the guarantee survives the return.
    return { ...agent, octets: body };
  }

  /**
   * Express-style middleware. It requires the body as RAW BYTES — mount
   * `express.raw` with a wildcard type, whose `Buffer` is a `Uint8Array` and is passed
   * straight through with no copy and no decode.
   *
   * A decoded body is refused as `body_not_raw`, and that includes a `string`, which this
   * adapter used to accept: `express.text` runs the bytes through a charset decoder, and
   * every malformed sequence comes out as U+FFFD. Two different deliveries then reach the
   * verifier as the same text and digest the same, so one signature covers both while the
   * application still sees whichever bytes actually arrived. The middleware cannot detect
   * that from the string it is handed, so it declines to vouch for it at all.
   */
  function middleware() {
    return async (req: NodeStyleRequest, res: NodeStyleResponse, next: () => void) => {
      try {
        const host = req.get?.("host") ?? singleHeader(req.headers.host) ?? "";
        const url = `${req.protocol ?? "https"}://${host}${req.originalUrl ?? req.url ?? ""}`;

        let body: Uint8Array = EMPTY_BODY;
        if (req.body instanceof Uint8Array) {
          body = req.body;
        } else if (req.body !== undefined) {
          throw deny(
            "body_not_raw",
            'The middleware needs the raw body bytes; mount express.raw({ type: "*/*" }) before it'
          );
        }

        const headers: Record<string, string | undefined> = {};
        for (const [name, value] of Object.entries(req.headers)) {
          headers[name.toLowerCase()] = singleHeader(value);
        }

        req.verifiedAgent = await verify({ method: req.method ?? "GET", url, headers, body });
        next();
      } catch (error) {
        const reason = error instanceof VerifyError ? error.reason : "verification_failed";
        if (error instanceof VerifyCapacityError) {
          // Not an auth failure: transient, and the client should retry rather than
          // re-authenticate. Surfacing it as 401 would mislead clients and alerting alike.
          res.status(error.status).json({ error: "temporarily_unavailable", reason });
          return;
        }
        res.status(401).json({ error: "unauthorized_agent", reason });
      }
    };
  }

  return { view, beginRequest, verify, verifyFetch, middleware };
}
