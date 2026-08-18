/**
 * A TrustView backed by a discovery service over HTTP. Nothing served is trusted as
 * such: key logs are replayed locally and every record is schema-checked, so a hostile
 * or buggy discovery host can withhold data but cannot forge it.
 *
 * BOUNDED DELIVERY. What a hostile host can spend of this process is capped at `getJson`, the
 * single choke point every method below goes through, so the bounds hold for every route at
 * once rather than per method:
 *
 *  - a WHOLE-EXCHANGE deadline ({@link DEFAULT_FETCH_DEADLINE_MS}) covering connect, headers
 *    and body, because the slot is held until the body is in hand and a host that answers
 *    promptly and then stalls its body costs exactly what a host that never answers costs;
 *  - a BYTE CAP ({@link DEFAULT_MAX_RESPONSE_BYTES}) enforced WHILE the body streams, not on a
 *    buffer that has already been paid for;
 *  - NO REDIRECTS. Discovery lives at one configured base URL; a redirect is the host naming
 *    an address the operator never chose, and following it is blind SSRF from inside the
 *    verifier — so a redirect is refused where it is seen and no second request is issued.
 *
 * Each refusal carries its own reason (`discovery_fetch_deadline`,
 * `discovery_response_too_large`, `discovery_redirect_refused`), so a stalled host, an
 * oversized one and a redirecting one are tellable apart from each other and from the
 * throttle's own refusals.
 *
 * RESIDUAL, stated because those three are not the whole story. The byte cap is PER RESPONSE:
 * a caller whose grant chain expands into many lookups can still make this process spend the
 * cap several times over, sequentially. What is bounded is the RESIDENT cost — at most
 * `maxConcurrentFetches * maxResponseBytes` of body in flight — and the cost of any one
 * answer. Downstream the record count is contained as before: `findRevocation` refuses a
 * revocation answer carrying more records than issuers were requested, so the RECORD count a
 * verifier processes stays caller-sized. And the redirect refusal binds what THIS module asks
 * for; an injected `options.fetch` that ignores the `redirect` init decides for itself.
 */
import {
  canonicalDigest,
  defaultMonotonicClock,
  KeyLogParticipantMismatch,
  replayKeyLogFor,
  safeVerificationCount,
  VerificationBudgetExceeded,
  type KeyState,
  type MonotonicClock
} from "@kinnet/crypto";
import {
  keyEventLogSchema,
  MAX_GRANT_CHAIN_LINKS,
  MAX_KEY_EVENT_KEYS,
  MAX_KEY_LOG_EVENTS,
  parseJsonStrict,
  relationshipSchema,
  revocationSchema,
  type KeyEvent,
  type ParticipantId,
  type Relationship,
  type Revocation
} from "@kinnet/protocol";
import {
  beginVerificationOperation,
  verificationWorkOptions,
  type TrustView,
  type VerificationBudget,
  type VerificationOperation
} from "@kinnet/trust";

import { VerifyCapacityError, VerifyError } from "./errors.js";

export type DiscoveryViewOptions = {
  /** Base URL of the discovery service, e.g. "https://discovery.example.com". */
  discoveryUrl: string;
  /** Injected for tests and custom runtimes; defaults to the global fetch. */
  fetch?: typeof fetch;
  /**
   * How long key logs, relationships, and revocation lookups are cached. A fresh
   * revocation becomes visible after at most this long. Default 60 seconds.
   *
   * THIS IS THE ONLY FRESHNESS KNOB, and the key-state memo below does not touch it: the memo
   * answers only for log bytes this TTL has already let through, so a rotation becomes visible
   * exactly as soon as it did before.
   *
   * DECIDED, NOT OVERLOOKED — the value is a security trade, not only a freshness one.
   * A node running this view at the 60 s default against a `recheckInterval` of 15 s hits the
   * trade squarely: spec 013 §2.4.4 SHOULDs a refresh "no coarser than `recheckInterval`", so
   * the view term dominates the rotation window by 4x. Lowering it to 15 s is deliberately not
   * done here, because it would cost two things at once: it would quadruple the discovery fetch
   * volume, and it would remove an accidental ~4x mitigation. An attacker who rotates a key log
   * misses the memo by construction and buys a fresh full replay for each rotation — and this
   * TTL is what caps how often they can make this process fetch, and therefore replay, at all.
   * So tightening freshness would also quadruple the rate at which that attacker can force
   * replays. Both sides belong on the table together, which makes it its own decision rather
   * than a knob to turn in passing.
   */
  cacheTtlSeconds?: number;
  /**
   * Ceiling on the Ed25519 verifications one key-log replay may spend. Default
   * {@link DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS}.
   *
   * The discovery host is hostile in this package's threat model — that is the premise of
   * every other bound here — and it chooses the key logs this view replays, on the inbound
   * request path, before the request has proven anything. `replayKeyLog`'s own default is
   * sized never to reject a schema-valid log, which makes it far too generous to hand to a
   * host that is assumed to be an adversary. Verifiers whose counterparties run large
   * signing committees can raise it.
   */
  maxSignatureVerifications?: number;
  /**
   * Hard ceiling on cached discovery lookups. The cache is keyed by request path, and the
   * participant id in that path is attacker-chosen: a key-state lookup happens BEFORE the
   * request signature is checked, so unauthenticated traffic naming fabricated ids can
   * populate this map. It is bounded, and stale entries are expired on a schedule rather
   * than only when the same key happens to be read again.
   *
   * Honest scope: unlike a nonce map, this is a CACHE — evicting an entry costs a re-fetch,
   * never a security property. So the ceiling evicts (oldest first) rather than failing
   * closed. An attacker cycling through fabricated ids can therefore thrash the cache and
   * degrade performance (more discovery round-trips); what they cannot do is grow this
   * process's memory without bound.
   *
   * Defaults to {@link DEFAULT_MAX_CACHE_ENTRIES}.
   */
  maxCacheEntries?: number;
  /**
   * Wall-clock injection for tests. Retained for API compatibility and for callers that pass
   * a shared clock; this module no longer reads it, because a cache TTL is a duration and is
   * therefore measured on {@link DiscoveryViewOptions.monotonicNowMs}.
   */
  now?: () => Date;
  /**
   * Monotonic source for the cache TTL. Injected in tests to drive expiry deterministically;
   * defaults to the platform monotonic clock. Measuring the TTL on the wall clock let a
   * backward step serve stale key state and revocations past their lifetime.
   */
  monotonicNowMs?: MonotonicClock;
  /**
   * Outbound discovery fetches allowed in flight at once, per process.
   * Defaults to {@link DEFAULT_MAX_CONCURRENT_FETCHES}; corrected per
   * {@link boundedThrottleOption}, so it can never be `Infinity` or zero.
   */
  maxConcurrentFetches?: number;
  /**
   * Callers allowed to wait for a fetch slot. Past this the lookup is refused rather than
   * queued, so the backlog itself stays bounded.
   * Defaults to {@link DEFAULT_MAX_QUEUED_FETCHES}; corrected per
   * {@link boundedThrottleOption}, so the queue can never be unbounded.
   */
  maxQueuedFetches?: number;
  /**
   * How long a queued lookup may wait for a slot before it is refused.
   * Defaults to {@link DEFAULT_FETCH_QUEUE_TIMEOUT_MS}; corrected per
   * {@link boundedThrottleOption}, so a waiter can never wait forever.
   */
  fetchQueueTimeoutMs?: number;
  /**
   * How long one discovery exchange may take once it HAS a slot — connect, headers and body
   * together, not time-to-headers.
   *
   * Separate from {@link DiscoveryViewOptions.fetchQueueTimeoutMs}, which bounds the wait for
   * a slot this one has already won. Without it a host that accepts a connection and never
   * finishes the body holds its slot forever, and enough of those retire every slot the
   * throttle has.
   *
   * Defaults to {@link DEFAULT_FETCH_DEADLINE_MS}; corrected per {@link boundedThrottleOption},
   * so a fetch can never be allowed to run forever.
   */
  fetchDeadlineMs?: number;
  /**
   * Bytes one discovery response may deliver before it is refused.
   *
   * Checked while the body STREAMS, so the refusal costs at most one chunk past the cap — a
   * check on an already-buffered body would be a report, not a bound. A declared
   * `content-length` over the cap is refused before a byte is read, but only as a cheap exit:
   * the header is host-supplied and may lie or be absent, so the streaming count is the
   * authority.
   *
   * Defaults to {@link DEFAULT_MAX_RESPONSE_BYTES}; corrected per
   * {@link boundedThrottleOption}, so the cap can never be `Infinity`.
   */
  maxResponseBytes?: number;
};

/**
 * Default cache ceiling. Rationale: at the default 60 s TTL a legitimate surface caches one
 * entry per distinct participant it talks to per minute; 10 000 is far above any realistic
 * working set for a single node/verifier, while capping the cache at a bounded number of
 * parsed key logs and lookup results.
 */
export const DEFAULT_MAX_CACHE_ENTRIES = 10_000;

/**
 * Ed25519 verifications one VERIFICATION CALL may spend, by default.
 *
 * `createVerifier().verify()` shares one allowance across the actor replay, RFC 9421 key search,
 * delegation, and optional representation check. A request handler can start a request context
 * to bound additional verification operations with one outer meter and view-isolated signer
 * memo, while this local default continues to bound each constituent operation.
 *
 * Let `E = MAX_KEY_LOG_EVENTS = 128`, `K = MAX_KEY_EVENT_KEYS = 8`,
 * `A = E*K = 1024`, and `L = MAX_GRANT_CHAIN_LINKS = 4`. The default is
 * `(3L + 1)A = 13A = 13,312`, and every HONEST verdict this call supports now completes well
 * inside it. Measured at the schema maxima, over full-length 1-of-K logs whose matching key is
 * last in every state:
 *
 *   `requireRepresents` agent + relationship + chain    7A + 5K = 7208
 *   late genuine relationship revocation                7A + 6K = 7216
 *   the same shapes with a hostile view's decoys        7A + 13K = 7272
 *
 * Every term is now either a REPLAY or a single walk. The `7A` is seven issuer-log replays —
 * one per distinct participant, memoized across the request's stages — and each `K` is one
 * record checked against the one key state its spec-016 anchor names. The link terms used to be
 * `2A` apiece, a replay plus a search across every historical state, which is why these figures
 * were `12A` and `13A` before 016 and why the hostile composition used to exceed this default
 * rather than fit inside it.
 *
 * The constant is deliberately NOT lowered to match. It is a local resource policy rather than a
 * cost model, its headroom now absorbs shapes it previously refused, and lowering a ceiling is a
 * change that can only start rejecting things. Tests construct and meter these shapes; the
 * formulas are not a substitute for the measurements.
 *
 * RFC 9421 request-signature verification is at most `K` curve checks and is charged to both
 * the local operation meter and any outer request meter. Operators may lower this local policy;
 * exhaustion stays distinguishable from invalid data.
 */
export const DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS =
  (3 * MAX_GRANT_CHAIN_LINKS + 1) * MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS;

/**
 * Outbound discovery fetches in flight at once. Sized for a verifier's own fan-out, not for
 * throughput: a single inbound request carrying a maximum-length grant chain issues its
 * lookups mostly sequentially, so 16 leaves ordinary concurrent traffic untouched while
 * keeping the socket and discovery-side load a burst can create bounded.
 */
export const DEFAULT_MAX_CONCURRENT_FETCHES = 16;

/**
 * Lookups allowed to wait for a slot. A queue is what lets a legitimate burst ride out a busy
 * moment instead of failing; a BOUNDED one is what stops the backlog from becoming the
 * unbounded thing the concurrency cap was meant to prevent.
 */
export const DEFAULT_MAX_QUEUED_FETCHES = 64;

/**
 * How long a queued lookup waits for a slot before it is refused. Past a few seconds the
 * inbound request it belongs to has usually been abandoned by its own client anyway, so
 * waiting longer only holds memory for an answer nobody is still listening for.
 */
export const DEFAULT_FETCH_QUEUE_TIMEOUT_MS = 5_000;

/**
 * How long one discovery exchange may take, end to end, once it holds a slot.
 *
 * WHOLE-EXCHANGE, not time-to-headers, because the slot is held until the body is in hand
 * ("Reading the body is part of the fetch's cost" — see `getJson`). A host that returns a
 * prompt `200` and then dribbles or freezes its body occupies a slot exactly as long as a host
 * that never answers at all, so a headers-only deadline would bound the cheaper of the two
 * attacks and leave the other untouched.
 *
 * 5,000 ms MIRRORS {@link DEFAULT_FETCH_QUEUE_TIMEOUT_MS}, and deliberately: the two are the
 * halves of one lookup's worst case, so a lookup that waits its full turn in the queue and
 * then stalls on the wire is refused at 10 s total — still inside the 60 s whole-request
 * ceiling ({@link FETCH_QUEUE_TIMEOUT_MS_CEILING}) with room for the handful of sequential
 * lookups a grant chain expands into. A discovery lookup is one small GET against a service
 * the verifier depends on and has a healthy round trip in the tens of milliseconds; past a few
 * seconds the answer is late enough that the inbound request it belongs to has usually been
 * abandoned by its own client, which is the same reasoning the queue deadline rests on.
 */
export const DEFAULT_FETCH_DEADLINE_MS = 5_000;

/**
 * Bytes one discovery response may deliver, by default.
 *
 * SIZED FROM THE LARGEST LEGITIMATE ANSWER, which is a key log — every other route here
 * returns a single record or a bounded record list. A key log's shape is fixed by protocol
 * constants rather than by taste: at most {@link MAX_KEY_LOG_EVENTS} = 128 events, each listing
 * at most {@link MAX_KEY_EVENT_KEYS} = 8 keys and carrying exactly its threshold in signatures
 * (also at most 8). One maximal event, JSON-encoded:
 *
 *     8 signatures    x ~96 B   base58btc multibase of a 64-byte Ed25519 signature    768 B
 *     8 key refs      x ~56 B   base58btc multibase of a 32-byte key + multicodec     448 B
 *     id, prior, next x ~64 B   participant id and two multihashes                    192 B
 *     field names, seq, kind, threshold, braces, commas, quotes                      ~128 B
 *                                                                                 ---------
 *                                                                                  ~1,536 B
 *
 * 128 of those is ~196,608 B, i.e. ~192 KiB, plus a negligible `{"events":[…]}` envelope. The
 * default is 1 MiB — about 5x that headroom — so pretty-printed JSON, key material longer than
 * Ed25519's, and envelope fields added later all still fit, while a hostile host is held to a
 * number this process can afford on every slot at once: at the default 16 concurrent fetches
 * the resident worst case is 16 MiB.
 *
 * NOT DERIVABLE FROM THE SCHEMA, which is why the arithmetic is written out rather than
 * computed. `@kinnet/protocol` bounds the COUNT of events, keys and signatures; the multibase
 * strings inside them are regex-shaped and length-unbounded. So the schema alone admits a
 * 128-event log of arbitrary size, and this cap is the only thing between that and this
 * process's memory. If those counts move, this number is re-derived with them.
 */
export const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;

/**
 * Issuer ids this client puts in one issuer-targeted revocation request.
 *
 * It MIRRORS the discovery service's own per-request bound, which answers 400 rather than
 * truncating an over-sized ask. This package must not depend on a discovery service, so the
 * number is duplicated here — **the two
 * must move together, and this one may only ever be lowered relative to the route's.** Set
 * higher than the route's and a large ask becomes a thrown 400 instead of a split.
 *
 * A conforming grant-chain lookup never needs the split: its authorized-revoker set is a suffix
 * of a chain capped at `MAX_GRANT_CHAIN_LINKS`, well below this route limit. Splitting instead
 * keeps this public view method total for direct callers that supply a larger issuer set; such
 * an ask must not become a thrown 400 merely because it did not originate in the resolver.
 */
export const MAX_ISSUERS_PER_REQUEST = 64;

export type DiscoveryView = TrustView & {
  /**
   * The current key state of `id`, or null when the log is missing, invalid, belongs to a
   * DIFFERENT participant, or costs more than `budget` allows. Pass the REQUEST's budget so
   * this replay is charged to the same allowance as everything else that request verifies.
   *
   * A non-null result is bound to `id`: the served log's own inception event derives `id` and
   * not merely some identity. Callers therefore do not need their own comparison, though the
   * ones that already have one keep it. That holds on the memoized path too — the memo is keyed
   * by `id` and can only be written with a state already bound to it.
   *
   * The REPLAY is memoized per (participant, exact log events), so asking twice about a log
   * nothing has changed verifies nothing the second time and spends nothing from `budget`. Only
   * work actually done is charged; a hit is never refunded or credited either.
   */
  getKeyState(
    id: ParticipantId,
    budget?: VerificationBudget,
    operation?: VerificationOperation
  ): Promise<KeyState | null>;
  /**
   * The one edge discovery holds for a decision tuple, or null. The decision key names the
   * AUTHORIZED WRITER — `issuerId` — so this asks about the party entitled to answer instead of
   * listing everyone who published an edge naming the subject.
   *
   * The narrowing happens on an untrusted host, so nothing about the answer is taken on trust.
   * Every predicate a client-side scan would have applied is applied here: the record is
   * schema-parsed, and its own (issuedBy, subjectId, objectId, predicate) must EQUAL the tuple
   * that was requested. A host answering with some other edge yields null, not a candidate.
   * Signature, expiry and revocation are checked where they always were — in the resolver,
   * client-side, on the record this returns.
   *
   * LIMIT, stated because the check invites the stronger reading: it pins WHICH TUPLE is
   * answered, NOT WHICH VERSION of the record. A hostile host holding a superseded edge for the
   * same tuple — one the issuer has since replaced, but which is still signed, unexpired and
   * unrevoked — can serve that old record and this check cannot tell: the tuple matches, because
   * the tuple is what the issuer replaced the record *within*. Nothing here is a freshness
   * mechanism, and none is added: a RELATIONSHIP EDGE's freshness comes from its `expiresAt` and
   * from revocation, so a replaced-but-still-valid edge is replayable until one of those catches
   * it. An issuer that needs a withdrawal to take effect before the edge expires revokes it.
   */
  getRelationshipEdge(
    issuerId: ParticipantId,
    subjectId: ParticipantId,
    objectId: ParticipantId,
    predicate: string
  ): Promise<Relationship | null>;
  /**
   * Entries currently held in the lookup cache. Exposed so the memory ceiling is
   * observable — by tests that assert stale entries are actually dropped from the map
   * rather than merely unreadable, and by operators wanting the number as a metric.
   */
  cacheSize(): number;
  /**
   * How many full O(size) cache sweeps have run. An operational metric: a rate that tracks
   * request rate means the cache is being rescanned per lookup, which is what the O(1) gate
   * on the at-ceiling sweep exists to prevent under a fabricated-id flood.
   */
  cacheSweepCount(): number;
};

function parseEach<T>(values: unknown, parse: (value: unknown) => T | null): T[] {
  if (!Array.isArray(values)) {
    return [];
  }
  return values.map(parse).filter((value): value is T => value !== null);
}

/**
 * The largest value each throttle bound may be configured to. A bound has to bound, and a
 * finite-but-astronomical value (`Number.MAX_VALUE` concurrency, a multi-week queue deadline)
 * is `Infinity` with better manners: the comparison never trips, so the mechanism is gone while
 * every line of it still runs. The ceilings say where "large" stops being a configuration and
 * starts being a deletion:
 *
 * - concurrency: 256 matches the scale of W1's per-process connection ceiling — more
 *   simultaneous outbound sockets than the process accepts inbound is never a real setting;
 * - queue: 4096 waiters is minutes of backlog at any plausible service rate, and each waiter
 *   holds a live timer and a promise chain;
 * - wait deadline: 60s is W1's whole-request total timeout, past which the inbound request the
 *   lookup belongs to has already been severed, so no waiter can usefully outlive it;
 * - fetch deadline: the same 60s for the same reason. A fetch that outlives the inbound
 *   request it was issued for is holding a slot for an answer nobody will read, and the two
 *   deadlines are halves of the same budget, so neither half may exceed the whole;
 * - response bytes: 8 MiB is ~42x the largest legitimate answer ({@link
 *   DEFAULT_MAX_RESPONSE_BYTES} derives that ~192 KiB figure). At the DEFAULT concurrency that
 *   is 128 MiB of body resident at once, already the outer edge of what a verifier process can
 *   be asked to hold on behalf of unauthenticated callers; a larger number is not a
 *   configuration of the cap but a way of not having one.
 */
const MAX_CONCURRENT_FETCHES_CEILING = 256;
const MAX_QUEUED_FETCHES_CEILING = 4_096;
const FETCH_QUEUE_TIMEOUT_MS_CEILING = 60_000;
const FETCH_DEADLINE_MS_CEILING = 60_000;
const MAX_RESPONSE_BYTES_CEILING = 8_388_608;

/**
 * One throttle bound, forced to a usable whole number inside [1, ceiling].
 *
 * These options are programmer input rather than caller input, so this is not input validation —
 * but a limiter whose bound can be `Infinity` is not a limiter. `Infinity` deletes the semaphore
 * entirely (nothing is ever `>= Infinity`), `0` and negatives invert it into a permanent refusal,
 * a fractional value gives a ceiling that no integer count can sit exactly at, and a huge finite
 * value is a deletion wearing a number (see the ceilings above). A non-finite value falls back
 * to the decided default because there is no honest way to clamp it; anything else is truncated
 * toward zero, floored at 1 and capped at the ceiling. Silently, and deliberately so: this is a
 * self-protection bound, and refusing to construct the view would take the whole verifier down
 * over a value that has a safe reading.
 */
function boundedThrottleOption(
  value: number | undefined,
  fallback: number,
  ceiling: number
): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(ceiling, Math.max(1, Math.trunc(value)));
}

/**
 * A running deadline for one discovery exchange.
 *
 * `expired()` rather than error inspection is the whole point of the shape. An abort surfaces
 * out of `fetch` as a `DOMException`/`AbortError` on some runtimes and as a `TypeError` wrapping
 * one on others, and undici has changed which more than once — so the caller asks THIS object
 * whether it fired instead of reading tea leaves out of an error message. A raw abort must never
 * escape to a consumer that has no way to tell it from a connection reset.
 */
type FetchDeadline = {
  readonly signal: AbortSignal;
  /** True once the timer fired, so any error seen afterwards is attributable to it. */
  readonly expired: () => boolean;
  /** Stops the timer. Always called in a `finally`; a stray timer is a stray abort later. */
  readonly cancel: () => void;
};

function startFetchDeadline(deadlineMs: number): FetchDeadline {
  const controller = new AbortController();
  let expired = false;
  const timer = setTimeout(() => {
    expired = true;
    controller.abort();
  }, deadlineMs);
  // A library must never hold the event loop open. `unref` is Node-only; on edge runtimes
  // `setTimeout` hands back a number, so this is feature-detected rather than assumed — the
  // same treatment the queue deadline in `acquireFetchSlot` gets.
  if (typeof timer === "object" && typeof timer.unref === "function") {
    timer.unref();
  }
  return {
    signal: controller.signal,
    expired: () => expired,
    cancel: () => clearTimeout(timer)
  };
}

/**
 * Lets go of a body this view will not read. Fire-and-forget with the rejection swallowed:
 * cancelling a stream that is already errored or aborted rejects, and an unhandled rejection
 * from a cleanup path would be a worse bug than the socket it is trying to free.
 */
function discardBody(response: Response): void {
  void response.body?.cancel().catch(() => undefined);
}

function refuseOversized(path: string, bytes: number, cap: number, source: string): VerifyError {
  return new VerifyError(
    "discovery_response_too_large",
    `Discovery response for ${path} is ${bytes} bytes (${source}), over the ${cap}-byte cap`
  );
}

/**
 * The response body as text, refused the moment it passes `maxResponseBytes`.
 *
 * STREAMING, not `await response.text()` and a length check: by the time `text()` resolves the
 * memory the cap exists to protect has already been spent, so the check would be a report of an
 * attack that succeeded. Reading chunk by chunk means the refusal costs at most one chunk past
 * the cap, whatever the host intended to send after it.
 *
 * The bytes are decoded as UTF-8 and handed to `parseJsonStrict` exactly as `text()` would have
 * produced them, so strict-JSON behaviour — the duplicate-key rejection every record in this
 * view depends on — is unchanged. A null body (204, or a runtime that gives no stream) decodes
 * to the empty string, which is what `text()` returned for it before.
 */
async function readCappedBody(
  response: Response,
  maxResponseBytes: number,
  path: string
): Promise<string> {
  // CHEAP EXIT ONLY. A declared length over the cap saves reading a byte, but the header is
  // host-supplied: it can lie, and chunked responses omit it entirely. The streaming count
  // below is the authority and runs whatever this says.
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (Number.isFinite(length) && length > maxResponseBytes) {
      discardBody(response);
      throw refuseOversized(path, length, maxResponseBytes, "declared");
    }
  }

  const body = response.body;
  if (body === null) {
    return "";
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maxResponseBytes) {
        throw refuseOversized(path, total, maxResponseBytes, "streamed");
      }
      chunks.push(value);
    }
  } finally {
    // Cancelling frees the socket on BOTH exits: after a refusal it stops a host that was
    // still sending, and after a clean read it is a no-op on an already-closed stream. Without
    // it a refused transfer would keep arriving into a body nobody is reading.
    void reader.cancel().catch(() => undefined);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

export function createDiscoveryView(options: DiscoveryViewOptions): DiscoveryView {
  const fetchImpl = options.fetch ?? fetch;
  const ttlMs = (options.cacheTtlSeconds ?? 60) * 1000;
  const base = options.discoveryUrl.replace(/\/+$/, "");
  const maxCacheEntries = options.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;
  const maxSignatureVerifications = safeVerificationCount(
    options.maxSignatureVerifications,
    DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS
  );
  const monotonicNowMs = options.monotonicNowMs ?? defaultMonotonicClock;
  const maxConcurrentFetches = boundedThrottleOption(
    options.maxConcurrentFetches,
    DEFAULT_MAX_CONCURRENT_FETCHES,
    MAX_CONCURRENT_FETCHES_CEILING
  );
  const maxQueuedFetches = boundedThrottleOption(
    options.maxQueuedFetches,
    DEFAULT_MAX_QUEUED_FETCHES,
    MAX_QUEUED_FETCHES_CEILING
  );
  const fetchQueueTimeoutMs = boundedThrottleOption(
    options.fetchQueueTimeoutMs,
    DEFAULT_FETCH_QUEUE_TIMEOUT_MS,
    FETCH_QUEUE_TIMEOUT_MS_CEILING
  );
  const fetchDeadlineMs = boundedThrottleOption(
    options.fetchDeadlineMs,
    DEFAULT_FETCH_DEADLINE_MS,
    FETCH_DEADLINE_MS_CEILING
  );
  const maxResponseBytes = boundedThrottleOption(
    options.maxResponseBytes,
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_RESPONSE_BYTES_CEILING
  );
  /**
   * Insertion-ordered, and — because the monotonic deadline is stamped AT INSERT from a clock
   * this module samples itself, with one TTL — insertion order IS deadline order. That is why
   * no tracked-minimum bookkeeping is needed: the first entry always holds the earliest
   * deadline, so an O(1) look at it decides whether a sweep could free anything.
   *
   * `expiresMono` is process-local and resets on restart; this cache dies with the process,
   * so there is never a surviving deadline to compare against a reset clock.
   */
  const cache = new Map<string, { value: unknown; expiresMono: number }>();
  let lastSweepMono: number | null = null;
  let sweeps = 0;

  /**
   * Memoized RESOLVED key state, keyed by participant id, holding the digest of the exact
   * events it was replayed from.
   *
   * The cache above removes the FETCH and none of the CPU: `getKeyState` replayed the fetched
   * log — every Ed25519 signature in it — on every call, so a request that resolves the same
   * participant twice paid twice, and a 15 s stream re-check paid again every tick for as long
   * as the stream stayed open, against a log nothing had changed. This memo removes the replay.
   *
   * A COST control, not a bound. It changes no verdict ABOUT A LOG: a hit answers with the
   * state a funded call would have computed, a miss is slower but never different, and an
   * attacker cycling fabricated ids or rotating a log misses by construction and pays the full
   * replay every time. The one observable difference is that a caller whose budget is exhausted
   * is handed that state instead of a cost refusal, because a hit performs no work to refuse —
   * benign in both directions that matter: the CPU bound the budget exists to enforce is
   * untouched (zero work was done), `remaining` never rises, and the substitution is always a
   * correct answer replacing a capacity refusal, never an acceptance replacing a rejection.
   * What bounds the hostile case is the caller's budget, which this does not touch — a hit
   * spends nothing from it, and nothing is ever refunded to it.
   *
   * Staleness is structurally impossible rather than carefully managed: a hit requires the
   * exact events to digest identically, so a publish changes the log, changes the digest, and
   * the old entry cannot answer for it. There is no invalidation call for a future call site
   * to forget, and freshness stays exactly where it was — on the fetch TTL above, which decides
   * when new bytes are seen at all.
   *
   * The digest is over the PARSED events, so two encodings that parse to the same log share an
   * entry. That is correct because replay reads only the parsed form.
   *
   * MEMORY BOUND, stated because the key is attacker-influenceable — a key-state lookup happens
   * before any signature is checked, so unauthenticated traffic naming fabricated ids drives
   * insertions. One entry per participant id, at most `maxCacheEntries` of them (default
   * {@link DEFAULT_MAX_CACHE_ENTRIES}), evicted least-recently-used at the ceiling — so a flood
   * of fabricated ids thrashes this map and cannot grow it. It reuses that ceiling rather than
   * inventing a second knob because both maps are indexed by the same attacker-chosen id space,
   * and a `KeyState` — four short strings plus at most `MAX_KEY_EVENT_KEYS` key refs — is
   * smaller than the parsed log the lookup cache already holds for the same id. The honest
   * accounting is therefore: this process now holds up to `maxCacheEntries` key states IN
   * ADDITION to `maxCacheEntries` lookup results, a fraction more of an already-bounded cost.
   *
   * The TTL above does NOT expire entries here, and must not: it is a freshness rule about when
   * new bytes are fetched, and this map makes no freshness claim — it answers only for bytes it
   * was handed. Entries leave by replacement or by eviction, and eviction costs a replay rather
   * than any security property, which is what lets them be dropped without ceremony.
   */
  const keyStates = new Map<ParticipantId, { digest: string; state: KeyState }>();

  /**
   * Records a resolved state, evicting the least recently used entry at the ceiling.
   *
   * The id comparison sits HERE, at the map's only door, rather than at the read — an entry
   * that could not exist cannot be served, so `getKeyState`'s hit path needs no check of its
   * own and callers inherit the same binding on a hit as on a miss. It cannot fire while the
   * only producer is `replayKeyLogFor(id, ...)`, which throws on exactly this condition; it is
   * here because that is a property of one call site rather than of this map, and the throw
   * fails closed (`getKeyState` answers `null`) rather than filing a state under a stranger.
   */
  function rememberKeyState(id: ParticipantId, digest: string, state: KeyState): void {
    if (state.id !== id) {
      throw new KeyLogParticipantMismatch(id, state.id);
    }
    if (keyStates.size >= maxCacheEntries) {
      const oldest = keyStates.keys().next();
      if (!oldest.done) {
        keyStates.delete(oldest.value);
      }
    }
    // Insertion-ordered, which is what makes "the first key" the least recently used: a hit
    // deletes and reinserts, so a scan across many participants cannot push out the ones
    // actually being served — it only wastes its own misses.
    keyStates.set(id, { digest, state });
  }

  /** Drops every entry past its TTL, whether or not anyone ever reads it again. */
  function sweep(mono: number): void {
    for (const [key, entry] of cache) {
      if (entry.expiresMono <= mono) {
        cache.delete(key);
      }
    }
    lastSweepMono = mono;
    sweeps += 1;
  }

  /** True when a sweep could actually free something, decided in O(1). */
  function sweepCouldFree(mono: number): boolean {
    const oldest = cache.values().next();
    return oldest.done !== true && oldest.value.expiresMono <= mono;
  }

  /**
   * Makes room for one more entry. Expiry first (a stale entry costs nothing to drop), then
   * — because this is a cache, not a replay control — eviction of the oldest live entries.
   * Eviction costs a re-fetch, so a fabricated-id flood degrades hit rate, not correctness.
   */
  function admit(mono: number): void {
    if (cache.size < maxCacheEntries) {
      return;
    }
    if (sweepCouldFree(mono)) {
      sweep(mono);
    }
    while (cache.size >= maxCacheEntries) {
      const oldest = cache.keys().next();
      if (oldest.done === true) {
        return;
      }
      cache.delete(oldest.value);
    }
  }

  /**
   * SELF-THROTTLE on outbound fan-out.
   *
   * One inbound request is not one outbound fetch. A request carrying a maximum-length grant
   * chain expands into a key-log lookup and a revocation lookup for every link, plus a
   * relationship edge per hop — and none of that fan-out is authenticated yet, because key
   * state has to be fetched BEFORE a signature can be checked. So an
   * unauthenticated caller chooses how much outbound work this process does on their behalf,
   * and a handful of concurrent callers can put the verifier's whole socket budget, and the
   * discovery service, under load neither of them asked for.
   *
   * The choice made here is that the verifier BOUNDS ITS OWN fan-out, rather than routing
   * these fetches through a rate limiter's accounting. A limiter answers "is this caller
   * allowed to ask again", which is the wrong question for a fetch the verifier has already
   * decided it needs; the question here is "can this process afford another socket right
   * now", and only this process can answer it. It also keeps the failure honest: refusing at
   * the point of the fetch produces a 503 the caller can retry, instead of a slow collapse.
   *
   * Scope, stated plainly: this is PER PROCESS, not per caller and not cluster-wide. It caps
   * what one verifier instance will do concurrently; N instances still fan out N times this.
   * Nothing here attributes load to whoever caused it — the cap is deliberately blind, and a
   * burst of legitimate traffic can be refused alongside an abusive one.
   *
   * Fail CLOSED past the queue: a lookup that cannot get a slot is refused with a 503, never
   * answered from thin air, because "could not check" must never read as "checked and fine".
   */
  const waiters: Array<{ readonly grant: () => void }> = [];
  let fetchesInFlight = 0;

  function acquireFetchSlot(): Promise<void> {
    if (fetchesInFlight < maxConcurrentFetches) {
      fetchesInFlight += 1;
      return Promise.resolve();
    }
    if (waiters.length >= maxQueuedFetches) {
      return Promise.reject(
        new VerifyCapacityError(
          "discovery_fetch_capacity",
          "Discovery fetch queue is full; refusing rather than fanning out further"
        )
      );
    }
    return new Promise<void>((resolve, reject) => {
      // Granting the slot clears the timer, and the timer drops the waiter from the queue, so
      // whichever fires first leaves nothing behind for the other: no slot handed to a caller
      // that already gave up, and no timer left running for a caller already served.
      const waiter = {
        grant: (): void => {
          clearTimeout(timer);
          fetchesInFlight += 1;
          resolve();
        }
      };
      const timer = setTimeout(() => {
        const index = waiters.indexOf(waiter);
        if (index >= 0) {
          waiters.splice(index, 1);
        }
        reject(
          new VerifyCapacityError(
            "discovery_fetch_timeout",
            "Discovery fetch did not get a slot before its deadline"
          )
        );
      }, fetchQueueTimeoutMs);
      // A library must never hold the event loop open. `unref` is Node-only; on edge runtimes
      // `setTimeout` hands back a number, so this is feature-detected rather than assumed.
      if (typeof timer === "object" && typeof timer.unref === "function") {
        timer.unref();
      }
      waiters.push(waiter);
    });
  }

  /**
   * Gives the slot back and, synchronously, hands it to the next waiter if there is one. No
   * await sits between the two, so nothing can observe the count dipping and slip past the
   * cap — the handover is atomic as far as any other caller is concerned.
   */
  function releaseFetchSlot(): void {
    fetchesInFlight -= 1;
    waiters.shift()?.grant();
  }

  async function getJson(path: string): Promise<unknown> {
    // Cache lifetime is a DURATION since we fetched, so it is measured monotonically. On the
    // wall clock a backward step made this cache serve stale key state and revocation
    // results past their TTL — an authorization-relevant staleness, since a fresh revocation
    // is exactly what the TTL exists to let through.
    const mono = monotonicNowMs();
    // Timely expiry, driven by traffic rather than a background timer (a library must not
    // hold the event loop open). Once per TTL window every stale entry goes, so an entry
    // written for a fabricated id is dropped whether or not that id is ever asked for again.
    if (lastSweepMono === null || mono - lastSweepMono >= ttlMs) {
      sweep(mono);
    }
    const cached = cache.get(path);
    if (cached) {
      if (cached.expiresMono > mono) {
        return cached.value;
      }
      cache.delete(path);
    }

    // Only a MISS is throttled, and only from here down. Everything above is local work on
    // already-fetched data, so a cache hit costs no socket and must not be made to wait for
    // one — throttling hits would turn the cache from a relief valve into a queue.
    await acquireFetchSlot();
    let value: unknown = null;
    try {
      // The deadline starts HERE, after the slot is won, so a lookup is not charged for time
      // it spent queued — that wait has its own bound. It covers everything below it,
      // including the body read, because the signal handed to `fetchImpl` aborts the response
      // stream and not merely the header exchange.
      const deadline = startFetchDeadline(fetchDeadlineMs);
      try {
        let response: Response;
        try {
          response = await fetchImpl(`${base}${path}`, {
            signal: deadline.signal,
            // FOLLOW NOTHING. Every path this view requests is on one configured base URL, so a
            // redirect is never how a correct discovery service answers; it is the untrusted
            // host choosing a destination for a request the operator meant for somewhere else,
            // and following it is blind SSRF — to link-local metadata, to an internal service,
            // to anything the verifier's network can reach.
            //
            // `"manual"` rather than `"error"`, and the difference is distinguishability rather
            // than permissiveness: neither follows, but `"error"` collapses into an untyped
            // network `TypeError` that cannot be told from a connection reset, while `"manual"`
            // hands back the 3xx (or an opaque redirect) for the explicit refusal below. A
            // refusal a caller cannot classify is half a mechanism. This is deliberately NOT
            // configurable: there is no discovery deployment that needs a verifier to chase a
            // redirect, and a knob here would only exist to be turned the wrong way.
            redirect: "manual"
          });
        } catch (error) {
          // A fetch that throws BEFORE producing a Response is a transport failure — DNS,
          // connection refused, connection reset, a TLS error. That is discovery being
          // UNREACHABLE, which is transient and retryable: a 503 the caller should back off and
          // retry, never a 401 telling it its credentials are wrong.
          //
          // Two things are re-thrown UNCHANGED rather than mapped. Our own deadline abort, so the
          // outer catch can classify it as `discovery_fetch_deadline`. And any error that is
          // ALREADY a typed `VerifyError` — a custom or wrapping `fetch` may throw its own
          // classified refusal (a self-imposed throttle, say), and relabelling it would erase a
          // more specific reason with a coarser one. Only an UNCLASSIFIED throw — the runtime's
          // network `TypeError` — is the unreachable-host signal this maps.
          if (deadline.expired() || error instanceof VerifyError) {
            throw error;
          }
          throw new VerifyCapacityError(
            "discovery_unavailable",
            `Discovery could not be reached for ${path}: ${
              error instanceof Error ? error.message : "fetch failed"
            }`
          );
        }
        // `opaqueredirect` is what a browser-style runtime returns under `"manual"`; Node and
        // the Workers runtime hand back the real 3xx. Both are the same refusal.
        if (
          response.type === "opaqueredirect" ||
          (response.status >= 300 && response.status < 400)
        ) {
          discardBody(response);
          throw new VerifyError(
            "discovery_redirect_refused",
            `Discovery answered ${path} with a redirect; this view follows none`
          );
        }
        if (response.status !== 404) {
          if (!response.ok) {
            // A 5xx — or a 429 — is the discovery host FAILING to answer a well-formed lookup,
            // not a verdict on this request. Transient and retryable, so it is a capacity 503
            // like an unreachable host, not a 401. Every OTHER non-ok status (a 4xx other than
            // the 404 handled above) is the host REJECTING the request, which a retry cannot
            // change, so it stays a plain error the surface answers 401 — behaviour unchanged.
            if (response.status >= 500 || response.status === 429) {
              discardBody(response);
              throw new VerifyCapacityError(
                "discovery_unavailable",
                `Discovery answered ${response.status} for ${path}; treating it as a transient outage`
              );
            }
            throw new Error(`Discovery request failed with ${response.status} for ${path}`);
          }
          // Reading the body is part of the fetch's cost — it is still holding the socket — so
          // the slot is held until the body is in hand, not merely until headers arrive. The
          // deadline above has the same scope for the same reason.
          //
          // STRICT (spec 015 S6.1), and this is the single choke point for it: EVERY record
          // this view returns arrives through here — key logs, revocations, relationships,
          // claims — so refusing a delivery whose JSON carries a duplicate object key at any
          // depth covers all of them at once rather than per method.
          //
          // The host is untrusted by this module's own contract, and `z.strictObject` cannot
          // stand in: a schema inspects the ALREADY-RESOLVED object, by which point the
          // duplicate has been silently decided last-wins. Only a strict parse of the bytes
          // sees it. Two implementations handed one delivered byte string would otherwise
          // replay two different key logs and derive two different `prior` chains from it.
          value = parseJsonStrict(await readCappedBody(response, maxResponseBytes, path));
        }
      } catch (error) {
        // An abort reaches here as whatever the runtime chose to throw — `AbortError`,
        // `DOMException`, a wrapping `TypeError`. Asking the deadline whether it fired is
        // what turns any of those into one typed, retryable refusal, and it leaves every
        // OTHER failure (a reset, a 500, a strict-JSON rejection) propagating verbatim, which
        // is what existing callers and tests depend on.
        if (deadline.expired()) {
          throw new VerifyCapacityError(
            "discovery_fetch_deadline",
            `Discovery exchange for ${path} did not complete within ${fetchDeadlineMs} ms`
          );
        }
        throw error;
      } finally {
        deadline.cancel();
      }
    } finally {
      // `finally`, because a slot that leaks on the error path is permanent: enough failed
      // fetches and every subsequent lookup queues behind slots nobody holds, and the
      // verifier wedges. Rejections are the COMMON case here (a discovery host that is down
      // is exactly when this runs hot), not the exotic one.
      releaseFetchSlot();
    }

    // Sample AFTER the await, so the deadline reflects when the value was actually cached.
    // This is also what makes insertion order equal deadline order, which the O(1) sweep
    // gate relies on — the pre-await timestamp used previously did not.
    const insertedAt = monotonicNowMs();
    admit(insertedAt);
    // Delete before reinserting. `Map.set` on an existing key keeps its ORIGINAL position,
    // so replacing an entry in place would leave a fresh deadline sitting at an old spot and
    // break the insertion-order == deadline-order property the O(1) sweep gate depends on.
    // Two concurrent lookups of the same path (the second missing while the first is still in
    // flight) reach exactly this line, so it is a live path, not a theoretical one.
    cache.delete(path);
    cache.set(path, { value, expiresMono: insertedAt + ttlMs });
    return value;
  }

  async function getKeyLog(id: ParticipantId): Promise<KeyEvent[] | null> {
    const body = await getJson(`/participants/${encodeURIComponent(id)}/key-log`);
    const events = (body as { events?: unknown } | null)?.events;
    const parsed = keyEventLogSchema.safeParse(events);
    return parsed.success ? parsed.data : null;
  }

  const discoveryView: DiscoveryView = {
    maxSignatureVerifications,
    getKeyLog,

    async getKeyState(id, budget, operation) {
      if (operation) {
        // `getKeyState` is the one lower-level consumer that receives an already-started
        // operation directly. Validate its exact view before fetching or consulting this
        // view's memo; otherwise a foreign operation could spend the wrong outer meter.
        beginVerificationOperation(discoveryView, { operation });
      }
      if (budget) {
        budget.remaining = safeVerificationCount(budget.remaining, 0);
      }
      const events = await getKeyLog(id);
      if (!events) {
        return null;
      }
      const digest = canonicalDigest(events);
      const memo = keyStates.get(id);
      if (memo && memo.digest === digest) {
        // A HIT SPENDS NOTHING. It performs no Ed25519 verification, so charging a budget for
        // it would invent cost that was not paid; crediting one would hand a caller allowance
        // it never had, which is the shape a hostile caller would use to buy replays. The
        // budget is simply not touched, and `remaining` can therefore never rise here.
        keyStates.delete(id);
        keyStates.set(id, memo);
        return memo.state;
      }
      // A miss on a CHANGED log drops the stale entry BEFORE replaying, so a throw cannot leave
      // the previous state answering for bytes it was not computed from.
      keyStates.delete(id);
      try {
        // BOUND to `id`, so no consumer of this method has to remember to compare. The
        // returned `KeyState.id` is self-derived from the log's own inception event: it is a
        // claim the log makes about itself, and the host that chose which bytes to serve at
        // `id`'s path is untrusted — that is this module's premise. `createVerifier` and
        // `@kinnet/a2a` do compare and are therefore already safe; a node surface's owner-mode
        // envelope check and `reauthorizeStream`'s current-state checks do not, and a host
        // answering V's id with an attacker's valid log would have let the attacker's keys
        // satisfy a check about V. Binding here closes every caller at once, which is the
        // point of doing it in the view rather than at each site.
        const state = replayKeyLogFor(id, events, {
          ...(operation
            ? verificationWorkOptions(operation)
            : {
                maxSignatureVerifications: budget ? budget.remaining : maxSignatureVerifications,
                ...(budget
                  ? { onSignatureVerifications: (spent: number) => (budget.remaining -= spent) }
                  : {})
              })
        });
        // Only a log that replayed clean is remembered. A refusal — malformed, forged,
        // substituted, or refused on cost — leaves NO entry, so it is re-replayed in full the
        // next time it is asked about: no caller can be handed a remembered failure, and a
        // caller that comes back with a larger allowance gets a real answer rather than the
        // cheap `null` the exhausted one produced.
        rememberKeyState(id, digest, state);
        return state;
      } catch (error) {
        // A refusal on COST is not "no key log resolves", and reporting it as one sends the
        // caller to fix a log that may be perfectly good — the rule this change exists to
        // keep. So it is rethrown for a caller that opted into the budget protocol by passing
        // one, and left as `null` for callers that did not (`@kinnet/a2a`, a client SDK),
        // whose contract here is `KeyState | null` and whose behaviour must not change.
        if ((budget || operation) && error instanceof VerificationBudgetExceeded) {
          throw error;
        }
        // A substituted log lands here and becomes `null` — this method's return type carries
        // no reason channel, and inventing a throw for it would change the contract for the
        // callers above that document `KeyState | null`. `null` is fail-closed at every one of
        // them: each treats it as "no key state" and denies. The DISTINGUISHABLE reasons for a
        // substitution live where there is a channel to carry them — `@kinnet/trust`'s
        // `*_key_log_participant_mismatch` verdicts, and `createVerifier`'s own id comparison,
        // which is kept rather than deleted precisely so it does not depend on this one.
        return null;
      }
    },

    async getRevocations(revokesDigest, issuerIds) {
      // Sorted and deduped first, because the request path is the cache key: the same
      // authorized-revoker set in a different order is the same question and must hit the same
      // entry, and a repeated id must not consume a slot in the per-request issuer bound.
      // Per-(digest, issuer) cache entries were the alternative — more reusable across
      // differently shaped asks, but they make one lookup N cache probes and, on a partial
      // miss, N fetches, turning the batching this method exists for back into per-issuer
      // round trips.
      const issuers = Array.from(new Set(issuerIds)).sort();
      if (issuers.length === 0) {
        return [];
      }

      // SPLIT, never truncate. The route refuses an over-sized ask with a 400 rather than
      // trimming it, so a direct caller's set larger than one request's worth has to be asked
      // for in pieces. Resolver-produced sets are bounded by `MAX_GRANT_CHAIN_LINKS` and never
      // reach this branch; keeping it makes the public view method safe outside that path.
      // Sequential is fine: past one chunk is rare, and the union matters more than latency.
      //
      // Each chunk is its OWN request path and therefore its own cache entry, so a >64-issuer
      // ask caches per chunk. Chunks are cut from the sorted list, so the same set asked twice
      // cuts the same chunks and hits the same entries.
      const found: Revocation[] = [];
      for (let start = 0; start < issuers.length; start += MAX_ISSUERS_PER_REQUEST) {
        const chunk = issuers.slice(start, start + MAX_ISSUERS_PER_REQUEST);
        const query = chunk.map((id) => `issuer=${encodeURIComponent(id)}`).join("&");
        const body = await getJson(`/revocations/${encodeURIComponent(revokesDigest)}?${query}`);
        const revocations = (body as { revocations?: unknown } | null)?.revocations;
        found.push(
          ...parseEach<Revocation>(revocations, (value) => {
            const parsed = revocationSchema.safeParse(value);
            return parsed.success ? parsed.data : null;
          })
        );
      }
      return found;
    },

    async getRelationshipEdge(issuerId, subjectId, objectId, predicate) {
      // Fixed parameter order, because the request path is the cache key: the same tuple must
      // produce the same path — and therefore the same entry — on every call.
      const query = [
        `issuer=${encodeURIComponent(issuerId)}`,
        `object=${encodeURIComponent(objectId)}`,
        `predicate=${encodeURIComponent(predicate)}`
      ].join("&");
      const body = await getJson(
        `/participants/${encodeURIComponent(subjectId)}/relationships?${query}`
      );
      const parsed = relationshipSchema.safeParse(
        (body as { relationship?: unknown } | null)?.relationship
      );
      if (!parsed.success) {
        return null;
      }
      const edge = parsed.data;
      // The host filtered; that is a hint, not a fact. Re-checking the returned record's tuple
      // against the requested one is what keeps a hostile or buggy host from substituting a
      // different edge — for instance one issued by somebody the caller never named. Dropping
      // this check because "the server already filtered" IS the vulnerability.
      if (
        edge.issuedBy !== issuerId ||
        edge.subjectId !== subjectId ||
        edge.objectId !== objectId ||
        edge.predicate !== predicate
      ) {
        return null;
      }
      return edge;
    },

    cacheSize() {
      return cache.size;
    },

    cacheSweepCount() {
      return sweeps;
    }
  };
  return discoveryView;
}
