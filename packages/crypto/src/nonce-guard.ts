/**
 * Bounded replay-nonce tracking for RFC 9421 request signatures (spec 004).
 *
 * A signature's `nonce` must be remembered for as long as its timestamp could still pass
 * the freshness check, otherwise the same signed request can be replayed inside that
 * window. Remembering nonces means a map that grows with request volume, and on the open
 * internet request volume is attacker-influenced — so the map needs a hard ceiling.
 *
 * ## Sizing the TTL: the replay window is 2 x skew, INCLUSIVE at both ends
 *
 * `verifyRequest` accepts a signature iff `Math.abs(now - created) <= maxSkew` (it rejects
 * on `>`). So for a fixed `created = c` the signature is presentable across the CLOSED
 * interval `t in [c - S, c + S]`, where `S = maxSkewSeconds`. The earliest a first
 * presentation can happen is `tFirst = c - S`; the latest a replay can still pass freshness
 * is `tLast = c + S = tFirst + 2S`.
 *
 * This guard reports `replayed` while `expiry > atSeconds`, so refusing the replay at
 * `tLast` requires `tFirst + ttl > tFirst + 2S`, i.e. `ttl > 2S`. Every quantity here is an
 * integer number of seconds, so the minimum sufficient TTL is:
 *
 *     ttlSeconds = 2 * maxSkewSeconds + 1
 *
 * `ttl = 2S` is OFF BY ONE and leaves a real hole: at exactly `tLast` the entry has expired
 * (`expiry > at` is false) while freshness still passes, so the signature replays. That was
 * a live bug — accepted at `t`, refused at `t + 2S - 1`, accepted again at `t + 2S`. At
 * `tLast + 1` the freshness check rejects on its own, so no margin beyond `+1` is needed.
 *
 * The caller MUST also sample its clock ONCE and pass the same value to both `verifyRequest`
 * and `check`. Reading the clock twice lets it tick between them, which re-opens the same
 * one-second hole that `+1` closes.
 *
 * ## Retention is measured on a MONOTONIC clock, and only there
 *
 * The `2S + 1` argument above silently assumes the wall clock only moves forward. It does
 * not: NTP steps, VM snapshot restores and manual changes move it both ways.
 *
 * A **forward** wall jump makes entries look expired early. Sweep them and their signatures
 * are still fresh once the clock is corrected — they replay. Measuring retention on a
 * monotonic clock removes that entirely: retention is a duration since we saw the nonce, and
 * a duration has no business on a clock that can be stepped.
 *
 * Retention deliberately carries NO wall-clock component. Storing a wall deadline alongside
 * and reclaiming only when both had passed would cover backward jumps too, and it would
 * reintroduce a permanent wedge through the other door: during a forward spike the wall
 * deadline is written far in the future, so after the clock is corrected those entries can
 * never be reclaimed, they accumulate to the ceiling, and the guard fails closed forever —
 * while `sweepCouldFree` (which sees only the monotonic deadline) would keep believing a
 * sweep would help, restoring the O(n)-per-refusal cost as well.
 *
 * ## The residual this does NOT close — and it is silent, not loud
 *
 * A **backward** wall step re-opens replay, and no retention scheme can prevent it, because
 * the exposure is in the FRESHNESS check rather than in retention. Freshness must compare
 * against `created`, which is a wall-clock value chosen by the signer.
 *
 * The exposure starts at ONE SECOND, not at the retention window. Worked through with
 * `S = 120`: a signature `created = c` first presented at `c - S` is retained until
 * `c + S + 1` and then correctly reclaimed, because freshness would reject it from
 * `c + S + 1` onwards. Rewind the wall clock by one second to `c + S`, and freshness computes
 * `|c + S - c| = S <= S` — fresh — against a map that no longer holds the nonce. The replay
 * is accepted. Generally, a rewind of `d` seconds re-opens a `d`-wide band of captured
 * signatures for about `d` seconds.
 *
 * The exposure does NOT coincide with a total outage, and it must not be read as requiring the
 * clock to be more than `maxSkew` wrong. At
 * `d = 1` a signer minting a fresh signature at real time `c + S + 1` still verifies
 * (`|c + S - (c + S + 1)| = 1 <= S`), so legitimate traffic flows normally throughout. The
 * condition is silent.
 *
 * Closing it requires detecting wall-versus-monotonic divergence and refusing on backward
 * divergence until the clock catches up — a real mechanism with real availability
 * consequences, deliberately not attempted here. Until then this is an OPERATIONAL
 * obligation, specified in `spec/013-realtime.md`: a snapshot restore or a backward clock
 * step is a security event. `nonce-guard.test.ts` pins the one-second case as an explicit
 * test so the exposure cannot quietly be believed to be smaller than it is.
 *
 *
 * ## Honest scope of the ceiling — it is a memory bound, NOT an abuse control
 *
 * A nonce map is a REPLAY CONTROL, not a cache: evicting an unexpired nonce re-opens the
 * replay window for that signature. So this guard never evicts a live nonce. It prunes
 * entries whose window has closed, and if the map is still full it FAILS CLOSED —
 * `"at_capacity"` — refusing the new request.
 *
 * Be precise about what that is worth, because it is easy to overclaim:
 *
 * - What it does NOT add: a bound in TIME. The pre-existing prune-on-insert loop already
 *   held the map to `arrival rate x TTL`; it was never unbounded in time.
 * - What it DOES add: a bound in RATE — an absolute cap that holds no matter how fast
 *   signatures arrive.
 * - What it COSTS: the cap is a global denial primitive, and it is cheaper to trigger than
 *   the exhaustion it prevents. At the default 200 000 entries and a 241 s TTL, roughly
 *   830 signed requests per second sustained holds the map full, after which EVERY signed
 *   request on that process is refused — for every caller, not just the attacker. Discovery
 *   key-log publishing is self-serve, so minting valid signatures is not a privileged act.
 *
 * So this is a LAST-RESORT MEMORY BOUND: it stops an OOM, and it converts that failure mode
 * into a loud, bounded, self-healing refusal. It is NOT an anti-abuse mechanism, and nothing
 * here should be read as making a surface safe to expose. Admission bounds (W1) and rate
 * limiting (W3) are the controls that do that; a limiter lowers arrival rate so this ceiling
 * is never approached in the first place. Reaching `at_capacity` in production means those
 * controls are absent or misconfigured — treat it as an alert, not as the design working.
 */

import { defaultMonotonicClock, type MonotonicClock } from "./monotonic.js";

/**
 * Default hard ceiling on simultaneously tracked nonces. See the module comment for the
 * sizing rationale: generous enough that legitimate traffic cannot reach it, small enough
 * that a saturated map is bounded memory.
 */
export const DEFAULT_MAX_TRACKED_NONCES = 200_000;

/**
 * The smallest nonce TTL that closes the replay window for a given skew allowance:
 * `2 * maxSkewSeconds + 1`. The `+ 1` is load-bearing, not padding — freshness is inclusive
 * at both ends while the guard's expiry check is strict, so `2 * maxSkew` leaves the
 * signature replayable at exactly `created + maxSkew`. See the module comment's derivation.
 *
 * Every surface tracking spec-004 nonces should derive its TTL through this function rather
 * than open-coding the arithmetic, so the boundary is reasoned about in exactly one place.
 */
export function replayTtlSeconds(maxSkewSeconds: number): number {
  return assertWholeSeconds(maxSkewSeconds, "maxSkewSeconds") * 2 + 1;
}

/**
 * Rejects any second-count that would make the replay arithmetic unsound.
 *
 * `NaN` is the dangerous one: every comparison against it is false, so `Math.abs(now -
 * created) > maxSkew` never rejects and the freshness check is silently disabled entirely,
 * while `at + NaN` expiries are forgotten the instant they are written. `Infinity` breaks the
 * same comparisons in the other direction. Fractional values are rejected because the
 * `2 * skew + 1` derivation is a statement about INTEGER seconds — with a fractional skew the
 * `+ 1` is no longer the minimum sufficient margin, and the guarantee it encodes quietly
 * stops being the guarantee that was proved.
 */
export function assertWholeSeconds(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(
      `${label} must be a non-negative whole number of seconds, got ${String(value)}`
    );
  }
  return value;
}

/**
 * - `fresh` — the nonce had not been seen; it is now recorded.
 * - `replayed` — the nonce is already recorded and its window is still open. Refuse.
 * - `at_capacity` — the ceiling is reached and nothing was expired enough to prune. Refuse
 *   (fail closed); accepting without recording would silently disable replay protection.
 * - `clock_invalid` — the supplied WALL clock is not a safe integer (`NaN`, `Infinity`, …),
 *   which would make every comparison against it meaningless. Refuse.
 *
 * There is deliberately no verdict for a rewound clock: retention spans two timelines
 * (see the module comment), so a clock that moves in either direction is absorbed by
 * remembering entries for longer rather than by refusing requests.
 */
export type NonceVerdict = "fresh" | "replayed" | "at_capacity" | "clock_invalid";

export type NonceGuard = {
  /**
   * Records `nonce` as seen at `atSeconds` (seconds since the epoch, the same clock the
   * signature's `created` parameter is checked against) and reports the verdict.
   *
   * This is the COMMIT half of the two-phase use below, and it is total on its own: a caller
   * with nothing to decide between the two phases calls only this.
   */
  check(nonce: string, atSeconds: number): NonceVerdict;
  /**
   * Reports what {@link NonceGuard.check} WOULD say about `nonce`, recording nothing.
   *
   * WHY A READ-ONLY PHASE EXISTS. `check` both decides and commits, which forces a caller to
   * commit at the moment it wants to ask — and a verifier's first question about a nonce comes
   * long before it knows whether the request is authorized at all. Committing there means an
   * UNAUTHORIZED request occupies a slot in a map that fails closed at its ceiling, so a party
   * whose requests are all refused still spends the capacity that legitimate callers need.
   * Splitting the question from the record lets the verifier ask early (so a replay is refused
   * before any expensive authorization work) and record late (so only a request that actually
   * authorized costs a slot). See `packages/verify/src/verifier.ts`.
   *
   * NEVER `at_capacity`: this reserves nothing, so there is nothing for a ceiling to refuse.
   * The capacity verdict belongs to `check`, which is the call that would insert.
   *
   * An entry whose retention has elapsed reads as `fresh` — the same answer `check` gives it —
   * and is left in place rather than reclaimed here, because a read must not perturb the
   * insertion-order-equals-deadline-order property the O(1) sweep gate depends on. `check`
   * deletes and reinserts it in the ordinary way.
   *
   * WHAT IT DOES NOT PROMISE: `peek` returning `fresh` is not a reservation. Two concurrent
   * presentations of one nonce can both peek `fresh`; the guarantee that only one of them is
   * admitted lives in `check`, which is where the map is actually written. A caller must
   * therefore still act on `check`'s verdict, never treat it as a formality after a clean peek.
   */
  peek(nonce: string, atSeconds: number): Exclude<NonceVerdict, "at_capacity">;
  /** Currently tracked nonces. Exposed for tests and operational metrics. */
  size(): number;
  /**
   * How many full O(size) sweeps this guard has performed. An operational metric: a rate
   * that tracks request rate means the map is being rescanned per request, which is the
   * pathology {@link createNonceGuard} avoids by gating the at-capacity sweep. Under normal
   * operation this grows at roughly one per TTL window.
   */
  sweepCount(): number;
};

export type NonceGuardOptions = {
  /**
   * How long a nonce stays remembered, in seconds. It must STRICTLY EXCEED the width of the
   * window in which a replayed signature would still pass the freshness check. Freshness is
   * inclusive at both ends (`|now - created| <= maxSkew`), so that window is `2 * maxSkew`
   * wide and the minimum sufficient value is `2 * maxSkewSeconds + 1`. Passing `2 * maxSkew`
   * leaves the signature replayable at exactly the last second of its validity. Prefer
   * {@link replayTtlSeconds} over computing this by hand.
   */
  ttlSeconds: number;
  /** Hard ceiling on tracked nonces. Defaults to {@link DEFAULT_MAX_TRACKED_NONCES}. */
  maxEntries?: number;
  /**
   * Monotonic source for the retention half of the timeline. Injected in tests to drive
   * durations deterministically; defaults to {@link defaultMonotonicClock}.
   */
  monotonicNowMs?: MonotonicClock;
};

export function createNonceGuard(options: NonceGuardOptions): NonceGuard {
  const ttlSeconds = assertWholeSeconds(options.ttlSeconds, "ttlSeconds");
  const ttlMs = ttlSeconds * 1000;
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_TRACKED_NONCES;
  const monotonicNowMs = options.monotonicNowMs ?? defaultMonotonicClock;
  /**
   * nonce -> its retention deadline on the MONOTONIC timeline. One deadline, one timeline:
   * retention is a duration since we saw the nonce, and durations do not belong on a clock
   * that NTP can step.
   */
  const seen = new Map<string, number>();
  let lastSweepMono: number | null = null;
  let sweeps = 0;

  /** Drops every entry past its retention deadline. O(size), run at most amortized. */
  function sweep(mono: number): void {
    for (const [nonce, expiresMono] of seen) {
      if (expiresMono <= mono) {
        seen.delete(nonce);
      }
    }
    lastSweepMono = mono;
    sweeps += 1;
  }

  /**
   * True when a sweep could actually free something, decided in O(1).
   *
   * Deadlines are `mono + ttlMs` on a nondecreasing clock with a single TTL, so they are
   * assigned in nondecreasing order and the Map's insertion order IS deadline order — the
   * first entry holds the minimum. (This is why the guard needs no tracked-minimum
   * bookkeeping: unlike a caller-supplied `expiresAt`, the deadline here is derived from a
   * clock this function samples itself, so the ordering is a property of the code rather
   * than a hope about callers. Replacement deletes before reinserting, so a refreshed entry
   * moves to the back rather than keeping a stale position.)
   *
   * The gate matters because it sits on the refusal path: without it, every refused request
   * at a full map costs a full O(size) scan of synchronous main-thread work (~1.2 ms at the
   * default ceiling), so a flood of refusals burns a core and legitimate traffic queues
   * behind it — the ceiling would amplify the very exhaustion it exists to prevent.
   */
  function sweepCouldFree(mono: number): boolean {
    const oldest = seen.values().next();
    return oldest.done !== true && oldest.value <= mono;
  }

  return {
    check(nonce, atSeconds) {
      // The wall clock plays no part in retention, but the caller hands it to us and an
      // unusable value means the freshness check it feeds is meaningless too. Refuse rather
      // than record a nonce for a request that cannot have been soundly time-checked.
      if (!Number.isSafeInteger(atSeconds) || atSeconds < 0) {
        return "clock_invalid";
      }
      const mono = monotonicNowMs();

      // Timely expiry, paced on the monotonic timeline so a wall-clock jump can neither
      // trigger a storm of sweeps nor suppress them.
      if (lastSweepMono === null || mono - lastSweepMono >= ttlMs) {
        sweep(mono);
      }

      const expiresMono = seen.get(nonce);
      if (expiresMono !== undefined) {
        if (expiresMono > mono) {
          return "replayed";
        }
        // Retention has elapsed. Delete before reinserting below so the entry takes a fresh
        // position at the back of the map, preserving insertion-order == deadline-order.
        seen.delete(nonce);
      }

      if (seen.size >= maxEntries) {
        // Prune first — only expired entries may go. A live nonce is never evicted. The
        // O(1) gate keeps a sustained refusal flood from rescanning the map per request.
        if (sweepCouldFree(mono)) {
          sweep(mono);
        }
        if (seen.size >= maxEntries) {
          return "at_capacity";
        }
      }

      seen.set(nonce, mono + ttlMs);
      return "fresh";
    },

    peek(nonce, atSeconds) {
      if (!Number.isSafeInteger(atSeconds) || atSeconds < 0) {
        return "clock_invalid";
      }
      // No sweep, no delete, no insert. Sweeping here would let a read reorder the map, and
      // the O(1) `sweepCouldFree` gate is only sound while insertion order is deadline order.
      const expiresMono = seen.get(nonce);
      return expiresMono !== undefined && expiresMono > monotonicNowMs() ? "replayed" : "fresh";
    },

    size() {
      return seen.size;
    },

    sweepCount() {
      return sweeps;
    }
  };
}
