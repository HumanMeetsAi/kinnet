import { describe, expect, it } from "vitest";

import {
  createNonceGuard,
  DEFAULT_MAX_TRACKED_NONCES,
  replayTtlSeconds,
  type NonceGuardOptions
} from "../src/nonce-guard.js";

/**
 * Two clocks, driven independently, because that separation is the thing under test. `tick`
 * advances real time (both timelines together, the healthy case); `stepWall` moves only the
 * wall clock, which is what NTP steps and snapshot restores actually do.
 */
function clocks(startWallSeconds = 1_000) {
  let wall = startWallSeconds;
  let mono = 0;
  return {
    wall: () => wall,
    monotonicNowMs: () => mono,
    /** Real time passes: both timelines advance. */
    tick(seconds: number) {
      wall += seconds;
      mono += seconds * 1000;
    },
    /** The wall clock alone is stepped; no real time passes. */
    stepWall(seconds: number) {
      wall += seconds;
    }
  };
}

/** A guard wired to a driven monotonic clock, for every duration-dependent test. */
function guardOn(c: ReturnType<typeof clocks>, options: Omit<NonceGuardOptions, "monotonicNowMs">) {
  return createNonceGuard({ ...options, monotonicNowMs: c.monotonicNowMs });
}

describe("createNonceGuard", () => {
  it("accepts a nonce once and refuses the replay inside its window", () => {
    const guard = createNonceGuard({ ttlSeconds: 240 });
    expect(guard.check("n1", 1_000)).toBe("fresh");
    expect(guard.check("n1", 1_000)).toBe("replayed");
    expect(guard.check("n1", 1_239)).toBe("replayed");
  });

  it("forgets a nonce only once its replay window has closed", () => {
    const c = clocks();
    const guard = guardOn(c, { ttlSeconds: 241 });
    expect(guard.check("n1", c.wall())).toBe("fresh");
    // Still remembered at the last second the signature could pass freshness...
    c.tick(240);
    expect(guard.check("n1", c.wall())).toBe("replayed");
    // ...and forgotten one second later, by which point the freshness check rejects it
    // anyway. (The previous version of this test asserted `fresh` at 1_240 with a comment
    // claiming the freshness check owned rejection from there. That was empirically false:
    // freshness is `|now - created| <= maxSkew`, inclusive, so a signature created at
    // `t + skew` is still fresh at `t + 2 * skew` — the exact second this guard had already
    // forgotten it. That off-by-one was a live replay hole.)
    c.tick(1);
    expect(guard.check("n1", c.wall())).toBe("fresh");
  });

  it("closes the replay window at both ends for the derived TTL", () => {
    // The end-to-end boundary, in guard terms. S = 120, so a signature created at `c` is
    // presentable across [c - 120, c + 120]: first presentation at c - 120, last possible
    // replay at c + 120, i.e. 240 s later.
    const S = 120;
    const c = clocks();
    const guard = guardOn(c, { ttlSeconds: replayTtlSeconds(S) });

    expect(guard.check("n", c.wall())).toBe("fresh");
    let elapsed = 0;
    for (const target of [0, 1, 2 * S - 1, 2 * S]) {
      c.tick(target - elapsed);
      elapsed = target;
      expect(guard.check("n", c.wall())).toBe("replayed");
    }
  });

  it("derives a TTL that strictly exceeds the replay window width", () => {
    expect(replayTtlSeconds(120)).toBe(241);
    expect(replayTtlSeconds(0)).toBe(1);
    // The invariant that matters: strictly greater than 2 * skew, never equal.
    for (const skew of [0, 1, 30, 120, 300]) {
      expect(replayTtlSeconds(skew)).toBeGreaterThan(2 * skew);
    }
  });

  it("sweeps expired entries out of the map without being at the ceiling", () => {
    const c = clocks();
    const guard = guardOn(c, { ttlSeconds: 10, maxEntries: 1_000 });
    for (let i = 0; i < 100; i += 1) {
      guard.check(`n${i}`, c.wall());
    }
    expect(guard.size()).toBe(100);
    // One later call, a full TTL window on, is enough to drop all 100 expired entries.
    c.tick(11);
    expect(guard.check("later", c.wall())).toBe("fresh");
    expect(guard.size()).toBe(1);
  });

  it("stays out of the way of legitimate load beneath the ceiling", () => {
    const guard = createNonceGuard({ ttlSeconds: 240, maxEntries: 500 });
    for (let i = 0; i < 499; i += 1) {
      expect(guard.check(`n${i}`, 1_000)).toBe("fresh");
    }
    expect(guard.size()).toBe(499);
    expect(guard.check("n499", 1_000)).toBe("fresh");
  });

  it("fails closed at the ceiling instead of growing", () => {
    const guard = createNonceGuard({ ttlSeconds: 240, maxEntries: 500 });
    for (let i = 0; i < 500; i += 1) {
      expect(guard.check(`n${i}`, 1_000)).toBe("fresh");
    }
    expect(guard.check("overflow", 1_000)).toBe("at_capacity");
    expect(guard.size()).toBe(500);
  });

  it("never evicts a live nonce to make room, so replay stays refused at the ceiling", () => {
    const guard = createNonceGuard({ ttlSeconds: 240, maxEntries: 3 });
    expect(guard.check("live", 1_000)).toBe("fresh");
    expect(guard.check("b", 1_000)).toBe("fresh");
    expect(guard.check("c", 1_000)).toBe("fresh");

    // Saturated: new work is refused...
    expect(guard.check("d", 1_000)).toBe("at_capacity");
    expect(guard.check("e", 1_001)).toBe("at_capacity");
    // ...and the oldest live nonce is still remembered, so its replay is still refused.
    expect(guard.check("live", 1_002)).toBe("replayed");
    expect(guard.size()).toBe(3);
  });

  /**
   * `peek` is the read-only half that lets a caller ASK before it is ready to RECORD. Its
   * whole value is that it does not mutate, so every test here is about what did NOT happen.
   *
   * THE MUTATION THESE CATCH: implementing `peek` as `check` (or as a `check` that sweeps or
   * reclaims). Each such implementation passes a naive "peek reports replayed" test and fails
   * the size/verdict assertions below.
   */
  describe("peek — asking without recording", () => {
    it("reports an unseen nonce fresh and records nothing", () => {
      const guard = createNonceGuard({ ttlSeconds: 240 });
      expect(guard.peek("n1", 1_000)).toBe("fresh");
      expect(guard.peek("n1", 1_000)).toBe("fresh");
      expect(guard.size()).toBe(0);
      // And the nonce is genuinely still available afterwards — a peek must not consume it.
      expect(guard.check("n1", 1_000)).toBe("fresh");
      expect(guard.size()).toBe(1);
    });

    it("reports a live nonce replayed, exactly as `check` would", () => {
      const guard = createNonceGuard({ ttlSeconds: 240 });
      expect(guard.check("n1", 1_000)).toBe("fresh");
      expect(guard.peek("n1", 1_000)).toBe("replayed");
      expect(guard.peek("n1", 1_239)).toBe("replayed");
      expect(guard.size()).toBe(1);
    });

    it("agrees with `check` at the retention boundary, without reclaiming the entry", () => {
      const c = clocks();
      const guard = guardOn(c, { ttlSeconds: 241 });
      expect(guard.check("n1", c.wall())).toBe("fresh");
      c.tick(240);
      expect(guard.peek("n1", c.wall())).toBe("replayed");
      c.tick(1);
      // Retention has elapsed: the answer flips to `fresh`, and the stale entry is LEFT in
      // place. Reclaiming it in a read would reorder the map, and the O(1) at-capacity gate
      // is only sound while insertion order is deadline order.
      expect(guard.peek("n1", c.wall())).toBe("fresh");
      expect(guard.size()).toBe(1);
    });

    it("never sweeps, so a read cannot be made to carry O(size) work", () => {
      const c = clocks();
      const guard = guardOn(c, { ttlSeconds: 10, maxEntries: 500 });
      for (let i = 0; i < 100; i += 1) {
        expect(guard.check(`n${i}`, c.wall())).toBe("fresh");
      }
      const sweepsBefore = guard.sweepCount();
      // Well past the TTL: a `check` here WOULD sweep. A thousand peeks must not.
      c.tick(1_000);
      for (let i = 0; i < 1_000; i += 1) {
        expect(guard.peek(`n${i % 100}`, c.wall())).toBe("fresh");
      }
      expect(guard.sweepCount()).toBe(sweepsBefore);
      expect(guard.size()).toBe(100);
    });

    it("never answers at_capacity, because it reserves nothing", () => {
      const guard = createNonceGuard({ ttlSeconds: 240, maxEntries: 3 });
      for (const nonce of ["a", "b", "c"]) {
        expect(guard.check(nonce, 1_000)).toBe("fresh");
      }
      expect(guard.check("d", 1_000)).toBe("at_capacity");
      // The map is saturated and a peek still answers the replay question — which is the
      // point: a caller can refuse a replay cheaply even when it could not have recorded it.
      expect(guard.peek("d", 1_000)).toBe("fresh");
      expect(guard.peek("a", 1_000)).toBe("replayed");
      expect(guard.size()).toBe(3);
    });

    it("refuses an unusable wall clock rather than answering from it", () => {
      const guard = createNonceGuard({ ttlSeconds: 240 });
      for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, 2 ** 53]) {
        expect(guard.peek("n1", bad)).toBe("clock_invalid");
      }
      expect(guard.size()).toBe(0);
    });

    it("does not reserve: two peeks then two checks admit exactly one", () => {
      // The honest limit of the split. `peek` is not a hold, and a caller that treated a clean
      // peek as permission would admit both presentations of one captured signature.
      const guard = createNonceGuard({ ttlSeconds: 240 });
      expect(guard.peek("n1", 1_000)).toBe("fresh");
      expect(guard.peek("n1", 1_000)).toBe("fresh");
      expect(guard.check("n1", 1_000)).toBe("fresh");
      expect(guard.check("n1", 1_000)).toBe("replayed");
    });
  });

  it("recovers capacity once tracked nonces expire", () => {
    const c = clocks();
    const guard = guardOn(c, { ttlSeconds: 10, maxEntries: 2 });
    expect(guard.check("a", c.wall())).toBe("fresh");
    expect(guard.check("b", c.wall())).toBe("fresh");
    expect(guard.check("c", c.wall())).toBe("at_capacity");
    c.tick(10);
    expect(guard.check("c", c.wall())).toBe("fresh");
    expect(guard.size()).toBe(1);
  });

  it("does not rescan the map on every refused request at capacity", () => {
    // The refusal path is attacker-reachable by construction, so it must not carry O(size)
    // work: at the default ceiling a full sweep is ~1.2 ms of synchronous main-thread time,
    // and a sustained refusal flood would burn a core with legitimate traffic queued behind
    // it — the ceiling amplifying the exhaustion it exists to prevent.
    const guard = createNonceGuard({ ttlSeconds: 240, maxEntries: 500 });
    for (let i = 0; i < 500; i += 1) {
      expect(guard.check(`n${i}`, 1_000)).toBe("fresh");
    }

    const sweepsBeforeFlood = guard.sweepCount();
    for (let i = 0; i < 1_000; i += 1) {
      // Same second throughout, so nothing can have expired and no sweep can free anything.
      expect(guard.check(`flood-${i}`, 1_000)).toBe("at_capacity");
    }
    expect(guard.sweepCount()).toBe(sweepsBeforeFlood);
  });

  it("still sweeps at capacity when the sweep can actually free something", () => {
    // The gate must not turn into "never sweep": once entries expire, capacity recovers.
    const c = clocks();
    const guard = guardOn(c, { ttlSeconds: 10, maxEntries: 3 });
    for (let i = 0; i < 3; i += 1) {
      expect(guard.check(`n${i}`, c.wall())).toBe("fresh");
    }
    c.tick(5);
    expect(guard.check("refused", c.wall())).toBe("at_capacity");

    // Past the TTL the oldest entry is reclaimable, so the sweep runs and admits.
    c.tick(5);
    expect(guard.check("admitted", c.wall())).toBe("fresh");
    expect(guard.size()).toBe(1);
  });

  it("retains a nonce across a backward wall step while retention has not elapsed", () => {
    // Retention rides the monotonic clock, so a wall step of any size neither shortens nor
    // extends it. While the nonce is still retained, a rewind changes nothing.
    const c = clocks();
    const guard = guardOn(c, { ttlSeconds: 241, maxEntries: 100 });
    expect(guard.check("n", c.wall())).toBe("fresh");

    c.tick(30);
    c.stepWall(-30);
    expect(guard.check("n", c.wall())).toBe("replayed");
  });

  it("DOCUMENTED RESIDUAL: a ONE-SECOND wall rewind re-opens replay, silently", () => {
    // Pinning what is NOT closed, at its true magnitude, so it cannot be believed smaller.
    //
    // Retention is monotonic and correct; the exposure is in the FRESHNESS check, which must
    // compare against the signer-supplied `created` and therefore must use wall time. With
    // S = 120 and `created = c`, a signature first presented at `c - S` is retained for
    // 2S + 1 and reclaimed at `c + S + 1` — correct, since freshness rejects it from there.
    // Rewind the wall clock by ONE second and freshness computes |c + S - c| = S <= S, fresh,
    // against a map that no longer holds the nonce.
    //
    // There is no outage while this is true: a signer minting at real time c + S + 1 gets
    // |c + S - (c + S + 1)| = 1 <= S and still verifies. An earlier comment claimed the
    // opposite; it was wrong, and the claim is gone.
    const S = 120;
    const c = clocks(10_000); // c - S, the earliest presentation
    const created = 10_000 + S;
    const guard = guardOn(c, { ttlSeconds: replayTtlSeconds(S), maxEntries: 100 });

    expect(guard.check("n", c.wall())).toBe("fresh");

    // Real time reaches the reclamation point: created + S + 1.
    c.tick(2 * S + 1);
    expect(c.wall()).toBe(created + S + 1);
    expect(guard.check("other", c.wall())).toBe("fresh"); // drives the sweep
    expect(guard.size()).toBe(1); // "n" really was reclaimed

    // A one-second rewind puts the wall clock back inside the signature's freshness window.
    c.stepWall(-1);
    expect(Math.abs(c.wall() - created)).toBeLessThanOrEqual(S); // still fresh
    expect(guard.check("n", c.wall())).toBe("fresh"); // <- the residual, asserted honestly
  });

  it("does not wedge at capacity after a forward wall spike and its correction", () => {
    // Two wedges have been shipped and taken back here; this pins both.
    //
    // (1) A wall-clock high-water mark never lowered, so one forward spike refused forever.
    // (2) Storing a WALL deadline alongside the monotonic one and reclaiming only when both
    //     passed: during a spike the wall deadline was written far in the future, so after
    //     the clock was corrected those entries could never be reclaimed. They accumulated to
    //     the ceiling and the guard failed closed permanently.
    //
    // Retention is monotonic-only, so entries minted during a spike carry an ordinary
    // deadline and retire on schedule. The ceiling must be entered AND left.
    const c = clocks(1_000_000);
    const guard = guardOn(c, { ttlSeconds: 10, maxEntries: 5 });

    // Fill the map entirely with nonces minted while the wall clock is years ahead.
    c.stepWall(365 * 24 * 3600);
    for (let i = 0; i < 5; i += 1) {
      expect(guard.check(`spike-${i}`, c.wall())).toBe("fresh");
    }
    expect(guard.check("overflow", c.wall())).toBe("at_capacity");

    // Correct the clock. Under the dual-deadline design every entry above was now
    // unreclaimable forever and this guard would refuse for the rest of the process.
    c.stepWall(-365 * 24 * 3600);

    // Real time passes the TTL: the spike-era entries must retire and capacity must return.
    c.tick(11);
    expect(guard.check("after-correction", c.wall())).toBe("fresh");
    expect(guard.size()).toBe(1);
  });

  it("keeps forgetting entries normally when both clocks advance together", () => {
    // The dual deadline must not turn into "never forget": on a healthy clock, retention is
    // still exactly the TTL.
    const c = clocks();
    const guard = guardOn(c, { ttlSeconds: 10, maxEntries: 100 });
    for (let i = 0; i < 20; i += 1) {
      guard.check(`n${i}`, c.wall());
    }
    expect(guard.size()).toBe(20);
    c.tick(11);
    expect(guard.check("later", c.wall())).toBe("fresh");
    expect(guard.size()).toBe(1);
  });

  it("refuses an unusable clock rather than silently disabling expiry", () => {
    // NaN makes every comparison false: nothing looks expired, nothing looks replayed, and
    // `at + ttl` is NaN, so entries are forgotten the instant they are written.
    const guard = createNonceGuard({ ttlSeconds: 241 });
    expect(guard.check("n", Number.NaN)).toBe("clock_invalid");
    expect(guard.check("n", Number.POSITIVE_INFINITY)).toBe("clock_invalid");
    expect(guard.check("n", 1.5)).toBe("clock_invalid");
    expect(guard.size()).toBe(0);
  });

  it("rejects a TTL that is not a whole number of seconds", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5]) {
      expect(() => createNonceGuard({ ttlSeconds: bad })).toThrow(/whole number of seconds/);
    }
  });

  it("rejects a skew that would make the replay derivation unsound", () => {
    // NaN is the dangerous one: `Math.abs(now - created) > NaN` is false for every input, so
    // an unvalidated NaN skew disables the freshness check entirely. Fractional values break
    // the integer-seconds argument the `+ 1` margin is derived from.
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, 0.5, 120.5]) {
      expect(() => replayTtlSeconds(bad)).toThrow(/whole number of seconds/);
    }
    // The valid boundary still works, including zero skew.
    expect(replayTtlSeconds(0)).toBe(1);
    expect(replayTtlSeconds(120)).toBe(241);
  });

  it("reclaims the oldest entry at the ceiling when deadlines genuinely differ", () => {
    // The O(1) gate reads only the FIRST entry's monotonic deadline. That is sound here (and
    // needs no tracked-minimum bookkeeping) precisely because the guard samples the monotonic
    // clock itself and applies one TTL, so deadlines are assigned in nondecreasing order —
    // unlike a caller-supplied `expiresAt`. This exercises genuinely staggered deadlines
    // rather than several entries sharing one instant, which would pass either way.
    const c = clocks();
    const guard = guardOn(c, { ttlSeconds: 10, maxEntries: 2 });
    expect(guard.check("oldest", c.wall())).toBe("fresh"); // mono deadline 10_000
    c.tick(4);
    expect(guard.check("newer", c.wall())).toBe("fresh"); // mono deadline 14_000
    expect(guard.size()).toBe(2);

    // Only `oldest` is past both deadlines here; `newer` still has 4s to run.
    c.tick(6);
    expect(guard.check("admitted", c.wall())).toBe("fresh");
    expect(guard.size()).toBe(2);
    // `newer` really was retained rather than swept along with `oldest`.
    expect(guard.check("newer", c.wall())).toBe("replayed");
  });

  it("conforms to the spec 013 nonce-TTL rule, which forbids maxSkewSeconds * 2", () => {
    // Spec 013 (Replay amplification): "Implementations MUST use
    // nonceTtlSeconds = maxSkewSeconds * 2 + 1". This test encodes the spec's normative rule
    // so the spec and the implementation cannot drift apart: the previously prescribed
    // `maxSkewSeconds * 2` is insufficient and must fail here.
    for (const S of [0, 1, 120, 300]) {
      expect(replayTtlSeconds(S)).toBe(S * 2 + 1);
      expect(replayTtlSeconds(S)).not.toBe(S * 2);
    }

    // And the rule's consequence, stated as the spec states it: at `c + S` — the last second
    // the signature passes freshness — the nonce is still remembered.
    const S = 120;
    const guard = createNonceGuard({ ttlSeconds: replayTtlSeconds(S) });
    const firstPresentation = 10_000; // c - S, for c = 10_000 + S
    expect(guard.check("n", firstPresentation)).toBe("fresh");
    expect(guard.check("n", firstPresentation + 2 * S)).toBe("replayed");
  });

  it("conforms to spec 013's monotonic-duration and validation rules", () => {
    // Spec 013: "Durations MUST be measured on a monotonic clock, not the wall clock" and
    // "`maxSkewSeconds` and the sampled clock MUST each be a finite, non-negative safe
    // integer". Encoded here so an implementation cannot drift from the normative text.
    const c = clocks(100_000);
    const guard = guardOn(c, { ttlSeconds: 10, maxEntries: 100 });
    expect(guard.check("n", c.wall())).toBe("fresh");

    // A wall-clock jump — in either direction — must not decide retention.
    c.stepWall(3_600);
    expect(guard.check("n", c.wall())).toBe("replayed");
    c.stepWall(-7_200);
    expect(guard.check("n", c.wall())).toBe("replayed");

    // Only real elapsed time retires it.
    c.stepWall(3_600);
    c.tick(11);
    expect(guard.check("n", c.wall())).toBe("fresh");

    // Validation of both freshness inputs.
    expect(() => replayTtlSeconds(Number.NaN)).toThrow(/whole number of seconds/);
    expect(guard.check("x", Number.NaN)).toBe("clock_invalid");
  });

  it("defaults to a ceiling far above any legitimate steady-state cardinality", () => {
    expect(DEFAULT_MAX_TRACKED_NONCES).toBeGreaterThanOrEqual(100_000);
    const guard = createNonceGuard({ ttlSeconds: 240 });
    expect(guard.check("n", 1_000)).toBe("fresh");
    expect(guard.size()).toBe(1);
  });
});
