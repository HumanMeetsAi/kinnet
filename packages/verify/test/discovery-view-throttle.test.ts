import { createIdentity } from "@kinnet/crypto";
import { describe, expect, it, vi } from "vitest";

import {
  createDiscoveryView,
  DEFAULT_FETCH_QUEUE_TIMEOUT_MS,
  DEFAULT_MAX_CACHE_ENTRIES,
  DEFAULT_MAX_CONCURRENT_FETCHES,
  DEFAULT_MAX_QUEUED_FETCHES,
  type DiscoveryViewOptions
} from "../src/discovery-view.js";
import { VerifyCapacityError } from "../src/verifier.js";

const identity = createIdentity({
  currentSeed: new Uint8Array(32).fill(3),
  nextSeed: new Uint8Array(32).fill(4)
});

/**
 * A discovery stub whose every request HANGS until the test releases it, so "in flight" is a
 * state the test controls rather than races. It records the live count and its high-water
 * mark: the cap is a statement about the maximum, so the maximum is what gets asserted.
 */
function blockingFetch() {
  const pending: Array<{
    readonly resolve: (response: Response) => void;
    readonly reject: (error: unknown) => void;
  }> = [];
  let live = 0;
  let highWater = 0;
  let started = 0;

  const impl: typeof fetch = async () => {
    live += 1;
    started += 1;
    highWater = Math.max(highWater, live);
    try {
      return await new Promise<Response>((resolve, reject) => {
        pending.push({ resolve, reject });
      });
    } finally {
      live -= 1;
    }
  };

  function settleNext(response: Response): void {
    pending.shift()?.resolve(response);
  }

  function failNext(error: unknown): void {
    pending.shift()?.reject(error);
  }

  return {
    impl,
    /** Requests currently blocked inside the stub. */
    get inFlight() {
      return pending.length;
    },
    /** Highest number of simultaneously live requests seen so far. */
    get highWater() {
      return highWater;
    },
    /** Requests the stub has been asked for at all, released or not. */
    get started() {
      return started;
    },
    settleNext,
    failNext,
    /** Answers the identity's key log; anything else 404s like a fabricated id would. */
    settleNextFound(): void {
      settleNext(Response.json({ events: identity.log }));
    },
    settleNextMissing(): void {
      settleNext(Response.json({ error: "not_found" }, { status: 404 }));
    }
  };
}

/** Lets pending promise chains run. Three macrotask turns is well past what a hop needs. */
async function flush(turns = 3): Promise<void> {
  for (let turn = 0; turn < turns; turn += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

const view = (options: Omit<DiscoveryViewOptions, "discoveryUrl">) =>
  createDiscoveryView({ discoveryUrl: "https://discovery.example.com", ...options });

describe("discovery view fetch throttle", () => {
  it("pins the defaults, so a caller relying on them can see them move", () => {
    expect(DEFAULT_MAX_CONCURRENT_FETCHES).toBe(16);
    expect(DEFAULT_MAX_QUEUED_FETCHES).toBe(64);
    expect(DEFAULT_FETCH_QUEUE_TIMEOUT_MS).toBe(5000);
    // Sanity: the throttle knobs did not disturb the pre-existing cache ceiling.
    expect(DEFAULT_MAX_CACHE_ENTRIES).toBe(10_000);
  });

  it("holds outbound fetches at the default cap while 30 distinct lookups pile up", async () => {
    const fetches = blockingFetch();
    const discovery = view({ fetch: fetches.impl });

    // Thirty DISTINCT ids: distinct request paths, so every one of them is a cache miss and
    // has to go through the throttle. A repeated id would be a cache hit and prove nothing.
    const lookups = Array.from({ length: 30 }, (_unused, index) =>
      discovery.getKeyState(`pk_fanout_${index}`)
    );
    await flush();

    expect(fetches.inFlight).toBe(DEFAULT_MAX_CONCURRENT_FETCHES);
    expect(fetches.highWater).toBe(DEFAULT_MAX_CONCURRENT_FETCHES);
    // Non-vacuous: the other 14 are waiting, not running. Without the cap this would be 30.
    expect(fetches.started).toBe(DEFAULT_MAX_CONCURRENT_FETCHES);

    // Drain one at a time. Each release admits exactly one waiter, and the high-water mark
    // must never move past the cap while the backlog works through.
    while (fetches.inFlight > 0) {
      fetches.settleNextMissing();
      await flush();
      expect(fetches.highWater).toBe(DEFAULT_MAX_CONCURRENT_FETCHES);
    }

    expect(await Promise.all(lookups)).toEqual(Array.from({ length: 30 }, () => null));
    expect(fetches.started).toBe(30);
    expect(fetches.highWater).toBe(DEFAULT_MAX_CONCURRENT_FETCHES);
  });

  it("refuses the lookup that overflows the wait queue, and keeps the ones already in it", async () => {
    const fetches = blockingFetch();
    const discovery = view({ fetch: fetches.impl, maxConcurrentFetches: 2, maxQueuedFetches: 3 });

    // Exactly fills the throttle: 2 running, 3 queued.
    const accepted = Array.from({ length: 5 }, (_unused, index) =>
      discovery.getKeyState(`pk_queued_${index}`)
    );
    await flush();
    expect(fetches.started).toBe(2);

    // The sixth has nowhere to go and is refused rather than queued.
    const overflow = await discovery.getKeyState("pk_overflow").catch((error: unknown) => error);
    expect(overflow).toBeInstanceOf(VerifyCapacityError);
    expect((overflow as VerifyCapacityError).reason).toBe("discovery_fetch_capacity");
    expect((overflow as VerifyCapacityError).status).toBe(503);
    // Refused BEFORE any socket was opened — the point of failing closed at the queue.
    expect(fetches.started).toBe(2);

    // Non-vacuous the other way: the five that fit were not harmed by the refusal.
    while (fetches.inFlight > 0) {
      fetches.settleNextMissing();
      await flush();
    }
    expect(await Promise.all(accepted)).toEqual([null, null, null, null, null]);
    expect(fetches.started).toBe(5);
  });

  it("refuses a queued lookup that cannot start before its deadline", async () => {
    const fetches = blockingFetch();
    const discovery = view({
      fetch: fetches.impl,
      maxConcurrentFetches: 1,
      maxQueuedFetches: 4,
      fetchQueueTimeoutMs: 25
    });

    const blocker = discovery.getKeyState("pk_blocker");
    await flush();
    expect(fetches.started).toBe(1);

    const queued = await discovery.getKeyState("pk_waiting").catch((error: unknown) => error);
    expect(queued).toBeInstanceOf(VerifyCapacityError);
    expect((queued as VerifyCapacityError).reason).toBe("discovery_fetch_timeout");
    expect((queued as VerifyCapacityError).status).toBe(503);
    // It gave up in the queue: no request was ever issued for it.
    expect(fetches.started).toBe(1);

    fetches.settleNextMissing();
    expect(await blocker).toBeNull();
  });

  it("lets a queued lookup through when a slot frees up inside the deadline", async () => {
    // The control for the test above: the same queue, a deadline that is not exceeded. Without
    // this, "the queued one failed" could mean queued lookups never run at all.
    const fetches = blockingFetch();
    const discovery = view({
      fetch: fetches.impl,
      maxConcurrentFetches: 1,
      maxQueuedFetches: 4,
      fetchQueueTimeoutMs: 5_000
    });

    const first = discovery.getKeyState("pk_first");
    await flush();
    const second = discovery.getKeyState("pk_second");
    await flush();
    expect(fetches.started).toBe(1);

    fetches.settleNextMissing();
    await flush();
    expect(fetches.started).toBe(2);
    fetches.settleNextMissing();

    expect(await first).toBeNull();
    expect(await second).toBeNull();
  });

  it("serves a cache hit while the throttle is saturated", async () => {
    const fetches = blockingFetch();
    // The smallest throttle there is: one slot, one queue place. Both are filled below, so any
    // further lookup that needs the throttle is refused immediately — which is what makes "was
    // this served without touching the throttle" observable. (A queue of 0 would say the same
    // thing more directly, but the bounds are floored at 1; see `boundedThrottleOption`.)
    const discovery = view({ fetch: fetches.impl, maxConcurrentFetches: 1, maxQueuedFetches: 1 });

    // Prime the cache with a real key log, so the repeat lookup has a non-null answer to
    // return and cannot pass by accident.
    const primed = discovery.getKeyState(identity.id);
    await flush();
    fetches.settleNextFound();
    expect(await primed).not.toBeNull();
    expect(discovery.cacheSize()).toBe(1);

    // Saturate: one blocked miss occupies the only slot, one more fills the only queue place.
    const blocker = discovery.getKeyState("pk_saturating");
    await flush();
    expect(fetches.started).toBe(2);
    const queued = discovery.getKeyState("pk_queued_while_full");
    await flush();
    expect(fetches.started).toBe(2);

    // A fresh id is refused — proof the throttle really is full right now.
    const missWhileFull = await discovery
      .getKeyState("pk_fresh_while_full")
      .catch((error: unknown) => error);
    expect(missWhileFull).toBeInstanceOf(VerifyCapacityError);

    // The primed path answers anyway, from cache, without waiting for the blocked fetch and
    // without opening a request of its own.
    expect(await discovery.getKeyState(identity.id)).not.toBeNull();
    expect(fetches.started).toBe(2);

    fetches.settleNextMissing();
    await flush();
    fetches.settleNextMissing();
    await flush();
    expect(await blocker).toBeNull();
    expect(await queued).toBeNull();
  });

  it("returns the slot when a fetch rejects, so failures do not wedge the verifier", async () => {
    const fetches = blockingFetch();
    // One slot, a queue of one, and a short deadline: if a failed fetch leaked its slot, the
    // next lookup would sit in the queue and die on the deadline instead of running.
    const discovery = view({
      fetch: fetches.impl,
      maxConcurrentFetches: 1,
      maxQueuedFetches: 1,
      fetchQueueTimeoutMs: 50
    });

    for (let round = 0; round < 3; round += 1) {
      const failing = discovery.getKeyState(`pk_transport_error_${round}`);
      await flush();
      fetches.failNext(new Error("connection reset"));
      await expect(failing).rejects.toThrow("connection reset");

      const after = discovery.getKeyState(`pk_after_error_${round}`);
      await flush();
      // The slot came back: this lookup actually reached the network on attempt number
      // (round * 2 + 2), rather than queueing behind a slot nobody holds.
      expect(fetches.started).toBe(round * 2 + 2);
      fetches.settleNextMissing();
      expect(await after).toBeNull();
    }
  });

  it("returns the slot when discovery answers with an error status", async () => {
    const fetches = blockingFetch();
    const discovery = view({
      fetch: fetches.impl,
      maxConcurrentFetches: 1,
      maxQueuedFetches: 1,
      fetchQueueTimeoutMs: 50
    });

    const failing = discovery.getKeyState("pk_server_error");
    await flush();
    // A 500 is thrown from inside the slot, after the fetch resolved — a different path
    // through the `finally` than a rejected fetch.
    fetches.settleNext(Response.json({ error: "boom" }, { status: 500 }));
    await expect(failing).rejects.toThrow(/500/);

    const after = discovery.getKeyState("pk_after_server_error");
    await flush();
    expect(fetches.started).toBe(2);
    fetches.settleNextMissing();
    expect(await after).toBeNull();
  });

  it("caps the default queue, not just the default concurrency", async () => {
    const fetches = blockingFetch();
    const discovery = view({ fetch: fetches.impl });

    const capacity = DEFAULT_MAX_CONCURRENT_FETCHES + DEFAULT_MAX_QUEUED_FETCHES;
    const accepted = Array.from({ length: capacity }, (_unused, index) =>
      discovery.getKeyState(`pk_default_${index}`)
    );
    await flush();
    expect(fetches.started).toBe(DEFAULT_MAX_CONCURRENT_FETCHES);

    // One past 16 + 64 is where the default queue stops accepting.
    const overflow = await discovery
      .getKeyState("pk_default_overflow")
      .catch((error: unknown) => error);
    expect(overflow).toBeInstanceOf(VerifyCapacityError);
    expect((overflow as VerifyCapacityError).reason).toBe("discovery_fetch_capacity");

    while (fetches.inFlight > 0) {
      fetches.settleNextMissing();
      await flush();
    }
    expect(await Promise.all(accepted)).toHaveLength(capacity);
    expect(fetches.started).toBe(capacity);
  });
});

describe("a throttle bound that would not bound anything", () => {
  it("does not let Infinity delete the semaphore", async () => {
    const fetches = blockingFetch();
    // Nothing is ever `>= Infinity`, so this asked for a limiter with no limit — every lookup
    // would open its own socket, which is the fan-out the cap exists to stop.
    const discovery = view({ fetch: fetches.impl, maxConcurrentFetches: Number.POSITIVE_INFINITY });

    const lookups = Array.from({ length: 30 }, (_unused, index) =>
      discovery.getKeyState(`pk_infinite_${index}`)
    );
    await flush();
    expect(fetches.started).toBe(DEFAULT_MAX_CONCURRENT_FETCHES);

    while (fetches.inFlight > 0) {
      fetches.settleNextMissing();
      await flush();
    }
    expect(await Promise.all(lookups)).toHaveLength(30);
  });

  it("does not let Infinity leave the wait queue unbounded", async () => {
    const fetches = blockingFetch();
    const discovery = view({
      fetch: fetches.impl,
      maxConcurrentFetches: 1,
      maxQueuedFetches: Number.POSITIVE_INFINITY
    });

    // An unbounded queue turns the concurrency cap into a memory leak: the backlog becomes the
    // unbounded thing the cap was meant to prevent.
    const accepted = Array.from({ length: 1 + DEFAULT_MAX_QUEUED_FETCHES }, (_unused, index) =>
      discovery.getKeyState(`pk_queue_infinite_${index}`)
    );
    await flush();
    expect(fetches.started).toBe(1);

    const overflow = await discovery.getKeyState("pk_queue_overflow").catch((e: unknown) => e);
    expect(overflow).toBeInstanceOf(VerifyCapacityError);
    expect((overflow as VerifyCapacityError).reason).toBe("discovery_fetch_capacity");

    while (fetches.inFlight > 0) {
      fetches.settleNextMissing();
      await flush();
    }
    expect(await Promise.all(accepted)).toHaveLength(1 + DEFAULT_MAX_QUEUED_FETCHES);
  });

  it("floors zero at one rather than refusing every lookup forever", async () => {
    const fetches = blockingFetch();
    // Zero inverts the bound into a permanent refusal: no slot is ever available, so the verifier
    // answers 503 to everything it cannot serve from cache. One is the smallest bound that is
    // still a working throttle.
    const discovery = view({ fetch: fetches.impl, maxConcurrentFetches: 0, maxQueuedFetches: 0 });

    const first = discovery.getKeyState("pk_zero_first");
    await flush();
    expect(fetches.started).toBe(1);

    // And the floored queue is a queue of one, not of none.
    const queued = discovery.getKeyState("pk_zero_queued");
    await flush();
    expect(fetches.started).toBe(1);

    fetches.settleNextMissing();
    await flush();
    fetches.settleNextMissing();
    await flush();
    expect(await first).toBeNull();
    expect(await queued).toBeNull();
    expect(fetches.started).toBe(2);
  });

  it("truncates a fractional bound to a whole number of slots", async () => {
    const fetches = blockingFetch();
    // 2.9 slots is not a thing a counter can sit at; `>= 2.9` admits three, so the effective cap
    // silently differs from the number that was written down.
    const discovery = view({ fetch: fetches.impl, maxConcurrentFetches: 2.9 });

    const lookups = Array.from({ length: 6 }, (_unused, index) =>
      discovery.getKeyState(`pk_fractional_${index}`)
    );
    await flush();
    expect(fetches.started).toBe(2);
    expect(fetches.highWater).toBe(2);

    while (fetches.inFlight > 0) {
      fetches.settleNextMissing();
      await flush();
    }
    expect(await Promise.all(lookups)).toHaveLength(6);
    expect(fetches.highWater).toBe(2);
  });

  it("refuses a queued lookup once its deadline passes", async () => {
    const fetches = blockingFetch();
    const discovery = view({
      fetch: fetches.impl,
      maxConcurrentFetches: 1,
      fetchQueueTimeoutMs: 1
    });

    const blocker = discovery.getKeyState("pk_deadline_blocker");
    await flush();
    expect(fetches.started).toBe(1);

    // The slot is never released, so the ONLY way this settles is the deadline timer firing.
    // Awaiting the rejection is what makes the test non-vacuous: a deadline that never fires
    // hangs the test rather than passing it.
    await expect(discovery.getKeyState("pk_deadline_queued")).rejects.toMatchObject({
      name: "VerifyCapacityError",
      reason: "discovery_fetch_timeout"
    });

    fetches.settleNextMissing();
    expect(await blocker).toBeNull();
  });

  it("falls back to the default deadline when the configured one is not finite", async () => {
    // An Infinite deadline is a waiter that never gives up, holding memory for an answer whose
    // own client has long since walked away. There is no honest clamp for it, so the decided
    // default stands — and the fake clock is what lets this test SEE the default: still
    // waiting one tick before it, refused one tick after it.
    vi.useFakeTimers();
    try {
      const fetches = blockingFetch();
      const discovery = view({
        fetch: fetches.impl,
        maxConcurrentFetches: 1,
        fetchQueueTimeoutMs: Number.POSITIVE_INFINITY
      });

      void discovery.getKeyState("pk_default_deadline_blocker").catch(() => null);
      await vi.advanceTimersByTimeAsync(0);
      expect(fetches.started).toBe(1);

      let outcome: unknown = "pending";
      discovery.getKeyState("pk_default_deadline_queued").then(
        (value) => {
          outcome = value;
        },
        (error: unknown) => {
          outcome = error;
        }
      );

      await vi.advanceTimersByTimeAsync(DEFAULT_FETCH_QUEUE_TIMEOUT_MS - 1);
      expect(outcome).toBe("pending");
      await vi.advanceTimersByTimeAsync(2);
      expect(outcome).toMatchObject({
        name: "VerifyCapacityError",
        reason: "discovery_fetch_timeout"
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("caps a huge finite deadline at the one-minute ceiling", async () => {
    // Number-shaped deletions: 2_000_000_000 ms is a multi-week wait, which is `Infinity` with
    // better manners. The ceiling is 60s — W1's whole-request timeout, past which the inbound
    // request this lookup belongs to has already been severed.
    vi.useFakeTimers();
    try {
      const fetches = blockingFetch();
      const discovery = view({
        fetch: fetches.impl,
        maxConcurrentFetches: 1,
        fetchQueueTimeoutMs: 2_000_000_000
      });

      void discovery.getKeyState("pk_ceiling_deadline_blocker").catch(() => null);
      await vi.advanceTimersByTimeAsync(0);
      expect(fetches.started).toBe(1);

      let outcome: unknown = "pending";
      discovery.getKeyState("pk_ceiling_deadline_queued").then(
        (value) => {
          outcome = value;
        },
        (error: unknown) => {
          outcome = error;
        }
      );

      await vi.advanceTimersByTimeAsync(59_999);
      expect(outcome).toBe("pending");
      await vi.advanceTimersByTimeAsync(2);
      expect(outcome).toMatchObject({
        name: "VerifyCapacityError",
        reason: "discovery_fetch_timeout"
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("caps huge finite concurrency at the ceiling instead of deleting the semaphore", async () => {
    const fetches = blockingFetch();
    // `Number.MAX_VALUE` passes an `isFinite` gate while making `count >= bound` unreachable —
    // every line of the semaphore still runs and none of it binds. The ceiling (256, the scale
    // of W1's per-process connection bound) is what keeps "large" from meaning "gone".
    const discovery = view({
      fetch: fetches.impl,
      maxConcurrentFetches: Number.MAX_VALUE,
      fetchQueueTimeoutMs: 1_000_000
    });

    const lookups = Array.from({ length: 260 }, (_unused, index) =>
      discovery.getKeyState(`pk_huge_${index}`).catch(() => null)
    );
    await flush();
    expect(fetches.started).toBe(256);
    expect(fetches.highWater).toBe(256);

    while (fetches.inFlight > 0) {
      fetches.settleNextMissing();
      await flush(1);
    }
    await Promise.all(lookups);
    expect(fetches.highWater).toBe(256);
  });
});
