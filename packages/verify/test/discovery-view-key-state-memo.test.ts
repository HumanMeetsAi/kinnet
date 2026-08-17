/**
 * The discovery view's memo of RESOLVED key state.
 *
 * The lookup cache removes the fetch and none of the CPU: before this memo, `getKeyState`
 * replayed the fetched log — every Ed25519 signature in it — on every call, so one request
 * resolving the same participant twice paid twice and a 15 s stream re-check paid again every
 * tick against a log nothing had changed.
 *
 * HOW COST IS COUNTED HERE. Every assertion reads `budget.remaining`, which
 * `replayKeyLogFor`'s `onSignatureVerifications` hook decrements by the exact number of
 * Ed25519 verifications the replay performed. That is instrumentation of the primitive's own
 * counter, not timing, and it is the same instrument a node surface's re-check budget tests use.
 * A delta of zero therefore means zero curve operations, not "fast".
 *
 * Every test below was watched to FAIL before it was trusted — against the pre-change code
 * where the memo does not exist, or with the mutation named in its own comment applied to the
 * memo. The four cases for this memo — a hit costs zero, changed bytes miss, a rejected log is
 * never memoized, a hit never stretches a budget — plus the participant-binding case the key-log
 * binding change established and this memo must not weaken.
 */
import {
  createIdentity,
  rotateIdentity,
  VerificationBudgetExceeded,
  type Identity
} from "@kinnet/crypto";
import { MAX_KEY_LOG_EVENTS, type KeyEvent } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  createDiscoveryView,
  DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS
} from "../src/discovery-view.js";

const DISCOVERY_URL = "https://discovery.example.com";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

/** An identity whose log has `events` events. Every event is 1-of-1, so replay costs one
 * verification per event — which is what lets a spend be compared against `log.length` rather
 * than against a number written into this file. */
function grown(events: number, currentFill: number, nextFill: number): Identity {
  expect(events).toBeLessThanOrEqual(MAX_KEY_LOG_EVENTS);
  let identity = createIdentity({ currentSeed: seed(currentFill), nextSeed: seed(nextFill) });
  while (identity.log.length < events) {
    identity = rotateIdentity(identity);
  }
  return identity;
}

/**
 * A discovery host whose served key log can be changed mid-test, counting every request.
 *
 * The counter matters as much as the logs: a memo that only looked fast because the BYTES were
 * cached would prove nothing about replay cost, so the tests that assert a zero spend also
 * assert that the bytes were re-fetched.
 */
function host(initial: Record<string, KeyEvent[]> = {}) {
  const logs = new Map<string, KeyEvent[]>(Object.entries(initial));
  const paths: string[] = [];
  const impl: typeof fetch = async (input) => {
    const url = new URL(
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url
    );
    paths.push(url.pathname);
    const match = /^\/participants\/([^/]+)\/key-log$/.exec(url.pathname);
    const log = match ? logs.get(decodeURIComponent(match[1]!)) : undefined;
    return log
      ? Response.json({ events: log })
      : Response.json({ error: "key_log_not_found" }, { status: 404 });
  };
  return {
    impl,
    paths,
    serve(id: string, log: KeyEvent[]): void {
      logs.set(id, log);
    }
  };
}

/**
 * A view that re-fetches on every lookup. The memo is the only thing that can remove replay
 * cost here, so nothing below can pass on the strength of the byte cache.
 */
function refetchingView(impl: typeof fetch) {
  return createDiscoveryView({ discoveryUrl: DISCOVERY_URL, fetch: impl, cacheTtlSeconds: 0 });
}

const budget = (remaining = DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS) => ({ remaining });

describe("a memo hit performs zero signature verifications", () => {
  it("replays once for two lookups of an unchanged log, re-fetching both times", async () => {
    // WATCHED TO FAIL against the pre-change code, where the second call replays the log again
    // and spends `log.length` a second time.
    const identity = grown(6, 1, 2);
    const discovery = host({ [identity.id]: identity.log });
    const view = refetchingView(discovery.impl);
    const spending = budget();

    const before = spending.remaining;
    const first = await view.getKeyState(identity.id, spending);
    const firstSpend = before - spending.remaining;

    // One verification per event: the honest 1-of-1 cost of this log, derived from the fixture.
    expect(first?.id).toBe(identity.id);
    expect(firstSpend).toBe(identity.log.length);

    const afterFirst = spending.remaining;
    const second = await view.getKeyState(identity.id, spending);

    // ZERO. Not "fewer" — the budget is the verification counter, and it did not move.
    expect(spending.remaining).toBe(afterFirst);
    expect(second).toEqual(first);
    // And the bytes DID come off the wire again, so the byte cache is not what saved the work.
    expect(discovery.paths).toHaveLength(2);
  });

  it("keeps costing nothing across a long run of re-checks", async () => {
    // The SSE shape: a stream re-checking every 15 s used to pay a full replay per tick,
    // forever. WATCHED TO FAIL against the pre-change code, which spends `log.length` per tick.
    const identity = grown(8, 3, 4);
    const discovery = host({ [identity.id]: identity.log });
    const view = refetchingView(discovery.impl);
    const spending = budget();

    await view.getKeyState(identity.id, spending);
    const afterFirstTick = spending.remaining;
    for (let tick = 0; tick < 20; tick += 1) {
      await view.getKeyState(identity.id, spending);
    }

    expect(spending.remaining).toBe(afterFirstTick);
    expect(discovery.paths).toHaveLength(21);
  });

  it("memoizes for a caller carrying no budget at all", async () => {
    // The client-side contract (`@kinnet/a2a`, a client SDK) passes no budget, so there is no
    // counter to read. The instrument here is object IDENTITY: a replay constructs a fresh
    // `KeyState`, and only a memo can hand back the one it is holding. WATCHED TO FAIL against
    // the pre-change code, which returns a newly built state every time; also fails under the
    // mutation "read the memo only when a budget was passed". It pins the SHARED-INSTANCE design
    // deliberately — every caller of a hit holds the one object this map is holding — so a
    // maintainer who moves to a clone per call (equally safe, and it costs a copy) should DELETE
    // this assertion rather than repair it; there is nothing else here to preserve.
    const identity = grown(5, 5, 6);
    const discovery = host({ [identity.id]: identity.log });
    const view = refetchingView(discovery.impl);

    const first = await view.getKeyState(identity.id);
    const second = await view.getKeyState(identity.id);
    expect(second).toBe(first);
    expect(second?.id).toBe(identity.id);
  });
});

describe("changed bytes are never answered from the memo", () => {
  it("returns the NEW key state after the participant publishes a rotation", async () => {
    // WATCHED TO FAIL with the mutation "drop the digest comparison from the hit condition
    // (`if (memo)`), keying the memo by participant id alone" — under which this returns the
    // pre-rotation keys, i.e. a rotated-out key still resolving as current.
    const before = grown(3, 7, 8);
    const after = rotateIdentity(before);
    const discovery = host({ [before.id]: before.log });
    const view = refetchingView(discovery.impl);

    const first = await view.getKeyState(before.id);
    expect(first?.keys).toEqual(before.log.at(-1)?.keys);

    discovery.serve(before.id, after.log);
    const second = await view.getKeyState(before.id);

    // Asserted on the CONTENT of the returned state, not on a counter: the keys are the ones
    // the newest event establishes, and they are not the ones the memo was holding.
    expect(second?.keys).toEqual(after.log.at(-1)?.keys);
    expect(second?.keys).not.toEqual(first?.keys);
    expect(second?.seq).toBe(String(after.log.length - 1));
    expect(second?.id).toBe(before.id);
  });

  it("charges the full replay for the changed log", async () => {
    // The corollary of the above, and what makes a log-rotating attacker gain nothing: their
    // every lookup is a miss and pays in full. Same mutation as above.
    const before = grown(4, 9, 10);
    const after = rotateIdentity(before);
    const discovery = host({ [before.id]: before.log });
    const view = refetchingView(discovery.impl);
    const spending = budget();

    await view.getKeyState(before.id, spending);
    const afterFirst = spending.remaining;
    await view.getKeyState(before.id, spending);
    expect(spending.remaining).toBe(afterFirst); // unchanged bytes: a hit

    discovery.serve(before.id, after.log);
    await view.getKeyState(before.id, spending);
    expect(afterFirst - spending.remaining).toBe(after.log.length);
  });
});

describe("a rejected log is never memoized", () => {
  /** A schema-valid log whose last event carries another event's signature, so replay rejects
   * it on the signature check rather than on its shape. */
  function forged(identity: Identity): KeyEvent[] {
    const log = identity.log.map((event) => ({ ...event }));
    const last = log.at(-1)!;
    last.signature = log[0]!.signature;
    return log;
  }

  it("fails identically on a later identical call, having remembered nothing", async () => {
    // WATCHED TO FAIL with the mutation "memoize the OUTCOME rather than the state — record a
    // `null` for a log that threw and answer it on a hit" — under which the second call spends
    // zero and this file's central claim (a miss is slower, never different) stops holding.
    const identity = grown(4, 11, 12);
    const discovery = host({ [identity.id]: forged(identity) });
    const view = refetchingView(discovery.impl);
    const spending = budget();

    const before = spending.remaining;
    expect(await view.getKeyState(identity.id, spending)).toBeNull();
    const firstSpend = before - spending.remaining;
    expect(firstSpend).toBeGreaterThan(0);

    const afterFirst = spending.remaining;
    expect(await view.getKeyState(identity.id, spending)).toBeNull();
    expect(afterFirst - spending.remaining).toBe(firstSpend);
  });

  it("gives a real answer to a caller who comes back with a larger allowance", async () => {
    // A cost refusal is the case that would hurt most if it were remembered: the log is fine,
    // the caller simply ran short. Same mutation as above — a memoized `null` would make the
    // funded retry return "no key state" for a log this process can replay perfectly well.
    const identity = grown(6, 13, 14);
    const discovery = host({ [identity.id]: identity.log });
    const view = refetchingView(discovery.impl);

    const starved = { remaining: 1 };
    await expect(view.getKeyState(identity.id, starved)).rejects.toBeInstanceOf(
      VerificationBudgetExceeded
    );

    const funded = budget();
    const before = funded.remaining;
    const state = await view.getKeyState(identity.id, funded);
    expect(state?.id).toBe(identity.id);
    // Charged in full: the exhausted attempt left nothing behind to reuse.
    expect(before - funded.remaining).toBe(identity.log.length);
  });

  it("drops the entry it held when a later log for the same id is rejected", async () => {
    // A good log, memoized; then the host serves a forged one. The stale entry must not stay
    // resident and answer once the host goes back to serving anything at all. Mutation that
    // fails this: keeping the previous entry across a failed replay instead of deleting it
    // before replaying.
    const identity = grown(4, 15, 16);
    const discovery = host({ [identity.id]: identity.log });
    const view = refetchingView(discovery.impl);
    const spending = budget();

    expect((await view.getKeyState(identity.id, spending))?.id).toBe(identity.id);

    discovery.serve(identity.id, forged(identity));
    expect(await view.getKeyState(identity.id, spending)).toBeNull();

    // Back to the genuine log: it must be REPLAYED, not answered from an entry that survived
    // the rejection.
    discovery.serve(identity.id, identity.log);
    const before = spending.remaining;
    expect((await view.getKeyState(identity.id, spending))?.id).toBe(identity.id);
    expect(before - spending.remaining).toBe(identity.log.length);
  });
});

describe("the memo does not launder the budget", () => {
  it("charges every alternation in full and never gives allowance back", async () => {
    // The hostile shape: one id, two valid logs, alternated so that no lookup can be answered
    // from the memo. WATCHED TO FAIL under two mutations, each named because they fail
    // different assertions here:
    //   (a) "credit a hit back to the budget (`budget.remaining += spent`)" — caught by the
    //       never-increases assertion;
    //   (b) "key the memo by participant id alone, ignoring the digest" — caught by the
    //       per-call spend assertions, which would see zeroes where a full replay is owed
    //       (and by the state content, which would be the other log's).
    const first = grown(4, 17, 18);
    const second = rotateIdentity(first);
    const discovery = host({ [first.id]: first.log });
    const view = refetchingView(discovery.impl);
    const spending = budget();

    const sequence: { log: KeyEvent[]; expectedSpend: number }[] = [
      { log: first.log, expectedSpend: first.log.length },
      { log: first.log, expectedSpend: 0 }, // repeat: a hit, and hits are free
      { log: second.log, expectedSpend: second.log.length },
      { log: first.log, expectedSpend: first.log.length },
      { log: second.log, expectedSpend: second.log.length },
      { log: second.log, expectedSpend: 0 }
    ];

    let owed = 0;
    for (const step of sequence) {
      discovery.serve(first.id, step.log);
      const before = spending.remaining;
      const state = await view.getKeyState(first.id, spending);

      // A hit never INCREASES the remaining allowance. This is the laundering assertion: an
      // allowance that can go up is an allowance a caller can farm.
      expect(spending.remaining).toBeLessThanOrEqual(before);
      expect(before - spending.remaining).toBe(step.expectedSpend);
      // And the answer is always the log being served, hit or miss.
      expect(state?.keys).toEqual(step.log.at(-1)?.keys);
      owed += step.expectedSpend;
    }

    // The total is the sum of the MISSES and nothing else: no hit added to it, and no hit
    // subtracted from it either.
    expect(DEFAULT_VERIFY_MAX_SIGNATURE_VERIFICATIONS - spending.remaining).toBe(owed);
    expect(owed).toBe(first.log.length * 2 + second.log.length * 2);
  });

  it("cannot be used to finish a run the budget could not afford", async () => {
    // Sized so the alternating run costs more than the allowance: if hits could be made to pay
    // for misses, this would complete. It must run out instead. WATCHED TO FAIL with the
    // mutation "key the memo by participant id alone, ignoring the digest", under which the
    // second alternation is answered free from the first log's state and the allowance survives.
    const first = grown(4, 19, 20);
    const second = rotateIdentity(first);
    const affordable = first.log.length + second.log.length;
    const spending = { remaining: affordable };
    const discovery = host({ [first.id]: first.log });
    const view = refetchingView(discovery.impl);

    await view.getKeyState(first.id, spending);
    discovery.serve(first.id, second.log);
    await view.getKeyState(first.id, spending);
    expect(spending.remaining).toBe(0);

    // The third alternation has nothing left to spend, and the memo cannot cover it: the log
    // it would need is not the one memoized.
    discovery.serve(first.id, first.log);
    await expect(view.getKeyState(first.id, spending)).rejects.toBeInstanceOf(
      VerificationBudgetExceeded
    );
  });
});

describe("a memo hit is bound to the participant it was asked about", () => {
  const attacker = grown(3, 21, 22);
  const victim = grown(3, 23, 24);

  /** A hostile host: every key-log path answers with the attacker's own genuine log. */
  function substitutingFetch(): typeof fetch {
    return async (input) => {
      const url = new URL(
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url
      );
      return url.pathname.endsWith("/key-log")
        ? Response.json({ events: attacker.log })
        : Response.json({ error: "not_found" }, { status: 404 });
    };
  }

  it("never answers one participant's lookup from another's memoized state", async () => {
    // The key-log participant binding, re-pinned against the memo. WATCHED TO FAIL with the
    // mutation "key the
    // memo by the log digest alone, dropping the participant id from the key" — under which
    // the victim's lookup hits the attacker's entry and the attacker's keys become current for
    // the victim, which is complete impersonation and needs none of the victim's keys.
    const view = refetchingView(substitutingFetch());

    // Warm the memo with the attacker's own, impeccable log at its own id.
    const genuine = await view.getKeyState(attacker.id);
    expect(genuine?.id).toBe(attacker.id);

    // The identical BYTES served at the victim's id resolve to nothing, memo or no memo.
    expect(await view.getKeyState(victim.id)).toBeNull();
    // And asking again does not turn the refusal into an answer.
    expect(await view.getKeyState(victim.id)).toBeNull();

    // A hit still carries the id its caller asked about, so a `boundKeyState`-style comparison
    // at the call site passes on the hit path exactly as it does on the miss path.
    const hit = await view.getKeyState(attacker.id);
    expect(hit?.id).toBe(attacker.id);
    expect(hit).toEqual(genuine);
  });

  it("does not let the substituted lookup spend from the memo's own participant", async () => {
    // The mismatch is not a cost condition and must not be answered from a state resolved for
    // somebody else: the victim's lookup pays a full replay and still gets `null`.
    const view = refetchingView(substitutingFetch());
    const spending = budget();

    await view.getKeyState(attacker.id, spending);
    const afterAttacker = spending.remaining;

    expect(await view.getKeyState(victim.id, spending)).toBeNull();
    expect(afterAttacker - spending.remaining).toBe(attacker.log.length);
  });
});
