/**
 * Spec 003 key-log replay conformance vectors — the rejection suite.
 *
 * The fixture is the artifact: `packages/crypto/test/fixtures/key-log-rejection-vectors.json`
 * carries, for every vector, the log exactly as delivered, the spec-001 signing input and the
 * spec-003 digest of each event, the replay verdict, and — for a refusal — the normative
 * rejection class plus the reference implementation's exact throw. A second implementation can
 * check itself against those bytes without running this file.
 *
 * This suite exists because the external security review found the committed fixtures weaker
 * than they look: one 1-of-1 inception, no rotation, no threshold above one, and no rejection
 * vector, so "an independent implementation with broken rotation, threshold, chaining or
 * pre-rotation behaviour would still pass it".
 *
 * What this file checks:
 *
 *  1. **The fixture tells the truth** — every recorded byte-level fact (signing inputs, event
 *     digests, the `prior` chain, schema acceptance) is recomputed here from the events.
 *  2. **Every vector replays to its recorded verdict**, with the recorded state or the recorded
 *     error, message included.
 *  3. **The rejection CLASS is asserted, not just the fact of a throw.** A budget refusal and a
 *     substituted log are distinct error types and must never read as "this log is invalid";
 *     every rule rejection must be neither of those. Asserting only "it threw" would let one
 *     over-eager check stand in for eleven.
 *  4. **The suite is not vacuous** — both verdicts present, every documented code exercised.
 */
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import { keyEventLogSchema, type KeyEvent, type ParticipantId } from "@kinnet/protocol";

import {
  canonicalBytes,
  canonicalDigest,
  KeyLogParticipantMismatch,
  KeyLogWorkBudgetExceeded,
  replayKeyLog,
  replayKeyLogFor,
  type KeyState
} from "../src/index.js";

type Vector = {
  name: string;
  why: string;
  valid: boolean;
  expectedId?: ParticipantId;
  options?: { maxSignatureVerifications?: number };
  events: KeyEvent[];
  signingInputs: string[];
  digests: string[];
  schemaValid: boolean;
  state: KeyState | null;
  rejection: string | null;
  error: { name: string; message: string } | null;
};

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/key-log-rejection-vectors.json", import.meta.url), "utf8")
) as { note: string; codes: Record<string, string>; vectors: Vector[] };

const vectors = fixture.vectors;

/** The spec-001 signing input's shape: the event with its `signature` field removed. */
const stripSignature = (event: KeyEvent): Record<string, unknown> => {
  const unsigned: Record<string, unknown> = { ...event };
  delete unsigned.signature;
  return unsigned;
};

/** Replays a vector exactly as the fixture says it should be judged. */
const replay = (vector: Vector): KeyState =>
  vector.expectedId === undefined
    ? replayKeyLog(vector.events, vector.options ?? {})
    : replayKeyLogFor(vector.expectedId, vector.events, vector.options ?? {});

describe("spec 003 key-log conformance vectors", () => {
  it("is not vacuous: distinct names, both verdicts, and a rejection-heavy suite", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(12);
    expect(new Set(vectors.map((vector) => vector.name)).size).toBe(vectors.length);
    expect(vectors.some((vector) => vector.valid)).toBe(true);
    // The review's complaint was specifically that rejection coverage was thin, so the balance
    // is part of what this suite promises.
    expect(vectors.filter((vector) => !vector.valid).length).toBeGreaterThanOrEqual(9);
    for (const vector of vectors) {
      expect(vector.why.length).toBeGreaterThan(40);
    }
  });

  it("exercises every documented rejection class, and documents every class it uses", () => {
    const documented = new Set(Object.keys(fixture.codes));
    const used = new Set(
      vectors.map((vector) => vector.rejection).filter((code): code is string => code !== null)
    );
    expect([...used].sort()).toEqual([...documented].sort());
    for (const description of Object.values(fixture.codes)) {
      expect(description.length).toBeGreaterThan(40);
    }
  });

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "%s — the recorded bytes are the log's own",
    (_name, vector) => {
      expect(vector.events.length).toBe(vector.signingInputs.length);
      expect(vector.events.length).toBe(vector.digests.length);

      vector.events.forEach((event, index) => {
        // The signing input is spec 001's: JCS of the event WITHOUT its signature field.
        expect(new TextDecoder().decode(canonicalBytes(stripSignature(event)))).toBe(
          vector.signingInputs[index]
        );
        // The digest is spec 003's: over the COMPLETE event, signature array included.
        expect(canonicalDigest(event)).toBe(vector.digests[index]);
      });

      // Schema acceptance is a separate gate from replay, and the fixture records which.
      expect(keyEventLogSchema.safeParse(vector.events).success).toBe(vector.schemaValid);
    }
  );

  it.each(vectors.filter((vector) => vector.valid).map((v) => [v.name, v] as const))(
    "%s — replays to the recorded key state",
    (_name, vector) => {
      expect(replay(vector)).toEqual(vector.state);
      expect(vector.rejection).toBeNull();
      expect(vector.error).toBeNull();
    }
  );

  it.each(vectors.filter((vector) => !vector.valid).map((v) => [v.name, v] as const))(
    "%s — is refused, with the recorded error and the recorded class",
    (_name, vector) => {
      expect(vector.state).toBeNull();
      const error = vector.error;
      if (error === null) {
        throw new Error("A rejected vector must record the error it expects");
      }

      let thrown: unknown;
      try {
        replay(vector);
        throw new Error("Replay accepted a log the fixture records as rejected");
      } catch (caught) {
        thrown = caught;
      }

      expect(thrown).toBeInstanceOf(Error);
      const actual = thrown as Error;
      expect(actual.name).toBe(error.name);
      expect(actual.message).toBe(error.message);

      // The class, asserted per rejection code. The two non-verdict refusals have their own
      // error types precisely so a caller can tell them apart from "this log is invalid", and
      // every rule rejection must be NEITHER — otherwise a budget that fired too early would
      // pass for a rule that never ran.
      switch (vector.rejection) {
        case "work_budget_exceeded":
          expect(actual).toBeInstanceOf(KeyLogWorkBudgetExceeded);
          break;
        case "participant_mismatch":
          expect(actual).toBeInstanceOf(KeyLogParticipantMismatch);
          // A substituted log is not a cost condition: a caller that retries budget failures
          // must not retry this one forever.
          expect(actual).not.toBeInstanceOf(KeyLogWorkBudgetExceeded);
          break;
        default:
          expect(actual).not.toBeInstanceOf(KeyLogWorkBudgetExceeded);
          expect(actual).not.toBeInstanceOf(KeyLogParticipantMismatch);
          break;
      }
    }
  );

  it("chains every accepted log: each event's `prior` is the previous event's digest", () => {
    for (const vector of vectors.filter((entry) => entry.valid)) {
      expect(vector.events[0]!.prior).toBeNull();
      vector.events.slice(1).forEach((event, index) => {
        expect(event.prior).toBe(vector.digests[index]);
      });
    }
  });

  /**
   * The finding-4 pair, side by side: one honest rotation and one hijack, differing ONLY in the
   * threshold the rotation declares. The key lists are byte-identical, which is the whole point
   * — a commitment over the key list alone would accept both.
   */
  it("rejects the same committed keys revealed at two thresholds", () => {
    const honest = vectors.find(
      (vector) => vector.name === "accepted — rotation revealing a committed 2-of-2 committee"
    );
    const hijack = vectors.find(
      (vector) =>
        vector.name === "rejected — the committed committee revealed at a LOWERED threshold"
    );
    if (!honest || !hijack) {
      throw new Error("The finding-4 pair is missing from the fixture");
    }

    const honestRotation = honest.events[1]!;
    const hijackRotation = hijack.events[1]!;

    // Same identity, same inception, same revealed keys — the commitment's key half matches.
    expect(hijack.events[0]).toEqual(honest.events[0]);
    expect(hijackRotation.keys).toEqual(honestRotation.keys);
    expect(hijackRotation.prior).toBe(honestRotation.prior);

    // Only the declared threshold, and therefore the signature count, differ.
    expect(honestRotation.threshold).toBe("2");
    expect(hijackRotation.threshold).toBe("1");
    expect(honestRotation.signature.length).toBe(2);
    expect(hijackRotation.signature.length).toBe(1);

    // And the hijack is refused on the COMMITMENT, before any signature is verified: the prior
    // event's `next` covers {keys, threshold}, so the rotation cannot restate its own threshold.
    expect(hijack.rejection).toBe("commitment_not_reproduced");
    expect(hijack.error?.message).toContain("does not reveal the pre-committed next key state");
  });
});
