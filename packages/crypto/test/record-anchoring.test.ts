/**
 * Spec 016 — record anchoring: a signature-set record names the ONE key state it is judged
 * against, and no other state is tried.
 *
 * The fixture is the artifact: `packages/crypto/test/fixtures/record-anchoring-vectors.json`
 * carries, for every vector, the issuer's key log, the digest of each of its events, the record
 * exactly as delivered, its spec-001 signing input, its spec-003 digest, the state the anchor
 * resolves to, and the verdict. A second implementation can check itself against those bytes
 * without running this file.
 *
 * What this file checks:
 *
 *  1. **The fixture tells the truth** — the recorded event digests, signing inputs, record
 *     digests and schema verdicts are all recomputed here from the bytes.
 *  2. **Every log replays valid.** Spec 016's rule has three clauses and the first is that the
 *     issuer's log is valid; it also matters that the logs an earlier interim rule refused for
 *     sharing a quorum now replay, because that is the flexibility 016 buys back.
 *  3. **Every vector reaches its recorded verdict, with its recorded rejection class** — a
 *     suite whose refusals were all one generic code could not show that the anchor lookup and
 *     the S0–S3 check are separately enforced.
 *  4. **Exactly one state is tried**, asserted directly rather than inferred: for each refused
 *     vector whose set would satisfy SOME state of the log, that state is found here and the
 *     anchored verdict is still a refusal.
 *  5. **The suite is not vacuous** — both verdicts, every documented code exercised, both
 *     record shapes present.
 */
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import { grantSchema, keyEventLogSchema, revocationSchema, type KeyEvent } from "@kinnet/protocol";

import {
  canonicalBytes,
  canonicalDigest,
  checkAnchoredSignatureSet,
  checkSignatureSet,
  eventDigest,
  findAnchoredKeyState,
  replayKeyLogStates,
  verifyAnchoredRecord
} from "../src/index.js";

type Vector = {
  name: string;
  why: string;
  schema: "revocation" | "grant";
  events: KeyEvent[];
  anchors: string[];
  foreignEvents?: KeyEvent[];
  record: Record<string, unknown> & { anchor: string; signature: string[] };
  signingInput: string;
  digest: string;
  schemaValid: boolean;
  anchoredState: { keys: string[]; threshold: string; seq: string } | null;
  valid: boolean;
  rejection: string | null;
};

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/record-anchoring-vectors.json", import.meta.url), "utf8")
) as { note: string; codes: Record<string, string>; vectors: Vector[] };

const vectors = fixture.vectors;

const schemaFor = (name: Vector["schema"]) =>
  name === "revocation" ? revocationSchema : grantSchema;

/** The spec-001 signing input's shape: the record with its `signature` field removed. */
const stripSignature = (record: Record<string, unknown>): Record<string, unknown> => {
  const unsigned: Record<string, unknown> = { ...record };
  delete unsigned["signature"];
  return unsigned;
};

describe("spec 016 record-anchoring conformance vectors", () => {
  it("is not vacuous: distinct names, both verdicts, both record shapes", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(15);
    expect(new Set(vectors.map((vector) => vector.name)).size).toBe(vectors.length);
    expect(vectors.some((vector) => vector.valid)).toBe(true);
    expect(vectors.filter((vector) => !vector.valid).length).toBeGreaterThanOrEqual(8);
    expect(new Set(vectors.map((vector) => vector.schema))).toEqual(
      new Set(["revocation", "grant"])
    );
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
    "%s — the recorded bytes are the record's and the log's own",
    (_name, vector) => {
      // The anchors are the spec-003 digests of the complete events — the same values the
      // NEXT event's `prior` carries, which is what makes an anchor and a chain link one
      // primitive rather than two.
      expect(vector.anchors).toEqual(vector.events.map((event) => eventDigest(event)));
      vector.events.slice(1).forEach((event, index) => {
        expect(event.prior).toBe(vector.anchors[index]);
      });

      // `anchor` is an ordinary field of the record, so it sits inside the signed bytes.
      expect(new TextDecoder().decode(canonicalBytes(stripSignature(vector.record)))).toBe(
        vector.signingInput
      );
      expect(vector.signingInput).toContain(`"anchor":"${vector.record.anchor}"`);
      expect(canonicalDigest(vector.record)).toBe(vector.digest);

      expect(schemaFor(vector.schema).safeParse(vector.record).success).toBe(vector.schemaValid);
    }
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "%s — the issuer's log replays valid and resolves the recorded state",
    (_name, vector) => {
      expect(keyEventLogSchema.safeParse(vector.events).success).toBe(true);
      const { states } = replayKeyLogStates(vector.events);
      expect(states.map((state) => state.anchor)).toEqual(vector.anchors);

      const anchored = findAnchoredKeyState(states, vector.record.anchor);
      if (vector.anchoredState === null) {
        expect(anchored).toBeUndefined();
      } else {
        expect(anchored).toBeDefined();
        expect({
          keys: anchored!.keys,
          threshold: anchored!.threshold,
          seq: anchored!.seq
        }).toEqual(vector.anchoredState);
      }
    }
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "%s — reaches the recorded verdict against the anchored state",
    (_name, vector) => {
      const { states } = replayKeyLogStates(vector.events);
      const verdict = checkAnchoredSignatureSet(vector.record, states, { explain: true });
      expect(verdict.ok).toBe(vector.valid);
      expect(verifyAnchoredRecord(vector.record, states)).toBe(vector.valid);
      if (!verdict.ok) {
        expect(verdict.code).toBe(vector.rejection);
      } else {
        expect(vector.rejection).toBeNull();
      }
    }
  );

  it("tries exactly one state: a refused record stays refused even where another state accepts", () => {
    // The heart of 016. For every refused vector, look for a state of the SAME log that the
    // record's set would satisfy — that is precisely what 015 S5's existential would have
    // returned — and assert the anchored rule refuses it anyway. At least one vector must
    // actually have such a state, or this assertion would be vacuous.
    let elsewhereAccepted = 0;
    for (const vector of vectors.filter((entry) => !entry.valid)) {
      const { states } = replayKeyLogStates(vector.events);
      const accepting = states.filter(
        (state) => checkSignatureSet(vector.record, state.keys, state.threshold).ok
      );
      if (accepting.length > 0) {
        elsewhereAccepted += 1;
        // Some state of this very log accepts the set…
        expect(accepting.every((state) => state.anchor !== vector.record.anchor)).toBe(true);
        // …and the anchored rule refuses the record regardless.
        expect(verifyAnchoredRecord(vector.record, states)).toBe(false);
      }
    }
    expect(elsewhereAccepted).toBeGreaterThan(0);
  });

  it("refuses an anchor that names a genuine event of another participant's log", () => {
    // An anchor selects a state WITHIN the log the record's issuer resolves to; it never
    // carries a log with it. A verifier resolving anchors globally would let anyone graft a
    // state they control onto someone else's record.
    const vector = vectors.find((entry) => entry.foreignEvents !== undefined);
    expect(vector).toBeDefined();
    const foreign = replayKeyLogStates(vector!.foreignEvents!);
    // The anchor is real — it names an event of that other log…
    expect(findAnchoredKeyState(foreign.states, vector!.record.anchor)).toBeDefined();
    // …and unknown to the issuer's own log, which is the only one that may answer.
    const { states } = replayKeyLogStates(vector!.events);
    expect(findAnchoredKeyState(states, vector!.record.anchor)).toBeUndefined();
    expect(vector!.rejection).toBe("anchor_unknown");
    expect(foreign.current.id).not.toBe(states[0]!.id);
  });

  it("does not orphan a record when its issuer rotates", () => {
    // 012 forbids verifying against the CURRENT state, because that invalidates every record
    // its issuer has ever signed on each rotation. An anchor names a historical state instead,
    // and an append-only log keeps that event forever.
    const vector = vectors.find((entry) => entry.name.startsWith("non-tip anchor"));
    expect(vector).toBeDefined();
    const { current, states } = replayKeyLogStates(vector!.events);
    expect(current.anchor).not.toBe(vector!.record.anchor);
    expect(current.seq).toBe("2");
    expect(vector!.anchoredState?.seq).toBe("1");
    expect(verifyAnchoredRecord(vector!.record, states)).toBe(true);
  });

  it("charges no verification for an anchor that resolves to nothing", () => {
    // Reported before any curve work: with no state there is nothing to verify, so a caller
    // carrying one allowance across many records must not be charged for a lookup miss.
    const vector = vectors.find((entry) => entry.rejection === "anchor_unknown");
    expect(vector).toBeDefined();
    const { states } = replayKeyLogStates(vector!.events);
    let spent = -1;
    const verdict = checkAnchoredSignatureSet(vector!.record, states, {
      onSignatureVerifications: (count) => (spent = count)
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.ok ? null : verdict.code).toBe("anchor_unknown");
    // The callback belongs to `checkSignatureSet`, which is never reached.
    expect(spent).toBe(-1);
  });
});
