/**
 * Spec 015 S0–S3 and spec 003's quorum rule, rule by rule.
 *
 * `signature-sets.test.ts` checks the committed conformance vectors — the artifact a third
 * party verifies from bytes alone. This file is the enforcement battery: for each rule it
 * constructs an input that violates THAT rule and asserts the specific code the
 * implementation reports, so a green suite cannot come from a check that never ran.
 *
 * Every `code` asserted below is distinct per rule. That is deliberate and it is what makes
 * the battery diagnostic: a battery whose rejections are all one generic "invalid signature
 * set" cannot distinguish a real result from a no-op.
 *
 * WHERE ISOLATION IS IMPOSSIBLE, THIS FILE SAYS SO rather than letting a passing test imply
 * coverage it does not have — see `threshold_exceeds_key_count` below, whose violation cannot
 * be constructed without also violating `m = t`, because a threshold above the key count is
 * unsatisfiable by construction.
 */
import { describe, expect, it } from "vitest";

import {
  canonicalBytes,
  canonicalDigest,
  checkSignatureSet,
  commitToKeyState,
  createIdentity,
  deriveParticipantId,
  encodeKeyRef,
  encodeSignature,
  eventDigest,
  generateKeyPair,
  quorumViolation,
  replayKeyLog,
  rotateIdentity,
  sign,
  verifyThresholdRecord,
  type KeyPair
} from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);
const keyPairs = (count: number, from: number): KeyPair[] =>
  Array.from({ length: count }, (_unused, index) => generateKeyPair(seed(from + index)));

/** The record every vector in this file signs; content is irrelevant to S0–S3. */
const RECORD = { scope: "strict-signature-sets", issuedAt: "2026-06-12T00:00:00.000Z" };

const signOver = (key: KeyPair, value: Record<string, unknown> = RECORD): string =>
  encodeSignature(sign(canonicalBytes(value), key.secretKey));

/** A well-formed signature by a real key over DIFFERENT bytes: verifies under nothing. */
const junk = (key: KeyPair): string => signOver(key, { ...RECORD, tampered: true });

const setOf = (signature: string[]) => ({ ...RECORD, signature });

const codeOf = (keys: string[], threshold: string, signature: string[]): string | "accepted" => {
  const verdict = checkSignatureSet(setOf(signature), keys, threshold, { explain: true });
  return verdict.ok ? "accepted" : verdict.code;
};

describe("spec 015 S0 — the key state must be well-formed", () => {
  it("refuses a state that lists the same key twice, and names the rule", () => {
    const [alpha, beta] = keyPairs(2, 10) as [KeyPair, KeyPair];
    const a = encodeKeyRef(alpha.publicKey);
    const b = encodeKeyRef(beta.publicKey);

    // Violates S0 ONLY. t = 2 <= n = 3, m = t = 2, and the two members verify under distinct
    // key VALUES in increasing index order — the greedy walk assigns member 0 to position 0
    // and member 1 to position 2, so S1, S2 and S3 all hold. The rule 015 replaces accepted
    // this: it counted two distinct satisfied keys against a threshold of two.
    expect(codeOf([a, a, b], "2", [signOver(alpha), signOver(beta)])).toBe("state_repeats_key");
  });

  it("refuses a repeated key at threshold 1, where the old rule accepted outright", () => {
    const alpha = keyPairs(1, 20)[0]!;
    const a = encodeKeyRef(alpha.publicKey);
    expect(codeOf([a, a], "1", [signOver(alpha)])).toBe("state_repeats_key");
  });

  it("compares key VALUE, not list position — raw bytes and KeyRef are the same key", () => {
    const alpha = keyPairs(1, 30)[0]!;
    const verdict = checkSignatureSet(
      setOf([signOver(alpha)]),
      [encodeKeyRef(alpha.publicKey), alpha.publicKey],
      "1"
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.ok ? null : verdict.code).toBe("state_repeats_key");
  });
});

describe("spec 015 S1 — threshold domain and the exact member count", () => {
  const [alpha, beta, gamma] = keyPairs(3, 40) as [KeyPair, KeyPair, KeyPair];
  const keys = [alpha, beta, gamma].map((key) => encodeKeyRef(key.publicKey));

  it.each([
    ["0", "the fail-open value: `satisfied.size >= 0` was always true"],
    ["01", "a leading zero"],
    ["1.0", "a fraction that Number() would coerce to 1"],
    [" 1", "leading whitespace"],
    ["", "the empty string"],
    ["1e0", "exponent notation"],
    ["+1", "an explicit sign"]
  ])("refuses threshold %j (%s)", (threshold) => {
    expect(codeOf([keys[0]!], threshold, [signOver(alpha)])).toBe("threshold_malformed");
  });

  it("refuses the degenerate call the old public API returned true for", () => {
    // Recorded in 015's migration section: `verifyThresholdRecord({signature: []}, [], "0")`
    // returned TRUE, because `satisfied.size >= Number("0")` is `0 >= 0`.
    expect(verifyThresholdRecord({ signature: [] }, [], "0")).toBe(false);
    expect(codeOf([], "0", [])).toBe("threshold_malformed");
  });

  it("refuses a threshold above the state's key count", () => {
    // NOT ISOLATABLE, and saying so is the point. A threshold above the key count is
    // unsatisfiable by construction: `m = t > n` cannot also hold with S2's injectivity,
    // because there are not `t` distinct keys to assign to. So every input violating this
    // rule violates `m = t` or S2 as well. The order of checks decides which code fires, and
    // 015's procedure puts the state rule first — a state is invalid before any record is
    // judged against it.
    expect(codeOf([keys[0]!, keys[1]!], "3", [signOver(alpha), signOver(beta)])).toBe(
      "threshold_exceeds_key_count"
    );
  });

  it("refuses a set carrying MORE members than the threshold (the surplus-deletion hole)", () => {
    // Violates `m = t` ONLY: three members, each verifying under a distinct listed key in
    // increasing order, against a threshold of two. The rule 015 replaces ACCEPTED this —
    // two distinct satisfied keys met the threshold and the third member was never examined
    // — and deleting the surplus member left another valid record with a different digest,
    // an edit anyone can make holding no key at all.
    expect(codeOf(keys, "2", [signOver(alpha), signOver(beta), signOver(gamma)])).toBe(
      "signature_count_not_threshold"
    );
    // ...while the record with the surplus removed is the conforming one, and stays valid.
    expect(verifyThresholdRecord(setOf([signOver(alpha), signOver(beta)]), keys, "2")).toBe(true);
  });

  it("refuses a set carrying FEWER members than the threshold", () => {
    expect(codeOf(keys, "2", [signOver(alpha)])).toBe("signature_count_not_threshold");
  });

  it("checks the member count BEFORE decoding the signature array", () => {
    // A length comparison must not be reached through a parse of every element, or the bound
    // has added cost rather than removed it. `"not-base58!"` cannot decode, so if the count
    // rule ran after the decode this would throw instead of returning a verdict.
    expect(codeOf(keys, "2", ["not-base58!"])).toBe("signature_count_not_threshold");
  });
});

describe("spec 015 S2/S3 — every member verifies, under a distinct key, in key order", () => {
  const [alpha, beta, gamma] = keyPairs(3, 60) as [KeyPair, KeyPair, KeyPair];
  const outsider = keyPairs(1, 70)[0]!;
  const keys = [alpha, beta, gamma].map((key) => encodeKeyRef(key.publicKey));

  it("accepts the conforming 2-of-3", () => {
    expect(codeOf(keys, "2", [signOver(alpha), signOver(gamma)])).toBe("accepted");
  });

  it("refuses a member that verifies under no listed key (S2, totality)", () => {
    expect(codeOf(keys, "2", [signOver(alpha), junk(outsider)])).toBe(
      "member_verifies_under_no_listed_key"
    );
  });

  it("refuses a member signed by a key the state does not list", () => {
    expect(codeOf(keys, "2", [signOver(alpha), signOver(outsider)])).toBe(
      "member_verifies_under_no_listed_key"
    );
  });

  it("refuses the same signature twice (S2, injectivity)", () => {
    expect(codeOf(keys, "2", [signOver(alpha), signOver(alpha)])).toBe(
      "members_not_injectively_assignable"
    );
  });

  it("refuses a set whose members verify but sit out of key order (S3)", () => {
    // Both members verify, under DISTINCT keys, and the count is exact — only the order is
    // wrong. The rule 015 replaces accepted this, so an m-member set had m! valid byte-forms
    // and therefore m! valid digests.
    expect(codeOf(keys, "2", [signOver(gamma), signOver(alpha)])).toBe("members_out_of_key_order");
    // Reordered into key order, the very same two signature values conform.
    expect(verifyThresholdRecord(setOf([signOver(alpha), signOver(gamma)]), keys, "2")).toBe(true);
  });

  it("reports one code for S2/S3 without `explain`, and refines it with", () => {
    const misordered = setOf([signOver(gamma), signOver(alpha)]);
    const plain = checkSignatureSet(misordered, keys, "2");
    expect(plain.ok).toBe(false);
    expect(plain.ok ? null : plain.code).toBe("no_conforming_assignment");
    expect(plain.ok ? null : plain.memberIndex).toBe(1);
  });

  it("spends at most one verification per listed key, whatever the member count", () => {
    // The cost claim of 015's walk, measured rather than asserted. An 8-of-8 whose members
    // match nothing runs the key cursor to the end and stops: 8 verifications, not 8 x 8.
    const wide = keyPairs(8, 90);
    const decoys = keyPairs(8, 110);
    let spent = -1;
    const verdict = checkSignatureSet(
      setOf(decoys.map((key) => junk(key))),
      wide.map((key) => encodeKeyRef(key.publicKey)),
      "8",
      { onSignatureVerifications: (n) => (spent = n) }
    );
    expect(verdict.ok).toBe(false);
    expect(spent).toBe(8);

    // And a conforming 8-of-8 signed in key order costs exactly 8 as well.
    let honestSpend = -1;
    expect(
      checkSignatureSet(
        setOf(wide.map((key) => signOver(key))),
        wide.map((key) => encodeKeyRef(key.publicKey)),
        "8",
        { onSignatureVerifications: (n) => (honestSpend = n) }
      ).ok
    ).toBe(true);
    expect(honestSpend).toBe(8);
  });
});

describe("spec 015 S5 — the existential over states stays outside the per-state check", () => {
  it("a record signed under an old state still verifies after a rotation", () => {
    // S5 is a property of the CALLER: `checkSignatureSet` judges one set against one state,
    // and the `∃ state` quantifier composes on the outside. Pinned here as the shape callers
    // must keep — `states.some(state => check(record, state))` — because collapsing it (for
    // instance by unioning every state's keys into one list) would both weaken the check and
    // orphan records the participant already signed.
    const identity = createIdentity({ currentSeed: seed(150), nextSeed: seed(151) });
    const rotated = rotateIdentity(identity, { nextSeeds: [seed(152)] });
    const record = setOf([signOver(identity.currentKeys[0]!)]);

    const states = rotated.log.map((event) => ({ keys: event.keys, threshold: event.threshold }));
    expect(states).toHaveLength(2);

    // The record conforms against the INCEPTION state and not the current one, and the
    // existential is what makes it valid.
    expect(verifyThresholdRecord(record, states[0]!.keys, states[0]!.threshold)).toBe(true);
    expect(verifyThresholdRecord(record, states[1]!.keys, states[1]!.threshold)).toBe(false);
    expect(states.some((state) => verifyThresholdRecord(record, state.keys, state.threshold))).toBe(
      true
    );

    // Unioning the states into one key list is NOT the same question, and is the collapse
    // this test exists to forbid: it would make a one-member set fail `m = t` against a
    // two-key state at threshold 1 only by accident, and it destroys per-state thresholds.
    const union = [...states[0]!.keys, ...states[1]!.keys];
    expect(verifyThresholdRecord(record, union, states[0]!.threshold)).toBe(true);
    expect(union).toHaveLength(2);
  });
});

describe("spec 003 — no two states of one log may share a quorum", () => {
  const pool = keyPairs(6, 180);
  const k = pool.map((pair) => encodeKeyRef(pair.publicKey));

  it.each([
    ["route 3 — the later state's keys are a subset", [[0, 1, 2], "3"], [[0, 2], "2"], false],
    ["route 4 — the later state is a permutation", [[0, 1], "2"], [[1, 0], "2"], false],
    ["variant G — the key set grows", [[0], "1"], [[0, 1], "2"], false],
    ["variant P — partial rotation, lowered threshold", [[0, 1, 2], "3"], [[0, 1, 3], "2"], false],
    ["legal — a 1-of-1 rotation", [[0], "1"], [[1], "1"], true],
    ["legal — a 2-of-3 retaining exactly one key", [[0, 1, 2], "2"], [[0, 3, 4], "2"], true]
  ])("%s", (_name, first, second, legal) => {
    const state = ([indices, threshold]: unknown[]) => ({
      keys: (indices as number[]).map((index) => k[index]!),
      threshold: threshold as string
    });
    expect(quorumViolation([state(first as unknown[]), state(second as unknown[])]) === null).toBe(
      legal
    );
  });

  it("checks ALL pairs, not merely consecutive ones", () => {
    const states = [
      { keys: [k[0]!, k[1]!], threshold: "2" },
      { keys: [k[2]!, k[3]!, k[4]!], threshold: "3" },
      { keys: [k[1]!, k[0]!], threshold: "2" }
    ];
    // Each consecutive pair is legal on its own...
    expect(quorumViolation([states[0]!, states[1]!])).toBeNull();
    expect(quorumViolation([states[1]!, states[2]!])).toBeNull();
    // ...and the log is still illegal, because states 0 and 2 share a quorum.
    const violation = quorumViolation(states);
    expect(violation).toEqual({ first: 0, second: 2, shared: 2, minThreshold: 2 });
  });

  it("agrees with the committed log-rule vectors", async () => {
    const { readFileSync } = await import("node:fs");
    const fixture = JSON.parse(
      readFileSync(new URL("./fixtures/signature-set-vectors.json", import.meta.url), "utf8")
    ) as {
      logRuleVectors: {
        name: string;
        legal: boolean;
        states: { keys: string[]; threshold: string }[];
      }[];
    };
    expect(fixture.logRuleVectors.length).toBeGreaterThanOrEqual(8);
    for (const vector of fixture.logRuleVectors) {
      expect([vector.name, quorumViolation(vector.states) === null]).toEqual([
        vector.name,
        vector.legal
      ]);
    }
  });

  it("replayKeyLog rejects a log whose two states share a quorum", () => {
    // A real, otherwise fully valid two-event log: the hash chain, the pre-rotation
    // commitment, the participant-id derivation, the sequence and every signature check out,
    // and each event on its own satisfies S0–S3. Only spec 003's log-level quorum rule
    // refuses it. Before this change the replay looked at no cross-state overlap at all, so
    // this log replayed clean and returned a key state.
    //
    // The shape is a log that RE-REVEALS its own current key set — which 003 names explicitly
    // as now illegal, and which was legal before this section existed, because a rotation was
    // defined purely by the pre-rotation commitment.
    const held = keyPairs(2, 200);
    const after = keyPairs(2, 220);
    const keyRefs = held.map((key) => encodeKeyRef(key.publicKey));

    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: keyRefs,
      threshold: "2",
      // The rotation below re-reveals this very key set at threshold "2", so that is the
      // state committed here — the commitment must reproduce or the replay stops at the
      // commitment check and never reaches the quorum rule this test is about.
      next: commitToKeyState(keyRefs, "2")
    };
    const id = deriveParticipantId(establishment);
    const inceptionUnsigned = { ...establishment, id, prior: null };
    const inception = {
      ...inceptionUnsigned,
      signature: held.map((key) => signOver(key, inceptionUnsigned))
    };

    const rotationUnsigned = {
      id,
      seq: "1",
      prior: eventDigest(inception),
      kind: "rot" as const,
      keys: keyRefs,
      threshold: "2",
      next: commitToKeyState(
        after.map((key) => encodeKeyRef(key.publicKey)),
        "2"
      )
    };
    const rotation = {
      ...rotationUnsigned,
      signature: held.map((key) => signOver(key, rotationUnsigned))
    };

    // Each event replays fine on its own — so the refusal below is the LOG rule and not an
    // event rule wearing its hat.
    expect(replayKeyLog([inception]).seq).toBe("0");
    expect(() => replayKeyLog([inception, rotation])).toThrow(/share a quorum/);
    expect(() => replayKeyLog([inception, rotation])).toThrow(
      /share 2 keys against a threshold of 2/
    );
  });

  it("leaves every honest 1-of-1 rotation legal, however long the log", () => {
    // The migration claim, executed rather than asserted: every documented first-party log is
    // 1-of-1, and a 1-of-1 rotation shares zero keys against min(t) = 1.
    let identity = createIdentity({ currentSeed: seed(240), nextSeed: seed(241) });
    for (let index = 0; index < 6; index += 1) {
      identity = rotateIdentity(identity);
    }
    expect(identity.log).toHaveLength(7);
    expect(replayKeyLog(identity.log).seq).toBe("6");
    expect(
      quorumViolation(
        identity.log.map((event) => ({ keys: event.keys, threshold: event.threshold }))
      )
    ).toBeNull();
  });
});

/**
 * COMPOSITION — the rules taken singly versus the rule set as a whole.
 *
 * S0–S3 each hold within one key state, and a combination none of them refuses still exists:
 * spec 015 calls it route 3 (cross-state deletion) and route 4 (cross-state reorder), and is
 * explicit that "the existential is where this spec's guarantee stops". The construction
 * below is that combination, executed rather than described, and it shows exactly two things:
 * S0–S3 alone DO admit it, and spec 003's quorum rule is what refuses it.
 */
describe("composition — S0-S3 hold singly and still admit a keyless cross-state edit", () => {
  it("route 3: stripping a member moves a record from one conforming state to another", () => {
    const keys = keyPairs(3, 260);
    const refs = keys.map((key) => encodeKeyRef(key.publicKey));

    // State A: 3-of-3 over all three keys. State B: 2-of-2 over keys 0 and 2 — a strict
    // subset of A's key list, in A's order.
    const stateA = { keys: refs, threshold: "3" };
    const stateB = { keys: [refs[0]!, refs[2]!], threshold: "2" };

    const original = setOf(keys.map((key) => signOver(key)));
    // The edit needs NO key at all: delete the middle member of the array.
    const edited = setOf([original.signature[0]!, original.signature[2]!]);

    // Each record conforms against its own state, and every rule holds for each of them
    // taken singly: no repeated key, a threshold in range and at most the key count, an
    // exact member count, every member verifying under a distinct key, in increasing order.
    expect(verifyThresholdRecord(original, stateA.keys, stateA.threshold)).toBe(true);
    expect(verifyThresholdRecord(edited, stateB.keys, stateB.threshold)).toBe(true);

    // Two valid records with two different digests, from one keyless edit. Neither S0, nor
    // S1, nor S2, nor S3 refuses this — the rules are stated against ONE state and the
    // quantifier over states sits outside them.
    expect(canonicalDigest(original)).not.toBe(canonicalDigest(edited));

    // What closes it is spec 003's log-level rule: a log committing both states shares two
    // keys against min(t) = 2, so the LOG is invalid and no conforming log ever puts both
    // states in play. That is a closure in practice, conditional on the verifier enforcing
    // the log rule; record anchoring (proposed as spec 016) is what makes it structural.
    expect(quorumViolation([stateA, stateB])).toEqual({
      first: 0,
      second: 1,
      shared: 2,
      minThreshold: 2
    });
  });

  it("route 4: swapping two members moves a record between two permuted states", () => {
    const keys = keyPairs(2, 280);
    const refs = keys.map((key) => encodeKeyRef(key.publicKey));
    const stateA = { keys: refs, threshold: "2" };
    const stateB = { keys: [refs[1]!, refs[0]!], threshold: "2" };

    const original = setOf(keys.map((key) => signOver(key)));
    const swapped = setOf([original.signature[1]!, original.signature[0]!]);

    // Both thresholds are 2 and both records carry two members, so `m = t` gives no
    // protection here at all — which is why 015 says the m = t narrowing "reassures about
    // nothing" across states.
    expect(verifyThresholdRecord(original, stateA.keys, stateA.threshold)).toBe(true);
    expect(verifyThresholdRecord(swapped, stateB.keys, stateB.threshold)).toBe(true);
    expect(canonicalDigest(original)).not.toBe(canonicalDigest(swapped));

    expect(quorumViolation([stateA, stateB])).not.toBeNull();
  });

  it("a log committing a route-3 or route-4 pair does not replay", () => {
    // The closure, end to end rather than through `quorumViolation` alone: build the route-3
    // state pair as a real log and watch `replayKeyLog` refuse it. Both events are
    // individually valid — the refusal is the pair.
    const all = keyPairs(3, 300);
    const refs = all.map((key) => encodeKeyRef(key.publicKey));
    const subset = [refs[0]!, refs[2]!];
    const later = keyPairs(2, 320);

    const establishment = {
      seq: "0",
      kind: "icp" as const,
      keys: refs,
      threshold: "3",
      // The rotation reveals `subset` at threshold "2", so "2" is the committed next state.
      next: commitToKeyState(subset, "2")
    };
    const id = deriveParticipantId(establishment);
    const icpUnsigned = { ...establishment, id, prior: null };
    const icp = { ...icpUnsigned, signature: all.map((key) => signOver(key, icpUnsigned)) };

    const rotUnsigned = {
      id,
      seq: "1",
      prior: eventDigest(icp),
      kind: "rot" as const,
      keys: subset,
      threshold: "2",
      next: commitToKeyState(
        later.map((key) => encodeKeyRef(key.publicKey)),
        "2"
      )
    };
    const rot = {
      ...rotUnsigned,
      signature: [all[0]!, all[2]!].map((key) => signOver(key, rotUnsigned))
    };

    expect(replayKeyLog([icp]).seq).toBe("0");
    expect(() => replayKeyLog([icp, rot])).toThrow(/share a quorum/);
  });
});
