/**
 * Spec 015 S0–S3, and spec 016's anchored lookup on top of them, rule by rule.
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
  keyLogAnchor,
  replayKeyLog,
  replayKeyLogStates,
  rotateIdentity,
  sign,
  verifyAnchoredRecord,
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

describe("spec 016 — the record names its state, and no other state is tried", () => {
  it("keeps a record signed under an old state valid after a rotation", () => {
    // What 012 protects, under the anchored rule: an anchor names a HISTORICAL state, and the
    // log is append-only, so a later rotation cannot invalidate a record already signed. This
    // is the difference between anchoring and "verify against the current state".
    const identity = createIdentity({ currentSeed: seed(150), nextSeed: seed(151) });
    const anchor = keyLogAnchor(identity.log);
    const record = { ...RECORD, anchor };
    const signed = { ...record, signature: [signOver(identity.currentKeys[0]!, record)] };

    const rotated = rotateIdentity(identity, { nextSeeds: [seed(152)] });
    const { states, current } = replayKeyLogStates(rotated.log);
    expect(states).toHaveLength(2);
    expect(current.anchor).not.toBe(anchor);

    expect(verifyAnchoredRecord(signed, states)).toBe(true);
  });

  it("refuses a record whose set another state of the same log would accept", () => {
    // The lookup, stated as the property that distinguishes it from 015 S5's existential: the
    // set here satisfies the CURRENT state and the record names the inception, so a verifier
    // searching the log would accept it and an anchored verifier must not.
    const identity = createIdentity({ currentSeed: seed(160), nextSeed: seed(161) });
    const inceptionAnchor = keyLogAnchor(identity.log);
    const rotated = rotateIdentity(identity, { nextSeeds: [seed(162)] });
    const { states } = replayKeyLogStates(rotated.log);

    const record = { ...RECORD, anchor: inceptionAnchor };
    // Signed by the key of the state at seq 1, while naming the state at seq 0.
    const signed = { ...record, signature: [signOver(rotated.currentKeys[0]!, record)] };

    expect(verifyThresholdRecord(signed, states[1]!.keys, states[1]!.threshold)).toBe(true);
    expect(states.some((state) => verifyThresholdRecord(signed, state.keys, state.threshold))).toBe(
      true
    );
    expect(verifyAnchoredRecord(signed, states)).toBe(false);
  });

  it("refuses an anchor that names no event of the log, rather than falling back to a search", () => {
    const identity = createIdentity({ currentSeed: seed(170), nextSeed: seed(171) });
    const { states } = replayKeyLogStates(identity.log);
    const record = { ...RECORD, anchor: canonicalDigest({ not: "a key event" }) };
    const signed = { ...record, signature: [signOver(identity.currentKeys[0]!, record)] };

    // The set is honest against the only state the log commits; the anchor is not.
    expect(verifyThresholdRecord(signed, states[0]!.keys, states[0]!.threshold)).toBe(true);
    expect(verifyAnchoredRecord(signed, states)).toBe(false);
  });
});

/**
 * COMPOSITION — the rules taken singly versus the rule set as a whole.
 *
 * S0–S3 each hold within one key state, and a combination none of them refuses still exists:
 * spec 015 calls it route 3 (cross-state deletion) and route 4 (cross-state reorder). The
 * constructions below are that combination, executed rather than described, and they show
 * exactly two things: S0–S3 alone DO admit it, and spec 016's anchor is what refuses it.
 *
 * The logs are legal. Two states of one log may share keys, and may share a quorum of them —
 * an earlier interim rule forbade that shape to keep the routes out of reach, and 016 replaces
 * it with a rule that travels inside the record instead of constraining rotation.
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
    // S1, nor S2, nor S3 refuses this — the rules are stated against ONE state, and which
    // state applies is not their question.
    expect(canonicalDigest(original)).not.toBe(canonicalDigest(edited));
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
  });

  it("anchoring refuses the route-3 edit on a log that commits both states", () => {
    // The closure, end to end: build the route-3 state pair as a real log, watch it REPLAY
    // (it commits two states sharing a quorum, which is legal), anchor the honest record to
    // the inception, and watch the keyless deletion fail against that one state — while the
    // narrower state the remainder satisfies is never consulted.
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
    const { states } = replayKeyLogStates([icp, rot]);
    expect(states.map((state) => state.seq)).toEqual(["0", "1"]);

    const record = { ...RECORD, anchor: states[0]!.anchor };
    const original = { ...record, signature: all.map((key) => signOver(key, record)) };
    const edited = { ...record, signature: [original.signature[0]!, original.signature[2]!] };

    expect(verifyAnchoredRecord(original, states)).toBe(true);
    // The edited set satisfies the LATER state — and is refused, because the record names the
    // earlier one and exactly one state is tried.
    expect(verifyThresholdRecord(edited, states[1]!.keys, states[1]!.threshold)).toBe(true);
    expect(verifyAnchoredRecord(edited, states)).toBe(false);
  });
});
