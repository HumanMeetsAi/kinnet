/**
 * Spec 015 (canonical signature sets) conformance vectors.
 *
 * The fixture is the artifact: `packages/crypto/test/fixtures/signature-set-vectors.json`
 * carries, for every vector, the record, the key state it is judged against, the spec-001
 * signing input, a per-signature/per-key Ed25519 verification matrix, the spec-003 digest of
 * the complete signed record, and the spec-015 verdict with a sentence of reasoning. A second
 * implementation can check itself against those bytes without running this file.
 *
 * What this file checks is that the fixture TELLS THE TRUTH — every recorded byte-level fact is
 * recomputed here from the record itself — that the `valid` labels are exactly what spec 015's
 * decision procedure yields, and that `verifyThresholdRecord` returns that same verdict on
 * every vector. The third of those is new: until the enforcement change this file instead
 * pinned a LIST of vectors the implementation got wrong, which is the before half of the
 * watched failure.
 */
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import { grantSchema, revocationSchema } from "@kinnet/protocol";

import {
  canonicalBytes,
  canonicalDigest,
  checkSignatureSet,
  decodeKeyRef,
  decodeSignature,
  verify,
  verifyThresholdRecord
} from "../src/index.js";

type Vector = {
  name: string;
  why: string;
  valid: boolean;
  schema: "grant" | "revocation" | null;
  schemaValid: boolean;
  state: { keys: string[]; threshold: string };
  record: Record<string, unknown> & { signature: string[] };
  signingInput: string;
  digest: string;
  matrix: boolean[][];
};

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/signature-set-vectors.json", import.meta.url), "utf8")
) as { note: string; vectors: Vector[] };

const vectors = fixture.vectors;
const byName = (name: string): Vector => {
  const found = vectors.find((vector) => vector.name === name);
  if (!found) {
    throw new Error(`No vector named ${name}`);
  }
  return found;
};

const THRESHOLD_PATTERN = /^[1-9][0-9]*$/;

/**
 * Spec 015's decision procedure, over the recorded verification matrix rather than over the
 * curve: S1's threshold domain and count bounds, then the greedy strictly-increasing walk that
 * decides S2 and S3 together. Written here, against the matrix, so that what it tests is the
 * fixture's labelling and not this repo's crypto.
 */
function specVerdict(matrix: boolean[][], keys: string[], threshold: string): boolean {
  const keyCount = keys.length;
  // S0: a key state listing the same key twice is invalid, and so is every record checked
  // against it. Enforced on key VALUE — an index-based reading is exactly the bug S0 closes.
  if (new Set(keys).size !== keyCount) {
    return false;
  }
  if (!THRESHOLD_PATTERN.test(threshold)) {
    return false;
  }
  const required = Number(threshold);
  if (required > keyCount) {
    return false;
  }
  // S1's count rule is EXACT: not "at least the threshold", not "at most the key count".
  if (matrix.length !== required) {
    return false;
  }
  let key = 0;
  for (const row of matrix) {
    while (key < keyCount && !row[key]) {
      key += 1;
    }
    if (key === keyCount) {
      return false;
    }
    key += 1;
  }
  return true;
}

describe("spec 015 signature-set conformance vectors", () => {
  it("is not vacuous: distinct names, and both verdicts represented", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(8);
    expect(new Set(vectors.map((vector) => vector.name)).size).toBe(vectors.length);
    expect(vectors.some((vector) => vector.valid)).toBe(true);
    expect(vectors.some((vector) => !vector.valid)).toBe(true);
    for (const vector of vectors) {
      expect(vector.why.length).toBeGreaterThan(40);
    }
  });

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "%s — the recorded bytes are the record's own",
    (_name, vector) => {
      const { signature, ...unsigned } = vector.record;
      const input = canonicalBytes(unsigned);

      // The signing input is spec 001's: JCS of the record WITHOUT its signature field.
      expect(new TextDecoder().decode(input)).toBe(vector.signingInput);

      // The digest is spec 003's: over the COMPLETE signed record, signature array included.
      expect(canonicalDigest(vector.record)).toBe(vector.digest);

      // Every cell of the matrix, recomputed against the curve.
      expect(vector.matrix.length).toBe(signature.length);
      vector.matrix.forEach((row, index) => {
        expect(row.length).toBe(vector.state.keys.length);
        const member = decodeSignature(signature[index]!);
        row.forEach((expected, keyIndex) => {
          expect(verify(member, input, decodeKeyRef(vector.state.keys[keyIndex]!))).toBe(expected);
        });
      });
    }
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "%s — the verdict is what spec 015 yields",
    (_name, vector) => {
      expect(specVerdict(vector.matrix, vector.state.keys, vector.state.threshold)).toBe(
        vector.valid
      );
    }
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "%s — schema acceptance is recorded correctly",
    (_name, vector) => {
      if (vector.schema === null) {
        return;
      }
      const schema = vector.schema === "grant" ? grantSchema : revocationSchema;
      expect(schema.safeParse(vector.record).success).toBe(vector.schemaValid);
    }
  );

  it("shows why order is normative: one signer set, two orders, two digests", () => {
    const ordered = byName("deletion family 2/3 — the conforming 2-of-3, m = t = 2");
    const misordered = byName("invalid — mis-ordered set");

    // Same unsigned record, same two signatures — only the array order differs.
    const strip = (vector: Vector) => {
      const unsigned: Record<string, unknown> = { ...vector.record };
      delete unsigned.signature;
      return unsigned;
    };
    expect(strip(misordered)).toEqual(strip(ordered));
    expect([...misordered.record.signature].sort()).toEqual([...ordered.record.signature].sort());

    // And yet the digests differ, which is the whole reason S3 exists: without an ordering
    // rule an m-member set would present m! digests, all of them verifying.
    expect(misordered.record.signature).not.toEqual(ordered.record.signature);
    expect(misordered.digest).not.toBe(ordered.digest);
  });

  /**
   * The direct evidence for `m = t`. One unsigned record, one 2-of-3 state, three signature
   * arrays that are subsequences of one another — so each is reachable from the one above by
   * DELETING a member, an edit that needs no key at all. Exactly one of the three conforms.
   *
   * Under the rule 015 replaces, 1/3 and 2/3 were both valid with different digests, which is
   * how a revoked over-signed grant could be edited into an unrevoked one.
   */
  it("closes surplus deletion: the family is a deletion chain with exactly one valid member", () => {
    const over = byName("deletion family 1/3 — over-signed 2-of-3, m = 3");
    const conforming = byName("deletion family 2/3 — the conforming 2-of-3, m = t = 2");
    const under = byName("deletion family 3/3 — one member deleted from the conforming set, m = 1");
    const family = [over, conforming, under];

    // One unsigned record and one key state across the family: only the members differ.
    const strip = (vector: Vector) => {
      const unsigned: Record<string, unknown> = { ...vector.record };
      delete unsigned.signature;
      return unsigned;
    };
    for (const member of family) {
      expect(strip(member)).toEqual(strip(conforming));
      expect(member.state).toEqual(conforming.state);
    }

    // Each array is obtained from the previous by deleting one member, order preserved.
    const isSubsequence = (inner: string[], outer: string[]): boolean => {
      let index = 0;
      for (const value of outer) {
        if (index < inner.length && inner[index] === value) {
          index += 1;
        }
      }
      return index === inner.length;
    };
    expect(isSubsequence(conforming.record.signature, over.record.signature)).toBe(true);
    expect(isSubsequence(under.record.signature, conforming.record.signature)).toBe(true);
    expect(over.record.signature.length).toBe(3);
    expect(conforming.record.signature.length).toBe(2);
    expect(under.record.signature.length).toBe(1);

    // Three distinct digests — the deletion really does move the record's identity...
    const digests = new Set(family.map((member) => member.digest));
    expect(digests.size).toBe(3);

    // ...and exactly one member of the family is valid, so no key-free edit carries a verifier
    // from one valid record to another.
    expect(family.filter((member) => member.valid)).toEqual([conforming]);

    // Every member of the over-signed set genuinely verifies under a distinct key in order: it
    // fails on the COUNT alone, which is what makes it evidence for the exact-count rule rather
    // than for S2 or S3.
    expect(over.matrix).toEqual([
      [true, false, false],
      [false, true, false],
      [false, false, true]
    ]);
  });

  /**
   * The gap this spec was written to close, now closed: the reference implementation's
   * verdict is spec 015's verdict on EVERY committed vector, with no exceptions list.
   *
   * This replaces a test that pinned the divergence as a LIST of five vector names — the
   * over-signed 2-of-3, the non-verifying extra appended to a 1-of-1 grant, the duplicate
   * signature at threshold 1, the mis-ordered set, and the degenerate threshold. Those five
   * were `verifyThresholdRecord === true` while the vector says `valid: false`; they are the
   * watched failure this change was measured against, and they are now all rejected.
   */
  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "%s — verifyThresholdRecord agrees with the vector",
    (_name, vector) => {
      expect(verifyThresholdRecord(vector.record, vector.state.keys, vector.state.threshold)).toBe(
        vector.valid
      );
    }
  );

  it("leaves no vector on which the implementation disagrees with 015", () => {
    const disagreements = vectors
      .filter(
        (vector) =>
          verifyThresholdRecord(vector.record, vector.state.keys, vector.state.threshold) !==
          vector.valid
      )
      .map((vector) => vector.name);

    expect(disagreements).toEqual([]);
    // Not vacuous: the suite really does contain vectors of both verdicts, so an empty
    // disagreement list cannot come from an empty or all-valid corpus.
    expect(vectors.filter((vector) => vector.valid).length).toBeGreaterThan(0);
    expect(vectors.filter((vector) => !vector.valid).length).toBeGreaterThan(0);
  });

  /**
   * The rejection has to name the rule, or a caller cannot tell an over-signed record from a
   * mis-ordered one and a test battery cannot show that each rule is separately enforced.
   */
  it.each(vectors.filter((vector) => !vector.valid).map((v) => [v.name, v] as const))(
    "%s — the rejection names a rule",
    (_name, vector) => {
      const verdict = checkSignatureSet(vector.record, vector.state.keys, vector.state.threshold, {
        explain: true
      });
      expect(verdict.ok).toBe(false);
      if (verdict.ok) {
        return;
      }
      expect(verdict.code).not.toBe("no_conforming_assignment");
      expect(verdict.message.length).toBeGreaterThan(20);
    }
  );
});
