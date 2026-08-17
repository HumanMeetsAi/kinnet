import { describe, expect, it } from "vitest";

import { assertSignableNumbers, canonicalize } from "../src/jcs.js";

describe("canonicalize (RFC 8785)", () => {
  it("sorts object keys by UTF-16 code units", () => {
    expect(canonicalize({ b: 1, a: 2, A: 4, é: 3 })).toBe('{"A":4,"a":2,"b":1,"é":3}');
  });

  it("uses minimal separators and preserves array order", () => {
    expect(canonicalize({ list: [3, 1, 2], empty: [], nested: { x: {} } })).toBe(
      '{"empty":[],"list":[3,1,2],"nested":{"x":{}}}'
    );
  });

  it("serializes numbers per ECMAScript", () => {
    expect(canonicalize([1e21, 4.5, 2e-3, 1e30, 10])).toBe("[1e+21,4.5,0.002,1e+30,10]");
  });

  it("escapes strings per JSON.stringify", () => {
    expect(canonicalize({ s: '\u000f\nA"\\' })).toBe('{"s":"\\u000f\\nA\\"\\\\"}');
  });

  it("serializes literals", () => {
    expect(canonicalize([null, true, false])).toBe("[null,true,false]");
  });

  it("drops undefined object properties, like JSON.stringify", () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it("rejects non-finite numbers, bigints, and top-level undefined", () => {
    expect(() => canonicalize(Number.NaN)).toThrow();
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow();
    expect(() => canonicalize(1n)).toThrow();
    expect(() => canonicalize(undefined)).toThrow();
  });

  it("is stable under key-order permutations", () => {
    const a = { x: 1, y: { b: 2, a: 3 } };
    const b = { y: { a: 3, b: 2 }, x: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });
});

describe("assertSignableNumbers (spec 001 number rule)", () => {
  it("accepts safe integers", () => {
    expect(() => assertSignableNumbers({ n: 42, list: [0, -7] })).not.toThrow();
  });

  it("rejects floats anywhere in the record", () => {
    expect(() => assertSignableNumbers({ nested: { n: 1.5 } })).toThrow(/spec 001/);
  });

  it("rejects integers beyond 2^53", () => {
    expect(() => assertSignableNumbers({ n: 2 ** 53 })).toThrow(/spec 001/);
  });
});
