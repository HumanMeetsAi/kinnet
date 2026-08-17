/**
 * Brand neutrality of the wire (spec 000, _Wire identifiers are brand-neutral_).
 *
 * Every spec-defined byte sequence an independent implementation must emit or match names the
 * network — `pn` — and never the product. The rule was applied by hand when the identifiers were
 * de-branded; nothing kept it applied. This is that guard: a branded wire identifier fails the
 * test run rather than shipping, because after the Stage-1 wire-freeze a rename would be a
 * protocol revision and unpayable.
 *
 * It reads the package's own exports at runtime instead of a hand-kept list, so a constant added
 * tomorrow is covered on arrival. Identifiers owned by packages downstream of this one are
 * guarded next to them — `pn-grants` in `@kinnet/crypto`, `pn.discovery.participant-export/1` in
 * `@kinnet/storage`, the `pn` SSE event name in the participant node — since importing them here
 * would invert the dependency graph.
 */
import { describe, expect, it } from "vitest";

import * as protocol from "../src/index.js";

/** Every string constant the package exports: the whole wire-identifier surface it owns. */
const STRING_EXPORTS = (Object.entries(protocol) as [string, unknown][]).filter(
  (entry): entry is [string, string] => typeof entry[1] === "string"
);

/** Reserved envelope types, found by name so a new `PN_TYPE_*` is covered without an edit here. */
const RESERVED_TYPES = STRING_EXPORTS.filter(([name]) => name.startsWith("PN_TYPE_"));

describe("wire identifiers are brand-neutral (spec 000)", () => {
  it("has reserved envelope types to check", () => {
    // Guards the guard: if the discovery predicate ever matches nothing, the per-type
    // assertions below would pass vacuously.
    expect(RESERVED_TYPES.length).toBeGreaterThan(0);
  });

  it("reserves the `pn/` envelope-type prefix", () => {
    expect(protocol.PN_RESERVED_PREFIX).toBe("pn/");
  });

  it.each(RESERVED_TYPES)("%s is under the reserved `pn/` prefix", (_name, value) => {
    expect(value.startsWith(protocol.PN_RESERVED_PREFIX)).toBe(true);
  });

  it("recognizes reserved types only under the `pn/` prefix", () => {
    const misprefixed = [...protocol.KNOWN_RESERVED_TYPES].filter(
      (type) => !type.startsWith(protocol.PN_RESERVED_PREFIX)
    );
    expect(misprefixed).toEqual([]);
  });

  it("carries the product name in no exported constant", () => {
    const branded = STRING_EXPORTS.filter(([, value]) => /kinnet/i.test(value)).map(
      ([name]) => name
    );
    expect(branded).toEqual([]);
  });
});
