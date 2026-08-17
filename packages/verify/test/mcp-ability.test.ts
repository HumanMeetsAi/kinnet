/**
 * Mapping MCP tool names onto spec 009 abilities.
 *
 * The charset collision is real and had no answer: abilities are `^[a-z0-9-]+(/[a-z0-9-]+)*$`,
 * MCP tool names are conventionally snake_case and often carry capitals, so `grantSchema` rejects
 * a grant naming `tool_call` at MINT time — which reads as a broken SDK rather than as an illegal
 * ability. Widening the charset is not available (it is what makes `abilityCovers` a
 * segment-boundary test, and it is frozen at the protocol layer), so the answer is a mapping
 * applied identically at both ends.
 *
 * Two properties matter more than the individual cases: the output is ALWAYS a valid ability (or
 * the call threw), and the mapping is NOT injective — which is a hazard callers must be able to
 * see, so it is pinned here rather than left as a footnote.
 */
import { abilitySchema } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  abilityCovers,
  AbilityMappingError,
  MCP_ABILITY_NAMESPACE,
  mcpToolAbility
} from "../src/index.js";

describe("mcpToolAbility", () => {
  it("maps snake_case to the namespaced ability", () => {
    expect(mcpToolAbility("tool_call")).toBe("mcp/tool-call");
    expect(mcpToolAbility("read_resource")).toBe("mcp/read-resource");
    expect(mcpToolAbility("list")).toBe("mcp/list");
  });

  it("lower-cases, so a camelCase or SHOUTING tool name still maps", () => {
    expect(mcpToolAbility("searchDocs")).toBe("mcp/searchdocs");
    expect(mcpToolAbility("READ_FILE")).toBe("mcp/read-file");
    expect(mcpToolAbility("Get_Weather")).toBe("mcp/get-weather");
  });

  it("takes a custom namespace, and an empty one yields a bare ability", () => {
    expect(mcpToolAbility("tool_call", "vendor")).toBe("vendor/tool-call");
    expect(mcpToolAbility("tool_call", "")).toBe("tool-call");
    expect(MCP_ABILITY_NAMESPACE).toBe("mcp");
  });

  it("produces a namespace segment a bare grant covers, per spec 009 path-prefix cover", () => {
    // The reason the namespace is a SEGMENT rather than a prefix glued on: a grant of `mcp`
    // authorizes every tool, and `mcp/tool-call` authorizes exactly one. Neither would hold if
    // the separator were anything but `/`.
    expect(abilityCovers("mcp", mcpToolAbility("tool_call"))).toBe(true);
    expect(abilityCovers("mcp/tool-call", mcpToolAbility("tool_call"))).toBe(true);
    expect(abilityCovers("mcp/tool-call", mcpToolAbility("tool_calls"))).toBe(false);
  });

  it("always returns something abilitySchema accepts", () => {
    // The invariant that makes this function usable at mint time at all: whatever comes back is
    // a legal ability, or nothing came back. A caller never has to re-validate.
    const names = ["tool_call", "READ_FILE", "a", "x-y_z", "get2", "a_b_c_d", "0", "search-docs"];
    for (const name of names) {
      expect(abilitySchema.safeParse(mcpToolAbility(name)).success).toBe(true);
      expect(abilitySchema.safeParse(mcpToolAbility(name, "")).success).toBe(true);
    }
  });

  it("throws a typed error on a name it cannot express, rather than mangling it", () => {
    // No safe fallback exists. Dropping, encoding or substituting the offending characters all
    // map two different tools onto one ability — and an ability is an authorization, so the
    // caller would be granting authority over something other than what it named.
    for (const bad of ["☃", "tool call", "tool.call", "tool/call?", "", "café", "a__b/"]) {
      let thrown: unknown;
      try {
        mcpToolAbility(bad);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(AbilityMappingError);
      expect(thrown).toBeInstanceOf(Error);
      expect((thrown as AbilityMappingError).toolName).toBe(bad);
    }
  });

  it("throws on a namespace that is not itself a legal segment", () => {
    // Validating the WHOLE result rather than the mapped tail: an invalid namespace produces an
    // invalid ability just as surely, and the caller should hear about it here.
    expect(() => mcpToolAbility("tool_call", "My Vendor")).toThrow(AbilityMappingError);
    expect(() => mcpToolAbility("tool_call", "vendor/")).toThrow(AbilityMappingError);
  });

  it("IS NOT INJECTIVE — the hazard both ends have to know about", () => {
    // `tool_call` and `tool-call` are different MCP tools and one ability. A server exposing both
    // cannot authorize one without authorizing the other, and no grant can tell them apart. That
    // follows from the ability charset, not from this function — but a caller who does not know
    // it will eventually ship a grant that authorizes more than they meant.
    expect(mcpToolAbility("tool_call")).toBe(mcpToolAbility("tool-call"));
    expect(mcpToolAbility("Tool_Call")).toBe(mcpToolAbility("TOOL-CALL"));

    // Which is precisely why BOTH ENDS must apply this same mapping. A minter that hand-writes
    // the ability and a verifier that calls this will eventually disagree, and the disagreement
    // fails closed — the check simply does not match, which looks like a bug rather than like a
    // misconfiguration.
    const minted = mcpToolAbility("tool_call");
    const required = mcpToolAbility("tool_call");
    expect(abilityCovers(minted, required)).toBe(true);
  });

  it("is idempotent on an ability it already produced", () => {
    // Cheap safety for a caller that cannot tell whether a string has been mapped already —
    // which happens the moment the mapping is applied in two layers.
    const once = mcpToolAbility("tool_call", "");
    expect(mcpToolAbility(once, "")).toBe(once);
  });
});
