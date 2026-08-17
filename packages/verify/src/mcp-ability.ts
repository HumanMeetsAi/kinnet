/**
 * Naming MCP tools as Kinnet abilities.
 *
 * Spec 009 abilities are `^[a-z0-9-]+(/[a-z0-9-]+)*$`: lower-case, hyphen-separated, `/` for
 * hierarchy. MCP tool names are conventionally snake_case and frequently carry capitals. The two
 * vocabularies therefore do not overlap, and the collision is not hypothetical — a grant naming
 * `tool_call` is rejected by `grantSchema` at mint time, which reads as "the client library is
 * broken" rather than as "that is not a legal ability".
 *
 * The charset is NOT the thing to change. It is what makes `abilityCovers` a segment-boundary
 * test rather than a string-prefix one, it is frozen at the protocol layer, and widening it to
 * admit `_` would mean `tool_call` and `tool-call` become distinct abilities that no verifier
 * could tell apart by intent. The resolution is a MAPPING applied at both ends, written once
 * here so the mint side and the verify side cannot drift.
 */
import { abilitySchema } from "@kinnet/protocol";

/**
 * A tool name that cannot be expressed as a spec 009 ability.
 *
 * Thrown rather than returned because there is no safe fallback. Every alternative — dropping
 * the offending characters, percent-encoding them, substituting a placeholder — silently maps
 * two different tools onto one ability, and an ability is an authorization: the caller would be
 * granting or checking authority over something other than what it named. A mapping that cannot
 * be performed has to stop the caller.
 */
export class AbilityMappingError extends Error {
  constructor(
    readonly toolName: string,
    message: string
  ) {
    super(message);
    this.name = "AbilityMappingError";
  }
}

/** The default namespace segment MCP tool abilities are minted under. */
export const MCP_ABILITY_NAMESPACE = "mcp";

/**
 * Maps an MCP tool name to the ability that authorizes calling it.
 *
 * `mcpToolAbility("tool_call")` is `"mcp/tool-call"`; `mcpToolAbility("searchDocs")` is
 * `"mcp/searchdocs"`. Two transformations, and only two: lower-case, then `_` to `-`. Nothing
 * else is rewritten, so anything the ability charset does not admit is an ERROR rather than
 * something quietly removed.
 *
 * The namespace is a segment, so a grant of the bare `mcp` ability covers every tool by spec
 * 009's path-prefix rule, and `mcp/tool-call` covers only that tool. Pass `namespace: ""` for a
 * bare ability when the surface already scopes its vocabulary some other way.
 *
 * THE MAPPING IS NOT INJECTIVE, which is the one thing a caller has to know. `tool_call` and
 * `tool-call` both map to `mcp/tool-call`, as do `Tool_Call` and `TOOL-CALL`. A server exposing
 * two tools whose names differ only by case or by `_` versus `-` cannot distinguish them by
 * ability, and no grant can authorize one without authorizing the other. That is a property of
 * the ability charset, not of this function — but it means BOTH ENDS MUST APPLY THIS SAME
 * MAPPING. A minter that writes the ability by hand and a verifier that calls this will
 * eventually disagree, and the disagreement fails closed (the check does not match), which is
 * the failure mode that looks like a bug rather than like a misconfiguration.
 *
 * @throws {AbilityMappingError} when the mapped result is not a valid spec 009 ability.
 */
export function mcpToolAbility(
  toolName: string,
  namespace: string = MCP_ABILITY_NAMESPACE
): string {
  if (toolName.length === 0) {
    throw new AbilityMappingError(toolName, "An MCP tool name cannot be empty");
  }
  // `toLowerCase` before the underscore swap, because the two are independent and the order only
  // matters for readability. Locale-INDEPENDENT: `toLocaleLowerCase` would map "I" to a dotless
  // "ı" under a Turkish locale, so the same tool name would produce different abilities on
  // differently configured hosts — a mint/verify mismatch caused by an environment variable.
  const mapped = toolName.toLowerCase().replaceAll("_", "-");
  const ability = namespace.length > 0 ? `${namespace}/${mapped}` : mapped;
  if (!abilitySchema.safeParse(ability).success) {
    // Validating the WHOLE result, namespace included, rather than the mapped tail alone: an
    // invalid namespace produces an invalid ability just as surely, and a caller passing one
    // should hear about it here rather than at mint time from a schema error naming a field.
    throw new AbilityMappingError(
      toolName,
      `MCP tool name ${JSON.stringify(toolName)} maps to ${JSON.stringify(ability)}, which is ` +
        "not a valid ability (spec 009 allows only [a-z0-9-] segments separated by /)"
    );
  }
  return ability;
}
