/**
 * JSON Canonicalization Scheme (RFC 8785) — spec 001.
 *
 * Signing input for every record is UTF8(JCS(record without its signature field)).
 * JSON.stringify already implements the ECMAScript string and number serialization
 * RFC 8785 specifies; canonicalization adds key ordering by UTF-16 code units and
 * minimal separators.
 */

export function canonicalize(value: unknown): string {
  if (value === undefined) {
    throw new Error("JCS: undefined is not serializable");
  }

  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("JCS: non-finite numbers are not serializable");
      }
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new Error(`JCS: a ${typeof value} is not serializable`);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, propertyValue]) => propertyValue !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([key, propertyValue]) => `${JSON.stringify(key)}:${canonicalize(propertyValue)}`);

  return `{${entries.join(",")}}`;
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

/**
 * Spec 001's number rule for signed records: no floats, and integers that may exceed
 * 2^53 must be strings. Enforced at signing time so plain JCS stays general.
 */
export function assertSignableNumbers(value: unknown, path = "$"): void {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error(
        `Signed records may not contain floats or unsafe integers (at ${path}); use strings per spec 001`
      );
    }
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertSignableNumbers(item, `${path}[${index}]`));
    return;
  }

  if (value !== null && typeof value === "object") {
    for (const [key, propertyValue] of Object.entries(value)) {
      assertSignableNumbers(propertyValue, `${path}.${key}`);
    }
  }
}
