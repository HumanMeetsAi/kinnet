/**
 * Mint-side Grant validation: a legible projection of `grantSchema` for the party ISSUING a
 * grant, rather than the party verifying one.
 *
 * The two sides had very different tools. A verifier that meets a malformed grant rejects the
 * chain with `grant_malformed` and is done. A minter had nothing: `@kinnet/sdk`'s `issueGrant`
 * signed whatever fields it was handed and returned it cast to `Grant`, so a grant that
 * `grantSchema` rejects — a key-audience link with no `expiresAt`, an `e2ee` credential carrying
 * caveats, a key-audience link with no `aud` — was minted, signed, stored, and shipped to a
 * counterparty, and the first party to learn it was invalid was the VERIFIER, at request time,
 * with no way to say which field was wrong. `apps/custody` had already worked this out and
 * validates after signing (`signRootGrant`); this is that check, lifted out of the app so every
 * minter gets it.
 *
 * `grantSchema` remains the single source of cross-field truth. Nothing here re-implements a
 * rule; this module only turns the schema's rejection into something a caller can act on.
 */
import { grantSchema, type Grant } from "@kinnet/protocol";

/**
 * One reason a value is not a Grant, flattened out of a Zod issue.
 *
 * A STABLE PROJECTION, deliberately narrower than Zod's own issue type. Handing back
 * `ZodError` would make the validation library part of this package's public API — a consumer
 * would import Zod's types to read the result, and a Zod major version would become a breaking
 * change for everyone downstream. Three fields carry everything a minter needs: which field
 * (`path`), what kind of problem (`code`), and what to tell a human (`message`).
 */
export type GrantIssue = {
  /**
   * Dotted path to the offending field — `"caveats.aud"`, `"abilities.0"`, `"expiresAt"` — or
   * `""` for an issue about the record as a whole (a non-object, or an unrecognized key on a
   * strict schema).
   */
  path: string;
  /** Zod's issue code: `"invalid_type"`, `"custom"`, `"unrecognized_keys"`, and so on. */
  code: string;
  /** The schema's own message. These are written for humans and quote the governing spec. */
  message: string;
};

export type GrantValidation =
  | { ok: true; grant: Grant }
  | {
      ok: false;
      /** Never empty: a failed parse always carries at least one issue. */
      issues: GrantIssue[];
    };

/**
 * Validates an unknown value as a spec 009/011/014 Grant.
 *
 * RESULT-RETURNING rather than throwing, because the common mint-side caller wants to REPORT
 * every problem — a form, a CLI, an API validating a request body — and an exception carries
 * one. {@link GrantValidationError} is the throwing wrapper for callers that want the other
 * shape; both are built from this so the two cannot disagree.
 *
 * The returned `grant` is the schema's own PARSED output, not the input value re-typed. For a
 * grant the two are byte-identical (the schema is strict and transforms nothing today), and
 * returning the parsed value is what keeps that true if it ever stops being — a caller signing
 * the value it passed in while validating the value that came out is the classic way a
 * validated record and a signed record drift apart.
 */
export function validateGrant(value: unknown): GrantValidation {
  const parsed = grantSchema.safeParse(value);
  if (parsed.success) {
    return { ok: true, grant: parsed.data };
  }
  return {
    ok: false,
    issues: parsed.error.issues.map((issue) => ({
      // `path` elements are string keys or numeric array indices; joining with "." gives the
      // form an operator recognises from every other config error they have ever read.
      path: issue.path.join("."),
      code: issue.code,
      message: issue.message
    }))
  };
}

/**
 * The throwing form of {@link validateGrant}, carrying every issue rather than only the first.
 *
 * `message` is a single line naming all of them, because it is what lands in a log or a stack
 * trace and a message naming one of three problems sends the caller round the loop three times.
 * `issues` carries the structured form for anything that needs to render them per field.
 */
export class GrantValidationError extends Error {
  readonly issues: GrantIssue[];

  constructor(issues: GrantIssue[], context = "Grant failed schema validation") {
    const detail = issues
      .map((issue) => (issue.path ? `${issue.path}: ${issue.message}` : issue.message))
      .join("; ");
    super(`${context}: ${detail || "malformed grant"}`);
    this.name = "GrantValidationError";
    this.issues = issues;
  }
}

/**
 * Validates and returns the grant, throwing {@link GrantValidationError} on rejection.
 *
 * The shape a minter wants at the end of a sign step: the value is either a Grant or the call
 * did not complete. `context` prefixes the message so the throw says which mint failed.
 */
export function assertGrant(value: unknown, context?: string): Grant {
  const result = validateGrant(value);
  if (!result.ok) {
    throw new GrantValidationError(result.issues, context);
  }
  return result.grant;
}
