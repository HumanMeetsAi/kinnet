/**
 * Mint-side grant validation (`validateGrant` / `assertGrant`).
 *
 * The property under test is LEGIBILITY, not merely accept/reject. `grantSchema` already
 * decided which grants are well-formed; what this module adds is a minter's answer to "which
 * field is wrong", and that answer is only worth anything if the `path` is exact. A validator
 * that reported every cross-field violation at the record root would pass an accept/reject
 * suite and still leave the minter guessing, so the assertions below pin `path` character for
 * character rather than checking that some issue exists.
 *
 * The three spec 011/014 cross-field rules are each exercised alone. Testing them only in
 * combination would hide the case that matters most to a caller — one broken field, named.
 */
import { createIdentity, encodeKeyRef, generateKeyPair, signThresholdRecord } from "@kinnet/crypto";
import { grantSchema, type Grant } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import { assertGrant, GrantValidationError, validateGrant } from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const ISSUED_AT = "2026-06-01T00:00:00.000Z";
const EXPIRES_AT = "2026-07-01T00:00:00.000Z";

const org = createIdentity({ currentSeed: seed(1), nextSeed: seed(2) });
const admin = createIdentity({ currentSeed: seed(3), nextSeed: seed(4) });
const service = createIdentity({ currentSeed: seed(5), nextSeed: seed(6) });

/** A bare spec-005 KeyRef audience: a key with no log, which is what triggers 011's rules. */
const sessionKeyRef = encodeKeyRef(generateKeyPair(seed(9)).publicKey);

type GrantFields = {
  subjectId?: string;
  issuerId?: string;
  audienceId?: string;
  abilities?: string[];
  caveats?: Record<string, unknown>;
  proof?: string | null;
  issuedAt?: string;
  expiresAt?: string;
};

/**
 * Signs a grant-shaped record. Deliberately returns `unknown`, not `Grant`: every interesting
 * case here is a record the schema REJECTS, so a helper typed as `Grant` would be lying and
 * would need a cast at each call site to construct the very shapes under test.
 */
function signGrantLike(fields: GrantFields = {}): unknown {
  return signThresholdRecord(
    {
      subjectId: org.id,
      issuerId: org.id,
      audienceId: admin.id,
      abilities: ["directory"],
      caveats: {},
      proof: null,
      issuedAt: ISSUED_AT,
      ...fields
    },
    [org.currentKeys[0]!.secretKey]
  );
}

/** A key-audience grant satisfying both of 011's requirements, for use as a baseline. */
function signKeyAudienceGrant(fields: GrantFields = {}): unknown {
  return signGrantLike({
    audienceId: sessionKeyRef,
    abilities: ["msg"],
    expiresAt: EXPIRES_AT,
    caveats: { aud: [service.id] },
    ...fields
  });
}

function issuesOf(value: unknown): { path: string; code: string; message: string }[] {
  const result = validateGrant(value);
  expect(result.ok).toBe(false);
  // A failed parse with no issues would make every downstream error report empty; the type
  // promises this can't happen, so state it once here where every rejection case flows through.
  expect(result.ok === false && result.issues.length).toBeGreaterThan(0);
  return result.ok === false ? result.issues : [];
}

describe("validateGrant accepts the grants the schema accepts", () => {
  it("accepts a participant-audience grant and returns it unchanged", () => {
    const grant = signGrantLike();
    const result = validateGrant(grant);

    expect(result.ok).toBe(true);
    // The parsed output is byte-identical to the input today. This is what lets a minter sign
    // the input and hand back the parsed value without the two drifting apart — if the schema
    // ever gains a transform, this assertion is the tripwire.
    expect(result.ok === true && result.grant).toEqual(grant);
  });

  it("accepts a key-audience grant carrying expiresAt and caveats.aud", () => {
    expect(validateGrant(signKeyAudienceGrant()).ok).toBe(true);
  });

  it("accepts an e2ee credential link with empty caveats and no aud", () => {
    // The 014 exemption in force: a credential link to a bare key needs no `aud`, but still
    // needs `expiresAt`, because a bare key has no log to revoke through.
    const credential = signKeyAudienceGrant({ abilities: ["e2ee/leaf"], caveats: {} });
    expect(validateGrant(credential).ok).toBe(true);
  });
});

describe("each spec 011/014 cross-field rule is reported at its own field", () => {
  it("blames expiresAt when a key-audience grant carries no expiry", () => {
    const [issue, ...rest] = issuesOf(signKeyAudienceGrant({ expiresAt: undefined }));

    expect(rest).toHaveLength(0);
    expect(issue!.path).toBe("expiresAt");
    expect(issue!.code).toBe("custom");
    expect(issue!.message).toMatch(/011/);
  });

  it("blames caveats when an e2ee credential link carries any caveat", () => {
    const credential = signKeyAudienceGrant({
      abilities: ["e2ee/leaf"],
      caveats: { aud: [service.id] }
    });
    const [issue, ...rest] = issuesOf(credential);

    // The whole `caveats` object is at fault, not one key inside it: 014 closes the shape, so
    // there is no per-key answer to give.
    expect(rest).toHaveLength(0);
    expect(issue!.path).toBe("caveats");
    expect(issue!.code).toBe("custom");
    expect(issue!.message).toMatch(/014/);
  });

  it("blames caveats.aud when a non-credential key-audience grant omits it", () => {
    const [issue, ...rest] = issuesOf(signKeyAudienceGrant({ caveats: {} }));

    expect(rest).toHaveLength(0);
    // Two segments deep. Flattening this to `caveats` would send the minter looking at a
    // record that is structurally fine except for one missing key inside it.
    expect(issue!.path).toBe("caveats.aud");
    expect(issue!.code).toBe("custom");
    expect(issue!.message).toMatch(/011/);
  });

  it("blames caveats.aud for a malformed aud value", () => {
    const [issue, ...rest] = issuesOf(signKeyAudienceGrant({ caveats: { aud: 7 } }));

    expect(rest).toHaveLength(0);
    expect(issue!.path).toBe("caveats.aud");
    expect(issue!.code).toBe("custom");
  });

  it("mixing e2ee with a non-e2ee ability forfeits the 014 exemption", () => {
    // Not a credential link, so 011 applies unchanged and the missing `aud` is a violation.
    const mixed = signKeyAudienceGrant({ abilities: ["e2ee/leaf", "msg"], caveats: {} });
    expect(issuesOf(mixed).map((issue) => issue.path)).toEqual(["caveats.aud"]);
  });
});

describe("validateGrant rejects what is not a grant at all", () => {
  it("rejects an unknown key at the record root, because the schema is strict", () => {
    // A stripped unknown key would give one delivery two digests, which is what defeats
    // revocation-by-digest. Zod reports an unrecognized key against the OBJECT, not the key,
    // so the path is empty — recorded here so a caller rendering issues per field knows the
    // root bucket has to exist.
    const [issue, ...rest] = issuesOf({ ...(signGrantLike() as object), note: "extra" });

    expect(rest).toHaveLength(0);
    expect(issue!.path).toBe("");
    expect(issue!.code).toBe("unrecognized_keys");
    expect(issue!.message).toContain("note");
  });

  it.each([
    ["null", null],
    ["a string", "nope"],
    ["a number", 42]
  ])("rejects %s with a root-level type issue", (_label, value) => {
    const [issue, ...rest] = issuesOf(value);

    expect(rest).toHaveLength(0);
    expect(issue!.path).toBe("");
    expect(issue!.code).toBe("invalid_type");
  });

  it("reports every missing field of an empty object at once", () => {
    // The result-returning shape exists so a caller can render ALL the problems; a validator
    // that stopped at the first missing field would make that impossible.
    const paths = issuesOf({}).map((issue) => issue.path);
    expect(paths).toEqual(
      expect.arrayContaining(["subjectId", "issuerId", "audienceId", "abilities", "signature"])
    );
  });
});

describe("assertGrant is the throwing form of the same check", () => {
  it("returns the grant when the value is valid", () => {
    const grant = signGrantLike();
    expect(assertGrant(grant)).toEqual(grant);
    // Returning a `Grant` is the point: the caller can sign/store the result without a cast.
    expect(grantSchema.safeParse(assertGrant(grant) as Grant).success).toBe(true);
  });

  it("throws a GrantValidationError carrying the same issues validateGrant returns", () => {
    // Two rules broken at once: a key audience with neither an expiry nor an `aud`.
    const broken = signKeyAudienceGrant({ expiresAt: undefined, caveats: {} });
    const issues = issuesOf(broken);
    expect(issues.map((issue) => issue.path)).toEqual(["expiresAt", "caveats.aud"]);

    let thrown: unknown;
    try {
      assertGrant(broken);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(GrantValidationError);
    expect(thrown).toBeInstanceOf(Error);
    // `name` is set explicitly because subclassing Error does not set it, and a log line
    // reading "Error:" instead of "GrantValidationError:" loses the only cheap signal of what
    // kind of failure this was.
    expect((thrown as GrantValidationError).name).toBe("GrantValidationError");
    expect((thrown as GrantValidationError).issues).toEqual(issues);

    // Every issue in the message, not just the first: a message naming one of two problems
    // sends the caller round the fix-and-retry loop twice.
    const message = (thrown as Error).message;
    for (const issue of issues) {
      expect(message).toContain(issue.path);
      expect(message).toContain(issue.message);
    }
  });

  it("puts the caller's context in the message so the throw names the mint", () => {
    expect(() => assertGrant(null, "custom context")).toThrow(/^custom context: /);
  });

  it("falls back to a default context when the caller gives none", () => {
    expect(() => assertGrant(null)).toThrow(/^Grant failed schema validation: /);
  });
});
