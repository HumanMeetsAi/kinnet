/**
 * The ISSUING side of the records this package verifies.
 *
 * Verifying and issuing are two halves of one contract, and keeping them apart is how they
 * drift: an issuer that lives in a different package signs the fields it remembers, while the
 * verifier here decides against the fields the spec names. Both sides now read from one module
 * pair — `resolver.ts` decides, this file mints — so a rule that changes has one place to be
 * wrong in rather than two places to disagree in.
 *
 * Nothing here talks to a network. A Claim, a Relationship and a Revocation are published to a
 * discovery service (`@kinnet/discovery-client`); a Grant is a BEARER record the holder
 * presents and is never published at all (spec 009). Minting is pure and costs only CPU, so an
 * issuer that throws leaves no trace anywhere.
 *
 * Every record is signed at the issuer's CURRENT keys — `identity.currentKeys` — because that
 * is the key set a verifier resolves from the issuer's key log (spec 003). Scalar-signature
 * records (Claim, Relationship) take the first current key; signature-set records (Grant,
 * Revocation) are signed by all of them, so an issuer running a signing committee satisfies its
 * own threshold without the caller assembling the set.
 */
import { signRecord, signThresholdRecord, type Identity } from "@kinnet/crypto";
import type {
  Claim,
  Grant,
  ParticipantId,
  Principal,
  Relationship,
  Revocation
} from "@kinnet/protocol";

import { assertGrant } from "./grant-validate.js";
import { REPRESENTS_PREDICATE } from "./resolver.js";

/** Fields common to the two issued statements: an identifier and a validity window. */
type IssuedStatementOptions = {
  /** The record's own id, unique per issuer. Discovery keys the record by (issuer, id). */
  id: string;
  subjectId: ParticipantId;
  /** Defaults to now. Pass it explicitly for a reproducible record. */
  issuedAt?: string;
  expiresAt?: string;
};

export type IssueRelationshipOptions = IssuedStatementOptions & {
  predicate: string;
  objectId: ParticipantId;
};

export type IssueClaimOptions = IssuedStatementOptions & {
  claimType: string;
  value: unknown;
};

export type IssueGrantOptions = {
  expiresAt?: string;
  issuedAt?: string;
  caveats?: Grant["caveats"];
};

export type IssueRevocationOptions = {
  /** Defaults to now. */
  revokedAt?: string;
  reason?: string;
};

/**
 * Signs a Relationship (spec 008): the issuer asserts `subject predicate object`.
 *
 * The issuer is not the subject in the general case, which is what makes the record worth
 * anything — a participant asserting something about itself is a self-record, while a
 * relationship is a third party putting its own signature behind a statement about someone
 * else. Discovery stores it under the ISSUER, and `verifyRelationship` decides it against the
 * issuer's key state.
 */
export function issueRelationship(
  issuer: Identity,
  options: IssueRelationshipOptions
): Relationship {
  return signRecord(
    {
      id: options.id,
      subjectId: options.subjectId,
      predicate: options.predicate,
      objectId: options.objectId,
      issuedBy: issuer.id,
      issuedAt: options.issuedAt ?? new Date().toISOString(),
      ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt })
    },
    issuer.currentKeys[0]!.secretKey
  ) as Relationship;
}

/**
 * Signs a Claim (spec 008): the issuer asserts that `subject` has `claimType = value`.
 *
 * `value` is unconstrained by the schema, so it is unconstrained here — but it is SIGNED, so it
 * must be JSON-canonicalizable; `signRecord` refuses a value that is not.
 */
export function issueClaim(issuer: Identity, options: IssueClaimOptions): Claim {
  return signRecord(
    {
      id: options.id,
      subjectId: options.subjectId,
      claimType: options.claimType,
      value: options.value,
      issuedBy: issuer.id,
      issuedAt: options.issuedAt ?? new Date().toISOString(),
      ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt })
    },
    issuer.currentKeys[0]!.secretKey
  ) as Claim;
}

/**
 * Signs a `represents` edge: the organization asserts that the agent acts for it.
 *
 * A thin call to {@link issueRelationship} with the pinned predicate, so the one string every
 * representation consumer matches on cannot be typed differently on the issuing side than on
 * the verifying side. `id` defaults to `represents-<agentId>`, which is unique per (issuer,
 * agent) and therefore re-issuable without colliding with another agent's edge.
 */
export function issueRepresentsEdge(
  organization: Identity,
  agentId: ParticipantId,
  options: { id?: string; expiresAt?: string; issuedAt?: string } = {}
): Relationship {
  return issueRelationship(organization, {
    id: options.id ?? `represents-${agentId}`,
    subjectId: agentId,
    predicate: REPRESENTS_PREDICATE,
    objectId: organization.id,
    ...(options.issuedAt === undefined ? {} : { issuedAt: options.issuedAt }),
    ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt })
  });
}

/**
 * Signs a self-issued root Grant (spec 009): the issuer delegates the listed abilities of its
 * own authority to `audienceId`. Grants are bearer records — the holder presents the chain to
 * verifiers; nothing is stored in discovery.
 *
 * `caveats` narrows the link (spec 011): most importantly `aud`, the verifiers the grant may be
 * presented to — verifiers configured with `requireAud` reject chains without it, and a
 * key-audience grant is malformed without it.
 *
 * VALIDATED AFTER SIGNING, and throws {@link GrantValidationError} rather than returning a
 * grant no verifier will accept. Without the check, the three cross-field rules `grantSchema`
 * enforces — a key audience needs `expiresAt`, an `e2ee` credential link needs empty caveats, a
 * key-audience non-credential needs `caveats.aud` — are checked nowhere on the mint path. A
 * grant breaking one of them is signed, handed to a counterparty, and rejected at the far end
 * as `grant_malformed`, which names neither the field nor the party that got it wrong. Failing
 * at the mint is the difference between a stack trace pointing at the caller's own arguments
 * and a support thread.
 *
 * Signing first and validating second is deliberate: `signature` is itself a validated field,
 * so a pre-signing check could not cover the whole record.
 */
export function issueGrant(
  issuer: Identity,
  audienceId: Principal,
  abilities: string[],
  options: IssueGrantOptions = {}
): Grant {
  const signed = signThresholdRecord(
    {
      subjectId: issuer.id,
      issuerId: issuer.id,
      audienceId,
      abilities,
      caveats: options.caveats ?? {},
      proof: null,
      issuedAt: options.issuedAt ?? new Date().toISOString(),
      ...(options.expiresAt ? { expiresAt: options.expiresAt } : {})
    },
    issuer.currentKeys.map((keyPair) => keyPair.secretKey)
  );
  return assertGrant(signed, "issueGrant produced an invalid grant");
}

/**
 * Signs a Revocation (spec 008) withdrawing the record named by `revokes` — the multihash
 * digest of that record's complete signed form.
 *
 * There is no `id`: a revocation's identity IS the pair (issuer, revoked digest), which is why
 * `revocationSchema` defines no such field and why discovery keys the record by the digest in
 * its path. Revocation is permanent and monotonic; nothing here can be undone by a later
 * record, so the digest passed in had better be the one intended.
 */
export function issueRevocation(
  issuer: Identity,
  revokes: string,
  options: IssueRevocationOptions = {}
): Revocation {
  return signThresholdRecord(
    {
      revokes,
      issuerId: issuer.id,
      revokedAt: options.revokedAt ?? new Date().toISOString(),
      ...(options.reason === undefined ? {} : { reason: options.reason })
    },
    issuer.currentKeys.map((keyPair) => keyPair.secretKey)
  ) as Revocation;
}
