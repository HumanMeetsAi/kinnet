import { z } from "zod";

import { base64UrlNoPad, isCanonical, multibaseBase58btc } from "./encoding.js";

export * from "./encoding.js";

/**
 * Encodings (spec 005): keys and digests are multicodec-tagged and multibase-encoded
 * (base58btc, prefix "z"); signatures are multibase-encoded raw bytes — their suite is
 * named by the verifying KeyRef.
 */
const BASE58BTC_MULTIBASE = /^z[1-9A-HJ-NP-Za-km-z]+$/;

export const keyRefSchema = z.string().regex(BASE58BTC_MULTIBASE);
export type KeyRef = z.infer<typeof keyRefSchema>;

export const signatureSchema = z.string().regex(BASE58BTC_MULTIBASE);
export type Signature = z.infer<typeof signatureSchema>;

export const multihashSchema = z.string().regex(BASE58BTC_MULTIBASE);
export type Multihash = z.infer<typeof multihashSchema>;

/**
 * A length-bounded array whose LENGTH is checked before any element is parsed.
 *
 * `z.array(element).min(a).max(b)` does not short-circuit: zod records the length issue and
 * then parses every element anyway, so validating a 349,524-element array against a bound of
 * 128 costs O(n) — measured at 2.3 seconds, against a replay the bound exists to keep under
 * a millisecond. On any schema reachable from an unauthenticated request body that inverts
 * the premise of the bound: rejecting the payload becomes far more expensive than the work
 * being guarded.
 *
 * Gating the element parse behind a length predicate makes the rejection O(1) — the same
 * measurement drops to 0.2 ms — and it is the same "length before shape" rule
 * `decodeGrantsHeader` applies by hand in `@kinnet/crypto`. Doing it here rather than at each
 * call site means every consumer of these schemas gets it, including ones that never think
 * to guard.
 *
 * Accept/reject semantics are unchanged: identical inputs succeed and fail as before. Only
 * the cost of a rejection changes.
 */
function boundedArray<T extends z.ZodTypeAny>(
  element: T,
  minItems: number,
  maxItems: number
): z.ZodPipe<z.ZodCustom<unknown[], unknown[]>, z.ZodArray<T>> {
  const withinBounds = (value: unknown): boolean =>
    Array.isArray(value) && value.length >= minItems && value.length <= maxItems;

  return z
    .custom<unknown[]>(withinBounds, {
      message: `expected an array of ${minItems} to ${maxItems} items`
    })
    .pipe(z.array(element));
}

/**
 * Group nonce (spec 014): multibase(base58btc) over exactly **32 random bytes** — raw bytes,
 * no multicodec tag. It makes every E2EE Conversation record byte-unique, so a creator cannot
 * re-sign byte-identical records (Ed25519 is deterministic, `createdAt` is creator-chosen) and
 * obtain the same MLS `group_id` for two distinct groups.
 *
 * The textual window — 32 characters (all bytes zero, each encoded as `1`) through 44
 * (58^44 > 2^256 ≥ 58^43) — is a **necessary** condition and was for a while the only one
 * checked, which is exactly how `z` + 32 `"2"`s (a 23-byte value) and `z` + 44 `"z"`s (33 bytes)
 * were accepted as nonces. It is kept as a cheap prefilter in front of the O(n^2) base58
 * decode, never as the check: {@link decodeCanonical} decides, and it demands the one canonical
 * form of exactly 32 bytes.
 */
export const GROUP_NONCE_BYTES = 32;

export const groupNonceSchema = z
  .string()
  .regex(/^z[1-9A-HJ-NP-Za-km-z]{32,44}$/)
  .refine((text) => isCanonical(text, multibaseBase58btc, { bytes: GROUP_NONCE_BYTES }), {
    message: `groupNonce must be the canonical multibase(base58btc) encoding of exactly ${GROUP_NONCE_BYTES} bytes (spec 014)`
  });
export type GroupNonce = z.infer<typeof groupNonceSchema>;

/**
 * Participant ID (spec 002): "pk_" + multibase(multihash(sha2-256, JCS(inception
 * establishment data))). Self-certifying and stable across key rotation.
 */
export const participantIdSchema = z.string().regex(/^pk_z[1-9A-HJ-NP-Za-km-z]+$/);
export type ParticipantId = z.infer<typeof participantIdSchema>;

export const participantTypeSchema = z.enum([
  "person",
  "organization",
  "team",
  "application",
  "service",
  "workflow",
  "agent"
]);
export type ParticipantType = z.infer<typeof participantTypeSchema>;

/**
 * Bounds on key-event and key-log size.
 *
 * Replaying a log costs Ed25519 verifications, and a key log is accepted from an
 * unauthenticated caller (spec 004's first-write bootstrap: the submitted log is what
 * resolves the keys the request signature is then checked against). Unbounded `keys`,
 * `signature`, and event-count arrays therefore let a small request body buy an
 * arbitrarily large amount of single-threaded CPU.
 *
 * These three numbers are the protocol-visible limit, and they are load-bearing for the
 * replay budget in `@kinnet/crypto`: spec 015's greedy walk performs at most one verification
 * per listed key, so a conforming log costs at most
 * `MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS`. `DEFAULT_MAX_KEY_LOG_SIGNATURE_VERIFICATIONS` is
 * exactly that product. `MAX_KEY_EVENT_SIGNATURES` still bounds bytes and parsing, but is no
 * longer a curve-cost multiplicand. Raising the event or key bounds requires re-deriving the
 * replay budget; raising only the signature bound does not.
 *
 * 8 keys and 8 signatures allow an M-of-N committee well beyond anything the network runs:
 * every identity this codebase can mint is 1-of-1, because `createIdentity` produces one
 * key and `rotateIdentity` preserves the count. 128 events is about a decade of monthly
 * rotations.
 */
export const MAX_KEY_EVENT_KEYS = 8;

/**
 * Signatures one signature-set record may carry — a revocation, grant, conversation or
 * device-set record.
 *
 * Equal to {@link MAX_KEY_EVENT_KEYS}, and for the same reason a key event refuses more
 * signatures than it lists keys: under threshold semantics a signature can only ever count
 * once, against one of the signer's own keys, and a signer cannot hold more keys than an
 * event may list. More signatures than that is meaningless — and it was the shape that made
 * the old threshold search expensive. Spec 015's current greedy walk performs at most one
 * verification per listed key after enforcing the exact signature count.
 *
 * This is a COUNT bound and nothing more. Whether every member of the set must verify is a
 * separate question (the canonical-signature-set decision) and is untouched here.
 */
export const MAX_RECORD_SIGNATURES = MAX_KEY_EVENT_KEYS;
export const MAX_KEY_EVENT_SIGNATURES = 8;
export const MAX_KEY_LOG_EVENTS = 128;

/**
 * Key-history log event (spec 003). Establishment data — seq, kind, keys, threshold,
 * next — is the event minus id and signature; the inception event's establishment data
 * is what the participant ID hashes.
 */
export const keyEventSchema = z
  // STRICT (spec 015 S6.3): a record carrying a key the schema does not define is invalid,
  // not silently stripped. A plain `z.object` strips, and a key event is digest-addressed —
  // `prior` names the previous event by digest — so a stripped key means one delivered byte
  // string and two different digests. `conversationSchema` has been strict for this reason
  // since 012; 015 generalizes it to every signature-set record.
  .strictObject({
    id: participantIdSchema,
    seq: z.string().regex(/^(0|[1-9][0-9]*)$/),
    prior: multihashSchema.nullable(),
    kind: z.enum(["icp", "rot"]),
    keys: boundedArray(keyRefSchema, 1, MAX_KEY_EVENT_KEYS),
    threshold: z.string().regex(/^[1-9][0-9]*$/),
    next: multihashSchema,
    signature: boundedArray(signatureSchema, 1, MAX_KEY_EVENT_SIGNATURES)
  })
  .superRefine((event, ctx) => {
    // Every check below is a comparison over data the element parse has already bounded to
    // MAX_KEY_EVENT_KEYS / MAX_KEY_EVENT_SIGNATURES entries, so all three are O(1) against
    // the bound and none of them re-walks an unbounded array. `boundedArray` is what makes
    // that true: it gates the element parse behind the length predicate.
    if (event.signature.length > event.keys.length) {
      // Spec 003's ratio rule. Under threshold semantics a signature can only ever count
      // once, against one of the event's own keys, so a larger set is meaningless. Spec 015's
      // `m = t` subsumes it (m = t <= n), but 003 states it separately with its own
      // diagnosis and this schema keeps that diagnosis: "3 signatures, 2 keys" tells an
      // operator more than "3 members against a threshold of 2".
      ctx.addIssue({
        code: "custom",
        path: ["signature"],
        message: "an event may not carry more signatures than it lists keys"
      });
    }
    if (new Set(event.keys).size !== event.keys.length) {
      // Spec 015 S0, and spec 003's _Events_ section states it at the record layer in as many words:
      // "a validator built from this section alone MUST reject such an event, not only a
      // replay implementation". Until now the rule existed in exactly one line of the
      // reference replay, so an implementation built from the schema admitted a state the
      // reference rejects. Compared on key VALUE — an index-based reading is what would let
      // one signature satisfy a threshold of two.
      ctx.addIssue({
        code: "custom",
        path: ["keys"],
        message: "an event may not list the same key twice (spec 003, spec 015 S0)"
      });
    }
    if (Number(event.threshold) > event.keys.length) {
      // Spec 015 S1: a threshold above the key count is unsatisfiable by construction, so the
      // STATE is invalid rather than merely unsatisfiable — accepting it only defers the
      // failure to every record ever checked against it. `threshold` is already pinned to
      // ^[1-9][0-9]*$ by the field schema above, so `Number` here cannot produce NaN, 0 or a
      // negative, and this comparison is the only part of S1 that concerns the state alone.
      ctx.addIssue({
        code: "custom",
        path: ["threshold"],
        message: "an event may not declare a threshold above its own key count (spec 015 S1)"
      });
    }
    if (event.signature.length !== Number(event.threshold)) {
      // Spec 015 S1's `m = t`, now decidable here because spec 003 settled which state a key
      // event is judged against: the one it carries. For an inception that state is what the
      // participant id hashes (002); for a rotation the previous event's `next` commits both
      // the key list AND the threshold, so `threshold` is the committed value rather than one
      // the rotating party chose. Either way the event's own `threshold` IS the threshold of
      // the state in question, which is what makes this comparison correct on one event.
      //
      // What a validator built from this schema alone CANNOT check is that the declared
      // threshold is the committed one — that needs the prior event, so it is a log-level
      // rule and lives in the replay. Such a validator is entitled to conclude "every event
      // carries exactly its declared threshold in signatures" and NOT "this rotation was
      // authorized"; spec 003 states that split where the rule is defined.
      ctx.addIssue({
        code: "custom",
        path: ["signature"],
        message: "an event must carry exactly its threshold in signatures (spec 015 S1)"
      });
    }
  });
export type KeyEvent = z.infer<typeof keyEventSchema>;

/**
 * A key-history log (spec 003): an inception event followed by rotations. Shape-valid
 * per this schema; chain, commitment, and signature validity require a replay.
 */
export const keyEventLogSchema = boundedArray(keyEventSchema, 1, MAX_KEY_LOG_EVENTS);
export type KeyEventLog = z.infer<typeof keyEventLogSchema>;

/**
 * STRICT, like every other signed record here (spec 001, _Record kinds are non-confusable_): a
 * profile carrying a key this schema does not define is rejected rather than silently stripped.
 * Stripping is what let one delivered byte string be two logical records — the signature is
 * checked over the stripped object, so an unknown key travelled unverified, and a record kind
 * was decided by which schema happened to be tried rather than by the record.
 */
export const participantProfileSchema = z.strictObject({
  id: participantIdSchema,
  type: participantTypeSchema,
  displayName: z.string().min(1),
  description: z.string().optional(),
  capabilities: z.array(z.string()).default([]),
  ownerId: participantIdSchema.optional(),
  verifiedDomains: z.array(z.string()).default([]),
  updatedAt: z.string().datetime(),
  signature: signatureSchema
});
export type ParticipantProfile = z.infer<typeof participantProfileSchema>;

/**
 * The transports a node advertises (spec 017).
 *
 * `"websocket"` was removed by 017: spec 013 §5 rejects WebSocket as a delivery surface — the
 * live surface is SSE over a signed GET, which inherits 004/011 request verification unchanged,
 * while a WebSocket upgrade would need its own signing profile for nothing the surface needs. No
 * route ever defined the value, so advertising it named a transport no conforming node serves.
 */
export const nodeTransportSchema = z.enum(["https", "webrtc"]);
export type NodeTransport = z.infer<typeof nodeTransportSchema>;

/** STRICT for the reason given on {@link participantProfileSchema}. */
export const participantNodeSchema = z.strictObject({
  id: z.string().min(1),
  participantId: participantIdSchema,
  label: z.string().min(1),
  endpoint: z.string().url().optional(),
  servedBy: participantIdSchema.optional(),
  publicKey: keyRefSchema,
  transports: z.array(nodeTransportSchema),
  updatedAt: z.string().datetime(),
  signature: signatureSchema
});
export type ParticipantNode = z.infer<typeof participantNodeSchema>;

/**
 * Revocation (spec 008): withdraws any signed record, named by the digest of its
 * complete signed form (the 003 digest rule). Permanent and monotonic — never itself
 * revoked. Signed per the revoker's threshold. Key events are out of scope: keys
 * leave the log by rotation, not revocation.
 */
// STRICT (spec 015 S6.3): a Revocation is named by what it revokes and is itself
// digest-addressed, so an unknown key must be rejected rather than stripped — a stripped key
// gives one delivered byte string two digests.
export const revocationSchema = z.strictObject({
  revokes: multihashSchema,
  issuerId: participantIdSchema,
  revokedAt: z.string().datetime(),
  reason: z.string().optional(),
  signature: boundedArray(signatureSchema, 1, MAX_RECORD_SIGNATURES)
});
export type Revocation = z.infer<typeof revocationSchema>;

/**
 * Ability (spec 009): a namespaced path; a parent path covers its descendants
 * ("directory" covers "directory/curate").
 */
export const abilitySchema = z.string().regex(/^[a-z0-9-]+(\/[a-z0-9-]+)*$/);
export type Ability = z.infer<typeof abilitySchema>;

/**
 * The ability that means "hold an MLS leaf that speaks for the subject" (spec 014).
 */
export const ABILITY_E2EE_LEAF = "e2ee/leaf";

/**
 * The ability to author a **self-departure** — a `remove` evidence record whose `members` is
 * exactly `[actor]` (spec 014, amended 2026-08-02).
 *
 * Pinned **outside** the `msg` namespace deliberately. `msg/conversation-update` is minted from
 * the envelope type by 012's generative rule, so every already-issued bare-`msg` umbrella covers
 * it (009 path-prefix cover) — and with it, unilateral self-expulsion authority. Splitting the
 * self-departure out under `msg` would have needed an exclusion rule inside the umbrella's cover
 * math; a sibling namespace needs none: `msg` does not cover `conversation/self-remove`, by the
 * same segment-boundary rule that makes `msg` cover `msg/send`.
 *
 * A delegated-signed self-departure therefore requires a chain covering this ability; bare `msg`
 * does not suffice. Issuing a self-remove-capable grant is a deliberate act, not a side effect of
 * an everyday session grant.
 */
export const ABILITY_CONVERSATION_SELF_REMOVE = "conversation/self-remove";

/**
 * The ability to enroll an inbox — `PUT /inboxes/:id` where `:id` is the chain's subject
 * (spec 011, amended 2026-08-03: delegable enrollment).
 *
 * Pinned **top-level**, outside `msg`, by the same segment-boundary rule that places
 * `conversation/self-remove` there: `msg` covers `msg/send` and never `inbox/enroll`, so no
 * everyday session grant confers enrollment by accident. A bare `inbox` umbrella buys nothing
 * either — the enrollment route demands this exact string, not a covering prefix, which is
 * what makes the vocabulary discipline enforceable at the wire rather than exhorted in prose.
 *
 * The route accepts **single-hop key-audience chains only**: one root grant self-issued by the
 * subject to a KeyRef, whose abilities contain this exact string. Single-hop is what makes the
 * authority bound real — a key-audience grant covering a non-`e2ee` ability must carry
 * `expiresAt` and `caveats.aud` (011 as amended by 014), and with no upstream link there is
 * nothing to re-mint a fresh bounded leaf from.
 */
export const ABILITY_INBOX_ENROLL = "inbox/enroll";

/**
 * The `e2ee`-namespace predicate (spec 014), pinned so two verifiers cannot differ.
 *
 * This ONE function is both halves of the rule: it decides whether a key-audience grant is
 * exempt from 011's `caveats.aud` requirement (a credential link has no request surface to
 * bind an audience to), and it decides whether a presented chain must be rejected as never
 * request-valid. The spec is emphatic that they be the same function over the same chain, so
 * no chain lands in a gap between them — an exemption test broader than the rejection test
 * would be a bypass.
 *
 * Note it is a namespace test, not a prefix test: `"e2eex"` is a different namespace and is
 * NOT an `e2ee` ability. Segment-boundary matching is 009's cover rule (`msg` covers
 * `msg/send`, never `msgx`).
 */
export function isE2eeAbility(ability: string): boolean {
  return ability === "e2ee" || ability.startsWith("e2ee/");
}

/**
 * Principal (spec 011): who may issue or receive a grant — a participant id (the
 * rotation-stable principal) or a bare spec-005 KeyRef (the disposable one, e.g. a
 * browser session key). The shapes are disjoint by construction: participant ids carry
 * the `pk_` prefix, KeyRefs are bare multibase. Verifiers MUST classify a principal
 * against exactly these two shapes and reject anything that matches neither.
 */
export const principalSchema = z.union([participantIdSchema, keyRefSchema]);
export type Principal = z.infer<typeof principalSchema>;

/**
 * The `aud` caveat (spec 011, the first standard caveat): the verifiers a grant link
 * may be presented to — one ParticipantId or a non-empty array of them. A child's aud
 * must be covered by its parent's effective aud (narrowing only); absent means
 * unrestricted.
 */
export const audCaveatSchema = z.union([participantIdSchema, z.array(participantIdSchema).min(1)]);
export type AudCaveat = z.infer<typeof audCaveatSchema>;

/**
 * Links one delegation chain may carry.
 *
 * Verifying a chain costs a key-log replay AND a signature walk over the issuer's whole key
 * history PER LINK, so an unbounded chain is unbounded work bought with one request header —
 * and the header arrives before the chain has proven anything. The honest worst case for a
 * no-candidate chain is
 * `MAX_GRANT_CHAIN_LINKS * 2 * MAX_KEY_LOG_EVENTS * MAX_KEY_EVENT_KEYS` verifications, so this
 * number is a direct multiplier on what a verifier must be willing to spend per request.
 *
 * 4, reduced from 8. Spec 011's shapes are shallow — subject to application to service is
 * three links — so 4 carries every shape the specs describe with one spare, while halving the
 * verification ceiling. A longer chain is not a capability anyone has asked for, and buying
 * depth nobody uses with seconds of blocked CPU per inbound request is the wrong trade. A local
 * allowance cannot enable more depth: both the schema and the resolver enforce this hard cap,
 * so raising it requires a protocol change and a fresh derivation of the composed allowance.
 */
export const MAX_GRANT_CHAIN_LINKS = 4;

/**
 * Abilities one grant link may carry. Abilities are namespaced paths and a parent covers its
 * descendants, so a link needing more than a handful of distinct roots is already unusual;
 * 32 is far above any shape spec 009 or 011 describes. Bounded because a grant chain arrives
 * in a request header, before anything has been proven.
 */
export const MAX_GRANT_ABILITIES = 32;

/**
 * Grant (spec 009, principals widened per spec 011): one link in a UCAN-aligned
 * capability-delegation chain. subjectId is constant along the chain and always a
 * participant; the root link is self-issued (issuerId == subjectId, hence the root
 * issuer is always a participant); proof names the parent link by digest (003 digest
 * rule). Caveats only narrow and fail closed: a verifier that cannot evaluate one
 * rejects.
 *
 * Cross-field validity (spec 011, schema-enforced so independent verifiers agree the
 * record is malformed, not merely unwelcome): a key-audience grant MUST carry
 * `expiresAt` (a bare key has no log — expiry is the only planned end it can have) and
 * MUST carry a well-formed `caveats.aud`. A present `caveats.aud` must be well-formed
 * for any audience.
 *
 * Amended by spec 014 for **credential links** — a grant every one of whose abilities
 * satisfies {@link isE2eeAbility}:
 *
 * - `caveats` MUST be empty. A caveat a verifier cannot evaluate fails closed (009 rule
 *   6), and inside an MLS group a fail-closed rejection is a permanent split, so 014
 *   closes the shape at the schema rather than relying on a literal reading of an
 *   exclusion. A credential is presented to no verifier and exercised against no surface,
 *   so it has nothing to narrow.
 * - the `caveats.aud` requirement is lifted for a key audience: there is no request
 *   surface to bind it to, the set of future counterparty verifiers is unknowable at
 *   issuance, and the namespace rule (an `e2ee` chain is never request-valid) is the bound
 *   the caveat would have been. `expiresAt` is NOT lifted — a bare key still has no log.
 *
 * A grant **mixing** `e2ee` and non-`e2ee` abilities is not a credential link and gets no
 * exemption: 011's rules apply to it unchanged.
 */
export const grantSchema = z
  // STRICT (spec 015 S6.3). A Grant is digest-addressed twice over: a child names its parent
  // by `proof`, and 008 keys revocation by the same digest. A stripped unknown key is
  // therefore a second digest for one delivery, which is exactly the malleability that
  // defeated revocation-by-digest.
  .strictObject({
    subjectId: participantIdSchema,
    issuerId: principalSchema,
    audienceId: principalSchema,
    abilities: boundedArray(abilitySchema, 1, MAX_GRANT_ABILITIES),
    caveats: z.record(z.string(), z.unknown()),
    proof: multihashSchema.nullable(),
    issuedAt: z.string().datetime(),
    expiresAt: z.string().datetime().optional(),
    signature: boundedArray(signatureSchema, 1, MAX_RECORD_SIGNATURES)
  })
  .superRefine((grant, ctx) => {
    const keyAudience = !grant.audienceId.startsWith("pk_");
    // A credential link (spec 014): every ability in the `e2ee` namespace. `abilities` is
    // non-empty by schema, so `every` cannot be vacuously true here.
    const credentialLink = grant.abilities.every(isE2eeAbility);
    if (keyAudience && grant.expiresAt === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "A key-audience grant must carry expiresAt (spec 011)"
      });
    }
    if (credentialLink && Object.keys(grant.caveats).length > 0) {
      ctx.addIssue({
        code: "custom",
        path: ["caveats"],
        message: "An e2ee credential link must carry empty caveats (spec 014)"
      });
    }
    if (keyAudience && !credentialLink && grant.caveats["aud"] === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["caveats", "aud"],
        message: "A key-audience grant must carry the aud caveat (spec 011)"
      });
    }
    if (
      grant.caveats["aud"] !== undefined &&
      !audCaveatSchema.safeParse(grant.caveats["aud"]).success
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["caveats", "aud"],
        message: "caveats.aud must be a ParticipantId or a non-empty array of them (spec 011)"
      });
    }
  });
export type Grant = z.infer<typeof grantSchema>;

/**
 * Relationship (spec 001's non-confusability rule, and the 2026-08 review's finding 6e).
 *
 * STRICT is what makes a Relationship distinguishable from a {@link claimSchema} Claim. Open,
 * both schemas stripped what they did not define, so a single object carrying the union of the
 * two field sets parsed as **both**, and `verifyRelationship` and `verifyClaim` both returned
 * valid over one signature and one digest — one signing act, two records, and `canonicalDigest`
 * has no domain separation to tell them apart. Closed, `predicate`/`objectId` are unknown keys to
 * the Claim schema and `claimType`/`value` are unknown keys here, so the hybrid is rejected by
 * both. `test/record-kinds.test.ts` is the enforcement, over every record kind, not just this pair.
 */
export const relationshipSchema = z.strictObject({
  id: z.string().min(1),
  subjectId: participantIdSchema,
  predicate: z.string().min(1),
  objectId: participantIdSchema,
  issuedBy: participantIdSchema,
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime().optional(),
  signature: signatureSchema
});
export type Relationship = z.infer<typeof relationshipSchema>;

/** STRICT — the other half of the Claim/Relationship confusion; see {@link relationshipSchema}. */
export const claimSchema = z.strictObject({
  id: z.string().min(1),
  subjectId: participantIdSchema,
  claimType: z.string().min(1),
  value: z.unknown(),
  issuedBy: participantIdSchema,
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime().optional(),
  signature: signatureSchema
});
export type Claim = z.infer<typeof claimSchema>;

/**
 * MessageEnvelope (spec 010, amended by 012). The optional `conversationId` field associates
 * the envelope with a Conversation record by its digest id; it is signed like every other
 * field, so the association is exactly as tamper-proof as the message. An envelope without
 * `conversationId` is a bare message — the machine lane keeps working unchanged.
 */
export const messageEnvelopeSchema = z.strictObject({
  id: z.string().min(1),
  from: participantIdSchema,
  to: participantIdSchema,
  createdAt: z.string().datetime(),
  type: z.string().min(1),
  payload: z.unknown(),
  conversationId: multihashSchema.optional(),
  signature: signatureSchema
});
export type MessageEnvelope = z.infer<typeof messageEnvelopeSchema>;

/**
 * Conversation record (spec 012): a grouping record signed by its creator (or, in delegated
 * mode, a session key delegated to act for them). The record's identity is the spec-003
 * digest of its complete signed bytes — every member holds the same bytes and derives the
 * same id with no coordination. The schema is **strict** (`.strict()`): a record carrying
 * any key not defined here is rejected rather than silently stripped, so two implementations
 * cannot end up digesting the same logical record to different ids. Membership is fixed at
 * creation on the machine lane; spec 014 lifts that for the E2EE lane (see
 * {@link conversationUpdateSchema}).
 *
 * Spec 014 adds two OPTIONAL fields, under the same signature: `lane` and `groupNonce`. Both
 * absent is the machine lane, so every pre-014 record stays valid and keeps its digest.
 *
 * Cross-field rules (spec 012, schema-enforced so independent verifiers agree the record is
 * malformed, not merely unwelcome):
 *
 * - `participants` MUST include `creator`, contain no duplicates, and be sorted by string
 *   comparison over UTF-8 codepoints (JavaScript's default `<` on strings agrees with a
 *   UTF-8-codepoint sort for the base58btc alphabet participant ids live in — no surrogate
 *   pairs, no combining characters).
 * - (spec 014) `lane === "e2ee"` ⇒ `groupNonce` present; `lane` absent ⇒ `groupNonce` absent.
 *   `lane` MUST be OMITTED for the machine lane — never `"machine"`, never `null` — and a
 *   machine-lane record MUST NOT carry a stray nonce, because either would be a second
 *   byte-form of the same logical conversation and 012's digest identity admits only one.
 */
/**
 * Participants one conversation record may name. Unchanged in value from the `.max(256)` it
 * replaces — named only so the bound reads the same way as the key-log ones and so the
 * length-before-shape treatment is visibly deliberate rather than incidental.
 */
export const MAX_CONVERSATION_PARTICIPANTS = 256;

export const conversationSchema = z
  .strictObject({
    creator: participantIdSchema,
    participants: boundedArray(participantIdSchema, 2, MAX_CONVERSATION_PARTICIPANTS),
    createdAt: z.string().datetime(),
    title: z.string().min(1).max(256).optional(),
    lane: z.literal("e2ee").optional(),
    groupNonce: groupNonceSchema.optional(),
    signature: boundedArray(signatureSchema, 1, MAX_RECORD_SIGNATURES)
  })
  .superRefine((record, ctx) => {
    if (!record.participants.includes(record.creator)) {
      ctx.addIssue({
        code: "custom",
        path: ["participants"],
        message: "participants must include creator (spec 012)"
      });
    }
    // Reject duplicates: membership must be unique.
    if (new Set(record.participants).size !== record.participants.length) {
      ctx.addIssue({
        code: "custom",
        path: ["participants"],
        message: "participants must be unique (spec 012)"
      });
    }
    // Sorted by string comparison — spec 012 requires a stable ordering so two members with
    // the same logical set canonicalize to the same bytes and therefore the same id.
    for (let i = 1; i < record.participants.length; i += 1) {
      if (record.participants[i - 1]! >= record.participants[i]!) {
        ctx.addIssue({
          code: "custom",
          path: ["participants"],
          message: "participants must be sorted ascending (spec 012)"
        });
        break;
      }
    }
    // Lane / nonce coupling (spec 014). The lane is declared in the signed record and is
    // immutable for the life of the conversation, so "the same conversation, downgraded" is
    // not expressible: tampering with the lane changes the id.
    if (record.lane === "e2ee" && record.groupNonce === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["groupNonce"],
        message: "an e2ee conversation must carry groupNonce (spec 014)"
      });
    }
    if (record.lane === undefined && record.groupNonce !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["groupNonce"],
        message: "a machine-lane conversation (lane omitted) must not carry groupNonce (spec 014)"
      });
    }
  });
export type Conversation = z.infer<typeof conversationSchema>;

/**
 * Adds the codepoint-sorted, duplicate-free set rules spec 014's evidence record puts on both
 * `members` and `leaves`, on 012's `participants` precedent and for the same reason: a canonical
 * order is what makes two members' byte-forms of the same logical set identical.
 */
function refineSortedUniqueSet(
  values: readonly string[],
  field: string,
  ctx: z.RefinementCtx
): void {
  if (new Set(values).size !== values.length) {
    ctx.addIssue({
      code: "custom",
      path: [field],
      message: `${field} must be unique (spec 014)`
    });
  }
  for (let i = 1; i < values.length; i += 1) {
    if (values[i - 1]! >= values[i]!) {
      ctx.addIssue({
        code: "custom",
        path: [field],
        message: `${field} must be sorted ascending (spec 014)`
      });
      break;
    }
  }
}

/**
 * ConversationUpdate (spec 014): the membership-change **evidence** record — an authorization
 * ("the participant authorizes this change"), never an ordering ("this change came after that
 * one"). MLS is the only orderer; the record layer never orders anything. Hence no `seq`, no
 * `prior`, no chain: each record is independent and self-contained, signed **by the participant**
 * (012's two modes) and never by an MLS leaf, which is what lets a participant who has lost every
 * device still author `device-remove` for the lost leaves.
 *
 * Strict/closed like {@link conversationSchema}: it travels as `pn/conversation-update` and is
 * digest-identified, so an unknown key is rejected rather than silently stripped.
 *
 * The schema enforces **well-formedness only**. Everything lane- or conversation-conditional —
 * that evidence is an E2EE-lane mechanism, what `leaves` mean against the group's tree, the
 * authorization rules of 014's rule 2, and the epoch's one-shot binding to a commit — is a
 * delivery/validation rule evaluated where the Conversation record and the group state are held.
 * This schema cannot see either, and spec 014 says so explicitly.
 *
 * Cross-field rules:
 *
 * - `members` and `leaves` are each non-empty, unique, and sorted by codepoint.
 * - `kind` of `device-add`/`device-remove` ⇒ `members` is exactly `[actor]`: a participant governs
 *   their own device set and nobody else's, so a device record can never introduce a participant.
 * - `epoch` is decimal with no leading zeros. Load-bearing, not cosmetic: epoch **equality** is the
 *   one-shot replay defense (a record authorizes exactly one commit at exactly one point in MLS's
 *   own history), and `"01"` vs `"1"` would be two records claiming one epoch.
 * - `actor` need NOT appear in `members`: on `add`/`remove` the actor is the creator, acting on
 *   others.
 */
export const conversationUpdateSchema = z
  .strictObject({
    conversationId: multihashSchema,
    kind: z.enum(["add", "remove", "device-add", "device-remove"]),
    members: z.array(participantIdSchema).min(1),
    leaves: z.array(keyRefSchema).min(1),
    actor: participantIdSchema,
    epoch: z.string().regex(/^(0|[1-9][0-9]*)$/),
    createdAt: z.string().datetime(),
    signature: boundedArray(signatureSchema, 1, MAX_RECORD_SIGNATURES)
  })
  .superRefine((record, ctx) => {
    refineSortedUniqueSet(record.members, "members", ctx);
    refineSortedUniqueSet(record.leaves, "leaves", ctx);
    if (record.kind === "device-add" || record.kind === "device-remove") {
      if (record.members.length !== 1 || record.members[0] !== record.actor) {
        ctx.addIssue({
          code: "custom",
          path: ["members"],
          message: "a device-add/device-remove record's members must be exactly [actor] (spec 014)"
        });
      }
    }
  });
export type ConversationUpdate = z.infer<typeof conversationUpdateSchema>;

/**
 * The chain half of a `(record, chain)` unit (spec 014, on 011's precedent): the leaf-first
 * grant chain that authorizes a **delegated-signed** record, carried alongside the record and
 * never inside it.
 *
 * `.min(1)` because an empty array is not a weaker chain, it is a malformed one: a
 * present-but-empty `chain` would claim delegated mode and then name no delegation, which no
 * verifier can distinguish from a truncation. Absent means owner mode; present means at least
 * a leaf.
 */
const recordChainSchema = boundedArray(grantSchema, 1, MAX_GRANT_CHAIN_LINKS);

/**
 * `pn/conversation` payload (spec 012, amended by 014): the `(record, chain)` unit —
 * {@link conversationSchema} plus, when the record is delegated-signed, the chain that
 * authorizes it.
 *
 * See {@link conversationUpdatePayloadSchema} for the design; these are the same unit over
 * different records, so a custodial creator's conversation record is re-deliverable by any
 * member — and by the creator from a later session — exactly as their evidence is.
 */
export const conversationPayloadSchema = z.strictObject({
  record: conversationSchema,
  chain: recordChainSchema.optional()
});
export type ConversationPayload = z.infer<typeof conversationPayloadSchema>;

/**
 * `pn/conversation-update` payload (spec 014): the evidence record as a `(record, chain)`
 * unit — the record, and, when it is delegated-signed, the leaf-first grant chain whose
 * abilities cover `msg/conversation-update` (or, for a self-departure,
 * {@link ABILITY_CONVERSATION_SELF_REMOVE}).
 *
 * **The chain sits alongside the record, never inside it.** Record identity is unchanged: the
 * record's id is the spec-003 digest of `record` alone, so one record carries one id whether
 * or not a chain travels with it. That is the KeyPackage-credential precedent (014: the
 * publication carries the credential _alongside_ the package), and it is what lets two members
 * who received the same record by different routes — authored delivery, a re-delivery, a
 * joiner's relayed history — agree on the digests a commit binding names.
 *
 * Both objects are **strict**: an unknown key at the unit level is rejected rather than
 * silently stripped, and `record` stays strict underneath, so a chain smuggled _into_ the
 * record — the one shape that would change its id — is malformed, not merely unwelcome.
 *
 * The wrapper is not optional: a bare record is not a valid payload. The unit, not the
 * envelope, is what re-verifies, which is what lets any member re-deliver a delegated-signed
 * record in either transport mode.
 */
export const conversationUpdatePayloadSchema = z.strictObject({
  record: conversationUpdateSchema,
  chain: recordChainSchema.optional()
});
export type ConversationUpdatePayload = z.infer<typeof conversationUpdatePayloadSchema>;

/**
 * Reserved envelope-type prefix (spec 012): a `type` beginning with `pn/` names a
 * protocol-defined payload. 010's "sender-defined `type`" becomes "sender-defined, except
 * this prefix". Unknown reserved types fail closed — a node MUST reject a `pn/…`
 * envelope whose name it does not recognize rather than storing it as opaque payload.
 */
export const PN_RESERVED_PREFIX = "pn/";
export const PN_TYPE_CONVERSATION = "pn/conversation";

/**
 * The E2EE lane's reserved types (spec 014). By 012's generative ability rule each requires the
 * matching `msg/<name>` ability: `msg/conversation-update`, `msg/mls`, `msg/welcome`.
 */
export const PN_TYPE_CONVERSATION_UPDATE = "pn/conversation-update";
export const PN_TYPE_MLS = "pn/mls";
export const PN_TYPE_WELCOME = "pn/welcome";

/**
 * The set of `pn/…` types this build of the protocol package knows how to validate.
 * A node's reserved-type registry uses this to distinguish "unknown to the protocol" from
 * "known payload, validate it" — the former fails closed.
 */
export const KNOWN_RESERVED_TYPES = new Set<string>([
  PN_TYPE_CONVERSATION,
  PN_TYPE_CONVERSATION_UPDATE,
  PN_TYPE_MLS,
  PN_TYPE_WELCOME
]);

/**
 * base64url without padding — the house encoding (011's `1:` grants profile). Unpadded is the
 * only accepted form: a padded and an unpadded encoding of the same bytes would be two byte-forms
 * of one payload, and these envelopes are digested like every other record.
 *
 * The alphabet regex is a prefilter; canonicity is decided by {@link decodeCanonical}. Alphabet
 * alone accepted `"A"` — a lone character encodes no whole byte — and `"AB"`, whose four bits
 * past the single byte a permissive decoder folds onto the byte `"AA"` gives, so one payload had
 * two textual forms inside a signed, digest-identified envelope. `@kinnet/sdk`'s decoder has
 * refused both since it was written; this is the schema catching up to it.
 *
 * No maximum: an MLS message is as large as its group, and the bound that matters is the
 * transport's body limit rather than a number invented here. The canonicity check is linear in
 * the input, so it costs the same as the alphabet scan it follows.
 */
const BASE64URL_NOPAD = /^[A-Za-z0-9_-]+$/;

const opaqueBase64UrlSchema = z
  .string()
  .regex(BASE64URL_NOPAD)
  .refine((text) => isCanonical(text, base64UrlNoPad), {
    message: "must be the canonical unpadded base64url encoding of at least one byte (spec 014)"
  });

/**
 * `pn/mls` payload (spec 014): one MLS `PrivateMessage` — commit, proposal, or application
 * message. The bytes are **opaque to the node**, which never validates MLS internals; this schema
 * pins the envelope-level shape only.
 */
export const mlsPayloadSchema = z.strictObject({
  mlsMessage: opaqueBase64UrlSchema
});
export type MlsPayload = z.infer<typeof mlsPayloadSchema>;

/**
 * `pn/welcome` payload (spec 014): the MLS `Welcome` delivered to a newly added participant,
 * carrying the `ratchet_tree` extension so a joiner needs no out-of-band tree fetch. Opaque to the
 * node, exactly like {@link mlsPayloadSchema}.
 */
export const welcomePayloadSchema = z.strictObject({
  welcome: opaqueBase64UrlSchema
});
export type WelcomePayload = z.infer<typeof welcomePayloadSchema>;

/**
 * Parses a JSON body while rejecting objects that carry duplicate keys (spec 012). Standard
 * JSON parsers resolve `{"a":1,"a":2}` last-wins, but last-wins differs across parsers, so
 * two implementations digesting the same bytes could end up with different logical records
 * and different ids. This parser refuses those bytes rather than resolving them: a signed
 * record whose identity is its digest cannot afford ambiguity in its own source form.
 *
 * Implementation: run the normal parser first (rejects malformed JSON), then walk the source
 * text with a small scanner and count keys per open object at every depth. Every character
 * class we care about — `{`, `}`, `[`, `]`, and `"…":` — is unambiguous once strings are
 * skipped, so the second pass is linear and doesn't need to reproduce the parser's grammar.
 */
/**
 * WHERE THIS IS APPLIED (spec 015 S6.1).
 *
 * S6.1's MUST is on "a verifier receiving a signature-set record". It is stated per CALL SITE
 * rather than enforceable by a type, because the rule is about BYTES and every schema in this
 * file sees an already-resolved object — `z.strictObject` cannot stand in for it, since by the
 * time a schema runs the duplicate has silently been decided last-wins. So the guarantee is
 * only as complete as the set of byte paths that route through this parser, and an unlisted
 * delivery is how the rule goes unmet.
 *
 * In this repository the paths that turn bytes from outside the process into a record that is,
 * or is lifted into, a signature set are `@kinnet/verify`'s discovery view (the one `getJson`
 * every record it returns passes through — key logs, revocations, relationships, claims; the
 * host is untrusted by the module's own contract) and `@kinnet/crypto`'s `PN-Grants` header
 * decoder (the chain on every delegated request, read before anything has been proven). Any
 * consumer of this package — an SDK, a node, a discovery service, an operator tool reading a
 * grants file — carries the same obligation on every byte path that reaches a record schema,
 * including unauthenticated bootstrap bodies that are replayed to discover the keys a request
 * signature is then checked against.
 *
 * Deliberately outside the class, so that "not wired" is a judgement on the record rather than
 * an omission: bytes a process itself wrote and integrity-protected (row deserializers, its own
 * MAC'd tokens, decrypted key material); page cursors, build info and configuration, which are
 * not records; SSE event framing and decrypted MLS application content, which feed no record
 * schema (MLS plaintext is authenticated by the group); and `messageEnvelopeSchema` deliveries
 * — the nearest miss, called out rather than assumed: an envelope carries a SCALAR signature,
 * nothing lifts it into a set, and it is identified by its creator-chosen `envelope.id` rather
 * than by a digest, so S6.1's stated hazard (two digests for one delivery) does not arise.
 * The same parse hygiene would still be defensible there; widening 015's scope to reach it is
 * a spec question, not a patch.
 */
/**
 * Decode content octets as UTF-8, refusing anything that is not well-formed UTF-8.
 *
 * The companion to {@link parseJsonStrict} for the byte-to-text step that precedes it, and
 * strict for the same reason. `TextDecoder`'s default is lossy in one direction only: every
 * malformed sequence becomes U+FFFD, so `FF` and the three bytes that legitimately encode
 * U+FFFD arrive as the same character. Anywhere a record is built from a delivery — and a
 * request signature covers a digest of the DELIVERED OCTETS (RFC 9530), not of their decoded
 * form — a lenient decode would build the record from a body nobody sent, and two
 * implementations reading the same bytes could disagree about what was written.
 *
 * JSON is defined over UTF-8 (RFC 8259 §8.1), so refusing here costs no legitimate delivery:
 * bytes that do not decode were never a record to begin with. Throws a `TypeError`, which
 * the callers' existing `catch` around parsing already handles as a malformed body.
 */
export function decodeUtf8Strict(octets: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(octets);
}

export function parseJsonStrict(text: string): unknown {
  const parsed: unknown = JSON.parse(text);
  assertNoDuplicateKeys(text);
  return parsed;
}

function isWhitespace(ch: string | undefined): boolean {
  return ch === " " || ch === "\t" || ch === "\n" || ch === "\r";
}

/**
 * Scans a well-formed JSON source and throws if any object literal contains a duplicate
 * top-level key. Called after {@link parseJsonStrict}'s initial parse guarantees the text
 * is well-formed. Objects are tracked as their own frames; array frames are pushed too so
 * that a key inside a nested object attaches to the correct enclosing object rather than a
 * sibling array's parent.
 */
function assertNoDuplicateKeys(raw: string): void {
  type Frame = { kind: "object"; keys: Set<string> } | { kind: "array" };
  const stack: Frame[] = [];
  let index = 0;
  const len = raw.length;

  while (index < len) {
    const ch = raw[index]!;
    if (ch === '"') {
      // Read the string literal, then decide whether it's an object key (next non-ws is `:`).
      const start = index;
      index += 1;
      let escape = false;
      while (index < len) {
        const c = raw[index]!;
        if (escape) {
          escape = false;
        } else if (c === "\\") {
          escape = true;
        } else if (c === '"') {
          index += 1;
          break;
        }
        index += 1;
      }
      let peek = index;
      while (peek < len && isWhitespace(raw[peek])) {
        peek += 1;
      }
      const top = stack[stack.length - 1];
      if (raw[peek] === ":" && top && top.kind === "object") {
        const key = JSON.parse(raw.slice(start, index)) as string;
        if (top.keys.has(key)) {
          throw new Error(`duplicate key ${JSON.stringify(key)} in JSON object`);
        }
        top.keys.add(key);
      }
      continue;
    }
    if (ch === "{") {
      stack.push({ kind: "object", keys: new Set() });
    } else if (ch === "[") {
      stack.push({ kind: "array" });
    } else if (ch === "}" || ch === "]") {
      stack.pop();
    }
    index += 1;
  }
}
