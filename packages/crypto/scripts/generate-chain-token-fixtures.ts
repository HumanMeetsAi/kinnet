/**
 * Regenerates the committed chain access token conformance vectors for the OAuth
 * chain-access-token profile: one self-issued, audience-bound, attenuated grant link, presented
 * as a bearer credential.
 *
 * The token IS the credential: `"pnc1." + base64url( UTF8( JSON.stringify(chain) ) )`, handed to
 * an OAuth client as its `access_token` and decoded by whatever resource server it is presented
 * to. There is no introspection endpoint to ask, so every implementation that reads one has to
 * agree, from the bytes alone, on which tokens are readable at all — and it has to disagree in
 * the same ORDER, because the guards are not independent. The link cap in particular is checked
 * before any element is parsed: a token whose payload holds five malformed links must be refused
 * for its length, not spend a schema parse per link deciding that. That ordering is not visible
 * in a verdict, so `refused — five links, none of them shape-valid` below carries five
 * structurally invalid elements — an implementation that parses elements first refuses it for the
 * wrong reason, and the recorded error says which.
 *
 * The accepted vectors are realistically signed: each link is a genuine Ed25519 signature over
 * the spec-001 signing input, minted from deterministic seeds, and each child's `proof` is the
 * spec-003 digest of its parent. The codec does not check any of that — it is a codec — but a
 * fixture of hand-typed placeholder grants would let a reader mistake "this decodes" for "this
 * is a chain", and would not catch a decoder that quietly reordered or rewrote links.
 *
 * Run from the repo root (after `pnpm build`). BOTH commands, in order — this script writes
 * `JSON.stringify(…, null, 2)` and the committed file is prettier-formatted, so skipping the
 * second step leaves a diff that is pure formatting and makes the fixture look
 * non-reproducible:
 *
 *   pnpm exec tsx packages/crypto/scripts/generate-chain-token-fixtures.ts
 *   pnpm exec prettier --write packages/crypto/test/fixtures/chain-token-vectors.json
 */
import { writeFileSync } from "node:fs";

import { base64urlnopad } from "@scure/base";

import {
  canonicalDigest,
  createIdentity,
  decodeChainAccessToken,
  encodeChainAccessToken,
  encodeKeyRef,
  keyLogAnchor,
  signThresholdRecord,
  verifyThresholdRecord,
  type Identity
} from "@kinnet/crypto";
import { grantSchema, MAX_GRANT_CHAIN_LINKS, type Grant, type Principal } from "@kinnet/protocol";

const encoder = new TextEncoder();

const CODES: Record<string, string> = {
  unsupported_prefix:
    "The token does not begin with `pnc1.`. The prefix names the encoding, so a missing, " +
    "differently-cased or future prefix is refused outright rather than guessed at — including " +
    "the PN-Grants header's `1:`, which carries a byte-identical payload behind a different " +
    "delivery and must not be interchangeable with a bearer token.",
  payload_not_base64url:
    "The bytes after the prefix are not base64url without padding. Padding characters and the " +
    "standard-base64 alphabet are outside this profile, so a token that merely looks decodable " +
    "is still refused.",
  payload_not_utf8_json:
    "The payload does not decode to well-formed UTF-8 carrying strict JSON. Strict means spec " +
    "015 S6.1: a duplicate object key at any depth is refused rather than resolved, because " +
    "last-wins and first-wins are both defensible and a Grant's digest is what its child's " +
    "`proof` names and what spec 008 keys its revocation by.",
  payload_not_nonempty_array:
    "The payload parses but is not a JSON array with at least one element. A bare grant object " +
    "is not a one-link chain, and an empty chain authorizes nothing while looking like a token.",
  chain_too_long:
    "The array carries more than MAX_GRANT_CHAIN_LINKS links. Checked on the DECODED LENGTH " +
    "before any element is parsed: verifying a chain replays the issuer's key log per link, so " +
    "the depth is work the presenter chooses, and it is chosen before anything has been proven.",
  element_not_a_grant:
    "The chain is the right shape but an element is not a shape-valid Grant per spec 011's " +
    "closed schema — an undefined key, or a key-audience link without `expiresAt`. Every " +
    "element is parsed, not just the leaf."
};

type Vector = {
  name: string;
  /** What this vector pins, and what it deliberately does not. */
  why: string;
  /** The token exactly as presented. The ONLY input a conforming implementation reads. */
  token: string;
  /** Whether a conforming decode yields a chain. */
  accept: boolean;
  /** Accepted only: the exact UTF-8 JSON the payload decodes to, before any parsing. */
  payloadJson: string | null;
  /** Accepted only: the chain a conforming decode yields, leaf first. */
  chain: Grant[] | null;
  /** Accepted only: the key ref that signed link i, so the signatures are checkable. */
  signerKeys: string[] | null;
  /** Refused only: the normative rejection class (see `codes`). */
  rejection: string | null;
  /**
   * Refused only, and only where the CODEC refuses: the reference implementation's exact throw,
   * recorded so this repo's test can assert it byte for byte, NOT as a wire contract another
   * implementation must reproduce. Null for `element_not_a_grant`, whose text belongs to the
   * schema library rather than to this profile — conform to `rejection`, not to the English.
   */
  error: { name: string; message: string } | null;
  /** Refused with `element_not_a_grant`: the index of the first element the schema refuses. */
  invalidElementIndex: number | null;
};

// --------------------------------------------------------------------------------------------
// Deterministic identities. Seeds, not randomness: the committed token strings must be
// reproducible byte for byte by re-running this script.
// --------------------------------------------------------------------------------------------

const identity = (fill: number): Identity =>
  createIdentity({
    currentSeed: new Uint8Array(32).fill(fill),
    nextSeed: new Uint8Array(32).fill(fill + 1)
  });

/** The human whose consent mints the chain. */
const person = identity(11);
/** The MCP resource the token is addressed to — a participant audience, never a bare key. */
const resource = identity(21);
/** The organization at the root of the longer chains; the subject every link names. */
const org = identity(31);
const admin = identity(41);
const team = identity(51);
const agent = identity(61);

const ISSUED_AT = "2026-08-14T09:00:00.000Z";
const EXPIRES_AT = "2026-08-14T10:00:00.000Z";

type Link = {
  subjectId: string;
  issuer: Identity;
  audienceId: Principal;
  abilities: string[];
  caveats?: Record<string, unknown>;
  /** The parent link, leaf-first order's next element. Null at the root. */
  parent?: Grant;
};

/** Mints one signed link: 1-of-1 over the spec-001 signing input, `proof` naming the parent. */
function link(spec: Link): Grant {
  const unsigned = {
    subjectId: spec.subjectId,
    issuerId: spec.issuer.id,
    audienceId: spec.audienceId,
    abilities: spec.abilities,
    caveats: spec.caveats ?? {},
    proof: spec.parent === undefined ? null : canonicalDigest(spec.parent),
    // Spec 016: a participant-issued link names the key state it is signed under. Every issuer
    // here signs with its current key, so the anchor is its log's tip.
    anchor: keyLogAnchor(spec.issuer.log),
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT
  };
  return grantSchema.parse(signThresholdRecord(unsigned, [spec.issuer.currentKeys[0]!.secretKey]));
}

const signerRef = (signer: Identity): string => encodeKeyRef(signer.currentKeys[0]!.publicKey);

// --------------------------------------------------------------------------------------------
// The chains.
// --------------------------------------------------------------------------------------------

/** The profile exactly: one self-issued link, resource audience, aud-bound, ticked scopes only. */
const consentChain = [
  link({
    subjectId: person.id,
    issuer: person,
    audienceId: resource.id,
    abilities: ["photos/read", "photos/write"],
    caveats: { aud: resource.id }
  })
];

/** The org-rooted shape the profile anticipates: root grant, then the consented attenuation. */
const orgRoot = link({
  subjectId: org.id,
  issuer: org,
  audienceId: admin.id,
  abilities: ["photos"],
  caveats: { aud: [resource.id] }
});
const delegatedChain = [
  link({
    subjectId: org.id,
    issuer: admin,
    audienceId: resource.id,
    abilities: ["photos/read"],
    caveats: { aud: resource.id },
    parent: orgRoot
  }),
  orgRoot
];

/** Four links: the cap is INCLUSIVE, which only a chain sitting on it can state. */
const capRoot = orgRoot;
const capSecond = link({
  subjectId: org.id,
  issuer: admin,
  audienceId: team.id,
  abilities: ["photos"],
  caveats: { aud: [resource.id] },
  parent: capRoot
});
const capThird = link({
  subjectId: org.id,
  issuer: team,
  audienceId: agent.id,
  abilities: ["photos/read"],
  caveats: { aud: [resource.id] },
  parent: capSecond
});
const capLeaf = link({
  subjectId: org.id,
  issuer: agent,
  audienceId: resource.id,
  abilities: ["photos/read"],
  caveats: { aud: resource.id },
  parent: capThird
});
const cappedChain = [capLeaf, capThird, capSecond, capRoot];

if (cappedChain.length !== MAX_GRANT_CHAIN_LINKS) {
  throw new Error(
    `The capped chain has ${cappedChain.length} links but the cap is ${MAX_GRANT_CHAIN_LINKS}`
  );
}

// --------------------------------------------------------------------------------------------
// Vector construction. Accepted vectors are built by the codec and then read back; refused ones
// are built as raw strings and their refusal is captured from the codec itself.
// --------------------------------------------------------------------------------------------

const payload = (value: unknown): string =>
  base64urlnopad.encode(encoder.encode(JSON.stringify(value)));

function accepted(name: string, why: string, chain: Grant[], signers: Identity[]): Vector {
  const token = encodeChainAccessToken(chain);
  const json = JSON.stringify(chain);

  // Self-checks: the recorded facts are recomputed, never asserted in prose.
  if (token !== `pnc1.${base64urlnopad.encode(encoder.encode(json))}`) {
    throw new Error(`The token for ${JSON.stringify(name)} is not the profile's encoding`);
  }
  if (JSON.stringify(decodeChainAccessToken(token)) !== JSON.stringify(chain)) {
    throw new Error(`The chain for ${JSON.stringify(name)} does not survive a round trip`);
  }
  chain.forEach((grant, index) => {
    if (!verifyThresholdRecord(grant, [signerRef(signers[index]!)], 1)) {
      throw new Error(`Link ${index} of ${JSON.stringify(name)} is not signed by its issuer`);
    }
    const parent = chain[index + 1];
    const expected = parent === undefined ? null : canonicalDigest(parent);
    if (grant.proof !== expected) {
      throw new Error(`Link ${index} of ${JSON.stringify(name)} does not name its parent`);
    }
  });

  return {
    name,
    why,
    token,
    accept: true,
    payloadJson: json,
    chain,
    signerKeys: signers.map(signerRef),
    rejection: null,
    error: null,
    invalidElementIndex: null
  };
}

function refused(
  name: string,
  why: string,
  token: string,
  rejection: string,
  invalidElementIndex: number | null = null
): Vector {
  if (!(rejection in CODES)) {
    throw new Error(`Vector ${JSON.stringify(name)} uses an undocumented rejection class`);
  }
  let thrown: { name: string; message: string } | null = null;
  try {
    decodeChainAccessToken(token);
  } catch (caught) {
    const error = caught as { name?: unknown; message?: unknown };
    thrown = {
      name: typeof error.name === "string" ? error.name : "",
      message: typeof error.message === "string" ? error.message : ""
    };
  }
  if (thrown === null) {
    throw new Error(`The codec accepted ${JSON.stringify(name)}, which the fixture refuses`);
  }
  // A schema refusal's wording is the schema library's, not this profile's, so it is recorded
  // as a class only. Everything else is the codec's own text and is pinned exactly.
  const schemaRefusal = rejection === "element_not_a_grant";
  if (schemaRefusal !== (thrown.name !== "Error")) {
    throw new Error(
      `Vector ${JSON.stringify(name)} was refused by the wrong layer (${thrown.name}: ${thrown.message})`
    );
  }
  if (schemaRefusal !== (invalidElementIndex !== null)) {
    throw new Error(`Vector ${JSON.stringify(name)} must record the element the schema refuses`);
  }

  return {
    name,
    why,
    token,
    accept: false,
    payloadJson: null,
    chain: null,
    signerKeys: null,
    rejection,
    error: schemaRefusal ? null : thrown,
    invalidElementIndex
  };
}

/** A grant with a duplicate `proof` key, produced textually because no encoder emits one. */
const DUPLICATE_KEY_JSON = JSON.stringify(consentChain).replace(
  '"proof":null',
  '"proof":null,"proof":"zQmDifferentParentEntirely"'
);
if (!DUPLICATE_KEY_JSON.includes('"proof":null,"proof"')) {
  throw new Error("The duplicate-key payload does not contain a duplicate key");
}

/**
 * A key-audience leaf minted WITHOUT `expiresAt`, which spec 011 requires of one. Signed as it
 * stands rather than stripped after signing: the signature covers exactly these bytes, so the
 * refusal is the schema's judgement on the shape and not a detectable tamper.
 */
const UNEXPIRING_KEY_AUDIENCE_LEAF = signThresholdRecord(
  {
    subjectId: person.id,
    issuerId: person.id,
    audienceId: encodeKeyRef(agent.currentKeys[0]!.publicKey),
    abilities: ["photos/read"],
    caveats: { aud: resource.id },
    proof: null,
    anchor: keyLogAnchor(person.log),
    issuedAt: ISSUED_AT
  },
  [person.currentKeys[0]!.secretKey]
);

const vectors: Vector[] = [
  accepted(
    "accepted — the one-link chain consent mints",
    "The profile's token, end to end: the participant self-issues one grant at the moment of " +
      "consent, audience the resource participant, abilities exactly the ticked scopes, " +
      "aud-bound to the resource, expiring. This is the token an RP receives from `/token` and " +
      "presents as a bearer credential, and it is the vector that pins the wire form the other " +
      "vectors deviate from.",
    consentChain,
    [person]
  ),
  accepted(
    "accepted — a two-link org-rooted chain, leaf first",
    "Order is part of the encoding: the array is LEAF FIRST, so element 0 is the link the " +
      "resource is asked to honour and each element's `proof` names the NEXT one by its spec-003 " +
      "digest. A decoder that sorted, reversed or deduplicated the array would still produce two " +
      "valid Grants, so a one-link fixture could not catch it; here the recorded `proof` values " +
      "only line up in one order.",
    delegatedChain,
    [admin, org]
  ),
  accepted(
    "accepted — four links, exactly at the spec 011 cap",
    `MAX_GRANT_CHAIN_LINKS is ${MAX_GRANT_CHAIN_LINKS} and the cap is INCLUSIVE — a boundary a ` +
      "verdict alone cannot state, which is why this sits beside the five-link refusal below. " +
      "Every link is genuinely signed by its issuer and names its parent, so a decoder cannot " +
      "pass this one by truncating the chain to something it finds more comfortable.",
    cappedChain,
    [agent, team, admin, org]
  ),

  // ------------------------------------------------------------------------------------------
  // Prefix: the token says what it is, or it is not read.
  // ------------------------------------------------------------------------------------------
  refused(
    "refused — the PN-Grants header form of the same chain",
    "THE PAYLOAD IS BYTE-IDENTICAL to the first accepted vector's; only the prefix differs. The " +
      "two deliveries deliberately share an encoding — one chain has one payload, whichever way " +
      "it travels — and deliberately do not share a prefix, because a bearer token and a request " +
      "header are handled by different code with different lifetimes. Accepting `1:` here would " +
      "make a header value pasted into an `Authorization: Bearer` a valid token.",
    `1:${payload(consentChain)}`,
    "unsupported_prefix"
  ),
  refused(
    "refused — the bare payload with no prefix",
    "An unversioned token. The prefix is what makes a future profile (chain-by-reference, a " +
      "different payload encoding) additive rather than ambiguous, so a payload that declines to " +
      "say which profile it is written in cannot be read under the current one by default.",
    payload(consentChain),
    "unsupported_prefix"
  ),
  refused(
    "refused — a future version prefix",
    "`pnc2.` is not defined by any profile today. A decoder must refuse it rather than fall back " +
      "to `pnc1.` parsing: a version prefix that is ignored when unrecognized is not a version " +
      "prefix, and it would let a future format's payload be reinterpreted under today's rules.",
    `pnc2.${payload(consentChain)}`,
    "unsupported_prefix"
  ),
  refused(
    "refused — the prefix in upper case",
    "The prefix is compared exactly, not case-insensitively. Recorded because bearer tokens pass " +
      "through case-normalizing plumbing often enough that a lenient comparison looks like a " +
      "kindness, and a decoder that offers it accepts a token no encoder in this profile emits.",
    `PNC1.${payload(consentChain)}`,
    "unsupported_prefix"
  ),

  // ------------------------------------------------------------------------------------------
  // Charset, then bytes, then JSON.
  // ------------------------------------------------------------------------------------------
  refused(
    "refused — a payload outside the base64url alphabet",
    "The charset guard runs before anything tries to make meaning of the bytes, so a token that " +
      "cannot be decoded at all is refused as such rather than as malformed JSON.",
    "pnc1.!!!not-base64url!!!",
    "payload_not_base64url"
  ),
  refused(
    "refused — a padded base64 payload",
    "`=` is not in this profile's alphabet: the payload is base64url WITHOUT padding. A decoder " +
      "that accepted padding would give one chain two token spellings, and a token is compared " +
      "and cached as a string by everything that handles it.",
    "pnc1.e30=",
    "payload_not_base64url"
  ),
  refused(
    "refused — well-formed base64url that is not JSON",
    "The decode succeeds and yields text; the text is not JSON. The control that keeps the JSON " +
      "guard from being mistaken for the charset guard.",
    `pnc1.${base64urlnopad.encode(encoder.encode("not json at all"))}`,
    "payload_not_utf8_json"
  ),
  refused(
    "refused — a payload that is not valid UTF-8",
    "Two bare `FF` octets, which no UTF-8 sequence contains. The decode is STRICT rather than " +
      "lenient: a lenient decoder turns these into U+FFFD and hands the JSON parser text the " +
      "presenter never sent, which is the same non-injectivity that makes a text-normalized " +
      "content digest unsound.",
    `pnc1.${base64urlnopad.encode(Uint8Array.of(0xff, 0xff))}`,
    "payload_not_utf8_json"
  ),
  refused(
    "refused — a link carrying a duplicate object key (spec 015 S6.1)",
    "ONE delivered byte string, two logical chains: `JSON.parse` resolves this last-wins and a " +
      "first-wins parser resolves it to the other `proof`, so two resource servers handed this " +
      "exact token would digest two different Grants. A Grant's digest is what its child's " +
      "`proof` names and what spec 008 keys its revocation by, so the ambiguity is a second " +
      "identity for one credential — and a token is long-lived and widely copied, which is " +
      "worse here than in a single request header. Both resolutions are defensible, so the " +
      "delivery is refused rather than resolved.",
    `pnc1.${base64urlnopad.encode(encoder.encode(DUPLICATE_KEY_JSON))}`,
    "payload_not_utf8_json"
  ),

  // ------------------------------------------------------------------------------------------
  // Shape, then length, then elements — and the length is checked FIRST of those two.
  // ------------------------------------------------------------------------------------------
  refused(
    "refused — a single grant that was not wrapped in an array",
    "A valid Grant object, presented as the whole payload. A one-link chain is an array of one; " +
      "a decoder that coerced a lone object into one would accept a token no encoder produces.",
    `pnc1.${payload(consentChain[0]!)}`,
    "payload_not_nonempty_array"
  ),
  refused(
    "refused — an empty array",
    "Syntactically a chain, semantically nothing: no leaf, no abilities, no subject. Refused at " +
      "decode so no caller ever has to decide what an authority-free token authorizes.",
    `pnc1.${payload([])}`,
    "payload_not_nonempty_array"
  ),
  refused(
    "refused — five links, none of them shape-valid",
    `Five elements against a cap of ${MAX_GRANT_CHAIN_LINKS}, and every element is an empty ` +
      "object — so the two possible orderings give two different refusals, and the recorded " +
      "error says which one this profile takes. Length first: chain verification replays a key " +
      "log per link, the depth is chosen by whoever presents the token, and a token is presented " +
      "by anyone holding it. An implementation that parsed elements first would refuse this for " +
      "the element and, on a five-link chain of VALID links, would spend the parses before " +
      "noticing the length at all.",
    `pnc1.${payload([{}, {}, {}, {}, {}])}`,
    "chain_too_long"
  ),
  refused(
    "refused — a link carrying a key the schema does not define (spec 015 S6.3)",
    "CLOSED schema: an unknown key is rejected, not silently stripped. A stripped key is a " +
      "second digest for one delivery, which is exactly the malleability that defeated " +
      "revocation-by-digest.",
    `pnc1.${payload([{ ...consentChain[0]!, surprise: 1 }])}`,
    "element_not_a_grant",
    0
  ),
  refused(
    "refused — a key-audience link without expiresAt (spec 011)",
    "A bare key has no key log, so expiry is the only planned end a grant to one can have. The " +
      "link is otherwise honest and honestly signed — the signature covers the record WITHOUT " +
      "`expiresAt`, so this is a shape refusal and not a forgery, which is the point: the schema " +
      "refuses records a signature cannot rescue.",
    `pnc1.${payload([UNEXPIRING_KEY_AUDIENCE_LEAF])}`,
    "element_not_a_grant",
    0
  ),
  refused(
    "refused — a valid leaf followed by a non-grant element",
    "EVERY element is parsed, not just the leaf. A decoder that validated element 0 and passed " +
      "the rest through would hand a verifier a chain whose parent links are attacker-shaped " +
      "objects, and the leaf is the one link a lazy implementation is most likely to check.",
    `pnc1.${payload([consentChain[0]!, { not: "a grant" }])}`,
    "element_not_a_grant",
    1
  )
];

// The suite only makes its point if it exercises every class it documents, and if the refusals
// really are distinguished by the codec rather than collapsed into one message.
const used = new Set(vectors.map((entry) => entry.rejection).filter((code) => code !== null));
if (used.size !== Object.keys(CODES).length) {
  throw new Error("The vectors do not exercise every documented rejection class");
}
if (new Set(vectors.map((entry) => entry.name)).size !== vectors.length) {
  throw new Error("Two vectors share a name");
}
if (new Set(vectors.map((entry) => entry.token)).size !== vectors.length) {
  throw new Error("Two vectors share a token, so one of them proves nothing");
}

const target = new URL("../test/fixtures/chain-token-vectors.json", import.meta.url);
writeFileSync(
  target,
  `${JSON.stringify(
    {
      note:
        "Conformance vectors for the chain access token of the OAuth chain-access-token " +
        "profile — one self-issued, audience-bound, attenuated grant link presented as a " +
        "bearer credential: " +
        '`"pnc1." + base64url( UTF8( JSON.stringify(chain) ) )`, where `chain` is a leaf-first ' +
        "array of spec-009/011 Grant records. The token IS the credential — a resource server " +
        "reads it without asking the issuer anything — so every implementation must agree from " +
        "the bytes alone on which tokens are readable, and must refuse the rest in the same " +
        "order. `token` is the exact string presented and is the only input a conforming " +
        "implementation reads. For an accepted token, `payloadJson` is the exact UTF-8 the " +
        "base64url payload decodes to, `chain` is the decode's result (leaf first, unreordered), " +
        "and `signerKeys[i]` is the multibase key ref whose Ed25519 signature covers link i's " +
        "spec-001 signing input — so the whole vector is checkable with a base64url decoder, a " +
        "JSON parser and an Ed25519 verifier. Each link's `proof` is the spec-003 digest of the " +
        "NEXT element, which is what makes the leaf-first order load-bearing. For a refused " +
        "token, `rejection` is the normative class (see `codes`); `error` is the reference " +
        "implementation's exact throw, recorded so this repo's test can assert it byte for byte " +
        "and NOT as a wire contract another implementation must reproduce — conform to " +
        "`rejection`, not to the English — and it is null where the refusal comes from the Grant " +
        "schema rather than from this codec, in which case `invalidElementIndex` names the first " +
        "element the schema refuses. The guard ORDER is itself pinned: the link cap is checked " +
        "on the decoded array length BEFORE any element is parsed, so " +
        "`refused — five links, none of them shape-valid` records a length refusal even though " +
        "every element is also invalid. The payload after the prefix is byte-identical to the " +
        "PN-Grants header's payload after its `1:` prefix — the same encoding and the same " +
        "guards — while the prefixes stay distinct, which the first refusal vector states by " +
        "presenting the header form of an accepted chain. Regenerate with " +
        "packages/crypto/scripts/generate-chain-token-fixtures.ts.",
      prefix: "pnc1.",
      maxChainLinks: MAX_GRANT_CHAIN_LINKS,
      codes: CODES,
      vectors
    },
    null,
    2
  )}\n`
);

const refusals = vectors.filter((entry) => !entry.accept).length;
console.log(
  `Wrote ${vectors.length} chain access token vectors (${refusals} refusals, ${
    vectors.length - refusals
  } accepted) to ${target.pathname}`
);
