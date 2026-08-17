/**
 * Regenerates the committed RFC 9530 `Content-Digest` conformance vectors.
 *
 * These pin ONE property of the spec 004 write-auth profile: the digest is taken over the
 * CONTENT OCTETS — the bytes on the wire — and never over a decoded form of them. It is the
 * kind of rule that looks self-evident in prose and is easy to lose in code, because the
 * natural shape of a web framework hands a route a `string`: `Request.text()`, Hono's
 * `c.req.text()`, `express.text()`. Every one of those runs the bytes through a UTF-8
 * decoder, and that decoder is not injective. Malformed input does not fail; it becomes
 * U+FFFD. So the three octets `EF BF BD` (a body that legitimately contains U+FFFD) and the
 * single octet `FF` (not UTF-8 at all) decode to the same string, and a verifier that
 * digests that string cannot tell the two deliveries apart. One signature then covers both,
 * and the application is handed whichever bytes actually arrived.
 *
 * That is the attack pair below (`attackPair`), recorded as two vectors that share a decoded
 * text and differ in digest. The rest of the set states the boundaries around it: an ASCII
 * control so the suite cannot pass vacuously, the empty body the profile digests on bodyless
 * requests, a multi-byte UTF-8 body where decoding happens to be lossless, and a binary body
 * that cannot be expressed as text at all — which is the other half of the same defect, since
 * a text-only digest cannot cover binary content faithfully even with no attacker present.
 *
 * Every vector is checkable from bytes alone: `bodyBase64` is the delivery, `contentDigest`
 * is the exact header value a conforming implementation MUST produce for it, and
 * `digestOverDecodedText` is what the text-normalizing implementation produces instead. When
 * those two differ the vector is one that DISTINGUISHES the two implementations; when they
 * agree the vector is a control that both pass. A reader can verify the whole file with a
 * base64 decoder and a SHA-256, without running this repository.
 *
 * Run from the repo root (after `pnpm build`). BOTH commands, in order — this script writes
 * `JSON.stringify(…, null, 2)` and the committed file is prettier-formatted, so skipping the
 * second step leaves a diff that is pure formatting and makes the fixture look
 * non-reproducible:
 *
 *   pnpm exec tsx packages/crypto/scripts/generate-content-digest-fixtures.ts
 *   pnpm exec prettier --write packages/crypto/test/fixtures/content-digest-vectors.json
 */
import { writeFileSync } from "node:fs";

import { base64 } from "@scure/base";

import { contentDigest } from "@kinnet/crypto";

const encoder = new TextEncoder();
/** Lenient by default — the decoder every framework body accessor uses underneath. */
const lenient = new TextDecoder("utf-8");
const strict = new TextDecoder("utf-8", { fatal: true });

type Vector = {
  /** Short label; `accept`/`reject` is meaningless here — every vector is a digest, not a verdict. */
  name: string;
  /** What this vector proves, and what it deliberately does not. */
  why: string;
  /** The delivered content octets, base64. The ONLY input a conforming implementation reads. */
  bodyBase64: string;
  /** The exact RFC 9530 `Content-Digest` header value over those octets. */
  contentDigest: string;
  /** True when the octets are well-formed UTF-8, i.e. when a strict decode succeeds. */
  wellFormedUtf8: boolean;
  /** What a lenient UTF-8 decode produces. Malformed sequences appear here as U+FFFD. */
  decodedText: string;
  /**
   * The digest a text-normalizing implementation produces: decode the octets, re-encode the
   * text, hash that. Equal to `contentDigest` exactly when the round trip is lossless.
   */
  digestOverDecodedText: string;
  /**
   * True when `contentDigest !== digestOverDecodedText` — this delivery is one the two
   * implementations disagree about, and the vector a text-based verifier fails.
   */
  distinguishesTextFromBytes: boolean;
};

function vector(name: string, why: string, body: Uint8Array): Vector {
  const digest = contentDigest(body);
  let wellFormedUtf8 = true;
  try {
    strict.decode(body);
  } catch {
    wellFormedUtf8 = false;
  }
  const decodedText = lenient.decode(body);
  const digestOverDecodedText = contentDigest(encoder.encode(decodedText));

  // Self-check: `contentDigest` must treat a string as the digest of its UTF-8 encoding, so
  // the two input forms agree whenever the body IS that encoding. This is the sender-side
  // convenience the profile allows, and it is pinned here rather than asserted in prose.
  if (wellFormedUtf8 && contentDigest(decodedText) !== digest) {
    throw new Error(`String and bytes forms disagree for vector ${JSON.stringify(name)}`);
  }
  if (base64.decode(base64.encode(body)).length !== body.length) {
    throw new Error(`base64 round trip changed length for vector ${JSON.stringify(name)}`);
  }

  return {
    name,
    why,
    bodyBase64: base64.encode(body),
    contentDigest: digest,
    wellFormedUtf8,
    decodedText,
    digestOverDecodedText,
    distinguishesTextFromBytes: digest !== digestOverDecodedText
  };
}

// ------------------------------------------------------------------------------------------
// The attack pair: one signed body, one delivered body, one decoded text, two digests.
// ------------------------------------------------------------------------------------------

/** `{"note":"�"}` with U+FFFD encoded properly, as `EF BF BD`. What the sender signs. */
const SIGNED_BODY = encoder.encode('{"note":"�"}');
/** The same delivery with those three octets replaced by the single invalid octet `FF`. */
const DELIVERED_BODY = (() => {
  const marker = [0xef, 0xbf, 0xbd];
  const at = SIGNED_BODY.findIndex((_byte, index) =>
    marker.every((expected, offset) => SIGNED_BODY[index + offset] === expected)
  );
  if (at < 0) {
    throw new Error("The signed body does not contain the UTF-8 encoding of U+FFFD");
  }
  const out = new Uint8Array(SIGNED_BODY.length - marker.length + 1);
  out.set(SIGNED_BODY.subarray(0, at), 0);
  out[at] = 0xff;
  out.set(SIGNED_BODY.subarray(at + marker.length), at + 1);
  return out;
})();

/** Arbitrary non-text content: every byte value once, which no decoder can round-trip. */
const BINARY_BODY = Uint8Array.from({ length: 256 }, (_unused, index) => index);

const vectors: Vector[] = [
  vector(
    "control — an ASCII JSON body",
    "The vector that stops this suite from passing vacuously. Plain ASCII round-trips through " +
      "a UTF-8 decoder unchanged, so a byte-digesting and a text-digesting implementation " +
      "agree here and both pass. It pins the header's exact wire form — the `sha-256=:` " +
      "prefix, base64 with padding, the trailing colon — which every other vector reuses.",
    encoder.encode('{"want":"quote"}')
  ),
  vector(
    "control — the empty body",
    "The spec 004 profile covers `content-digest` UNCONDITIONALLY, GETs included, so a " +
      "bodyless request still carries a digest and every implementation must agree on which " +
      "one. This is the SHA-256 of zero octets. It also pins that the empty string and zero " +
      'bytes are the same input, which is what lets a signer pass `""` and a verifier pass ' +
      "an empty `Uint8Array` for the same request.",
    new Uint8Array(0)
  ),
  vector(
    "control — multi-byte UTF-8 that decodes losslessly",
    "Non-ASCII text is NOT the defect. Well-formed UTF-8 survives a decode/re-encode round " +
      "trip byte for byte, so this vector's two digests agree and a text-digesting " +
      "implementation passes it. Recorded to keep the failing vectors honest: what breaks a " +
      "text-based verifier is malformed input, not foreign scripts, and a fixture that only " +
      "showed ASCII controls would leave that ambiguous.",
    encoder.encode('{"note":"héllo 世界 🌍"}')
  ),
  vector(
    "attack, signed half — a body containing a legitimate U+FFFD (EF BF BD)",
    "The body the sender signs. U+FFFD is an ordinary character that any text may contain, " +
      "and here it is correctly encoded as the three octets EF BF BD. Its digest is over " +
      "those three octets. Pair this with the delivered half below: the two bodies are " +
      "different byte strings, so they have different digests, and a signature over this one " +
      "must not verify over that one.",
    SIGNED_BODY
  ),
  vector(
    "attack, delivered half — the same text with EF BF BD replaced by the invalid octet FF",
    "The body an intermediary substitutes. `FF` is not valid UTF-8 anywhere, so a lenient " +
      "decoder maps it to U+FFFD — producing EXACTLY the decoded text of the signed half, as " +
      "`decodedText` shows for both. An implementation that digests the decoded text " +
      "therefore computes the signed half's digest for this delivery and accepts it, while " +
      "the application is handed these octets, which no signature ever covered. " +
      "`digestOverDecodedText` here IS the signed half's `contentDigest` — that equality is " +
      "the vulnerability, stated in bytes. Digesting the octets gives a different value and " +
      "the substitution is refused.",
    DELIVERED_BODY
  ),
  vector(
    "binary — all 256 byte values, which is not text at all",
    "The other half of the same defect, present with no attacker. A text-normalizing digest " +
      "cannot faithfully cover a binary body: 129 of these 256 octets are not well-formed " +
      "UTF-8, a lenient decode replaces them, and the re-encoded text is a different and " +
      "longer byte string. So the two digests differ, and under a text-based implementation " +
      "the signature over a binary body means nothing at all — every binary body with the " +
      "same replacement pattern shares one digest.",
    BINARY_BODY
  )
];

// The pair only makes its point if the two halves really do share a decoded text and really
// do differ in digest. Both are asserted here so the claim cannot silently rot.
const signedVector = vectors.find((entry) => entry.name.startsWith("attack, signed half"))!;
const deliveredVector = vectors.find((entry) => entry.name.startsWith("attack, delivered half"))!;
if (signedVector.decodedText !== deliveredVector.decodedText) {
  throw new Error("The attack pair does not share a decoded text; the vector proves nothing");
}
if (signedVector.bodyBase64 === deliveredVector.bodyBase64) {
  throw new Error("The attack pair is byte-identical; the vector proves nothing");
}
if (signedVector.contentDigest === deliveredVector.contentDigest) {
  throw new Error("The attack pair digests alike over octets; the fix would not catch it");
}
if (deliveredVector.digestOverDecodedText !== signedVector.contentDigest) {
  throw new Error("The delivered half does not collide with the signed half under text digesting");
}

/**
 * `JSON.stringify` escapes control characters below 0x20 but leaves 0x7f (DEL) literal, and
 * the binary vector's `decodedText` contains one. A raw control byte makes the whole file read
 * as binary to `grep`, which the repo's `check:text` gate refuses — so it is written as the
 * `\u007f` escape, which parses back to the identical string.
 */
const escapeDel = (json: string): string => json.replaceAll("\u007f", "\\u007f");

const target = new URL("../test/fixtures/content-digest-vectors.json", import.meta.url);
writeFileSync(
  target,
  `${escapeDel(
    JSON.stringify(
      {
        note:
          "Conformance vectors for the RFC 9530 `Content-Digest` value the spec 004 write-auth " +
          "profile covers. They pin ONE rule: the digest is computed over the CONTENT OCTETS as " +
          "transmitted, never over a decoded form of them. `bodyBase64` is the delivery and " +
          "`contentDigest` is the exact header value a conforming implementation MUST produce " +
          "for it — sha-256, base64 with padding, wrapped as `sha-256=:…:`. Checkable with a " +
          "base64 decoder and a SHA-256 alone. `digestOverDecodedText` records what the " +
          "text-normalizing implementation computes instead (lenient UTF-8 decode, re-encode, " +
          "hash), and `distinguishesTextFromBytes` marks the vectors where the two disagree — " +
          "those are the ones a text-based verifier fails. The reason a text-based verifier is " +
          "not merely imprecise but unsound is the attack pair: UTF-8 decoding is not " +
          "injective, because every malformed sequence becomes U+FFFD rather than an error, so " +
          "the three octets EF BF BD (a body legitimately containing U+FFFD) and the single " +
          "octet FF decode to the same text. The pair below is exactly that — two different " +
          "deliveries with one decoded text — and under text digesting the second one's digest " +
          "equals the first one's, so a signature over the first verifies over the second while " +
          "the application receives the second's bytes. Over octets the digests differ and the " +
          "substitution is refused. The binary vector states the same defect without an " +
          "attacker: a text-normalized digest cannot cover non-UTF-8 content at all. The three " +
          "controls (ASCII, empty, well-formed multi-byte UTF-8) agree under both " +
          "implementations and are recorded so the failing vectors are not confused with " +
          "'non-ASCII is unsupported'. A `string` body is a SENDER-SIDE convenience only: it is " +
          "digested as its UTF-8 encoding, which is correct exactly when the sender transmits " +
          "that encoding, and a verifier must never reach it by decoding what it received. " +
          "Regenerate with packages/crypto/scripts/generate-content-digest-fixtures.ts.",
        attackPair: {
          signed: signedVector.name,
          delivered: deliveredVector.name,
          sharedDecodedText: signedVector.decodedText,
          note:
            "Same decoded text, different octets, different digests. A verifier that digests " +
            "octets rejects the delivered half against the signed half's Content-Digest; a " +
            "verifier that digests decoded text accepts it. That is the whole finding."
        },
        vectors
      },
      null,
      2
    )
  )}\n`
);

console.log(`Wrote ${vectors.length} content-digest vectors to ${target.pathname}`);
