import { readFileSync } from "node:fs";

import type { Grant } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  conversationIdFromGroupId,
  decodeCommitBinding,
  decodePNCredential,
  decodeOpaque,
  decodeVarint,
  encodeCommitBinding,
  encodePNCredential,
  encodeOpaque,
  encodeVarint,
  groupIdFromConversationId,
  padApplicationContent,
  toMultibase,
  unpadApplicationContent,
  KINNET_CREDENTIAL_TYPE
} from "../src/index.js";

// The committed vectors are the shared oracle: a second implementation must reproduce
// these bytes from the inputs alone. This test READS the committed file only — never
// regenerate it at test time; regenerate it by hand and commit the new bytes.
const vectors = JSON.parse(
  readFileSync(new URL("./fixtures/mls-profile-vectors.json", import.meta.url), "utf8")
) as {
  varint: {
    encode: { value: number; hex: string }[];
    rejectEncode: { value: number; reason: string }[];
    rejectDecode: { hex: string; reason: string }[];
  };
  credential: { chain: Grant[]; hex: string };
  credentialEmptyCaveats: { chain: Grant[]; hex: string };
  commitBinding: {
    empty: { digests: string[]; sorted: string[]; hex: string };
    single: { digests: string[]; sorted: string[]; hex: string };
    threeUnsortedInput: { digests: string[]; sorted: string[]; hex: string };
    rejectDecode: { hex: string; reason: string }[];
  };
  groupId: { conversationId: string; groupIdHex: string };
};

const textEncoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

describe("variable-length integers (RFC 9000 §16 as profiled by RFC 9420 §2.1.2)", () => {
  it("round-trips the boundary value of every permitted form", () => {
    for (const value of [0, 1, 63, 64, 16383, 16384, 16385, (1 << 30) - 1]) {
      const encoded = encodeVarint(value);
      expect(encoded.length).toBe(1 << (encoded[0]! >> 6));
      expect(decodeVarint(encoded)).toEqual({ value, bytesRead: encoded.length });
    }
  });

  it("always uses the shortest form that fits", () => {
    expect(encodeVarint(63).length).toBe(1);
    expect(encodeVarint(64).length).toBe(2);
    expect(encodeVarint(16383).length).toBe(2);
    expect(encodeVarint(16384).length).toBe(4);
    expect(encodeVarint((1 << 30) - 1).length).toBe(4);
  });

  it("matches the committed encode vectors byte for byte", () => {
    for (const vector of vectors.varint.encode) {
      expect(toHex(encodeVarint(vector.value))).toBe(vector.hex);
      expect(toHex(encodeVarint(BigInt(vector.value)))).toBe(vector.hex);
      expect(decodeVarint(fromHex(vector.hex)).value).toBe(vector.value);
    }
  });

  it("rejects the committed decode vectors (non-minimal, 8-byte form, truncated)", () => {
    for (const vector of vectors.varint.rejectDecode) {
      expect(() => decodeVarint(fromHex(vector.hex)), vector.reason).toThrow();
    }
    // Spelled out, so the reason each vector is rejected is pinned and not just its bytes.
    expect(() => decodeVarint(fromHex("4000"))).toThrow(/Non-minimal/);
    expect(() => decodeVarint(fromHex("80000040"))).toThrow(/Non-minimal/);
    expect(() => decodeVarint(fromHex("c000000040000000"))).toThrow(/"11"/);
    expect(() => decodeVarint(fromHex("40"))).toThrow(/Truncated/);
    expect(() => decodeVarint(new Uint8Array(0))).toThrow(/Truncated/);
  });

  it("rejects values RFC 9420 cannot express, and non-integers", () => {
    for (const vector of vectors.varint.rejectEncode) {
      expect(() => encodeVarint(vector.value), vector.reason).toThrow(/2\^30/);
    }
    expect(() => encodeVarint(2 ** 30)).toThrow(/2\^30/);
    expect(() => encodeVarint(2n ** 62n)).toThrow(/2\^30/);
    expect(() => encodeVarint(-1)).toThrow(/non-negative/);
    expect(() => encodeVarint(-1n)).toThrow(/non-negative/);
    expect(() => encodeVarint(1.5)).toThrow(/safe integer/);
    expect(() => encodeVarint(Number.MAX_SAFE_INTEGER + 2)).toThrow(/safe integer/);
  });

  it("decodes at an offset without copying the buffer", () => {
    const bytes = fromHex("ff4040");
    expect(decodeVarint(bytes, 1)).toEqual({ value: 64, bytesRead: 2 });
    expect(() => decodeVarint(bytes, 2)).toThrow(/Truncated/);
    expect(() => decodeVarint(bytes, 3)).toThrow(/Truncated/);
  });
});

describe("opaque x<V>", () => {
  it("round-trips, and reports the bytes consumed so a vector can be walked", () => {
    const first = textEncoder.encode("alpha");
    const second = textEncoder.encode("");
    const buffer = new Uint8Array([...encodeOpaque(first), ...encodeOpaque(second)]);

    const one = decodeOpaque(buffer, 0);
    expect(one.value).toEqual(first);
    const two = decodeOpaque(buffer, one.bytesRead);
    expect(two.value).toEqual(second);
    expect(one.bytesRead + two.bytesRead).toBe(buffer.length);
  });

  it("rejects a body that runs past the end of the buffer", () => {
    const encoded = encodeOpaque(textEncoder.encode("alpha"));
    expect(() => decodeOpaque(encoded.slice(0, encoded.length - 1))).toThrow(/Truncated/);
  });
});

describe("PNCredential (spec 014 profile table)", () => {
  it("pins the private-use MLS credential type", () => {
    expect(KINNET_CREDENTIAL_TYPE).toBe(0xf001);
  });

  it("round-trips a grant chain, leaf first", () => {
    const chain = vectors.credential.chain;
    expect(decodePNCredential(encodePNCredential(chain))).toEqual(chain);
  });

  it("matches the committed bytes for the committed chain", () => {
    expect(toHex(encodePNCredential(vectors.credential.chain))).toBe(vectors.credential.hex);
    expect(decodePNCredential(fromHex(vectors.credential.hex))).toEqual(vectors.credential.chain);
  });

  it("round-trips a 014-shaped chain (e2ee abilities, empty caveats)", () => {
    // This is the real credential shape: 014 amends 011 so a key-audience grant whose
    // abilities all satisfy the `e2ee` predicate omits `caveats.aud`, and requires every
    // credential link to carry empty caveats. Decoding it exercises that amendment through
    // `grantSchema` — a chain the un-amended schema would have rejected.
    expect(toHex(encodePNCredential(vectors.credentialEmptyCaveats.chain))).toBe(
      vectors.credentialEmptyCaveats.hex
    );
    expect(decodePNCredential(fromHex(vectors.credentialEmptyCaveats.hex))).toEqual(
      vectors.credentialEmptyCaveats.chain
    );
  });

  it("rejects an empty chain", () => {
    expect(() => encodePNCredential([])).toThrow(/empty/);
  });

  it("fails closed on a credential link carrying caveats", () => {
    // 014 rule 3: a caveat a verifier cannot evaluate fails closed, which inside an MLS
    // group is a permanent split — so the shape is closed at the schema, and the codec
    // inherits it rather than accepting bytes the group would disagree about.
    const withCaveat = vectors.credentialEmptyCaveats.chain.map((grant) => ({
      ...grant,
      caveats: { aud: grant.subjectId }
    }));
    expect(() => decodePNCredential(encodePNCredential(withCaveat))).toThrow(/empty caveats/);
  });

  it("rejects trailing bytes after the structure", () => {
    const encoded = encodePNCredential(vectors.credential.chain);
    const trailing = new Uint8Array([...encoded, 0x00]);
    expect(() => decodePNCredential(trailing)).toThrow(/trailing/);
  });

  it("rejects a truncated structure", () => {
    const encoded = encodePNCredential(vectors.credential.chain);
    expect(() => decodePNCredential(encoded.slice(0, encoded.length - 1))).toThrow(/Truncated/);
  });

  it("rejects a malformed chain prefix", () => {
    const inner = encodePNCredential(vectors.credential.chain);
    const text = new TextDecoder().decode(decodeOpaque(inner).value);
    expect(() =>
      decodePNCredential(encodeOpaque(textEncoder.encode(`2:${text.slice(2)}`)))
    ).toThrow(/unsupported PN-Grants encoding/);
  });

  it("rejects a chain containing an element that is not a shape-valid Grant", () => {
    const payload = Buffer.from(JSON.stringify([{ not: "a grant" }]), "utf8").toString("base64url");
    expect(() => decodePNCredential(encodeOpaque(textEncoder.encode(`1:${payload}`)))).toThrow();
  });

  it("rejects a chain that is not valid UTF-8", () => {
    expect(() => decodePNCredential(encodeOpaque(Uint8Array.of(0xff, 0xfe)))).toThrow(/UTF-8/);
  });
});

describe("PNCommitBinding (spec 014, binding evidence to the commit)", () => {
  it("round-trips the empty list, which the founding and update-path commits carry", () => {
    const encoded = encodeCommitBinding([]);
    expect(toHex(encoded)).toBe(vectors.commitBinding.empty.hex);
    expect(decodeCommitBinding(encoded)).toEqual([]);
  });

  it("matches the committed bytes for one digest", () => {
    const { digests, hex } = vectors.commitBinding.single;
    expect(toHex(encodeCommitBinding(digests))).toBe(hex);
    expect(decodeCommitBinding(fromHex(hex))).toEqual(digests);
  });

  it("sorts by codepoint, so an unsorted input produces the sorted encoding", () => {
    const { digests, sorted, hex } = vectors.commitBinding.threeUnsortedInput;
    expect(digests).not.toEqual(sorted);
    expect(toHex(encodeCommitBinding(digests))).toBe(hex);
    expect(decodeCommitBinding(fromHex(hex))).toEqual(sorted);
    // Any permutation of the same set is one encoding.
    expect(toHex(encodeCommitBinding([...digests].reverse()))).toBe(hex);
    expect(toHex(encodeCommitBinding(sorted))).toBe(hex);
  });

  it("rejects duplicates rather than collapsing them", () => {
    const digest = vectors.commitBinding.single.digests[0]!;
    expect(() => encodeCommitBinding([digest, digest])).toThrow(/duplicate/);
  });

  it("rejects an entry that is not a well-formed sha2-256 multihash", () => {
    expect(() => encodeCommitBinding(["not-a-multihash"])).toThrow(/multibase/);
    expect(() => encodeCommitBinding(["z6MkTooShort"])).toThrow(/multihash/);
  });

  it("rejects the committed decode vectors", () => {
    const reasons = [/Non-minimal/, /trailing/, /sorted/, /duplicate/];
    vectors.commitBinding.rejectDecode.forEach((vector, index) => {
      expect(() => decodeCommitBinding(fromHex(vector.hex)), vector.reason).toThrow(
        reasons[index]!
      );
    });
  });

  it("rejects a truncated entry", () => {
    const encoded = encodeCommitBinding(vectors.commitBinding.single.digests);
    expect(() => decodeCommitBinding(encoded.slice(0, encoded.length - 1))).toThrow(/Truncated/);
  });
});

describe("application padding (spec 014 profile table)", () => {
  // Spelled out here rather than in the fixture file, because the whole vector is the point:
  // a second implementation has to produce these exact bytes for this exact content, and the
  // padding is what an operator sees on the wire.
  const HI_PADDED_HEX = `026869${"00".repeat(253)}`;
  const EMPTY_PADDED_HEX = "00".repeat(256);

  it("matches the byte vectors for a short message and for empty content", () => {
    expect(toHex(padApplicationContent(textEncoder.encode("hi")))).toBe(HI_PADDED_HEX);
    expect(unpadApplicationContent(fromHex(HI_PADDED_HEX))).toEqual(textEncoder.encode("hi"));

    // The minimum output is one full block — empty content is a valid frame, not zero bytes.
    expect(toHex(padApplicationContent(new Uint8Array(0)))).toBe(EMPTY_PADDED_HEX);
    expect(unpadApplicationContent(fromHex(EMPTY_PADDED_HEX))).toEqual(new Uint8Array(0));
  });

  it("round-trips every length, and always emits a positive multiple of 256 bytes", () => {
    // 63/64 and 254/255 straddle the varint header widening from one byte to two, which is
    // where the block count changes for a content length that barely moved.
    for (const length of [0, 1, 63, 64, 253, 254, 255, 256, 257, 1000, 4096]) {
      const content = new Uint8Array(length);
      for (let index = 0; index < length; index += 1) {
        content[index] = (index * 37 + 11) % 256;
      }
      const padded = padApplicationContent(content);
      expect(padded.length).toBeGreaterThan(0);
      expect(padded.length % 256).toBe(0);
      expect(unpadApplicationContent(padded)).toEqual(content);
    }
  });

  it("uses the fewest 256-byte blocks the frame fits in", () => {
    expect(padApplicationContent(new Uint8Array(0)).length).toBe(256);
    expect(padApplicationContent(new Uint8Array(63)).length).toBe(256);
    // 254 bytes of content plus a two-byte header is exactly one block.
    expect(padApplicationContent(new Uint8Array(254)).length).toBe(256);
    expect(padApplicationContent(new Uint8Array(255)).length).toBe(512);
    expect(padApplicationContent(new Uint8Array(510)).length).toBe(512);
    expect(padApplicationContent(new Uint8Array(511)).length).toBe(768);
  });

  it("hides the content length within a block", () => {
    const short = padApplicationContent(textEncoder.encode("hi"));
    const longer = padApplicationContent(textEncoder.encode("x".repeat(200)));
    expect(short.length).toBe(longer.length);
  });

  it("rejects a length that is not a positive multiple of 256", () => {
    expect(() => unpadApplicationContent(new Uint8Array(0))).toThrow(/positive multiple of 256/);
    expect(() => unpadApplicationContent(new Uint8Array(100))).toThrow(/positive multiple of 256/);
    expect(() => unpadApplicationContent(new Uint8Array(255))).toThrow(/positive multiple of 256/);
    expect(() => unpadApplicationContent(new Uint8Array(257))).toThrow(/positive multiple of 256/);
    // One byte short of a full frame is still a wrong length, not a truncated frame.
    const padded = padApplicationContent(textEncoder.encode("hi"));
    expect(() => unpadApplicationContent(padded.slice(0, padded.length - 1))).toThrow(
      /positive multiple of 256/
    );
  });

  it("rejects non-zero padding, wherever in the block it sits", () => {
    for (const position of [3, 128, 255]) {
      const padded = padApplicationContent(textEncoder.encode("hi"));
      padded[position] = 0x01;
      expect(() => unpadApplicationContent(padded)).toThrow(/non-zero padding/);
    }
  });

  it("rejects trailing garbage after the frame — a second frame in the same block", () => {
    // The frame is self-describing, so a decoder that stopped at `bytesRead` would accept two
    // different byte-forms for the same content. Anything after the frame must be zeros.
    const padded = padApplicationContent(textEncoder.encode("hi"));
    padded.set(encodeOpaque(textEncoder.encode("and more")), 3);
    expect(() => unpadApplicationContent(padded)).toThrow(/non-zero padding/);
  });

  it("rejects more padding than the frame needs", () => {
    const oversized = new Uint8Array(512);
    oversized.set(encodeOpaque(textEncoder.encode("hi")));
    expect(() => unpadApplicationContent(oversized)).toThrow(/more padding than the frame needs/);

    // The same content, padded correctly, is the only accepted form.
    expect(unpadApplicationContent(oversized.slice(0, 256))).toEqual(textEncoder.encode("hi"));
  });

  it("rejects a frame header that overruns the block", () => {
    const lying = new Uint8Array(256);
    // Declare 4096 bytes of content inside a 256-byte block.
    lying.set(encodeVarint(4096));
    expect(() => unpadApplicationContent(lying)).toThrow(/Truncated/);
  });

  it("rejects a non-minimal frame header", () => {
    const nonMinimal = new Uint8Array(256);
    // 2 bytes of content, but written in the two-byte varint form.
    nonMinimal.set([0x40, 0x02, 0x68, 0x69]);
    expect(() => unpadApplicationContent(nonMinimal)).toThrow(/Non-minimal/);
  });
});

describe("group_id derivation (spec 014 profile table)", () => {
  const { conversationId, groupIdHex } = vectors.groupId;

  it("is the raw multihash bytes of the conversation id, not its multibase string", () => {
    const groupId = groupIdFromConversationId(conversationId);
    expect(toHex(groupId)).toBe(groupIdHex);
    // The distinction the spec calls out: 34 raw bytes, not the 47-character string.
    expect(groupId.length).toBe(34);
    expect(groupId.length).not.toBe(textEncoder.encode(conversationId).length);
    expect(groupId[0]).toBe(0x12);
    expect(groupId[1]).toBe(0x20);
  });

  it("round-trips back to the conversation id", () => {
    expect(conversationIdFromGroupId(groupIdFromConversationId(conversationId))).toBe(
      conversationId
    );
    expect(conversationIdFromGroupId(fromHex(groupIdHex))).toBe(conversationId);
  });

  it("rejects a conversation id that is not a sha2-256 multihash", () => {
    expect(() => groupIdFromConversationId("QmNotMultibase")).toThrow(/multibase/);
    expect(() => groupIdFromConversationId("z6MkTooShort")).toThrow(/multihash/);
    // A well-formed multibase string of the right length but the wrong multihash code.
    const wrongCode = fromHex(groupIdHex);
    wrongCode[0] = 0x11;
    expect(() => groupIdFromConversationId(toMultibase(wrongCode))).toThrow(/multihash/);
  });

  it("rejects group_id bytes that are not a sha2-256 multihash", () => {
    expect(() => conversationIdFromGroupId(fromHex(groupIdHex).slice(2))).toThrow(/multihash/);
    expect(() => conversationIdFromGroupId(new Uint8Array(34))).toThrow(/multihash/);
  });
});
