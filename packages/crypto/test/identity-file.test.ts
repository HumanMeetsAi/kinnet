import {
  commitToKeyState,
  createIdentity,
  encodeKeyRef,
  generateKeyPair,
  rotateIdentity
} from "../src/index.js";
import { describe, expect, it } from "vitest";

import { fromIdentityFile, parseIdentityFile, toIdentityFile } from "../src/index.js";

describe("identity file round-trip", () => {
  it("restores an identity with working keys", () => {
    const identity = createIdentity();
    const restored = fromIdentityFile(toIdentityFile(identity));

    expect(restored.id).toBe(identity.id);
    expect(restored.log).toEqual(identity.log);
    expect(restored.currentKeys[0]!.secretKey).toEqual(identity.currentKeys[0]!.secretKey);

    // The restored identity can still rotate — the next keys are intact
    const rotated = rotateIdentity(restored);
    expect(rotated.log).toHaveLength(2);
    expect(rotated.currentKeys[0]!.publicKey).toEqual(identity.nextKeys[0]!.publicKey);
  });

  it("round-trips a rotated identity", () => {
    const rotated = rotateIdentity(createIdentity());
    const restored = fromIdentityFile(toIdentityFile(rotated));

    expect(restored.id).toBe(rotated.id);
    expect(restored.log).toHaveLength(2);
  });

  it("rejects a file whose ID does not match its key log", () => {
    const file = toIdentityFile(createIdentity());
    expect(() => fromIdentityFile({ ...file, id: createIdentity().id })).toThrow(/does not match/);
  });

  it("rejects mismatched key material", () => {
    const identity = createIdentity();
    const other = createIdentity();
    const file = toIdentityFile(identity);

    // secret key swapped out from under its public key
    expect(() =>
      fromIdentityFile({
        ...file,
        currentKeys: [{ publicKey: file.currentKeys[0]!.publicKey, secretKey: toSecret(other) }]
      })
    ).toThrow(/does not match its secret key/);

    // a consistent keypair that is not the log's current key
    expect(() =>
      fromIdentityFile({ ...file, currentKeys: toIdentityFile(other).currentKeys })
    ).toThrow(/current key set/);

    // next keys that do not match the pre-rotation commitment
    expect(() => fromIdentityFile({ ...file, nextKeys: toIdentityFile(other).nextKeys })).toThrow(
      /pre-rotation commitment/
    );
  });

  it("rejects files with a tampered key log", () => {
    const file = toIdentityFile(createIdentity());
    const tampered = {
      ...file,
      keyEvents: [{ ...file.keyEvents[0]!, threshold: "2" }]
    };
    expect(() => fromIdentityFile(tampered)).toThrow();
    expect(() => fromIdentityFile("not an object")).toThrow(/JSON object/);
  });
});

function toSecret(identity: ReturnType<typeof createIdentity>): string {
  return toIdentityFile(identity).currentKeys[0]!.secretKey;
}

/**
 * Spec 015 S6.1 on the two SDK paths that take a key log as raw bytes from outside this
 * process: an identity FILE (the CLI's on-disk state and the web app's import) and a key log
 * fetched from a discovery host.
 *
 * Both are digest-addressed all the way down — the participant id hashes the inception event's
 * establishment data (002) and every later event names its predecessor by digest — so one byte
 * string that two parsers resolve differently is one delivery describing two identities.
 */
describe("the committed next threshold survives the file (spec 003)", () => {
  it("round-trips a handover identity, which the library could once write but not read", () => {
    // A handover identity holds no next keys, so it has no committed threshold of its own. An
    // earlier draft wrote `""` for that `null`, which is neither a threshold nor a statement of
    // absence — and `commitToKeyState("")` then refused the file on load.
    const identity = createIdentity();
    const handed = rotateIdentity(identity, {
      nextCommitment: commitToKeyState([encodeKeyRef(generateKeyPair().publicKey)], "1")
    });

    const file = toIdentityFile(handed);
    expect(file.nextThreshold).toBeNull();

    const restored = fromIdentityFile(file);
    expect(restored.nextThreshold).toBeNull();
    expect(restored.nextKeys).toHaveLength(0);
    expect(restored.id).toBe(handed.id);
  });

  // BOTH halves of 015 S1, deliberately paired. Guarding only the domain half is what let the
  // `t <= n` half throw out of `commitToKeyState` — a load failure reported as a commit failure.
  it("blames the file, not the hashing helper, for an out-of-domain threshold", () => {
    const file = toIdentityFile(createIdentity());
    expect(() => fromIdentityFile({ ...file, nextThreshold: "01" })).toThrow(
      /Identity file's committed next threshold "01" is not a decimal string/
    );
  });

  it("blames the file, not the hashing helper, for a threshold above its stored next keys", () => {
    const file = toIdentityFile(createIdentity());
    expect(() => fromIdentityFile({ ...file, nextThreshold: "2" })).toThrow(
      /Identity file's committed next threshold "2" exceeds its 1 stored next key\(s\)/
    );
  });

  it("blames the file for a handover file that names a threshold it holds no keys for", () => {
    const handed = rotateIdentity(createIdentity(), {
      nextCommitment: commitToKeyState([encodeKeyRef(generateKeyPair().publicKey)], "1")
    });
    const file = { ...toIdentityFile(handed), nextThreshold: "1" };
    expect(() => fromIdentityFile(file)).toThrow(
      /Identity file's committed next threshold "1" exceeds its 0 stored next key\(s\)/
    );
  });

  it("loads the maximum eight stored next keys when they match the commitment", () => {
    const identity = rotateIdentity(createIdentity(), {
      nextKeyCount: 8,
      nextThreshold: "8"
    });

    const restored = fromIdentityFile(toIdentityFile(identity));
    expect(restored.nextKeys).toHaveLength(8);
    expect(restored.nextThreshold).toBe("8");
  });

  it("blames the file before the commitment helper sees nine stored next keys", () => {
    const identity = rotateIdentity(createIdentity(), {
      nextKeyCount: 8,
      nextThreshold: "8"
    });
    const file = toIdentityFile(identity);
    const extra = toIdentityFile(createIdentity()).nextKeys[0]!;
    const tooWide = { ...file, nextKeys: [...file.nextKeys, extra] };

    expect(() => fromIdentityFile(tooWide)).toThrow(
      /Identity file holds 9 stored next keys, exceeding the maximum of 8/
    );
    try {
      fromIdentityFile(tooWide);
    } catch (error) {
      expect((error as Error).message).not.toMatch(/^Cannot commit to a key state/);
    }
  });

  it("checks the stored-next-key width before replaying the key log", () => {
    const identity = rotateIdentity(createIdentity(), {
      nextKeyCount: 8,
      nextThreshold: "8"
    });
    const file = {
      ...toIdentityFile(identity),
      nextKeys: [
        ...toIdentityFile(identity).nextKeys,
        toIdentityFile(createIdentity()).nextKeys[0]!
      ]
    };
    Object.defineProperty(file, "keyEvents", {
      get: () => {
        throw new Error("key-log replay tripwire reached");
      }
    });

    expect(() => fromIdentityFile(file)).toThrow(
      /Identity file holds 9 stored next keys, exceeding the maximum of 8/
    );
  });

  it("checks the stored-next-key width before inspecting stored key material", () => {
    const identity = rotateIdentity(createIdentity(), {
      nextKeyCount: 8,
      nextThreshold: "8"
    });
    const file = toIdentityFile(identity);
    const poisonedCurrentKey = { ...file.currentKeys[0]! };
    Object.defineProperty(poisonedCurrentKey, "secretKey", {
      get: () => {
        throw new Error("stored-key restoration tripwire reached");
      }
    });

    expect(() =>
      fromIdentityFile({
        ...file,
        currentKeys: [poisonedCurrentKey],
        nextKeys: [...file.nextKeys, toIdentityFile(createIdentity()).nextKeys[0]!]
      })
    ).toThrow(/Identity file holds 9 stored next keys, exceeding the maximum of 8/);
  });

  it("checks the stored-next-key width before inspecting a stored next key", () => {
    const identity = rotateIdentity(createIdentity(), {
      nextKeyCount: 8,
      nextThreshold: "8"
    });
    const file = toIdentityFile(identity);
    const poisonedNextKey = { ...file.nextKeys[0]! };
    Object.defineProperty(poisonedNextKey, "secretKey", {
      get: () => {
        throw new Error("stored-next-key restoration tripwire reached");
      }
    });

    expect(() =>
      fromIdentityFile({
        ...file,
        nextKeys: [
          poisonedNextKey,
          ...file.nextKeys.slice(1),
          toIdentityFile(createIdentity()).nextKeys[0]!
        ]
      })
    ).toThrow(/Identity file holds 9 stored next keys, exceeding the maximum of 8/);
  });

  it.each(["01", "2"])(
    "never surfaces a commit-side diagnosis from the load path for %j",
    (threshold) => {
      const file = { ...toIdentityFile(createIdentity()), nextThreshold: threshold };
      // The property, stated rather than inferred from a message comparison: whatever the load
      // path rejects, it rejects AS a load failure.
      expect(() => fromIdentityFile(file)).toThrow();
      try {
        fromIdentityFile(file);
      } catch (error) {
        expect((error as Error).message).not.toMatch(/^Cannot commit to a key state/);
      }
    }
  );

  it("refuses a file that records no threshold at all", () => {
    const file = toIdentityFile(createIdentity());
    expect(() => fromIdentityFile({ ...file, nextThreshold: undefined })).toThrow(
      /does not record the threshold committed for its next keys/
    );
  });

  it("refuses a file holding next keys but claiming no commitment", () => {
    const file = toIdentityFile(createIdentity());
    expect(() => fromIdentityFile({ ...file, nextThreshold: null })).toThrow(
      /holds next keys but records no threshold committed for them/
    );
  });
});

describe("strict JSON parsing of key-log deliveries (spec 015 S6.1)", () => {
  const identity = createIdentity({
    currentSeed: new Uint8Array(32).fill(21),
    nextSeed: new Uint8Array(32).fill(22)
  });
  const duplicate = (text: string): string => {
    const out = text.replace('"threshold":"1"', '"threshold":"9","threshold":"1"');
    expect(out).not.toBe(text);
    return out;
  };

  it("parseIdentityFile accepts the honest file and refuses a duplicate-key one", () => {
    const honest = JSON.stringify(toIdentityFile(identity));
    expect(parseIdentityFile(honest).id).toBe(identity.id);
    expect(() => parseIdentityFile(duplicate(honest))).toThrow(/duplicate key "threshold"/);
  });

  it("fromIdentityFile still takes an already-parsed value, which is why the parse is separate", () => {
    // Stated rather than assumed: a schema inspects the RESOLVED object, so the duplicate is
    // already gone by the time `fromIdentityFile` runs and it accepts the last-wins reading.
    // That is exactly why the strict parse has to happen on the bytes.
    const resolved = JSON.parse(duplicate(JSON.stringify(toIdentityFile(identity))));
    expect(fromIdentityFile(resolved).id).toBe(identity.id);
  });
});
