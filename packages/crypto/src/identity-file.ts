/**
 * On-disk identity format. Contains secret key material — the file is local operator
 * state and is never sent to discovery (only the signed key log is published).
 */
import { commitToKeyState, replayKeyLog, type Identity } from "./log.js";
import { encodeKeyRef, fromMultibase, toMultibase } from "./encoding.js";
import { parseThreshold } from "./signature-set.js";
import { generateKeyPair, type KeyPair } from "./keys.js";
import { keyEventLogSchema, MAX_KEY_EVENT_KEYS, parseJsonStrict } from "@kinnet/protocol";

export type StoredKeyPair = {
  publicKey: string;
  secretKey: string;
};

export type IdentityFile = {
  id: string;
  keyEvents: Identity["log"];
  currentKeys: StoredKeyPair[];
  /** Pre-committed next keys — keep in split custody per spec 003. */
  nextKeys: StoredKeyPair[];
  /**
   * The threshold committed for `nextKeys`. Part of the pre-rotation commitment (003), so it
   * is required to reproduce that commitment and cannot be inferred from the keys alone.
   *
   * `null` when this holder holds no next keys — the custody-exit handover. That is a real
   * state, not a missing field, so it round-trips as `null`: an earlier draft wrote `""` for
   * it, which is neither a valid threshold nor a statement of absence, and produced a file the
   * library could write but never load.
   */
  nextThreshold: string | null;
};

function storeKeyPair(keyPair: KeyPair): StoredKeyPair {
  return {
    publicKey: encodeKeyRef(keyPair.publicKey),
    secretKey: toMultibase(keyPair.secretKey)
  };
}

function restoreKeyPair(stored: StoredKeyPair): KeyPair {
  const keyPair = generateKeyPair(fromMultibase(stored.secretKey));
  if (encodeKeyRef(keyPair.publicKey) !== stored.publicKey) {
    throw new Error("Stored public key does not match its secret key");
  }
  return keyPair;
}

export function toIdentityFile(identity: Identity): IdentityFile {
  return {
    id: identity.id,
    keyEvents: identity.log,
    currentKeys: identity.currentKeys.map(storeKeyPair),
    nextKeys: identity.nextKeys.map(storeKeyPair),
    nextThreshold: identity.nextThreshold
  };
}

/**
 * Parses an identity file from its TEXT form, refusing a delivery whose JSON carries a
 * duplicate object key at any depth (spec 015 S6.1), then validates it.
 *
 * The strict parse belongs here rather than at each caller because an identity file carries a
 * `KeyEvent` log: the participant id hashes the inception event's establishment data (002) and
 * every later event names its predecessor by digest, so one byte string that two parsers
 * resolve differently is one file describing two identities. {@link fromIdentityFile} still
 * takes an already-parsed value — a caller that legitimately holds an object rather than bytes
 * needs it — so this is the entry point for anything that starts from text.
 */
export function parseIdentityFile(text: string): Identity {
  return fromIdentityFile(parseJsonStrict(text));
}

export function fromIdentityFile(data: unknown): Identity {
  if (typeof data !== "object" || data === null) {
    throw new Error("Identity file is not a JSON object");
  }
  const file = data as Partial<IdentityFile>;

  // A pure length bound before replay, key restoration or hashing: the stored list is
  // caller-controlled, and a wider list cannot match any commitment a conforming key event
  // can reveal. Diagnose the identity FILE here rather than leaking `commitToKeyState`'s
  // producer-side error after doing all of the more expensive work below.
  const storedNextKeys = file.nextKeys ?? [];
  if (storedNextKeys.length > MAX_KEY_EVENT_KEYS) {
    throw new Error(
      `Identity file holds ${storedNextKeys.length} stored next keys, exceeding the maximum of ${MAX_KEY_EVENT_KEYS}`
    );
  }

  const log = keyEventLogSchema.parse(file.keyEvents);
  const state = replayKeyLog(log);
  if (file.id !== state.id) {
    throw new Error("Identity file ID does not match its key log");
  }

  const currentKeys = (file.currentKeys ?? []).map(restoreKeyPair);
  const nextKeys = storedNextKeys.map(restoreKeyPair);

  if (
    JSON.stringify(currentKeys.map((keyPair) => encodeKeyRef(keyPair.publicKey))) !==
    JSON.stringify(state.keys)
  ) {
    throw new Error("Stored current keys do not match the key log's current key set");
  }

  const latest = log[log.length - 1]!;
  // The commitment covers the next key STATE — keys AND threshold (003) — so a stored file
  // that records only the keys cannot reproduce it, and is refused rather than guessed at.
  const nextThreshold = file.nextThreshold;
  if (nextThreshold !== null && typeof nextThreshold !== "string") {
    throw new Error("Identity file does not record the threshold committed for its next keys");
  }
  if (nextThreshold === null) {
    // A handover identity holds no next keys, so there is no commitment of its own to check —
    // the log's `next` names a state only the committed holder can reveal.
    if (nextKeys.length > 0) {
      throw new Error("Identity file holds next keys but records no threshold committed for them");
    }
    return { id: state.id, log, currentKeys, nextKeys, nextThreshold: null };
  }
  // Diagnosed here rather than inside the hashing helper, which would blame `commitToKeyState`
  // for a defect in the file being loaded. BOTH halves of 015 S1 have to be covered for that to
  // hold: the domain, `t <= n`, and the protocol key-count bound checked before replay above.
  // Leaving any one to the helper would reintroduce the exact attribution confusion this block
  // exists to prevent through another precondition of the same commitment.
  const parsed = parseThreshold(nextThreshold);
  if (parsed === null) {
    throw new Error(
      `Identity file's committed next threshold "${nextThreshold}" is not a decimal string matching ^[1-9][0-9]*$ (spec 015 S1)`
    );
  }
  if (parsed > nextKeys.length) {
    throw new Error(
      `Identity file's committed next threshold "${nextThreshold}" exceeds its ${nextKeys.length} stored next key(s)`
    );
  }
  if (
    commitToKeyState(
      nextKeys.map((keyPair) => encodeKeyRef(keyPair.publicKey)),
      nextThreshold
    ) !== latest.next
  ) {
    throw new Error("Stored next keys do not match the log's pre-rotation commitment");
  }

  return { id: state.id, log, currentKeys, nextKeys, nextThreshold };
}
