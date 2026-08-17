/**
 * The MLS runtime adapter contract — spec 014, decision I11.
 *
 * Spec 014 puts MLS only in clients and pins a *profile*, not a library: "OpenMLS, mls-rs,
 * or a successor are interchangeable behind RFC 9420 plus the profile". This file is that
 * seam in code. It is pure types plus one error class — no MLS runtime is imported here,
 * and nothing in this package depends on one. The `ts-mls`-backed implementation lives in
 * `@kinnet/mls`; the SDK's E2EE flows accept an {@link MlsRuntime} and never name a
 * concrete implementation, so replacing the runtime is a contained change (I11's condition
 * 1: no `ts-mls` type crosses into `apps/*`, `packages/sdk`, or the node).
 *
 * Byte conventions, pinned here because both sides of the seam must agree:
 *
 *  - Every wire blob (`keyPackage`, `welcome`, `message`) is a serialized RFC 9420
 *    `MLSMessage` — the self-describing framing that carries `version` and `wireformat` —
 *    not a bare inner struct. These are the bytes that ride envelopes and the KeyPackage
 *    routes, base64url-encoded at the envelope layer.
 *  - `credential` is the serialized `PNCredential` struct (this package's
 *    `encodePNCredential`), i.e. the content of an MLS credential of type
 *    `KINNET_CREDENTIAL_TYPE` (0xF001).
 *  - `signaturePublicKey` is a raw 32-byte Ed25519 public key (the profile's ciphersuite
 *    fixes the algorithm), so callers can derive the `KeyRef` that evidence records and
 *    credential audiences use.
 *  - `privateKeyPackage`, `secretKey`, and serialized session blobs are opaque,
 *    runtime-defined encodings. They contain secret material in the clear; callers own
 *    encryption at rest.
 *
 * Profile enforcement lives on the implementation side of this seam wherever the check is
 * mechanical (I11's condition 2 among them): the pinned ciphersuite and credential type,
 * PrivateMessage-only framing, rejection of standalone proposals and every out-of-profile
 * MLS feature, `required_capabilities` validation *before* committing an Add, the
 * multiple-of-256 padding precondition on application plaintext, and empty
 * `authenticated_data` on application messages. Checks that need records, key logs, or
 * judgment — evidence coverage, credential-chain verification, the wait-not-reject rules —
 * live above the seam, in the SDK; that is why commits are inspect-then-apply here.
 */

/** A device's MLS leaf signature keypair. `secretKey`'s encoding is runtime-defined. */
export type MlsLeafKeyPair = {
  /** Raw 32-byte Ed25519 public key — encode with `encodeKeyRef` for evidence/credentials. */
  publicKey: Uint8Array;
  /** Opaque runtime-defined secret encoding. Secret material; never leaves the device. */
  secretKey: Uint8Array;
};

/** A generated KeyPackage: the publishable half and the private half to hold for the Welcome. */
export type MlsKeyPackage = {
  /** Serialized `MLSMessage(key_package)` — the bytes published to the KeyPackage pool. */
  keyPackage: Uint8Array;
  /**
   * Opaque runtime-defined private half (init/HPKE/signature secrets). Persist until the
   * matching Welcome is processed, then destroy: spec 014 — "a joiner MUST delete a
   * KeyPackage's private init key on processing the first Welcome that uses it".
   */
  privateKeyPackage: Uint8Array;
};

/** One leaf of the ratchet tree, as the SDK renders and validates it (spec 014 rule 3). */
export type MlsLeafView = {
  /** The RFC 9420 leaf index — stable across removals, unlike compacted member arrays. */
  leafIndex: number;
  /** Raw 32-byte Ed25519 leaf signature key. */
  signaturePublicKey: Uint8Array;
  /** The serialized `PNCredential` carried by this leaf (decode to a Grant chain). */
  credential: Uint8Array;
};

/**
 * What a commit would do, read without applying it. The SDK validates 014's commit rules
 * (evidence coverage, authorization, complete removal, credential structure) against this
 * view, then either applies the commit or waits — a missing evidence record is a wait
 * condition, never a rejection, so inspection MUST NOT advance group state, and inspecting
 * MUST NOT prevent the same bytes from being applied later or discarded unapplied.
 */
export type MlsCommitInspection = {
  /** The commit's `authenticated_data` — the `PNCommitBinding` bytes to decode. */
  authenticatedData: Uint8Array;
  /** The epoch this commit extends (the current epoch; 014's evidence `epoch` field). */
  epoch: bigint;
  /** The committing leaf, or undefined when the runtime cannot name it pre-application. */
  committerLeafIndex: number | undefined;
  /** Leaves the commit adds, in proposal order. */
  adds: { signaturePublicKey: Uint8Array; credential: Uint8Array }[];
  /** Leaves the commit removes. */
  removes: MlsLeafView[];
  /** Whether the commit updates the committer's own leaf (path rotation / rule 5). */
  updatesPath: boolean;
  /**
   * Whether the commit's UpdatePath installs a signature key different from the committer's
   * pre-commit leaf key. RFC 9420 permits this; the 014 profile does not — rotating a
   * device's signature key is a `device-remove` + `device-add` pair with its own evidence,
   * never an update (rule 4). Implementations MUST derive this by comparing the committer's
   * leaf before and after; validators reject the commit when it is true. False whenever
   * `updatesPath` is false.
   */
  pathSignatureKeyChanged: boolean;
  /**
   * The committer's post-update leaf, when `updatesPath` is true and the runtime can surface
   * it — so rule 3's structural credential checks run on a re-issued credential exactly as
   * they do on added leaves.
   */
  pathLeaf?: { signaturePublicKey: Uint8Array; credential: Uint8Array };
};

/** The state change an applied commit produced. */
export type MlsAppliedCommit = {
  /** The epoch after the commit. */
  epoch: bigint;
  /** True when the commit removed this session's own leaf — the group is over for us. */
  removedSelf: boolean;
};

/** A processed incoming message that carried application content. */
export type MlsApplicationMessage = {
  kind: "application";
  /** The decrypted, still-padded plaintext — unpad with `unpadApplicationContent`. */
  plaintext: Uint8Array;
  /** The authoring leaf (spec 014: authorship renders from the MLS layer, not `from`). */
  senderLeafIndex: number;
  /** The authoring leaf's view at processing time, for authorship rendering. */
  sender: MlsLeafView;
};

/** A processed incoming message that is a commit, held for inspect-then-apply. */
export type MlsCommitMessage = {
  kind: "commit";
  inspection: MlsCommitInspection;
};

/**
 * A commit for an epoch this session has already passed. Spec 014: re-delivery is normal
 * and MUST be ignored, never treated as an error — and the old epoch's handshake keys may
 * already be destroyed, so no inspection is offered.
 */
export type MlsStaleCommit = {
  kind: "staleCommit";
  /** The stale message's epoch (cleartext in MLS framing). */
  epoch: bigint;
};

export type MlsReceivedMessage = MlsApplicationMessage | MlsCommitMessage | MlsStaleCommit;

/**
 * Thrown by an adapter implementation when bytes or a request violate the pinned profile:
 * a PublicMessage, a standalone proposal, an out-of-profile MLS feature, a wrong
 * ciphersuite or credential type, application plaintext that is not a positive multiple of
 * 256 bytes, non-empty application `authenticated_data`, or an Add whose KeyPackage fails
 * the group's `required_capabilities`. Distinct from transport/processing failures so the
 * SDK can treat profile violations as protocol errors (fail closed) rather than retries.
 */
export class MlsProfileViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MlsProfileViolation";
  }
}

/**
 * One MLS group, held by one device. Methods that change state do so atomically inside the
 * session (implementations own the immutable-state threading of their runtime); after
 * `removedSelf`, every state-changing method throws.
 *
 * Serialization: `serialize()` returns an opaque runtime-defined blob (secret material in
 * the clear — encrypt at rest) that `MlsRuntime.loadSession` restores. A serialized-then-
 * restored session MUST be able to continue exactly where it left off, including applying
 * a commit that was inspected before serialization.
 */
export interface MlsGroupSession {
  /** The MLS `group_id` — for a conforming group, `groupIdFromConversationId(id)` bytes. */
  groupId(): Uint8Array;
  /** The current epoch. */
  epoch(): bigint;
  /** This device's own leaf index. */
  ownLeafIndex(): number;
  /** Every occupied leaf, by leaf index — the device-set rendering data (spec 014). */
  leaves(): MlsLeafView[];

  /**
   * Encrypts application content into a `MLSMessage(PrivateMessage)`. `paddedPlaintext`
   * MUST already be `padApplicationContent` output (a positive multiple of 256 bytes) —
   * implementations throw {@link MlsProfileViolation} otherwise and MUST NOT add their own
   * padding or any `authenticated_data`.
   */
  encryptApplication(paddedPlaintext: Uint8Array): Promise<Uint8Array>;

  /**
   * Processes one incoming `MLSMessage(PrivateMessage)`. Application messages ratchet
   * forward and return content; commits are returned inspected but NOT applied; a commit
   * for an epoch this session has already passed returns `{ kind: "staleCommit" }` (spec
   * 014: ignore, never error). A PublicMessage, a standalone proposal, or any
   * out-of-profile content throws {@link MlsProfileViolation}.
   */
  receive(mlsMessage: Uint8Array): Promise<MlsReceivedMessage>;

  /**
   * Applies a commit previously returned by {@link receive} — the same bytes, after the
   * SDK's validity rules passed. Idempotence is the caller's job via the epoch check.
   */
  applyCommit(mlsMessage: Uint8Array): Promise<MlsAppliedCommit>;

  /**
   * Creates a commit adding the given KeyPackages (proposals by value, spec 014), with
   * `authenticatedData` as its `authenticated_data` (the encoded `PNCommitBinding`).
   * Validates each KeyPackage against the group's `required_capabilities` and the pinned
   * profile BEFORE committing (I11 condition 2) — throws {@link MlsProfileViolation} on
   * failure, since the runtime skips this check for the committer's own Adds. Returns the
   * commit message and the Welcome (with `ratchet_tree`) for the added leaves. The commit
   * is applied to this session immediately (the committer advances per RFC 9420); the
   * returned bytes are what every other member receives.
   */
  commitAdd(options: {
    keyPackages: Uint8Array[];
    authenticatedData: Uint8Array;
  }): Promise<{ commit: Uint8Array; welcome: Uint8Array; epoch: bigint }>;

  /** Creates and applies a commit removing the given leaves (by leaf index), by value. */
  commitRemove(options: {
    leafIndexes: number[];
    authenticatedData: Uint8Array;
  }): Promise<{ commit: Uint8Array; epoch: bigint }>;

  /**
   * Creates and applies an empty commit rotating this leaf's path (rule 5 PCS refresh),
   * optionally installing a re-issued credential for the SAME signature key (rule 4 —
   * implementations MUST refuse a credential-bearing update that would change the
   * signature key). `authenticatedData` is the encoded empty `PNCommitBinding`.
   */
  commitSelfUpdate(options: {
    authenticatedData: Uint8Array;
    newCredential?: Uint8Array;
  }): Promise<{ commit: Uint8Array; epoch: bigint }>;

  /** Serializes the full session state. Secret material in the clear — encrypt at rest. */
  serialize(): Promise<Uint8Array>;
}

/** Factory surface — what a device needs before or without holding a group. */
export interface MlsRuntime {
  /** Generates a leaf signature keypair (fresh per conversation, spec 014's SHOULD). */
  generateLeafKeyPair(): Promise<MlsLeafKeyPair>;

  /**
   * Generates a KeyPackage for publication: pinned ciphersuite, credential type 0xF001
   * only (the profile's capabilities rule), `lifetime.notAfter` supplied by the caller
   * (spec 014: no later than the earliest `expiresAt` in the leaf's credential chain).
   */
  generateKeyPackage(options: {
    credential: Uint8Array;
    leafKeyPair: MlsLeafKeyPair;
    lifetime: { notBefore: bigint; notAfter: bigint };
  }): Promise<MlsKeyPackage>;

  /**
   * Creates a new group at epoch 0 with the caller's leaf and the profile's
   * `required_capabilities` extension (credential type 0xF001), under the given
   * `group_id` (the conversation's raw multihash bytes).
   */
  createGroup(options: {
    groupId: Uint8Array;
    keyPackage: MlsKeyPackage;
  }): Promise<MlsGroupSession>;

  /**
   * Joins from a `MLSMessage(welcome)` using a held KeyPackage's private half. Throws when
   * the Welcome does not address this KeyPackage (callers try each pending package and
   * ignore misses — spec 014: "Welcomes for its other devices are ignored, not errors")
   * and {@link MlsProfileViolation} when the Welcome lacks the `ratchet_tree` extension.
   * Callers MUST destroy the private half after the first successful join and refuse a
   * second Welcome for the same package (spec 014's serve-once rule is client-side).
   */
  joinFromWelcome(options: {
    welcome: Uint8Array;
    keyPackage: MlsKeyPackage;
  }): Promise<MlsGroupSession>;

  /** Restores a session from `MlsGroupSession.serialize` output. */
  loadSession(serialized: Uint8Array): Promise<MlsGroupSession>;
}
