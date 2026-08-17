/**
 * Continuing-authority re-check for long-lived HTTP streams (spec 013 §2.4.1).
 *
 * The subscribe request is authorized once at open by `Verifier.verify`, the same
 * decision every read makes. A stream then holds that authority open for hours,
 * so the node MUST re-run the decision periodically at a fresh `now` — this is
 * what `reauthorizeStream` does. It is deliberately not an HTTP verification:
 * there is no re-signed request, and the peer is not re-authenticated. Only the
 * authority is re-checked, so the caller supplies the state captured at open and
 * the current wall clock; the tool returns `{ authorized: true }` or a
 * terminate-with-reason verdict.
 *
 * Fail-closed rule (spec 013 §2.4.2 rule 4): every branch that cannot complete
 * — an unresolved key log, a thrown error, a resolver rejection whose reason we
 * do not recognize — MUST return `Terminated`, never `Authorized`. The previous
 * decision is never extended on the grounds that nothing was proven wrong. A
 * re-check that exhausts `ReauthorizeStreamOptions.budget` is one of those
 * branches: it terminates as `unverifiable` like any other incomplete one.
 */
import { canonicalDigest, safeVerificationCount } from "@kinnet/crypto";
import type { Grant, KeyRef, ParticipantId, Principal } from "@kinnet/protocol";
import {
  abilityCovers,
  verifyGrantChain,
  type TrustView,
  type VerificationBudget
} from "@kinnet/trust";

/**
 * The immutable subscription record captured at open. Everything the re-check
 * needs, and nothing else — no HTTP request, no headers, no signature. The
 * record's shape is the whole contract.
 */
export type StreamAuthRecord = {
  /** Owner-mode: signed with the subject's own key. Delegated: chain-authorized. */
  mode: "owner" | "delegated";
  /** The subject the stream serves (the inbox id — spec 013 §2.4.1). */
  subject: ParticipantId;
  /** The request keyid principal (spec 011): participant id or session KeyRef. */
  principal: Principal;
  /**
   * The KeyRef that satisfied the RFC 9421 signature at open. In owner mode
   * this is the participant key that signed; in delegated mode it is the leaf
   * key (the session key itself, or — on the multi-hop tail — the leaf
   * participant's key). The owner-mode arm checks that this key is still in
   * the subject's current key state (spec 013 T3, §2.4.3 rotation rule); the
   * delegated arm re-checks it only when the leaf principal is a participant.
   */
  satisfiedKey: KeyRef;
  /** The chain as presented at open; owner mode: null. */
  chain: Grant[] | null;
  /**
   * Verifier surface id (this node's participant id) — passed through to the
   * chain re-check so aud-restricted chains still admit us at `now`.
   */
  verifierId?: ParticipantId;
  /** Passed through to the chain re-check exactly as at open. */
  requireAud?: boolean;
  /** Passed through to the chain re-check exactly as at open. */
  evaluateCaveats?: (grant: Grant) => boolean;
  /**
   * The abilities the caller demands the chain still covers — for the SSE
   * route, `["msg/subscribe"]` plus any view-parity extension (`msg/read` for
   * the pending view, `msg/consent` for the consent view — spec 013 §2.5).
   */
  requiredAbilities?: string[];
};

/** Reason codes correspond to spec 013 §2.4.6 close reasons. */
export type StreamReauthorization =
  | { authorized: true }
  | {
      authorized: false;
      reason:
        | "expired"
        | "revoked"
        | "rotated"
        | "unverifiable"
        | "abilities_insufficient"
        | "audience_not_admitted"
        | "subject_drift";
    };

/**
 * A minimal view over the participant's current key state. `TrustView.getKeyLog`
 * returns the full log; the caller-side helpers replay it to a current state
 * (`packages/verify/src/discovery-view.ts` already does this via `getKeyState`),
 * so we accept an already-replayed accessor here for the same reason the SSE
 * route does — the node's discovery-view instance is shared, and re-replaying
 * on every re-check would duplicate work its cache already amortizes.
 *
 * It MUST return a state whose `id` is the id that was asked for, and the returned shape
 * carries `id` so that this module can check rather than trust. An accessor is an arbitrary
 * function supplied by a caller: `createDiscoveryView().getKeyState` binds, but nothing in
 * this type stopped a future caller from passing a raw replay, and an unbound one reopens the
 * substitution this module was hardened against — see {@link boundKeyState}.
 *
 * The optional second parameter is the re-check's shared {@link VerificationBudget}. It is
 * optional so that a one-argument accessor still satisfies this type; an accessor that ignores
 * it replays on whatever ceiling it sets for itself, which is what every caller got before this
 * parameter existed. `createDiscoveryView().getKeyState` accepts it and meters the replay
 * against it, rethrowing `VerificationBudgetExceeded` when it runs out.
 */
export type CurrentKeyStateFn = (
  id: ParticipantId,
  budget?: VerificationBudget
) => Promise<{ id: ParticipantId; keys: KeyRef[] } | null>;

/**
 * Resolves a current key state and DISCARDS one that belongs to anyone else.
 *
 * `KeyState.id` is derived from the log's own inception event, so an accessor backed by an
 * untrusted discovery host can hand back a perfectly valid state for a different participant.
 * The concrete attack this closes is narrow but real, and plain substitution does not reach
 * it: an attacker's ordinary log served at the subject's path yields keys that do not contain
 * `satisfiedKey`, so the stream already closed as `rotated`. What works is a CRAFTED log —
 * an inception listing `[attackerKey, victimKey]` at `threshold: "1"`, signed only by the
 * attacker. `verifyEventSignatures` permits `signature.length <= keys.length` and stops
 * verifying once the threshold is met, so it replays clean under the attacker's own id while
 * still listing the victim's key. Served at the victim's path after the victim rotates, it
 * makes `keys.includes(satisfiedKey)` true and holds open a stream that should have closed.
 *
 * Checked here rather than left to the caller because this is the module that decides whether
 * a stream stays open, and the guarantee must not depend on which accessor it was handed.
 */
async function boundKeyState(
  getKeyState: CurrentKeyStateFn,
  id: ParticipantId,
  budget: VerificationBudget | undefined
): Promise<{ id: ParticipantId; keys: KeyRef[] } | null> {
  const state = await getKeyState(id, budget);
  return state && state.id === id ? state : null;
}

export type ReauthorizeStreamOptions = {
  now?: Date;
  /**
   * The shared allowance for THIS call: both the chain re-check and the key-state lookups
   * spend from it, so what it bounds is one whole re-check rather than each stage separately.
   *
   * Omitted, every stage builds its own allowance from `view.maxSignatureVerifications` and a
   * caller gets one per stage — which bounds no single number the caller can reason about.
   *
   * Running out is TERMINAL, exactly like every other branch that cannot complete: a chain
   * refused on cost carries a `*_too_expensive` reason that is not in the mapped set and lands
   * on the fail-closed `unverifiable` default, and a `VerificationBudgetExceeded` thrown by a
   * budget-aware `getKeyState` is caught by this function's catch and becomes `unverifiable`
   * too. Spec 013 §2.4.1 requires termination on anything but authorized, and this option does
   * not change that.
   */
  budget?: VerificationBudget;
};

/**
 * Runs the spec 013 §2.4.1 re-authorization contract. Returns `Terminated` on
 * any branch that cannot complete cleanly — this is deliberate and load-bearing.
 */
export async function reauthorizeStream(
  record: StreamAuthRecord,
  view: TrustView,
  getKeyState: CurrentKeyStateFn,
  options: ReauthorizeStreamOptions = {}
): Promise<StreamReauthorization> {
  if (options.budget) {
    options.budget.remaining = safeVerificationCount(options.budget.remaining, 0);
  }
  const now = options.now ?? new Date();

  try {
    if (record.mode === "owner") {
      // Owner-mode reads verify against the CURRENT key state (spec 013 §2.4.3);
      // this ensures a rotated-out key stops streaming as soon as the view
      // catches up. Fail-closed on any unresolved lookup or thrown error.
      const state = await boundKeyState(getKeyState, record.subject, options.budget);
      if (!state) {
        return { authorized: false, reason: "unverifiable" };
      }
      if (!state.keys.includes(record.satisfiedKey)) {
        return { authorized: false, reason: "rotated" };
      }
      return { authorized: true };
    }

    // Delegated mode: run the full 009/011 chain decision at `now`. The
    // resolver already enforces expiry, revocation, `aud`, and issuer key-log
    // resolution, and gives us a reason for each failure — we translate to
    // spec-013 close reasons, leaving anything unmapped as `unverifiable`.
    //
    // A stream holds a request authorization open, so the re-check runs at request
    // purpose: spec 014's `grant_e2ee_not_request_valid` is unmapped and therefore
    // terminates the stream as `unverifiable`, which is the fail-closed answer.
    if (!record.chain || record.chain.length === 0) {
      return { authorized: false, reason: "unverifiable" };
    }
    const verdict = await verifyGrantChain(record.chain, view, {
      now,
      purpose: "request",
      ...(record.verifierId !== undefined ? { verifierId: record.verifierId } : {}),
      ...(record.requireAud !== undefined ? { requireAud: record.requireAud } : {}),
      ...(record.evaluateCaveats !== undefined ? { evaluateCaveats: record.evaluateCaveats } : {}),
      ...(options.budget !== undefined ? { budget: options.budget } : {})
    });
    if (!verdict.valid) {
      switch (verdict.reason) {
        case "grant_expired":
          return { authorized: false, reason: "expired" };
        case "grant_revoked":
          return { authorized: false, reason: "revoked" };
        case "grant_audience_not_admitted":
        case "grant_audience_required":
          return { authorized: false, reason: "audience_not_admitted" };
        default:
          return { authorized: false, reason: "unverifiable" };
      }
    }
    if (verdict.audienceId !== record.principal) {
      // The chain's leaf audience has drifted from the request's keyid — the
      // stream's authorization is no longer coherent.
      return { authorized: false, reason: "unverifiable" };
    }
    if (verdict.subjectId !== record.subject) {
      return { authorized: false, reason: "subject_drift" };
    }
    if (record.requiredAbilities?.length) {
      const missing = record.requiredAbilities.some(
        (required) => !verdict.abilities.some((granted) => abilityCovers(granted, required))
      );
      if (missing) {
        return { authorized: false, reason: "abilities_insufficient" };
      }
    }

    // A key-audience leaf: the leaf key must still verify the chain (already
    // done by the resolver) — no owner-mode style current-state check is
    // possible because the KeyRef lives in no log (spec 011).
    //
    // A participant-audience leaf: the leaf key that signed the request must
    // still be in that participant's current key state (spec 013 §2.4.1
    // additional clause — the owner-mode rule composes on top).
    if (record.principal.startsWith("pk_")) {
      const leafState = await boundKeyState(
        getKeyState,
        record.principal as ParticipantId,
        options.budget
      );
      if (!leafState) {
        return { authorized: false, reason: "unverifiable" };
      }
      if (!leafState.keys.includes(record.satisfiedKey)) {
        return { authorized: false, reason: "rotated" };
      }
    }

    return { authorized: true };
  } catch {
    return { authorized: false, reason: "unverifiable" };
  }
}

/**
 * The digest of a chain's root grant — the delegation-tree identity used for
 * per-tree budget accounting (spec 013 §2.8). Owner mode: null (no chain).
 */
export function delegationTreeDigest(chain: Grant[] | null): string | null {
  if (!chain || chain.length === 0) {
    return null;
  }
  return canonicalDigest(chain[chain.length - 1]!);
}
