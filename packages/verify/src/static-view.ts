/**
 * A {@link DiscoveryView} over records already in hand — no network, no cache, no clock.
 *
 * Verification in this repo has always been offline-capable in PRINCIPLE: the trust resolver
 * takes a `TrustView` and `verifyGrantChain` never fetches anything itself. In practice the only
 * shipped view was `createDiscoveryView`, and `createVerifier` built one internally, so "verify
 * this from bytes I already hold" had no implementation — every caller wanting it wrote a fake
 * view, and each fake re-decided the parts of the contract that are easy to get wrong (the
 * issuer-targeted revocation bound, the tuple re-check on a relationship edge, whether a key log
 * belongs to the id it was asked about).
 *
 * This is that view, written once and against the same contract the discovery-backed one
 * observes. It is a fixture holder, not a store: nothing here mutates after construction.
 *
 * WHAT IT DOES NOT DO, and deliberately: it does not verify anything. Every method is a lookup,
 * and the resolver re-validates whatever comes back — signatures, expiry, issuer membership,
 * key-log replay. A view is an untrusted source in this package's threat model even when the
 * records came from the caller's own disk, and building one that "pre-validated" its inputs
 * would only invite a caller to skip the check that actually counts.
 */
import {
  deriveParticipantId,
  replayKeyLogFor,
  safeVerificationCount,
  VerificationBudgetExceeded,
  type KeyState
} from "@kinnet/crypto";
import type { KeyEvent, ParticipantId, Relationship, Revocation } from "@kinnet/protocol";
import { beginVerificationOperation, verificationWorkOptions } from "@kinnet/trust";

import type { DiscoveryView } from "./discovery-view.js";

export type StaticTrustViewOptions = {
  /**
   * Key logs, one array of events per participant, keyed by NOTHING — the id each log answers
   * for is derived from the log itself by replaying it, exactly as a verifier would.
   *
   * Taking a map keyed by participant id was the alternative and it is worse: the key would be
   * caller-asserted and the log would be the evidence, so a mistyped key produces a view that
   * serves one identity's log at another's id — the precise substitution `getKeyState` exists to
   * catch, manufactured by the fixture instead of by an attacker. Deriving it means a log can
   * only ever be filed under the identity it actually replays as.
   *
   * A log that does not replay is kept and served anyway. It is not this view's job to reject
   * it: the resolver's replay is what decides, and a test whose whole point is a broken log must
   * be able to put one here. Such a log is filed under the id its INCEPTION event derives, which
   * is the same id a verifier would ask about — so `getKeyLog` hands it over and `getKeyState`
   * answers `null`, exactly as a discovery host serving the same bytes would.
   *
   * A log with NO inception event is skipped: it answers for nobody, and there is no id to file
   * it under.
   */
  keyLogs?: readonly (readonly KeyEvent[])[];
  /**
   * Revocations this view knows about. Served subject to the issuer-targeted contract on
   * {@link DiscoveryView.getRevocations} — see the method below for what that costs.
   */
  revocations?: readonly Revocation[];
  /**
   * Relationship edges, answered as point lookups on the (issuer, subject, object, predicate)
   * decision tuple. Never listed: `getRelationshipEdge` is a lookup by decision key precisely so
   * an attacker cannot flip an ALLOW to a DENY by publishing edges that name the subject, and a
   * view that scanned would reintroduce that.
   */
  relationships?: readonly Relationship[];
  /**
   * Ceiling on the Ed25519 verifications one key-log replay may spend, passed through to the
   * resolver.
   *
   * Omitted by default, which is correct for the case this view is built for: the records are
   * the caller's own, the source is in-process, and `TrustView` documents that an in-process
   * view need not set this. A caller replaying logs it did not author — a fixture corpus from a
   * third party, a conformance suite — should set it.
   */
  maxSignatureVerifications?: number;
};

export type StaticTrustView = DiscoveryView & {
  /** The participant ids this view holds a key log for. Useful when writing fixtures. */
  participantIds(): ParticipantId[];
};

/** The tuple `getRelationshipEdge` is keyed by, joined with a separator no id can contain. */
function edgeKey(issuerId: string, subjectId: string, objectId: string, predicate: string): string {
  return JSON.stringify([issuerId, subjectId, objectId, predicate]);
}

export function createStaticTrustView(options: StaticTrustViewOptions = {}): StaticTrustView {
  const logs = new Map<ParticipantId, KeyEvent[]>();
  for (const events of options.keyLogs ?? []) {
    const log = [...events];
    const inception = log[0];
    if (inception === undefined) {
      // An empty log answers for no one; there is no id to file it under. Skipped rather than
      // thrown so a caller can pass a sparse fixture array without pre-filtering it.
      continue;
    }
    // The id comes from the INCEPTION event's establishment data (spec 002), not from a replay.
    //
    // Two reasons, and the second is the important one. Deriving costs one hash where a replay
    // costs an Ed25519 verification per event, so filing a fixture corpus does not pay for
    // verification nobody asked for — and this runs at CONSTRUCTION, before any caller has said
    // which log it cares about. More: an unreplayable log still has an inception event and still
    // answers for exactly one identity, so it can be filed and SERVED, which is what lets a test
    // whose whole point is a broken log put one here. Replaying to derive would have silently
    // dropped it and turned "this log does not replay" into "there is no such participant" — two
    // different verdicts, and only one of them is true.
    //
    // Nothing is trusted as a result: `getKeyState` still replays, bound to the id, and the
    // resolver replays again on its own account.
    const id: ParticipantId = deriveParticipantId({
      seq: inception.seq,
      kind: inception.kind,
      keys: inception.keys,
      threshold: inception.threshold,
      next: inception.next
    });
    logs.set(id, log);
  }

  const revocations = [...(options.revocations ?? [])];

  const edges = new Map<string, Relationship>();
  for (const edge of options.relationships ?? []) {
    // LAST WRITER WINS on a duplicate tuple. Discovery holds one record per decision key, and
    // the whole point of `getRelationshipEdge` is that a tuple has one answer; keeping both and
    // picking one at lookup time would make this view able to express a state the real one
    // cannot.
    edges.set(edgeKey(edge.issuedBy, edge.subjectId, edge.objectId, edge.predicate), edge);
  }

  const view: StaticTrustView = {
    ...(options.maxSignatureVerifications !== undefined
      ? { maxSignatureVerifications: options.maxSignatureVerifications }
      : {}),

    async getKeyLog(id) {
      return logs.get(id) ?? null;
    },

    async getRevocations(revokesDigest, issuerIds) {
      // TWO rules, and the second is a hard contract rather than an optimisation.
      //
      // A revocation's identity is (issuer, revoked-digest), so at most ONE record can exist per
      // issuer for a given digest — and `TrustView.getRevocations` states that a view returning
      // more than one per distinct issuer describes records that cannot exist, which the
      // resolver treats as a hostile answer and THROWS on rather than sifting. A fixture holding
      // two revocations of one digest by one issuer (two signatures, two `revokedAt` values —
      // easy to write by accident) would trip that and fail the test with an error about the
      // view rather than about the thing under test. Deduping per issuer here keeps this view
      // inside the contract by construction.
      //
      // Which one survives does not matter to the caller: the resolver re-validates whatever
      // comes back — issuer membership, signature, and the digest — and any record it accepts
      // means the same thing, namely that this digest is revoked by an authorized issuer.
      const wanted = new Set(issuerIds);
      const perIssuer = new Map<string, Revocation>();
      for (const revocation of revocations) {
        if (revocation.revokes !== revokesDigest || !wanted.has(revocation.issuerId)) {
          continue;
        }
        if (!perIssuer.has(revocation.issuerId)) {
          perIssuer.set(revocation.issuerId, revocation);
        }
      }
      return [...perIssuer.values()];
    },

    async getKeyState(id, budget, operation): Promise<KeyState | null> {
      if (operation) {
        // Same guard the discovery view carries, for the same reason: `getKeyState` is the one
        // lower-level consumer handed an already-started operation, and validating that it
        // belongs to THIS view is what stops a foreign operation spending the wrong outer meter.
        // Being in-process buys no exemption — a composing caller can hold several views.
        beginVerificationOperation(view, { operation });
      }
      if (budget) {
        budget.remaining = safeVerificationCount(budget.remaining, 0);
      }
      const events = logs.get(id);
      if (!events) {
        return null;
      }
      try {
        // BOUND to `id` via `replayKeyLogFor`, exactly as the discovery view binds. Records here
        // came from the caller rather than from a hostile host, so the substitution this guards
        // against is a fixture mistake rather than an attack — but a view whose binding depends
        // on where its records came from would be the wrong shape to test a verifier with.
        return replayKeyLogFor(id, events, {
          ...(operation
            ? verificationWorkOptions(operation)
            : {
                maxSignatureVerifications: budget
                  ? budget.remaining
                  : options.maxSignatureVerifications,
                ...(budget
                  ? { onSignatureVerifications: (spent: number) => (budget.remaining -= spent) }
                  : {})
              })
        });
      } catch (error) {
        // A COST refusal is rethrown for a caller that opted into the budget protocol, so
        // `createVerifier` can report `agent_key_log_too_expensive` (503) instead of
        // `agent_key_log_unresolved` (401) — the distinction is the whole reason those two
        // reasons are separate, and swallowing it here would make an injected view quietly
        // behave differently from a discovery-backed one.
        if ((budget || operation) && error instanceof VerificationBudgetExceeded) {
          throw error;
        }
        // Everything else — an unreplayable log, a substituted one — becomes `null`. This
        // method has no reason channel, and `null` is fail-closed at every caller.
        return null;
      }
    },

    async getRelationshipEdge(issuerId, subjectId, objectId, predicate) {
      return edges.get(edgeKey(issuerId, subjectId, objectId, predicate)) ?? null;
    },

    cacheSize() {
      // Nothing is cached — every answer is already in memory and none of it expires. Reported
      // as 0 rather than as the fixture size: this number means "entries that could be evicted",
      // and an operator or test reading it as fixture size would be misled.
      return 0;
    },

    cacheSweepCount() {
      return 0;
    },

    participantIds() {
      return [...logs.keys()];
    }
  };
  return view;
}
