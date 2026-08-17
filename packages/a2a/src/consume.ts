/**
 * Consuming agent cards: fetch /.well-known/agent.json like any A2A client, then — when
 * the card carries the Kinnet extension — verify the claimed identity and represents
 * chain from signed records via discovery. The card is treated as untrusted input
 * throughout; only the signed records prove anything.
 */
import type { ParticipantId } from "@kinnet/protocol";
import { REPRESENTS_PREDICATE, verifyRepresentsChain } from "@kinnet/trust";
import { createDiscoveryView } from "@kinnet/verify";

import { AGENT_CARD_PATH, parseKinnetExtension, type AgentCard } from "./card.js";

export type ConsumeOptions = {
  /** Injected for tests and custom runtimes; defaults to the global fetch. */
  fetch?: typeof fetch;
  /** Clock injection for tests. */
  now?: () => Date;
};

export type AgentCardVerification =
  | { status: "no_kinnet_extension" }
  | { status: "unverified"; participantId: ParticipantId; reason: string }
  | {
      status: "verified";
      participantId: ParticipantId;
      discoveryUrl: string;
    };

export type ConsumedAgentCard = {
  card: AgentCard;
  kinnet: AgentCardVerification;
};

/**
 * Verifies a card's Kinnet extension against discovery. A card without the extension
 * is reported, not rejected — it is still a valid A2A card, just an unverifiable one.
 */
export async function verifyAgentCard(
  card: unknown,
  options: ConsumeOptions = {}
): Promise<AgentCardVerification> {
  const extension = parseKinnetExtension(card);
  if (!extension) {
    return { status: "no_kinnet_extension" };
  }

  const view = createDiscoveryView({
    discoveryUrl: extension.discoveryUrl,
    fetch: options.fetch,
    now: options.now
  });

  const state = await view.getKeyState(extension.participantId);
  if (!state || state.id !== extension.participantId) {
    return {
      status: "unverified",
      participantId: extension.participantId,
      reason: "agent_key_log_unresolved"
    };
  }

  // The card names the organization it claims to represent, so the represents question has a
  // known subject AND a known issuer — only the represented party may assert representation.
  // That is the whole decision key, so this is a point lookup on it rather than a scan of every
  // edge published about the agent, a list anyone can grow. A card that claims no organization
  // asks no representation question, and no relationship read happens.
  const now = options.now ?? (() => new Date());
  if (extension.organizationId) {
    const organizationId = extension.organizationId;
    const edge = await view.getRelationshipEdge(
      organizationId,
      extension.participantId,
      organizationId,
      REPRESENTS_PREDICATE
    );
    // The lookup narrows candidates; it does not authorize. The returned edge is still checked
    // for signature, expiry and revocation before the card counts as verified.
    const verdict = edge
      ? await verifyRepresentsChain(
          { agentId: extension.participantId, organizationId, edge },
          view,
          { now: now() }
        )
      : null;
    if (verdict?.valid !== true) {
      return {
        status: "unverified",
        participantId: extension.participantId,
        reason: "represents_chain_unverified"
      };
    }
  }

  return {
    status: "verified",
    participantId: extension.participantId,
    discoveryUrl: extension.discoveryUrl
  };
}

/** Fetches an agent's card from its well-known location and verifies it. */
export async function consumeAgentCard(
  agentUrl: string,
  options: ConsumeOptions = {}
): Promise<ConsumedAgentCard> {
  const fetchImpl = options.fetch ?? fetch;
  const cardUrl = new URL(AGENT_CARD_PATH, agentUrl);

  const response = await fetchImpl(cardUrl.href);
  if (!response.ok) {
    throw new Error(`Agent card request failed with ${response.status} for ${cardUrl.href}`);
  }

  const card = (await response.json()) as unknown;
  if (
    typeof card !== "object" ||
    card === null ||
    typeof (card as { name?: unknown }).name !== "string"
  ) {
    throw new Error(`No valid agent card at ${cardUrl.href}`);
  }

  return { card: card as AgentCard, kinnet: await verifyAgentCard(card, options) };
}
