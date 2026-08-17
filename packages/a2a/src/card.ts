/**
 * A2A agent cards with a Kinnet identity extension. The card stays a plain A2A card —
 * any A2A client can consume it — while the extension carries a pointer (participant
 * ID + discovery URL) that lets a Kinnet-aware counterparty verify the agent's identity
 * and represents chain from signed records, which the card alone cannot prove.
 */
import { participantIdSchema, type ParticipantId, type ParticipantProfile } from "@kinnet/protocol";

/** Where A2A clients expect the card. */
export const AGENT_CARD_PATH = "/.well-known/agent.json";

/** The participant extension, advertised in capabilities.extensions. */
export const PN_EXTENSION_URI = "urn:pn:participant:v1";

export type AgentSkill = {
  id: string;
  name: string;
  description?: string;
  tags?: string[];
};

export type AgentExtension = {
  uri: string;
  description?: string;
  required?: boolean;
  params?: Record<string, unknown>;
};

export type AgentCard = {
  protocolVersion: string;
  name: string;
  description: string;
  url: string;
  version: string;
  capabilities: { extensions?: AgentExtension[] } & Record<string, unknown>;
  defaultInputModes: string[];
  defaultOutputModes: string[];
  skills: AgentSkill[];
} & Record<string, unknown>;

export type KinnetExtensionParams = {
  participantId: ParticipantId;
  discoveryUrl: string;
  /** The organization the card claims this agent represents, verifiable via discovery. */
  organizationId?: ParticipantId;
};

export type BuildAgentCardOptions = KinnetExtensionParams & {
  name: string;
  description?: string;
  /** The agent's A2A endpoint. */
  url: string;
  version?: string;
  skills?: AgentSkill[];
  /** Extra or overriding A2A card fields, merged last. */
  card?: Record<string, unknown>;
};

export function buildAgentCard(options: BuildAgentCardOptions): AgentCard {
  const extension: AgentExtension = {
    uri: PN_EXTENSION_URI,
    description: "Kinnet participant identity, verifiable from signed records via discovery",
    params: {
      participantId: options.participantId,
      discoveryUrl: options.discoveryUrl,
      ...(options.organizationId ? { organizationId: options.organizationId } : {})
    }
  };

  return {
    protocolVersion: "0.3.0",
    name: options.name,
    description: options.description ?? "",
    url: options.url,
    version: options.version ?? "0.0.1",
    capabilities: { extensions: [extension] },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills: options.skills ?? [],
    ...options.card
  };
}

/** Derives a card from a published participant profile; capabilities become skills. */
export function agentCardFromProfile(
  profile: ParticipantProfile,
  options: Omit<BuildAgentCardOptions, "participantId" | "name" | "description" | "skills">
): AgentCard {
  return buildAgentCard({
    ...options,
    participantId: profile.id,
    name: profile.displayName,
    description: profile.description,
    skills: profile.capabilities.map((capability) => ({
      id: capability,
      name: capability
    }))
  });
}

/**
 * Extracts the Kinnet extension from an untrusted card. Returns null when the card
 * does not carry one (or carries a malformed one) — the card is then just an A2A card.
 */
export function parseKinnetExtension(card: unknown): KinnetExtensionParams | null {
  if (typeof card !== "object" || card === null) {
    return null;
  }
  const capabilities = (card as { capabilities?: unknown }).capabilities;
  const extensions = (capabilities as { extensions?: unknown } | undefined)?.extensions;
  if (!Array.isArray(extensions)) {
    return null;
  }

  for (const extension of extensions) {
    if (typeof extension !== "object" || extension === null) {
      continue;
    }
    const { uri, params } = extension as { uri?: unknown; params?: unknown };
    if (uri !== PN_EXTENSION_URI || typeof params !== "object" || params === null) {
      continue;
    }

    const { participantId, discoveryUrl, organizationId } = params as Record<string, unknown>;
    const parsedParticipant = participantIdSchema.safeParse(participantId);
    if (!parsedParticipant.success || typeof discoveryUrl !== "string" || discoveryUrl === "") {
      continue;
    }
    const parsedOrganization =
      organizationId === undefined ? null : participantIdSchema.safeParse(organizationId);
    if (parsedOrganization && !parsedOrganization.success) {
      continue;
    }

    return {
      participantId: parsedParticipant.data,
      discoveryUrl,
      ...(parsedOrganization ? { organizationId: parsedOrganization.data } : {})
    };
  }

  return null;
}
