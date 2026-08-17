import {
  canonicalDigest,
  createIdentity,
  signThresholdRecord,
  type Identity
} from "@kinnet/crypto";
import type { Grant, ParticipantId, Principal } from "@kinnet/protocol";
import { describe, expect, it } from "vitest";

import {
  createFinancialCaveatEvaluator,
  evaluateFinancialCaveats,
  verifyGrantChain,
  type FinancialAction,
  type TrustView
} from "../src/index.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

const NOW = new Date("2026-06-12T00:00:00.000Z");
const ISSUED_AT = new Date(NOW.getTime() - 86_400_000).toISOString();

// A treasury delegates payment authority to an operations service, which attenuates it
// down to an agent under a spending cap. Two links, both participant audiences, so spec
// 011 requires no `aud` and the financial caveats are the only foreign ones in play.
const treasury = createIdentity({ currentSeed: seed(101), nextSeed: seed(102) });
const ops = createIdentity({ currentSeed: seed(103), nextSeed: seed(104) });
const agent = createIdentity({ currentSeed: seed(105), nextSeed: seed(106) });

const view: TrustView = {
  async getKeyLog(id) {
    return (
      new Map([treasury, ops, agent].map((identity) => [identity.id, identity.log])).get(id) ?? null
    );
  },
  async getRevocations() {
    return [];
  }
};

type GrantFields = {
  subjectId: ParticipantId;
  issuerId: Principal;
  audienceId: Principal;
  abilities: string[];
  proof: string | null;
  caveats: Record<string, unknown>;
};

function makeGrant(signer: Identity, fields: GrantFields): Grant {
  return signThresholdRecord({ issuedAt: ISSUED_AT, ...fields }, [
    signer.currentKeys[0]!.secretKey
  ]) as Grant;
}

function rootGrant(caveats: Record<string, unknown> = {}): Grant {
  return makeGrant(treasury, {
    subjectId: treasury.id,
    issuerId: treasury.id,
    audienceId: ops.id,
    abilities: ["payments"],
    proof: null,
    caveats
  });
}

function leafGrant(parent: Grant, caveats: Record<string, unknown>): Grant {
  return makeGrant(ops, {
    subjectId: treasury.id,
    issuerId: ops.id,
    audienceId: agent.id,
    abilities: ["payments/transfer"],
    proof: canonicalDigest(parent),
    caveats
  });
}

const LEAF_CAVEATS = {
  maxAmount: "1000.00",
  currency: "USD",
  beneficiary: ["acct:vendor-7", "acct:vendor-9"]
};

const CONFORMING: FinancialAction = {
  amount: "250.75",
  currency: "USD",
  beneficiary: "acct:vendor-7"
};

describe("evaluateFinancialCaveats — amounts are money, not floats", () => {
  const cap = { maxAmount: "100.00", currency: "USD" };

  it("accepts an action exactly at the cap", () => {
    expect(evaluateFinancialCaveats(cap, { amount: "100.00", currency: "USD" })).toBe(true);
    expect(evaluateFinancialCaveats(cap, { amount: "100", currency: "USD" })).toBe(true);
  });

  it("rejects an action one minor unit over the cap", () => {
    expect(evaluateFinancialCaveats(cap, { amount: "100.01", currency: "USD" })).toBe(false);
    // And one whole unit over, so the rejection is not an artifact of the scale.
    expect(evaluateFinancialCaveats(cap, { amount: "101", currency: "USD" })).toBe(false);
  });

  it("compares across differing fractional lengths without rounding either side away", () => {
    const accepts = (maxAmount: string, amount: string) =>
      evaluateFinancialCaveats({ maxAmount, currency: "USD" }, { amount, currency: "USD" });

    // Trailing zeros carry no weight: these pairs name the same amount in both directions.
    expect(accepts("10", "10.00")).toBe(true);
    expect(accepts("10.00", "10")).toBe(true);
    expect(accepts("10.001", "10.0010")).toBe(true);
    expect(accepts("10.0010", "10.001")).toBe(true);

    // But a digit past the cap's own precision is NOT rounded off — the comparison
    // normalizes up to the longer fractional length, so the extra digit still counts.
    expect(accepts("10", "10.000000000000000001")).toBe(false);
    expect(accepts("10.001", "10.0011")).toBe(false);
    expect(accepts("10.0011", "10.001")).toBe(true);

    // 0.1 + 0.2 territory: exact under BigInt, wrong under IEEE-754 doubles.
    expect(accepts("0.3", "0.30000000000000004")).toBe(false);
    expect(accepts("0.3", "0.1")).toBe(true);
  });

  it("accepts an 18-digit fractional amount at full precision", () => {
    expect(
      evaluateFinancialCaveats(
        { maxAmount: "1.000000000000000001", currency: "ETH" },
        { amount: "1.000000000000000001", currency: "ETH" }
      )
    ).toBe(true);
    expect(
      evaluateFinancialCaveats(
        { maxAmount: "1.000000000000000001", currency: "ETH" },
        { amount: "1.000000000000000002", currency: "ETH" }
      )
    ).toBe(false);
  });
});

describe("evaluateFinancialCaveats — the fail-closed rules", () => {
  it("rejects any caveat key outside the vocabulary, even alongside satisfiable ones", () => {
    expect(
      evaluateFinancialCaveats(
        { maxAmount: "100.00", currency: "USD", memo: "lunch" },
        { amount: "1.00", currency: "USD" }
      )
    ).toBe(false);
    // Including a key that only LOOKS like part of the vocabulary.
    expect(evaluateFinancialCaveats({ MaxAmount: "100.00" }, { amount: "1.00" })).toBe(false);
    expect(evaluateFinancialCaveats({ maxamount: "100.00" }, { amount: "1.00" })).toBe(false);
  });

  it("rejects malformed caveat values rather than treating them as absent", () => {
    const attempt = (caveats: Record<string, unknown>, action: FinancialAction = CONFORMING) =>
      evaluateFinancialCaveats(caveats, action);

    // Amounts: no sign, no exponent, no leading zeros, no whitespace, no numbers.
    expect(attempt({ maxAmount: "-1", currency: "USD" })).toBe(false);
    expect(attempt({ maxAmount: "1e5", currency: "USD" })).toBe(false);
    expect(attempt({ maxAmount: "01", currency: "USD" })).toBe(false);
    expect(attempt({ maxAmount: " 100 ", currency: "USD" })).toBe(false);
    expect(attempt({ maxAmount: "100.", currency: "USD" })).toBe(false);
    expect(attempt({ maxAmount: ".5", currency: "USD" })).toBe(false);
    expect(attempt({ maxAmount: "1.0000000000000000001", currency: "USD" })).toBe(false);
    expect(attempt({ maxAmount: 100, currency: "USD" })).toBe(false);
    expect(attempt({ maxAmount: "", currency: "USD" })).toBe(false);

    // Currencies: uppercase, letter-initial, 3-8 characters. Case is never folded.
    expect(attempt({ currency: "usd" }, { currency: "usd" })).toBe(false);
    expect(attempt({ currency: "US" }, { currency: "US" })).toBe(false);
    expect(attempt({ currency: "TOOLONGCODE" }, { currency: "TOOLONGCODE" })).toBe(false);
    expect(attempt({ currency: "1ST" }, { currency: "1ST" })).toBe(false);

    // Beneficiaries: non-empty string, or non-empty array of non-empty strings.
    expect(attempt({ beneficiary: "" }, { beneficiary: "" })).toBe(false);
    expect(attempt({ beneficiary: [] }, { beneficiary: "acct:vendor-7" })).toBe(false);
    expect(attempt({ beneficiary: [""] }, { beneficiary: "" })).toBe(false);
    expect(attempt({ beneficiary: ["acct:vendor-7", 7] }, { beneficiary: "acct:vendor-7" })).toBe(
      false
    );

    // Action ids: non-empty string.
    expect(attempt({ actionId: "" }, { actionId: "" })).toBe(false);
    expect(attempt({ actionId: 7 }, { actionId: "7" })).toBe(false);

    // Tiers: integers in 0..100, in the caveat AND in the action.
    expect(attempt({ approvalTier: 101 }, { approvalTier: 101 })).toBe(false);
    expect(attempt({ approvalTier: -1 }, { approvalTier: 0 })).toBe(false);
    expect(attempt({ approvalTier: 1.5 }, { approvalTier: 2 })).toBe(false);
    expect(attempt({ approvalTier: "2" }, { approvalTier: 2 })).toBe(false);
    expect(attempt({ approvalTier: 2 }, { approvalTier: 2.5 })).toBe(false);
    // An action tier ABOVE the vocabulary does not clear a tier-100 caveat by being
    // "even higher" — it names no defined tier, so it denies.
    expect(attempt({ approvalTier: 100 }, { approvalTier: 101 })).toBe(false);
    expect(attempt({ approvalTier: 2 }, { approvalTier: Number.POSITIVE_INFINITY })).toBe(false);
    expect(attempt({ approvalTier: 2 }, { approvalTier: Number.NaN })).toBe(false);
  });

  it("rejects an action that does not state the field a caveat constrains", () => {
    expect(evaluateFinancialCaveats({ maxAmount: "100.00", currency: "USD" }, {})).toBe(false);
    expect(
      evaluateFinancialCaveats({ maxAmount: "100.00", currency: "USD" }, { currency: "USD" })
    ).toBe(false);
    expect(
      evaluateFinancialCaveats({ maxAmount: "100.00", currency: "USD" }, { amount: "1.00" })
    ).toBe(false);
    expect(evaluateFinancialCaveats({ currency: "USD" }, {})).toBe(false);
    expect(evaluateFinancialCaveats({ beneficiary: "acct:vendor-7" }, {})).toBe(false);
    expect(evaluateFinancialCaveats({ actionId: "wire-1" }, {})).toBe(false);
    expect(evaluateFinancialCaveats({ approvalTier: 0 }, {})).toBe(false);
  });

  it("rejects a maxAmount caveat carrying no currency caveat, whatever the action says", () => {
    expect(evaluateFinancialCaveats({ maxAmount: "100.00" }, { amount: "1.00" })).toBe(false);
    expect(
      evaluateFinancialCaveats({ maxAmount: "100.00" }, { amount: "1.00", currency: "USD" })
    ).toBe(false);
  });

  it("rejects a currency mismatch between the caveat and the action", () => {
    expect(
      evaluateFinancialCaveats(
        { maxAmount: "100.00", currency: "USD" },
        { amount: "1.00", currency: "EUR" }
      )
    ).toBe(false);
    expect(evaluateFinancialCaveats({ currency: "USD" }, { currency: "EUR" })).toBe(false);
  });

  it("rejects a beneficiary outside the allow-list, and an id mismatch", () => {
    expect(
      evaluateFinancialCaveats(
        { beneficiary: ["acct:vendor-7", "acct:vendor-9"] },
        { beneficiary: "acct:vendor-8" }
      )
    ).toBe(false);
    expect(
      evaluateFinancialCaveats({ beneficiary: "acct:vendor-7" }, { beneficiary: "acct:vendor-70" })
    ).toBe(false);
    expect(evaluateFinancialCaveats({ actionId: "wire-1" }, { actionId: "wire-2" })).toBe(false);
  });

  it("rejects an action below the minimum approval tier", () => {
    expect(evaluateFinancialCaveats({ approvalTier: 3 }, { approvalTier: 2 })).toBe(false);
    expect(evaluateFinancialCaveats({ approvalTier: 1 }, { approvalTier: 0 })).toBe(false);
  });
});

describe("evaluateFinancialCaveats — what it accepts", () => {
  it("ignores aud, which the resolver owns and has already evaluated", () => {
    expect(
      evaluateFinancialCaveats(
        { aud: [treasury.id], maxAmount: "1000.00", currency: "USD" },
        { amount: "250.75", currency: "USD" }
      )
    ).toBe(true);
    // Even an aud this module could not possibly parse: not its key, not its business.
    expect(evaluateFinancialCaveats({ aud: 12345 }, {})).toBe(true);
  });

  it("accepts membership in an array beneficiary, in either position", () => {
    const allowed = { beneficiary: ["acct:vendor-7", "acct:vendor-9"] };
    expect(evaluateFinancialCaveats(allowed, { beneficiary: "acct:vendor-7" })).toBe(true);
    expect(evaluateFinancialCaveats(allowed, { beneficiary: "acct:vendor-9" })).toBe(true);
    expect(
      evaluateFinancialCaveats({ beneficiary: "acct:vendor-7" }, { beneficiary: "acct:vendor-7" })
    ).toBe(true);
  });

  it("accepts an approval tier at or above the minimum, including tier 0", () => {
    expect(evaluateFinancialCaveats({ approvalTier: 2 }, { approvalTier: 2 })).toBe(true);
    expect(evaluateFinancialCaveats({ approvalTier: 2 }, { approvalTier: 100 })).toBe(true);
    expect(evaluateFinancialCaveats({ approvalTier: 0 }, { approvalTier: 0 })).toBe(true);
  });

  it("accepts an empty caveat map — there is nothing to deny", () => {
    expect(evaluateFinancialCaveats({}, {})).toBe(true);
  });

  it("accepts the whole vocabulary at once when every dimension conforms", () => {
    expect(
      evaluateFinancialCaveats(
        {
          aud: [treasury.id],
          maxAmount: "1000.00",
          currency: "USD",
          beneficiary: ["acct:vendor-7", "acct:vendor-9"],
          actionId: "wire-1",
          approvalTier: 2
        },
        {
          amount: "250.75",
          currency: "USD",
          beneficiary: "acct:vendor-7",
          actionId: "wire-1",
          approvalTier: 3
        }
      )
    ).toBe(true);
  });
});

describe("evaluateFinancialCaveats — totality under hostile input", () => {
  // Shapes a caller could hand this if the "caveats" it passes never went through
  // `grantSchema`, plus the ones that survive JSON and still break a naive parser.
  const HOSTILE: unknown[] = [
    null,
    undefined,
    [],
    ["maxAmount", "100"],
    {},
    { nested: { deeply: { deeper: [1, 2, 3] } } },
    true,
    0,
    -0,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
    "",
    "9".repeat(100_000),
    "0".repeat(100_000) + "1",
    "1".repeat(50) + "." + "1".repeat(50),
    new Date(NOW),
    () => "100"
  ];

  it("never throws whatever the caveats map is", () => {
    for (const caveats of HOSTILE) {
      expect(() =>
        evaluateFinancialCaveats(caveats as Record<string, unknown>, CONFORMING)
      ).not.toThrow();
      expect(evaluateFinancialCaveats(caveats as Record<string, unknown>, CONFORMING)).toBe(
        // Only a PLAIN object with no unknown keys can be approved; `{}` is the one such
        // shape in the list, and an empty caveat map has nothing to deny. `[]` and a Date
        // also have zero own keys and must NOT ride that through as "no caveats".
        caveats !== null &&
          typeof caveats === "object" &&
          Object.getPrototypeOf(caveats) === Object.prototype &&
          Object.keys(caveats).length === 0
      );
    }
  });

  it("never throws whatever a single caveat value is", () => {
    for (const value of HOSTILE) {
      for (const key of ["maxAmount", "currency", "beneficiary", "actionId", "approvalTier"]) {
        expect(() =>
          evaluateFinancialCaveats({ [key]: value, currency: "USD" }, CONFORMING)
        ).not.toThrow();
      }
    }
  });

  it("never throws whatever the action's fields are", () => {
    for (const value of HOSTILE) {
      const action = {
        amount: value,
        currency: value,
        beneficiary: value,
        actionId: value,
        approvalTier: value
      } as unknown as FinancialAction;
      expect(() => evaluateFinancialCaveats(LEAF_CAVEATS, action)).not.toThrow();
      expect(evaluateFinancialCaveats(LEAF_CAVEATS, action)).toBe(false);
    }
  });

  it("denies rather than propagating a throwing property getter", () => {
    const booby = Object.defineProperty({}, "maxAmount", {
      enumerable: true,
      get() {
        throw new Error("boom");
      }
    }) as Record<string, unknown>;
    expect(() => evaluateFinancialCaveats(booby, CONFORMING)).not.toThrow();
    expect(evaluateFinancialCaveats(booby, CONFORMING)).toBe(false);
  });

  it("reads only own properties, and denies a map with a foreign prototype outright", () => {
    // A null-prototype map is a plain map: own keys, no inherited surface, evaluated
    // normally. Pinned so the plain-object guard cannot be tightened into an
    // `Object.prototype`-only check that silently denies a legitimate `Object.create(null)`.
    const nullPrototype = Object.assign(Object.create(null) as Record<string, unknown>, {
      maxAmount: "1000.00",
      currency: "USD"
    });
    expect(evaluateFinancialCaveats(nullPrototype, CONFORMING)).toBe(true);

    // A caveat parked on the PROTOTYPE is invisible to `Object.keys` — the same view the
    // resolver's own foreign-caveat sweep has. Approving around a constraint neither side
    // can see is how a caveat gets laundered, so the whole map denies.
    const inherited = Object.create({ maxAmount: "0.01" }) as Record<string, unknown>;
    expect(evaluateFinancialCaveats(inherited, CONFORMING)).toBe(false);
  });
});

describe("financial caveats through verifyGrantChain", () => {
  const root = rootGrant();
  const leaf = leafGrant(root, LEAF_CAVEATS);
  const chain = [leaf, root];

  const accepted = {
    valid: true,
    subjectId: treasury.id,
    audienceId: agent.id,
    abilities: ["payments/transfer"]
  };

  it("verifies a chain whose leaf caps spending, for a conforming action", async () => {
    const verdict = await verifyGrantChain(chain, view, {
      now: NOW,
      evaluateCaveats: createFinancialCaveatEvaluator(CONFORMING)
    });
    expect(verdict).toEqual(accepted);
  });

  it("rejects an action over the cap", async () => {
    const verdict = await verifyGrantChain(chain, view, {
      now: NOW,
      evaluateCaveats: createFinancialCaveatEvaluator({ ...CONFORMING, amount: "1000.01" })
    });
    expect(verdict).toEqual({ valid: false, reason: "grant_caveat_rejected" });
  });

  it("rejects an action paying a beneficiary the leaf never allowed", async () => {
    const verdict = await verifyGrantChain(chain, view, {
      now: NOW,
      evaluateCaveats: createFinancialCaveatEvaluator({
        ...CONFORMING,
        beneficiary: "acct:attacker-1"
      })
    });
    expect(verdict).toEqual({ valid: false, reason: "grant_caveat_rejected" });
  });

  it("rejects a chain carrying a caveat key this evaluator does not understand", async () => {
    const extra = leafGrant(root, { ...LEAF_CAVEATS, settlementWindow: "T+2" });
    const verdict = await verifyGrantChain([extra, root], view, {
      now: NOW,
      evaluateCaveats: createFinancialCaveatEvaluator(CONFORMING)
    });
    expect(verdict).toEqual({ valid: false, reason: "grant_caveat_rejected" });
  });

  it("rejects the same chain with no evaluator supplied at all", async () => {
    const verdict = await verifyGrantChain(chain, view, { now: NOW });
    expect(verdict).toEqual({ valid: false, reason: "grant_caveat_rejected" });
  });

  it("takes the intersection across links: the tightest cap on the chain is the one that binds", async () => {
    // The root allows 100 USD and the leaf 1000 USD. The hook runs per link, so an action
    // between the two is approved by the leaf and refused by the root — no cross-link
    // narrowing rule needed, and a leaf that "widens" its parent's cap gains nothing.
    const tightRoot = rootGrant({ maxAmount: "100.00", currency: "USD" });
    const wideLeaf = leafGrant(tightRoot, { maxAmount: "1000.00", currency: "USD" });

    const within = await verifyGrantChain([wideLeaf, tightRoot], view, {
      now: NOW,
      evaluateCaveats: createFinancialCaveatEvaluator({ amount: "99.99", currency: "USD" })
    });
    expect(within).toEqual(accepted);

    const between = await verifyGrantChain([wideLeaf, tightRoot], view, {
      now: NOW,
      evaluateCaveats: createFinancialCaveatEvaluator({ amount: "500.00", currency: "USD" })
    });
    expect(between).toEqual({ valid: false, reason: "grant_caveat_rejected" });
  });

  it("evaluates no caveats at record purpose, by design", async () => {
    // Spec 011/014: caveats bind a chain to the delivery surface it was exercised against,
    // and a stored record is not one — a member re-verifying it later is not the payer and
    // has no action to evaluate. Pinned here because a financial caveat makes the existing
    // behavior look like a hole; it is not one, and this test is what stops someone
    // "fixing" it into a fail-closed rejection of every stored record.
    const verdict = await verifyGrantChain(chain, view, {
      now: NOW,
      purpose: "record",
      at: NOW
    });
    expect(verdict).toEqual(accepted);
  });
});
