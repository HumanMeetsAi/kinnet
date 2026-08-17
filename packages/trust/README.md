# @kinnet/trust

Verify claims, `represents` relationships, and UCAN-aligned grant chains (specs 008/009/011),
offline from committed bytes: key logs are replayed locally, so discovery is a directory and
never a trusted party.

## Financial caveats

A grant's `caveats` map bounds what its holder may do. The resolver evaluates exactly one
caveat natively — `aud` (spec 011) — and **fails closed on every other key**: a link carrying
any foreign caveat is rejected with `grant_caveat_rejected` unless the caller's
`evaluateCaveats` hook returns `true` for that link.

`@kinnet/trust` ships one such vocabulary, for delegations that move money.

```ts
import { createFinancialCaveatEvaluator, verifyGrantChain } from "@kinnet/trust";

// The pending side effect, as the relying party (e.g. an MCP shim gating a tool call)
// describes it. One evaluator per action — the closure IS the request context that the
// resolver's per-link hook signature does not carry.
const verdict = await verifyGrantChain(chain, view, {
  now: new Date(),
  verifierId: serviceId,
  evaluateCaveats: createFinancialCaveatEvaluator({
    amount: "250.75",
    currency: "USD",
    beneficiary: "acct:vendor-7"
  })
});
```

### Vocabulary

| Caveat         | Value shape                                               | Satisfied when                                                                                         |
| -------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `maxAmount`    | decimal string, `^(0\|[1-9][0-9]*)(\.[0-9]{1,18})?$`      | a `currency` caveat is also present and equals `action.currency`, **and** `action.amount <= maxAmount` |
| `currency`     | `^[A-Z][A-Z0-9]{2,7}$` (ISO-4217 and crypto tickers)      | `action.currency` is exactly equal — case is never folded                                              |
| `beneficiary`  | non-empty string, or non-empty array of non-empty strings | `action.beneficiary` equals it, or is a member of the allow-list                                       |
| `actionId`     | non-empty string                                          | `action.actionId` is exactly equal — binds the grant to one specific action                            |
| `approvalTier` | integer in `0..100`                                       | `action.approvalTier` is an integer in the same range and **at least** the caveat's value              |
| `aud`          | (spec 011)                                                | ignored here — the resolver has already evaluated it against `verifierId`                              |

The action shape is `FinancialAction`: `{ amount?, currency?, beneficiary?, actionId?,
approvalTier? }`. `amount` is a decimal **string**, never a number.

### Fail-closed rules

Each of these is a way authority could otherwise widen to "unbounded", so each denies:

- **An unrecognized caveat key denies the whole map.** Returning `true` while ignoring a key
  the evaluator cannot enforce would launder a foreign caveat past the protocol's own
  fail-closed rule.
- **A malformed caveat value denies.** A cap the schema rejects is not "no cap". `"-1"`,
  `"1e5"`, `"01"`, `100` (a number), `""`, `"usd"`, an empty beneficiary list and a tier of
  `101` all deny.
- **A missing action field denies.** An action that does not state its amount cannot be
  proven to be within a spending cap; omitting a field is never a waiver.
- **`maxAmount` without `currency` denies.** An uncurrencied cap is meaningless — "at most
  100" is satisfied by 100 units of something worth a hundred times more — and there is no
  correct default, so the pairing is required and a grant minted without it is inert.
- **A non-plain-object caveat map denies.** `[]` and a class instance have no own keys and
  would otherwise read as "no caveats".

### Amounts are money, not floats

Amounts are decimal strings compared as scaled `BigInt`s, normalized **up** to the longer of
the two fractional lengths. So `"10"`, `"10.00"` and `"10.000"` are one amount, while
`"10.000000000000000001"` exceeds a cap of `"10"`. `0.1 + 0.2 !== 0.3` is a rounding curiosity
in a report and an authorization bypass in a spending cap.

### Composition across a chain

The hook runs **once per link** and one `false` rejects the chain, so a chain whose root caps
spending at 1000 USD and whose leaf caps it at 100 USD authorizes at most 100 USD: the
effective authority is the **intersection** of every link's caveats, evaluated against the same
action. Unlike `aud`, these caveats are therefore not checked for narrowing — a leaf that
raises its cap above its parent's gains nothing, because the parent's lower cap is still
evaluated and still rejects.

### What is _not_ evaluated

At `purpose: "record"` the resolver evaluates **no** caveats at all — `aud` included. A stored
`(record, chain)` unit is not a delivery surface: the member re-verifying it later is not the
payer and has no action to describe. That is spec 011 behavior, not a gap.

The action is not signed and is not part of the chain. The chain bounds it; the relying party
is trusted to describe its own pending side effect honestly. A shim that lies to its own
evaluator has already lost.

### Conformance fixture

`test/fixtures/financial-chain.json` commits a two-link capped payment chain and its verdicts
— accepting action, over-cap action, no evaluator, and a one-digit raise of the cap (which
fails on the **signature**, since caveats are signed). Fixtures are regenerated, never
hand-edited:

```bash
pnpm build
pnpm exec tsx packages/trust/scripts/generate-fixtures.ts
pnpm format
```
