# FLOP rule registry

Every FLOP economic rule this tool relies on, with the official text it came
from, as data in `conformance/flop/rule-registry.json`. The code reads the file
through `flop.rules.FlopRuleRegistry`; it never assumes a rule.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** Every rule below is `official-draft` or `unknown`. None is final.
The teaser's own front matter says its figures are provisional and may change.

## Why a file

A provisional figure in a draft should be changeable by editing the record of
the draft. The 3-to-1 unlock ratio is a `formula` object, not a `3` in a Python
file; `flop.testnet.mainnet` reads it through `rules.unlock_ratio` and answers
"not yet available" when the rule is missing or carries no formula rather than
guessing (`docs/FLOP_TESTNET_EXECUTOR.md`, mainnet adapter).

## Record shape

```text
id                     stable rule id
statement              the sentence, quoted, or UNKNOWN_FROM_OFFICIAL_SPEC
statementIsQuotation   true when the statement is verbatim from the source
status                 official-final | official-draft | community | unknown
effectiveNetworkPhase  genesis | testnet | mainnet | any
derivation             null, or "derived" when the statement is a reading rather than a quotation
derivationNote         why it is a reading, and from what
formula                arithmetic as data, or null
absentFrom             source ids that were searched and do not contain it
consequence            what the tool does because of this rule
source                 { sourceId, sourceUrl, sourceVersion, sourceDate, fetchedAt, hash }
```

`source.hash` is the `sha256` of the source document as it was when the rule
was written down. That is what makes staleness detectable.

## Stale rules — `RULE UPDATED`

`FlopRuleRegistry.stale_rules(snapshot)` compares each rule's recorded hash
against the current `official-sources.json` snapshot. A mismatch means the
source has changed since the rule was transcribed. The rule is then reported
with the label `RULE UPDATED` and is never quietly served as current
(acceptance test 6, `test_acceptance_6_a_changed_official_source_marks_its_rules_stale`).

The same fingerprint reaches the executor: `prepare.rule_set_hash(registry)` is
part of every `ExecutionPlan`, and an approval granted under one rule set is
`REPREPARE_REQUIRED` under another (acceptance N).

A rule whose `hash` is `null` cannot be checked and is reported as
`UNVERIFIABLE` freshness — one such rule exists, below.

## The rules, at snapshot 2026-09-08T03:40:53Z

The second snapshot. Between 2026-09-03 and 2026-09-08 flop.finance published
the Yellow Paper (`/intro/yellowpaper/`, v0.5.0 draft, "Implementation spec -
iterating", updated 2026-09-05) and a set of `/intro/` pages, and the teaser
gained a banner saying two of its figures lead the protocol parameters of
record and are not ratified. Every rule below was re-verified mechanically:
its quotation is a substring of the body its source hash names, or it is
marked derived or unknown. The previous snapshot's hashes are kept in
`official-sources.json` under `_meta.history`.

| id | status | phase | source | what it records |
|---|---|---|---|---|
| `flop-testnet-schedule` | official-draft | testnet | `flop-finance-teaser` | Flop Testnet is planned for Q4 2026 and runs for roughly ninety days, with mainnet to follow in Q1 2027. |
| `flop-figures-provisional` | official-draft | any | `flop-finance-teaser` | Several are still under review against the protocol parameters of record and may change. The Yellow Paper i... |
| `flop-teaser-unratified-figures` | official-draft | any | `flop-finance-teaser` | Draft. Two figures on this page LEAD the protocol parameters of record and are not yet ratified: the 3.5bn... |
| `flop-genesis-airdrop-pool` | official-draft | genesis | `flop-finance-teaser` | The genesis airdrop of 3,500,000,000 $FLOP - 20.4% of the total network supply at year 10 - is allocated as... |
| `flop-genesis-supply-parameter` | official-draft | genesis | `flop-finance-yellowpaper` | Total genesis supply MUST be genesis_supply = 2,483,460,000 FLOP (18 decimals), allocated to airdrop accoun... |
| `flop-agent-airdrop-allocation` | official-draft | genesis | `flop-finance-teaser` | Agents up to 1,200,000,000 (7.0%) Compute consumed through inference requests |
| `flop-agent-airdrop-basis` | official-draft | testnet | `flop-finance-teaser` | Agents - claim a test-token faucet and spend it on inference. Their airdrop is based largely on what they s... |
| `flop-agent-unlock-ratio` | official-draft | mainnet | `flop-finance-teaser` | It arrives locked and spendable only on inference or staking - every 3 $FLOP spent on inference unlocks 1 a... |
| `flop-agent-unlock-ratio-intro` | official-draft | mainnet | `flop-finance-intro-agent` | Agent airdrops are locked to inference spend or stake delegation. Every 3 FLOP of inference fees unlocks 1... |
| `flop-testnet-settlement` | official-draft | genesis | `flop-finance-teaser` | At the end of the testnet, results are settled into the genesis block. The bulk of the pool is expected to... |
| `flop-airdrop-vesting-unspecified` | official-draft | genesis | `flop-finance-yellowpaper` | airdrop-vesting 's tier set, linear schedule, performance adjustment, and claim path are unspecified, as is... |
| `flop-account-features` | official-draft | mainnet | `flop-finance-teaser` | The Flop Network account-based system allows agents to do the following: Token transfers Multisig Proxy / a... |
| `flop-agent-wallet-caps` | official-draft | mainnet | `flop-finance-yellowpaper` | pallet_session_keys + pallet_agent_wallet let an owner pre-authorize a delegate agent with a lifetime cap,... |
| `flop-session-key-lifetime` | official-draft | mainnet | `flop-finance-yellowpaper` | The session-key lifetime MUST be <= 864,000 blocks ( SessionKeysMaxDuration ). |
| `flop-delegate-revocable` | official-draft | mainnet | `flop-finance-yellowpaper` | The owner MUST be able to revoke at any time. Spending MUST be blocked at the session cap (§11 INV-02), the... |
| `flop-attenuable-capabilities-future` | official-draft | mainnet | `flop-finance-yellowpaper` | The wider composition target is three declarative, bounded, conservation-safe layers: composable spend cond... |
| `flop-account-signature-schemes` | official-draft | mainnet | `flop-finance-yellowpaper` | The runtime signature type is MultiSignature (signer MultiSigner ), admitting sr25519 , ed25519 , and ecdsa... |
| `flop-network-parameters` | official-draft | mainnet | `flop-finance-teaser` | Block time One second on average Block reward 96 $FLOP Block halving Every 730 days for the first five halv... |
| `flop-inference-fee-split` | official-draft | mainnet | `flop-finance-teaser` | The miner who completes the task successfully earns 85% of the $FLOP inference fee. |
| `flop-yellow-paper-status` | official-draft | any | `flop-finance-yellowpaper` | Draft - the normative specification of the protocol. Sections marked planned are not yet implemented. |
| `technocore-native-delegation` | official-draft | any | `technocore-llms` | DELEGATION: a key can say another key acts for it, so an agent holds its own key
instead of being handed yo... |
| `technocore-capacity` | official-draft | any | `technocore-llms` | CAPACITY: at most 163840 rooms, 5242880 notes in total and 163840 per |
| `technocore-not-a-settlement-system` | official-draft, **derived** | any | `flop-labs-github-org` | Technocore is a coordination layer, not a settlement system: parties meet and agree in a room, and value mo... |
| `flop-testnet-endpoint` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-faucet-procedure` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-inference-api` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-inference-pricing` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-network-identifier` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-auth-signing-scheme` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-airdrop-claim-path` | unknown | genesis | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |

The `formula` for `flop-agent-unlock-ratio`:

```json
{
  "kind": "unlock-ratio",
  "cohort": "agents",
  "spentPerUnlocked": 3,
  "unlockedPerRatio": 1,
  "unit": "FLOP",
  "expression": "unlocked = floor(inferenceSpend / spentPerUnlocked) * unlockedPerRatio"
}
```

What changed for a reader of the previous table: the 3.5bn genesis figure is
still quoted, because the teaser still prints it, but its `consequence` now
says the Yellow Paper fixes `genesis_supply = 2,483,460,000 FLOP` and the
teaser's own banner calls the 3.5bn unratified. The fee split is flagged the
same way. Nothing was silently rewritten; a stale rule would have shown as
`RULE UPDATED` had the snapshot moved without this re-verification.

## Absence is recorded, not filled in

The seven `unknown` rules are entries so a screen can show them as unanswered.
A missing entry would look like a question nobody asked. Each carries a
`consequence`: no endpoint may be executable; faucet exists only as simulation;
spend is never estimated from a guess; simulation uses `.invalid`; no signer is
implemented; every economic rule stays draft.

## The one derived rule

The directive's sentence "Technocore is a coordination layer, not a settlement
system" does not appear in any `flop.finance` document. The nearest statement is
in `flop-labs/tclk` `SPEC.md` (rooms coordinate; money is on a rail). It is
registered as `official-draft` with `derivation: "derived"`, `hash: null`,
source `flop-labs-github-org`, and `statementIsQuotation: false`. The tclk
`SPEC.md` body was not fetched in the session that wrote the registry; the
entry records a reading of a document this project already ported
(`docs/TCLK_INTEGRATION.md`), not a quotation. Freshness for this rule is
`UNVERIFIABLE`, and the Sources screen shows it that way.

This is the judgement the recon brief asked for. It was flagged for review in
the stage-1 report and is recorded here so the reviewer can find it.

## Where the registry is shown

- `GET /v1/flop/rules` — every rule with its source and staleness.
- `GET /v1/flop/status` — `ruleCount`, `unknownRuleCount`, `staleRuleCount`.
- `la flop rules`.
- The Sources screen's `RuleSource` component, which shows status, version,
  date, `fetchedAt`, and `RULE UPDATED` when stale (`docs/FLOP_UI_GUIDE.md`).
- Recommendations carry `ruleId` and are `official` only when the rule is.

## Adding or changing a rule

Edit the JSON. Quote the sentence; record the source hash from
`official-sources.json` at the time of quoting; set `statementIsQuotation`
honestly; put arithmetic in `formula`. Do not write the figure into code.
`tests/test_flop_rules.py` checks that every hashed rule matches the shipped
snapshot, that a missing source is reported rather than ignored, that nothing
claims to be final while the Yellow Paper is unpublished, that a derived
statement may not claim to be a quotation, and that the number three is not
written in the module that applies the unlock ratio.
