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

## The rules, at snapshot 2026-09-03T04:25:46Z

Source `flop-finance-teaser` = `https://flop.finance/teaser/`, "Version 0.1
(draft) · Status Draft · Updated 2026-08-26", sha256 `bc9c93a3a420b7a2…`.

| id | status | phase | what it records |
|---|---|---|---|
| `flop-testnet-schedule` | official-draft | testnet | testnet Q4 2026, about 90 days; mainnet Q1 2027 |
| `flop-figures-provisional` | official-draft | any | "The figures in this document are provisional … may change." |
| `flop-genesis-airdrop-pool` | official-draft | genesis | 3,500,000,000 $FLOP, 20.4% of year-10 supply |
| `flop-agent-airdrop-allocation` | official-draft | genesis | agents up to 1.2bn (7.0%), "compute consumed through inference requests" |
| `flop-agent-airdrop-basis` | official-draft | testnet | based largely on what is spent on inference over the testnet, plus prizes |
| `flop-agent-unlock-ratio` | official-draft | mainnet | every 3 $FLOP spent on inference unlocks 1 airdropped $FLOP — carried as `formula` |
| `flop-testnet-settlement` | official-draft | genesis | results settled into the genesis block; bulk at TGE, remainder later |
| `flop-account-features` | official-draft | mainnet | transfers, multisig, proxy / authority delegation, staking, timelock, pools, declarative spend conditions |
| `flop-network-parameters` | official-draft | mainnet | ~1s block time, 96 $FLOP block reward, 730-day halving |
| `flop-inference-fee-split` | official-draft | mainnet | miner 85% of the inference fee; validators block rewards plus 15% |
| `technocore-not-a-settlement-system` | official-draft, **derived** | any | see below |
| `flop-testnet-endpoint` | unknown | testnet | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-faucet-procedure` | unknown | testnet | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-inference-api` | unknown | testnet | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-inference-pricing` | unknown | testnet | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-network-identifier` | unknown | testnet | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-auth-signing-scheme` | unknown | testnet | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-yellow-paper` | unknown | any | the definitive specification the teaser names; not published |

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
