# FLOP rule registry

Every FLOP economic rule this tool relies on, with the official text it came
from, as data in `conformance/flop/rule-registry.json`. The code reads the file
through `flop.rules.FlopRuleRegistry`; it never assumes a rule.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** Every rule below is `official-draft` or `unknown`. None is final.
The teaser's own front matter says its figures are provisional and may change.

## Why a file

A provisional figure in a draft should be changeable by editing the record of
the draft, and in two weeks it changed twice. The agent airdrop's 3-to-1 unlock
ratio was a `formula` object, never a `3` in a Python file. On 2026-09-30 the
teaser and the agent page dropped it and the formula came out of the registry
(D-122); on 2026-10-05 the new airdrop page stated it again and the Yellow Paper
made it a normative Agent grant rule, so the formula went back in, quoting the
airdrop page (D-123). Neither change needed a number edited in code.
`flop.testnet.mainnet` and the passport read the ratio through
`rules.unlock_ratio` and say "not yet available" when no formula is registered
(`docs/FLOP_TESTNET_EXECUTOR.md`, mainnet adapter).

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

## The rules, at snapshot 2026-10-09T01:55:07Z

The eighth snapshot. Between the seventh and this one, the testnet and airdrop
pages changed their security-disclosure wording without a new printed date; a
fetch at 2026-10-07T02:16Z still had the old wording and one at
2026-10-09T00:07Z the new, which is as closely as the change can be dated. The
testnet page made two changes: it adds a condition, that a vulnerability is
reported privately to security@flop.finance (it named no channel before), and
where it said responsible reports are rewarded from the ecosystem reserve it
now says they "could be eligible for a reward from the ecosystem reserve". The
airdrop page names no channel. It no longer lists security rewards among the
reserve's growth programmes, adds that a responsibly reported vulnerability
"could also be eligible for a reward from it; this is not a bug bounty
programme", and its allocation table's reserve row now reads "possible rewards
for responsibly reported vulnerabilities".

The Yellow Paper changed in more than its paid-storage, capacity-reservation
and rent rules (section 5.4 and their rows in Appendices E, F.7, G.4 and H.3).
Its HTLC text now says that the shipped `htlc_burn_share_ppt` is zero and
timeout resolution preserves the full locked principal, that a nonzero timeout
burn is a proposal (D-0523) not yet ratified, and that the FLOP/native BTC,
FLOP/native NEAR and FLOP/NEP-141-on-NEAR pairs are target-only, with no
deployed chain-pair completion guarantee (sections 10.1 and 10.2, a new
parameter row in Appendix A, E.48 and H.5). This tool's tclk verifier knows
the `flop-htlc` rail; for it, H.5 marks the local HTLC mechanics LIVE and every
implemented pair direction target-only, so cross-chain completion is still a
target, not a guarantee. Appendix F adds that its corpus checks wire format
only, not the money path, and H.4 marks reward liquidity on issue (R9.13)
LIVE, with the agent and staker legs still accruing in pool accounts until
E.40 ratifies their distribution. Its section 8, the airdrop, Agent grant and
claim text, is as the seventh snapshot recorded, and every quotation from the
Yellow Paper still verifies. Every other fetched source kept its wording; the
`flop-labs` organisation listing is checked for its HTTP status only, so its
wording was not compared.

Most of the table comes from the seventh snapshot. On 2026-10-05 flop.finance published three new pages,
`/testnet/`, `/airdrop/` and `/whitepaper/`, and reworked its navigation, which
moved the wording of the front page, the teaser and every `/intro/` page. For
all of them but one that was the navigation and the footer date: the teaser's
version panel still reads 2026-09-30, and its rules keep that date. The
exception is `/intro/revenue/`, which now states the agent unlock as "every 3
FLOP spent unlocks 1" (D-0522) in its pool projection; the whitepaper's
glossary gives the same figure. The new pages are now watched, with
`flop.finance/llms.txt`, the site's own index of its protocol documents. The
airdrop page gives the agent unlock as 3:1 in settled sessions with no end
date, and the Yellow Paper makes the same rule normative (its printed header
still says 2026-09-24 and its footer 2026-10-05; the body was revised). The
teaser and the agent intro page still say the schedule is not set. The testnet
page says what an agent needs and what counts, including a minimum-activity
floor for every role, and sets out four fairness rules: one participant one
score, independent demand only, fraud forfeits and security disclosure. Every rule
below was re-verified mechanically: its quotation occurs in the body its source
hash names under `quotation_key` folding (dashes and quotes folded to ASCII,
whitespace ignored), or it is marked derived or unknown. The previous
snapshot's hashes are kept in `official-sources.json` under `_meta.history`.

<!-- flop-rules-table:begin -->
| id | status | phase | source | what it records |
|---|---|---|---|---|
| `flop-testnet-schedule` | official-draft | testnet | `flop-finance-teaser` | Flop Testnet is planned for Q4 2026 and runs for roughly ninety days, with mainnet to follow in Q1 2027. |
| `flop-figures-provisional` | official-draft | any | `flop-finance-teaser` | Several are still under review against the protocol parameters of record and may change. The Yellow Paper i... |
| `flop-teaser-unratified-figures` | official-draft | any | `flop-finance-teaser` | Draft. One figure on this page LEADS the protocol parameters of record and is not yet ratified: the 85/15 i... |
| `flop-genesis-airdrop-pool` | official-draft | genesis | `flop-finance-teaser` | The genesis airdrop of 4,400,000,000 $FLOP - 24.3% of the total network supply at year 10 - is allocated as... |
| `flop-genesis-supply-parameter` | official-draft | genesis | `flop-finance-yellowpaper` | Total genesis supply MUST be genesis_supply = 4,400,000,000 FLOP (18 decimals), held at genesis only by the... |
| `flop-genesis-cohort-parameters` | official-draft | genesis | `flop-finance-yellowpaper` | genesis_agent_airdrop = 1,200,000,000; plus the genesis_reserve = 800,000,000 residual (ecosystem/incentive... |
| `flop-agent-airdrop-allocation` | official-draft | genesis | `flop-finance-teaser` | Agents up to 1,200,000,000 (6.6%) Compute consumed through inference requests |
| `flop-agent-airdrop-basis` | official-draft | testnet | `flop-finance-teaser` | Agents - claim a test-token faucet and spend it on inference. Their airdrop is based largely on what they s... |
| `flop-agent-scoring-settled-spend` | official-draft | genesis | `flop-finance-yellowpaper` | A faucet grant, sponsored bond, or transferred balance MUST NOT by itself create an allocation right; held... |
| `flop-testnet-sole-route` | official-draft | testnet | `flop-finance-testnet` | The Flop Testnet is the pre-launch operating period of the network and the sole route to the genesis airdrop. |
| `flop-agent-participation` | official-draft | testnet | `flop-finance-testnet` | Agent A decentralised identifier (DID) and a wallet, with access to the test-token faucet Purchase inferenc... |
| `flop-agent-what-counts` | official-draft | testnet | `flop-finance-testnet` | Agents - compute purchased in settled sessions. Holding test tokens earns nothing. |
| `flop-agent-allocation-pro-rata` | official-draft | genesis | `flop-finance-airdrop` | Agents - supply demand. The allocation is shared pro rata to compute purchased in settled sessions. A fauce... |
| `flop-minimum-activity-floor` | official-draft | testnet | `flop-finance-testnet` | Minimum activity - each role has a floor below which no allocation is earned, so dormant accounts do not di... |
| `flop-one-participant-one-score` | official-draft | testnet | `flop-finance-testnet` | One participant, one score - wallets under common control are scored as a single participant; dividing acti... |
| `flop-independent-demand-only` | official-draft | testnet | `flop-finance-testnet` | Independent demand only - spend routed to a miner under common control, or circulated between wallets under... |
| `flop-fraud-forfeits` | official-draft | testnet | `flop-finance-testnet` | Fraud forfeits - an account flagged for manufactured activity forfeits its allocation, subject to appeal wi... |
| `flop-security-disclosure` | official-draft | testnet | `flop-finance-testnet` | Security disclosure - vulnerabilities reported responsibly during the testnet, privately to security@flop.f... |
| `flop-testnet-snapshot-height` | official-draft | genesis | `flop-finance-testnet` | The record is frozen at a published, finalized block height. Activity after that height is not credited, an... |
| `flop-agent-unlock-ratio` | official-draft | mainnet | `flop-finance-airdrop` | Spendable only on inference. Every 3 $FLOP of the locked balance spent in settled sessions unlocks 1 $FLOP,... |
| `flop-agent-unlock-ratio-intro` | official-draft | mainnet | `flop-finance-intro-agent` | Locked agent airdrop can be spent only on compute: opening or topping up inference sessions. When it become... |
| `flop-teaser-agent-release-unset` | official-draft | mainnet | `flop-finance-teaser` | It arrives locked, and a locked balance can be spent only on compute; the schedule on which it becomes liqu... |
| `flop-agent-unlock-yellowpaper` | official-draft | mainnet | `flop-finance-yellowpaper` | It MUST unlock only against spend credit: one FLOP of principal for each three FLOP of its locked part (R8.... |
| `flop-agent-grant-no-end-block` | official-draft | mainnet | `flop-finance-yellowpaper` | An Agent grant MUST NOT unlock any principal at its start block, and it has no end block. |
| `flop-testnet-settlement` | official-draft | genesis | `flop-finance-teaser` | At the end of the testnet, results are settled into the genesis block. The bulk of the pool is expected to... |
| `flop-airdrop-vesting-unspecified` | official-draft | genesis | `flop-finance-yellowpaper` | The conversion score, validator activity basis, Validator release order, and reserve disposition remain ope... |
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
| `technocore-capacity` | official-draft | any | `technocore-llms` | CAPACITY: at most 300000 rooms, 16777216 notes in total and 300000 per |
| `technocore-not-a-settlement-system` | official-draft, **derived** | any | `flop-labs-github-org` | Technocore is a coordination layer, not a settlement system: parties meet and agree in a room, and value mo... |
| `flop-testnet-endpoint` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-faucet-procedure` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-inference-api` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-inference-pricing` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-network-identifier` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-auth-signing-scheme` | unknown | testnet | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
| `flop-airdrop-claim-path` | official-draft | mainnet | `flop-finance-yellowpaper` | claim_vested MUST use the finalized head to calculate the unlocked amount, subtract the amount already clai... |
<!-- flop-rules-table:end -->

The `formula` for `flop-agent-unlock-ratio`, restored at the seventh snapshot
(D-123) and unchanged at the eighth:

```json
{
  "kind": "unlock-ratio",
  "cohort": "agents",
  "spentPerUnlocked": 3,
  "unlockedPerRatio": 1,
  "unit": "FLOP",
  "expression": "unlocked = floor(lockedSpendInSettledSessions / spentPerUnlocked) * unlockedPerRatio"
}
```

What changed at the eighth snapshot: only `flop-security-disclosure`, re-quoted
with the new wording. The other 37 quotations verify against the same text as
before, and the other 44 rules (those 37, the six unknown rules and the one
derived rule) keep their statements and consequences.

What changed at the seventh snapshot:

- `flop-agent-unlock-ratio` quotes the airdrop page's unlock terms and carries
  the formula again. The teaser's sentence that the schedule is not set is now
  its own rule, `flop-teaser-agent-release-unset`, and
  `flop-agent-unlock-ratio-intro` keeps the agent page's matching sentence:
  official pages disagree, and the registry shows it instead of choosing
  silently. The airdrop page says it follows the Yellow Paper, which is the
  definitive specification.
- `flop-agent-unlock-yellowpaper` and `flop-agent-grant-no-end-block` are new:
  the Yellow Paper's normative form of the rule. Only the payable of a settled,
  finalized session counts, once its dispute window has passed and every fraud
  dispute raised in it has resolved with none upheld; nothing unlocks at the
  start block, and there is no end block. The rule is in the specification but
  not in the runtime: the Yellow Paper's status matrix marks R8.7 and R8.8
  PARTIAL, with no Agent spend credit or spend cap implemented.
- `flop-airdrop-vesting-unspecified` quotes the one-sentence summary at the end
  of section 8.2, which no longer lists the agent release horizon: that there is
  no end block is decided. What is not decided is E.38's own longer list, which
  now leaves open the disposition of Miner and Agent principal that never
  unlocks, whether a fraud verdict upheld after the dispute window reverses
  spend credit (E.44), and the residual risk of an agent unlocking by paying a
  miner it controls (no runtime common-control rule, E.49).
- `flop-airdrop-claim-path` is a quotation of R8.8 (`claim_vested`) instead of
  an unknown, so six questions remain unanswered.
- New from the testnet and airdrop pages: `flop-testnet-sole-route`,
  `flop-agent-participation` (a DID, a wallet and the faucet),
  `flop-agent-what-counts` and `flop-agent-allocation-pro-rata` (compute
  purchased in settled sessions; holding or a faucet grant earns nothing),
  `flop-minimum-activity-floor`, `flop-one-participant-one-score`,
  `flop-independent-demand-only`, `flop-fraud-forfeits`,
  `flop-security-disclosure` and `flop-testnet-snapshot-height`.

`check` reported the one broken quotation (E.38). All 38 quotations were
verified against the fetched bodies (37 by `snapshot`, which also recorded the
four new sources as added; `flop-security-disclosure`, added in review, against
the same testnet body and hash).

## Absence is recorded, not filled in

The six `unknown` rules are entries so a screen can show them as unanswered
(the claim path left the list at the seventh snapshot, when R8.8 specified it).
A missing entry would look like a question nobody asked. Each carries a
`consequence`: no endpoint may be executable; faucet exists only as simulation;
spend is never estimated from a guess; quotes are simulated and labelled as
such; simulation uses `.invalid`; no signer is implemented.

## The one derived rule

The directive's sentence "Technocore is a coordination layer, not a settlement
system" does not appear verbatim in any `flop.finance` document. Since the
seventh snapshot the nearest official text is fetched and hashed: the
whitepaper's section 11 says Technocore "records what was agreed, by whom and
when; it settles nothing and holds no keys", and its section 10 that Technocore
operates alongside the protocol rather than within it. The entry was first read
from `flop-labs/tclk` `SPEC.md` (rooms coordinate; money is on a rail). It is
registered as `official-draft` with `derivation: "derived"`, `hash: null`,
source `flop-labs-github-org`, and `statementIsQuotation: false`. The tclk
`SPEC.md` body was not fetched in the session that wrote the registry; the
entry records a reading of a document this project already ported
(`docs/TCLK_INTEGRATION.md`), not a quotation, and its `derivationNote` names
the whitepaper's sentences. Freshness for this rule is `UNVERIFIABLE`, and the
Sources screen shows it that way.

This is the judgement the recon brief asked for. It was flagged for review in
the stage-1 report and is recorded here so the reviewer can find it.

## Where the registry is shown

- `GET /v1/flop/rules` — every rule with its source and staleness.
- `GET /v1/flop/status` — `ruleCount`, `unknownRuleCount`, `staleRuleCount`.
- `la flop rules`.
- The Sources screen's `RuleSource` component, which shows status, version,
  date, `fetchedAt`, and `RULE UPDATED` when stale (`docs/FLOP_UI_GUIDE.md`).
- Recommendations carry `ruleId` and are `official` only when the rule is.

## Taking the next snapshot

`uv run python scripts/flop_sources.py check` fetches every source, keeps the
bodies outside the repository, prints for each whether its bytes and its
wording moved, and checks every quotation above against the fresh text. It
writes nothing here. When it reports a quotation as missing, or when a page's
wording has moved, `uv run python scripts/flop_sources.py snapshot --note "..."`
writes the next `official-sources.json`, re-stamps every verified rule to the
new hashes and regenerates the table between the markers in this page. A rule
whose quotation is gone keeps its old hash and shows as `RULE UPDATED` until
someone re-quotes it; the script refuses to snapshot over it without
`--allow-stale`. The paragraph above the table, the version hints and the
notes are written by a person (D-119).

## Adding or changing a rule

Edit the JSON. Quote the sentence; record the source hash from
`official-sources.json` at the time of quoting (`snapshot` does this for every
rule whose quotation it can find); set `statementIsQuotation` honestly; put
arithmetic in `formula`. Do not write the figure into code.
`tests/test_flop_rules.py` checks that every hashed rule matches the shipped
snapshot, that a missing source is reported rather than ignored, that nothing
claims to be final while the Yellow Paper is a draft, that a derived
statement may not claim to be a quotation, and that the number three is not
written in the module that applies the unlock ratio.
