# FLOP rule registry

Every FLOP economic rule this tool relies on, with the official text it came
from, as data in `conformance/flop/rule-registry.json`. The code reads the file
through `flop.rules.FlopRuleRegistry`; it never assumes a rule.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** Every rule below is `official-draft` or `unknown`. None is final.
The teaser's own front matter says its figures are provisional and may change.

## Why a file

A provisional figure in a draft should be changeable by editing the record of
the draft, and that is what happened. The agent airdrop's 3-to-1 unlock ratio
was a `formula` object, never a `3` in a Python file; on 2026-09-30 the teaser
and the agent page dropped it, and removing it took an edit to this registry and
no number in the code (D-122). The rule now quotes the new text and carries no
formula, so `rules.unlock_ratio` returns nothing and `flop.testnet.mainnet`
answers "not yet available" rather than guessing; what the code changed was how
the adapter and the passport word that case (`docs/FLOP_TESTNET_EXECUTOR.md`,
mainnet adapter). The
loader refuses a malformed formula, so a typo here cannot pass for the official
text setting no ratio.

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

## The rules, at snapshot 2026-10-05T02:04:55Z

The sixth snapshot. flop.finance revised its pages on 2026-09-30: the teaser
and every `/intro/` page print the new date, and the Yellow Paper's printed
date moved to 2026-09-24 with about a third more text. For the agent airdrop
the change is substantive: the teaser and the agent page no longer state the
3-to-1 spend-to-unlock ratio, a locked agent balance can now be spent only on
compute, and the release schedule is not set. The Yellow Paper still calls 3:1
a proposal: E.38 leaves the Agent grant horizon and whether spend-to-unlock
ships to be ratified, noting that the proposed requirement exceeds projected
inference demand. Separately, the Yellow Paper's new R8.4 says agent scoring
derives from settled compute-channel spend (the conversion score's caps and
aggregation are open in E.38), and its new R8.6-R8.8 define grant landing, the
Miner and Validator unlock schedules and the claim call (`claim_vested`); the
Validator release order and the Agent grant's release horizon stay open. The
front page, the brand page and every Technocore document kept their wording. Every rule below was re-verified
mechanically: its quotation is a substring of the body its source hash names,
or it is marked derived or unknown. The previous snapshot's hashes are kept in
`official-sources.json` under `_meta.history`.

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
| `flop-agent-unlock-ratio` | official-draft | mainnet | `flop-finance-teaser` | It arrives locked, and a locked balance can be spent only on compute; the schedule on which it becomes liqu... |
| `flop-agent-unlock-ratio-intro` | official-draft | mainnet | `flop-finance-intro-agent` | Locked agent airdrop can be spent only on compute: opening or topping up inference sessions. When it become... |
| `flop-testnet-settlement` | official-draft | genesis | `flop-finance-teaser` | At the end of the testnet, results are settled into the genesis block. The bulk of the pool is expected to... |
| `flop-airdrop-vesting-unspecified` | official-draft | genesis | `flop-finance-yellowpaper` | The conversion score, validator activity basis, Validator release order, agent release horizon, and reserve... |
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
| `flop-airdrop-claim-path` | unknown | genesis | `flop-finance-yellowpaper` | `UNKNOWN_FROM_OFFICIAL_SPEC` |
<!-- flop-rules-table:end -->

No rule carries a `formula` at this snapshot. Until 2026-09-30,
`flop-agent-unlock-ratio` carried `{"kind": "unlock-ratio", "spentPerUnlocked":
3, "unlockedPerRatio": 1}`; the teaser and the agent page dropped the ratio,
no current text sets one, and the formula went with it.

What changed for a reader of the previous table:

- `flop-agent-unlock-ratio` and `flop-agent-unlock-ratio-intro` no longer quote
  a 3:1 unlock. A locked agent balance can be spent only on compute, and when it
  becomes liquid is not set.
- `flop-airdrop-vesting-unspecified` now quotes the Yellow Paper's list of what
  remains open in E.38, the agent release horizon among it.
- `flop-teaser-unratified-figures` quotes the banner's new wording: the 4.4bn
  genesis pool, ratified by D-0440 (the figure itself has been 4.4bn since the
  third snapshot).
- `flop-agent-wallet-caps` lost the words "(epoch-reset)" in the source.
- `flop-agent-scoring-settled-spend` is new: the Yellow Paper's R8.4 says agent
  scoring derives from settled compute-channel spend, and that a faucet grant
  alone creates no allocation right. It is a scoring rule of the draft, not an
  unlock rule, and the teaser still says the airdrop is based largely on
  inference spend along with various prizes.

The other 26 rules verify against the same wording as before. `check` found all
five broken quotations; they were re-quoted by hand, and `snapshot` re-stamped
every verified rule to the new hashes. Four of the 26 kept their quotation but
needed a new `consequence`, because the new Yellow Paper answers what they said
was missing:

- `flop-airdrop-claim-path` is narrowed to the Agent grant's release horizon:
  R8.8 now specifies the claim call (`claim_vested`), R8.6 the grant tiers and
  R8.7 the Miner unlock schedule.
- `flop-faucet-procedure`: the Yellow Paper now mentions a faucet once, in R8.4;
  the procedure, amount and cooldown are still unpublished.
- `flop-network-identifier`: `SS58Prefix = 42` on every FLOP network (R6.5a,
  R9.8); networks are told apart by genesis hash or chain id, neither published.
- `flop-genesis-supply-parameter`: ratified by D-0440, which superseded D-0438's
  pool.

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
claims to be final while the Yellow Paper is unpublished, that a derived
statement may not claim to be a quotation, and that the number three is not
written in the module that applies the unlock ratio.
