# FLOP data model

The typed vocabulary of the FLOP layer, `packages/py/lineageauth/flop/model.py`.
Every distinction the Console makes is an enum or a frozen dataclass here rather
than a string compared in three places. Nothing in the module reads a file,
reaches a network or holds a key.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** No type in this model can hold an allocation, a rank, or a
prediction about anyone.

## Two rules the model enforces

**Evidence levels never collapse into a rating.** A record is one of four
things, and the four are not points on a scale that can be summed. `docs/09`
says the same about the core passport, for the same reason: a sum reads as a
verdict nobody signed.

**A feature that does not exist reports `NOT_YET_AVAILABLE`, not zero.** Zero is
an observation about something that is there. `0 FLOP spent` on a testnet that
has not launched is a lie told by a data model rather than by a person.

## Enums

| Enum | Values | Note |
|---|---|---|
| `EvidenceLevel` | `self-claimed`, `cryptographically-linked`, `evidence-supported`, `third-party-attested` | `is_externally_supported` is true for the last two |
| `SourceClass` | `official`, `verified-third-party`, `community`, `unknown`, `suspicious` | decided by origin, never by wording; only `official` may carry the badge |
| `VerificationState` | `verified`, `partially-verified`, `unverified`, `conflicted`, `invalid` | what *this session* actually checked |
| `CoverageState` | `STRONG_EVIDENCE`, `SOME_EVIDENCE`, `NOT_OBSERVED`, `NOT_YET_AVAILABLE`, `SOURCE_UNKNOWN` | only the first two are `is_covered` |
| `NetworkPhase` | six phases, `docs/FLOP_NETWORK_PHASES.md` | `testnet_is_live` only at `TESTNET_ENABLED` |
| `FeatureStatus` | `available`, `not-yet-available`, `not-configured`, `not-observed`, `unsupported` | why a passport section is empty |
| `SafetyLevel` | `INFO`, `CAUTION`, `HIGH_RISK`, `BLOCKED` | display strings `SAFE TO REVIEW` … `BLOCKED`; never an authorisation |
| `RecommendationType` | `officialRequirement`, `officialDirection`, `evidenceGap`, `securityRecommendation`, `communityObservation` | `is_official` for the first two only |
| `RuleStatus` | `official-final`, `official-draft`, `community`, `unknown` | the directive's four |
| `InferencePurpose` | `evaluation`, `translation`, `summarisation`, `code-review`, `research`, `other` | stated by a person, never inferred |
| `TestnetFailure` | nineteen typed reasons, `docs/FLOP_TESTNET_EXECUTOR.md` | every refusal carries one |
| `ActivityCategory` | eleven useful-work kinds plus `message-volume`, `room-participation`, `tclk-deal`, `identity`, `inference` | `USEFUL_WORK_CATEGORIES` is a fixed subset of nine |

`message-volume` and `room-participation` are kept in the enum so a counter can
be shown; they are excluded from `USEFUL_WORK_CATEGORIES` so it can never be
counted as work.

## Records

All frozen, slotted, with `to_dict()` producing the JSON the API and the page
render. A record cannot be edited after the layer that knows its provenance has
handed it on.

### `ActivityRecord`

One thing that happened and how well it is backed: `record_id`, `subject_did`,
`category`, `title`, `occurred_at`, `source_id`, `source_class`,
`evidence_level`, `verification_state`, optional `artifact_hash`,
`artifact_ref`, `event_id`, `counterparties`, `third_party_ref`, and three
flags.

- `synthetic` — the record came from the mock adapter. `to_dict()` adds
  `banner: "SYNTHETIC MOCK DATA"` whenever it is set, so the flag cannot be
  rendered without the words.
- `secondary` — volume, not work. A room with five hundred posts is a fact and
  is not useful participation; the analytics view shows the number, the
  evidence view refuses to count it. `is_useful_work` is false for every
  secondary record whatever its category (acceptance test 3).
- `detail` — free text, limited to 4096 characters.

`sort_records` orders by instant then id, so two identical runs diff as
identical.

### `OfficialSourceSnapshot` and `RuleSource`

A source as it was at one instant: URL, HTTP status, byte length, `sha256`,
`fetchedAt`, `versionHint`, `status`. `bodyStored` is always `false` in the
output. `RuleSource` is the same idea pinned to one rule: id, URL, version,
date, `fetchedAt`, `hash`. `docs/FLOP_RULE_REGISTRY.md`.

### `EconomicRule`

One published FLOP rule with the sentence it came from: `statement`,
`statement_is_quotation`, `status`, `effective_network_phase`, `source`,
optional `derivation`/`derivation_note`, `formula`, `absent_from`,
`consequence`. Arithmetic lives in `formula` as data; the code never embeds a
figure from a draft.

### `SafetyFinding`

What the scanner noticed: `level`, `pattern_id`, `reason`, `source_class`,
`excerpt`, `url`. `executed` exists to be permanently `false`; `__post_init__`
raises if it is ever set, because the type should refuse to represent the value
the safety layer exists to prevent. `to_dict()` also emits `autoOpened: false`.

### `WashSignal`

A pattern that is hard to tell apart from wash activity: `pattern_id`,
`label`, `reason`, `record_ids`. The label is fixed — `Possible low-value /
circular activity` — and `to_dict()` emits `isAccusation: false`. It says what
is difficult to distinguish, not what somebody did.

### `Recommendation`

`title`, `recommendation_type`, `reason`, `confidence`, `rule_id`. `official`
is true only when the type is official *and* a rule id is attached; inferred
advice never claims it. `to_dict()` emits `isEligibilityClaim: false`.

### `CoverageCategory` and `PassportSection`

A coverage category is `category_id`, `label`, `state`, `observed`, `reason`.
A passport section is `section_id`, `status: FeatureStatus`, `reason`,
`detail`. Both carry the reason for their state, because an empty section with
no reason looks like an omission.

### `FlopActivityPassport`

The projection: `subject_did`, `lineage`, `generated_at`, `network_phase`,
`sections`, `coverage`, `activities`, `safety`, `wash_signals`,
`recommendations`, `sources`, `warnings`, `contains_synthetic`.

It is a projection *over* the core passport (`passport.build_passport`, four
claim categories, `docs/09`), not a replacement. The core answers "what does
this bundle say about this DID"; this answers "what of that is relevant to
FLOP participation, and what is still unknown". There is no combined figure,
because there is nothing honest to combine.

`to_dict()` output, the parts that carry a promise:

```text
evidenceCoverage.label        "Evidence coverage — not an airdrop score"
evidenceCoverage.labelAscii   the same without the em dash, for cp932 consoles
evidenceCoverage.covered      count of categories in STRONG_EVIDENCE or SOME_EVIDENCE
evidenceCoverage.total        10
evidenceCoverage.isAirdropScore   false
summary.volumeNote            "Volume is not evidence of useful participation."
containsSyntheticData         true iff any record is synthetic; then banner is present
notices.affiliation / seedPhrase / coverage
holdsPrivateKeys              false
walletCustody                 false
```

There is no `aggregateScore` field. A test asserts its absence.

## Coverage categories

Ten, fixed in `flop.coverage.COVERAGE_CATEGORIES`:

| id | label | filled by | requires phase |
|---|---|---|---|
| `identity` | Identity continuity | `identity` records | — |
| `useful-work` | Useful work | the nine `USEFUL_WORK_CATEGORIES` | — |
| `external-verification` | External verification | `external-verification` | — |
| `collaboration` | Agent collaboration | `agent-collaboration` | — |
| `technocore` | Technocore participation | `room-participation` | — |
| `tclk` | tclk activity | `tclk-deal` | — |
| `inference` | Testnet inference | `inference` | `TESTNET_ENABLED` |
| `broker` | Broker demand contribution | nothing yet | `TESTNET_ENABLED` |
| `creator` | Creator attribution | nothing yet | `TESTNET_ENABLED` |
| `mainnet` | Mainnet continuation | nothing yet | `MAINNET_VERIFIED` |

Below its required phase a category reports `NOT_YET_AVAILABLE` with the
reason text from the spec (acceptance test 5). Two or more non-secondary
records at `evidence-supported` or better make `STRONG_EVIDENCE`; one makes
`SOME_EVIDENCE`; only self-claimed records make `NOT_OBSERVED` with a reason
saying why the claims do not count.

## Constants that are part of the contract

```text
COVERAGE_LABEL            "Evidence coverage — not an airdrop score"
COVERAGE_LABEL_ASCII      "Evidence coverage - not an airdrop score"
NOT_AFFILIATED_NOTICE     "Independent tool for the FLOP ecosystem - not affiliated with or endorsed by FLOP Labs."
SEED_WARNING_NOTICE       "FLOP token may not yet exist on the current network phase. Never enter a seed phrase or private key to claim an airdrop."
SYNTHETIC_BANNER          "SYNTHETIC MOCK DATA"
SIMULATION_BANNER         "SIMULATION - NO FLOP NETWORK ACTION"
VOLUME_NOTE               "Volume is not evidence of useful participation."
NOT_VERIFIED_BY_OFFICIAL  "NOT VERIFIED BY CURRENT OFFICIAL FLOP SOURCES"
UNKNOWN_FROM_OFFICIAL_SPEC
```

The API and the page use the em-dash forms; the CLI uses the ASCII forms,
because one em dash in a help string took a command down on a cp932 console
(`tests/test_zero_cost.py` found it).

`FORBIDDEN_VOCABULARY` lists the phrases this product may not use about a
person's activity, and `forbidden_vocabulary_in(text)` is run by tests over
every rendered API response, CLI output and passport. The disclaimer's own
negated phrase is exempted first; the bare phrase still fires.

## Where the records come from

`flop.activity` defines `ActivitySourceAdapter` (`source_id`, `source_class`,
`read_only: bool`, `fetch(subject)`) and five implementations, every one with
`read_only = True` set in its constructor and checked by the collector:

| Adapter | Reads | Source class | Notes |
|---|---|---|---|
| `LocalEventsAdapter` | an `EventBundle` — core passport, artifacts, attestations, tasks, tclk frames | `verified-third-party` (the core verified the signatures before the adapter saw them) | evidence level derived from the core's four categories; the only source that reaches `cryptographically-linked` without a third party |
| `TechnocoreAdapter` | a `TechnocoreReader` with an injected transport | `community` | message volume is `secondary`; never follows a URL |
| `TclkAdapter` | tclk/1 frame lines | `community` | folded with `adapters.tclk` |
| `PublicEvidenceAdapter` | `conformance/flop/public-evidence.json` | `verified-third-party`, or the entry's own `sourceClass` when that claims no more | real contributions, capped at `partially-verified`; never mixed with mock |
| `MockAdapter` | `conformance/flop/mock-activity.json` | `unknown`, or the entry's own `sourceClass` when that claims no more | every record `synthetic: true` whatever the file says, and every record says whose record it is not; only mounted with `flop_demo_mode=True` |

An entry's own `sourceClass` is a ceiling, never a promotion. `official` is
decided by origin (`sources.classify_source`), so a record file that writes
`"sourceClass": "official"` about itself is shown at its adapter's class with
the downgrade written into its `detail`, and `official` additionally has to
survive `classify_source` on the record's own URL. Before that clamp, anyone
who could edit `public-evidence.json` or `mock-activity.json` could hand a
record an OFFICIAL badge without going anywhere near an official origin.

No adapter can post, sign, spend or follow a link it found. That is not a
convention; the `Protocol` has no member that could.
