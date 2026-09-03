# FLOP Activity Console

A local, read-only console that shows one agent what it has actually done in
the FLOP ecosystem, which of it has evidence, which FLOP rules are officially
published, what looks dangerous, and what useful activity to consider next.
`packages/py/lineageauth/flop/`, `apps/flop/`, `conformance/flop/`.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** Evidence coverage is not an airdrop score. Nothing in the
Console is a claim about anyone's allocation of anything.

## Positioning

The LineageAuth FLOP Activity Passport helps agents track FLOP ecosystem
participation, preserve verifiable evidence of useful work, and distinguish
official requirements from unverified claims. It is built independently for
the FLOP ecosystem, and it is not "the official FLOP airdrop tracker" — no
statement of that kind is made anywhere, and none will be without FLOP Labs
saying so.

## The five questions

The console directive's target (§37) is that a new user answers five questions
in under thirty seconds without knowing what LineageAuth is. Each has one
place on the Overview screen:

| Question | Where | What it shows |
|---|---|---|
| What have I done? | hero card **Useful work** | the count of non-secondary, useful-work records |
| Which of it has evidence? | hero card **Evidence coverage** | `n / 10 categories`, subtitle `Not an airdrop score.` |
| Which rules are official? | Sources screen, `RuleSource` | every rule with `official-draft` / `unknown`, its source, and `RULE UPDATED` when stale |
| Is anything dangerous? | Safety screen, `SecurityAlert` | scan findings with a text level, never colour alone |
| What next? | **Next best action** under the hero row | one recommendation, with the rule id it rests on |

Protocol detail — event ids, hashes, canonical bytes — sits behind the
Evidence screen and the raw projection panels rather than on the Overview.

## Architecture

```text
read-only adapters                 flop.activity
  LocalEventsAdapter               signed events in the bundle (core passport, artifacts,
                                   attestations, tasks, tclk frames)
  TechnocoreAdapter                TechnocoreReader with an injected transport; volume is secondary
  TclkAdapter                      tclk/1 frame lines, folded by adapters.tclk
  PublicEvidenceAdapter            conformance/flop/public-evidence.json, real, partially-verified
  MockAdapter                      conformance/flop/mock-activity.json, synthetic, demo mode only
        |
        v  collect_activities -> ActivityCollection (sorted, deduplicated, warnings kept)
        |
        +--> flop.coverage        ten categories x five states, no total
        +--> flop.wash            five patterns, one fixed label, isAccusation: false
        +--> flop.recommend       rule-based, each item names its rule id; no spam advice
        +--> flop.safety          scan_text over untrusted text; executes nothing
        |
        v
flop.passport.build_flop_passport  a projection over passport.build_passport (docs/09)
        |
        v
flop.api  GET /v1/flop/{status,sources,rules,activities,coverage,recommendations,passport/{did}}
          POST /v1/flop/safety/scan
        |
        v
apps/flop  index.html + app.js + app.css + tokens.css (generated)
```

Every adapter sets `read_only = True` and the collector refuses one that does
not. The `ActivitySourceAdapter` protocol has no member that could post, sign,
spend or follow a URL (`docs/FLOP_DATA_MODEL.md`).

The core is untouched. The FLOP layer is mounted on `create_app` as a router
and a set of static routes, and `flop_demo_mode` — the only new parameter —
defaults to off so the mock adapter is never consulted in a production mount
(D-108).

## What the Console reads

| Source | Class | How it is treated |
|---|---|---|
| The lineage's own signed events | verified by the core before the adapter sees them | the only records that reach `cryptographically-linked` or better without a third party |
| `conformance/flop/official-sources.json` | eight snapshots, hashes only, `fetchedAt` 2026-09-03T04:25:46Z | the definition of *official* (`docs/FLOP_SAFETY.md`) |
| `conformance/flop/rule-registry.json` | eighteen rules, eleven `official-draft`, seven `unknown` | quoted, hashed, marked stale when the source moves (`docs/FLOP_RULE_REGISTRY.md`) |
| `conformance/flop/public-evidence.json` | thirteen real public contributions of the subject DID | `partially-verified` at most: the URL is on record, this session did not re-fetch it; a third party's public citation is `evidence-supported`, not attested, because no attestation event exists |
| `conformance/flop/mock-activity.json` | the directive's synthetic sample | every record `synthetic: true` and the banner `SYNTHETIC MOCK DATA`; only with `flop_demo_mode=True` |
| Technocore rooms | community, via `adapters.technocore` | message volume shown as a number and excluded from coverage; GET-write URLs refused before reading |
| tclk/1 transcripts | community, via `adapters.tclk` | deals folded read-only; no rail, no settlement |

Real and synthetic never share a file, an adapter or a source id.

## Evidence levels and coverage

Four evidence levels, from `docs/09`'s four claim categories and never
summed: `self-claimed`, `cryptographically-linked`, `evidence-supported`,
`third-party-attested`. Ten coverage categories in five states
(`STRONG_EVIDENCE`, `SOME_EVIDENCE`, `NOT_OBSERVED`, `NOT_YET_AVAILABLE`,
`SOURCE_UNKNOWN`). The four categories that depend on a network phase —
inference, broker, creator, mainnet — report `NOT_YET_AVAILABLE` in
`PRE_TESTNET`, which is not zero: zero would say the feature exists and was
unused.

Volume is a fact and not evidence. Five hundred room messages with no artifact
inflate nothing (acceptance test 3), and the summary carries `Volume is not
evidence of useful participation.` wherever a count is shown.

## The ten screens

| # | Screen | Shows | Reads |
|---|---|---|---|
| 1 | Overview | subject form, three hero cards, next best action | `/coverage`, `/recommendations` |
| 2 | Activity | every record, filters All / Useful Work / Technocore / tclk / Inference / Creator / Broker / Security | `/activities` |
| 3 | Evidence | one record: badges, hash, verification state, raw projection | the record already loaded |
| 4 | Technocore | room participation, volume shown and kept out of coverage | `/activities` |
| 5 | tclk | deals observed, read-only | `/activities` |
| 6 | Inference | `Waiting for official FLOP Testnet`; the four-step simulation walkthrough; real faucet and execute buttons disabled with the reason | `/status`, `/testnet/state`, `/testnet/inference/*`, `/testnet/simulation/run` |
| 7 | Passport | the whole projection: sections, coverage, activities, safety, wash signals, recommendations, sources | `/passport/{did}` |
| 8 | Safety | paste text, choose where it came from, scan | `/safety/scan` |
| 9 | Sources | eight snapshots with their classification; every rule with its `RuleSource` | `/sources`, `/rules` |
| 10 | Settings | kill switch (locked), spend policy, custody and writes, mainnet rule, reset local preferences | `/status`, `/testnet/state` |

The Passport screen is reachable as `#/passport/<did>?lineage=…` and, for a
pasted link, as `/flop/passport/<did>` on the server, which returns the same
page. Screen layout, tokens and components: `docs/FLOP_UI_GUIDE.md`. The
Inference screen's four steps and what each one refuses:
`docs/FLOP_TESTNET_EXECUTOR.md`.

## Recommendations

`flop.recommend.recommend` is a rule table, not a model. Each item has a type
(`officialRequirement`, `officialDirection`, `evidenceGap`,
`securityRecommendation`, `communityObservation`), a reason, a confidence, and
the rule id it rests on; `official` is true only when the type is official
*and* a rule is attached. In `PRE_TESTNET` the official direction is to wait
for an official testnet endpoint before any inference activity, and the
evidence gaps are the kind a person can close with one artifact, one
independent verification, or one collaboration with an agent they do not
operate. The engine cannot say "post more" or "join more rooms"; a test fixes
the banned words. `next_best_action` picks the first by a fixed priority
(security first, official next, then gaps) so two runs agree.

## Anti-wash

`flop.wash.detect_wash_signals` reports repeated artifact hashes, repeated
titles, self-dealing, same-operator counterparties (through `fleet.resolve_fleets`,
D-105) and rapid churn with nothing to show. Every signal is labelled
`Possible low-value / circular activity` and carries `isAccusation: false`.
It describes what this tool cannot tell apart, which is all it knows.

## Running it locally

```text
py -3 -m uv run python scripts/serve_flop_console.py
http://127.0.0.1:8792/flop
```

The script builds a demo bundle with the public, deterministic, unsafe test
keys: a lineage, one delegation with scope `http` /
`host:testnet.simulation.invalid` / `post` and `approval: required` naming
`ROOT` as the sole approver (D-107), two artifacts with receipts, an
attestation, a task chain and a profile — then mounts the API with
`flop_demo_mode=True`. Everything the mock adapter contributes carries the
synthetic banner; everything the bundle contributes is signed by keys that
belong to nobody. `la flop status | sources | rules` show the same data from
a terminal, in ASCII.

## What it never does

- Hold, read, or ask for a seed phrase or private key. The persistent notice
  says so on every screen, and `holdsPrivateKeys: false` / `walletCustody:
  false` are fields in `/v1/flop/status` rather than sentences in a README.
- Post, sign, spend, claim, connect or follow a link it found. The adapters
  cannot; the page generates no `href` from data; the scanner reports
  `executedAnything: false` on every scan.
- Produce a number that reads as an allocation. There is no `aggregateScore`,
  and a test asserts its absence; the forbidden vocabulary is checked over
  every API response, CLI output and the page source.
- Treat a message as official because of a nickname, a room name, a topic or
  a signature. `classify_source` sees the URL and nothing else.
- Serve synthetic data without the banner, or in a mount that did not ask for
  it.

## Related

`docs/FLOP_DATA_MODEL.md` (types), `docs/FLOP_RULE_REGISTRY.md` (rules and
staleness), `docs/FLOP_SAFETY.md` (classification and scanning),
`docs/FLOP_UI_GUIDE.md` (tokens, components, accessibility),
`docs/FLOP_NETWORK_PHASES.md` and `docs/FLOP_TESTNET_EXECUTOR.md` (the
Inference screen's other half), D-108 in `docs/29_DECISIONS.md`, and the
two implementation reports.
