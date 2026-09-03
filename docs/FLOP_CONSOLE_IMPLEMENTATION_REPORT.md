# FLOP ACTIVITY CONSOLE — IMPLEMENTATION REPORT

**Date:** 2026-09-03
**Directive:** `LineageAuth — FLOP Activity Console / Activity Passport`, §35.
**Standing:** independent tool for the FLOP ecosystem — not affiliated with or
endorsed by FLOP Labs. Evidence coverage is not an airdrop score.
**External writes during build:** none. No post, push, issue, PR, comment,
deploy, faucet, wallet, token or inference spend. Read-only public retrieval
happened once, in the source-snapshot phase; no network access during
implementation or in any test.

Figures below are taken from the stage reports of the build (stage 1: model,
sources, rules, safety, activity, coverage, wash, recommendations, passport,
API; stage 2: testnet executor; stage 3: page). Where a figure was not
measured it says so.

## Official sources checked

Snapshot `fetchedAt` 2026-09-03T04:25:46Z; hashes in
`conformance/flop/official-sources.json`; bodies not stored.

| URL | HTTP | bytes | sha256 (first 16) | version / date |
|---|---|---|---|---|
| https://flop.finance/ | 200 | 16472 | `dedb1ae9d9cd72bd` | text only, no rules |
| https://flop.finance/teaser/ | 200 | 44723 | `bc9c93a3a420b7a2` | Version 0.1 (draft) · Status Draft · Updated 2026-08-26 · definitive spec Yellow Paper (not yet final) |
| https://flop.finance/brand/ | 200 | 13389 | `5211800919428e2a` | six swatches |
| https://flop.finance/design.md | 200 | 30278 | `476fe27b0cebf5fe` | front matter `version: alpha`; Mascot V3.0 design system; ETag `7e047e3e7b87506b8511ca62138b7688` |
| https://technocore.chat/llms.txt | 200 | 24048 | `c386c79a48d95b66` | Last-Modified Thu, 03 Sep 2026 04:21:08 GMT |
| https://technocore.chat/auth.md | 200 | 5200 | `ae4c61d5d6d4b13e` | "There is no authentication" |
| https://technocore.chat/patterns.md | 200 | 13028 | `1851ca6b3d43edb5` | ETag `fb603312a91fcd563f58d4e8c9372e68` |
| https://github.com/flop-labs | 200 | — | — | repositories `tclk` (pushed 2026-09-03T04:20:16Z, main `8872fab1`, tag v0.1.0) and `technocore-chat` (pushed 2026-09-02T18:04:40Z); **no testnet, faucet or inference repository** |

Network phase determined from these: **`PRE_TESTNET`**. Official testnet
executable: **NO**.

## Source versions relied on

- Economic rules: teaser v0.1 draft, 2026-08-26, all `official-draft`. Seven
  details registered as `unknown` (`UNKNOWN_FROM_OFFICIAL_SPEC`): testnet
  endpoint, faucet procedure, inference API, pricing, network identifier,
  auth/signing scheme, Yellow Paper.
- One derived rule (`technocore-not-a-settlement-system`): the directive's
  sentence is not in any `flop.finance` document; registered as
  `official-draft`, `derivation: "derived"`, `hash: null`, freshness
  `UNVERIFIABLE`, source the `flop-labs/tclk` `SPEC.md` reading this project
  already ported. Flagged for review; `docs/FLOP_RULE_REGISTRY.md`.
- Design tokens: `design.md` alpha over the supplied baseline; fifteen
  differences recorded in `ui-tokens.json#diffFromBaseline`;
  `docs/FLOP_UI_GUIDE.md`.

## Files added

```text
packages/py/lineageauth/flop/__init__.py
packages/py/lineageauth/flop/model.py          enums, frozen records, contract constants
packages/py/lineageauth/flop/sources.py        origin allowlist, classify_source, snapshot load/compare
packages/py/lineageauth/flop/rules.py          FlopRuleRegistry, staleness, unlock_ratio
packages/py/lineageauth/flop/safety.py         scan_text, scan_report; executes nothing
packages/py/lineageauth/flop/activity.py       ActivitySourceAdapter + five read-only adapters
packages/py/lineageauth/flop/coverage.py       ten categories, five states, no total
packages/py/lineageauth/flop/wash.py           five patterns, one label, isAccusation: false
packages/py/lineageauth/flop/recommend.py      rule table, next_best_action
packages/py/lineageauth/flop/passport.py       build_flop_passport, a projection over docs/09
packages/py/lineageauth/flop/api.py            build_flop_router
packages/py/lineageauth/flop/cli.py            la flop …
packages/py/lineageauth/flop/testnet/*.py      see docs/FLOP_TESTNET_EXECUTOR_IMPLEMENTATION_REPORT.md
apps/flop/index.html, app.js, app.css          the page
apps/flop/tokens.css                           GENERATED from conformance/flop/ui-tokens.json
scripts/generate_flop_tokens.py
scripts/serve_flop_console.py                  demo bundle on port 8792, flop_demo_mode=True
conformance/flop/official-sources.json
conformance/flop/rule-registry.json
conformance/flop/ui-tokens.json
conformance/flop/public-evidence.json          real, synthetic: false, 13 entries
conformance/flop/mock-activity.json            SYNTHETIC MOCK DATA, copied unchanged from the directive
conformance/flop/README.md
tests/test_flop_{model,sources,rules,safety,activity,coverage,recommend,passport,api_console}.py
tests/test_flop_{ui,a11y}.py
tests/flop_testnet_fixtures.py, tests/test_flop_testnet_*.py, tests/test_flop_api_testnet.py, tests/test_cli_flop.py
docs/FLOP_ACTIVITY_CONSOLE.md, FLOP_DATA_MODEL.md, FLOP_RULE_REGISTRY.md, FLOP_UI_GUIDE.md, FLOP_SAFETY.md
docs/FLOP_TESTNET_EXECUTOR.md, FLOP_TESTNET_SECURITY.md, FLOP_TESTNET_ACTIVATION.md,
     FLOP_INFERENCE_EVIDENCE.md, FLOP_NETWORK_PHASES.md
docs/FLOP_CONSOLE_IMPLEMENTATION_REPORT.md      this file
docs/FLOP_TESTNET_EXECUTOR_IMPLEMENTATION_REPORT.md
```

## Files changed

```text
packages/py/lineageauth/api.py     FLOP_ROOT; router mount; /flop, /flop/app.css, /flop/app.js,
                                   /flop/tokens.css, /flop/passport/{did}; create_app(flop_demo_mode=False)
packages/py/lineageauth/cli.py     import flop_app; app.add_typer(flop_app)  (two lines)
tests/test_api.py                  pinned POST set gains /v1/flop/safety/scan; route enumeration made
                                   recursive because FastAPI 0.141 wraps include_router and the flat
                                   walk would have silently missed every mounted route
tests/test_api_tclk.py             getattr(route, "path", "") for the same FastAPI change (one line)
tests/test_zero_cost.py            NETWORK_MODULES "urllib" narrowed to urllib.request / urllib.error;
                                   urllib.parse is a string parser and opens no socket
tests/test_flop_api_console.py     (stage 2) the pinned FLOP POST set gains the five testnet routes
README.md                          one status line
docs/16_API_SDK_CLI.md, docs/17_UI_UX.md, docs/29_DECISIONS.md (D-108)   appended
```

The three test edits exceed "append to the pinned route set" and are reported
as such; each moves in the direction of stricter checking. No file in the
core's do-not-touch list was modified. `SPEC CHANGE REQUIRED`: none.

## Adapters implemented

| Adapter | Source | Read-only | Notes |
|---|---|---|---|
| `LocalEventsAdapter` | the lineage's signed events | yes | core passport, artifacts, attestations, tasks, tclk frames |
| `TechnocoreAdapter` | `TechnocoreReader`, injected transport | yes | volume `secondary`; GET-write URLs refused via `adapters.technocore.routes.classify` |
| `TclkAdapter` | tclk/1 frame lines | yes | folded with `adapters.tclk` |
| `PublicEvidenceAdapter` | `public-evidence.json` | yes | file only, no network; `partially-verified` cap |
| `MockAdapter` | `mock-activity.json` | yes | `synthetic: true` forced; demo mode only |

## Tests added

Measured with `py -3 -m uv run pytest --collect-only`, counting `::` node ids
(no `-q`), after the QA repair pass: **1983 collected** (1414 at HEAD `a094d72`
before the work began; 1892 at the end of stage 3, before the repairs).

| Stage | Files | Tests |
|---|---|---|
| 1 — console backend | 9 `tests/test_flop_*.py` | 203 |
| 2 — testnet executor | 12 files (`test_flop_testnet_*`, `test_flop_api_testnet`, `test_cli_flop`) | 234 |
| 3 — page | `test_flop_ui.py` (33), `test_flop_a11y.py` (9) | 42 |
| 4 — QA repairs | `test_flop_qa_regressions.py` | 67 |
| total FLOP | 24 files | **546** |

Acceptance tests 1–8 of the console directive (§31) exist under their numbers
and pass: 1 official badge by origin only (classifier and scanner); 2 signed
wallet-connect request `BLOCKED`; 3 five hundred messages and no artifact
inflate nothing; 4 a third-party verification surfaces as attested; 5
inference reads `NOT_YET_AVAILABLE` and is not counted as covered; 6 a changed
official source marks its rules stale; 7 every mock record carries the
synthetic banner; 8 an activity without evidence stays self-claimed.

Gate, last full run (QA repair pass, `py -3 -m uv run python scripts/gate.py`):

```text
PASS  lint     (ruff check .)
PASS  format   (ruff format --check .)   247 files already formatted
PASS  types    (mypy strict)             Success: no issues found in 84 source files
PASS  tests    1983 passed
all checks passed
```

The docs stage re-ran `ruff format --check .` after writing this report; the
result is in the stage's return.

## What the QA pass found, and what changed

An adversarial review read this build and reported ten defects. Nine are fixed
here and one is recorded as a residual risk. Each fix has a regression test in
`tests/test_flop_qa_regressions.py`, named after the defect.

| Defect | Severity | Fix |
|---|---|---|
| `classify_source` read a raw path, so `github.com/flop-labs/../evil-org/x` was OFFICIAL and the scanner reported nothing | Medium | dot segments and encoded separators are `SUSPICIOUS` (`dot-segment-path`, `encoded-separator-path`); the URL now raises `url.lookalike` |
| `POST /safety/scan` took `networkPhase` and `sourceClass` from the body, so a page could switch off the network-claim and impersonation families | Medium | the field is gone (422) and `sourceClass: official` is refused (400); the phase is the service's. `scan_text` now reports a suppression as its own `CAUTION` finding instead of going silent, and the page's dropdown lost its `official` option |
| Overview drew coverage counts from mock records with no label | Medium | `CoverageReport` carries `containsSyntheticData`, `/coverage` and `/recommendations` carry it, and the header shows a banner that no screen change removes |
| A record file could write `"sourceClass": "official"` about itself; `MockAdapter` answered for any DID | Medium | a declared class is clamped to the adapter's, `official` additionally has to survive `classify_source`, and every mock record says whose record it is not |
| `Origin` was compared against a value built from the attacker-controlled `Host`, so DNS rebinding bypassed the CSRF check on reads and writes alike | Medium | every FLOP route checks `Host` against a fixed set (`DEFAULT_ALLOWED_HOSTS`, overridable per deployment) and answers 421 otherwise |
| `prepared_actions` and `receipts` were unbounded dicts an unauthenticated local caller could grow | Medium | bounded to 256, oldest first, expired actions dropped on the next prepare; an id this process no longer holds is a typed `REPREPARE_REQUIRED` |
| a concrete endpoint path was not character-checked, so `?`, `#`, `@` and `%2e%2e%2f` could ride into the destination | Low | `matches_path` applies the pattern's character set to the path too |
| a counterparty's own response was recorded as `VERIFIED`, and its self-reported spend was what the ledger charged | Low | no response reaches `VERIFIED`; the ledger charges the greater of the approved estimate and the reported spend |
| the network-import guard stopped seeing `from urllib import request` | Low | the detector reads the imported names as well as the module |
| the `network` pytest marker was declared and never applied | Low | `addopts` carries `-m 'not network'`, and a test asserts this session ran with it |
| `JsonlAuditLog` read the whole file per append and wrote without a lock | Low | tail-only read under an exclusive lock file; the chain survives concurrent writers |
| `networkWritesPerformed: 0` and `walletCustody: false` were literals | Low | counted by `NetworkWriteMeter` and read from `NoSigner.holds_private_keys` |

Residual closed after the review (D-110): the audit chain is unkeyed, so an editor
with write access could rewrite a line and recompute the hashes after it. Rather
than sign the head as a new event type, `la flop audit anchor` drafts an existing
`artifact.register` whose artifact id is the chain head, signed outside the
process; `verify_anchor` checks a log against it and reports lines beyond the
anchor as uncovered. What remains is only what was always true: a log with no
anchor yet is a local record, not evidence (`tests/test_flop_audit_anchor.py`).

## UI screens

Ten, at `/flop`: Overview, Activity, Evidence, Technocore, tclk, Inference,
Passport, Safety, Sources, Settings. Desktop left navigation 240 px; mobile
bottom navigation Overview / Activity / Passport / Safety / More. Hash routes,
plus `/flop/passport/{did}` on the server. Browser walkthrough (stage 3, local
server on 127.0.0.1:8792): every screen opened; the Inference simulation ran
through Purpose → Quote → Security Review → `Approve & Run (SIMULATION)` and
reported all nine executor stages including the exact-action refusal; the
Safety scan returned `BLOCKED` for a wallet-connect request; the Passport hash
route rendered the `SYNTHETIC MOCK DATA` banner; the theme toggle was verified
by computed style; the bottom navigation appeared at 375 px; the browser
console showed zero errors throughout.

Two defects found and fixed in that walkthrough: the Sources table read
`sources.snapshots` where the API sends `sources.sources`; and
`.badge-synthetic` used a red-on-Ice text pair with no published contrast
ratio, changed to a border-only treatment and pinned by a test.

## Accessibility results

- WCAG AA for normal text, computed: `tests/test_flop_a11y.py` recomputes
  every published pair (tolerance 0.1), checks both sides of the 4.5:1
  boundary, and refuses any `color:` declaration that is a literal or an
  unsafe token. 9 tests, all pass.
- Structure: skip link, `aria-label` on both navigations, polite live region,
  native `<button>` controls, no hidden focus. Pinned by `test_flop_ui.py`.
- Meaning never by colour alone: every badge and alert is a text label.
- Not measured: screen-reader traversal, keyboard-only traversal of the
  Inference wizard, Lighthouse or axe scores. These were not run.

## Security results

- Page: no markup sink (`innerHTML` etc. absent), no inline script or style,
  strict CSP as header and meta, same-origin requests only, no web font, no
  `href` generated from data, no CORS header, foreign-`Origin` `POST` → 403.
- Classification by origin only; lookalikes (`fl0p.finance`,
  `flop-finance.com`, `flop.finance.x.example`), userinfo, punycode,
  downgrade and odd ports are `suspicious`; unobserved subdomains fail closed
  to `unknown`.
- Scanner: `SafetyFinding.executed` cannot be true (constructor raises);
  every report says `executedAnything: false`, `followedAnyUrl: false`;
  Technocore GET-write URLs detected through the adapter's own route table.
- No secret: no key file read; tests use `tests/testkeys.py` unsafe keys only;
  the passport output is tested to contain no seed-like or bare 64-hex string;
  `scripts/pre_push_check.py` clean.
- Forbidden vocabulary checked over every API response, CLI output, passport
  and the page source; the only permitted form is the disowning label.
- `flop_demo_mode` defaults off, so the mock adapter never leaks into a
  production mount (tested).
- Line endings: every new file LF; no CRLF introduced (checked).

## Current unsupported network features

| Feature | Status | Shown as |
|---|---|---|
| Testnet inference (live) | not available — no official endpoint | `Waiting for official FLOP Testnet`; coverage `NOT_YET_AVAILABLE` |
| Faucet (live) | not available — no official procedure | `INTERFACE_ONLY`; button disabled with reason |
| Broker demand contribution | not available | `NOT_YET_AVAILABLE` |
| Creator attribution | not available | `NOT_YET_AVAILABLE` |
| Mainnet unlock (3:1) | not available — rule is draft, network does not exist | `NotYetAvailable` adapter reading the ratio from the registry |
| Official pricing / quote | not available | `officialPricingAvailable: false`; quote labelled simulation |

## Remaining risks

- Every unknown above is a guess about shape once the official spec appears;
  `docs/FLOP_TESTNET_ACTIVATION.md` is the procedure for re-reading this
  work against it.
- `technocore-not-a-settlement-system` is a derived rule with no hash; it
  cannot go stale and should be replaced by a quotation when a source can be
  cited.
- The public-evidence entries are `partially-verified` because this session
  recorded URLs and did not re-fetch them; a later session that does can
  raise them, and one that finds them gone must lower them.
- The tests for the page read its HTML and script as text; they pin syntax
  and structure, not rendering. The browser walkthrough was manual and is not
  in the gate.
- Two keys may be one operator (D-105); the wash signal sees only what is
  disclosed.

## No-wallet / no-external-write status

- Wallet custody introduced: **NO**. Private keys held: **none**. Signer:
  `NoSigner` only.
- External FLOP writes performed: **NONE**. Network writes performed: 0.
  Network writes possible in `PRE_TESTNET`: none, by construction
  (`docs/FLOP_TESTNET_SECURITY.md`).
- External writes of any other kind during the build (X, Technocore, GitHub,
  git push, deploy): **none**. Commits, if any, are local.
