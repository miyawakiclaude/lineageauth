# FLOP TESTNET EXECUTOR — IMPLEMENTATION REPORT

**Date:** 2026-09-03
**Directive:** `LineageAuth — FLOP Testnet Executor`, "PREPARE NOW / ACTIVATE
ONLY AGAINST OFFICIAL FLOP TESTNET", §37 format.
**Standing:** independent tool for the FLOP ecosystem — not affiliated with or
endorsed by FLOP Labs. Testnet tokens have no assumed monetary value.

```text
FLOP TESTNET EXECUTOR REPORT

Current FLOP phase:
PRE_TESTNET

Official sources reviewed:
- https://flop.finance/                  200  sha256 dedb1ae9d9cd72bd...  (no rules)
- https://flop.finance/teaser/           200  sha256 bc9c93a3a420b7a2...  Version 0.1 (draft), Updated 2026-08-26,
                                              testnet Q4 2026 (~90 days), mainnet Q1 2027, Yellow Paper not yet final
- https://flop.finance/brand/            200  sha256 5211800919428e2a...
- https://flop.finance/design.md         200  sha256 476fe27b0cebf5fe...  version: alpha
- https://technocore.chat/llms.txt       200  sha256 c386c79a48d95b66...
- https://technocore.chat/auth.md        200  sha256 ae4c61d5d6d4b13e...  "There is no authentication"
- https://technocore.chat/patterns.md    200  sha256 1851ca6b3d43edb5...
- https://github.com/flop-labs           200  repos: tclk (8872fab1, v0.1.0), technocore-chat;
                                              no testnet, faucet or inference repository
  fetchedAt 2026-09-03T04:25:46Z; hashes in conformance/flop/official-sources.json; bodies not stored

Official Testnet executable:
NO

Phase gate:
PASS
  PhaseGate default PRE_TESTNET, kill switch ON and locked below TESTNET_VERIFIED;
  transition table has no PRE_TESTNET -> TESTNET_ENABLED edge; TESTNET_ENABLED requires
  every id of the fifteen-item ACTIVATION_CHECKLIST; downgrade always allowed.
  Acceptance A (three tests) pass.

Endpoint registry:
PASS
  FlopEndpointRegistry.default(): two simulation entries, zero executable.
  `executable` = official origin AND verifiedAt AND enabled; the constructor refuses an
  executable entry from a non-official origin. Community and unknown URLs resolve to
  READABLE_IF_SAFE / BLOCKED, never executable. Acceptance B (four tests) pass.

Simulation:
PASS
  Origin https://testnet.simulation.invalid (RFC 6761). Synthetic faucet, balance, quote,
  LineageAuth authority, exact approval, execution, receipt, evidence drafts, passport --
  through the same executor, approval check and builders as the real path. Simulation is
  decided by the registry entry, not by the prepared action's claim; a lying claim is
  REQUEST_INVALID at stage 3. Every object carries SIMULATION - NO FLOP NETWORK ACTION.
  Acceptance D and M pass. Verified in the browser through the Inference screen.
  Post-pipeline browser check found the walkthrough stopping at the approval step (the
  page holds no keys); fixed by taking the receipt from a pasted envelope or, in a demo
  process only, a demo approver -- labelled, verified like any receipt, never indexed
  (tests/test_flop_approval_receipt.py).

Faucet:
INTERFACE_ONLY

Inference:
INTERFACE_ONLY

Exact approval:
PASS
  ActionRequest.over_bytes(namespace="http", resource="host:<host>", action="post",
  destination=<canonical destination>, content=<canonical request bytes>) through the
  core's check_execution; approver designated on the grant (D-107); approve previews with
  reserve=False, the executor commits at stage 8 with reserve=True; a re-run is
  APPROVAL_MISMATCH with the wash wording; approval: none still requires a receipt.
  Acceptance C, E, K pass.

Spend limits:
PASS
  TestnetSpendPolicy defaults per action 10 / session 25 / day 50, approval above 0,
  nested or refused, Decimal only, raised only through raised(); maxSpend is inside the
  canonical request so the approval binds the ceiling. Acceptance F, G pass.

Evidence recording:
PASS
  receipt -> two artifact.register drafts + one attestation.issue draft via the core
  builders; predicate flop.testnet.inference left unregistered; synthetic marker in the
  attestation's reasonCode, no key injected into a signed payload;
  conformance/frozen-shapes.json unchanged. Acceptance L, M pass.

Activity Passport integration:
PASS
  Simulated attestations appear in the timeline and on the Passport screen with the
  banner; the `inference` coverage category stays NOT_YET_AVAILABLE below
  TESTNET_ENABLED (console acceptance 5). Mainnet adapter: NotYetAvailable, ratio read
  from the rule registry, never from code.

Prompt injection tests:
PASS
  build_plan has no prompt parameter (inspect.signature pinned); assemble_request copies
  the workload field by field from an allowlist (**workload and dict-merge syntax
  grepped out); a prompt demanding another endpoint or cap changes nothing; a seed-phrase
  request is BLOCKED at prepare; a clean scan is not permission. Acceptance H, I pass.

Wallet custody introduced:
NO
  NoSigner only; no import of lineageauth.crypto in flop/**; an AST test finds no
  parameter named like a seed, key, keyfile or passphrase.

External FLOP writes performed:
NONE
  Acceptance O: a counting transport records zero calls across all four non-live phases;
  NullTransport refuses rather than answering. No egress library is imported anywhere in
  flop/** (AST walk).

Live activation required later:
YES
  docs/FLOP_TESTNET_ACTIVATION.md -- the fifteen-item checklist, then a person.

Remaining unknown official details:
- testnet endpoint
- faucet procedure, amount, cooldown
- inference request / response schema
- pricing and quote mechanism
- network identifier
- authentication / signing scheme
- Yellow Paper body
  (each an `unknown` rule with a consequence in conformance/flop/rule-registry.json)

STATUS:
PASS  (prelaunch scope, §34; live activation, §35, not attempted by design)
```

## Measurements behind the verdicts

Gate after the QA repair pass, `py -3 -m uv run python scripts/gate.py`:

```text
PASS  lint     (ruff check .)
PASS  format   (ruff format --check .)
PASS  types    (mypy strict)   Success: no issues found in 84 source files
PASS  tests    1983 passed
all checks passed
```

`pytest --collect-only` counting `::` node ids: 1983 in the repository, of
which the twelve testnet files contribute 234 and the FLOP files together 569
(1850 and 233 at stage 2; 1892 and 478 at stage 3). No failures at any stage.

Acceptance A–O of the directive (§25) are 54 tests whose names carry their
letter, for example
`test_acceptance_a_pre_testnet_blocks_a_live_execution`,
`test_acceptance_h_the_executed_destination_comes_from_the_control_plane`,
`test_acceptance_o_with_the_testnet_disabled_the_transport_is_called_zero_times`.
All pass. `scripts/pre_push_check.py` clean; every new file LF.

L moved during the repair pass. It read "only a complete response verifies";
it now reads "even a complete response stops at partially-verified", because
every field in a response is the counterparty describing its own behaviour --
`observedSpend` included, which is the party being billed against stating what
it charged. The directive's requirement (a response missing a receipt must not
be fully verified) still holds; the ceiling is simply lower than it was, and
`test_acceptance_l_no_response_at_all_can_produce_a_verified_receipt` states
the property rather than an example.

## Changes the QA repair pass made to this package

| Defect | Fix | Test |
|---|---|---|
| the ledger recorded the endpoint's self-reported spend, so an endpoint reporting zero kept the daily and session caps empty forever | the ledger is charged `max(approved estimate, reported spend)`, and the audit line records `chargedToLedger` | `test_an_execution_charges_the_estimate_when_the_answer_reports_zero` |
| `receipt_from_response` returned `VERIFIED` when three fields were present | no payload reaches `VERIFIED`; `SELF_REPORTED_REASON` is on every receipt | `TestNothingACounterpartySaysIsVerification` |
| `matches_path` character-checked the pattern and not the concrete path | the same character set applies to both, so `?`, `#`, `@` and `%2e%2e%2f` cannot reach `url_for` | `TestAConcretePathIsCheckedLikeAPattern` |
| `JsonlAuditLog.append` read the whole file and wrote without a lock, so two writers computed the same `seq` and `prev` | tail-only read inside an exclusive lock file | `TestTheAuditLogSurvivesTwoWriters` |
| `networkWritesPerformed` was a literal zero in three files | `NetworkWriteMeter` counts what the executor reports; a simulation run computes attempts minus the calls the simulation transport received | `TestTheZeroOnTheHeaderIsMeasured` |
| `walletCustody: false` was a literal beside a signer that knew the answer | `NoSigner.holds_private_keys`, on the `Signer` protocol | same |

Residual closed after the review (D-110): the audit chain is unkeyed, so an editor
with write access could rewrite a line and recompute the hashes after it. Rather
than sign the head as a new event type, `la flop audit anchor` drafts an existing
`artifact.register` whose artifact id is the chain head, signed outside the
process; `verify_anchor` checks a log against it and reports lines beyond the
anchor as uncovered. What remains is only what was always true: a log with no
anchor yet is a local record, not evidence (`tests/test_flop_audit_anchor.py`).

Not measured: behaviour against any real response, because none exists; wall
time of the simulation run; memory.

## Files

Added — `packages/py/lineageauth/flop/testnet/{__init__, ports, phase,
endpoints, spend, prepare, approve, client, simulation, executor, receipts,
evidence, audit, mainnet, signer}.py` (4,340 lines);
`packages/py/lineageauth/flop/cli.py` (471 lines); `tests/flop_testnet_fixtures.py`;
`tests/test_flop_testnet_{phase, endpoints, spend, prepare_approve, executor,
client, simulation, evidence, audit, signer}.py`, `tests/test_flop_api_testnet.py`,
`tests/test_cli_flop.py`.

Changed — `flop/api.py` (seven testnet routes; `prepare` delegates to
`simulation.prepare_simulation` so the bytes approved in the UI are the bytes
the run executes); `flop/model.py` (`TestnetFailure` gains the directive's
§24 names `OFFICIAL_SOURCE_UNVERIFIED`, `APPROVAL_EXPIRED`, `QUOTE_EXPIRED`,
`SIGNER_NOT_CONFIGURED`, `INVALID_RESPONSE`, `RECEIPT_UNVERIFIED`;
`TestnetRefusal`, `TestnetRefusedError` added; no existing member changed);
`lineageauth/cli.py` (two lines); `tests/test_flop_api_console.py` (the pinned
FLOP POST set gains the five testnet routes — an explicit set, not a count, so
the addition is a deliberate edit).

## The nine stages, and the one the directive did not list

```text
1 phase  2 official-source  3 endpoint  4 request-validation  5 active-did
6 authority  7 spend  8 exact-approval  9 network
```

The directive names eight checks. The phase gate was split out as the first so
it is unmistakably consulted before anything is read, and the network is the
ninth. `STAGES` is a constant and a test walks it. Every refusal is
`TestnetRefusal(failure, detail, stage)` with `executed: false`; the API
answers 409 with that object.

## API and CLI delivered

`GET /v1/flop/testnet/state`, `GET /v1/flop/testnet/receipts/{id}`,
`POST /v1/flop/testnet/inference/{quote, prepare, approve, execute}`,
`POST /v1/flop/testnet/simulation/run`. Bodies `extra="forbid"`; `endpointId`
never accepted from a client (422); foreign `Origin` → 403; `execute` → 409
`TESTNET_NOT_LIVE` at stage `phase` in every phase below `TESTNET_ENABLED`.

`la flop status | sources | rules`, `la flop testnet simulate`,
`la flop faucet prepare` (unavailable / simulation only), `la flop inference
quote | prepare | inspect`, `la flop receipt verify`. **No `execute`
command.** ASCII output.

## SPEC CHANGE proposals — recorded, not adopted

The directive's spend safety and per-action-type permission would be cleanest
as a `flop` namespace and a typed spend constraint on a scope. Both are
protocol changes (`scopes.py`, `docs/24`); neither was needed to make the path
safe in `PRE_TESTNET`; both are written up as proposals in
`docs/FLOP_TESTNET_EXECUTOR.md` and referenced by D-108(b), in the same
standing as `docs/TCLK_GAP_ANALYSIS.md`. What was built instead: `http` /
`host:<official host>` / `post`, with the cap bound into `requestHash`.

## Review points handed to the checker

1. Simulation bypasses the phase gate on the strength of the registry entry
   (`simulation=True`, origin under `.invalid`), with a lying prepared action
   refused at stage 3 — whether two guards suffice.
2. `client.redact` treats a seed-like match greedily to end of line,
   over-redacting by choice.
3. The synthetic marker rides in the attestation's `reasonCode` rather than as
   an injected payload key.
4. The stage-1 test edits (`tests/test_api.py` recursion,
   `tests/test_api_tclk.py`, `tests/test_zero_cost.py` narrowing) and the
   stage-2 extension of `tests/test_flop_api_console.py`.
5. The derived rule `technocore-not-a-settlement-system` registered with
   `hash: null` and freshness `UNVERIFIABLE`.

## External writes

None. No push, issue, PR, comment, post, deploy, faucet, wallet, token or
inference spend. The only network activity of the whole build was the
read-only source snapshot before any code was written.
