# 16 — API, SDK, CLI

## REST

Core:
- `POST /v1/verify/event`
- `POST /v1/verify/authority`
- `POST /v1/check-permission`
- `GET /v1/events/{id}`
- `GET /v1/lineages/{id}`
- `GET /v1/dids/{did}`
- `POST /v1/tclk/inspect` — decode one tclk/1 frame line (read-only)
- `POST /v1/tclk/simulate` — fold a transcript at stated instants; no default clock
- `POST /v1/tclk/authorize` — authority for the room write, plus a dry-run approval check; never posts

Drafts:
- root
- recovery
- delegation
- revoke
- succession
- approval
- artifact
- task
- attestation
- fleet
- dispute

Evidence:
- `GET /v1/passports/{id}`
- `GET /v1/tasks/{id}`
- `GET /v1/artifacts/{id}`
- `GET /v1/impact/{id}`
- `POST /v1/router/search`

## CLI

Core:
- `la verify`
- `la verify-authority`
- `la check`
- `la lineage show`
- `la graph`

Draft:
- `la root draft`
- `la recovery draft`
- `la delegate draft`
- `la revoke draft`
- `la succession draft`
- `la approval draft`
- `la artifact draft`
- `la task draft`
- `la attest draft`

Signer:
- `la sign --key-ref ...`
Do not accept raw private seed as CLI arg.

Technocore:
- `la technocore inspect`
- `la technocore prepare`
- future `publish` must confirmation gate

## SDK

Python first:
- parse
- canonicalize
- event_id
- verify_event
- verify_authority
- verify_approval
- build_draft
- passport projection

TypeScript after stable test vectors.

## Error model

Machine-readable reason codes and human explanation.

Never return only boolean for complex verification.

## FLOP layer (application over LAP; D-108)

Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs. Every route and command below reads, computes and refuses; none
fetches a source, signs, spends or sends. `docs/FLOP_ACTIVITY_CONSOLE.md`,
`docs/FLOP_TESTNET_EXECUTOR.md`.

REST, mounted on `create_app` under `/v1/flop`:
- `GET /v1/flop/status` — phase, badge, `officialTestnetExecutable: false`, kill switch, counts, notices
- `GET /v1/flop/sources` — the official-source snapshot with each URL's classification
- `GET /v1/flop/rules` — every registered rule with source, hash and staleness (`RULE UPDATED`)
- `GET /v1/flop/activities?lineage=&did=[&at=]` — every record the read-only adapters found
- `GET /v1/flop/coverage?lineage=&did=[&at=]` — ten categories, five states, no total
- `GET /v1/flop/recommendations?lineage=&did=[&at=]` — rule-based items, `nextBestAction`, wash signals
- `GET /v1/flop/passport/{did}?lineage=[&at=]` — the whole projection
- `POST /v1/flop/safety/scan` — scan untrusted text; executes nothing, follows no URL
- `GET /v1/flop/testnet/state` — phase gate, registry (`executableCount: 0`), spend policy, signer, stages
- `GET /v1/flop/testnet/receipts/{id}` — one receipt from this process; a simulated one says so
- `POST /v1/flop/testnet/inference/quote` — a synthetic quote, `officialPricingAvailable: false`
- `POST /v1/flop/testnet/inference/prepare` — the exact action a person would approve; sends nothing
- `POST /v1/flop/testnet/inference/approve` — checks a receipt binds this action; consumes nothing
- `POST /v1/flop/testnet/inference/execute` — `409 {failure: TESTNET_NOT_LIVE, stage: phase, executed: false}` below `TESTNET_ENABLED`
- `POST /v1/flop/testnet/simulation/run` — the whole flow against `https://testnet.simulation.invalid`

Every `POST` body is `extra="forbid"`; `endpointId` is never accepted from a
client (422); a `POST` with a foreign `Origin` header is refused with 403 and
no CORS header is sent. Every response carries `notices` (affiliation,
seed-phrase warning, coverage label). Static: `GET /flop`, `/flop/app.css`,
`/flop/app.js`, `/flop/tokens.css`, `/flop/passport/{did}` (the same page).

Three inputs the client does not get to choose:

- The scan body has no `networkPhase` field (422) and refuses
  `sourceClass: "official"` (400). Both of those parameters make the scanner
  quieter, the phase is what this service observed, and official is decided by
  origin. When a rule is softened anyway -- a live phase, or an official class
  supplied in-process -- the suppression is reported as its own `CAUTION`
  finding rather than as silence.
- Every FLOP route, read included, checks the `Host` header against the set the
  router was built for (loopback by default, `allowed_hosts=` to override) and
  answers `421` otherwise. Without it the same-origin test compares `Origin`
  against a value derived from `Host`, which a DNS-rebinding page controls.
- `prepared` actions and receipts are held in memory, capped at 256 and dropped
  when they expire. An action id this process no longer holds comes back as
  `409 {failure: REPREPARE_REQUIRED}`.

`GET /v1/flop/status` and `/v1/flop/testnet/state` report
`networkWritesPerformed` from a counter (`networkWriteAccounting.measured:
true`) rather than as a constant, and `walletCustody` from the signer.

CLI, ASCII output only:
- `la flop status | sources | rules`
- `la flop testnet simulate --did … [--lineage … --bundle … --at …]`
- `la flop faucet prepare --did …` — unavailable / simulation output only
- `la flop inference quote | prepare | inspect`
- `la flop receipt verify`

There is no `la flop inference execute`. If one is added after activation it
must take an approved prepared-action id and nothing else.
