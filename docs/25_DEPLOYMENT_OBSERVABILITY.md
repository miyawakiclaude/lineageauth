# 25 — Deployment and Observability

## Budget invariant

Default deployment budget is:

`¥0 / month`

This section MUST be implemented under the ZERO-COST POLICY in the Claude contract.

Do not equate production-readiness with managed paid infrastructure.

## Tier 0 — Local authoritative reference

Required and always supported:

```text
Local machine
├─ Python verifier / API
├─ SQLite derived index
├─ immutable signed event directory
├─ local CLI
└─ local Explorer
```

Cost:
`¥0`

This tier must support the full protocol and all conformance tests.

## Tier 1 — Initial public zero-cost deployment

Only after checking current official free-tier rules.

Preferred candidate topology:

```text
GitHub public repo
      |
      +-> static docs / source
      |
      +-> Cloudflare Pages (Explorer candidate)
              |
              +-> Workers Free (small API candidate)
                      |
                      +-> D1 Free (derived index candidate)
                      |
                      +-> R2 Free allowance (optional immutable mirror)
```

Important:
- providers are replaceable
- no paid plan is required by protocol
- do not enable automatic billing upgrades
- if a provider free tier changes, choose another zero-cost path or fall back to local/read-only

## Tier 2 — Zero-cost degraded mode

When public free limits are reached:

1. stop background indexing
2. extend cache durations
3. disable nonessential analytics
4. disable optional router freshness sync
5. serve static/read-only Explorer where possible
6. keep local verifier/CLI fully operational
7. provide event export/import
8. report limit to human

Do not auto-upgrade.

## Tier 3 — Paid scale architecture

Documentation-only by default.

Possible future components:
- managed PostgreSQL
- Redis
- paid object storage
- managed search
- queues
- paid monitoring
- custom domain

These may be evaluated only after:
- real demand exists
- free path is insufficient
- human explicitly approves cost

No Tier 3 resource is part of the default implementation.

## Services

Minimum **functional** system:
- local core verifier
- local event store
- local SQLite index
- local Explorer

Minimum **public** zero-cost candidate:
- static Explorer
- small API if needed
- free derived DB if needed

Router/search and background sync are optional.

## Secret separation

Public API/indexer should need no root private key.

Deployment secrets:
- DB credentials if any
- object store credentials if any
- service auth if any

Never deploy root/recovery/operational private signing keys to generic public infrastructure.

## Cost manifest

Create `docs/31_ZERO_COST_OPERATIONS.md`.

When infra files are added, create:

`infra/cost-policy.yaml`

Required default:

```yaml
budget_mode: zero_cost
monthly_spend_limit_jpy: 0
allow_paid_services: false
allow_automatic_upgrades: false
allow_domain_purchase: false
on_free_limit_exceeded: stop_or_degrade
```

## Metrics — zero-cost first

Collect only what can be gathered without paid observability.

Local/API logs + simple counters:
- event ingest rate
- invalid signature count
- resolver conflict count
- stale resolver count
- verify latency
- router latency
- API error count
- task spam rate
- approval replay rejection count

Do not introduce paid telemetry only for dashboards.

## Logs

Do not log secrets/tokens.

Public DIDs/event IDs are acceptable only after privacy review.

## Backups

Zero-cost backup strategy:
- signed event files are portable
- repository contains schemas/spec/tests, not secrets
- export SQLite projections
- rebuild from immutable events
- local/offline copy when necessary

Cloud object replication is optional, not mandatory.

## Disaster recovery

Test:
- empty DB
- rebuild from events
- compare projections/checksums
- restore on a clean local machine without paid services

## Free-limit shutdown

Every hosted component must document:
- free limit assumption
- what happens when exceeded
- whether requests fail
- whether data remains exportable
- how to return to local operation

The correct response to a free-tier limit is controlled degradation, not silent spending.
