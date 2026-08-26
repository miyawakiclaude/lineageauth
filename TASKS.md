# TASKS — Final Development Board

Claude Code must maintain this file.

**Current phase:** P1 Lineage (in progress).
**Last updated:** 2026-08-26.

Local checks, all passing at ¥0:

```bash
uv run pytest && uv run ruff check . && uv run mypy
```

## P0 Foundation
- [x] verify repository is outside company RPO repository
      — repo root `~/dev/lineageauth`, outside OneDrive and outside any company tree
- [~] verify intended personal account is `miyawakiclaude`
      — repo-local `user.name` set; the GitHub account itself is unverified
        because `gh` is not installed and no remote exists yet
- [x] add repository-local Git identity guidance without inventing email
      — see START_HERE.md; `user.email` deliberately left unset, so the first
        commit is blocked until the human supplies a personal address
- [ ] add pre-push personal-account safety check
      — deferred until a remote exists; must check account, owner, remote, branch
- [ ] add company contamination/release scan
      — CI scans for private key material; the contamination scan
        (company org names, internal domains, RPO paths) is still to be written
- [x] monorepo scaffold
- [x] Python 3.12 uv project
- [x] lint/type/test — ruff, mypy (strict), pytest, hypothesis
- [x] CI — `.github/workflows/ci.yml`, free on public repos (verified 2026-08-26)
- [x] secret-safe gitignore
- [x] package boundaries
- [ ] schema generation pipeline — JSON Schema emission from the event models

## P1 Lineage
- [x] JCS — RFC 8785 via the `rfc8785` library, never hand-rolled
- [x] event preimage — `b"lineageauth:event:v1" + LF + JCS(payload)`
- [x] event ID — `sha256:<64 lowercase hex>`, golden vectors computed externally
- [x] did:key Ed25519 parser — canonical-only, rejects DID URLs and other codecs
- [x] signature verify — per-proof results with reason codes, offline
- [x] root.create — draft builder + lineage derivation (D-025, D-026)
- [x] recovery.policy — draft builder, distinct members, ordered replacement
- [x] succession — draft builder, normal and recovery modes
- [x] epoch — `bundle.py` (admission) + `lineage.py` (`resolve_lineage`).
      `at` takes no part in the decision (D-033); duplicate event copies merge
      by union of verified signers (D-036)
- [x] conflict status — competing successions, unorderable policies, and forked
      policy chains all report `CONFLICTED` and fail closed. Never tie-broken
      by `issuedAt`; regression-guarded
- [x] CLI — `la lineage show BUNDLE [--lineage] [--at] [--json]`
- [~] vectors — 5 deterministic examples published; the full conformance
      package (query + expected result + evidence path) is still to come

## P2 Authority
- [ ] scope types
- [ ] Technocore containment
- [ ] MCP containment
- [ ] A2A containment
- [ ] GitHub placeholder
- [ ] HTTP placeholder
- [ ] delegation grant
- [ ] attenuation
- [ ] delegation depth
- [ ] revoke
- [ ] path resolver
- [ ] reason codes
- [ ] property tests

## P3 Approval
- [ ] canonical action descriptor
- [ ] content/request hash
- [ ] destination binding
- [ ] nonce
- [ ] expiry
- [ ] approver authority
- [ ] spent store
- [ ] atomic reserve
- [ ] TOCTOU recheck
- [ ] tests

## P4 Resolver/Explorer
- [ ] immutable event store abstraction
- [ ] SQLite index
- [ ] Postgres schema
- [ ] rebuild
- [ ] REST verify
- [ ] REST read
- [ ] graph projection
- [ ] Next.js explorer
- [ ] security headers
- [ ] no key storage

## P5 Technocore
- [ ] re-read official latest docs
- [ ] read-only client
- [ ] semantic endpoint table
- [ ] dry-run write builder
- [ ] announcement formatter
- [ ] confirmation boundary
- [ ] mock transport
- [ ] no live writes tests

## P6 MCP/A2A
- [ ] verify latest MCP spec
- [ ] MCP server package
- [ ] verify/check tools
- [ ] draft tools
- [ ] latest A2A mapping
- [ ] namespaced extension
- [ ] native auth coexistence tests

## P7 Evidence
- [ ] artifact.register
- [ ] artifact.receipt
- [ ] attestation
- [ ] private artifact hash-only support
- [ ] evidence bundle
- [ ] tests

## P8 Useful Work
- [ ] task.request
- [ ] task.claim
- [ ] release
- [ ] result
- [ ] verify
- [ ] work.receipt
- [ ] derived state machine
- [ ] anti-gaming signals
- [ ] tests

## P9 Passport
- [ ] profile statement
- [ ] skill claim
- [ ] claim/evidence categories
- [ ] passport projection
- [ ] passport API
- [ ] passport UI

## P10 Router
- [ ] query schema
- [ ] skill index
- [ ] authority index
- [ ] availability
- [ ] explainable ranking v1
- [ ] fleet independence signals
- [ ] search API
- [ ] search UI

## P11 Task Exchange
- [ ] task registry
- [ ] claim coordinator
- [ ] task states
- [ ] moderation
- [ ] API/UI
- [ ] independent-agent test

## P12 Jury
- [ ] dispute
- [ ] juror nomination/selection mode
- [ ] conflict disclosure
- [ ] vote
- [ ] verdict
- [ ] UI
- [ ] tests

## P13 Fleet
- [ ] fleet.create
- [ ] bind
- [ ] unbind
- [ ] graph
- [ ] router integration
- [ ] clear limitations

## P14 Impact
- [ ] reuse event
- [ ] improve event
- [ ] impact edges
- [ ] independent impact summary
- [ ] fraud heuristics presentation
- [ ] impact UI

## P15 Production
- [ ] zero-cost deployment architecture
- [ ] `docs/31_ZERO_COST_OPERATIONS.md`
- [ ] `infra/cost-policy.yaml`
- [ ] free-limit stop/degrade behavior
- [ ] verify no automatic paid upgrades
- [ ] local full-stack ¥0 runbook
- [ ] multi-source resolver
- [ ] freshness policy
- [ ] conflict monitoring
- [ ] deployment
- [ ] optional PostgreSQL scale design (do not provision if paid)
- [ ] optional object storage design (do not provision if paid)
- [ ] observability
- [ ] backup/rebuild drill
- [ ] dependency audit
- [ ] fuzz
- [ ] conformance package
- [ ] version/migration docs
- [ ] v1 release checklist

## Final gate
- [ ] repository is owned/targeted by personal account `miyawakiclaude`
- [ ] no company RPO remote/account is used for writes
- [ ] no company secrets/code/customer data are present
- [ ] no company cloud/billing environment is required
- [ ] complete local/reference system runs at ¥0
- [ ] no paid service is required by default
- [ ] no billing/automatic upgrade is enabled
- [ ] all selected hosted free tiers were re-verified before deployment
- [ ] all protocol tests pass
- [ ] property tests pass
- [ ] conformance vectors publishable
- [ ] no secrets
- [ ] no unapproved external side effect
- [ ] DB rebuild validated
- [ ] recovery conflicts tested
- [ ] exact approval demo
- [ ] useful-work demo
- [ ] passport/router demo
- [ ] Technocore adapter safe
- [ ] MCP current
- [ ] A2A current
- [ ] README/security/limitations complete
