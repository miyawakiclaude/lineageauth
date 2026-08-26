# 30 — Final Roadmap and Phase Gates

## Phase 0 — Foundation
Deliver:
- repo
- CI
- lint/type/test
- schemas
Gate:
- clean local build

## Phase 1 — Lineage
Deliver:
- root.create
- recovery.policy
- root.succession
Gate:
- deterministic root/epoch verification

## Phase 2 — Authority
Deliver:
- grant/revoke
- scopes
- attenuation
Gate:
- explainable ALLOW/DENY

## Phase 3 — Approval
Deliver:
- exact approval
- replay
Gate:
- safe execution decision

## Phase 4 — Resolver/Explorer
Deliver:
- event store
- indexer
- API
- graph
Gate:
- DB rebuild and read UI

## Phase 5 — Technocore
Deliver:
- read
- dry-run prepare
- mock
Gate:
- zero unapproved live writes

## Phase 6 — MCP/A2A
Deliver:
- MCP verify/build tools
- A2A extension mapping
Gate:
- native authorization still enforced

## Phase 7 — Evidence
Deliver:
- artifacts
- attestations
Gate:
- portable evidence bundle

## Phase 8 — Useful Work
Deliver:
- task lifecycle
- work receipt
Gate:
- accepted work appears as evidence

## Phase 9 — Passport
Deliver:
- projection
- claim/evidence separation
Gate:
- public verifiable passport

## Phase 10 — Router
Deliver:
- search
- explainable ranking
Gate:
- skill+authority+evidence queries

## Phase 11 — Task Exchange
Deliver:
- coordination service
- state derivation
Gate:
- multiple independent agents complete tasks

## Phase 12 — Jury
Deliver:
- dispute/vote/verdict
Gate:
- contested result resolved with signed evidence

## Phase 13 — Fleet
Deliver:
- bind/unbind
- independence signals
Gate:
- shared operator relationships visible

## Phase 14 — Impact
Deliver:
- reuse/improve graph
Gate:
- downstream evidence visible

## Phase 15 — Production
Deliver:
- multi-source freshness
- **zero-cost reference deployment**
- controlled free-tier degradation behavior
- deployment
- observability without paid dependency
- migration
- security hardening
- conformance vectors
- optional paid-scale architecture documentation only

Gate:
- reproducible production deployment and independent implementation compatibility
- full local/reference operation at ¥0
- no paid infrastructure required for core functionality
- no automatic billing/upgrade path

## Final acceptance

The product is “final v1 architecture complete” only when:
- all phase gates pass
- spec is versioned
- Python reference verifier exists
- conformance vectors exist
- no private-key server dependency
- external writes have safety boundaries
- Technocore/MCP/A2A adapters are current
- Passport/Router do not overclaim identity/trust
- useful-work evidence is independently verifiable
- DB can rebuild from events
- recovery conflict behavior is tested
- third-party adoption is possible without project operator custody
- zero-cost local/reference operation is fully supported
- paid services are optional and require explicit approval
- repository/account ownership is isolated from company RPO development
- intended personal Git/GitHub owner is `miyawakiclaude`
