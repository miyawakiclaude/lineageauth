# MASTER PLAN — From Empty Repository to Final Agent Authority Network

## Product thesis

Agent ecosystems need more than authentication.

They need portable proof of:
- lineage
- delegated authority
- current root
- recovery state
- exact human approval
- produced evidence
- useful work
- downstream impact

LineageAuth starts as a minimal cryptographic authority protocol and evolves into an **Agent Authority + Evidence Network**.

## Phase map

### Phase 0 — Foundation
Repo, tooling, CI, schemas, docs discipline.

### Phase 1 — Core Lineage
`root.create`, recovery policy, succession, epoch.

### Phase 2 — Delegation
Scopes, grants, attenuation, revocation, verifier.

### Phase 3 — Human Approval
Exact-action receipts and replay protection.

### Phase 4 — Resolver / Explorer
Immutable event store, indexer, graph explorer.

### Phase 5 — Technocore
Safe read adapter, dry-run write preparation, authority demo.

### Phase 6 — MCP / A2A
Authority verification extension layers.

### Phase 7 — Evidence
Artifact receipts, attestations, content-addressed evidence.

### Phase 8 — Useful Work
Task/work receipts: request -> claim -> result -> verify.

### Phase 9 — Agent Passport
Portable evidence-first public profile.

### Phase 10 — Router
Search agents by skill/capability/authority/evidence/availability.

### Phase 11 — Task Exchange
Networked task coordination.

### Phase 12 — Jury
Dispute and multi-verifier verdict protocol.

### Phase 13 — Fleet
Voluntary shared-operator graph.

### Phase 14 — Impact
Reuse, improvement and downstream effect graph.

### Phase 15 — Production hardening
Transparency, freshness, deployment, migration, observability, abuse defense.

## Architecture evolution

```text
PHASE 1-3
Identity -> Authority -> Approval

PHASE 4-7
Identity -> Authority -> Approval -> Action -> Evidence

PHASE 8-10
Task -> Agent -> Authority -> Work -> Evidence -> Passport -> Discovery

PHASE 11-14
Task Exchange -> Jury -> Fleet -> Impact Graph

FINAL
Cross-protocol Agent Authority + Evidence Network
```

## Final network objects

- Lineage
- DID
- Root epoch
- Recovery policy
- Delegation
- Revocation
- Succession
- Approval receipt
- Artifact
- Artifact receipt
- Task
- Claim
- Result
- Verification
- Attestation
- Useful-work receipt
- Passport projection
- Availability statement
- Fleet binding
- Jury case
- Verdict
- Impact edge

## Core invariants

1. Signed object is authoritative, not server DB.
2. Every authority path terminates at current valid lineage root.
3. Authority monotonically attenuates down a chain.
4. Higher valid recovery epoch supersedes lower current authority.
5. Human approval never creates missing underlying authority.
6. Evidence hashes content; it does not guarantee truth.
7. Attestations prove who signed an assessment, not that the assessment is correct.
8. Passport is a projection of evidence, not a centralized identity truth.
9. Router rankings must be explainable.
10. Fleet is voluntary operator disclosure, not Sybil-proofing.
11. No crypto wallet dependency in protocol core.
12. Technocore remains transport/discovery, not source of truth.
