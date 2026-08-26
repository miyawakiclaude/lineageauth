# 01 — System Architecture

## Layers

```text
Local/offline trust boundary
  Root Signer
  Recovery Signers
  Operational Signer

Protocol core
  Canonicalization
  Hashing
  Signature verification
  Event schemas
  Authority resolver
  Approval verifier
  Evidence verifier

Derived infrastructure
  Immutable object store
  Indexer
  Resolver
  Search
  Passport projection
  Router

Interaction layers
  CLI
  SDK
  REST API
  Explorer
  MCP
  A2A
  Technocore

Coordination layers
  Task Exchange
  Jury
  Fleet
  Impact Graph
```

## Monorepo proposal

```text
/
  CLAUDE.md
  apps/
    api/
    explorer/
  packages/
    py/lineageauth/
    ts/lineageauth/
    mcp/
    a2a/
  services/
    indexer/
    router/
  integrations/
    technocore/
  schemas/
  spec/
  examples/
  tests/
  infra/
```

Python is reference verifier first. TypeScript verifier can follow after vectors stabilize.

## Trust boundaries

Authoritative:
- signed valid protocol event
- cryptographic proof under protocol rules

Non-authoritative:
- index
- cache
- search rank
- room/topic/note
- display name
- social post
- discovery URL

## Offline verification

Verifier accepts a bundle:
- events
- target action
- verification timestamp
- optional approval
and returns result without network.

Online resolvers only collect bundles.

## Storage

Immutable signed events are content-addressed.

Indexer DB is reconstructible.

Search indexes are projections.

## Failure behavior

Authority failures fail closed.

Evidence queries may return “unknown/incomplete” instead of negative claims when sources are incomplete.
