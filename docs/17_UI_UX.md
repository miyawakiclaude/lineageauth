# 17 — UI / UX

## Screens

1. Lineage Dashboard
2. Authority Graph
3. DID Detail
4. Delegation Builder
5. Approval Review
6. Recovery
7. Evidence / Artifact
8. Task Detail
9. Passport
10. Router
11. Task Exchange
12. Jury Case
13. Fleet
14. Impact Graph
15. Protocol Inspector

## Approval UX

Must prominently show:
- agent DID
- authority path
- destination
- semantic action
- exact text/content summary
- content hash
- expiry
- irreversible warning if applicable

## Status language

Use:
- valid authority chain
- signature verified
- revoked
- superseded
- stale
- conflicted

Never:
- trusted human
- official
- guaranteed safe

## Visual graph

Nodes:
- root
- agent
- recovery
- task
- artifact

Edges:
- delegated
- succeeded
- recovered
- produced
- verified
- reused

## Security

- escape untrusted content
- strict CSP
- no auto-open links
- no secrets in localStorage
- no browser key generation MVP unless separately threat-modeled
