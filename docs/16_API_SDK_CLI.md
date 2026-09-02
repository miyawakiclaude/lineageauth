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
