# 04 — Scope and Authorization Semantics

## Scope tuple

```json
{
  "namespace": "technocore",
  "resource": "room:lobby",
  "actions": ["write"]
}
```

## Default

No grant = DENY.

## Core matching

A request is authorized only if at least one complete valid chain covers:
- namespace
- resource
- action
- time
- delegation constraints

## Wildcards

MVP wildcards only at explicitly supported suffix positions.

Examples:
- `room:*`
- `repo:owner/*`

Never use arbitrary regex from untrusted events.

## Attenuation

Child must be subset.

### Actions
Child actions ⊆ parent actions.

### Resource
Child resource must be equal/narrower under namespace-specific containment.

### Time
Child:
- notBefore >= parent
- expiresAt <= parent

### Delegation depth
If parent allows depth N, child delegation consumes one level.

### Human approval
Constraint monotonicity:

`none < external-only < required`

A child can strengthen but never weaken.

### Designated approvers
A grant whose `approval` is anything but `none` must carry `approvers`: the
did:key values entitled to sign a receipt for an action it authorizes. A grant
that demands approval and names nobody is refused (D-107, fail closed).

`approvers` attenuates like everything else: a child may only name a subset of
its parent's. A parent that names nobody (and so needs no approval) constrains
nothing, and a child may introduce a list when it strengthens `approval`.

Nobody is entitled by position. Neither the root nor an issuer on the path may
approve unless a grant names them. The agent is never entitled, named or not.

## Namespaces

### Technocore
Resources:
- `room:<name>`
- `room:*`
- `note:<namespace>/<key>`
- `owned-room:<name>`

Actions:
- read
- write
- create
- claim
- allow

### MCP
Resources:
- `server:<id>`
- `server:<id>/tool:<tool>`

Actions:
- discover
- invoke

### A2A
Resources:
- `agent:<id>`
- `skill:<id>`

Actions:
- discover
- message
- invoke
- task

### GitHub
Resources:
- `repo:<owner>/<repo>`
- future issue/pr subresources

Actions:
- read
- issue.create
- issue.comment
- pr.create
- pr.comment
- commit
- merge

### HTTP
Resources:
- `host:<hostname>`
- future path constraints

Actions:
- get
- post
- put
- patch
- delete

## Provider auth

LineageAuth authority NEVER bypasses:
- OAuth
- API key
- repository permission
- A2A server policy
- MCP server authorization

It only supplies additional provenance/policy evidence.

## Authorization response

Must explain:
- result
- current root/epoch
- matched path
- active grant IDs
- warnings
- approval requirement
- reason code
