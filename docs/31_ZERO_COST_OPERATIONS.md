# 31 — Zero-Cost Operations

## Objective

A developer/operator must be able to build, test, demonstrate, and initially publish LineageAuth without spending money.

## Mandatory operating modes

### `local`
No external infrastructure.

### `zero-cost-public`
Uses only currently verified free-tier infrastructure.

### `paid-scale`
Disabled by default and requires explicit human approval.

## Reference local setup

```text
Python 3.12
uv
SQLite
local event directory
FastAPI localhost
Next.js localhost
pytest / ruff / type checker
```

Expected infrastructure cost:
`¥0`

## Public deployment decision tree

1. Can feature be static?
   - yes -> static hosting / Pages-style free hosting
2. Does it need API compute?
   - use a free serverless request allowance only if current limits are verified
3. Does it need shared derived state?
   - use a verified free database tier only if needed
4. Does it need artifact bytes?
   - prefer hash-only receipts
   - host only necessary public artifacts
   - use free object allowance only when needed
5. Does it need search?
   - start with DB/full-text deterministic search
   - no paid vector DB
6. Does it need analytics?
   - local/basic provider free analytics only
   - no paid observability

## Services cost register

Maintain a table:

| Service | Purpose | Required? | Cost mode | Billing enabled | Free tier checked | Fallback |
|---|---|---:|---|---:|---|---|
| Local SQLite | Index | Yes | Free | No | N/A | N/A |
| GitHub | Source | Yes/public | Free | No | at use | local git |
| Pages provider | Explorer | Optional | Free | No | at deploy | localhost/static files |
| Serverless API | API | Optional | Free | No | at deploy | local API |
| Free DB | Shared index | Optional | Free | No | at deploy | SQLite/export |
| Object storage | Mirror | Optional | Free allowance | No | at deploy | local files/hash-only |

Claude Code updates this table when selecting infrastructure.

## Paid-service detector

During implementation review, search configuration/docs for:
- `pro`
- `enterprise`
- `pay-as-you-go`
- paid database SKU
- billing account
- custom domain purchase
- managed Redis
- paid observability
- paid vector DB
- paid LLM/API

Presence is not automatically wrong, but any active dependency on them in the zero-cost path is a blocker.

## Capacity philosophy

If adoption grows beyond free capacity, that is a success signal.

Do not prepay for hypothetical scale.

At that point produce:
- actual traffic/storage numbers
- bottleneck
- optimized zero-cost alternatives
- smallest paid option, if any
- estimated monthly cost

Then wait for human decision.

## Zero-cost definition of done

The following must work with no paid service:
- all schemas
- all core verification
- all conformance vectors
- CLI
- local API
- SQLite index/rebuild
- local Explorer
- Technocore dry-run
- MCP local tools
- A2A mapping tests
- evidence/work receipts
- passport projection
- local router
- task exchange demo
- jury demo
- fleet demo
- impact demo

A public hosted URL is useful but not required to prove protocol correctness.
