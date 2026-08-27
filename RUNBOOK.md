# Runbook — the whole thing, locally, for ¥0

Everything below runs on one machine with no account, no API key, no hosted
service and no network. That is not a convenience claim, it is the point:
`docs/22_SECURITY.md` requires that verifying an event, resolving a lineage and
checking a permission all work offline, so that a verifier is never something
you have to be online — or solvent — to be.

The claim is also checked rather than asserted. `tests/test_zero_cost.py`
executes the "zero-cost definition of done" from
[`docs/31_ZERO_COST_OPERATIONS.md`](docs/31_ZERO_COST_OPERATIONS.md) item by
item, and names what is not built yet instead of quietly passing.

## Setup

```bash
py -3 -m uv sync --all-extras
```

`uv` installs into `.venv/`. The optional extras (`api`, `mcp`) are installed
here for convenience; nothing in the sections below except **Local API** and
**MCP** needs them, and a test enforces that.

## The gate

Four commands. Run all four before every commit — `ruff check` passing is not
the same as `ruff format --check` passing, and CI checks both.

```bash
py -3 -m uv run ruff check .
```

```bash
py -3 -m uv run ruff format --check .
```

```bash
py -3 -m uv run mypy
```

```bash
py -3 -m uv run pytest
```

## Verify an event

```bash
py -3 -m uv run la verify examples/root-create.json
```

`examples/tampered-root-create.json` is the negative control and must fail. If
it ever passes, stop and do not trust anything else in this file.

## Resolve a lineage

```bash
py -3 -m uv run la lineage show examples/root-succession-recovery.json
```

## Check a permission

```bash
py -3 -m uv run la check examples/delegation-allowed.json --agent did:key:z6MkqFRbThS1M62TP7pUYo8DGxizE5TD66mbf6vXh6kmyE6X --namespace technocore --resource room:lobby --action write
```

`examples/delegation-revoked.json` carries the same grant plus its revocation,
and must come back denied.

## Build and inspect the index

Events enter through the store, and only through the store. There is no HTTP
path that can add one:

```bash
py -3 -m uv run la index add ./events examples/root-create.json examples/delegation-allowed.json
```

Adding the same event twice is a no-op -- the store is content-addressed, so
the two files above contribute three envelopes and two events.

The index is derived. Deleting it loses nothing, which is the property worth
checking:

```bash
py -3 -m uv run la index rebuild ./events --db ./index.sqlite3
```

```bash
py -3 -m uv run la index stat --db ./index.sqlite3
```

`rebuild` runs in a single transaction, so a concurrent reader never sees an
index that has lost a revocation halfway through.

## Local API (optional extra)

```bash
py -3 -m uv run uvicorn lineageauth.api:create_app --factory --port 8000
```

Read-only. It accepts no events over HTTP and holds no keys — `GET /v1/meta`
says both, in the response, on purpose.

## Regenerate the published examples

```bash
py -3 -m uv run python scripts/generate_examples.py
```

Deterministic: run it twice and `git status` stays clean. If it does not, the
canonicalization changed and that is a protocol-level event, not a formatting
one.

## Windows notes

The Japanese console (`cp932`) cannot print every character Python can produce.
`la --help` used to crash there because of a single em dash in the help text.
Fixed, and pinned by a test that runs the CLI under `PYTHONIOENCODING=cp932`.

If a *new* command ever fails the same way:

```bash
PYTHONIOENCODING=utf-8 py -3 -m uv run la --help
```

That works around it; the fix is to keep non-ASCII out of anything the CLI
prints.

PowerShell 5.1 has no `&&`. Run one command per line.

## What costs money

Nothing above. The register in
[`infra/cost-policy.yaml`](infra/cost-policy.yaml) records
`monthly_spend_limit_jpy: 0`, `allow_paid_services: false` and
`on_free_limit_exceeded: stop_or_degrade`, and a test asserts all three are
still there.

Public hosting is **not required to prove the protocol works** — `docs/31` says
so explicitly, and the definition-of-done list contains no hosted service. The
trigger for spending anything is narrow: somebody outside needs to verify
without cloning this repository, *and* a static file cannot answer them. A
passport and an event bundle are both static JSON, so the first half of that is
usually solved by a file. See the notes beside `candidates_not_selected` in the
cost policy for the checked free-tier numbers and the one real constraint
(Cloudflare Workers allow 10 ms CPU per request on the free plan, which
Ed25519 verification over a whole bundle has not been measured against).

Anything paid needs a human decision recorded in
[`docs/29_DECISIONS.md`](docs/29_DECISIONS.md) first.
