# LineageAuth

[![CI](https://github.com/miyawakiclaude/lineageauth/actions/workflows/ci.yml/badge.svg)](https://github.com/miyawakiclaude/lineageauth/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

**Portable authority and evidence infrastructure for autonomous agents.**

Protocol family: **LAP — Lineage Authority Protocol**
Status: **pre-alpha, protocol version `0.1`** — schemas and semantics will change.

---

## What problem this addresses

Agent tooling can usually answer *"which key signed this?"*. That is rarely the
question that matters when an agent is about to do something consequential. The
question is:

> Who authorized this agent, for what scope, under which constraints? Is that
> authority still current? Did a human approve this exact action? And what
> verifiable evidence did the action produce?

LineageAuth is a layer that carries those answers with the agent, as signed
objects anyone can check offline.

## What it is not

LineageAuth **does not** prove a human's identity, legal entity status, company
affiliation, honesty, or competence. A valid `did:key` proves control of the
matching private key — nothing more. The verifier never reports "trusted"; it
reports a specific reason code such as `VALID_AUTHORITY_CHAIN`, `REVOKED`,
`SUPERSEDED`, `APPROVAL_REQUIRED`, or `CONFLICTED`.

It also **does not** replace OAuth, API keys, repository permissions, MCP server
authorization, or A2A server policy. It is additive provenance, never a bypass.

The core holds **no wallet keys, transfers no tokens, escrows nothing**, and
makes no claim about anyone's eligibility for anything. See
[docs/28_NON_GOALS_LIMITATIONS.md](docs/28_NON_GOALS_LIMITATIONS.md).

## Design commitments

| Commitment | Where |
|---|---|
| The signed event is the source of truth — never a server, index, or cache | [D-001](docs/29_DECISIONS.md) |
| Verification runs offline: no network, no database, no private keys | [docs/01](docs/01_SYSTEM_ARCHITECTURE.md) |
| Deny by default; authority only attenuates down a chain | [D-005, D-006](docs/29_DECISIONS.md) |
| Human approval binds one exact action, and never creates missing authority | [D-009, D-010](docs/29_DECISIONS.md) |
| Ambiguous competing roots fail closed as `CONFLICTED` | [D-008](docs/29_DECISIONS.md) |
| RFC 8785 JCS + SHA-256 + Ed25519, no home-grown crypto or canonical JSON | [D-002 – D-004](docs/29_DECISIONS.md) |
| Everything runs at ¥0 — no paid service is required for correctness | [docs/31](docs/31_ZERO_COST_OPERATIONS.md) |

## Cryptographic core

```text
preimage  =  b"lineageauth:event:v1\n" + JCS(payload)
event id  =  "sha256:" + lowercase_hex( SHA-256(preimage) )
proof     =  { "alg": "Ed25519", "signer": "did:key:z6Mk…", "sig": <base64url, unpadded> }
envelope  =  { "payload": { … }, "proofs": [ proof, … ] }
```

Proofs sit outside the payload, so one payload can carry several signatures —
which is what a recovery quorum needs.

## Quick start

Requires Python 3.12+. No paid service, no account, no network.

```bash
uv sync --extra dev
```

```bash
uv run la verify examples/root-create.json
```

```bash
uv run la check examples/delegation-allowed.json --agent did:key:z6MkqFRbThS1M62TP7pUYo8DGxizE5TD66mbf6vXh6kmyE6X --namespace technocore --resource room:lobby --action write
```

```bash
uv run pytest
```

## Repository layout

```text
CLAUDE.md          implementation contract — authoritative for coding agents
MASTER_PLAN.md     phase map, phase 0 → 15
TASKS.md           execution board
docs/00…32         the specification, one document per concern
spec/              the single-file master specification
packages/py/       Python reference implementation
tests/             unit, property, and conformance vectors
infra/             cost policy (budget invariant: ¥0)
```

Start with [START_HERE.md](START_HERE.md).

## Implementation status

Phase 1 (lineage) is in progress. Nothing here is production-ready; do not put
real authority behind it yet.

- [x] RFC 8785 canonicalization, signing preimage, event ids
- [x] Ed25519 `did:key` encode/decode, strict and canonical
- [x] Envelope model, strict JSON loading, strict RFC3339 UTC
- [x] Event integrity verification with reason codes — `la verify`
- [x] Root creation, recovery policy, succession, epoch resolution — `la lineage show`
- [x] Delegation, attenuation, revocation, authority resolver — `la check`
- [x] Exact-action human approval and replay protection — `check_execution`
- [x] Event store, rebuildable SQLite index, and a read-and-verify REST API
- [x] Evidence — artifacts, signed authorship receipts, attestations
- [x] Useful work — task lifecycle, derived state, anti-gaming signals
- [x] Fleet transparency — voluntary disclosure that never costs the discloser
- [x] Router — discovery by capability, authority, evidence, and availability
- [x] Task exchange — competing claims stay competing, and a blocklist
      hides without deleting
- [x] Impact graph — signed downstream use, counted by distinct key rather
      than by edge, with no score attached
- [x] Agent passport — four claim categories, deliberately never merged
- [x] Disputes — a stated procedure, a derived outcome, and an undecided
      case when the jury splits
- [x] MCP adapter — tools for verification, authority, and unsigned drafts
- [x] A2A adapter — a data-only agent-card extension that can never be
      marked required, and never fetches the resolver it reads
- [x] Technocore adapter — GET-write classification, single-line sweep,
      dry-run write preparation. It cannot publish.
- [ ] Everything after that — see [MASTER_PLAN.md](MASTER_PLAN.md)

## Contributing

The most useful contribution right now is an **independent implementation that
disagrees with this one**. If your verifier reaches a different verdict on the
same event bundle, that is a finding worth an issue.

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: don't hand-roll
crypto or canonical JSON, fail closed, never commit key material, and record
protocol decisions in [docs/29_DECISIONS.md](docs/29_DECISIONS.md).

## Security

Never put a real private seed in a prompt, an issue, a fixture, a log, or this
repository. Test vectors use disposable deterministic keys, labelled as unsafe
test material.

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). The working
threat model is [docs/22_SECURITY.md](docs/22_SECURITY.md).

## License

[Apache-2.0](LICENSE).
