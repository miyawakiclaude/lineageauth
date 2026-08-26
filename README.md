# LineageAuth

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
- [ ] Root creation, recovery policy, succession, epoch resolution
- [ ] Delegation, attenuation, revocation, authority resolver
- [ ] Exact-action human approval and replay protection
- [ ] Everything after that — see [MASTER_PLAN.md](MASTER_PLAN.md)

## Security

Never put a real private seed in a prompt, an issue, a fixture, a log, or this
repository. Test vectors use disposable deterministic keys, labelled as unsafe
test material. See [docs/22_SECURITY.md](docs/22_SECURITY.md).

## License

Apache-2.0.
