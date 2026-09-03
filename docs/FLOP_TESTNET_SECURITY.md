# FLOP testnet security

The threat model for the testnet executor, and what each threat runs into.
Companion to `docs/FLOP_TESTNET_EXECUTOR.md` and `docs/22_SECURITY.md`.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** Wallet custody introduced: **no**. External FLOP writes performed:
**none**. Network writes possible in the current phase: **none**, by
construction rather than by policy.

## Assets

- The operator's authority: the delegation chain and the approver's key.
- Test FLOP, once it exists. No monetary value is assumed, but a wash pattern
  or a runaway loop would still cost the operator's standing.
- The operator's secrets — which this process must never hold.
- The evidence record: receipts, drafts and the audit chain, whose value is
  that they were not fabricated by a prompt.

## Why a live write is impossible in `PRE_TESTNET`

Five independent guards. Any one of them alone stops the write; none of them
trusts another.

1. **The registry has no executable entry.** `FlopEndpoint.executable` is a
   derived property requiring an official origin, a `verifiedAt` and
   `enabled`, and the constructor raises on an executable entry from a
   non-official origin. `executable_entries` is empty; a test pins the count.
2. **The executor's client is a required argument.** `ExecutorContext` has no
   default transport and no lazily built one (D-089: no default that turns the
   guard off). Forgetting to choose one is a `TypeError`, not a connection.
3. **The phase gate is stage 1 of 9.** `gate.refusal()` returns
   `TESTNET_NOT_LIVE` before the executor reads anything else, and the
   transport is consulted only at stage 9. Test O asserts zero transport calls
   across all four non-live phases with a counting transport.
4. **No egress library exists in the package.** `tests/test_flop_testnet_phase.py`
   walks the AST of `flop/**` and fails on any import or call of `socket`,
   `httpx`, `requests`, `aiohttp`, `urllib.request`, `subprocess`, `eval` or
   `exec`. `urllib.parse` alone is allowed: it is a string parser and cannot
   open a socket (the reason `tests/test_zero_cost.py` narrowed its ban).
5. **The transition table has no `PRE_TESTNET → TESTNET_ENABLED` edge**, and
   the kill switch is locked ON below `TESTNET_VERIFIED`. Reaching a live
   phase takes an official snapshot, a checklist and a person.

The simulation's destination, `https://testnet.simulation.invalid`, is a sixth:
RFC 6761 reserves `.invalid` so that even a transport with a bug has nowhere
to send a packet.

## Threats and where they stop

| Threat | Stops at |
|---|---|
| A room post publishes a "testnet faucet" URL | `classify_source` → `community` or `suspicious` by origin; registry disposition `READABLE_IF_SAFE`/`BLOCKED`, never executable (test B) |
| A convincing lookalike (`fl0p.finance`, `flop-finance.com`, `flop.finance.x.example`) | `suspicious`; scanner `url.lookalike` HIGH_RISK |
| A prompt says "use endpoint X" or "raise maxSpend" | the workload cannot reach the control plane: `build_plan` has no prompt parameter, `assemble_request` copies fields from an allowlist, and the executed destination is the plan's (test H) |
| A prompt asks for a seed phrase | scanner `secret.seed-phrase` → `BLOCKED` at prepare; `SUSPICIOUS_CONTENT` (test I) |
| A prepared action claims `simulation: true` to skip the phase gate | the executor checks the registry's entry, not the claim; mismatch is `REQUEST_INVALID` at stage 3 |
| An approval is reused for a second execution | `check_execution(reserve=True)` spends the receipt; the re-run is `APPROVAL_MISMATCH` with the wash wording (test K) |
| One byte of the request changes after approval | `requestHash` covers the canonical bytes, including `control.maxSpend`; the approval no longer binds (test E) |
| An approver who is not on the grant's `approvers` | `check_execution` refuses (D-107, test C) |
| A grant with `approval: none` | still `APPROVAL_MISSING` — FLOP spend always needs a receipt |
| The official source changes between prepare and execute | snapshot and rule-set fingerprints are in the plan; `REPREPARE_REQUIRED` (test N) |
| A quote expires | `QUOTE_EXPIRED` (test G) |
| A quote above the approved ceiling | `SPEND_LIMIT_EXCEEDED` (test F) |
| A response redirects to another origin | the client never follows; a transport that did is caught by `final_url` and re-classified; `ENDPOINT_BLOCKED` (test J) |
| An oversized or slow response | the cap and timeout travel inside `TransportRequest`; the transport cannot be handed a request without them |
| A response with no receipt reference | `partially-verified`, reasons listed (test L) |
| Secret material in a request, response or log | `client.redact` on the way in: sensitive headers wholesale, seed-like values to end of line; audit drops secret-named keys entirely |
| A signer that holds a key | none exists: `NoSigner` only; an AST test asserts no parameter named like a seed, key, keyfile or passphrase anywhere in `flop/**`, and no import of `lineageauth.crypto` |
| A scheduled or retried farming loop | no scheduler, no retry of a state-mutating action, `APPROVAL_MISMATCH` on repeat; `wash.py` flags churn |
| A page on another origin drives the local API | `POST` with a foreign `Origin` header → 403; no CORS header is sent |
| Synthetic evidence mistaken for real | `synthetic: true` + banner on the wrapper and `reasonCode: SYNTHETIC_SIMULATION_NO_NETWORK_ACTION` in the attestation itself (test M) |

## Secrets policy

- This process never takes a seed, private key, keyfile path or passphrase.
  The absence is a property of the parameter lists, checked by a test that
  reads the syntax tree.
- `LocalSigner` from `lineageauth.crypto` is not wired in. It holds a seed in
  memory, which is right for signing one's own lineage events in a CLI and
  wrong for a long-lived web process that also talks to a network.
- Tests use only `tests/testkeys.py` unsafe keys. `scripts/pre_push_check.py`
  scans for bare 64-hex strings; every hash in the FLOP fixtures carries a
  `sha256:` prefix.
- The audit log is append-only JSONL with a hash chain. It records that
  something happened, never what a secret was, and it drops rather than masks.

## Prompt injection

Two layers, neither trusting the other. The scanner (`docs/FLOP_SAFETY.md`)
labels and can block. The type split (`ControlInput` / `Untrusted[Workload]`)
means a prompt that gets past the scanner still cannot move the endpoint, the
cap, the signer or the registry. A test greps `prepare.py` for the syntax that
would merge a workload into the request.

## What remains

- **Unknown official details.** Endpoint, faucet, schema, price, network id,
  signing scheme, Yellow Paper. Every guard above is built against the shape
  of a request this tool has *designed*; the official shape may differ, and
  activation (`docs/FLOP_TESTNET_ACTIVATION.md`) must re-read this page against
  it.
- **The delegator's judgement.** D-107 moved "who may approve" from the chain's
  shape to a list the delegator writes. A delegator that names a key it wrongly
  believes is a person is not caught.
- **Two keys, one operator.** Only a fleet disclosure ties them (D-105);
  `wash.same-operator-counterparty` flags what is disclosed, not what is
  hidden.
- **The simulation is not the network.** It exercises the flow, not the
  protocol. Nothing about a live response's shape, timing or failure modes is
  known yet.
- **The audit log is local and unsigned.** It is a reconstruction aid, not
  evidence; it can be deleted by whoever owns the disk.

## Review points left open for the checker

Recorded from the stage-2 report so they are not lost:

1. Simulation skipping the phase gate is decided by the registry entry
   (`simulation=True`, origin under `.invalid`), and a lying prepared action is
   refused at stage 3. Whether two guards are enough.
2. `client.redact` treats a seed-like match greedily to end of line, erring
   toward over-redaction.
3. The synthetic marker rides in the attestation's `reasonCode` rather than as
   an extra payload key, to keep signed payloads exactly what the core builders
   produce.

## Residual risks, named

Three things this design does not do, written down so that nobody has to
rediscover them by reading the code.

*The audit chain is tamper-evident only up to its last anchor.* `testnet/audit.py`
hashes each line over the previous line's hash, with no key. That catches a
removed line, a reordered one and a truncated file; it does not catch an editor
with write access, who can change a line and recompute every hash after it.
D-110 closes that without a protocol change: `la flop audit anchor` drafts an
`artifact.register` whose artifact id *is* the chain head, to be signed outside
this process by the operator's key, and `verify_anchor` checks a log against
it. Lines appended after the last anchor are reported as uncovered, never
passed. Nothing in the UI calls the bare chain tamper detection.

*A counterparty's account of itself is not verification.* Everything in a
response — the receipt reference, the result, and `observedSpend`, which is the
party being billed against stating what it charged — describes the far side's
own behaviour. `receipt_from_response` therefore cannot return `VERIFIED` at
all; the ceiling is `PARTIALLY_VERIFIED` and `SELF_REPORTED_REASON` is on every
receipt. The spend ledger is charged `max(approved estimate, reported spend)`
so that an endpoint reporting zero cannot keep the daily and session caps empty
forever, and the audit line records `chargedToLedger` beside `observedSpend`.

*The host set is a deployment decision.* Every FLOP route checks `Host` against
the set the router was built for, because the same-origin test derives the
origin it expects from that header and a DNS-rebinding page controls it. The
default is loopback. A deployment that serves the console under another name
must pass `allowed_hosts=` — and one that puts it behind a proxy must make sure
the proxy sets a `Host` from that set rather than forwarding the client's.
