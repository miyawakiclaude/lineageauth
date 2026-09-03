# FLOP testnet executor

The part of the FLOP layer that could, one day, send a request to a FLOP
testnet — and the reasons it cannot today. `packages/py/lineageauth/flop/testnet/`.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** Current phase `PRE_TESTNET`; official testnet executable: **no**;
wallet custody: **none**; external FLOP writes performed: **none**.

## In one paragraph

A person states a purpose and a ceiling. The tool builds a *plan* from the
control plane alone (endpoint from the registry, network, cap, signer id,
snapshot and rule-set fingerprints), then *assembles* a request by copying the
untrusted workload into one subtree of that plan. The request's canonical
bytes are hashed; that hash is what a designated approver signs, through the
core's own `check_execution` (D-107, D-089). The executor then walks nine
checks in a fixed order, and the network is the ninth. Below
`TESTNET_ENABLED` the first check refuses with `TESTNET_NOT_LIVE` before any
transport is consulted. Only the simulation — whose destination is
`https://testnet.simulation.invalid`, a name RFC 6761 guarantees cannot resolve
— runs end to end.

## Modules

| Module | Responsibility |
|---|---|
| `phase.py` | `PhaseGate`: phase, kill switch, transition table without the forbidden edge, `ACTIVATION_CHECKLIST` (`docs/FLOP_NETWORK_PHASES.md`) |
| `endpoints.py` | `FlopEndpointRegistry`; an entry is `executable` only if official origin **and** `verifiedAt` **and** enabled, checked in the constructor; `SIMULATION_ORIGIN`; dispositions `READABLE_IF_SAFE` / `BLOCKED` |
| `spend.py` | `TestnetSpendPolicy` (nested limits, `Decimal` only), `SpendLedger` (observed spend, never an estimate) |
| `prepare.py` | `ControlInput → build_plan → ExecutionPlan`; `assemble_request(plan, Untrusted[InferenceWorkload]) → PreparedTestnetAction`; `ActionRequest.over_bytes` |
| `approve.py` | hands the core `check_execution` the right `ActionRequest`; adds expiry and `REPREPARE_REQUIRED` |
| `executor.py` | `STAGES`, `ExecutorContext`, `execute()`; the client is a required argument |
| `client.py` | `RestrictedClient`: allowlisted origins, https, timeout, size cap, no redirects, request/response hashes, redaction; no public method takes a URL |
| `simulation.py` | synthetic faucet, balance, quote, `SimulationTransport`, `run_simulation` — the same executor, approval and evidence as the real thing |
| `receipts.py` | `FlopTestnetExecutionReceipt`, `receipt_from_response`, `verificationState` |
| `evidence.py` | receipt → two `artifact.register` drafts + one `attestation.issue` draft, predicate unregistered (`docs/FLOP_INFERENCE_EVIDENCE.md`) |
| `audit.py` | append-only JSONL, each line committing to the previous; secrets dropped, not masked |
| `mainnet.py` | `MainnetUnlockAdapter` protocol; `NotYetAvailable` reads the 3:1 ratio from the rule registry |
| `signer.py` | `Signer` protocol; `NoSigner` only; no parameter anywhere takes a seed, key, keyfile or passphrase |
| `ports.py` | every seam (`TestnetTransport`, `AuditSink`, `Clock`, `TransportRequest`) so the executor imports no implementation |

## The nine stages

```text
1  phase                PhaseGate.refusal()                      TESTNET_NOT_LIVE | KILL_SWITCH_ENGAGED
                        (skipped only when the registry entry is the simulation's)
2  official-source      freshness_refusal(prepared, snapshot,    REPREPARE_REQUIRED | QUOTE_EXPIRED
                        rules, at): fingerprints still match, action not expired
3  endpoint             registry.resolve(id, phase)              ENDPOINT_NOT_OFFICIAL | ENDPOINT_BLOCKED
                        (a simulation claim the registry disagrees with)   REQUEST_INVALID
4  request-validation   canonical bytes re-hashed, approval binds them   REQUEST_INVALID | APPROVAL_MISMATCH | REPREPARE_REQUIRED
5  active-did           did:key well-formed, lineage current    DID_NOT_ACTIVE
6  authority            check_permission(http, host:<host>, post)   AUTHORITY_DENIED (+ core reason code)
7  spend                policy.check(amount, ledger)             SPEND_LIMIT_EXCEEDED
8  exact-approval       check_execution(reserve=True)            APPROVAL_MISSING | APPROVAL_MISMATCH | APPROVAL_EXPIRED
9  network              client.send(endpoint, path, request)     NETWORK_REFUSED | INVALID_RESPONSE | RECEIPT_UNVERIFIED
```

The order is the security property, not the presence of the checks. A spend
policy consulted after the request was sent is a report; an authority check
made before the request was validated has verified authority over something
other than what will be transmitted. `STAGES` is a constant and a test walks
it. The phase gate is first because it can refuse without reading anything
else; the network is ninth because nothing may reach it that the previous
eight have not agreed to.

The directive lists eight steps. The ninth is the phase gate, split out so it
is unmistakably the first thing consulted.

Every refusal is a `TestnetRefusal(failure, detail, stage)` and serialises
with `executed: false`. A boolean false teaches the caller nothing and invites
a retry loop; a refusal naming its stage tells the operator which thing to fix.

## Typed failures

`TestnetFailure`, nineteen members. The directive's thirteen (§24) map as:

| directive | here | note |
|---|---|---|
| `TESTNET_NOT_LIVE` | same | stage 1 |
| `OFFICIAL_SOURCE_UNVERIFIED` | same | stage 2 |
| `ENDPOINT_NOT_ALLOWLISTED` | `ENDPOINT_NOT_OFFICIAL`, `ENDPOINT_BLOCKED` | split: "not official" and "refused for this phase" call for different fixes |
| `AUTHORITY_INVALID` | `AUTHORITY_DENIED`, `DID_NOT_ACTIVE` | the core's reason code rides in `detail` |
| `APPROVAL_REQUIRED` | `APPROVAL_MISSING` | |
| `APPROVAL_EXPIRED` | same | |
| `REQUEST_CHANGED` | `APPROVAL_MISMATCH`, `REPREPARE_REQUIRED` | a changed byte vs. a changed rule set |
| `SPEND_LIMIT_EXCEEDED` | same | |
| `QUOTE_EXPIRED` | same | |
| `NETWORK_ERROR` | `NETWORK_REFUSED` | |
| `INVALID_RESPONSE` | same | |
| `RECEIPT_UNVERIFIED` | same | |
| `SUSPICIOUS_CONTENT` | same | scanner `BLOCKED` at prepare |
| — | `KILL_SWITCH_ENGAGED`, `REQUEST_INVALID`, `SIGNER_NOT_CONFIGURED` | added |

## Control plane and workload

Directive §22 says a prompt must never change the endpoint, the spend limit,
the signer or the source registry. That is arranged as a type property rather
than a rule to remember:

```python
plan = build_plan(
    ControlInput(
        endpoint_id="simulation-inference",
        subject_did=agent,
        action_type="inference",
        purpose=InferencePurpose.EVALUATION,
        max_spend=Decimal("5"),
    ),
    registry=registry,
    policy=policy,
    gate=gate,
    snapshot=snapshot,
    rules=rules,
)
prepared = assemble_request(
    plan,
    Untrusted(InferenceWorkload(purpose=plan.purpose, prompt=prompt)),
    at=now,
    quote=quote,
)
```

`build_plan` has no parameter that could carry a prompt; `inspect.signature`
is asserted in a test. `assemble_request` copies the workload into the
`workload` subtree field by field from a fixed allowlist, and a test greps the
module for `**workload` and dict-merge syntax. `ControlInput` has no free-text
field. `Untrusted[T]` makes the unwrap a line somebody wrote. Tests H (a
prompt demanding another endpoint changes nothing; the executed destination
comes from the control plane) and I pin it.

`maxSpend` is inside the canonical request's `control` subtree, so it is bound
into `requestHash` and therefore into the approval. Amounts are `Decimal`;
floats are refused by type. Test E: one changed byte moves the request hash;
an approval for one request does not cover the other.

## Approval

`approve.approve(prepared, *, bundle, lineage, agent, at, store, snapshot,
rules, reserve=False)` builds
`ActionRequest.over_bytes(namespace="http", resource=f"host:{host}",
action="post", destination=canonicalDestination, content=canonical request
bytes)` and calls the core's `check_execution`. Nothing is re-implemented: the
receipt must bind this exact `requestHash`, be signed by an approver the grant
designates (D-107), be inside its window, and be unspent. `approve` previews
with `reserve=False`; the executor commits at stage 8 with `reserve=True`, so a
second execution of the same approved action is `APPROVAL_MISMATCH` with the
wash wording (test K).

Two checks the core cannot make are added because they are about FLOP rather
than about authority: the prepared action has not expired (`QUOTE_EXPIRED`,
test G), and the snapshot and rule set have not moved since preparation
(`REPREPARE_REQUIRED`, test N).

Approval never creates authority. A grant with `approval: none` still requires
a receipt for a FLOP spend (`APPROVAL_MISSING`); a chain that denies the
action is `AUTHORITY_DENIED` whoever signed (test C).

## Spend policy

Defaults, conservative on purpose: per action 10, per session 25, per day 50,
approval required above 0. The three limits must nest or the constructor
refuses. Raising any of them goes through `raised(...)`, which returns a new
policy and is expected to be logged; there is no setter. Test F: a quote above
the approved maximum is refused. The ledger records observed spend from
responses only.

## Client

`RestrictedClient.send(endpoint, path, request)` — there is no `fetch(url)`.
The endpoint comes from the registry and the path must match the endpoint's
own pattern, so a URL from a prompt, a room message or a redirect has no
parameter to arrive through. Https only; 10 s timeout and 262,144-byte cap
travel inside the `TransportRequest`; redirects are never followed and a
transport that followed one anyway is caught because `final_url` differs and
is re-classified — a different origin is a different side effect and needs a
new approval (test J). Request and response bodies are hashed; secrets are
redacted on the way *into* any record, `Authorization`/`Cookie` headers
wholesale, seed-like strings to end of line.

`NullTransport` refuses rather than answering quietly; `CountingTransport`
exists so test O can assert zero calls across all four non-live phases.

## Simulation

`run_simulation` performs the full directive §28 flow — synthetic faucet,
balance, quote, LineageAuth authority, exact approval, execution, receipt,
evidence, passport — through the same executor, approval check and evidence
drafts the real thing would use. Only the transport differs, and the transport
is the piece that would otherwise be the whole risk. The API's `prepare` route
delegates to `simulation.prepare_simulation` so the bytes a person approves in
the UI are the bytes the simulation run executes.

Simulation skips the phase gate, and only simulation can: the executor checks
the *registry's* entry (`simulation=True` and origin under `.invalid`), not the
prepared action's claim about itself; a prepared action that lies is refused
at stage 3 with `REQUEST_INVALID`. Every object it produces carries
`synthetic: true` and `SIMULATION - NO FLOP NETWORK ACTION`. Faucet and quote
amounts (100, 2.5, default ceiling 5) are constants of the simulation and are
labelled as such.

### Where the walkthrough's approval comes from

The page holds no keys, so it cannot approve anything itself, and the first
browser run after the pipeline finished stopped at the approval step for that
reason. `POST /v1/flop/testnet/simulation/run` now takes the receipt from one of
three places and names which in `approvalReceipt.source`:

- `pasted` — the caller supplied a signed `approval.receipt` envelope. It is
  verified for this run, used once, and never written to the index; the console
  has no ingest path and a receipt is not an exception.
- `demo-approver` — a demo process started with an approver DID and a
  receipt-signing callback (`flop_demo_approver`, `flop_demo_sign_receipt`)
  has one signed with the same unsafe, public test key the demo bundle uses.
  The key stays in the demo script; the FLOP layer holds a function, never a
  key, and its import guard still passes. The response says so
  (`synthetic: true`), and a production mount ignores both even if handed them.
- `none` — the run stops at the approval step and says how to continue.

Whatever the source, the receipt is checked by `check_execution` like any other:
a key the grant does not name, or a receipt for a different request hash or a
different spend cap, is refused. `maxSpend` from the request reaches the run,
so the cap the page shows is the cap the receipt binds.

## Audit

Every prepare, approve, execute attempt, network result, evidence draft and
failure is appended as a JSONL line carrying `prev` (the previous hash) and
`hash` over the canonical bytes of the rest. `verify_chain` reports *where*
the chain stopped adding up. Keys whose names look like secrets are dropped —
a line recording `"seed": "[REDACTED]"` still records that a seed was handled
here, and this tool handles none. Bytes are stored as sha256. `at` is a
required argument; the log never reads a clock (D-106's "no default clock").

## API and CLI

`GET /v1/flop/testnet/state`, `GET /v1/flop/testnet/receipts/{id}`,
`POST /v1/flop/testnet/inference/{quote,prepare,approve,execute}`,
`POST /v1/flop/testnet/simulation/run`. Bodies are `extra="forbid"`;
`endpointId` is not accepted from a client (422) — the control plane chooses
it. `execute` answers `409` with `{failure: "TESTNET_NOT_LIVE", stage:
"phase", executed: false}` in every phase below `TESTNET_ENABLED`.

`la flop status | sources | rules`, `la flop testnet simulate`,
`la flop faucet prepare` (unavailable/simulation only), `la flop inference
quote | prepare | inspect`, `la flop receipt verify`. There is no `execute`
command. Output is ASCII.

## SPEC CHANGE proposals — recorded, not adopted

The recon brief required the FLOP testnet authority to be expressed with the
existing `http` namespace: `http` / `host:<official endpoint host>` / `post`.
That is what was built, and no namespace, action, reason code, event type,
payload shape or predicate was added (D-108). Two things the model cannot say
are recorded here as proposals, in the same standing as
`docs/TCLK_GAP_ANALYSIS.md` §"SPEC CHANGE REQUIRED": awaiting a decision, not
taken.

### Proposal 1 — a `flop` namespace

```text
namespace: flop
resources: testnet:<network-id> | mainnet:<network-id> | endpoint:<host>
actions:   faucet | inference | stake | transfer
```

*Would close:* per-action-type permission ("may buy inference but not claim
the faucet"), which today is carried by the endpoint's path pattern and the
spend policy rather than by the grant. *Cost:* a second authority the same
request needs (the `http` host write does not go away), a new family in
`frozen-shapes.json`, a second implementation that must agree, and — as with
the `tclk` proposal — the `authority` family is *held* pending the UCAN
question (D-101, D-105). *Status:* not adopted.

### Proposal 2 — a spend constraint on a scope

```text
{"namespace": "http", "resource": "host:<official host>", "actions": ["post"],
 "constraints": {"maxSpend": {"asset": "FLOP", "value": "10", "per": "action"}}}
```

*Would close:* the spend limit living in the grant rather than in a local
policy. Today the ceiling is a policy default, raised only through an explicit
API, and the *approved* ceiling is bound into `requestHash` — so a person
approves a specific cap, but a delegator cannot cap a delegate. *Cost:*
attenuation semantics per constraint, a canonical comparison rule, and the
reason to be slow: this is the constraint language `PRIOR_ART.md` credits to
ADTP and UCAN caveats, and the tclk analysis already declined to reinvent it
beside them. *Status:* not adopted.

Both are `SPEC CHANGE REQUIRED` in the sense of `scopes.py` ("Adding a
namespace or an action is a protocol change") and `docs/24`. Neither was
needed to make the testnet path safe in `PRE_TESTNET`, and neither should be
taken before an official spec says what a FLOP action actually is.

## What is unknown, still

Testnet endpoint; faucet procedure, amount, cooldown; inference request and
response schema; pricing and quote mechanism; network identifier;
authentication and signing scheme; the Yellow Paper. Each is an `unknown` rule
in the registry with a consequence attached. An executable endpoint can be
added only after these appear in an official snapshot and a `verifiedAt` is
recorded (`docs/FLOP_TESTNET_ACTIVATION.md`).
