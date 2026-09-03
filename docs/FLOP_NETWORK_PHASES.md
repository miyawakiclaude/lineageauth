# FLOP network phases

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** This page describes how the FLOP layer decides what it believes
about the FLOP network, and what each belief permits. Nothing here is a
statement about the network itself; it is a statement about what this tool has
been able to confirm from official sources.

## Current phase

`PRE_TESTNET`, as of the official-source snapshot taken 2026-09-03T04:25:46Z
(`conformance/flop/official-sources.json`).

Facts behind that: the teaser (`https://flop.finance/teaser/`, "Version 0.1
(draft)", updated 2026-08-26) schedules a testnet for Q4 2026 and a mainnet for
Q1 2027; no official source publishes a testnet endpoint, a faucet procedure,
an inference API, a price, a network identifier or a signing scheme; and no
repository in the `flop-labs` GitHub organisation carries any of them.

Judgement drawn from those facts: no endpoint may be executable, and the
executor must refuse every live action with `TESTNET_NOT_LIVE` before it
touches a transport. Only the simulation runs.

## The six phases

The vocabulary is `flop.model.NetworkPhase`. It is the directive's list, with
one property that matters more than the names: `testnet_is_live` is true for
`TESTNET_ENABLED` and nothing else. *Verified* means checked, not switched on.

| Phase | What it means | UI | Simulation | Real faucet | Real inference spend |
|---|---|---|---|---|---|
| `PRE_TESTNET` | no official endpoint or spec exists | works | allowed | disabled | disabled |
| `TESTNET_DISCOVERED_UNVERIFIED` | a candidate endpoint or spec was found somewhere | works, shows the source-verification panel | allowed | disabled | disabled |
| `TESTNET_VERIFIED` | a current official source confirms the endpoint and spec; parser and adapter tests pass | works | allowed | disabled until enabled | disabled until enabled |
| `TESTNET_ENABLED` | a person explicitly enabled execution after the activation checklist | works | allowed | per exact-action approval | per exact-action approval |
| `MAINNET_DISCOVERED_UNVERIFIED` | a mainnet candidate was found | works | allowed | n/a | disabled |
| `MAINNET_VERIFIED` | official source confirms mainnet | works | allowed | n/a | not implemented |

The badge shown in the header collapses these to three words — `PRE-TESTNET`,
`TESTNET`, `MAINNET` — because a badge is read at a glance and the finer
distinction is carried next to it as text.

## Transitions

`flop.testnet.phase.PhaseGate` holds the phase and the kill switch. Its
transition table is a constant, and the edge the directive forbids —
`PRE_TESTNET → TESTNET_ENABLED` — is not a refused transition; it is absent
from the table. The version that survives somebody being in a hurry is the
version where the edge does not exist.

```text
PRE_TESTNET
  → TESTNET_DISCOVERED_UNVERIFIED     (a candidate was found)
  → TESTNET_VERIFIED                  (PhaseEvidence: official source id, url, sha256, verifiedAt)
  → TESTNET_ENABLED                   (PhaseEvidence.checklist complete; a person says so)
  → MAINNET_DISCOVERED_UNVERIFIED
  → MAINNET_VERIFIED
```

Every promotion is one rung. Promotion to `TESTNET_VERIFIED`,
`TESTNET_ENABLED` or `MAINNET_VERIFIED` requires a `PhaseEvidence` naming the
source document and its hash, so a later snapshot that differs can invalidate
the promotion rather than inherit it. Promotion to `TESTNET_ENABLED`
additionally requires every item of `ACTIVATION_CHECKLIST` (fifteen entries,
listed in `docs/FLOP_TESTNET_ACTIVATION.md`) to be present in the evidence;
`missing_checklist_items` names what is absent.

Downgrading is always allowed, to any lower rung, with no evidence. A gate that
could not be dropped back to `PRE_TESTNET` would make a mistaken promotion
permanent. A transition never releases the kill switch; that is a separate act.

## The kill switch

`Disable all FLOP network writes`. Default ON. Two rules:

- It is **locked ON** while the phase is below `TESTNET_VERIFIED`, and
  `release_kill_switch` raises rather than releasing. The Settings screen shows
  the locked wording: `Disable all FLOP network writes: ON (locked while the
  network phase is PRE_TESTNET)`.
- It overrides the phase in one direction only. It can stop a write the phase
  would permit; it can never permit one the phase forbids.
  `network_writes_allowed` is `testnet_is_live and not kill_switch_engaged`.

`PhaseGate.refusal()` is the first of the executor's nine stages
(`docs/FLOP_TESTNET_EXECUTOR.md`). Below `TESTNET_ENABLED` it returns
`TESTNET_NOT_LIVE`; at `TESTNET_ENABLED` with the switch engaged it returns
`KILL_SWITCH_ENGAGED`. Both are typed refusals with a stage name, never a
boolean.

## What the phase does not decide

- Whether a source is official. That is `flop.sources.classify_source`, by
  origin alone (`docs/FLOP_SAFETY.md`).
- Whether an endpoint is executable. That is the registry constructor, which
  requires an official origin *and* a `verifiedAt` (`docs/FLOP_TESTNET_EXECUTOR.md`).
- Whether a simulated action may run. Simulation is decided by the registry
  entry's origin (`https://testnet.simulation.invalid`, RFC 6761), not by the
  phase and not by the prepared action's own claim.

Three guards that agree by construction are stronger than one guard that
everything trusts.

## Where the phase is shown

- `GET /v1/flop/status` — `networkPhase`, `networkPhaseBadge`,
  `officialTestnetExecutable: false`, `officialTestnetReason`, `killSwitch`.
- `GET /v1/flop/testnet/state` — the whole gate, the registry, the spend
  policy, the signer, the mainnet adapter, `executorStages`.
- `la flop status` — the same, ASCII only.
- The Console header badge, and the Inference screen's `Waiting for official
  FLOP Testnet` state.

Coverage categories that depend on a phase (`inference`, `broker`, `creator`,
`mainnet`) report `NOT_YET_AVAILABLE` below their required phase, which is
deliberately not zero (`docs/FLOP_DATA_MODEL.md`).

See also: `docs/FLOP_TESTNET_ACTIVATION.md` for how the phase is meant to move,
and D-108 in `docs/29_DECISIONS.md`.
