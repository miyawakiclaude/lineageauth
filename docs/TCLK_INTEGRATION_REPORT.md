# LINEAGEAUTH × TCLK/1 INTEGRATION REPORT

**Date:** 2026-09-02
**Directive:** read-only / no wallet / no external write. Honoured throughout:
no post, no push, no comment, no issue, no deal, no rail, no key read.

## Official tclk version reviewed

`tclk/1` — `flop-labs/tclk` at commit `81a83464bd909fb5cd80de647da4e42fbae177dd`,
tag `v0.1.0`, dated 2026-09-02T14:44:20+08:00, retrieved 2026-09-02T10:20:43Z.

## Official sources

- https://x.com/flop_labs/status/2095043853535608866 (2026-09-02T06:59:13Z) — the announcement
- https://github.com/flop-labs/tclk — `SPEC.md` (normative), `src/*.ts`, `tests/*.ts`, `README.md`, `SECURITY.md`, `CHANGELOG.md`, `AGENTS.md`, `examples/htlc-walkthrough.md`
- https://technocore.chat/patterns.md §6, `/llms.txt`, `/skill.md`, `/interop.md`
- `flop-labs/technocore-chat` `CHANGELOG.md` 0.11.3 (2026-09-02)
- https://flop.finance — no mention of tclk

Full detail, with the unknowns: [`TCLK_RESEARCH_REPORT.md`](TCLK_RESEARCH_REPORT.md).

## Implementation

A read-only adapter, `lineageauth.adapters.tclk`, that (1) decodes and
validates tclk/1 frames with the reference's exact field rules and reproduces
its golden vectors byte for byte, (2) folds a transcript into a contract state
with a port of the reference state machine, (3) maps a frame onto the
LineageAuth authority posting it needs — `technocore` / `room:<room>` / `write`
— and answers with LineageAuth's existing verifier, (4) prepares the exact
bytes, destination and `ActionRequest` an exact-action approval binds to, and
(5) drafts evidence events. Plus four read-only `la tclk` commands.

**No change to LAP core**: no event type, payload shape, namespace, action,
reason code or predicate was added. Canonical JSON is `json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=True)`. No new dependency.

## Files added

```
packages/py/lineageauth/adapters/tclk/__init__.py
packages/py/lineageauth/adapters/tclk/frames.py        wire format, ids, strict decoder
packages/py/lineageauth/adapters/tclk/locks.py         hash/point verification (no minting)
packages/py/lineageauth/adapters/tclk/machine.py       state machine, fold with per-frame instants
packages/py/lineageauth/adapters/tclk/venue.py         rooms, state note, capability token
packages/py/lineageauth/adapters/tclk/authority.py     authority-before-deal
packages/py/lineageauth/adapters/tclk/prepare.py       PREPARE; publish() raises
packages/py/lineageauth/adapters/tclk/evidence.py      artifact / attestation drafts
packages/py/lineageauth/adapters/tclk/interop.py       A2A / ACP status maps
packages/py/lineageauth/adapters/tclk/commitments.py   vote-commitment verification
packages/py/lineageauth/adapters/tclk/rail.py          read-only rail Protocol; refusal
tests/test_tclk.py
tests/test_cli_tclk.py
conformance/tclk/golden-vectors.json                   copied verbatim, commit recorded
conformance/tclk/synthetic-transcript.json             labelled synthetic
conformance/tclk/README.md
docs/TCLK_RESEARCH_REPORT.md
docs/TCLK_LINEAGEAUTH_ARCHITECTURE.md
docs/TCLK_GAP_ANALYSIS.md
docs/TCLK_INTEGRATION.md
docs/TCLK_THREAT_MODEL.md
docs/TCLK_MAPPING.md
docs/TCLK_INTEGRATION_REPORT.md                        this file
```

## Files modified

```
packages/py/lineageauth/cli.py           `la tclk inspect | simulate | authorize | prepare`
scripts/pre_push_check.py                path-scoped mask for 0x-hex under conformance/tclk/
tests/test_final_gate.py                 test that the mask is path- and prefix-scoped
README.md                                one status line, "independent integration"
docs/29_DECISIONS.md                     D-106
```

## Tests added

90 — 80 in `tests/test_tclk.py` (golden vectors; wire format A–C, T; locks;
state machine D–H; venue; authority I–P, S; exact-action approval L–M;
hostile content Q–R; rail boundary; evidence; interop and votes; the synthetic
fixture), 9 in `tests/test_cli_tclk.py`, 1 in `tests/test_final_gate.py`.

## All tests

1382 passed.

## CI

`scripts/gate.py`: lint PASS, format PASS, types PASS, tests PASS.
`scripts/pre_push_check.py`: remote, identity and tree clean.

## Authority mapping

A frame is a Technocore signed-lane message, so posting it is
`technocore` / `room:<room>` / `write` with the room from `SPEC.md` §2
(`tclk-offers` for offer and accept; `mb-p-tclk-<16hex>` after). Four checks
in a fixed order: structural validity (`MALFORMED` / `UNKNOWN_VERSION`), sender
is the agent, a `lock`'s rail is known (fail closed), then `check_permission`.
Every decision lists what LineageAuth did **not** check: `spend-limit`,
`rail-allowlist`, `counterparty`, `frame-type`, `settlement`.

## Human approval

`prepare_frame` produces `ActionRequest.over_bytes(content=<frame line>)` with
`destination = <origin>/r/<room>`. The line carries every term, so contract id,
counterparty, rails, amount, asset and deadlines are bound without being named
in the receipt. Changing one byte (tested: the nonce) yields `APPROVAL_REQUIRED`;
a receipt without underlying authority yields `DENIED`, not `APPROVAL_REQUIRED`.
No signer is needed: the canonical challenge `<room>|<nonce>|<line>` is
returned for the key's holder to sign wherever that key lives.

## Evidence mapping

Each frame → `artifact.register` (`sha256:` over the line). Terminal outcome →
`attestation.issue` with the deliberately **unregistered** predicate
`tclk.contract.outcome`, subject = the accept frame's artifact. A reveal is
recorded as `secret_revealed: true`; the value is never held. `evidence_summary`
states what the transcript does not prove.

## Arbitration overlap

Compared feature by feature in [`TCLK_MAPPING.md`](TCLK_MAPPING.md) §5. tclk §8
changes *who holds the secret* and so has a settlement effect; LineageAuth's
jury produces a technical result with none. Neither is re-implemented in the
other; `verify_vote_commitment` lets a LineageAuth reader re-check a tclk
commit–reveal round from an export. Both reach the same conclusion about
"same operator, different keys" — tclk §8.5 in prose, LineageAuth in D-105 and
`CONFLICT_SAME_FLEET`.

## FLOP native delegation overlap

`UNKNOWN_FROM_OFFICIAL_SPEC`. The FLOP-network escrow, its policy language, and
any proxy/delegation/spend-limit facility are described in `SPEC.md` prose only;
no public repository, specification or deployment was found. Nothing here
assumes their shape. Principle recorded: provider-native authorization remains
authoritative; LineageAuth is additive provenance and policy.

## Security

Threat model: [`TCLK_THREAT_MODEL.md`](TCLK_THREAT_MODEL.md), thirteen threats
with the control and the test for each. Invariants 1–8 from the directive are
each asserted by a test. The suite refuses the network. The package's source is
grepped for network and key-material imports. Room content is data; a hostile
`job.id` or `reason` authorises and folds exactly as a benign one and triggers
nothing.

## Wallet integration

NOT IMPLEMENTED.

## Settlement

NOT IMPLEMENTED. No rail. The rail type is a read-only `Protocol`;
`refuse_value_movement` raises for lock/claim/refund/reveal/sign/pay/send/publish.

## External writes

NONE. No post, push, comment, issue, deal, or network call of any kind. The
reference repository was cloned read-only into scratch space.

## Unknowns in official spec

1. The FLOP-network rail (`flop-htlc`) and its escrow policy language
2. The `has-station` escrow named in §1
3. FLOP-native delegation, proxy accounts, spend limits
4. The rail-specific PTLC "claim message"
5. Any byte-exact end-to-end transcript (the walkthrough says its own is not)
6. Duplicate JSON keys (reference: last wins; this port: refused)

Also recorded: the vector file and `AGENTS.md` disagree about whether the
golden vectors came from the reference or an independent implementation.

## SPEC CHANGE REQUIRED

**NO** change made. **Four proposals** recorded in
[`TCLK_GAP_ANALYSIS.md`](TCLK_GAP_ANALYSIS.md): a `tclk` namespace with
per-frame-type actions; typed constraints (spend limit, rail allowlist,
counterparty) on a scope; registering `tclk.contract.outcome`; a task-level
`a2a` resource. The second is the constraint language `PRIOR_ART.md` already
credits to ADTP and UCAN, which is the reason to decide slowly.

## Remaining risks

- Undisclosed collusion between two DIDs held by one operator (tclk §8.5, D-105).
- A `lock` frame's rail reference is a posted string; nothing here can check it.
- tclk/1 is alpha. A new optional key on a `tclk1 ` frame would be refused
  until this port is re-pinned — fail-closed, and a maintenance cost.
- The Explorer page (§24) was not built; core first.
- Three ports of this spec now exist (TypeScript reference, the reference's
  MCP server, this). Only the four golden vectors are shared ground truth.

## Recommended next step

Offer the four golden vectors plus this port's synthetic transcript to the
reference maintainers as a cross-implementation check — after the user decides
whether and how to make contact. That is the one thing the pinned commit cannot
give: a second implementation that disagrees, or does not.

## STATUS

**PASS** — with §24 (Explorer page) explicitly not built, and the commit left
local, unpushed, for the user's review.
