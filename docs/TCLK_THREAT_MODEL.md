# tclk/1 integration — threat model

Scope: `lineageauth.adapters.tclk` and the `la tclk` commands. The rest of
LineageAuth's threat model (`docs/22`) applies unchanged; this adds the threats
that appear because frames arrive from a world-writable room and describe money.

## Assets

- the agent's LineageAuth signing key (never read here; the signer is optional
  and used only to produce an unsent `PreparedWrite`)
- payment keys, preimages, witnesses — **not held**: nothing mints, stores or
  echoes one
- the correctness of an authority decision about a frame
- the correctness of a contract state folded from a transcript

## Trust boundaries

| boundary | on the far side | rule |
|---|---|---|
| room content | every frame, note, topic, nickname, `from` field | untrusted data; parsed fail-closed; never executed, fetched or obeyed |
| the tclk/1 spec and reference | a third party's convention, alpha | pinned to a commit; conformance by golden vectors; changes fail loudly |
| the settlement rail | someone else's system, undocumented | no interface to reach it that moves value |
| Technocore's signed lane | the transport's verification | reused from `adapters/technocore`; not re-implemented, not bypassed |
| LineageAuth authority | the project's own verifier | the only source of an allow |

## Threats and controls

### T1 — a valid frame is mistaken for authority

*A frame that parses, has the right shape and even verifies a signature is
treated as permission to post it.*
Control: `verify_tclk_authority` derives an allow only from `check_permission`.
The frame is an input. Test: valid frame + genesis only → `DENIED`.

### T2 — authority is mistaken for tclk validity

*An agent with a valid room grant posts a malformed or hostile frame and the
verifier waves it through.*
Control: structural validation runs first and returns before the authority
layer is consulted; `decision.decision is None` in that case. Test: grant +
`tclk1 {"type":"offer"}` → `MALFORMED`, no authority consulted.

### T3 — prompt injection through free-text fields

*`job.id`, `reason`, `ref`, `asset` carry "ignore previous instructions", a
URL, "enter your seed phrase", "official FLOP task".*
Control: the package has no code path that fetches, executes, or reads
instructions from a field; a string is validated for shape and carried
verbatim. The test suite patches `socket` to refuse and greps the package for
network and key-material imports. Tests: hostile `job.id` authorises exactly as
a benign one; hostile `reason` cancels exactly as a benign one.

### T4 — the verifier leaks a secret

*A revealed preimage or witness is kept in state, logged, or echoed.*
Control: `ContractState` records `secret_revealed: bool` and has no field for
the value — stricter than the reference library, matching its MCP server's
rule. Nothing mints a secret (`generate*`/`split*` are absent by test).

### T5 — a byte changes between approval and execution

*A human approves an offer; the agent posts a different one.*
Control: the receipt binds `sha256(frame line)` inside `requestHash`; the line
contains every term. Test: changing the nonce (the smallest change) makes
`check_execution` return `APPROVAL_REQUIRED`.

### T6 — an approval for one room is spent in another

Control: `destination` and `resource` are inside the request hash; the offer
board and a deal room produce different hashes for the same lock frame.

### T7 — unknown semantics are guessed

*A `tclk2 ` frame, an unknown field, an unknown rail.*
Control: fail closed. `tclk2 ` → `UNKNOWN_VERSION`; unknown key → refused;
`lock` naming a rail outside `KNOWN_RAILS` → `DENIED` with the rail named.

### T8 — a non-canonical or duplicate-key line

*Two lines that parse to one frame, or one line that parses two ways.*
Control: strict canonical decode by default (line must equal its re-encoding)
and duplicate keys refused. The reference accepts both; this refuses both.

### T9 — the state machine drifts from the reference

Control: `conformance/tclk/golden-vectors.json` copied from the reference and
asserted byte for byte; the state-machine tests mirror the reference suite
case for case (wrong party, wrong order, wrong secret, expiry, replay, cancel,
receipt contradiction, point-lock keys).

### T10 — the DID is trusted because it looks right

Control: the frame-level DID check is shape only, as in the reference; who
actually wrote the bytes is Technocore's signed-lane verification
(`verify_message_signature`), and who is entitled is LineageAuth's. Neither is
short-circuited by the frame saying `from`.

### T11 — two keys, one operator

*The payer and payee, or a juror and a party, are the same operator wearing
two `did:key`s.* `SPEC.md` §8.5 says so itself: "a `did:key` costs nothing to
mint".
Control: none cryptographic — the same limit D-105 records for approval.
`FleetView.same_fleet` catches the operator who disclosed; nothing catches one
who did not, and no document here claims otherwise.

### T12 — value movement through a "rail"

Control: the rail type is a `Protocol` with no `lock`, `claim`, `refund`,
`sign`, `pay` or `send`; `refuse_value_movement` raises for every one of those
names; `publish` raises. Tested.

### T13 — the venue clock

*Deadlines judged against the room's `ts`.*
Control: every check takes `now_ms` from the caller; nothing reads the wall
clock or a message timestamp. `claimByMs` is deliberately not enforced by the
machine, matching the reference, because it is the rail's to enforce.

## Residual risks (stated, not solved)

- Undisclosed collusion between DIDs (T11).
- **Upstream-open behaviours this port mirrors on purpose.** A `cancel` while
  `proposed` matches no contract id, so one signed cancel folds every pending
  offer from that sender to `cancelled`, and no `receipt` can follow (flop-labs/tclk
  #17, #5). On a payee-opened offer the party that mints the secret is the one
  that may not reveal it (#12). This port reads transcripts; disagreeing with
  the reference about what a transcript did would be a worse failure than
  sharing its behaviour, so both are reproduced and named here until upstream
  decides.
- A rail reference in a `lock` frame proves a message was posted, not that a
  lock exists. Nothing here can check it, and `evidence_summary` says so.
- The spec is alpha; a future `tclk1 ` frame with new optional keys would be
  refused by this port until re-pinned. That is the fail-closed choice.
- The sweep equivalence with the live Technocore service is asserted for
  printable ASCII only, which is all a canonical frame contains.

## Out of scope

The security of tclk/1 itself, of the adaptor-signature module, of Technocore,
or of any rail. `SECURITY.md` in the reference repository is the channel for
those.
