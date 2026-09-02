"""tclk/1 contract state machine, local and pure.

A port of `src/machine.ts` (flop-labs/tclk `81a8346`) with the guards kept
exactly. `apply_frame` never raises on a bad frame and never mutates its input:
an invalid transition returns the same state with `ok=False` and a reason, so a
reader can fold every line of a world-writable room through it.

    proposed ─accept→ accepted ─lock→ locked ─reveal→ claimed | ─refund→ refunded
    proposed|accepted ─cancel→ cancelled

One deliberate difference from the reference: the state never holds a revealed
secret. The reference keeps `state.secret`; its own MCP server refuses to echo
it (`secretRevealed: boolean`, SECURITY.md). This port takes the server's rule
for the library too, because a verifier that stores a preimage is a verifier
that can leak one, and nothing here needs the value after the check.

The machine tracks what a signed transcript establishes. It never touches money,
and it cannot tell whether a `lock` frame's rail reference points at anything.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from lineageauth.adapters.tclk.frames import (
    Frame,
    FrameError,
    accept_core,
    contract_id,
    validate_frame,
)
from lineageauth.adapters.tclk.locks import is_valid_statement, verify_secret

STATUSES: tuple[str, ...] = ("proposed", "accepted", "locked", "claimed", "refunded", "cancelled")
TERMINAL_STATUSES: frozenset[str] = frozenset({"claimed", "refunded", "cancelled"})


@dataclass(frozen=True, slots=True)
class ContractState:
    """The local view of one contract, read off the transcript so far."""

    status: str
    offer: Mapping[str, Any]
    payer_did: str | None = None
    payee_did: str | None = None
    payer_key: str | None = None
    payee_key: str | None = None
    contract: str | None = None
    statement: str | None = None
    rail: str | None = None
    rail_ref: str | None = None
    presig: Mapping[str, Any] | None = None
    secret_revealed: bool = False
    """True once a verifying reveal was applied. The value itself is not kept."""

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def is_party(self, did: str) -> bool:
        return did in (self.offer.get("from"), self.payer_did, self.payee_did)


@dataclass(frozen=True, slots=True)
class StepResult:
    state: ContractState
    ok: bool
    reason: str | None = None


def open_contract(offer: Mapping[str, Any] | Frame) -> ContractState:
    """The `proposed` state from a validated offer. Raises on a bad offer."""
    fields = offer.fields if isinstance(offer, Frame) else validate_frame(offer)
    if fields.get("type") != "offer":
        raise FrameError("tclk: a contract opens from an offer frame")
    is_payer = fields["role"] == "payer"
    key = fields.get("paymentKey")
    return ContractState(
        status="proposed",
        offer=dict(fields),
        payer_did=fields["from"] if is_payer else None,
        payee_did=None if is_payer else fields["from"],
        payer_key=key if is_payer else None,
        payee_key=None if is_payer else key,
    )


def _reject(state: ContractState, reason: str) -> StepResult:
    return StepResult(state=state, ok=False, reason=reason)


def apply_frame(state: ContractState, frame: Mapping[str, Any] | Frame, now_ms: int) -> StepResult:
    """Apply one frame at wall-clock `now_ms`. Structural validation first, then guards."""
    try:
        fields = frame.fields if isinstance(frame, Frame) else validate_frame(frame)
    except FrameError as exc:
        return _reject(state, str(exc))
    kind = fields["type"]
    sender = fields["from"]

    if kind == "offer":
        return _reject(state, "contract is already open")

    if kind == "accept":
        if state.status != "proposed":
            return _reject(state, f"accept in status {state.status}")
        if fields["ref"] != state.offer["id"]:
            return _reject(state, "accept.ref names a different offer")
        if sender == state.offer["from"]:
            return _reject(state, "cannot accept own offer")
        if now_ms >= int(state.offer["expiresMs"]):
            return _reject(state, "offer has expired")
        if fields["contract"] != contract_id(state.offer, accept_core(fields)):
            return _reject(state, "contract id mismatch")
        if state.offer["lock"] == "point" and "paymentKey" not in fields:
            return _reject(state, "point locks require the acceptor's paymentKey")
        if not is_valid_statement(str(state.offer["lock"]), fields["statement"]):
            return _reject(state, f"statement does not fit a {state.offer['lock']} lock")
        acceptor_is_payer = state.offer["role"] == "payee"
        key = fields.get("paymentKey")
        return StepResult(
            ok=True,
            state=replace(
                state,
                status="accepted",
                contract=fields["contract"],
                statement=fields["statement"],
                payer_did=sender if acceptor_is_payer else state.payer_did,
                payee_did=state.payee_did if acceptor_is_payer else sender,
                payer_key=key if acceptor_is_payer else state.payer_key,
                payee_key=state.payee_key if acceptor_is_payer else key,
            ),
        )

    if kind == "lock":
        if state.status != "accepted":
            return _reject(state, f"lock in status {state.status}")
        if fields["contract"] != state.contract:
            return _reject(state, "lock names a different contract")
        if sender != state.payer_did:
            return _reject(state, "only the payer locks")
        if fields["rail"] not in state.offer["rails"]:
            return _reject(state, f"rail {fields['rail']} was not offered")
        return StepResult(
            ok=True,
            state=replace(
                state,
                status="locked",
                rail=fields["rail"],
                rail_ref=fields["ref"],
                presig=fields.get("presig"),
            ),
        )

    if kind == "reveal":
        if state.status != "locked":
            return _reject(state, f"reveal in status {state.status}")
        if fields["contract"] != state.contract:
            return _reject(state, "reveal names a different contract")
        if sender != state.payee_did:
            return _reject(state, "only the payee reveals")
        if now_ms >= int(state.offer["refundAfterMs"]):
            return _reject(state, "refund window is open")
        assert state.statement is not None
        if not verify_secret(str(state.offer["lock"]), state.statement, fields["secret"]):
            return _reject(state, "secret does not open the statement")
        return StepResult(ok=True, state=replace(state, status="claimed", secret_revealed=True))

    if kind == "refund":
        if state.status != "locked":
            return _reject(state, f"refund in status {state.status}")
        if fields["contract"] != state.contract:
            return _reject(state, "refund names a different contract")
        if sender != state.payer_did:
            return _reject(state, "only the payer refunds")
        if now_ms < int(state.offer["refundAfterMs"]):
            return _reject(state, "refund window not open yet")
        return StepResult(ok=True, state=replace(state, status="refunded"))

    if kind == "cancel":
        if state.status not in ("proposed", "accepted"):
            return _reject(state, f"cancel in status {state.status}")
        if state.status == "accepted" and fields["contract"] != state.contract:
            return _reject(state, "cancel names a different contract")
        if not state.is_party(sender):
            return _reject(state, "cancel from a non-party")
        return StepResult(ok=True, state=replace(state, status="cancelled"))

    # receipt: a post-terminal acknowledgment, never a transition.
    if not state.terminal:
        return _reject(state, "receipt before a terminal status")
    if fields["contract"] != state.contract:
        return _reject(state, "receipt names a different contract")
    if not state.is_party(sender):
        return _reject(state, "receipt from a non-party")
    if fields["outcome"] != state.status:
        return _reject(state, f"receipt outcome {fields['outcome']} does not match {state.status}")
    return StepResult(ok=True, state=state)


def fold(
    offer: Mapping[str, Any] | Frame,
    frames: Iterable[Mapping[str, Any] | Frame],
    now_ms: int | Sequence[int],
) -> tuple[ContractState, tuple[StepResult, ...]]:
    """SIMULATE: open a contract and apply frames in order.

    `now_ms` is one instant for every frame, or one instant per frame. The
    distinction matters: a transcript replayed entirely at its last frame's
    time sees the offer expire before the accept, which is the machine being
    right about the wrong question. Every step is returned, including the
    rejected ones, so a caller can show exactly which lines were ignored and why.
    """
    queue = list(frames)
    instants = [now_ms] * len(queue) if isinstance(now_ms, int) else list(now_ms)
    if len(instants) != len(queue):
        raise FrameError("tclk: give one instant for every frame, or a single instant")
    state = open_contract(offer)
    steps: list[StepResult] = []
    for frame, instant in zip(queue, instants, strict=True):
        step = apply_frame(state, frame, instant)
        steps.append(step)
        state = step.state
    return state, tuple(steps)


def lock_terms(state: ContractState) -> dict[str, Any]:
    """The rail-facing projection of an accepted contract. Raises before accept."""
    if not (state.contract and state.statement and state.payer_did and state.payee_did):
        raise FrameError(f"tclk: contract is not accepted yet (status {state.status})")
    return {
        "contract": state.contract,
        "lock": state.offer["lock"],
        "statement": state.statement,
        "amount": state.offer["amount"],
        "asset": state.offer["asset"],
        "payer": state.payer_did,
        "payee": state.payee_did,
        "claimByMs": state.offer["claimByMs"],
        "refundAfterMs": state.offer["refundAfterMs"],
    }


__all__ = [
    "STATUSES",
    "TERMINAL_STATUSES",
    "ContractState",
    "StepResult",
    "apply_frame",
    "fold",
    "lock_terms",
    "open_contract",
]
