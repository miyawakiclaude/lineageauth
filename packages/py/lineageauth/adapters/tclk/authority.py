"""Authority before deal: may this agent post this tclk/1 frame?

The one binding this module makes, stated once so it can be checked:

    a tclk/1 frame is a Technocore signed-lane message, so posting one is
    `technocore` / `room:<room>` / `write`, where the room is the one
    `SPEC.md` section 2 assigns to that frame type.

That is an authority LineageAuth can already express (`docs/04`), so no new
namespace, action or reason code is introduced. What LineageAuth cannot express
-- a spend ceiling, a rail allowlist, a counterparty restriction, a per-frame-
type permission -- is not silently assumed: every decision names those as
`unchecked`, and `docs/TCLK_GAP_ANALYSIS.md` says what a future scope would
have to carry to close them.

The order of checks is the order a reader must not reorder:

    1. the line decodes as a valid tclk/1 frame          (else MALFORMED / UNKNOWN_VERSION)
    2. the frame's `from` is the agent asking             (else DENIED)
    3. a lock names a rail this verifier knows            (else DENIED, fail closed)
    4. LineageAuth authority for the room write           (check_permission)

A frame that is valid tclk creates no authority (invariant 1), and authority
never rescues an invalid frame (invariant 2): step 4 is not reached unless 1-3
pass. None of this touches a rail, a wallet or the network.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from lineageauth.adapters.tclk.frames import Frame, FrameError, decode_frame, version_of_line
from lineageauth.adapters.tclk.venue import KNOWN_RAILS, room_for_frame
from lineageauth.authority import AuthorityDecision, check_permission
from lineageauth.bundle import EventBundle
from lineageauth.errors import ReasonCode

TECHNOCORE_NAMESPACE = "technocore"
WRITE = "write"

UNCHECKED_BY_LINEAGEAUTH: tuple[str, ...] = (
    "spend-limit",
    "rail-allowlist",
    "counterparty",
    "frame-type",
    "settlement",
)
"""What this decision does not evaluate. See docs/TCLK_GAP_ANALYSIS.md."""

VERIFICATION_ORDER: tuple[str, ...] = (
    "tclk/1 frame validation (structural, fail-closed)",
    "sender is the agent asking",
    "rail is one this verifier knows",
    "LineageAuth authority for the room write (this answer)",
    "exact human approval, where the chain requires one",
    "Technocore's own signed-lane verification",
    "the settlement rail's own checks -- never performed here",
)

NOT_SETTLEMENT_NOTE = (
    "This answers one question: whether the agent holds a declared authority chain "
    "to post this frame to this room. It is not tclk validity beyond structure, not "
    "Technocore's transport check, and not settlement -- a rail decides whether money "
    "moves, and nothing here can ask it to."
)


@dataclass(frozen=True, slots=True)
class RequiredAuthority:
    """The LineageAuth authority a frame needs, plus the tclk facts it carries."""

    namespace: str
    resource: str
    action: str
    room: str
    frame_type: str
    sender: str
    contract: str | None
    amount: str | None
    asset: str | None
    rails: tuple[str, ...]
    rail: str | None
    counterparty: str | None
    claim_by_ms: int | None
    refund_after_ms: int | None
    expires_ms: int | None

    def render(self) -> str:
        return f"{self.namespace}:{self.resource} [{self.action}]"


def required_authority_for(frame: Frame, *, room: str | None = None) -> RequiredAuthority:
    """Map a frame onto the authority posting it needs. `room` overrides the derived one."""
    fields = frame.fields
    target = room if room is not None else room_for_frame(frame)
    rails = fields.get("rails")
    return RequiredAuthority(
        namespace=TECHNOCORE_NAMESPACE,
        resource=f"room:{target}",
        action=WRITE,
        room=target,
        frame_type=frame.kind,
        sender=frame.sender,
        contract=frame.contract,
        amount=_opt_str(fields.get("amount")),
        asset=_opt_str(fields.get("asset")),
        rails=tuple(str(r) for r in rails) if isinstance(rails, list) else (),
        rail=_opt_str(fields.get("rail")),
        counterparty=None,  # an offer names no counterparty; accept's is the offer's from
        claim_by_ms=_opt_int(fields.get("claimByMs")),
        refund_after_ms=_opt_int(fields.get("refundAfterMs")),
        expires_ms=_opt_int(fields.get("expiresMs")),
    )


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _opt_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


@dataclass(frozen=True, slots=True)
class TclkAuthorityDecision:
    """Whether an agent may post a frame, and exactly what was and was not checked."""

    allowed: bool
    reason: ReasonCode
    detail: str
    frame: Frame | None
    required: RequiredAuthority | None
    decision: AuthorityDecision | None
    unchecked: tuple[str, ...] = UNCHECKED_BY_LINEAGEAUTH
    verification_order: tuple[str, ...] = VERIFICATION_ORDER
    note: str = NOT_SETTLEMENT_NOTE

    @property
    def approval_required(self) -> bool:
        return self.reason is ReasonCode.APPROVAL_REQUIRED

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": str(self.reason),
            "detail": self.detail,
            "frame": None
            if self.frame is None
            else {
                "type": self.frame.kind,
                "from": self.frame.sender,
                "contract": self.frame.contract,
                "line": self.frame.line,
            },
            "required": None
            if self.required is None
            else {
                "namespace": self.required.namespace,
                "resource": self.required.resource,
                "action": self.required.action,
                "room": self.required.room,
            },
            "lineage": None if self.decision is None else self.decision.lineage,
            "root": None if self.decision is None else self.decision.root,
            "epoch": None if self.decision is None else self.decision.epoch,
            "path": [] if self.decision is None else list(self.decision.path),
            "approval": None if self.decision is None else self.decision.approval.wire_name,
            "unchecked": list(self.unchecked),
            "verificationOrder": list(self.verification_order),
            "note": self.note,
        }


def _refused(reason: ReasonCode, detail: str, frame: Frame | None = None) -> TclkAuthorityDecision:
    return TclkAuthorityDecision(
        allowed=False,
        reason=reason,
        detail=detail,
        frame=frame,
        required=None if frame is None else required_authority_for(frame),
        decision=None,
    )


def verify_tclk_authority(
    bundle: EventBundle,
    *,
    lineage: str,
    agent: str,
    frame_line: str,
    at: datetime,
    room: str | None = None,
    known_rails: frozenset[str] = KNOWN_RAILS,
    external: bool = True,
) -> TclkAuthorityDecision:
    """Decide whether `agent` holds LineageAuth authority to post `frame_line`.

    Offline, deterministic for a given bundle and `at`. See the module docstring
    for the order of checks and what is deliberately left unchecked.
    """
    try:
        frame = decode_frame(frame_line)
    except FrameError as exc:
        seen = version_of_line(frame_line)
        if seen is not None and seen != "tclk/1":
            return _refused(ReasonCode.UNKNOWN_VERSION, str(exc))
        return _refused(ReasonCode.MALFORMED, str(exc))

    if frame.sender != agent:
        return _refused(
            ReasonCode.DENIED,
            f"the frame's from is {frame.sender}, not the agent asking ({agent}); a "
            "signed-lane frame must be posted by the DID it names (SPEC 2)",
            frame,
        )

    if frame.kind == "lock":
        rail = str(frame.fields["rail"])
        if rail not in known_rails:
            return _refused(
                ReasonCode.DENIED,
                f"lock names rail {rail!r}, which this verifier does not know; refusing "
                f"rather than guessing (known: {sorted(known_rails)})",
                frame,
            )

    required = required_authority_for(frame, room=room)
    decision = check_permission(
        bundle,
        lineage=lineage,
        agent=agent,
        namespace=required.namespace,
        resource=required.resource,
        action=required.action,
        at=at,
        external=external,
    )
    return TclkAuthorityDecision(
        allowed=decision.allowed,
        reason=decision.reason,
        detail=decision.detail,
        frame=frame,
        required=required,
        decision=decision,
    )


def counterparty_of(offer: Mapping[str, Any], accept: Mapping[str, Any]) -> tuple[str, str]:
    """`(payer, payee)` once an accept closes the terms."""
    if offer.get("role") == "payer":
        return str(offer["from"]), str(accept["from"])
    return str(accept["from"]), str(offer["from"])


__all__ = [
    "NOT_SETTLEMENT_NOTE",
    "TECHNOCORE_NAMESPACE",
    "UNCHECKED_BY_LINEAGEAUTH",
    "VERIFICATION_ORDER",
    "RequiredAuthority",
    "TclkAuthorityDecision",
    "counterparty_of",
    "required_authority_for",
    "verify_tclk_authority",
]
