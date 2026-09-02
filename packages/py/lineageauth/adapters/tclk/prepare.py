"""PREPARE: the exact bytes, the exact destination, the exact authority -- and stop.

Mirrors `lineageauth.adapters.technocore.prepare` for one specific text: a
tclk/1 frame line. The value of stopping here is the same as there. The
`ActionRequest` produced is the object an exact-action approval binds to, so
the human sees the frame that would be posted, the receipt commits to a hash of
those bytes, and a byte changed after approval is a different action.

Which bytes are hashed, as `docs/06` requires every adapter to state: the frame
line itself, after Technocore's single-line sweep. A canonical frame line is
printable ASCII, so the sweep is the identity -- and that is asserted, not
assumed, because a sweep that changed a frame would change its id.

No signer is needed. Without one this returns the canonical signing challenge
(`<room>|<nonce>|<line>`) for the caller to sign wherever its key lives, the
same shape the reference MCP server returns when it holds no key. With a signer
it also returns the full `PreparedWrite`, still unsent. There is no send.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn

from lineageauth.actions import ActionRequest
from lineageauth.adapters.tclk.authority import RequiredAuthority, required_authority_for
from lineageauth.adapters.tclk.frames import Frame, FrameError, decode_frame, encode_frame
from lineageauth.adapters.tclk.rail import refuse_value_movement
from lineageauth.adapters.technocore.prepare import PreparedWrite, prepare_signed_message
from lineageauth.adapters.technocore.routes import SERVICE_ORIGIN
from lineageauth.adapters.technocore.text import build_signed_message, sweep
from lineageauth.crypto import LocalSigner
from lineageauth.errors import MalformedEventError

MODE_READ_ONLY = "read-only"
MODE_SIMULATE = "simulate"
MODE_PREPARE = "prepare"
MODES: tuple[str, ...] = (MODE_READ_ONLY, MODE_SIMULATE, MODE_PREPARE)
"""There is no publish mode. `publish()` below exists only to refuse."""


@dataclass(frozen=True, slots=True)
class PreparedFrame:
    """Everything needed to post a frame, and nothing that posts it."""

    frame: Frame
    room: str
    destination: str
    request: ActionRequest
    required: RequiredAuthority
    signing_challenge: str | None
    """`<room>|<nonce>|<line>` when a nonce was given; sign this with the DID's key."""
    prepared_write: PreparedWrite | None
    """The full GET-lane write when a signer was given. Not sent."""

    def preview(self) -> str:
        """What a human should be shown before consenting to this exact frame."""
        f = self.frame
        lines = [
            "tclk/1 frame (NOT SENT)",
            f"  type         {f.kind}",
            f"  from         {f.sender}",
            f"  contract     {f.contract or '-'}",
            f"  room         {self.room}",
            f"  destination  {self.destination}",
            f"  line         {f.line}",
            f"  contentHash  {self.request.content_hash}",
            f"  requestHash  {self.request.request_hash}",
            f"  authority    {self.required.render()}",
        ]
        if self.required.amount is not None:
            lines.append(f"  amount       {self.required.amount} {self.required.asset}")
        if self.required.rails:
            lines.append(f"  rails        {', '.join(self.required.rails)}")
        if self.required.rail is not None:
            lines.append(f"  rail         {self.required.rail}")
        if self.signing_challenge is not None:
            lines.append(f"  sign         {self.signing_challenge}")
        lines.append("  NOTE         authority to post is not settlement; no rail is touched")
        return "\n".join(lines)


def prepare_frame(
    frame: Frame | str,
    *,
    room: str | None = None,
    nonce: int | None = None,
    signer: LocalSigner | None = None,
    origin: str = SERVICE_ORIGIN,
) -> PreparedFrame:
    """Build -- but never send -- the Technocore write that would carry a frame."""
    parsed = decode_frame(frame) if isinstance(frame, str) else frame
    if encode_frame(parsed.fields) != parsed.line:  # pragma: no cover - Frame invariant
        raise FrameError("tclk: frame line is not the canonical encoding of its fields")

    required = required_authority_for(parsed, room=room)
    target = required.room
    if sweep(parsed.line) != parsed.line:
        raise MalformedEventError(
            "tclk: the frame line would be altered by Technocore's sweep; a canonical "
            "frame is printable ASCII and this one is not"
        )
    if signer is not None and signer.did != parsed.sender:
        raise MalformedEventError(
            f"tclk: the signer is {signer.did} but the frame's from is {parsed.sender}; "
            "a frame must be posted by the DID it names"
        )

    request = ActionRequest.over_bytes(
        namespace=required.namespace,
        resource=required.resource,
        action=required.action,
        destination=f"{origin}/r/{target}",
        content=parsed.line.encode(),
    )
    challenge: str | None = None
    write: PreparedWrite | None = None
    if nonce is not None:
        message = build_signed_message(room=target, nonce=nonce, text=parsed.line)
        challenge = message.signing_bytes.decode()
        if signer is not None:
            write = prepare_signed_message(
                room=target, text=parsed.line, nonce=nonce, signer=signer, origin=origin
            )
            if write.request.content_hash != request.content_hash:  # pragma: no cover
                raise MalformedEventError("tclk: prepared write hashes different bytes")
    return PreparedFrame(
        frame=parsed,
        room=target,
        destination=request.destination,
        request=request,
        required=required,
        signing_challenge=challenge,
        prepared_write=write,
    )


def publish(*_args: object, **_kwargs: object) -> NoReturn:
    """Deliberately unimplemented. See `docs/TCLK_INTEGRATION.md`."""
    refuse_value_movement("publish")


__all__ = [
    "MODES",
    "MODE_PREPARE",
    "MODE_READ_ONLY",
    "MODE_SIMULATE",
    "PreparedFrame",
    "prepare_frame",
    "publish",
]
