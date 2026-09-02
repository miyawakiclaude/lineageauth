"""Where tclk/1 frames live on Technocore: rooms, the state note, the capability token.

From `SPEC.md` section 2 and `src/technocore.ts` (flop-labs/tclk `81a8346`).
Pure string rules. Everything read back from any of these surfaces is untrusted:
the offer room is world-writable, the deal room is derivable by anyone who read
the board, the state note is a coordination pointer in a world-writable
namespace, and the DID note is forgeable. A signed frame verifying against a
DID is the only thing that proves anything, and it proves who wrote bytes.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from lineageauth.adapters.tclk.frames import HEX32, RAIL, Frame, FrameError
from lineageauth.adapters.tclk.machine import STATUSES

OFFER_ROOM = "tclk-offers"
"""Public offers and their acceptances. Ordinary, listed, world-writable."""

DEAL_ROOM_PREFIX = "mb-p-tclk-"
CAPABILITY_TOKEN_PREFIX = "tclk1:"  # noqa: S105 - a public note token, not a secret

# The expected rail vocabulary from SPEC 3.1. Rails are free-form ids in the
# protocol; this set is what *this* verifier is prepared to reason about.
KNOWN_RAILS: frozenset[str] = frozenset({"flop-htlc", "x402", "evm-htlc", "near-htlc"})

_RAIL_REF = re.compile(r"^[\x21-\x7e]{1,256}$")


def _contract(contract: str) -> str:
    if not isinstance(contract, str) or not HEX32.match(contract):
        raise FrameError(f"tclk: malformed contract id: {contract!r}")
    return contract


def deal_room(contract: str) -> str:
    """`mb-p-tclk-<first 16 hex of the contract id>`: signed-only, unlisted, derived.

    Not confidential. Both halves it derives from are public in `tclk-offers`.
    """
    return DEAL_ROOM_PREFIX + _contract(contract)[2:18]


def state_note(contract: str) -> tuple[str, str]:
    """`(namespace, key)` of the state-pointer note: `tclk-<2 hex>` / `<14 hex>`."""
    ident = _contract(contract)
    return f"tclk-{ident[2:4]}", ident[4:18]


def room_for_frame(frame: Frame) -> str:
    """The room a frame belongs in (SPEC 2): board for offer/accept, deal room after."""
    if frame.kind in ("offer", "accept"):
        return OFFER_ROOM
    contract = frame.contract
    if contract is None:  # pragma: no cover - every non-offer frame carries one
        raise FrameError("tclk: frame names no contract")
    return deal_room(contract)


def capability_token(rails: list[str]) -> str:
    if not rails:
        raise FrameError("tclk: capability token needs at least one rail")
    for rail in rails:
        if not RAIL.match(rail):
            raise FrameError(f"tclk: malformed rail: {rail}")
    return CAPABILITY_TOKEN_PREFIX + ",".join(rails)


def parse_capability_token(note: str) -> list[str] | None:
    """The rails a DID note advertises, or None when absent or malformed.

    Absent, empty and malformed all read as "no advertised capability" rather
    than as an empty rail set: the note is world-writable input.
    """
    if not isinstance(note, str):
        return None
    token = next((p for p in note.split() if p.startswith(CAPABILITY_TOKEN_PREFIX)), None)
    if token is None:
        return None
    rails = [r for r in token[len(CAPABILITY_TOKEN_PREFIX) :].split(",") if r]
    if not rails or not all(RAIL.match(r) for r in rails):
        return None
    return rails


def state_note_value(status: str, rail_ref: str | None = None) -> str:
    if status not in STATUSES:
        raise FrameError(f"tclk: unknown status {status!r}")
    if rail_ref is None:
        return status
    if not _RAIL_REF.match(rail_ref):
        raise FrameError("tclk: rail ref must be printable ASCII without spaces (max 256 chars)")
    return f"{status} {rail_ref}"


def parse_state_note_value(value: str) -> Mapping[str, Any] | None:
    """Parse a state-note value. None on anything malformed (world-writable input)."""
    if not isinstance(value, str):
        return None
    parts = value.split(" ")
    if len(parts) > 2 or parts[0] not in STATUSES:
        return None
    if len(parts) == 1:
        return {"status": parts[0]}
    return {"status": parts[0], "railRef": parts[1]}


__all__ = [
    "CAPABILITY_TOKEN_PREFIX",
    "DEAL_ROOM_PREFIX",
    "KNOWN_RAILS",
    "OFFER_ROOM",
    "capability_token",
    "deal_room",
    "parse_capability_token",
    "parse_state_note_value",
    "room_for_frame",
    "state_note",
    "state_note_value",
]
