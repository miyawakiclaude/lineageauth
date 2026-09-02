"""tclk/1 status onto the lifecycles other protocols speak (`SPEC.md` section 6).

Total, pure mappings, ported from `src/interop.ts`. A tclk contract is the
*payment leg* of a job defined elsewhere; these say how its status reads to an
A2A client or a Virtuals ACP participant watching that job. Neither mapping is
execution proof -- `locked` means funds were announced as locked, `claimed`
means a secret opened a statement, and nothing here says any work was done.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from lineageauth.adapters.tclk.frames import FrameError

A2A_STATES: Mapping[str, str] = {
    "proposed": "submitted",
    "accepted": "submitted",
    "locked": "working",
    "claimed": "completed",
    "refunded": "failed",
    "cancelled": "canceled",
}

ACP_PHASES: Mapping[str, str] = {
    "proposed": "request",
    "accepted": "negotiation",
    "locked": "transaction",
    "claimed": "completed",
    "refunded": "rejected",
    "cancelled": "rejected",
}


def tclk_status_to_a2a(status: str) -> str:
    try:
        return A2A_STATES[status]
    except KeyError as exc:
        raise FrameError(f"tclk: unknown status {status!r}") from exc


def tclk_status_to_acp_phase(status: str) -> str:
    try:
        return ACP_PHASES[status]
    except KeyError as exc:
        raise FrameError(f"tclk: unknown status {status!r}") from exc


def job_reference(offer: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The external job an offer binds to, as data. Not resolved, not fetched."""
    job = offer.get("job")
    return dict(job) if isinstance(job, Mapping) else None


__all__ = [
    "A2A_STATES",
    "ACP_PHASES",
    "job_reference",
    "tclk_status_to_a2a",
    "tclk_status_to_acp_phase",
]
