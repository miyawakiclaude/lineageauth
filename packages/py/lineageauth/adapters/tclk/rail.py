"""The settlement-rail boundary, and the side of it this package stays on.

`SPEC.md` section 5 defines a rail as `lock / verifyLock / claim / refund`.
Three of those move or release value. None of them exists here. What a
LineageAuth reader may do with a rail is *look*: ask whether a reference is
well-formed for that rail, and ask the rail what it holds under it. Both are
reads, and a `Protocol` with no `lock`, `claim`, `refund` or `sign` member is
the type-level statement that nothing in this package can be handed a rail and
made to spend through it.

There is no rail implementation here either, not even the reference's
`MemoryRail`, because a rail that enforces claim/refund predicates in-process is
a rehearsal of value movement, and `docs/TCLK_INTEGRATION.md` promises none.

`refuse_value_movement` is what any code path that finds itself about to
lock, claim, refund or reveal calls instead. It always raises.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import NoReturn, Protocol

FORBIDDEN_OPERATIONS: frozenset[str] = frozenset(
    {"lock", "claim", "refund", "reveal", "sign", "pay", "send", "publish"}
)


class SettlementRailView(Protocol):
    """Read-only view of a rail. Deliberately has no value-moving members."""

    @property
    def id(self) -> str: ...

    def validate_reference(self, ref: str) -> bool:
        """Is `ref` well-formed for this rail? Says nothing about what it holds."""
        ...

    def inspect(self, ref: str) -> Mapping[str, object] | None:
        """What the rail reports under `ref`, as untrusted data, or None."""
        ...


def refuse_value_movement(operation: str) -> NoReturn:
    """Fail closed. Every path that would move value ends here."""
    raise NotImplementedError(
        f"External tclk execution intentionally disabled: {operation!r} would move or "
        "release value, and this integration is read-only (docs/TCLK_INTEGRATION.md)"
    )


__all__ = ["FORBIDDEN_OPERATIONS", "SettlementRailView", "refuse_value_movement"]
