"""A count of the network attempts a process actually made.

The console's header says "no keys held, 0 network writes performed". That zero
used to be a literal in three files, which is the shape of claim `MEMORY.md`
warns about: a setting that exists is not a setting that works, and a hardcoded
zero keeps saying zero on the day it stops being true. The executor already
reports how many attempts it made, so the number can be counted instead of
asserted -- and then a zero on the screen is a measurement.

Simulated attempts are counted apart from performed ones. `SimulationTransport`
resolves no name and opens no socket, so an attempt that reached it is not a
network write; folding the two totals together would lose exactly the
distinction the number exists to draw.
"""

from __future__ import annotations

from typing import Any


class NetworkWriteMeter:
    """What this process observed. Counts up, never down, and starts at zero."""

    __slots__ = ("_performed", "_simulated")

    def __init__(self) -> None:
        self._performed = 0
        self._simulated = 0

    @property
    def performed(self) -> int:
        return self._performed

    @property
    def simulated(self) -> int:
        return self._simulated

    def observe(self, attempts: int, *, simulation: bool) -> None:
        if attempts <= 0:
            return
        if simulation:
            self._simulated += attempts
        else:  # pragma: no cover - no executable official endpoint exists to reach this
            self._performed += attempts

    def to_dict(self) -> dict[str, Any]:
        return {
            "networkWritesPerformed": self._performed,
            "simulatedAttempts": self._simulated,
            "measured": True,
            "note": (
                "Counted from what the executor reported in this process, not asserted. "
                "A simulated attempt reaches a reserved .invalid origin and opens no socket."
            ),
        }


__all__ = ["NetworkWriteMeter"]
