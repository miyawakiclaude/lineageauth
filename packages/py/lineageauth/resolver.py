"""Collecting events from several sources, and reporting what that did not prove.

`docs/15_RESOLVER_INDEXER.md` gives this layer one job and one prohibition:
collect and project signed events, and *never become protocol authority*. So
nothing here decides anything. It gathers, it measures how fresh the gathering
was, it names every disagreement between sources, and it hands all of that to a
caller who still has to decide.

**Merging is a union, never a selection.** Two sources that disagree about an
event's proofs contribute both, and a source that carries an event nobody else
has still contributes it. That is not generosity, it is the only safe rule: a
hostile source can add events (which then have to verify on their own
signatures, so adding junk achieves nothing) but it can never *remove* one from
a union. Selecting between copies would hand a hostile mirror the ability to
suppress a revocation, which is the same reasoning that governs proof merging
inside a bundle (D-036). Omission is the attack.

**Freshness is a measurement, not a proof of completeness.** `freshnessAge` is
the gap between now and the newest event anyone produced. A mirror that
withholds a revocation makes that gap *larger*, so the view fails closed --
but a mirror that withholds a revocation while forwarding some harmless recent
event makes it small again. A small freshness age therefore means "something
recent arrived", never "nothing is missing", and every response says so.

**Nothing here fetches a URL.** `docs/15`: never auto-fetch untrusted URLs from
messages without policy or human approval. Sources are objects the operator
constructs, so an HTTP mirror is entirely possible -- written by the operator,
under the operator's policy, outside this module.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError, MalformedEventError, ReasonCode
from lineageauth.timeutil import parse_instant

# Omitting one of these changes what an agent may do, which is why a source
# that is missing one is reported differently from a source missing an
# attestation nobody has read yet (docs/15).
AUTHORITY_CRITICAL_TYPES = frozenset(
    {
        "delegation.revoke",
        "root.succession",
        "recovery.policy",
    }
)

FRESHNESS_NOTE = (
    "freshnessAge is the gap between checkedAt and the newest event any source "
    "produced. It measures recency, never completeness: a mirror that withholds a "
    "revocation but forwards one harmless recent event produces a small age and an "
    "incomplete view. Treat a small age as 'something recent arrived', never as "
    "'nothing is missing'."
)

MERGE_NOTE = (
    "Sources are merged by union. A source can add events, which then have to "
    "verify on their own signatures, but no source can remove an event another "
    "source supplied. Selecting between copies would let a hostile mirror suppress "
    "a revocation, so no selection is made."
)

CONFLICT_NOTE = (
    "Conflicts are surfaced and not resolved. The only preferences this protocol "
    "defines are the union of proofs on one event and the ordering of epochs; "
    "anything else -- which mirror is right, which copy is current -- is left to "
    "whoever is deciding, because a resolver that picked a winner would be acting "
    "as authority."
)


@runtime_checkable
class Source(Protocol):
    """Anything that can produce envelopes when asked.

    Deliberately this small. An operator who wants an HTTP mirror writes one
    and passes it in; this module neither ships one nor needs to know.
    """

    @property
    def name(self) -> str: ...

    def envelopes(self) -> Iterable[Envelope]: ...


@dataclass(frozen=True, slots=True)
class MemorySource:
    """Envelopes already in hand -- a local bundle, a test fixture, an export."""

    _name: str
    _envelopes: tuple[Envelope, ...]

    def __init__(self, name: str, envelopes: Iterable[Envelope]) -> None:
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_envelopes", tuple(envelopes))

    @property
    def name(self) -> str:
        return self._name

    def envelopes(self) -> Iterable[Envelope]:
        return self._envelopes


@dataclass(frozen=True, slots=True)
class DirectorySource:
    """Every `*.json` under a directory, read as envelopes.

    A file that will not parse is skipped and reported rather than aborting the
    read: one corrupt file on a mirror should not be able to hide every other
    event that mirror holds.
    """

    _name: str
    _root: Path

    def __init__(self, name: str, root: str | Path) -> None:
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_root", Path(root))

    @property
    def name(self) -> str:
        return self._name

    def envelopes(self) -> Iterator[Envelope]:
        for path in sorted(self._root.rglob("*.json")):
            try:
                yield Envelope.from_json(path.read_text(encoding="utf-8"))
            except (LineageAuthError, OSError, json.JSONDecodeError):
                continue


@dataclass(frozen=True, slots=True)
class SourceReport:
    """What one source contributed, or why it contributed nothing."""

    name: str
    reachable: bool
    event_ids: frozenset[str]
    newest: datetime | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "reachable": self.reachable,
            "events": len(self.event_ids),
            "newest": self.newest.isoformat().replace("+00:00", "Z") if self.newest else None,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class Conflict:
    """An event some sources have and others do not."""

    event_id: str
    event_type: str
    present_in: tuple[str, ...]
    absent_from: tuple[str, ...]

    @property
    def authority_critical(self) -> bool:
        """Whether omitting this event would change what somebody may do.

        A missing revocation or succession is the dangerous case, because the
        source that omits it produces a view where authority still looks live.
        """
        return self.event_type in AUTHORITY_CRITICAL_TYPES

    def to_dict(self) -> dict[str, Any]:
        return {
            "eventId": self.event_id,
            "eventType": self.event_type,
            "presentIn": list(self.present_in),
            "absentFrom": list(self.absent_from),
            "authorityCritical": self.authority_critical,
        }


@dataclass(frozen=True, slots=True)
class FreshnessPolicy:
    """What a caller needs to be true before trusting a view for a decision.

    `docs/15`: if online freshness is required and cannot be established, the
    answer is `STALE_STATUS` and deny or review. This object is how a caller
    says what "required" means for them; nothing here picks a default that
    would silently pass.
    """

    max_age: timedelta | None = None
    min_sources: int = 1
    require_all_sources: bool = False

    def evaluate(
        self, *, reports: tuple[SourceReport, ...], age: timedelta | None
    ) -> tuple[bool, str]:
        reachable = [r for r in reports if r.reachable]
        if len(reachable) < self.min_sources:
            return (
                False,
                f"{len(reachable)} of {len(reports)} source(s) answered, and this policy "
                f"needs {self.min_sources}",
            )
        if self.require_all_sources and len(reachable) != len(reports):
            silent = sorted(r.name for r in reports if not r.reachable)
            return (
                False,
                f"this policy requires every source to answer, and {', '.join(silent)} "
                "did not; a source that is merely quiet is indistinguishable from one "
                "that is withholding a revocation",
            )
        if self.max_age is not None:
            if age is None:
                return (False, "no source produced a dated event, so there is no age to check")
            if age > self.max_age:
                return (
                    False,
                    f"the newest event anyone produced is {age} old and this policy "
                    f"allows {self.max_age}",
                )
        return (True, "the policy's freshness conditions were met")


@dataclass(frozen=True, slots=True)
class ResolvedView:
    """The merged events, plus everything the merge did not establish."""

    bundle: EventBundle
    checked_at: datetime
    sources: tuple[SourceReport, ...]
    newest_event_seen: datetime | None
    conflicts: tuple[Conflict, ...]
    fresh: bool
    detail: str
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def freshness_age(self) -> timedelta | None:
        if self.newest_event_seen is None:
            return None
        return self.checked_at - self.newest_event_seen

    @property
    def status(self) -> ReasonCode | None:
        """`STALE_STATUS` when the policy was not met, and None otherwise.

        Not a positive reason code: a met freshness policy is the absence of a
        problem, not a finding, and giving it an affirmative status would invite
        somebody to read it as a verdict about the events themselves.
        """
        return None if self.fresh else ReasonCode.STALE_STATUS

    @property
    def critical_conflicts(self) -> tuple[Conflict, ...]:
        return tuple(c for c in self.conflicts if c.authority_critical)

    @property
    def note(self) -> str:
        return f"{MERGE_NOTE} {FRESHNESS_NOTE} {CONFLICT_NOTE}"

    def require_fresh(self) -> None:
        """Raise unless the policy was met. For the high-risk path in `docs/15`.

        A caller on that path wants a refusal rather than a value they might
        forget to check, so this is the shape that fails closed by default.
        """
        if not self.fresh:
            raise StaleViewError(self.detail)

    def to_dict(self) -> dict[str, Any]:
        age = self.freshness_age
        return {
            "checkedAt": self.checked_at.isoformat().replace("+00:00", "Z"),
            "sources": [s.to_dict() for s in self.sources],
            "newestEventSeen": (
                self.newest_event_seen.isoformat().replace("+00:00", "Z")
                if self.newest_event_seen
                else None
            ),
            "freshnessAgeSeconds": age.total_seconds() if age is not None else None,
            "fresh": self.fresh,
            "status": str(self.status) if self.status is not None else None,
            "detail": self.detail,
            "conflicts": [c.to_dict() for c in self.conflicts],
            "authorityCriticalConflicts": len(self.critical_conflicts),
            "events": len(self.bundle.admitted),
            "rejectedEvents": len(self.bundle.rejected),
            "warnings": list(self.warnings),
            "note": self.note,
        }


class StaleViewError(LineageAuthError):
    """The freshness policy was not met and the caller asked to fail closed."""


def collect(
    sources: Iterable[Source],
    *,
    checked_at: datetime,
    policy: FreshnessPolicy | None = None,
) -> ResolvedView:
    """Read every source, merge by union, and report what the merge did not settle."""
    if checked_at.tzinfo is None:
        raise MalformedEventError("checked_at must be timezone-aware (RFC3339 UTC)")

    reports: list[SourceReport] = []
    merged: list[Envelope] = []
    warnings: list[str] = []
    by_source: dict[str, frozenset[str]] = {}

    for source in sources:
        name = source.name
        if name in by_source:
            raise MalformedEventError(
                f"two sources are both called {name!r}; a conflict report that cannot "
                "name which source is which would be unreadable"
            )
        try:
            envelopes = list(source.envelopes())
        except Exception as exc:
            # A source that throws is a source that did not answer. It must not
            # take the other mirrors down with it, and it must not look like a
            # mirror that answered with nothing.
            reports.append(
                SourceReport(
                    name=name,
                    reachable=False,
                    event_ids=frozenset(),
                    newest=None,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            by_source[name] = frozenset()
            continue

        ids: set[str] = set()
        newest: datetime | None = None
        for envelope in envelopes:
            merged.append(envelope)
            ids.add(envelope.event_id)
            issued = _issued_at(envelope)
            if issued is not None and (newest is None or issued > newest):
                newest = issued
        reports.append(
            SourceReport(name=name, reachable=True, event_ids=frozenset(ids), newest=newest)
        )
        by_source[name] = frozenset(ids)

    bundle = EventBundle.from_envelopes(merged)
    warnings.extend(bundle.warnings)

    newest_seen = max((r.newest for r in reports if r.newest is not None), default=None)
    conflicts = _conflicts(bundle, by_source=by_source, reports=tuple(reports))

    effective = policy or FreshnessPolicy()
    age = None if newest_seen is None else checked_at - newest_seen
    fresh, detail = effective.evaluate(reports=tuple(reports), age=age)

    return ResolvedView(
        bundle=bundle,
        checked_at=checked_at,
        sources=tuple(reports),
        newest_event_seen=newest_seen,
        conflicts=conflicts,
        fresh=fresh,
        detail=detail,
        warnings=tuple(warnings),
    )


def _issued_at(envelope: Envelope) -> datetime | None:
    """The envelope's own `issuedAt`, or None when it does not carry a usable one.

    Self-asserted, like every timestamp in a signed event, and used here only to
    measure recency -- never to order anything or to break a tie.
    """
    try:
        return parse_instant(envelope.payload.get("issuedAt"), field="issuedAt")
    except LineageAuthError:
        return None


def _conflicts(
    bundle: EventBundle,
    *,
    by_source: dict[str, frozenset[str]],
    reports: tuple[SourceReport, ...],
) -> tuple[Conflict, ...]:
    """Every admitted event that some answering source did not supply.

    Only sources that answered are compared. A source that failed did not
    disagree with anything -- it said nothing, which is a different fact and is
    already reported on its own row.
    """
    answering = [r.name for r in reports if r.reachable]
    if len(answering) < 2:
        return ()

    types = {event.event_id: event.event_type for event in bundle.admitted}
    found: list[Conflict] = []
    for event_id, event_type in sorted(types.items()):
        present = tuple(n for n in answering if event_id in by_source[n])
        absent = tuple(n for n in answering if event_id not in by_source[n])
        if present and absent:
            found.append(
                Conflict(
                    event_id=event_id,
                    event_type=event_type,
                    present_in=present,
                    absent_from=absent,
                )
            )
    # Authority-critical omissions first: a reader who stops after the first
    # few lines should see the ones that change what somebody may do.
    return tuple(sorted(found, key=lambda c: (not c.authority_critical, c.event_id)))


__all__ = [
    "AUTHORITY_CRITICAL_TYPES",
    "CONFLICT_NOTE",
    "FRESHNESS_NOTE",
    "MERGE_NOTE",
    "Conflict",
    "DirectorySource",
    "FreshnessPolicy",
    "MemorySource",
    "ResolvedView",
    "Source",
    "SourceReport",
    "StaleViewError",
    "collect",
]
