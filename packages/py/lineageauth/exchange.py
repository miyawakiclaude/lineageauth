"""The task exchange: a listing built from signed events, and its own limits.

`docs/11_TASK_EXCHANGE.md` describes a coordination marketplace that holds no
custody and moves no money, and two of its sentences shape this module more
than the rest.

*"Protocol must expose coordinator dependency honestly."* When two agents claim
a single-claimant task, nothing cryptographic decides who was first. Timestamps
are self-asserted, so ordering by `issuedAt` would hand the task to whoever
lies best. This module therefore reports **all** competing claims and awards
none of them -- unless the requester named a coordinator in the task itself,
in which case that key's `claim.coordinate` decides and every listing says out
loud that the award rests on that key's say-so.

*"Protocol preserves signed evidence; indexing can moderate visibility."* So
moderation lives here rather than in the store, it comes from the reader rather
than from any event, and hiding is always counted in the response. A blocklist
that silently shrank the results would be indistinguishable from an exchange
with nothing in it.

The listing status is a *view*: the task's own derived status from
`resolve_task`, with `DISPUTED` layered on while a case is open and unresolved.
The underlying status is always carried alongside, because a dispute must not
be able to erase what the verifications said (D-061).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from lineageauth.bundle import EventBundle
from lineageauth.canonical import is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError
from lineageauth.jury import DISPUTE_OPEN, Outcome, read_case, resolve_dispute
from lineageauth.work import TASK_REQUEST, Claim, Task, TaskStatus, read_task, resolve_task

CLAIM_COORDINATE = "claim.coordinate"

EXCHANGE_NOTE = (
    "An exchange listing is a view over signed events. This protocol holds no "
    "custody, escrows nothing, moves no money and does not validate any reward "
    "reference -- a rewardReference points at somebody else's system and means "
    "whatever that system means by it. Nothing here is an offer or a contract."
)

CONTEST_NOTE = (
    "When more claims are live than a task allows, every competing claim is "
    "listed and none is awarded. Which one was first is not something signed "
    "events can settle: an issuedAt is self-asserted, so ordering by it would "
    "award the task to whoever backdates best."
)

COORDINATOR_NOTE = (
    "This award rests on the coordinator key the requester named in the task, "
    "and on nothing else. The signature proves that key said it; it does not "
    "make the choice fair, and this protocol has no way to check whether the "
    "coordinator applied any rule at all."
)

MODERATION_NOTE = (
    "Moderation hides listings from this response and removes nothing. The "
    "events remain in the store and remain verifiable by anyone. Hidden "
    "listings are counted here so that a filtered view is never mistaken for "
    "an empty exchange."
)


class ListingStatus(StrEnum):
    """The task's status as an exchange shows it.

    Every member of `TaskStatus` plus `DISPUTED`, which is a fact about process
    rather than about the work: it says a case is open and undecided, never
    that anybody did anything wrong.
    """

    OPEN = "OPEN"
    CLAIMED = "CLAIMED"
    CANCELLED = "CANCELLED"
    SUBMITTED = "SUBMITTED"
    VERIFIED_ACCEPTED = "VERIFIED_ACCEPTED"
    VERIFIED_REJECTED = "VERIFIED_REJECTED"
    CONTESTED = "CONTESTED"
    DISPUTED = "DISPUTED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class Moderation:
    """A reader's own filter. Never read from events, never applied to the store.

    `docs/11` puts abuse controls in the service layer and keeps the protocol's
    evidence intact. Anything here is one reader's preference, so two readers
    with different lists see different exchanges from the same bundle -- which
    is correct, and is why the response says how many were hidden.
    """

    blocked_dids: frozenset[str] = frozenset()
    blocked_tasks: frozenset[str] = frozenset()

    @classmethod
    def of(cls, *, dids: Iterable[str] = (), tasks: Iterable[str] = ()) -> Moderation:
        for did in dids:
            public_key_from_did_key(did)
        for task in tasks:
            if not is_event_id(task):
                raise MalformedEventError("a blocked task must be a sha256:<64 hex> event id")
        return cls(blocked_dids=frozenset(dids), blocked_tasks=frozenset(tasks))

    def hides(self, task: Task) -> str | None:
        """Why this listing is hidden, or None to show it."""
        if task.event_id in self.blocked_tasks:
            return "task is on the reader's blocklist"
        if task.requester in self.blocked_dids:
            return "requester is on the reader's blocklist"
        return None


@dataclass(frozen=True, slots=True)
class ClaimContest:
    """More live claims than the task allows, and who if anyone was awarded one."""

    competing: tuple[Claim, ...]
    allowed: int
    awarded_claim: str | None = None
    coordinator: str | None = None

    @property
    def is_settled(self) -> bool:
        return self.awarded_claim is not None

    @property
    def note(self) -> str:
        if self.is_settled:
            return COORDINATOR_NOTE
        return CONTEST_NOTE


@dataclass(frozen=True, slots=True)
class Listing:
    """One task as the exchange presents it."""

    task: Task
    status: ListingStatus
    task_status: TaskStatus
    """The task's own derived status, unchanged by any dispute (D-061)."""

    detail: str
    live_claims: tuple[Claim, ...]
    workers: tuple[str, ...]
    open_disputes: tuple[str, ...]
    resolved_disputes: tuple[tuple[str, str], ...]
    contest: ClaimContest | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def open_slots(self) -> int:
        return max(0, self.task.allowed_claims - len(self.live_claims))

    @property
    def is_claimable(self) -> bool:
        """Whether a fresh claim would fit. Not advice, and not a reservation.

        A multi-claimant task stays claimable while it still has a free slot,
        so `CLAIMED` counts here as well as `OPEN`: on a task that allows three
        workers, one claim does not close it. Everything past submission does
        close it -- there is nothing useful left to claim once the work is in.
        """
        return self.status in (ListingStatus.OPEN, ListingStatus.CLAIMED) and self.open_slots > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task.event_id,
            "title": self.task.title,
            "requester": self.task.requester,
            "acceptanceCriteria": list(self.task.acceptance_criteria),
            "status": str(self.status),
            "taskStatus": str(self.task_status),
            "detail": self.detail,
            "allowedClaims": self.task.allowed_claims,
            "openSlots": self.open_slots,
            "isClaimable": self.is_claimable,
            "cancellable": self.task.cancellable,
            "coordinator": self.task.coordinator,
            "rewardReference": self.task.reward_reference,
            "liveClaims": [{"claim": c.event_id, "claimant": c.claimant} for c in self.live_claims],
            "workers": list(self.workers),
            "openDisputes": list(self.open_disputes),
            "resolvedDisputes": [
                {"case": case, "outcome": outcome} for case, outcome in self.resolved_disputes
            ],
            "claimContest": (
                {
                    "competing": [
                        {"claim": c.event_id, "claimant": c.claimant}
                        for c in self.contest.competing
                    ],
                    "allowed": self.contest.allowed,
                    "awardedClaim": self.contest.awarded_claim,
                    "coordinator": self.contest.coordinator,
                    "note": self.contest.note,
                }
                if self.contest is not None
                else None
            ),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class Exchange:
    """What one reader sees, and what that reader's filter removed."""

    listings: tuple[Listing, ...]
    evaluated_at: datetime
    hidden: tuple[tuple[str, str], ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        text = EXCHANGE_NOTE
        if self.hidden:
            text = f"{text} {MODERATION_NOTE}"
        return text

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluatedAt": self.evaluated_at.isoformat().replace("+00:00", "Z"),
            "listings": [listing.to_dict() for listing in self.listings],
            "hidden": [{"task": task, "reason": reason} for task, reason in self.hidden],
            "hiddenCount": len(self.hidden),
            "warnings": list(self.warnings),
            "note": self.note,
        }


def _awarded_claim(
    bundle: EventBundle, *, lineage: str, task: Task, claim_ids: frozenset[str]
) -> tuple[str | None, list[str]]:
    """The claim the named coordinator awarded, if any, and what was refused."""
    warnings: list[str] = []
    if task.coordinator is None:
        return None, warnings

    awarded: str | None = None
    conflicting = False
    for event in bundle.of_type(CLAIM_COORDINATE, lineage=lineage):
        if event.get("task") != task.event_id:
            continue
        coordinator = event.get("coordinator")
        if not isinstance(coordinator, str) or not event.signed_by(coordinator):
            warnings.append(
                f"claim.coordinate {event.event_id} ignored: malformed or not signed by "
                "the coordinator it names"
            )
            continue
        if coordinator != task.coordinator:
            warnings.append(
                f"claim.coordinate {event.event_id} ignored: signed by {coordinator}, but "
                f"the task names {task.coordinator} as its coordinator"
            )
            continue
        claim = event.get("claim")
        if not is_event_id(claim) or str(claim) not in claim_ids:
            warnings.append(
                f"claim.coordinate {event.event_id} ignored: it awards a claim this "
                "bundle does not carry for this task"
            )
            continue
        if awarded is not None and awarded != str(claim):
            conflicting = True
            continue
        awarded = str(claim)

    if conflicting:
        # The coordinator awarded the task twice. Picking one would be this
        # module inventing the ordering it just refused to invent.
        warnings.append(
            f"the coordinator {task.coordinator} awarded more than one claim on this "
            "task; no award is applied, because choosing between them here would be "
            "exactly the ordering this layer refuses to invent"
        )
        return None, warnings
    return awarded, warnings


def _disputes_on(
    bundle: EventBundle, *, lineage: str, task_id: str, at: datetime
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    """Open and resolved cases against this task."""
    open_cases: list[str] = []
    resolved: list[tuple[str, str]] = []
    for event in bundle.of_type(DISPUTE_OPEN, lineage=lineage):
        parsed = read_case(event)
        if isinstance(parsed, str) or parsed.task != task_id:
            continue
        try:
            outcome = resolve_dispute(
                bundle, lineage=lineage, case_id=parsed.event_id, at=at
            ).outcome
        except LineageAuthError:
            continue
        if outcome is Outcome.AWAITING_VOTES:
            open_cases.append(parsed.event_id)
        else:
            resolved.append((parsed.event_id, str(outcome)))
    return tuple(sorted(open_cases)), tuple(sorted(resolved))


def build_listing(bundle: EventBundle, *, lineage: str, task_id: str, at: datetime) -> Listing:
    """Present one task as an exchange entry, disputes and contests included."""
    state = resolve_task(bundle, lineage=lineage, task_id=task_id, at=at)
    task = state.task
    warnings = list(state.warnings)

    live = state.active_claims
    contest: ClaimContest | None = None
    if len(live) > task.allowed_claims:
        awarded, award_warnings = _awarded_claim(
            bundle,
            lineage=lineage,
            task=task,
            # Live claims, not every claim ever made. `live` is what the contest
            # is between, so awarding outside it would hand the task to somebody
            # whose hold had lapsed or who had already let it go -- and the
            # coordinator is trusted to settle a contest, not to revive a claim.
            # (D-094, the same omission as the one in `work.resolve_task`.)
            claim_ids=frozenset(c.event_id for c in live),
        )
        warnings.extend(award_warnings)
        contest = ClaimContest(
            competing=live,
            allowed=task.allowed_claims,
            awarded_claim=awarded,
            coordinator=task.coordinator,
        )

    open_cases, resolved_cases = _disputes_on(bundle, lineage=lineage, task_id=task_id, at=at)

    status = ListingStatus(str(state.status))
    detail = state.detail
    if open_cases:
        # A view, not a rewrite: `task_status` still carries what the
        # verifications said, and the dispute layer never overwrites it (D-061).
        status = ListingStatus.DISPUTED
        detail = (
            f"{len(open_cases)} dispute(s) open and undecided; the task's own status "
            f"is still {state.status}"
        )

    return Listing(
        task=task,
        status=status,
        task_status=state.status,
        detail=detail,
        live_claims=live,
        workers=tuple(sorted({r.worker for r in state.results})),
        open_disputes=open_cases,
        resolved_disputes=resolved_cases,
        contest=contest,
        warnings=tuple(warnings),
    )


def browse(
    bundle: EventBundle,
    *,
    lineage: str,
    at: datetime,
    status: Sequence[str] | None = None,
    requester: str | None = None,
    claimable_only: bool = False,
    moderation: Moderation | None = None,
) -> Exchange:
    """List the tasks in a bundle, filtered the way this reader asked.

    Filters narrow what is shown and never change what anything means. The one
    filter that removes rather than narrows -- moderation -- reports what it
    removed.
    """
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")
    if requester is not None:
        public_key_from_did_key(requester)
    try:
        wanted = {ListingStatus(s) for s in status} if status else None
    except ValueError as exc:
        # A filter naming a status that does not exist is a caller mistake, not
        # an empty result. Returning nothing would read as "no such tasks".
        raise MalformedEventError(
            f"unknown listing status in filter: {exc}; "
            f"known statuses are {sorted(s.value for s in ListingStatus)}"
        ) from exc
    filter_ = moderation or Moderation()

    listings: list[Listing] = []
    hidden: list[tuple[str, str]] = []
    warnings: list[str] = list(bundle.warnings)

    for event in bundle.of_type(TASK_REQUEST, lineage=lineage):
        parsed = read_task(event)
        if isinstance(parsed, str):
            warnings.append(f"task.request {event.event_id} ignored: {parsed}")
            continue
        reason = filter_.hides(parsed)
        if reason is not None:
            hidden.append((parsed.event_id, reason))
            continue
        if requester is not None and parsed.requester != requester:
            continue
        try:
            listing = build_listing(bundle, lineage=lineage, task_id=parsed.event_id, at=at)
        except LineageAuthError as exc:
            warnings.append(f"task {parsed.event_id} could not be listed: {exc}")
            continue
        if wanted is not None and listing.status not in wanted:
            continue
        if claimable_only and not listing.is_claimable:
            continue
        listings.append(listing)

    return Exchange(
        listings=tuple(sorted(listings, key=lambda listing: listing.task.event_id)),
        evaluated_at=at,
        hidden=tuple(sorted(hidden)),
        warnings=tuple(warnings),
    )


__all__ = [
    "CONTEST_NOTE",
    "COORDINATOR_NOTE",
    "EXCHANGE_NOTE",
    "MODERATION_NOTE",
    "ClaimContest",
    "Exchange",
    "Listing",
    "ListingStatus",
    "Moderation",
    "browse",
    "build_listing",
]
