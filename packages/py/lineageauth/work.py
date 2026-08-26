"""Proof of useful work: a task's state, derived from signed events.

`docs/08_USEFUL_WORK.md` sets the goal as representing useful work "as an
evidence chain rather than message count", and then spends its last section
listing the ways a naive implementation gets gamed. Both halves are load-bearing
here.

The state is derived, never stored:

    task.request -> task.claim -> task.result -> task.verify -> work.receipt

`TaskState` is computed from whatever signed events a bundle carries, at a
stated time. There is no field anyone writes to say a task is done; a task is
accepted because a verification says so, and if the verification is withdrawn
from the bundle the task is not accepted any more.

*Never mint points.* A `WorkReceipt` is a portable summary of signed inputs and
carries no number that could be added up. `docs/08` is explicit, and the reason
is that any score in the core becomes the thing people optimise instead of the
work.

*Say who is independent.* Self-created tasks and same-key verifications are not
equivalent to independent work, so `WorkReceipt` reports the relationship
signals -- whether the requester and the worker are the same key, whether a
verifier is also the worker, how many distinct independent verifiers there are,
and whether a verifier pair keeps verifying each other. It reports them; it does
not weight them. `docs/08` says rankers may use these transparently, which means
handing over the signals rather than an answer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import b64u_decode, is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError
from lineageauth.timeutil import format_instant, parse_instant

TASK_REQUEST = "task.request"
TASK_CLAIM = "task.claim"
TASK_RELEASE = "task.release"
TASK_RESULT = "task.result"
TASK_VERIFY = "task.verify"

ACCEPTED = "accepted"
REJECTED = "rejected"

WORK_NOTE = (
    "A work receipt summarises signed events. It carries no score, because any "
    "number in the core becomes the thing people optimise instead of the work. "
    "An accepted verdict is one verifier's opinion that the criteria were met, "
    "not a finding that the work is good."
)


class TaskStatus(StrEnum):
    """Derived state. Nobody writes this; it is read off the events."""

    OPEN = "OPEN"
    CLAIMED = "CLAIMED"
    SUBMITTED = "SUBMITTED"
    VERIFIED_ACCEPTED = "VERIFIED_ACCEPTED"
    VERIFIED_REJECTED = "VERIFIED_REJECTED"
    CONTESTED = "CONTESTED"
    EXPIRED = "EXPIRED"


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _as_did(value: Any) -> str | None:
    text = _as_str(value)
    if text is None:
        return None
    try:
        public_key_from_did_key(text)
    except LineageAuthError:
        return None
    return text


@dataclass(frozen=True, slots=True)
class Task:
    event_id: str
    requester: str
    title: str
    acceptance_criteria: tuple[str, ...]
    allowed_claims: int
    deadline: datetime | None
    reward_reference: str | None
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class Claim:
    event_id: str
    task: str
    claimant: str
    expires_at: datetime
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class Result:
    event_id: str
    task: str
    claim: str
    worker: str
    artifact_refs: tuple[str, ...]
    summary: str
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class Verification:
    event_id: str
    task: str
    result: str
    verifier: str
    verdict: str
    criteria_results: tuple[tuple[str, bool], ...]
    issued_at: datetime

    @property
    def accepted(self) -> bool:
        return self.verdict == ACCEPTED


def read_task(event: AdmittedEvent) -> Task | str:
    """Validate a `task.request` payload, returning it or a complaint."""
    requester = _as_did(event.get("requester"))
    if requester is None:
        return "requester must be a usable Ed25519 did:key"
    if not event.signed_by(requester):
        return f"not signed by the requester it names ({requester})"

    title = _as_str(event.get("title"))
    if not title:
        return "title must be a non-empty string"

    raw_criteria = event.get("acceptanceCriteria")
    if not isinstance(raw_criteria, list) or not raw_criteria:
        return (
            "acceptanceCriteria must be a non-empty array; without them a "
            "verification is an opinion about nothing in particular"
        )
    criteria: list[str] = []
    for item in raw_criteria:
        text = _as_str(item)
        if not text:
            return "every acceptance criterion must be a non-empty string"
        criteria.append(text)

    allowed = event.get("allowedClaims")
    if isinstance(allowed, bool) or not isinstance(allowed, int) or allowed < 1:
        return "allowedClaims must be an integer of at least 1"

    deadline: datetime | None = None
    if event.get("deadline") is not None:
        try:
            deadline = parse_instant(event.get("deadline"), field="deadline")
        except MalformedEventError as exc:
            return str(exc)

    reward = event.get("rewardReference")
    if reward is not None and not isinstance(reward, str):
        return "rewardReference must be an opaque string when present"

    return Task(
        event_id=event.event_id,
        requester=requester,
        title=title,
        acceptance_criteria=tuple(criteria),
        allowed_claims=allowed,
        deadline=deadline,
        reward_reference=reward,
        issued_at=event.issued_at,
    )


def read_claim(event: AdmittedEvent) -> Claim | str:
    task = event.get("task")
    if not is_event_id(task):
        return "task must be the event id of a task.request"
    claimant = _as_did(event.get("claimant"))
    if claimant is None:
        return "claimant must be a usable Ed25519 did:key"
    if not event.signed_by(claimant):
        return f"not signed by the claimant it names ({claimant})"
    nonce = event.get("nonce")
    if not isinstance(nonce, str):
        return "nonce must be a base64url string"
    try:
        b64u_decode(nonce)
    except MalformedEventError as exc:
        return f"nonce is not canonical unpadded base64url: {exc}"
    try:
        expires_at = parse_instant(event.get("expiresAt"), field="expiresAt")
    except MalformedEventError as exc:
        return str(exc)
    return Claim(
        event_id=event.event_id,
        task=str(task),
        claimant=claimant,
        expires_at=expires_at,
        issued_at=event.issued_at,
    )


def read_result(event: AdmittedEvent) -> Result | str:
    task, claim = event.get("task"), event.get("claim")
    if not is_event_id(task) or not is_event_id(claim):
        return "task and claim must both be event ids"
    worker = _as_did(event.get("worker"))
    if worker is None:
        return "worker must be a usable Ed25519 did:key"
    if not event.signed_by(worker):
        return f"not signed by the worker it names ({worker})"
    raw_refs = event.get("artifactRefs")
    if not isinstance(raw_refs, list) or not raw_refs:
        return "artifactRefs must be a non-empty array of content ids"
    refs: list[str] = []
    for ref in raw_refs:
        if not is_event_id(ref):
            return "every artifactRef must be a sha256:<64 lowercase hex> id"
        refs.append(str(ref))
    summary = _as_str(event.get("summary"))
    if not summary:
        return "summary must be a non-empty string"
    return Result(
        event_id=event.event_id,
        task=str(task),
        claim=str(claim),
        worker=worker,
        artifact_refs=tuple(sorted(set(refs))),
        summary=summary,
        issued_at=event.issued_at,
    )


def read_verification(event: AdmittedEvent) -> Verification | str:
    task, result = event.get("task"), event.get("result")
    if not is_event_id(task) or not is_event_id(result):
        return "task and result must both be event ids"
    verifier = _as_did(event.get("verifier"))
    if verifier is None:
        return "verifier must be a usable Ed25519 did:key"
    if not event.signed_by(verifier):
        return f"not signed by the verifier it names ({verifier})"
    verdict = _as_str(event.get("verdict"))
    if verdict not in (ACCEPTED, REJECTED):
        return f"verdict must be {ACCEPTED!r} or {REJECTED!r}, got {verdict!r}"
    raw_results = event.get("criteriaResults")
    criteria: list[tuple[str, bool]] = []
    if raw_results is not None:
        if not isinstance(raw_results, dict):
            return "criteriaResults must be an object of criterion -> boolean"
        for key, value in sorted(raw_results.items()):
            if not isinstance(value, bool):
                return "every criteriaResults value must be a boolean"
            criteria.append((str(key), value))
    return Verification(
        event_id=event.event_id,
        task=str(task),
        result=str(result),
        verifier=verifier,
        verdict=str(verdict),
        criteria_results=tuple(criteria),
        issued_at=event.issued_at,
    )


# ------------------------------------------------------------------ signals


@dataclass(frozen=True, slots=True)
class RelationshipSignals:
    """What `docs/08` asks to be exposed, without weighting any of it.

    These are the shapes that make a count of "completed tasks" misleading. They
    are reported so a ranker can use them transparently -- and so a reader can
    see them even when nobody ranks anything.
    """

    requester_is_worker: bool
    self_verified: bool
    independent_verifiers: tuple[str, ...]
    non_independent_verifiers: tuple[str, ...]
    reciprocal_verifier_pairs: tuple[str, ...]

    @property
    def has_independent_verification(self) -> bool:
        return bool(self.independent_verifiers)


@dataclass(frozen=True, slots=True)
class TaskState:
    """A task's derived state and the events behind it."""

    task: Task
    status: TaskStatus
    detail: str
    evaluated_at: datetime
    claims: tuple[Claim, ...] = ()
    released_claims: tuple[str, ...] = ()
    results: tuple[Result, ...] = ()
    verifications: tuple[Verification, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def active_claims(self) -> tuple[Claim, ...]:
        return tuple(
            c
            for c in self.claims
            if c.event_id not in self.released_claims and self.evaluated_at < c.expires_at
        )


@dataclass(frozen=True, slots=True)
class WorkReceipt:
    """A portable summary of one task's evidence chain.

    Derived, never signed as a fact of its own: everything here comes from the
    events, so a reader can recompute it. There is deliberately no score.
    """

    task_id: str
    title: str
    requester: str
    status: TaskStatus
    worker: str | None
    artifact_refs: tuple[str, ...]
    accepted_by: tuple[str, ...]
    rejected_by: tuple[str, ...]
    criteria_met: tuple[str, ...]
    criteria_unmet: tuple[str, ...]
    signals: RelationshipSignals
    evaluated_at: datetime
    reward_reference: str | None = None
    event_refs: tuple[str, ...] = ()

    @property
    def note(self) -> str:
        return WORK_NOTE

    def to_dict(self) -> dict[str, Any]:
        return {
            "taskId": self.task_id,
            "title": self.title,
            "requester": self.requester,
            "status": str(self.status),
            "worker": self.worker,
            "artifactRefs": list(self.artifact_refs),
            "acceptedBy": list(self.accepted_by),
            "rejectedBy": list(self.rejected_by),
            "criteriaMet": list(self.criteria_met),
            "criteriaUnmet": list(self.criteria_unmet),
            "signals": {
                "requesterIsWorker": self.signals.requester_is_worker,
                "selfVerified": self.signals.self_verified,
                "independentVerifiers": list(self.signals.independent_verifiers),
                "nonIndependentVerifiers": list(self.signals.non_independent_verifiers),
                "reciprocalVerifierPairs": list(self.signals.reciprocal_verifier_pairs),
                "hasIndependentVerification": self.signals.has_independent_verification,
            },
            # An external reference and nothing more. The core escrows nothing,
            # pays nothing, and validates no token value.
            "rewardReference": self.reward_reference,
            "evaluatedAt": format_instant(self.evaluated_at),
            "eventRefs": list(self.event_refs),
            "note": self.note,
        }


def _reciprocal_pairs(bundle: EventBundle, *, lineage: str) -> dict[str, set[str]]:
    """Who has verified whose work, across the whole bundle.

    Needed to spot a pair that keeps verifying each other, which is the cheapest
    way to manufacture the appearance of independent review.
    """
    workers: dict[str, str] = {}
    for event in bundle.of_type(TASK_RESULT, lineage=lineage):
        parsed = read_result(event)
        if not isinstance(parsed, str):
            workers[parsed.event_id] = parsed.worker

    verified: dict[str, set[str]] = {}
    for event in bundle.of_type(TASK_VERIFY, lineage=lineage):
        parsed_verification = read_verification(event)
        if isinstance(parsed_verification, str):
            continue
        worker = workers.get(parsed_verification.result)
        if worker is not None:
            verified.setdefault(parsed_verification.verifier, set()).add(worker)
    return verified


def resolve_task(bundle: EventBundle, *, lineage: str, task_id: str, at: datetime) -> TaskState:
    """Derive one task's state from the signed events in a bundle."""
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")
    if not is_event_id(task_id):
        raise MalformedEventError(f"task id must be sha256:<64 lowercase hex>, got {task_id!r}")

    warnings: list[str] = []
    request: Task | None = None
    for event in bundle.of_type(TASK_REQUEST, lineage=lineage):
        if event.event_id != task_id:
            continue
        parsed = read_task(event)
        if isinstance(parsed, str):
            raise MalformedEventError(f"task.request {task_id} is not usable: {parsed}")
        request = parsed
    if request is None:
        raise MalformedEventError(f"this bundle carries no task.request with id {task_id}")

    claims: list[Claim] = []
    for event in bundle.of_type(TASK_CLAIM, lineage=lineage):
        parsed_claim = read_claim(event)
        if isinstance(parsed_claim, str):
            warnings.append(f"task.claim {event.event_id} ignored: {parsed_claim}")
            continue
        if parsed_claim.task == task_id:
            claims.append(parsed_claim)

    claim_ids = {c.event_id for c in claims}
    by_claimant = {c.event_id: c.claimant for c in claims}
    released: list[str] = []
    for event in bundle.of_type(TASK_RELEASE, lineage=lineage):
        target = event.get("claim")
        claimant = _as_did(event.get("claimant"))
        if not is_event_id(target) or claimant is None or not event.signed_by(claimant):
            warnings.append(f"task.release {event.event_id} ignored: malformed or unsigned")
            continue
        if str(target) not in claim_ids:
            continue
        if by_claimant.get(str(target)) != claimant:
            # Only the holder may hand a claim back. Otherwise anyone could
            # free a task out from under whoever is working on it.
            warnings.append(
                f"task.release {event.event_id} ignored: {claimant} does not hold that claim"
            )
            continue
        released.append(str(target))

    results: list[Result] = []
    for event in bundle.of_type(TASK_RESULT, lineage=lineage):
        parsed_result = read_result(event)
        if isinstance(parsed_result, str):
            warnings.append(f"task.result {event.event_id} ignored: {parsed_result}")
            continue
        if parsed_result.task != task_id:
            continue
        if parsed_result.claim not in claim_ids:
            warnings.append(
                f"task.result {parsed_result.event_id} ignored: cites claim "
                f"{parsed_result.claim}, which this bundle does not carry for this task"
            )
            continue
        if by_claimant.get(parsed_result.claim) != parsed_result.worker:
            # Submitting against somebody else's claim would let a worker
            # borrow a claim they never made.
            warnings.append(
                f"task.result {parsed_result.event_id} ignored: the claim it cites is "
                f"held by {by_claimant.get(parsed_result.claim)}, not by "
                f"{parsed_result.worker}"
            )
            continue
        results.append(parsed_result)

    result_ids = {r.event_id for r in results}
    verifications: list[Verification] = []
    for event in bundle.of_type(TASK_VERIFY, lineage=lineage):
        parsed_verification = read_verification(event)
        if isinstance(parsed_verification, str):
            warnings.append(f"task.verify {event.event_id} ignored: {parsed_verification}")
            continue
        if parsed_verification.task != task_id or parsed_verification.result not in result_ids:
            continue
        verifications.append(parsed_verification)

    status, detail = _derive_status(request, claims, released, results, verifications, at=at)
    if len(claims) > request.allowed_claims:
        warnings.append(
            f"{len(claims)} claims exist but the task allows {request.allowed_claims}; "
            "which claim wins is a coordination question this protocol does not settle"
        )

    return TaskState(
        task=request,
        status=status,
        detail=detail,
        evaluated_at=at,
        claims=tuple(sorted(claims, key=lambda c: c.event_id)),
        released_claims=tuple(sorted(set(released))),
        results=tuple(sorted(results, key=lambda r: r.event_id)),
        verifications=tuple(sorted(verifications, key=lambda v: v.event_id)),
        warnings=tuple(warnings),
    )


def _derive_status(
    task: Task,
    claims: list[Claim],
    released: list[str],
    results: list[Result],
    verifications: list[Verification],
    *,
    at: datetime,
) -> tuple[TaskStatus, str]:
    accepted = [v for v in verifications if v.accepted]
    rejected = [v for v in verifications if not v.accepted]

    if accepted and rejected:
        # Both verdicts exist and this protocol does not adjudicate. Reporting
        # either one alone would be picking a side; docs/12 is where disputes
        # get resolved, and it is not built.
        return (
            TaskStatus.CONTESTED,
            f"{len(accepted)} verifier(s) accepted and {len(rejected)} rejected; "
            "this layer does not adjudicate between them",
        )
    if accepted:
        return (
            TaskStatus.VERIFIED_ACCEPTED,
            f"{len(accepted)} verifier(s) reported the acceptance criteria met",
        )
    if rejected:
        return (
            TaskStatus.VERIFIED_REJECTED,
            f"{len(rejected)} verifier(s) reported the acceptance criteria not met",
        )
    if results:
        return (TaskStatus.SUBMITTED, f"{len(results)} result(s) submitted, none verified yet")

    live = [c for c in claims if c.event_id not in released and at < c.expires_at]
    if live:
        return (TaskStatus.CLAIMED, f"{len(live)} live claim(s), no result submitted")
    if task.deadline is not None and at >= task.deadline:
        return (TaskStatus.EXPIRED, f"the deadline passed at {task.deadline.isoformat()}")
    return (TaskStatus.OPEN, "no live claim")


def build_work_receipt(
    bundle: EventBundle, *, lineage: str, task_id: str, at: datetime
) -> WorkReceipt:
    """Derive a portable receipt for one task.

    Everything in it comes from the events, so a reader can recompute it rather
    than trust it -- and there is no number in it to add up.
    """
    state = resolve_task(bundle, lineage=lineage, task_id=task_id, at=at)
    task = state.task

    worker = state.results[0].worker if state.results else None
    artifacts = tuple(sorted({ref for r in state.results for ref in r.artifact_refs}))

    accepted_by = tuple(sorted({v.verifier for v in state.verifications if v.accepted}))
    rejected_by = tuple(sorted({v.verifier for v in state.verifications if not v.accepted}))

    met: set[str] = set()
    unmet: set[str] = set()
    for verification in state.verifications:
        for criterion, passed in verification.criteria_results:
            (met if passed else unmet).add(criterion)

    verifiers = {v.verifier for v in state.verifications}
    participants = {task.requester} | ({worker} if worker else set())
    independent = tuple(sorted(verifiers - participants))
    non_independent = tuple(sorted(verifiers & participants))

    pairs: list[str] = []
    if worker is not None:
        verified_by = _reciprocal_pairs(bundle, lineage=lineage)
        for verifier in sorted(verifiers):
            # A verified B's work and B verified A's: the cheapest way to make
            # review look independent when it is a trade.
            if worker in verified_by.get(verifier, set()) and verifier in verified_by.get(
                worker, set()
            ):
                pairs.append(f"{min(worker, verifier)} <-> {max(worker, verifier)}")

    signals = RelationshipSignals(
        requester_is_worker=worker is not None and worker == task.requester,
        self_verified=bool(verifiers & participants),
        independent_verifiers=independent,
        non_independent_verifiers=non_independent,
        reciprocal_verifier_pairs=tuple(sorted(set(pairs))),
    )

    refs = (
        [task.event_id]
        + [c.event_id for c in state.claims]
        + [r.event_id for r in state.results]
        + [v.event_id for v in state.verifications]
    )

    return WorkReceipt(
        task_id=task.event_id,
        title=task.title,
        requester=task.requester,
        status=state.status,
        worker=worker,
        artifact_refs=artifacts,
        accepted_by=accepted_by,
        rejected_by=rejected_by,
        criteria_met=tuple(sorted(met - unmet)),
        criteria_unmet=tuple(sorted(unmet)),
        signals=signals,
        evaluated_at=at,
        reward_reference=task.reward_reference,
        event_refs=tuple(sorted(set(refs))),
    )


__all__ = [
    "ACCEPTED",
    "REJECTED",
    "TASK_CLAIM",
    "TASK_RELEASE",
    "TASK_REQUEST",
    "TASK_RESULT",
    "TASK_VERIFY",
    "Claim",
    "RelationshipSignals",
    "Result",
    "Task",
    "TaskState",
    "TaskStatus",
    "Verification",
    "WorkReceipt",
    "build_work_receipt",
    "read_claim",
    "read_result",
    "read_task",
    "read_verification",
    "resolve_task",
]
