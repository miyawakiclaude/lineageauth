"""Dispute resolution: a procedure that produces a record, not a truth.

`docs/12_JURY_DISPUTES.md` opens by saying what this is not -- not legal
arbitration -- and everything here follows from taking that seriously. A jury
outcome is what a stated procedure produced from signed votes. It is not a
finding about the world, and it is deliberately kept *beside* the task's own
derived status rather than overwriting it: two independent facts, in the same
spirit as the passport's four categories that never merge.

Four rules do most of the work:

*The policy is fixed before the votes.* Seats, quorum and threshold live in
`dispute.open`. Choosing the quorum once you can see the tally is the oldest
way to arrange an outcome, so the builder refuses a policy that both sides
could satisfy and this module never invents one that is missing.

*A tie is not a verdict.* Quorum met with neither side at the threshold is
`UNDECIDED`, which is a real answer. There is no tie-break, and in particular
nothing here breaks ties by `issuedAt` -- the same rule the root succession
layer holds (D-034).

*Conflicts are reported, never used to void a vote.* `docs/12` calls disclosure
evidence rather than identity truth. So a conflicted juror still counts, and
the resolved case additionally states what the outcome would have been without
the conflicted jurors. A reader who cares can see the difference; nobody has to
trust this module to have silently excluded the right people.

*The draw is reproducible, not fair.* Declared-pool selection sorts the pool by
`sha256(seed || did)`, which anybody can recompute. The opener chose the seed,
so the opener could have ground it. That is stated in the output every time,
because "deterministic" reads as "unbiased" to almost everyone unless you say
otherwise -- and `docs/12` explicitly forbids claiming unbiased random
selection that is not verifiably implemented.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from lineageauth.builders import MAX_JURORS
from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError
from lineageauth.fleet import FleetView, resolve_fleets
from lineageauth.work import TASK_VERIFY, resolve_task

DISPUTE_OPEN = "dispute.open"
JURY_DISCLOSE = "jury.disclose"
JURY_VOTE = "jury.vote"

NAMED_SELECTION = "named"
DECLARED_POOL_SELECTION = "declared-pool"

MEETS_CRITERIA = "result-meets-criteria"
FAILS_CRITERIA = "result-fails-criteria"
ABSTAIN = "abstain"

CONFLICT_SAME_FLEET = "same-fleet"
CONFLICT_PRIOR_ROLE = "prior-role-in-task"

JURY_NOTE = (
    "A jury outcome is what a stated procedure produced from signed votes. It is "
    "a technical result, not legal arbitration and not a finding about the world. "
    "It does not overwrite the task's own derived status, which still reads off "
    "the verifications; the two are reported side by side on purpose. Conflicts "
    "are disclosed and detected evidence, never grounds for voiding a vote."
)

DRAW_NOTE = (
    "This jury was drawn deterministically from a declared pool, so anybody can "
    "recompute the seats from the recorded seed. That makes the draw reproducible, "
    "not unbiased: whoever opened the case chose the seed and could have searched "
    "for one that seats favourable jurors."
)

DETECTION_NOTE = (
    "Detected conflicts cover only what a bundle can show: shared disclosed fleet "
    "membership, and a prior role in the disputed task. Everything else -- a "
    "repeated off-protocol relationship, an undisclosed fleet -- can only be "
    "disclosed, never detected, so an empty detected list is not a clean bill."
)


class Outcome(StrEnum):
    """Derived. Nobody signs this; it is read off the votes and the policy."""

    AWAITING_VOTES = "AWAITING_VOTES"
    MET_CRITERIA = "MET_CRITERIA"
    FAILED_CRITERIA = "FAILED_CRITERIA"
    UNDECIDED = "UNDECIDED"


class UnknownCaseError(LineageAuthError):
    """The bundle carries no admissible `dispute.open` with that id."""


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_did(value: Any) -> str | None:
    did = _as_str(value)
    if did is None:
        return None
    try:
        public_key_from_did_key(did)
    except LineageAuthError:
        return None
    return did


def _as_positive_int(value: Any) -> int | None:
    # bool is an int in Python and would sail through an isinstance check.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


@dataclass(frozen=True, slots=True)
class Selection:
    """How the seats were filled, kept in the form the opener committed to."""

    mode: str
    jurors: tuple[str, ...] = ()
    pool: tuple[str, ...] = ()
    seats: int = 0
    seed: str | None = None

    @property
    def is_drawn(self) -> bool:
        return self.mode == DECLARED_POOL_SELECTION


@dataclass(frozen=True, slots=True)
class Policy:
    seats: int
    quorum: int
    threshold: int


@dataclass(frozen=True, slots=True)
class Case:
    event_id: str
    opener: str
    task: str
    result: str
    reason_code: str
    statement: str
    selection: Selection
    policy: Policy
    disputed_verification: str | None
    evidence_refs: tuple[str, ...]
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class Vote:
    event_id: str
    case: str
    juror: str
    finding: str
    reason_code: str
    evidence_refs: tuple[str, ...]
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class Disclosure:
    event_id: str
    case: str
    juror: str
    conflicts: tuple[str, ...]
    note: str | None


def read_case(event: AdmittedEvent) -> Case | str:
    """Validate a `dispute.open` payload, returning it or a complaint."""
    opener = _as_did(event.get("opener"))
    if opener is None:
        return "opener must be a usable Ed25519 did:key"
    if not event.signed_by(opener):
        return f"not signed by the opener it names ({opener})"

    task, result = event.get("task"), event.get("result")
    if not is_event_id(task) or not is_event_id(result):
        return "task and result must both be event ids"

    reason_code = _as_str(event.get("reasonCode"))
    statement = _as_str(event.get("statement"))
    if reason_code is None or statement is None:
        return "reasonCode and statement must both be non-empty strings"

    selection = _read_selection(event.get("selection"))
    if isinstance(selection, str):
        return selection

    policy = _read_policy(event.get("policy"), selection=selection)
    if isinstance(policy, str):
        return policy

    disputed = event.get("disputedVerification")
    if disputed is not None and not is_event_id(disputed):
        return "disputedVerification must be an event id"

    refs = event.get("evidenceRefs") or []
    if not isinstance(refs, list) or not all(is_event_id(r) for r in refs):
        return "evidenceRefs must be a list of event ids"

    return Case(
        event_id=event.event_id,
        opener=opener,
        task=str(task),
        result=str(result),
        reason_code=reason_code,
        statement=statement,
        selection=selection,
        policy=policy,
        disputed_verification=str(disputed) if disputed is not None else None,
        evidence_refs=tuple(sorted(str(r) for r in refs)),
        issued_at=event.issued_at,
    )


def _read_selection(raw: Any) -> Selection | str:
    if not isinstance(raw, dict):
        return "selection must be an object"
    mode = _as_str(raw.get("mode"))
    if mode == NAMED_SELECTION:
        jurors = _read_did_list(raw.get("jurors"))
        if isinstance(jurors, str):
            return f"selection.jurors: {jurors}"
        return Selection(mode=mode, jurors=jurors, seats=len(jurors))
    if mode == DECLARED_POOL_SELECTION:
        pool = _read_did_list(raw.get("pool"))
        if isinstance(pool, str):
            return f"selection.pool: {pool}"
        seats = _as_positive_int(raw.get("seats"))
        seed = _as_str(raw.get("seed"))
        if seats is None or seed is None:
            return "a declared draw needs a positive seats and a recorded seed"
        if seats > len(pool):
            return "seats must not exceed the size of the pool"
        return Selection(mode=mode, pool=pool, seats=seats, seed=seed)
    return f"selection.mode must be {NAMED_SELECTION!r} or {DECLARED_POOL_SELECTION!r}"


def _read_did_list(raw: Any) -> tuple[str, ...] | str:
    if not isinstance(raw, list) or not raw:
        return "must be a non-empty list"
    dids: list[str] = []
    for entry in raw:
        did = _as_did(entry)
        if did is None:
            return "every entry must be a usable Ed25519 did:key"
        dids.append(did)
    if len(set(dids)) != len(dids):
        return "must not repeat a DID"
    return tuple(dids)


def _read_policy(raw: Any, *, selection: Selection) -> Policy | str:
    if not isinstance(raw, dict):
        return "policy must be an object"
    seats = _as_positive_int(raw.get("seats"))
    quorum = _as_positive_int(raw.get("quorum"))
    threshold = _as_positive_int(raw.get("threshold"))
    if seats is None or quorum is None or threshold is None:
        return "policy needs positive integer seats, quorum and threshold"
    if seats > MAX_JURORS:
        # Same reasoning as the threshold rule below, which already says it: the
        # builder refuses to draft this and a hand-written event must not get
        # further. An unbounded seat count is also work an outsider can ask this
        # resolver to do, since every seat is drawn and every draw is counted.
        # (D-098.)
        return f"policy.seats is {seats}; a jury may seat at most {MAX_JURORS}"
    if seats != selection.seats:
        return "policy.seats disagrees with the selection"
    if threshold <= seats // 2 or threshold > seats:
        # The builder refuses to draft this; refuse to resolve it too, or a
        # hand-written event could reach a tally both sides satisfy.
        return "threshold must be a strict majority of the seats and no more than the seats"
    if quorum < threshold or quorum > seats:
        return "quorum must be at least the threshold and no more than the seats"
    return Policy(seats=seats, quorum=quorum, threshold=threshold)


def read_vote(event: AdmittedEvent) -> Vote | str:
    """Validate a `jury.vote` payload, returning it or a complaint."""
    juror = _as_did(event.get("juror"))
    if juror is None:
        return "juror must be a usable Ed25519 did:key"
    if not event.signed_by(juror):
        # Without this an opener could mint the jury's findings themselves,
        # which would make the whole layer decorative.
        return f"not signed by the juror it names ({juror})"
    case = event.get("case")
    if not is_event_id(case):
        return "case must be the event id of a dispute.open"
    finding = _as_str(event.get("finding"))
    if finding not in (MEETS_CRITERIA, FAILS_CRITERIA, ABSTAIN):
        return f"finding must be a known finding code, got {finding!r}"
    reason_code = _as_str(event.get("reasonCode"))
    if reason_code is None:
        return "reasonCode must be a non-empty string"
    refs = event.get("evidenceRefs") or []
    if not isinstance(refs, list) or not all(is_event_id(r) for r in refs):
        return "evidenceRefs must be a list of event ids"
    return Vote(
        event_id=event.event_id,
        case=str(case),
        juror=juror,
        finding=finding,
        reason_code=reason_code,
        evidence_refs=tuple(sorted(str(r) for r in refs)),
        issued_at=event.issued_at,
    )


def read_disclosure(event: AdmittedEvent) -> Disclosure | str:
    """Validate a `jury.disclose` payload, returning it or a complaint."""
    juror = _as_did(event.get("juror"))
    if juror is None:
        return "juror must be a usable Ed25519 did:key"
    if not event.signed_by(juror):
        return f"not signed by the juror it names ({juror})"
    case = event.get("case")
    if not is_event_id(case):
        return "case must be the event id of a dispute.open"
    conflicts = event.get("conflicts")
    if not isinstance(conflicts, list) or not conflicts:
        return "conflicts must be a non-empty list"
    if not all(isinstance(c, str) and c for c in conflicts):
        return "every conflict must be a non-empty string"
    return Disclosure(
        event_id=event.event_id,
        case=str(case),
        juror=juror,
        conflicts=tuple(sorted(set(str(c) for c in conflicts))),
        note=_as_str(event.get("note")),
    )


def seat_jurors(selection: Selection) -> tuple[str, ...]:
    """Fill the seats. Named jurors are the seats; a pool is drawn from.

    The draw orders the pool by `sha256(seed || "\\n" || did)` and takes the
    first `seats`. The separator keeps two different (seed, did) splits from
    colliding into the same preimage. Ties on the digest fall back to the DID so
    the result never depends on the order the pool happened to be written in.
    """
    if selection.mode == NAMED_SELECTION:
        return selection.jurors

    def rank(did: str) -> tuple[str, str]:
        seed = selection.seed or ""
        digest = hashlib.sha256(seed.encode("utf-8") + b"\n" + did.encode("utf-8")).hexdigest()
        return (digest, did)

    return tuple(sorted(selection.pool, key=rank)[: selection.seats])


@dataclass(frozen=True, slots=True)
class JurorRecord:
    """One seat, and everything known about who is sitting in it."""

    juror: str
    finding: str | None
    reason_code: str | None
    disclosed_conflicts: tuple[str, ...]
    detected_conflicts: tuple[str, ...]

    @property
    def undisclosed_conflicts(self) -> tuple[str, ...]:
        return tuple(c for c in self.detected_conflicts if c not in self.disclosed_conflicts)

    @property
    def is_conflicted(self) -> bool:
        return bool(self.disclosed_conflicts or self.detected_conflicts)


@dataclass(frozen=True, slots=True)
class ResolvedCase:
    """A dispute, its tally, and what the tally does and does not settle."""

    case: Case
    outcome: Outcome
    detail: str
    evaluated_at: datetime
    jurors: tuple[JurorRecord, ...]
    meets: int
    fails: int
    abstentions: int
    votes_cast: int
    outcome_without_conflicted: Outcome
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        text = f"{JURY_NOTE} {DETECTION_NOTE}"
        if self.case.selection.is_drawn:
            text = f"{text} {DRAW_NOTE}"
        return text

    @property
    def outcome_depends_on_conflicted_jurors(self) -> bool:
        """True when dropping every conflicted juror changes the answer.

        Not an accusation. It is the one question a reader of a contested
        outcome always wants answered, and answering it here saves them from
        having to trust that the right people were excluded.
        """
        return self.outcome_without_conflicted is not self.outcome

    @property
    def unconflicted_jurors(self) -> tuple[str, ...]:
        return tuple(r.juror for r in self.jurors if not r.is_conflicted)

    @property
    def undisclosed_conflicts(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return tuple(
            (r.juror, r.undisclosed_conflicts) for r in self.jurors if r.undisclosed_conflicts
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.event_id,
            "task": self.case.task,
            "result": self.case.result,
            "opener": self.case.opener,
            "reasonCode": self.case.reason_code,
            "statement": self.case.statement,
            "outcome": str(self.outcome),
            "detail": self.detail,
            "evaluatedAt": self.evaluated_at.isoformat().replace("+00:00", "Z"),
            "policy": {
                "seats": self.case.policy.seats,
                "quorum": self.case.policy.quorum,
                "threshold": self.case.policy.threshold,
            },
            "selection": {
                "mode": self.case.selection.mode,
                "seats": [r.juror for r in self.jurors],
                **({"seed": self.case.selection.seed} if self.case.selection.seed else {}),
            },
            "tally": {
                "meetsCriteria": self.meets,
                "failsCriteria": self.fails,
                "abstentions": self.abstentions,
                "votesCast": self.votes_cast,
            },
            "jurors": [
                {
                    "juror": r.juror,
                    "finding": r.finding,
                    "reasonCode": r.reason_code,
                    "disclosedConflicts": list(r.disclosed_conflicts),
                    "detectedConflicts": list(r.detected_conflicts),
                    "undisclosedConflicts": list(r.undisclosed_conflicts),
                }
                for r in self.jurors
            ],
            "outcomeWithoutConflictedJurors": str(self.outcome_without_conflicted),
            "outcomeDependsOnConflictedJurors": self.outcome_depends_on_conflicted_jurors,
            "warnings": list(self.warnings),
            "note": self.note,
        }


def _tally(findings: dict[str, str], *, policy: Policy) -> tuple[Outcome, str, int, int, int]:
    meets = sum(1 for f in findings.values() if f == MEETS_CRITERIA)
    fails = sum(1 for f in findings.values() if f == FAILS_CRITERIA)
    abstentions = sum(1 for f in findings.values() if f == ABSTAIN)
    cast = len(findings)

    if cast < policy.quorum:
        return (
            Outcome.AWAITING_VOTES,
            f"{cast} of the {policy.quorum} votes this case needs have been cast",
            meets,
            fails,
            abstentions,
        )
    if meets >= policy.threshold:
        return (
            Outcome.MET_CRITERIA,
            f"{meets} of {policy.seats} jurors found the result met the criteria "
            f"(threshold {policy.threshold})",
            meets,
            fails,
            abstentions,
        )
    if fails >= policy.threshold:
        return (
            Outcome.FAILED_CRITERIA,
            f"{fails} of {policy.seats} jurors found the result failed the criteria "
            f"(threshold {policy.threshold})",
            meets,
            fails,
            abstentions,
        )
    return (
        Outcome.UNDECIDED,
        f"quorum was met with {cast} votes but neither side reached the threshold of "
        f"{policy.threshold} ({meets} met / {fails} failed / {abstentions} abstained); "
        "a split jury is an answer, and nothing here breaks the tie",
        meets,
        fails,
        abstentions,
    )


def _detect_conflicts(
    juror: str,
    *,
    bundle: EventBundle,
    lineage: str,
    case: Case,
    fleets: FleetView,
    at: datetime,
) -> tuple[str, ...]:
    """The conflicts a bundle can actually show. See `DETECTION_NOTE`."""
    parties: set[str] = {case.opener}
    try:
        state = resolve_task(bundle, lineage=lineage, task_id=case.task, at=at)
    except LineageAuthError:
        state = None
    if state is not None:
        parties.add(state.task.requester)
        parties.update(c.claimant for c in state.claims)
        parties.update(v.verifier for v in state.verifications)
    else:
        # The task itself is not in this bundle, so fall back to the verifiers
        # that are: a juror who already ruled on this result has a prior role
        # whether or not the task event travelled with it.
        for event in bundle.of_type(TASK_VERIFY, lineage=lineage):
            if event.get("result") == case.result:
                verifier = _as_did(event.get("verifier"))
                if verifier is not None:
                    parties.add(verifier)

    detected: list[str] = []
    if juror in parties:
        detected.append(CONFLICT_PRIOR_ROLE)
    if any(other != juror and fleets.same_fleet(juror, other) for other in parties):
        detected.append(CONFLICT_SAME_FLEET)
    return tuple(detected)


def resolve_dispute(
    bundle: EventBundle, *, lineage: str, case_id: str, at: datetime
) -> ResolvedCase:
    """Resolve one dispute into an outcome, a tally, and its own caveats."""
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")
    if not is_event_id(case_id):
        raise MalformedEventError("case_id must be a sha256:<64 hex> event id")

    warnings: list[str] = []
    case: Case | None = None
    for event in bundle.of_type(DISPUTE_OPEN, lineage=lineage):
        if event.event_id != case_id:
            continue
        parsed = read_case(event)
        if isinstance(parsed, str):
            raise UnknownCaseError(f"dispute.open {case_id} is not admissible: {parsed}")
        case = parsed
    if case is None:
        raise UnknownCaseError(f"this bundle carries no dispute.open with id {case_id}")

    seats = seat_jurors(case.selection)
    seated = set(seats)

    disclosed: dict[str, set[str]] = {}
    for event in bundle.of_type(JURY_DISCLOSE, lineage=lineage):
        parsed_disclosure = read_disclosure(event)
        if isinstance(parsed_disclosure, str):
            warnings.append(f"jury.disclose {event.event_id} ignored: {parsed_disclosure}")
            continue
        if parsed_disclosure.case != case_id:
            continue
        disclosed.setdefault(parsed_disclosure.juror, set()).update(parsed_disclosure.conflicts)

    findings: dict[str, str] = {}
    reasons: dict[str, str] = {}
    double_voters: set[str] = set()
    for event in bundle.of_type(JURY_VOTE, lineage=lineage):
        parsed_vote = read_vote(event)
        if isinstance(parsed_vote, str):
            warnings.append(f"jury.vote {event.event_id} ignored: {parsed_vote}")
            continue
        if parsed_vote.case != case_id:
            continue
        if parsed_vote.juror not in seated:
            warnings.append(
                f"jury.vote {parsed_vote.event_id} not counted: {parsed_vote.juror} does not "
                "hold a seat on this case"
            )
            continue
        previous = findings.get(parsed_vote.juror)
        if previous is not None and previous != parsed_vote.finding:
            # One juror, two different findings. Taking the later one would make
            # a vote revisable by whoever publishes last, and taking either is a
            # tie-break this layer has no business making (D-034).
            double_voters.add(parsed_vote.juror)
            continue
        findings[parsed_vote.juror] = parsed_vote.finding
        reasons[parsed_vote.juror] = parsed_vote.reason_code

    for juror in sorted(double_voters):
        findings.pop(juror, None)
        reasons.pop(juror, None)
        warnings.append(
            f"{juror} published conflicting findings on this case; that seat is not "
            "counted, in either direction"
        )

    fleets = resolve_fleets(bundle, lineage=lineage, at=at)
    records = tuple(
        JurorRecord(
            juror=juror,
            finding=findings.get(juror),
            reason_code=reasons.get(juror),
            disclosed_conflicts=tuple(sorted(disclosed.get(juror, set()))),
            detected_conflicts=_detect_conflicts(
                juror, bundle=bundle, lineage=lineage, case=case, fleets=fleets, at=at
            ),
        )
        for juror in seats
    )

    for juror, codes in sorted(disclosed.items()):
        if juror not in seated:
            warnings.append(
                f"jury.disclose from {juror} concerns a case they hold no seat on; "
                f"recorded but not applied ({', '.join(sorted(codes))})"
            )

    outcome, detail, meets, fails, abstentions = _tally(findings, policy=case.policy)
    clean = {r.juror: f for r in records if (f := r.finding) is not None and not r.is_conflicted}
    outcome_without_conflicted, _, _, _, _ = _tally(clean, policy=case.policy)

    return ResolvedCase(
        case=case,
        outcome=outcome,
        detail=detail,
        evaluated_at=at,
        jurors=records,
        meets=meets,
        fails=fails,
        abstentions=abstentions,
        votes_cast=len(findings),
        outcome_without_conflicted=outcome_without_conflicted,
        warnings=tuple(warnings),
    )


def disputes_involving(
    bundle: EventBundle, *, lineage: str, did: str, at: datetime
) -> tuple[ResolvedCase, ...]:
    """Every admissible case this DID opened, was judged in, or sat on.

    Used by the passport, where a dispute belongs beside the work rather than
    inside any claim category: it is a record of process, not something anybody
    claimed about themselves.
    """
    found: list[ResolvedCase] = []
    for event in bundle.of_type(DISPUTE_OPEN, lineage=lineage):
        parsed = read_case(event)
        if isinstance(parsed, str):
            continue
        try:
            resolved = resolve_dispute(bundle, lineage=lineage, case_id=parsed.event_id, at=at)
        except LineageAuthError:
            continue
        involved = {parsed.opener, *(r.juror for r in resolved.jurors)}
        if did not in involved:
            try:
                state = resolve_task(bundle, lineage=lineage, task_id=parsed.task, at=at)
            except LineageAuthError:
                continue
            involved.add(state.task.requester)
            involved.update(r.worker for r in state.results)
            if did not in involved:
                continue
        found.append(resolved)
    return tuple(sorted(found, key=lambda r: (r.case.issued_at, r.case.event_id)))
