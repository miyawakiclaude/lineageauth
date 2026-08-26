"""Discovery: find an agent by capability, authority, evidence, and availability.

`docs/10_ROUTER_DISCOVERY.md` asks for search that goes beyond a claimed skill,
and then constrains how the answer may be presented:

    Ranking must be explainable and versioned.
    Do not use hidden "trust AI" score.

So there is a number here, and it is a *relevance* number: how well a candidate
fits this query. It is not a rating of the agent. Every point of it arrives as a
named `Contribution` carrying its own value and the reason for it, so a caller
can add them up and get the same answer -- which is what "explainable" has to
mean if it means anything. `RANKING_VERSION` moves whenever the formula does,
because a rank that changed for reasons nobody can name is the opaque score the
document refuses.

Three things this deliberately will not do.

*It will not authorize anything.* `docs/10`: a search result is not execution
authorization. Authority is re-checked at the moment of action, because a grant
can be revoked between finding an agent and asking it to do something.

*It will not hide the relationships.* Sybil resistance is not on offer. What is
on offer is the shape of the evidence: how many independent lineages a candidate
has actually dealt with, whether its attestations concentrate in one key,
whether the same pair keeps verifying each other. `docs/13` is blunt that
disclosure is voluntary and undisclosed fleets remain possible, so nothing here
claims a candidate is not one.

*It will not treat stale availability as availability.* A statement expires, and
an expired one is reported as expired rather than quietly dropped -- an agent
that said it was free last week has told you nothing about now.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from lineageauth.authority import check_permission
from lineageauth.bundle import EventBundle
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError, ReasonCode
from lineageauth.fleet import FleetView, resolve_fleets
from lineageauth.passport import SKILL_CLAIM, Passport, build_passport
from lineageauth.scopes import ApprovalMode, parse_resource
from lineageauth.timeutil import format_instant, parse_instant
from lineageauth.work import TaskStatus

AVAILABILITY_STATEMENT = "availability.statement"

# Bumped whenever a contribution is added, removed, or reweighted. A rank that
# moved for reasons nobody can name is the opaque score docs/10 refuses.
RANKING_VERSION = "explainable-v1"

ROUTER_NOTE = (
    "Relevance measures fit for this query, not the quality or trustworthiness of "
    "an agent. A result is not authorization: re-check authority at the moment of "
    "action, because a grant can be revoked between finding an agent and asking it "
    "to act. Nothing here detects Sybils -- the relationship signals are shown so "
    "you can judge, not because they settle anything. A disclosed fleet is not "
    "penalised: siblings simply do not count as independent, and an agent with no "
    "disclosed fleet has said nothing rather than proved anything."
)

# Every contribution, with the weight it carries. Published rather than buried:
# a caller can recompute a relevance figure from the contributions returned.
WEIGHTS: dict[str, int] = {
    "skill_claimed": 1,
    "skill_evidence_supported": 4,
    "accepted_task": 3,
    "independent_verifier": 2,
    "independent_counterparty": 2,
    "authority_live": 5,
    "available_now": 2,
    # Negative evidence counts too. docs/10 lists it among the inputs, and a
    # ranking that only ever adds is one where a rejection costs nothing.
    "rejected_task": -3,
    "self_created_task_only": -2,
    "reciprocal_verification": -2,
}


@dataclass(frozen=True, slots=True)
class Requirement:
    """One thing a candidate must be authorized to do."""

    namespace: str
    resource: str
    action: str

    def __post_init__(self) -> None:
        parse_resource(self.namespace, self.resource)

    def render(self) -> str:
        return f"{self.namespace}:{self.resource} [{self.action}]"


@dataclass(frozen=True, slots=True)
class Query:
    """What the caller is looking for."""

    skills: tuple[str, ...] = ()
    requires: tuple[Requirement, ...] = ()
    approval_mode: ApprovalMode | None = None
    require_available: bool = False

    def render(self) -> str:
        parts: list[str] = []
        if self.skills:
            parts.append(f"skills={list(self.skills)}")
        if self.requires:
            parts.append(f"requires={[r.render() for r in self.requires]}")
        if self.approval_mode is not None:
            parts.append(f"approval<={self.approval_mode.wire_name}")
        if self.require_available:
            parts.append("available=now")
        return " ".join(parts) or "(any)"


@dataclass(frozen=True, slots=True)
class Contribution:
    """One named reason a candidate scored what it did."""

    name: str
    count: int
    weight: int
    detail: str

    @property
    def value(self) -> int:
        return self.count * self.weight


@dataclass(frozen=True, slots=True)
class Availability:
    """What a candidate last said about being free, and how old it is."""

    stated: bool
    expires_at: datetime | None
    event_id: str | None
    stale: bool

    @property
    def usable(self) -> bool:
        """Available *and* not expired. A stale yes is not a yes."""
        return self.stated and not self.stale


@dataclass(frozen=True, slots=True)
class RelationshipShape:
    """What the evidence looks like, so a caller can judge its independence.

    Not a Sybil verdict. `docs/13` is explicit that fleet disclosure is voluntary
    and undisclosed fleets remain possible, so a clean shape here means the
    evidence looks independent -- not that it is.
    """

    independent_counterparties: int
    attestation_concentration: float
    """Share of attestations from the single most frequent issuer, 0.0-1.0."""

    reciprocal_pairs: int
    self_created_tasks: int
    accepted_tasks: int
    rejected_tasks: int
    disclosed_fleets: tuple[str, ...] = ()
    same_fleet_counterparties: tuple[str, ...] = ()
    """Attesters a disclosure ties to this agent.

    These are *excluded* from the independent count rather than subtracted from
    the score. `docs/13` forbids penalising disclosure in a hidden way, and a
    penalty here would cost the operator who discloses exactly what it saves the
    one who stays quiet."""


@dataclass(frozen=True, slots=True)
class Candidate:
    """One agent, why it matched, and what it would still need to be checked for."""

    did: str
    lineage: str
    relevance: int
    authority_satisfied: bool
    authority_reasons: tuple[str, ...]
    matched_skills: tuple[str, ...]
    evidence_supported_skills: tuple[str, ...]
    availability: Availability
    shape: RelationshipShape
    contributions: tuple[Contribution, ...]
    evidence_refs: tuple[str, ...]

    @property
    def explanation(self) -> str:
        """The rank, spelled out. Adding these up reproduces `relevance`."""
        lines = [f"relevance {self.relevance} ({RANKING_VERSION})"]
        for item in self.contributions:
            lines.append(
                f"  {item.value:+4d}  {item.name} x{item.count} @ {item.weight}  -- {item.detail}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "did": self.did,
            "lineage": self.lineage,
            "relevance": self.relevance,
            "rankingVersion": RANKING_VERSION,
            "authoritySatisfied": self.authority_satisfied,
            "authorityReasons": list(self.authority_reasons),
            "matchedSkills": list(self.matched_skills),
            "evidenceSupportedSkills": list(self.evidence_supported_skills),
            "availability": {
                "stated": self.availability.stated,
                "usable": self.availability.usable,
                "stale": self.availability.stale,
                "expiresAt": (
                    format_instant(self.availability.expires_at)
                    if self.availability.expires_at
                    else None
                ),
                "eventId": self.availability.event_id,
            },
            "relationshipShape": {
                "independentCounterparties": self.shape.independent_counterparties,
                "attestationConcentration": round(self.shape.attestation_concentration, 3),
                "reciprocalPairs": self.shape.reciprocal_pairs,
                "selfCreatedTasks": self.shape.self_created_tasks,
                "acceptedTasks": self.shape.accepted_tasks,
                "rejectedTasks": self.shape.rejected_tasks,
                "disclosedFleets": list(self.shape.disclosed_fleets),
                # Not a penalty. Excluded from the independent count so a
                # disclosure is not double-counted, never subtracted -- see
                # docs/13 on not penalising disclosure.
                "sameFleetCounterparties": list(self.shape.same_fleet_counterparties),
            },
            "contributions": [
                {
                    "name": c.name,
                    "count": c.count,
                    "weight": c.weight,
                    "value": c.value,
                    "detail": c.detail,
                }
                for c in self.contributions
            ],
            "evidenceRefs": list(self.evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class SearchResult:
    """The ranked candidates, and the standing caveats."""

    query: Query
    evaluated_at: datetime
    candidates: tuple[Candidate, ...] = ()
    considered: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        return ROUTER_NOTE

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query.render(),
            "evaluatedAt": format_instant(self.evaluated_at),
            "rankingVersion": RANKING_VERSION,
            "weights": dict(sorted(WEIGHTS.items())),
            "considered": self.considered,
            "candidates": [c.to_dict() for c in self.candidates],
            "warnings": list(self.warnings),
            "note": self.note,
        }


def _read_availability(
    bundle: EventBundle, *, lineage: str, did: str, at: datetime
) -> Availability:
    """The candidate's most recent self-signed availability statement."""
    latest: tuple[datetime, str, bool, datetime] | None = None
    for event in bundle.of_type(AVAILABILITY_STATEMENT, lineage=lineage):
        subject = event.get("subject")
        if subject != did or not event.signed_by(did):
            continue
        stated = event.get("available")
        if not isinstance(stated, bool):
            continue
        try:
            expires_at = parse_instant(event.get("expiresAt"), field="expiresAt")
        except MalformedEventError:
            continue
        key = (event.issued_at, event.event_id, stated, expires_at)
        if latest is None or (key[0], key[1]) > (latest[0], latest[1]):
            latest = key

    if latest is None:
        return Availability(stated=False, expires_at=None, event_id=None, stale=False)
    _, event_id, stated, expires_at = latest
    return Availability(
        stated=stated,
        expires_at=expires_at,
        event_id=event_id,
        # An expired yes is not a yes. Reported as stale rather than dropped, so
        # a caller can see that the agent once said something and it lapsed.
        stale=at >= expires_at,
    )


def _shape_of(
    passport: Passport, bundle: EventBundle, *, at: datetime, fleets: FleetView
) -> RelationshipShape:
    # A disclosed sibling is not an independent counterparty. Excluded from the
    # count, never subtracted from the score (docs/13).
    related = fleets.related_to(passport.did)
    issuers = [a.issuer for a in passport.attestations if a.issuer != passport.did]
    same_fleet = tuple(sorted({i for i in issuers if i in related}))
    concentration = 0.0
    if issuers:
        counts: dict[str, int] = {}
        for issuer in issuers:
            counts[issuer] = counts.get(issuer, 0) + 1
        concentration = max(counts.values()) / len(issuers)

    reciprocal = 0
    from lineageauth.work import build_work_receipt

    for task in passport.tasks:
        try:
            receipt = build_work_receipt(
                bundle, lineage=passport.lineage, task_id=task.task_id, at=at
            )
        except MalformedEventError:  # pragma: no cover - defensive
            continue
        reciprocal += len(receipt.signals.reciprocal_verifier_pairs)

    return RelationshipShape(
        independent_counterparties=len(
            [d for d in passport.independent_counterparties if d not in related]
        ),
        attestation_concentration=concentration,
        reciprocal_pairs=reciprocal,
        self_created_tasks=sum(1 for t in passport.tasks if t.requester_is_worker),
        accepted_tasks=sum(1 for t in passport.tasks if t.status is TaskStatus.VERIFIED_ACCEPTED),
        rejected_tasks=sum(1 for t in passport.tasks if t.status is TaskStatus.VERIFIED_REJECTED),
        disclosed_fleets=fleets.fleets_of(passport.did),
        same_fleet_counterparties=same_fleet,
    )


def _subjects(bundle: EventBundle, *, lineage: str) -> tuple[str, ...]:
    """Every DID a bundle has anything to say about, sorted."""
    found: set[str] = set()
    for event in bundle.admitted:
        if event.lineage != lineage:
            continue
        for field_name in ("subject", "worker", "claimant", "createdBy"):
            value = event.get(field_name)
            if isinstance(value, str):
                try:
                    public_key_from_did_key(value)
                except LineageAuthError:
                    continue
                found.add(value)
    return tuple(sorted(found))


def search(
    bundle: EventBundle, *, lineage: str, query: Query, at: datetime, limit: int = 20
) -> SearchResult:
    """Rank the agents in a bundle by how well they fit `query`.

    Deterministic: ties break on DID, so the same events and the same query give
    the same order.
    """
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")
    if limit < 1:
        raise MalformedEventError("limit must be at least 1")

    warnings: list[str] = list(bundle.warnings)
    fleets = resolve_fleets(bundle, lineage=lineage, at=at)
    warnings.extend(fleets.warnings)
    candidates: list[Candidate] = []
    subjects = _subjects(bundle, lineage=lineage)

    for did in subjects:
        passport = build_passport(bundle, lineage=lineage, did=did, at=at)

        # ---- authority: every requirement must be satisfied ----
        reasons: list[str] = []
        satisfied = True
        for requirement in query.requires:
            decision = check_permission(
                bundle,
                lineage=lineage,
                agent=did,
                namespace=requirement.namespace,
                resource=requirement.resource,
                action=requirement.action,
                at=at,
            )
            usable = decision.reason in (
                ReasonCode.VALID_AUTHORITY_CHAIN,
                ReasonCode.APPROVAL_REQUIRED,
            )
            if query.approval_mode is not None and decision.approval > query.approval_mode:
                usable = False
                reasons.append(
                    f"{requirement.render()}: needs {decision.approval.wire_name} approval, "
                    f"more than the query allows"
                )
            elif not usable:
                reasons.append(f"{requirement.render()}: {decision.reason}")
            else:
                reasons.append(f"{requirement.render()}: {decision.reason}")
            satisfied = satisfied and usable
        if query.requires and not satisfied:
            continue

        # ---- capability ----
        claimed = {c.skill for c in passport.skill_claims}
        supported = {s.skill for s in passport.skills if s.is_evidence_supported}
        wanted = set(query.skills)
        matched = tuple(sorted(claimed & wanted)) if wanted else tuple(sorted(claimed))
        matched_supported = tuple(sorted(supported & set(matched)))
        if wanted and not matched:
            continue

        availability = _read_availability(bundle, lineage=lineage, did=did, at=at)
        if query.require_available and not availability.usable:
            continue

        shape = _shape_of(passport, bundle, at=at, fleets=fleets)

        # Declared as data rather than accumulated by a closure: a helper that
        # captured the list from this loop would be the shape of a late-binding
        # bug even where it happens to work, and this reads as what it is -- the
        # published list of inputs, in order.
        counted: tuple[tuple[str, int, str], ...] = (
            (
                "skill_claimed",
                len(matched),
                "skills claimed and matching the query -- a claim, whoever signed it",
            ),
            (
                "skill_evidence_supported",
                len(matched_supported),
                "matched skills backed by a signed receipt and an independent attester",
            ),
            ("accepted_task", shape.accepted_tasks, "tasks a verifier reported as accepted"),
            (
                "independent_verifier",
                sum(len(t.independent_verifiers) for t in passport.tasks),
                "verifications by keys that were neither the requester nor the worker",
            ),
            (
                "independent_counterparty",
                shape.independent_counterparties,
                "distinct other keys that have attested to this agent's artifacts",
            ),
            (
                "authority_live",
                1 if passport.holds_live_authority else 0,
                "holds at least one currently usable grant",
            ),
            (
                "available_now",
                1 if availability.usable else 0,
                "has an unexpired statement of availability",
            ),
            (
                "rejected_task",
                shape.rejected_tasks,
                "tasks a verifier reported as not meeting the criteria",
            ),
            (
                "self_created_task_only",
                shape.self_created_tasks,
                "tasks this agent both requested and worked on -- not independent work",
            ),
            (
                "reciprocal_verification",
                shape.reciprocal_pairs,
                "verifier pairs that verify each other, which makes review look "
                "independent when it is a trade",
            ),
        )
        contributions = [
            Contribution(name=name, count=count, weight=WEIGHTS[name], detail=detail)
            for name, count, detail in counted
            if count
        ]

        relevance = sum(item.value for item in contributions)
        refs = (
            [t.task_id for t in passport.tasks]
            + [p.receipt_id for p in passport.produced]
            + [a.event_id for a in passport.attestations]
            + ([availability.event_id] if availability.event_id else [])
        )

        candidates.append(
            Candidate(
                did=did,
                lineage=lineage,
                relevance=relevance,
                authority_satisfied=satisfied,
                authority_reasons=tuple(reasons),
                matched_skills=matched,
                evidence_supported_skills=matched_supported,
                availability=availability,
                shape=shape,
                contributions=tuple(contributions),
                evidence_refs=tuple(sorted(set(refs))),
            )
        )

    if any(c.availability.stale for c in candidates):
        warnings.append(
            "some candidates' availability statements have expired; an agent that "
            "said it was free last week has told you nothing about now"
        )

    ranked = tuple(sorted(candidates, key=lambda c: (-c.relevance, c.did))[:limit])
    return SearchResult(
        query=query,
        evaluated_at=at,
        candidates=ranked,
        considered=len(subjects),
        warnings=tuple(warnings),
    )


__all__ = [
    "AVAILABILITY_STATEMENT",
    "RANKING_VERSION",
    "ROUTER_NOTE",
    "SKILL_CLAIM",
    "WEIGHTS",
    "Availability",
    "Candidate",
    "Contribution",
    "Query",
    "RelationshipShape",
    "Requirement",
    "SearchResult",
    "search",
]
