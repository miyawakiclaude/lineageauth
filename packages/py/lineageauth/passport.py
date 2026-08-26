"""The agent passport: a projection of evidence, never a score.

`docs/09_AGENT_PASSPORT.md` states the goal and the trap in the same breath --
a portable, evidence-first profile that is *not* a centralized identity and not
a single trust number. The instruction that shapes this whole module is one
sentence from that document:

    Never merge these categories into one unlabeled truth.

So a passport is four separate collections, and there is deliberately no field
that combines them. Anything that reduced them to a rating would be the thing
`docs/09` and `docs/14` both refuse: an opaque score people would quote without
the caveats.

    self-claimed        what this DID says about itself
    cryptographically   what signatures and the authority chain establish
      linked
    evidence-supported  artifacts it signed a receipt for, backed by authority
    third-party         what other keys have said about those artifacts
      attested

Some absences are reported rather than left blank. Fleet bindings, impact
edges, and availability belong to phases that are not built yet, and an empty
list reads as "this agent has none" when the truth is "this system does not
track that". The `notIncluded` section names each one and why, and entries leave
it as their phases land -- completed tasks moved out of it when Phase 8 shipped.

And the standing caveat, on every passport: a key is not a person. Nothing here
establishes identity, employment, affiliation, or honesty.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from lineageauth.authority import DELEGATION_GRANT, describe_grants
from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError, ReasonCode
from lineageauth.evidence import (
    ARTIFACT_RECEIPT,
    ATTESTATION_ISSUE,
    check_receipt_authority,
    read_attestation,
)
from lineageauth.evidence import read_receipt as read_artifact_receipt
from lineageauth.lineage import resolve_lineage
from lineageauth.timeutil import format_instant
from lineageauth.work import TASK_REQUEST, TaskStatus, build_work_receipt, read_task

PROFILE_STATEMENT = "profile.statement"
SKILL_CLAIM = "skill.claim"

PASSPORT_NOTE = (
    "A passport is a projection of signed events, not an identity and not a score. "
    "A key is not a person: nothing here establishes who anyone is, who they work "
    "for, or whether they are honest. The four sections are kept apart on purpose "
    "-- a self-claimed skill and an independently attested one are different "
    "things, and combining them would hide which is which."
)

# Sections the specification calls for that no implemented phase can fill yet.
# Named rather than omitted: an empty list reads as an absence of evidence, and
# these are an absence of machinery.
NOT_IMPLEMENTED: tuple[tuple[str, str], ...] = (
    ("fleetBindings", "fleet disclosure is Phase 13 and is not built"),
    ("impact", "the impact graph is Phase 14 and is not built"),
    ("availability", "availability statements are Phase 10 and are not built"),
)


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
class SelfClaim:
    """Something a DID said about itself. Signed by that DID, and nothing more."""

    event_id: str
    nickname: str | None
    description: str | None


@dataclass(frozen=True, slots=True)
class SkillClaim:
    """A claimed skill, and who claimed it."""

    event_id: str
    skill: str
    claimed_by: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    self_claimed: bool
    """True when the subject signed it themselves."""


@dataclass(frozen=True, slots=True)
class ProducedArtifact:
    """An artifact this DID signed a receipt for, with the authority checked."""

    artifact_id: str
    receipt_id: str
    authority_supported: bool
    authority_reason: ReasonCode
    authority_detail: str


@dataclass(frozen=True, slots=True)
class TaskParticipation:
    """A task this DID worked on, and how far it got.

    The relationship signals travel with it. A completed-task count on its own
    is the number `docs/08` warns about -- self-created tasks and same-key
    verifications inflate it -- so the passport never shows the count without
    what qualifies it.
    """

    task_id: str
    title: str
    status: TaskStatus
    requester_is_worker: bool
    independent_verifiers: tuple[str, ...]
    artifact_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ThirdPartyClaim:
    """What another key said about one of this DID's artifacts."""

    event_id: str
    issuer: str
    subject_ref: str
    predicate: str
    predicate_is_known: bool
    value: str | None
    current: bool


@dataclass(frozen=True, slots=True)
class SkillEvidence:
    """How much a claimed skill is actually backed, and by what.

    Reported as counts and references, not a rating. `docs/10` requires ranking
    inputs to be explainable, and the way to keep them explainable is to hand a
    caller the parts rather than an answer.
    """

    skill: str
    self_claimed: bool
    cited_artifacts: tuple[str, ...]
    produced_artifacts: tuple[str, ...]
    independent_attesters: tuple[str, ...]

    @property
    def is_evidence_supported(self) -> bool:
        """True when the subject signed for a cited artifact *and* someone else vouched.

        Both halves matter. Without the receipt, the claim points at work nobody
        can tie to this key; without an independent attester, the only support is
        the claimant's own word twice over.
        """
        return bool(self.produced_artifacts) and bool(self.independent_attesters)


@dataclass(frozen=True, slots=True)
class Passport:
    """The projection. Four sections, deliberately never combined."""

    did: str
    lineage: str
    evaluated_at: datetime

    # cryptographically linked
    lineage_resolved: bool
    lineage_reason: ReasonCode
    current_root: str | None
    epoch: int | None
    authority_scopes: tuple[str, ...] = ()
    holds_live_authority: bool = False

    # self-claimed
    self_claims: tuple[SelfClaim, ...] = ()
    skill_claims: tuple[SkillClaim, ...] = ()

    # evidence-supported
    produced: tuple[ProducedArtifact, ...] = ()
    tasks: tuple[TaskParticipation, ...] = ()
    skills: tuple[SkillEvidence, ...] = ()

    # third-party attested
    attestations: tuple[ThirdPartyClaim, ...] = ()

    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        return PASSPORT_NOTE

    @property
    def independent_counterparties(self) -> tuple[str, ...]:
        """Distinct keys other than this one that have attested to its work.

        A count of keys, not of agreement. Two attesters may contradict each
        other and both are counted, because this layer does not adjudicate.
        """
        return tuple(sorted({a.issuer for a in self.attestations if a.issuer != self.did}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "did": self.did,
            "lineage": self.lineage,
            "evaluatedAt": format_instant(self.evaluated_at),
            "cryptographicallyLinked": {
                "lineageResolved": self.lineage_resolved,
                "reason": str(self.lineage_reason),
                "currentRoot": self.current_root,
                "epoch": self.epoch,
                "authorityScopes": list(self.authority_scopes),
                "holdsLiveAuthority": self.holds_live_authority,
            },
            "selfClaimed": {
                "statements": [
                    {
                        "eventId": c.event_id,
                        "nickname": c.nickname,
                        "description": c.description,
                    }
                    for c in self.self_claims
                ],
                "skills": [
                    {
                        "eventId": s.event_id,
                        "skill": s.skill,
                        "claimedBy": list(s.claimed_by),
                        "selfClaimed": s.self_claimed,
                        "evidenceRefs": list(s.evidence_refs),
                    }
                    for s in self.skill_claims
                ],
            },
            "evidenceSupported": {
                "producedArtifacts": [
                    {
                        "artifactId": p.artifact_id,
                        "receiptId": p.receipt_id,
                        "authoritySupported": p.authority_supported,
                        "authorityReason": str(p.authority_reason),
                        "authorityDetail": p.authority_detail,
                    }
                    for p in self.produced
                ],
                "completedTasks": [
                    {
                        "taskId": t.task_id,
                        "title": t.title,
                        "status": str(t.status),
                        "requesterIsWorker": t.requester_is_worker,
                        "independentVerifiers": list(t.independent_verifiers),
                        "artifactRefs": list(t.artifact_refs),
                    }
                    for t in self.tasks
                ],
                "skills": [
                    {
                        "skill": s.skill,
                        "selfClaimed": s.self_claimed,
                        "citedArtifacts": list(s.cited_artifacts),
                        "producedArtifacts": list(s.produced_artifacts),
                        "independentAttesters": list(s.independent_attesters),
                        "isEvidenceSupported": s.is_evidence_supported,
                    }
                    for s in self.skills
                ],
            },
            "thirdPartyAttested": {
                "attestations": [
                    {
                        "eventId": a.event_id,
                        "issuer": a.issuer,
                        "subjectRef": a.subject_ref,
                        "predicate": a.predicate,
                        "predicateIsKnown": a.predicate_is_known,
                        "value": a.value,
                        "current": a.current,
                    }
                    for a in self.attestations
                ],
                "independentCounterparties": list(self.independent_counterparties),
            },
            # Absent because unbuilt, not because the agent has none.
            "notIncluded": [
                {"section": name, "reason": reason} for name, reason in NOT_IMPLEMENTED
            ],
            "warnings": list(self.warnings),
            "note": self.note,
        }


def _read_profile(event: AdmittedEvent, *, did: str) -> SelfClaim | None:
    subject = _as_did(event.get("subject"))
    if subject != did:
        return None
    if not event.signed_by(did):
        # A statement about someone, signed by someone else, is not a
        # *self*-claim. It is dropped here rather than reclassified, since
        # nothing in the passport's vocabulary covers "a stranger's description
        # of you".
        return None
    return SelfClaim(
        event_id=event.event_id,
        nickname=_as_str(event.get("nickname")),
        description=_as_str(event.get("description")),
    )


def _read_skill(event: AdmittedEvent, *, did: str) -> SkillClaim | None:
    subject = _as_did(event.get("subject"))
    if subject != did:
        return None
    skill = _as_str(event.get("skill"))
    if not skill:
        return None
    raw_refs = event.get("evidenceRefs")
    refs = (
        tuple(sorted({str(r) for r in raw_refs if is_event_id(r)}))
        if isinstance(raw_refs, list)
        else ()
    )
    return SkillClaim(
        event_id=event.event_id,
        skill=skill,
        claimed_by=event.verified_signers,
        evidence_refs=refs,
        self_claimed=did in event.verified_signers,
    )


def build_passport(bundle: EventBundle, *, lineage: str, did: str, at: datetime) -> Passport:
    """Project everything a bundle says about one DID, kept in its categories.

    Offline and deterministic: same events, same `at`, same passport.
    """
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")
    if _as_did(did) is None:
        raise MalformedEventError(f"the subject must be a usable Ed25519 did:key, got {did!r}")

    warnings: list[str] = list(bundle.warnings)
    state = resolve_lineage(bundle, lineage=lineage, at=at)
    warnings.extend(state.warnings)

    # ---- cryptographically linked ----
    scopes: list[str] = []
    holds_live = False
    for standing in describe_grants(bundle, lineage=lineage, at=at):
        if standing.grant.subject != did:
            continue
        if standing.usable:
            holds_live = True
            scopes.extend(scope.render() for scope in standing.grant.scopes)
    authority_scopes = tuple(sorted(set(scopes)))

    # ---- self-claimed ----
    self_claims = tuple(
        claim
        for claim in (
            _read_profile(event, did=did)
            for event in bundle.of_type(PROFILE_STATEMENT, lineage=lineage)
        )
        if claim is not None
    )
    skill_claims = tuple(
        claim
        for claim in (
            _read_skill(event, did=did) for event in bundle.of_type(SKILL_CLAIM, lineage=lineage)
        )
        if claim is not None
    )

    # ---- evidence-supported ----
    produced: list[ProducedArtifact] = []
    receipt_ids: dict[str, str] = {}
    for event in bundle.of_type(ARTIFACT_RECEIPT, lineage=lineage):
        parsed = read_artifact_receipt(event)
        if isinstance(parsed, str):
            warnings.append(f"artifact.receipt {event.event_id} ignored: {parsed}")
            continue
        if parsed.worker != did:
            continue
        authority = check_receipt_authority(bundle, lineage=lineage, receipt=parsed, at=at)
        produced.append(
            ProducedArtifact(
                artifact_id=parsed.artifact_id,
                receipt_id=parsed.event_id,
                authority_supported=authority.supported,
                authority_reason=authority.reason,
                authority_detail=authority.detail,
            )
        )
        receipt_ids[parsed.event_id] = parsed.artifact_id

    produced_ids = {p.artifact_id for p in produced}

    # ---- tasks this DID worked on ----
    tasks: list[TaskParticipation] = []
    for event in bundle.of_type(TASK_REQUEST, lineage=lineage):
        parsed_task = read_task(event)
        if isinstance(parsed_task, str):
            warnings.append(f"task.request {event.event_id} ignored: {parsed_task}")
            continue
        try:
            work = build_work_receipt(bundle, lineage=lineage, task_id=parsed_task.event_id, at=at)
        except MalformedEventError as exc:  # pragma: no cover - defensive
            warnings.append(f"task {parsed_task.event_id} could not be summarised: {exc}")
            continue
        if work.worker != did:
            continue
        tasks.append(
            TaskParticipation(
                task_id=work.task_id,
                title=work.title,
                status=work.status,
                requester_is_worker=work.signals.requester_is_worker,
                independent_verifiers=work.signals.independent_verifiers,
                artifact_refs=work.artifact_refs,
            )
        )

    # ---- third-party attested ----
    subjects = produced_ids | set(receipt_ids)
    attestations: list[ThirdPartyClaim] = []
    for event in bundle.of_type(ATTESTATION_ISSUE, lineage=lineage):
        parsed_attestation = read_attestation(event)
        if isinstance(parsed_attestation, str):
            warnings.append(f"attestation.issue {event.event_id} ignored: {parsed_attestation}")
            continue
        if parsed_attestation.subject_ref not in subjects:
            continue
        attestations.append(
            ThirdPartyClaim(
                event_id=parsed_attestation.event_id,
                issuer=parsed_attestation.issuer,
                subject_ref=parsed_attestation.subject_ref,
                predicate=parsed_attestation.predicate,
                predicate_is_known=parsed_attestation.predicate_is_known,
                value=parsed_attestation.value,
                current=parsed_attestation.is_current(at),
            )
        )

    # ---- skills, backed or not ----
    skills: list[SkillEvidence] = []
    for claim in skill_claims:
        cited = set(claim.evidence_refs)
        made = sorted(cited & produced_ids)
        # Attesters who are not the subject, on artifacts this claim cites.
        attesters = sorted(
            {
                a.issuer
                for a in attestations
                if a.issuer != did
                and a.current
                and (a.subject_ref in cited or receipt_ids.get(a.subject_ref) in cited)
            }
        )
        skills.append(
            SkillEvidence(
                skill=claim.skill,
                self_claimed=claim.self_claimed,
                cited_artifacts=tuple(sorted(cited)),
                produced_artifacts=tuple(made),
                independent_attesters=tuple(attesters),
            )
        )

    return Passport(
        did=did,
        lineage=lineage,
        evaluated_at=at,
        lineage_resolved=state.resolved,
        lineage_reason=state.reason,
        current_root=state.root if state.resolved else None,
        epoch=state.epoch if state.resolved else None,
        authority_scopes=authority_scopes,
        holds_live_authority=holds_live,
        self_claims=tuple(sorted(self_claims, key=lambda c: c.event_id)),
        skill_claims=tuple(sorted(skill_claims, key=lambda c: c.event_id)),
        produced=tuple(sorted(produced, key=lambda p: p.receipt_id)),
        tasks=tuple(sorted(tasks, key=lambda t: t.task_id)),
        skills=tuple(sorted(skills, key=lambda s: s.skill)),
        attestations=tuple(sorted(attestations, key=lambda a: a.event_id)),
        warnings=tuple(warnings),
    )


__all__ = [
    "DELEGATION_GRANT",
    "NOT_IMPLEMENTED",
    "PASSPORT_NOTE",
    "PROFILE_STATEMENT",
    "SKILL_CLAIM",
    "Passport",
    "ProducedArtifact",
    "SelfClaim",
    "SkillClaim",
    "SkillEvidence",
    "TaskParticipation",
    "ThirdPartyClaim",
    "build_passport",
]
