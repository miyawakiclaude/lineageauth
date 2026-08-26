"""Discovery and explainable ranking.

docs/10 permits a number and constrains what kind: explainable, versioned, and
never a hidden trust score. So the tests here are mostly about the *shape* of
the answer -- that a rank can be recomputed from its stated parts, that a search
result refuses to authorize anything, and that the relationship signals a caller
needs in order to judge independence are present rather than folded away.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.actions import sha256_hex
from lineageauth.builders import (
    build_artifact_receipt,
    build_artifact_register,
    build_attestation,
    build_availability_statement,
    build_delegation_grant,
    build_delegation_revoke,
    build_root_create,
    build_skill_claim,
    build_task_claim,
    build_task_request,
    build_task_result,
    build_task_verify,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError
from lineageauth.identifiers import derive_lineage_id
from lineageauth.router import (
    RANKING_VERSION,
    WEIGHTS,
    Query,
    Requirement,
    search,
)
from lineageauth.scopes import ApprovalMode
from tests.testkeys import (
    AGENT_1,
    OUTSIDER,
    RECOVERY_1,
    RECOVERY_2,
    RECOVERY_3,
    ROOT_A,
    unsafe_signer,
)

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
ALICE = unsafe_signer(AGENT_1)
BOB = unsafe_signer(RECOVERY_3)
REQUESTER = unsafe_signer(RECOVERY_1)
VERIFIER = unsafe_signer(RECOVERY_2)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE: str = derive_lineage_id(ROOT.did)

SCOPE = {"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "write"]}
NEED = Requirement(namespace="technocore", resource="room:lobby", action="write")


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, subject: LocalSigner, approval: str = "none") -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=subject.did,
            epoch=0,
            scopes=[SCOPE],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            approval=approval,
            issued_at=AT,
        ),
        [ROOT],
    )


def skill(*, who: LocalSigner, name: str = "curation", refs: list[str] | None = None) -> Envelope:
    return sign_payload(
        build_skill_claim(
            lineage=LINEAGE, subject=who.did, skill=name, evidence_refs=refs, issued_at=AT
        ),
        [who],
    )


def available(
    *, who: LocalSigner, yes: bool = True, expires_at: datetime | None = None
) -> Envelope:
    return sign_payload(
        build_availability_statement(
            lineage=LINEAGE,
            subject=who.did,
            available=yes,
            expires_at=expires_at or AT + timedelta(days=1),
            issued_at=AT,
        ),
        [who],
    )


def produced_work(
    *, who: LocalSigner, content: bytes, verifier: LocalSigner | None = VERIFIER
) -> tuple[list[Envelope], str]:
    """A full task chain plus artifact evidence for `who`."""
    artifact = sha256_hex(content)
    events = [
        sign_payload(
            build_artifact_register(
                lineage=LINEAGE, artifact_id=artifact, created_by=who.did, issued_at=AT
            ),
            [who],
        ),
        sign_payload(
            build_artifact_receipt(
                lineage=LINEAGE, artifact_id=artifact, worker=who.did, issued_at=AT
            ),
            [who],
        ),
    ]
    task = sign_payload(
        build_task_request(
            lineage=LINEAGE,
            requester=REQUESTER.did,
            title=f"work for {content!r}",
            acceptance_criteria=["it is done"],
            issued_at=AT,
        ),
        [REQUESTER],
    )
    held = sign_payload(
        build_task_claim(
            lineage=LINEAGE,
            task=task.event_id,
            claimant=who.did,
            nonce=content.ljust(16, b"\x00")[:16],
            expires_at=AT + timedelta(days=7),
            issued_at=AT,
        ),
        [who],
    )
    done = sign_payload(
        build_task_result(
            lineage=LINEAGE,
            task=task.event_id,
            claim=held.event_id,
            worker=who.did,
            artifact_refs=[artifact],
            summary="finished",
            issued_at=AT,
        ),
        [who],
    )
    events += [task, held, done]
    if verifier is not None:
        events.append(
            sign_payload(
                build_task_verify(
                    lineage=LINEAGE,
                    task=task.event_id,
                    result=done.event_id,
                    verifier=verifier.did,
                    verdict="accepted",
                    issued_at=AT,
                ),
                [verifier],
            )
        )
        events.append(
            sign_payload(
                build_attestation(
                    lineage=LINEAGE,
                    issuer=verifier.did,
                    subject_ref=artifact,
                    predicate="artifact.reviewed",
                    issued_at=AT,
                ),
                [verifier],
            )
        )
    return events, artifact


def run(*envelopes: Envelope, query: Query | None = None, at: datetime = AT):
    return search(
        EventBundle.from_envelopes([genesis(), *envelopes]),
        lineage=LINEAGE,
        query=query or Query(),
        at=at,
    )


# ------------------------------------------------------------ explainability


class TestExplainableRanking:
    def test_the_contributions_add_up_to_the_relevance(self) -> None:
        """The whole meaning of "explainable": you can recompute it."""
        work, artifact = produced_work(who=ALICE, content=b"alice work")
        found = run(grant(subject=ALICE), skill(who=ALICE, refs=[artifact]), *work)
        candidate = next(c for c in found.candidates if c.did == ALICE.did)
        assert candidate.relevance == sum(item.value for item in candidate.contributions)

    def test_every_contribution_names_its_weight_and_reason(self) -> None:
        work, artifact = produced_work(who=ALICE, content=b"alice work")
        found = run(grant(subject=ALICE), skill(who=ALICE, refs=[artifact]), *work)
        candidate = next(c for c in found.candidates if c.did == ALICE.did)
        for item in candidate.contributions:
            assert item.weight == WEIGHTS[item.name]
            assert item.detail
            assert item.value == item.count * item.weight

    def test_the_weights_are_published_with_the_result(self) -> None:
        # Buried weights are the hidden score by another name.
        body = run(grant(subject=ALICE)).to_dict()
        assert body["weights"] == dict(sorted(WEIGHTS.items()))
        assert body["rankingVersion"] == RANKING_VERSION

    def test_the_explanation_reproduces_the_number(self) -> None:
        found = run(grant(subject=ALICE), skill(who=ALICE))
        candidate = found.candidates[0]
        assert f"relevance {candidate.relevance}" in candidate.explanation
        assert RANKING_VERSION in candidate.explanation

    def test_ranking_is_deterministic_and_ties_break_on_did(self) -> None:
        import itertools

        events = [grant(subject=ALICE), grant(subject=BOB), skill(who=ALICE), skill(who=BOB)]
        orders = {
            tuple(c.did for c in run(*order).candidates) for order in itertools.permutations(events)
        }
        assert len(orders) == 1

    def test_no_field_reads_as_a_trust_score(self) -> None:
        body = run(grant(subject=ALICE), skill(who=ALICE)).to_dict()

        def keys(value: object) -> set[str]:
            if isinstance(value, dict):
                found = set(value)
                for item in value.values():
                    found |= keys(item)
                return found
            if isinstance(value, list):
                found: set[str] = set()
                for item in value:
                    found |= keys(item)
                return found
            return set()

        for name in keys(body):
            for word in ("trust", "reputation", "score"):
                assert word not in name.lower(), f"{name} reads as a trust score"


# ------------------------------------------------------------ what it refuses


class TestItDoesNotAuthorize:
    def test_the_note_says_a_result_is_not_authorization(self) -> None:
        found = run(grant(subject=ALICE))
        assert "not authorization" in found.note
        assert "re-check authority at the moment of action" in found.note

    def test_a_candidate_without_the_required_authority_is_excluded(self) -> None:
        found = run(skill(who=ALICE), query=Query(requires=(NEED,)))
        assert not any(c.did == ALICE.did for c in found.candidates)

    def test_a_revoked_grant_removes_the_candidate(self) -> None:
        held = grant(subject=ALICE)
        revocation = sign_payload(
            build_delegation_revoke(
                lineage=LINEAGE, issuer=ROOT.did, grant=held.event_id, issued_at=AT
            ),
            [ROOT],
        )
        found = run(held, revocation, skill(who=ALICE), query=Query(requires=(NEED,)))
        assert found.candidates == ()

    def test_the_authority_reason_is_reported_per_requirement(self) -> None:
        found = run(grant(subject=ALICE), query=Query(requires=(NEED,)))
        candidate = found.candidates[0]
        assert candidate.authority_satisfied
        assert any("room:lobby" in reason for reason in candidate.authority_reasons)

    def test_an_approval_ceiling_filters_stricter_chains(self) -> None:
        # A chain demanding human approval is a live chain, but not one that
        # satisfies a query asking for work that can proceed unattended.
        found = run(
            grant(subject=ALICE, approval="required"),
            query=Query(requires=(NEED,), approval_mode=ApprovalMode.NONE),
        )
        assert found.candidates == ()


# ------------------------------------------------------------ availability


class TestAvailability:
    def test_a_current_statement_counts(self) -> None:
        found = run(grant(subject=ALICE), available(who=ALICE))
        candidate = next(c for c in found.candidates if c.did == ALICE.did)
        assert candidate.availability.usable

    def test_an_expired_statement_is_stale_not_available(self) -> None:
        """An agent that said it was free last week has told you nothing."""
        found = run(
            grant(subject=ALICE),
            available(who=ALICE, expires_at=AT + timedelta(hours=1)),
            at=AT + timedelta(days=2),
        )
        candidate = next(c for c in found.candidates if c.did == ALICE.did)
        assert candidate.availability.stated
        assert candidate.availability.stale
        assert not candidate.availability.usable

    def test_staleness_is_surfaced_as_a_warning(self) -> None:
        found = run(
            grant(subject=ALICE),
            available(who=ALICE, expires_at=AT + timedelta(hours=1)),
            at=AT + timedelta(days=2),
        )
        assert any("told you nothing about now" in w for w in found.warnings)

    def test_requiring_availability_excludes_the_stale(self) -> None:
        found = run(
            grant(subject=ALICE),
            available(who=ALICE, expires_at=AT + timedelta(hours=1)),
            query=Query(require_available=True),
            at=AT + timedelta(days=2),
        )
        assert found.candidates == ()

    def test_an_availability_statement_may_not_run_indefinitely(self) -> None:
        with pytest.raises(MalformedEventError, match="does not expire is treated as a fact"):
            build_availability_statement(
                lineage=LINEAGE,
                subject=ALICE.did,
                available=True,
                expires_at=AT + timedelta(days=365),
                issued_at=AT,
            )


# ------------------------------------------------------------ independence


class TestRelationshipShape:
    def test_evidence_backed_work_outranks_a_bare_claim(self) -> None:
        work, artifact = produced_work(who=ALICE, content=b"alice work")
        found = run(
            grant(subject=ALICE),
            grant(subject=BOB),
            skill(who=ALICE, refs=[artifact]),
            skill(who=BOB),
            *work,
            query=Query(skills=("curation",)),
        )
        assert found.candidates[0].did == ALICE.did
        assert found.candidates[0].evidence_supported_skills == ("curation",)

    def test_a_self_created_task_counts_against(self) -> None:
        """docs/08: not equivalent to independent work, and the rank says so."""
        task = sign_payload(
            build_task_request(
                lineage=LINEAGE,
                requester=ALICE.did,
                title="my own task",
                acceptance_criteria=["done"],
                issued_at=AT,
            ),
            [ALICE],
        )
        held = sign_payload(
            build_task_claim(
                lineage=LINEAGE,
                task=task.event_id,
                claimant=ALICE.did,
                nonce=b"\x55" * 16,
                expires_at=AT + timedelta(days=7),
                issued_at=AT,
            ),
            [ALICE],
        )
        done = sign_payload(
            build_task_result(
                lineage=LINEAGE,
                task=task.event_id,
                claim=held.event_id,
                worker=ALICE.did,
                artifact_refs=[sha256_hex(b"self work")],
                summary="done",
                issued_at=AT,
            ),
            [ALICE],
        )
        found = run(grant(subject=ALICE), task, held, done)
        candidate = next(c for c in found.candidates if c.did == ALICE.did)
        assert candidate.shape.self_created_tasks == 1
        penalty = next(c for c in candidate.contributions if c.name == "self_created_task_only")
        assert penalty.value < 0

    def test_a_rejected_task_counts_against(self) -> None:
        task = sign_payload(
            build_task_request(
                lineage=LINEAGE,
                requester=REQUESTER.did,
                title="rejected work",
                acceptance_criteria=["done"],
                issued_at=AT,
            ),
            [REQUESTER],
        )
        held = sign_payload(
            build_task_claim(
                lineage=LINEAGE,
                task=task.event_id,
                claimant=ALICE.did,
                nonce=b"\x66" * 16,
                expires_at=AT + timedelta(days=7),
                issued_at=AT,
            ),
            [ALICE],
        )
        done = sign_payload(
            build_task_result(
                lineage=LINEAGE,
                task=task.event_id,
                claim=held.event_id,
                worker=ALICE.did,
                artifact_refs=[sha256_hex(b"rejected")],
                summary="attempt",
                issued_at=AT,
            ),
            [ALICE],
        )
        rejected = sign_payload(
            build_task_verify(
                lineage=LINEAGE,
                task=task.event_id,
                result=done.event_id,
                verifier=VERIFIER.did,
                verdict="rejected",
                issued_at=AT,
            ),
            [VERIFIER],
        )
        found = run(grant(subject=ALICE), task, held, done, rejected)
        candidate = next(c for c in found.candidates if c.did == ALICE.did)
        assert candidate.shape.rejected_tasks == 1
        assert any(c.name == "rejected_task" and c.value < 0 for c in candidate.contributions)

    def test_attestation_concentration_is_reported(self) -> None:
        # Ten attestations from one key are one opinion repeated, and the
        # concentration figure is how a caller sees that.
        work, artifact = produced_work(who=ALICE, content=b"alice work")
        extra = sign_payload(
            build_attestation(
                lineage=LINEAGE,
                issuer=VERIFIER.did,
                subject_ref=artifact,
                predicate="artifact.reproduced",
                issued_at=AT,
            ),
            [VERIFIER],
        )
        found = run(grant(subject=ALICE), *work, extra)
        candidate = next(c for c in found.candidates if c.did == ALICE.did)
        assert candidate.shape.attestation_concentration == 1.0
        assert candidate.shape.independent_counterparties == 1

    def test_nothing_claims_sybil_detection(self) -> None:
        found = run(grant(subject=ALICE))
        assert "Nothing here detects Sybils" in found.note


# ------------------------------------------------------------ query semantics


class TestQuerySemantics:
    def test_a_skill_filter_excludes_agents_without_it(self) -> None:
        found = run(
            grant(subject=ALICE),
            grant(subject=BOB),
            skill(who=ALICE, name="curation"),
            skill(who=BOB, name="translation"),
            query=Query(skills=("curation",)),
        )
        assert [c.did for c in found.candidates] == [ALICE.did]

    def test_an_empty_query_returns_everyone_it_knows_about(self) -> None:
        found = run(grant(subject=ALICE), grant(subject=BOB), skill(who=ALICE), skill(who=BOB))
        assert {c.did for c in found.candidates} == {ALICE.did, BOB.did}

    def test_the_considered_count_is_reported(self) -> None:
        found = run(skill(who=ALICE), skill(who=BOB), query=Query(skills=("nothing",)))
        assert found.candidates == ()
        assert found.considered >= 2

    def test_a_naive_evaluation_time_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="timezone-aware"):
            search(
                EventBundle.from_envelopes([genesis()]),
                lineage=LINEAGE,
                query=Query(),
                at=datetime(2026, 8, 27, 12, 0, 0),
            )

    def test_a_malformed_requirement_is_refused_at_construction(self) -> None:
        with pytest.raises(MalformedEventError):
            Requirement(namespace="technocore", resource="room:a/b", action="write")
