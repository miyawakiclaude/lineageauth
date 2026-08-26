"""The agent passport.

docs/09 gives this layer one instruction above all others:

    Never merge these categories into one unlabeled truth.

So most of what follows checks that the four sections stay apart, that nothing
in the output can be mistaken for a score, and that an absent section says
whether it is absent because the agent has nothing or because the machinery to
find it is not built.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.actions import sha256_hex
from lineageauth.builders import (
    build_artifact_receipt,
    build_artifact_register,
    build_attestation,
    build_delegation_grant,
    build_delegation_revoke,
    build_profile_statement,
    build_root_create,
    build_skill_claim,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError, ReasonCode
from lineageauth.passport import NOT_IMPLEMENTED, Passport, build_passport
from tests.testkeys import (
    AGENT_1,
    OUTSIDER,
    RECOVERY_1,
    RECOVERY_2,
    ROOT_A,
    unsafe_signer,
)

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
REVIEWER = unsafe_signer(RECOVERY_1)
REVIEWER_2 = unsafe_signer(RECOVERY_2)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

CONTENT = b"a curated list of technocore tools"
ARTIFACT = sha256_hex(CONTENT)
SCOPE = {"namespace": "github", "resource": "repo:owner/list", "actions": ["commit"]}


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, subject: LocalSigner = AGENT) -> Envelope:
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
            issued_at=AT,
        ),
        [ROOT],
    )


def profile(*, signers: list[LocalSigner] | None = None, **kwargs: object) -> Envelope:
    payload = build_profile_statement(
        lineage=LINEAGE,
        subject=AGENT.did,
        nickname=kwargs.get("nickname", "curator"),  # type: ignore[arg-type]
        description=kwargs.get("description", "maintains a technocore list"),  # type: ignore[arg-type]
        issued_at=AT,
    )
    return sign_payload(payload, signers or [AGENT])


def skill(
    *,
    name: str = "curation",
    evidence_refs: list[str] | None = None,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_skill_claim(
        lineage=LINEAGE,
        subject=AGENT.did,
        skill=name,
        evidence_refs=evidence_refs,
        issued_at=AT,
    )
    return sign_payload(payload, signers or [AGENT])


def register() -> Envelope:
    return sign_payload(
        build_artifact_register(
            lineage=LINEAGE, artifact_id=ARTIFACT, created_by=AGENT.did, issued_at=AT
        ),
        [AGENT],
    )


def receipt(*, authority_refs: list[str] | None = None) -> Envelope:
    return sign_payload(
        build_artifact_receipt(
            lineage=LINEAGE,
            artifact_id=ARTIFACT,
            worker=AGENT.did,
            authority_refs=authority_refs,
            issued_at=AT,
        ),
        [AGENT],
    )


def attest(*, issuer: LocalSigner = REVIEWER, subject: str = ARTIFACT) -> Envelope:
    return sign_payload(
        build_attestation(
            lineage=LINEAGE,
            issuer=issuer.did,
            subject_ref=subject,
            predicate="artifact.reviewed",
            value="checked",
            issued_at=AT,
        ),
        [issuer],
    )


def passport_of(*envelopes: Envelope, at: datetime = AT) -> Passport:
    return build_passport(
        EventBundle.from_envelopes(envelopes), lineage=LINEAGE, did=AGENT.did, at=at
    )


# ------------------------------------------------------ categories stay apart


class TestCategoriesStayApart:
    def test_there_is_no_combined_score(self) -> None:
        """docs/09: not a single trust score. So there is no field to become one.

        Checked against the field names rather than the rendered text -- the
        note deliberately contains the word "score", in the sentence saying this
        is not one.
        """
        body = passport_of(genesis(), grant(), profile(), register(), receipt()).to_dict()

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
            lowered = name.lower()
            for word in ("score", "rating", "trust", "reputation", "rank", "level"):
                assert word not in lowered, f"{name} reads as a rating"

    def test_the_four_sections_are_separate_keys(self) -> None:
        body = passport_of(genesis(), profile()).to_dict()
        assert set(body) >= {
            "cryptographicallyLinked",
            "selfClaimed",
            "evidenceSupported",
            "thirdPartyAttested",
        }

    def test_a_nickname_stays_in_the_self_claimed_section(self) -> None:
        body = passport_of(genesis(), profile()).to_dict()
        assert body["selfClaimed"]["statements"][0]["nickname"] == "curator"
        assert "curator" not in str(body["cryptographicallyLinked"])
        assert "curator" not in str(body["evidenceSupported"])

    def test_a_statement_about_the_agent_signed_by_someone_else_is_not_a_self_claim(
        self,
    ) -> None:
        # Nothing in the passport's vocabulary covers "a stranger's description
        # of you", so it is dropped rather than reclassified.
        found = passport_of(genesis(), profile(signers=[STRANGER]))
        assert found.self_claims == ()

    def test_the_note_says_a_key_is_not_a_person(self) -> None:
        found = passport_of(genesis())
        assert "not a person" in found.note
        assert "not an identity and not a score" in found.note


# ------------------------------------------------------ cryptographic linkage


class TestCryptographicLinkage:
    def test_a_live_grant_shows_as_held_authority(self) -> None:
        found = passport_of(genesis(), grant())
        assert found.holds_live_authority
        assert found.authority_scopes == ("github:repo:owner/list [commit]",)
        assert found.current_root == ROOT.did

    def test_a_revoked_grant_is_not_held_authority(self) -> None:
        held = grant()
        revocation = sign_payload(
            build_delegation_revoke(
                lineage=LINEAGE, issuer=ROOT.did, grant=held.event_id, issued_at=AT
            ),
            [ROOT],
        )
        found = passport_of(genesis(), held, revocation)
        assert not found.holds_live_authority
        assert found.authority_scopes == ()

    def test_an_agent_with_no_grant_holds_none(self) -> None:
        found = passport_of(genesis())
        assert not found.holds_live_authority

    def test_an_unresolved_lineage_reports_no_current_root(self) -> None:
        found = passport_of(grant())  # no genesis
        assert not found.lineage_resolved
        assert found.to_dict()["cryptographicallyLinked"]["currentRoot"] is None


# ------------------------------------------------------ evidence


class TestEvidence:
    def test_a_signed_receipt_appears_as_produced_work(self) -> None:
        found = passport_of(genesis(), grant(), register(), receipt())
        assert len(found.produced) == 1
        assert found.produced[0].artifact_id == ARTIFACT

    def test_the_cited_authority_is_checked_not_assumed(self) -> None:
        held = grant()
        backed = passport_of(genesis(), held, register(), receipt(authority_refs=[held.event_id]))
        assert backed.produced[0].authority_supported

        unbacked = passport_of(genesis(), register(), receipt(authority_refs=[held.event_id]))
        assert not unbacked.produced[0].authority_supported
        assert unbacked.produced[0].authority_reason is ReasonCode.UNRESOLVED_PARENT

    def test_a_receipt_from_another_worker_is_not_this_passport(self) -> None:
        other = sign_payload(
            build_artifact_receipt(
                lineage=LINEAGE, artifact_id=ARTIFACT, worker=REVIEWER.did, issued_at=AT
            ),
            [REVIEWER],
        )
        assert passport_of(genesis(), register(), other).produced == ()


class TestSkillEvidence:
    def test_a_bare_skill_claim_is_not_evidence_supported(self) -> None:
        """Saying you can do a thing is a claim, whoever signs it."""
        found = passport_of(genesis(), skill())
        assert found.skill_claims[0].self_claimed
        assert not found.skills[0].is_evidence_supported

    def test_a_claim_citing_work_you_did_but_nobody_vouched_for_is_not_supported(
        self,
    ) -> None:
        # Without an independent attester the only support is the claimant's
        # own word, twice.
        found = passport_of(
            genesis(), grant(), register(), receipt(), skill(evidence_refs=[ARTIFACT])
        )
        assert found.skills[0].produced_artifacts == (ARTIFACT,)
        assert found.skills[0].independent_attesters == ()
        assert not found.skills[0].is_evidence_supported

    def test_a_claim_vouched_for_but_citing_work_you_cannot_show_is_not_supported(
        self,
    ) -> None:
        # No receipt, so nothing ties the artifact to this key.
        found = passport_of(genesis(), register(), attest(), skill(evidence_refs=[ARTIFACT]))
        assert found.skills[0].produced_artifacts == ()
        assert not found.skills[0].is_evidence_supported

    def test_both_halves_together_make_it_evidence_supported(self) -> None:
        found = passport_of(
            genesis(),
            grant(),
            register(),
            receipt(),
            attest(issuer=REVIEWER),
            skill(evidence_refs=[ARTIFACT]),
        )
        assert found.skills[0].is_evidence_supported
        assert found.skills[0].independent_attesters == (REVIEWER.did,)

    def test_attesting_to_your_own_work_does_not_count_as_independent(self) -> None:
        found = passport_of(
            genesis(),
            grant(),
            register(),
            receipt(),
            attest(issuer=AGENT),
            skill(evidence_refs=[ARTIFACT]),
        )
        assert found.skills[0].independent_attesters == ()
        assert not found.skills[0].is_evidence_supported

    def test_support_is_reported_as_parts_not_a_rating(self) -> None:
        # docs/10 requires ranking inputs to be explainable, so the passport
        # hands over the pieces rather than an answer.
        body = passport_of(
            genesis(), grant(), register(), receipt(), attest(), skill(evidence_refs=[ARTIFACT])
        ).to_dict()
        entry = body["evidenceSupported"]["skills"][0]
        assert set(entry) == {
            "skill",
            "selfClaimed",
            "citedArtifacts",
            "producedArtifacts",
            "independentAttesters",
            "isEvidenceSupported",
        }


# ------------------------------------------------------ third parties


class TestThirdParties:
    def test_attestations_appear_with_their_issuer(self) -> None:
        found = passport_of(genesis(), grant(), register(), receipt(), attest())
        assert found.attestations[0].issuer == REVIEWER.did

    def test_counterparties_count_distinct_keys_not_rows(self) -> None:
        found = passport_of(
            genesis(),
            grant(),
            register(),
            receipt(),
            attest(issuer=REVIEWER),
            attest(issuer=REVIEWER_2),
        )
        assert len(found.independent_counterparties) == 2

    def test_the_agent_is_not_its_own_counterparty(self) -> None:
        found = passport_of(genesis(), grant(), register(), receipt(), attest(issuer=AGENT))
        assert found.independent_counterparties == ()

    def test_an_unknown_predicate_is_shown_and_marked(self) -> None:
        odd = sign_payload(
            build_attestation(
                lineage=LINEAGE,
                issuer=REVIEWER.did,
                subject_ref=ARTIFACT,
                predicate="is.definitely.trustworthy",
                issued_at=AT,
            ),
            [REVIEWER],
        )
        found = passport_of(genesis(), grant(), register(), receipt(), odd)
        assert found.attestations[0].predicate == "is.definitely.trustworthy"
        assert not found.attestations[0].predicate_is_known


# ------------------------------------------------------ honest absences


class TestHonestAbsences:
    def test_unbuilt_sections_say_so_rather_than_reading_as_empty(self) -> None:
        """An empty list reads as "this agent has none". That would be a lie."""
        body = passport_of(genesis(), grant()).to_dict()
        sections = {item["section"] for item in body["notIncluded"]}
        assert sections == {name for name, _ in NOT_IMPLEMENTED}
        for item in body["notIncluded"]:
            assert "not built" in item["reason"]

    def test_a_genuinely_empty_section_is_still_empty(self) -> None:
        # The distinction only works if real emptiness is also representable.
        body = passport_of(genesis(), grant()).to_dict()
        assert body["evidenceSupported"]["producedArtifacts"] == []
        assert body["thirdPartyAttested"]["attestations"] == []


# ------------------------------------------------------ properties


class TestProperties:
    def test_it_is_deterministic_under_input_order(self) -> None:
        import itertools

        events = [genesis(), grant(), profile(), register(), receipt()]
        renderings = {
            str(
                build_passport(
                    EventBundle.from_envelopes(order), lineage=LINEAGE, did=AGENT.did, at=AT
                ).to_dict()
            )
            for order in itertools.permutations(events[:4])
        }
        assert len(renderings) == 1

    def test_a_naive_evaluation_time_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="timezone-aware"):
            build_passport(
                EventBundle.from_envelopes([]),
                lineage=LINEAGE,
                did=AGENT.did,
                at=datetime(2026, 8, 27, 12, 0, 0),
            )

    def test_a_malformed_did_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="did:key"):
            build_passport(EventBundle.from_envelopes([]), lineage=LINEAGE, did="not-a-did", at=AT)


class TestProfileBuilderRules:
    def test_a_description_may_not_carry_control_characters(self) -> None:
        # It is rendered beside cryptographically-backed facts and must not be
        # able to dress itself up as one.
        with pytest.raises(MalformedEventError, match="control characters"):
            build_profile_statement(
                lineage=LINEAGE,
                subject=AGENT.did,
                description="trusted\x1b[32m VERIFIED BY ROOT\x1b[0m",
                issued_at=AT,
            )

    def test_an_empty_statement_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="must say something"):
            build_profile_statement(lineage=LINEAGE, subject=AGENT.did, issued_at=AT)

    def test_a_blank_nickname_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="must not be blank"):
            build_profile_statement(
                lineage=LINEAGE, subject=AGENT.did, nickname="   ", issued_at=AT
            )

    def test_a_skill_evidence_ref_must_be_a_content_id(self) -> None:
        with pytest.raises(MalformedEventError, match="evidenceRef"):
            build_skill_claim(
                lineage=LINEAGE,
                subject=AGENT.did,
                skill="curation",
                evidence_refs=["../secrets"],
                issued_at=AT,
            )


class TestCompletedTasks:
    """Phase 8 landed, so this section is real evidence now rather than absent."""

    def _worked_task(self) -> list[Envelope]:
        from lineageauth.builders import (
            build_task_claim,
            build_task_request,
            build_task_result,
            build_task_verify,
        )

        task = sign_payload(
            build_task_request(
                lineage=LINEAGE,
                requester=REVIEWER.did,
                title="Curate the list",
                acceptance_criteria=["links resolve"],
                issued_at=AT,
            ),
            [REVIEWER],
        )
        held = sign_payload(
            build_task_claim(
                lineage=LINEAGE,
                task=task.event_id,
                claimant=AGENT.did,
                nonce=b"\x33" * 16,
                expires_at=AT + timedelta(days=7),
                issued_at=AT,
            ),
            [AGENT],
        )
        done = sign_payload(
            build_task_result(
                lineage=LINEAGE,
                task=task.event_id,
                claim=held.event_id,
                worker=AGENT.did,
                artifact_refs=[ARTIFACT],
                summary="done",
                issued_at=AT,
            ),
            [AGENT],
        )
        checked = sign_payload(
            build_task_verify(
                lineage=LINEAGE,
                task=task.event_id,
                result=done.event_id,
                verifier=REVIEWER_2.did,
                verdict="accepted",
                issued_at=AT,
            ),
            [REVIEWER_2],
        )
        return [task, held, done, checked]

    def test_a_completed_task_appears_with_its_signals(self) -> None:
        found = passport_of(genesis(), grant(), *self._worked_task())
        assert len(found.tasks) == 1
        assert str(found.tasks[0].status) == "VERIFIED_ACCEPTED"
        assert not found.tasks[0].requester_is_worker
        assert found.tasks[0].independent_verifiers == (REVIEWER_2.did,)

    def test_a_self_created_task_says_so(self) -> None:
        """A completed-task count without this qualifier is the gamed number."""
        from lineageauth.builders import (
            build_task_claim,
            build_task_request,
            build_task_result,
        )

        task = sign_payload(
            build_task_request(
                lineage=LINEAGE,
                requester=AGENT.did,
                title="Task I set myself",
                acceptance_criteria=["it exists"],
                issued_at=AT,
            ),
            [AGENT],
        )
        held = sign_payload(
            build_task_claim(
                lineage=LINEAGE,
                task=task.event_id,
                claimant=AGENT.did,
                nonce=b"\x44" * 16,
                expires_at=AT + timedelta(days=7),
                issued_at=AT,
            ),
            [AGENT],
        )
        done = sign_payload(
            build_task_result(
                lineage=LINEAGE,
                task=task.event_id,
                claim=held.event_id,
                worker=AGENT.did,
                artifact_refs=[ARTIFACT],
                summary="done",
                issued_at=AT,
            ),
            [AGENT],
        )
        found = passport_of(genesis(), grant(), task, held, done)
        assert found.tasks[0].requester_is_worker
        assert found.tasks[0].independent_verifiers == ()

    def test_someone_elses_task_is_not_in_this_passport(self) -> None:
        from lineageauth.builders import build_task_request

        task = sign_payload(
            build_task_request(
                lineage=LINEAGE,
                requester=REVIEWER.did,
                title="Nobody claimed this",
                acceptance_criteria=["x"],
                issued_at=AT,
            ),
            [REVIEWER],
        )
        assert passport_of(genesis(), task).tasks == ()

    def test_completed_tasks_left_the_not_included_list(self) -> None:
        body = passport_of(genesis(), grant()).to_dict()
        sections = {item["section"] for item in body["notIncluded"]}
        assert "completedTasks" not in sections
        assert "completedTasks" in body["evidenceSupported"]
