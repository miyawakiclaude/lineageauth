"""Disputes and juries.

`docs/12` is unusually clear about what this layer must not claim, and those
refusals are what the tests are mostly about: a split jury is not a verdict, a
deterministic draw is not an unbiased one, and a disclosed conflict is not
grounds for throwing a vote away.

The one thing a dispute layer must get right is that the procedure was fixed
before the votes were counted. So the policy travels inside `dispute.open` and
the builder refuses to draft a policy both sides could satisfy.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.actions import sha256_hex
from lineageauth.builders import (
    build_artifact_register,
    build_dispute_open,
    build_fleet_bind,
    build_fleet_create,
    build_jury_disclose,
    build_jury_vote,
    build_root_create,
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
from lineageauth.jury import (
    ABSTAIN,
    FAILS_CRITERIA,
    MEETS_CRITERIA,
    Outcome,
    UnknownCaseError,
    disputes_involving,
    resolve_dispute,
    seat_jurors,
)
from lineageauth.work import TaskStatus, resolve_task
from tests.testkeys import ROOT_A, unsafe_signer

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
REQUESTER = unsafe_signer("jury-requester")
WORKER = unsafe_signer("jury-worker")
VERIFIER = unsafe_signer("jury-verifier")
OPERATOR = unsafe_signer("jury-operator")
STRANGER = unsafe_signer("jury-stranger")
JURORS = [unsafe_signer(f"juror-{n}") for n in range(1, 6)]
J1, J2, J3, J4, J5 = JURORS

LINEAGE: str = derive_lineage_id(ROOT.did)
ARTIFACT = sha256_hex(b"the disputed work")


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


class Work:
    """One task carried all the way to a result, so a dispute has something to bite."""

    def __init__(self) -> None:
        self.request = sign_payload(
            build_task_request(
                lineage=LINEAGE,
                requester=REQUESTER.did,
                title="index the room list",
                acceptance_criteria=["every room reachable"],
                issued_at=AT,
            ),
            [REQUESTER],
        )
        self.claim = sign_payload(
            build_task_claim(
                lineage=LINEAGE,
                task=self.request.event_id,
                claimant=WORKER.did,
                nonce=b"n" * 16,
                expires_at=AT + timedelta(days=2),
                issued_at=AT,
            ),
            [WORKER],
        )
        self.artifact = sign_payload(
            build_artifact_register(
                lineage=LINEAGE, artifact_id=ARTIFACT, created_by=WORKER.did, issued_at=AT
            ),
            [WORKER],
        )
        self.result = sign_payload(
            build_task_result(
                lineage=LINEAGE,
                task=self.request.event_id,
                claim=self.claim.event_id,
                worker=WORKER.did,
                artifact_refs=[ARTIFACT],
                summary="indexed 41 rooms",
                issued_at=AT,
            ),
            [WORKER],
        )
        self.verification = sign_payload(
            build_task_verify(
                lineage=LINEAGE,
                task=self.request.event_id,
                result=self.result.event_id,
                verifier=VERIFIER.did,
                verdict="rejected",
                issued_at=AT,
            ),
            [VERIFIER],
        )

    @property
    def envelopes(self) -> list[Envelope]:
        return [self.request, self.claim, self.artifact, self.result, self.verification]


WORK = Work()


def case_envelope(
    *,
    opener: LocalSigner = WORKER,
    jurors: list[LocalSigner] | None = None,
    quorum: int = 3,
    threshold: int = 3,
    signers: list[LocalSigner] | None = None,
    **kwargs: object,
) -> Envelope:
    seated = jurors if jurors is not None else JURORS[:5]
    fields: dict[str, object] = {
        "lineage": LINEAGE,
        "opener": opener.did,
        "task": WORK.request.event_id,
        "result": WORK.result.event_id,
        "reason_code": "criteria-misread",
        "statement": "every room was reachable; the verifier tested a stale snapshot",
        "jurors": [j.did for j in seated],
        "quorum": quorum,
        "threshold": threshold,
        "disputed_verification": WORK.verification.event_id,
        "issued_at": AT,
    }
    fields.update(kwargs)
    payload = build_dispute_open(**fields)  # type: ignore[arg-type]
    return sign_payload(payload, signers or [opener])


def vote(
    juror: LocalSigner,
    finding: str,
    *,
    case: Envelope,
    reason: str = "reviewed-evidence",
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_jury_vote(
        lineage=LINEAGE,
        case=case.event_id,
        juror=juror.did,
        finding=finding,
        reason_code=reason,
        issued_at=AT,
    )
    return sign_payload(payload, signers or [juror])


def resolve(case: Envelope, *envelopes: Envelope, at: datetime = AT):
    bundle = EventBundle.from_envelopes([genesis(), *WORK.envelopes, case, *envelopes])
    return resolve_dispute(bundle, lineage=LINEAGE, case_id=case.event_id, at=at)


# ------------------------------------------------------------ the tally


class TestOutcome:
    def test_a_threshold_of_findings_settles_the_case(self) -> None:
        case = case_envelope()
        found = resolve(
            case,
            vote(J1, MEETS_CRITERIA, case=case),
            vote(J2, MEETS_CRITERIA, case=case),
            vote(J3, MEETS_CRITERIA, case=case),
        )
        assert found.outcome is Outcome.MET_CRITERIA
        assert found.meets == 3

    def test_the_other_side_settles_it_too(self) -> None:
        case = case_envelope()
        found = resolve(
            case,
            *(vote(j, FAILS_CRITERIA, case=case) for j in (J1, J2, J3)),
        )
        assert found.outcome is Outcome.FAILED_CRITERIA

    def test_below_quorum_is_awaiting_votes_not_a_verdict(self) -> None:
        case = case_envelope()
        found = resolve(case, vote(J1, MEETS_CRITERIA, case=case))
        assert found.outcome is Outcome.AWAITING_VOTES
        assert "1 of the 3 votes" in found.detail

    def test_a_split_jury_is_undecided_and_nothing_breaks_the_tie(self) -> None:
        """Quorum met, neither side at the threshold. That is a real answer."""
        case = case_envelope()
        found = resolve(
            case,
            vote(J1, MEETS_CRITERIA, case=case),
            vote(J2, MEETS_CRITERIA, case=case),
            vote(J3, FAILS_CRITERIA, case=case),
            vote(J4, FAILS_CRITERIA, case=case),
            vote(J5, ABSTAIN, case=case),
        )
        assert found.outcome is Outcome.UNDECIDED
        assert "nothing here breaks the tie" in found.detail

    def test_an_abstention_reaches_quorum_but_joins_neither_side(self) -> None:
        case = case_envelope()
        found = resolve(
            case,
            vote(J1, MEETS_CRITERIA, case=case),
            vote(J2, MEETS_CRITERIA, case=case),
            vote(J3, ABSTAIN, case=case),
        )
        assert found.votes_cast == 3
        assert found.abstentions == 1
        assert found.outcome is Outcome.UNDECIDED

    def test_the_order_votes_arrive_in_changes_nothing(self) -> None:
        case = case_envelope()
        votes = [vote(j, MEETS_CRITERIA, case=case) for j in (J1, J2, J3)]
        assert resolve(case, *votes).outcome is resolve(case, *reversed(votes)).outcome


class TestWhoMayVote:
    def test_a_vote_must_be_signed_by_the_juror_it_names(self) -> None:
        """Otherwise the opener could mint the jury's findings themselves."""
        case = case_envelope()
        forged = vote(J1, MEETS_CRITERIA, case=case, signers=[WORKER])
        found = resolve(case, forged, vote(J2, MEETS_CRITERIA, case=case))
        assert found.votes_cast == 1
        assert any("not signed by the juror" in w for w in found.warnings)

    def test_someone_without_a_seat_does_not_vote(self) -> None:
        case = case_envelope()
        found = resolve(case, vote(STRANGER, MEETS_CRITERIA, case=case))
        assert found.votes_cast == 0
        assert any("does not hold a seat" in w for w in found.warnings)

    def test_two_different_findings_from_one_juror_void_that_seat(self) -> None:
        """Taking the later one would make a vote revisable by publishing again."""
        case = case_envelope()
        found = resolve(
            case,
            vote(J1, MEETS_CRITERIA, case=case),
            vote(J1, FAILS_CRITERIA, case=case, reason="changed-my-mind"),
            vote(J2, MEETS_CRITERIA, case=case),
            vote(J3, MEETS_CRITERIA, case=case),
        )
        assert found.votes_cast == 2
        assert found.outcome is Outcome.AWAITING_VOTES
        assert any("in either direction" in w for w in found.warnings)

    def test_a_juror_republishing_the_same_finding_still_has_one_vote(self) -> None:
        case = case_envelope()
        again = sign_payload(
            build_jury_vote(
                lineage=LINEAGE,
                case=case.event_id,
                juror=J1.did,
                finding=MEETS_CRITERIA,
                reason_code="reviewed-evidence",
                issued_at=AT + timedelta(minutes=5),
            ),
            [J1],
        )
        found = resolve(case, vote(J1, MEETS_CRITERIA, case=case), again)
        assert found.votes_cast == 1


# ------------------------------------------------------------ conflicts


class TestConflicts:
    def _fleet(self, *members: LocalSigner) -> list[Envelope]:
        group = sign_payload(
            build_fleet_create(lineage=LINEAGE, controller=OPERATOR.did, name="acme", issued_at=AT),
            [OPERATOR],
        )
        return [group] + [
            sign_payload(
                build_fleet_bind(
                    lineage=LINEAGE,
                    fleet=group.event_id,
                    controller=OPERATOR.did,
                    member=m.did,
                    issued_at=AT,
                ),
                [OPERATOR],
            )
            for m in members
        ]

    def test_a_juror_who_already_ruled_on_the_result_has_a_prior_role(self) -> None:
        case = case_envelope(jurors=[VERIFIER, J1, J2])
        found = resolve(case)
        record = next(r for r in found.jurors if r.juror == VERIFIER.did)
        assert "prior-role-in-task" in record.detected_conflicts

    def test_a_disclosed_fleet_sibling_of_a_party_is_detected(self) -> None:
        case = case_envelope(jurors=[J1, J2, J3])
        found = resolve(case, *self._fleet(WORKER, J1))
        record = next(r for r in found.jurors if r.juror == J1.did)
        assert "same-fleet" in record.detected_conflicts

    def test_an_undisclosed_conflict_is_named_as_such(self) -> None:
        case = case_envelope(jurors=[VERIFIER, J1, J2])
        found = resolve(case)
        assert found.undisclosed_conflicts == ((VERIFIER.did, ("prior-role-in-task",)),)

    def test_disclosing_the_detected_conflict_clears_the_undisclosed_list(self) -> None:
        case = case_envelope(jurors=[VERIFIER, J1, J2])
        disclosure = sign_payload(
            build_jury_disclose(
                lineage=LINEAGE,
                case=case.event_id,
                juror=VERIFIER.did,
                conflicts=["prior-role-in-task"],
                note="I filed the rejection under dispute",
                issued_at=AT,
            ),
            [VERIFIER],
        )
        found = resolve(case, disclosure)
        assert found.undisclosed_conflicts == ()
        record = next(r for r in found.jurors if r.juror == VERIFIER.did)
        assert record.is_conflicted

    def test_a_conflict_never_voids_the_vote(self) -> None:
        """docs/12: disclosure is evidence, not automatic identity truth."""
        case = case_envelope(jurors=[VERIFIER, J1, J2], quorum=3, threshold=2)
        found = resolve(
            case,
            vote(VERIFIER, FAILS_CRITERIA, case=case),
            vote(J1, FAILS_CRITERIA, case=case),
            vote(J2, MEETS_CRITERIA, case=case),
        )
        assert found.votes_cast == 3
        assert found.outcome is Outcome.FAILED_CRITERIA

    def test_the_case_says_whether_the_outcome_needed_the_conflicted_votes(self) -> None:
        case = case_envelope(jurors=[VERIFIER, J1, J2], quorum=3, threshold=2)
        found = resolve(
            case,
            vote(VERIFIER, FAILS_CRITERIA, case=case),
            vote(J1, FAILS_CRITERIA, case=case),
            vote(J2, MEETS_CRITERIA, case=case),
        )
        assert found.outcome is Outcome.FAILED_CRITERIA
        assert found.outcome_without_conflicted is Outcome.AWAITING_VOTES
        assert found.outcome_depends_on_conflicted_jurors

    def test_an_outcome_that_stands_without_them_says_so(self) -> None:
        case = case_envelope(jurors=[J1, J2, J3])
        found = resolve(case, *(vote(j, MEETS_CRITERIA, case=case) for j in (J1, J2, J3)))
        assert not found.outcome_depends_on_conflicted_jurors
        # Seats come back in canonical DID order, not the order the opener typed.
        assert set(found.unconflicted_jurors) == {J1.did, J2.did, J3.did}

    def test_detection_does_not_pretend_to_be_complete(self) -> None:
        found = resolve(case_envelope())
        assert "an empty detected list is not a clean bill" in found.note


# ------------------------------------------------------------ selection


class TestSelection:
    def _drawn(self, *, seed: str, seats: int = 3) -> Envelope:
        payload = build_dispute_open(
            lineage=LINEAGE,
            opener=WORKER.did,
            task=WORK.request.event_id,
            result=WORK.result.event_id,
            reason_code="criteria-misread",
            statement="drawn from a declared pool",
            pool=[j.did for j in JURORS],
            seats=seats,
            seed=seed,
            quorum=2,
            threshold=2,
            issued_at=AT,
        )
        return sign_payload(payload, [WORKER])

    def test_a_draw_is_reproducible(self) -> None:
        case = self._drawn(seed="case-0001")
        first = resolve(case)
        second = resolve(case)
        assert [r.juror for r in first.jurors] == [r.juror for r in second.jurors]
        assert len(first.jurors) == 3

    def test_a_different_seed_seats_a_different_jury(self) -> None:
        one = {r.juror for r in resolve(self._drawn(seed="case-0001")).jurors}
        other = {r.juror for r in resolve(self._drawn(seed="case-0002")).jurors}
        assert one != other

    def test_the_draw_never_claims_to_be_unbiased(self) -> None:
        """The opener picks the seed, so the opener can grind it. Say so."""
        found = resolve(self._drawn(seed="case-0001"))
        assert "reproducible, not unbiased" in found.note
        assert "could have searched" in found.note

    def test_a_named_jury_carries_no_such_caveat(self) -> None:
        found = resolve(case_envelope())
        assert "reproducible, not unbiased" not in found.note

    def test_only_the_drawn_jurors_may_vote(self) -> None:
        case = self._drawn(seed="case-0001")
        seated = {r.juror for r in resolve(case).jurors}
        outside = next(j for j in JURORS if j.did not in seated)
        found = resolve(case, vote(outside, MEETS_CRITERIA, case=case))
        assert found.votes_cast == 0

    def test_seating_is_stable_under_pool_order(self) -> None:
        from lineageauth.jury import Selection

        pool = tuple(j.did for j in JURORS)
        forward = seat_jurors(Selection(mode="declared-pool", pool=pool, seats=3, seed="case-0001"))
        backward = seat_jurors(
            Selection(mode="declared-pool", pool=tuple(reversed(pool)), seats=3, seed="case-0001")
        )
        assert forward == backward


# ------------------------------------------------------------ what it settles


class TestWhatAVerdictIsNot:
    def test_the_task_status_is_untouched_by_the_jury(self) -> None:
        """Two independent facts, reported side by side rather than merged."""
        case = case_envelope()
        bundle = EventBundle.from_envelopes(
            [
                genesis(),
                *WORK.envelopes,
                case,
                *(vote(j, MEETS_CRITERIA, case=case) for j in (J1, J2, J3)),
            ]
        )
        state = resolve_task(bundle, lineage=LINEAGE, task_id=WORK.request.event_id, at=AT)
        found = resolve_dispute(bundle, lineage=LINEAGE, case_id=case.event_id, at=AT)
        assert state.status is TaskStatus.VERIFIED_REJECTED
        assert found.outcome is Outcome.MET_CRITERIA

    def test_the_note_refuses_the_bigger_claim(self) -> None:
        found = resolve(case_envelope())
        assert "not legal arbitration" in found.note
        assert "does not overwrite the task" in found.note

    def test_an_unknown_case_is_an_error_rather_than_an_empty_verdict(self) -> None:
        bundle = EventBundle.from_envelopes([genesis()])
        with pytest.raises(UnknownCaseError):
            resolve_dispute(bundle, lineage=LINEAGE, case_id="sha256:" + "a" * 64, at=AT)

    def test_a_case_not_signed_by_its_opener_is_not_a_case(self) -> None:
        forged = case_envelope(opener=WORKER, signers=[STRANGER])
        bundle = EventBundle.from_envelopes([genesis(), *WORK.envelopes, forged])
        with pytest.raises(UnknownCaseError, match="not signed by the opener"):
            resolve_dispute(bundle, lineage=LINEAGE, case_id=forged.event_id, at=AT)


class TestFindingCases:
    def test_the_worker_finds_the_case_against_their_work(self) -> None:
        case = case_envelope(opener=REQUESTER)
        bundle = EventBundle.from_envelopes([genesis(), *WORK.envelopes, case])
        found = disputes_involving(bundle, lineage=LINEAGE, did=WORKER.did, at=AT)
        assert [r.case.event_id for r in found] == [case.event_id]

    def test_a_juror_finds_the_case_they_sat_on(self) -> None:
        case = case_envelope()
        bundle = EventBundle.from_envelopes([genesis(), *WORK.envelopes, case])
        assert disputes_involving(bundle, lineage=LINEAGE, did=J1.did, at=AT)

    def test_an_unrelated_did_finds_nothing(self) -> None:
        case = case_envelope()
        bundle = EventBundle.from_envelopes([genesis(), *WORK.envelopes, case])
        assert disputes_involving(bundle, lineage=LINEAGE, did=STRANGER.did, at=AT) == ()


# ------------------------------------------------------------ builder rules


class TestPolicyIsFixedInAdvance:
    def test_a_threshold_both_sides_could_meet_is_refused(self) -> None:
        """2-of-4 is not a majority: a 2/2 split would satisfy both sides."""
        with pytest.raises(MalformedEventError, match="strict majority"):
            case_envelope(jurors=JURORS[:4], quorum=4, threshold=2)

    def test_a_quorum_below_the_threshold_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="quorum must be at least"):
            case_envelope(quorum=2, threshold=3)

    def test_a_quorum_larger_than_the_jury_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="quorum must not exceed"):
            case_envelope(jurors=JURORS[:3], quorum=4, threshold=2)

    def test_a_repeated_juror_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="must not repeat"):
            case_envelope(jurors=[J1, J1, J2])

    def test_naming_jurors_and_a_pool_at_once_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="not both"):
            build_dispute_open(
                lineage=LINEAGE,
                opener=WORKER.did,
                task=WORK.request.event_id,
                result=WORK.result.event_id,
                reason_code="criteria-misread",
                statement="both at once",
                jurors=[J1.did],
                pool=[J1.did, J2.did],
                seats=1,
                seed="x",
                quorum=1,
                threshold=1,
                issued_at=AT,
            )

    def test_a_draw_without_a_seed_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="recorded seed"):
            build_dispute_open(
                lineage=LINEAGE,
                opener=WORKER.did,
                task=WORK.request.event_id,
                result=WORK.result.event_id,
                reason_code="criteria-misread",
                statement="no seed",
                pool=[j.did for j in JURORS],
                seats=3,
                quorum=2,
                threshold=2,
                issued_at=AT,
            )

    def test_a_statement_may_not_carry_control_characters(self) -> None:
        with pytest.raises(MalformedEventError, match="control characters"):
            case_envelope(statement="looks\x1b[31m OFFICIAL\x1b[0m")

    def test_an_unknown_finding_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="finding must be one of"):
            build_jury_vote(
                lineage=LINEAGE,
                case="sha256:" + "a" * 64,
                juror=J1.did,
                finding="guilty",
                reason_code="x",
                issued_at=AT,
            )

    def test_an_unknown_conflict_code_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="conflict must be one of"):
            build_jury_disclose(
                lineage=LINEAGE,
                case="sha256:" + "a" * 64,
                juror=J1.did,
                conflicts=["vibes"],
                issued_at=AT,
            )

    def test_an_empty_disclosure_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="at least one conflict"):
            build_jury_disclose(
                lineage=LINEAGE,
                case="sha256:" + "a" * 64,
                juror=J1.did,
                conflicts=[],
                issued_at=AT,
            )


class TestNoScore:
    def test_the_case_carries_no_number_that_reads_as_a_rating(self) -> None:
        case = case_envelope()
        body = resolve(case, *(vote(j, MEETS_CRITERIA, case=case) for j in (J1, J2, J3))).to_dict()
        flat = repr(body).lower()
        for word in ("score", "rating", "reputation", "trustworthiness"):
            assert word not in flat


class TestPassportAndApi:
    """A dispute belongs beside the work, not inside any claim category."""

    def _bundle(self) -> tuple[Envelope, list[Envelope]]:
        case = case_envelope(opener=REQUESTER)
        envelopes = [
            genesis(),
            *WORK.envelopes,
            case,
            *(vote(j, MEETS_CRITERIA, case=case) for j in (J1, J2, J3)),
        ]
        return case, envelopes

    def test_the_passport_shows_the_case_without_calling_it_a_fault(self) -> None:
        from lineageauth.passport import build_passport

        case, envelopes = self._bundle()
        passport = build_passport(
            EventBundle.from_envelopes(envelopes), lineage=LINEAGE, did=WORKER.did, at=AT
        ).to_dict()
        section = passport["disputes"]
        assert [c["case"] for c in section["cases"]] == [case.event_id]
        assert section["cases"][0]["outcome"] == "MET_CRITERIA"
        assert section["cases"][0]["roles"] == ["party-to-the-task"]
        assert "never that the agent did anything wrong" in section["note"]

    def test_disputes_are_not_folded_into_a_claim_category(self) -> None:
        _, envelopes = self._bundle()
        from lineageauth.passport import build_passport

        passport = build_passport(
            EventBundle.from_envelopes(envelopes), lineage=LINEAGE, did=WORKER.did, at=AT
        ).to_dict()
        for category in ("selfClaimed", "evidenceSupported", "thirdPartyAttested"):
            assert "dispute" not in repr(passport[category]).lower()

    def test_the_api_serves_the_procedure_alongside_the_outcome(self) -> None:
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app
        from lineageauth.index import EventIndex

        case, envelopes = self._bundle()
        index = EventIndex()
        index.ingest_all(envelopes)
        client = TestClient(create_app(index))
        response = client.get(
            f"/v1/disputes/{case.event_id}",
            params={"lineage": LINEAGE, "at": "2026-08-27T12:00:00Z"},
        )
        body = response.json()
        assert response.status_code == 200
        assert body["outcome"] == "MET_CRITERIA"
        assert body["policy"] == {"seats": 5, "quorum": 3, "threshold": 3}
        assert len(body["jurors"]) == 5
        assert body["outcomeDependsOnConflictedJurors"] is False

    def test_an_unknown_case_is_a_404_rather_than_an_empty_verdict(self) -> None:
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app
        from lineageauth.index import EventIndex

        index = EventIndex()
        index.ingest_all([genesis()])
        client = TestClient(create_app(index))
        response = client.get(
            "/v1/disputes/sha256:" + "a" * 64,
            params={"lineage": LINEAGE, "at": "2026-08-27T12:00:00Z"},
        )
        assert response.status_code == 404
