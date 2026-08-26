"""Proof of useful work.

docs/08 sets the goal -- work as an evidence chain rather than a message count
-- and then lists how a naive implementation gets gamed. These tests are mostly
about the second half: self-created tasks, self-verification, and reciprocal
verifier pairs all have to be visible, and none of them may be quietly counted
as independent work.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.actions import sha256_hex
from lineageauth.builders import (
    build_root_create,
    build_task_claim,
    build_task_release,
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
from lineageauth.work import TaskStatus, build_work_receipt, resolve_task
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
REQUESTER = unsafe_signer(RECOVERY_1)
WORKER = unsafe_signer(AGENT_1)
VERIFIER = unsafe_signer(RECOVERY_2)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE: str = derive_lineage_id(ROOT.did)

ARTIFACT = sha256_hex(b"the finished work")
NONCE = b"\x22" * 16
CRITERIA = ["links resolve", "no duplicate entries"]


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def request(
    *,
    requester: LocalSigner = REQUESTER,
    allowed_claims: int = 1,
    deadline: datetime | None = None,
    reward_reference: str | None = None,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_task_request(
        lineage=LINEAGE,
        requester=requester.did,
        title="Curate the technocore tool list",
        acceptance_criteria=CRITERIA,
        allowed_claims=allowed_claims,
        deadline=deadline,
        reward_reference=reward_reference,
        issued_at=AT,
    )
    return sign_payload(payload, signers or [requester])


def claim(
    *,
    task: Envelope,
    claimant: LocalSigner = WORKER,
    expires_at: datetime | None = None,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_task_claim(
        lineage=LINEAGE,
        task=task.event_id,
        claimant=claimant.did,
        nonce=NONCE,
        expires_at=expires_at or AT + timedelta(days=7),
        issued_at=AT,
    )
    return sign_payload(payload, signers or [claimant])


def result(
    *,
    task: Envelope,
    held: Envelope,
    worker: LocalSigner = WORKER,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_task_result(
        lineage=LINEAGE,
        task=task.event_id,
        claim=held.event_id,
        worker=worker.did,
        artifact_refs=[ARTIFACT],
        summary="added 12 entries, removed 3 dead links",
        issued_at=AT,
    )
    return sign_payload(payload, signers or [worker])


def verify(
    *,
    task: Envelope,
    submitted: Envelope,
    verifier: LocalSigner = VERIFIER,
    verdict: str = "accepted",
    criteria: dict[str, bool] | None = None,
) -> Envelope:
    payload = build_task_verify(
        lineage=LINEAGE,
        task=task.event_id,
        result=submitted.event_id,
        verifier=verifier.did,
        verdict=verdict,
        criteria_results=criteria,
        issued_at=AT,
    )
    return sign_payload(payload, [verifier])


def state_of(task: Envelope, *envelopes: Envelope, at: datetime = AT):
    return resolve_task(
        EventBundle.from_envelopes([genesis(), task, *envelopes]),
        lineage=LINEAGE,
        task_id=task.event_id,
        at=at,
    )


def receipt_of(task: Envelope, *envelopes: Envelope, at: datetime = AT):
    return build_work_receipt(
        EventBundle.from_envelopes([genesis(), task, *envelopes]),
        lineage=LINEAGE,
        task_id=task.event_id,
        at=at,
    )


# ------------------------------------------------------------ the lifecycle


class TestLifecycle:
    def test_a_task_with_no_claim_is_open(self) -> None:
        assert state_of(request()).status is TaskStatus.OPEN

    def test_a_live_claim_makes_it_claimed(self) -> None:
        task = request()
        assert state_of(task, claim(task=task)).status is TaskStatus.CLAIMED

    def test_a_result_makes_it_submitted(self) -> None:
        task = request()
        held = claim(task=task)
        assert state_of(task, held, result(task=task, held=held)).status is TaskStatus.SUBMITTED

    def test_an_accepted_verification_completes_it(self) -> None:
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        found = state_of(task, held, done, verify(task=task, submitted=done))
        assert found.status is TaskStatus.VERIFIED_ACCEPTED

    def test_a_rejection_is_reported_as_such(self) -> None:
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        found = state_of(task, held, done, verify(task=task, submitted=done, verdict="rejected"))
        assert found.status is TaskStatus.VERIFIED_REJECTED

    def test_disagreeing_verifiers_leave_it_contested(self) -> None:
        """This layer does not adjudicate; picking a side would be inventing one."""
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        found = state_of(
            task,
            held,
            done,
            verify(task=task, submitted=done, verifier=VERIFIER, verdict="accepted"),
            verify(task=task, submitted=done, verifier=STRANGER, verdict="rejected"),
        )
        assert found.status is TaskStatus.CONTESTED
        assert "does not adjudicate" in found.detail

    def test_an_expired_claim_reopens_the_task(self) -> None:
        task = request()
        held = claim(task=task, expires_at=AT + timedelta(hours=1))
        assert state_of(task, held, at=AT + timedelta(days=1)).status is TaskStatus.OPEN

    def test_a_released_claim_reopens_the_task(self) -> None:
        task = request()
        held = claim(task=task)
        released = sign_payload(
            build_task_release(
                lineage=LINEAGE, claim=held.event_id, claimant=WORKER.did, issued_at=AT
            ),
            [WORKER],
        )
        assert state_of(task, held, released).status is TaskStatus.OPEN

    def test_only_the_holder_may_release_a_claim(self) -> None:
        # Otherwise anyone could free a task out from under whoever holds it.
        task = request()
        held = claim(task=task)
        forged = sign_payload(
            build_task_release(
                lineage=LINEAGE, claim=held.event_id, claimant=STRANGER.did, issued_at=AT
            ),
            [STRANGER],
        )
        found = state_of(task, held, forged)
        assert found.status is TaskStatus.CLAIMED
        assert any("does not hold that claim" in w for w in found.warnings)

    def test_a_past_deadline_with_no_claim_expires(self) -> None:
        task = request(deadline=AT + timedelta(days=1))
        assert state_of(task, at=AT + timedelta(days=2)).status is TaskStatus.EXPIRED

    def test_state_is_derived_so_removing_the_verification_undoes_acceptance(self) -> None:
        """Nobody writes "done". A task is accepted because an event says so."""
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        checked = verify(task=task, submitted=done)
        assert state_of(task, held, done, checked).status is TaskStatus.VERIFIED_ACCEPTED
        assert state_of(task, held, done).status is TaskStatus.SUBMITTED


# ------------------------------------------------------------ borrowed claims


class TestSignatureBinding:
    def test_a_result_against_someone_elses_claim_is_ignored(self) -> None:
        # Borrowing a claim would let a worker submit against work they never
        # signed up for.
        task = request()
        held = claim(task=task, claimant=WORKER)
        borrowed = sign_payload(
            build_task_result(
                lineage=LINEAGE,
                task=task.event_id,
                claim=held.event_id,
                worker=STRANGER.did,
                artifact_refs=[ARTIFACT],
                summary="not mine to submit",
                issued_at=AT,
            ),
            [STRANGER],
        )
        found = state_of(task, held, borrowed)
        assert found.results == ()
        assert any("held by" in w for w in found.warnings)

    def test_a_result_citing_no_known_claim_is_ignored(self) -> None:
        task = request()
        held = claim(task=task)
        orphan = sign_payload(
            build_task_result(
                lineage=LINEAGE,
                task=task.event_id,
                claim="sha256:" + "a" * 64,
                worker=WORKER.did,
                artifact_refs=[ARTIFACT],
                summary="no claim",
                issued_at=AT,
            ),
            [WORKER],
        )
        assert state_of(task, held, orphan).results == ()

    def test_a_task_not_signed_by_its_requester_is_unusable(self) -> None:
        forged = request(requester=REQUESTER, signers=[STRANGER])
        with pytest.raises(MalformedEventError, match="not signed by the requester"):
            state_of(forged)

    def test_more_claims_than_allowed_are_reported(self) -> None:
        # Which claim wins is a coordination question this protocol does not
        # settle, so it says so rather than picking one.
        task = request(allowed_claims=1)
        found = state_of(
            task, claim(task=task, claimant=WORKER), claim(task=task, claimant=STRANGER)
        )
        assert any("does not settle" in w for w in found.warnings)


# ------------------------------------------------------------ anti-gaming


class TestRelationshipSignals:
    def test_an_independent_verifier_is_reported_as_such(self) -> None:
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        got = receipt_of(task, held, done, verify(task=task, submitted=done))
        assert got.signals.independent_verifiers == (VERIFIER.did,)
        assert got.signals.has_independent_verification
        assert not got.signals.self_verified

    def test_a_worker_verifying_their_own_result_is_not_independent(self) -> None:
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        got = receipt_of(task, held, done, verify(task=task, submitted=done, verifier=WORKER))
        assert got.signals.self_verified
        assert got.signals.independent_verifiers == ()
        assert got.signals.non_independent_verifiers == (WORKER.did,)

    def test_a_requester_verifying_the_work_they_asked_for_is_not_independent(self) -> None:
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        got = receipt_of(task, held, done, verify(task=task, submitted=done, verifier=REQUESTER))
        assert got.signals.independent_verifiers == ()

    def test_a_self_created_task_is_visible(self) -> None:
        """docs/08: a self-created task is not equivalent to independent work."""
        task = request(requester=WORKER)
        held = claim(task=task, claimant=WORKER)
        done = result(task=task, held=held)
        got = receipt_of(task, held, done, verify(task=task, submitted=done))
        assert got.signals.requester_is_worker

    def test_a_reciprocal_verifier_pair_is_surfaced(self) -> None:
        """The cheapest way to make review look independent is to trade it."""
        # A does work that B verifies, and B does work that A verifies.
        task_a = request(requester=REQUESTER)
        claim_a = claim(task=task_a, claimant=WORKER)
        result_a = result(task=task_a, held=claim_a, worker=WORKER)
        verify_a = verify(task=task_a, submitted=result_a, verifier=VERIFIER)

        task_b = request(requester=REQUESTER, allowed_claims=2)
        claim_b = sign_payload(
            build_task_claim(
                lineage=LINEAGE,
                task=task_b.event_id,
                claimant=VERIFIER.did,
                nonce=NONCE,
                expires_at=AT + timedelta(days=7),
                issued_at=AT,
            ),
            [VERIFIER],
        )
        result_b = sign_payload(
            build_task_result(
                lineage=LINEAGE,
                task=task_b.event_id,
                claim=claim_b.event_id,
                worker=VERIFIER.did,
                artifact_refs=[sha256_hex(b"other work")],
                summary="the return favour",
                issued_at=AT,
            ),
            [VERIFIER],
        )
        verify_b = sign_payload(
            build_task_verify(
                lineage=LINEAGE,
                task=task_b.event_id,
                result=result_b.event_id,
                verifier=WORKER.did,
                verdict="accepted",
                issued_at=AT,
            ),
            [WORKER],
        )

        got = build_work_receipt(
            EventBundle.from_envelopes(
                [
                    genesis(),
                    task_a,
                    claim_a,
                    result_a,
                    verify_a,
                    task_b,
                    claim_b,
                    result_b,
                    verify_b,
                ]
            ),
            lineage=LINEAGE,
            task_id=task_a.event_id,
            at=AT,
        )
        assert got.signals.reciprocal_verifier_pairs
        # Still reported as independent by the narrow test -- which is exactly
        # why the reciprocal signal exists alongside it.
        assert got.signals.independent_verifiers == (VERIFIER.did,)

    def test_signals_are_reported_not_weighted(self) -> None:
        # docs/08 says rankers may use these transparently, which means handing
        # over the signals rather than an answer.
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        body = receipt_of(task, held, done, verify(task=task, submitted=done)).to_dict()
        assert set(body["signals"]) == {
            "requesterIsWorker",
            "selfVerified",
            "independentVerifiers",
            "nonIndependentVerifiers",
            "reciprocalVerifierPairs",
            "hasIndependentVerification",
        }


# ------------------------------------------------------------ the receipt


class TestWorkReceipt:
    def test_it_mints_no_points(self) -> None:
        """docs/08: never mint arbitrary points in core."""
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        body = receipt_of(task, held, done, verify(task=task, submitted=done)).to_dict()

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
            for word in ("score", "points", "rating", "rank", "reputation"):
                assert word not in name.lower(), f"{name} reads as a score"

    def test_it_names_every_event_behind_it(self) -> None:
        # Derived, so a reader can recompute it rather than trust it.
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        checked = verify(task=task, submitted=done)
        got = receipt_of(task, held, done, checked)
        assert set(got.event_refs) == {
            task.event_id,
            held.event_id,
            done.event_id,
            checked.event_id,
        }

    def test_criteria_results_are_carried_through(self) -> None:
        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        checked = verify(
            task=task,
            submitted=done,
            criteria={"links resolve": True, "no duplicate entries": False},
        )
        got = receipt_of(task, held, done, checked)
        assert got.criteria_met == ("links resolve",)
        assert got.criteria_unmet == ("no duplicate entries",)

    def test_a_reward_reference_is_carried_but_promises_nothing(self) -> None:
        task = request(reward_reference="https://example.test/bounty/17")
        got = receipt_of(task)
        assert got.reward_reference == "https://example.test/bounty/17"
        # Nothing in the receipt claims the reward exists or will be paid.
        body = got.to_dict()
        assert "amount" not in str(body)
        assert "escrow" not in str(body)

    def test_the_note_says_what_an_acceptance_is_not(self) -> None:
        got = receipt_of(request())
        assert "not a finding that the work is good" in got.note

    def test_it_is_deterministic_under_input_order(self) -> None:
        import itertools

        task = request()
        held = claim(task=task)
        done = result(task=task, held=held)
        checked = verify(task=task, submitted=done)
        renderings = {
            str(
                build_work_receipt(
                    EventBundle.from_envelopes([genesis(), task, *order]),
                    lineage=LINEAGE,
                    task_id=task.event_id,
                    at=AT,
                ).to_dict()
            )
            for order in itertools.permutations([held, done, checked])
        }
        assert len(renderings) == 1


class TestBuilderRules:
    def test_a_task_must_state_acceptance_criteria(self) -> None:
        with pytest.raises(MalformedEventError, match="acceptance criteria"):
            build_task_request(
                lineage=LINEAGE,
                requester=REQUESTER.did,
                title="vague",
                acceptance_criteria=[],
                issued_at=AT,
            )

    def test_a_result_must_reference_an_artifact(self) -> None:
        with pytest.raises(MalformedEventError, match="at least one artifact"):
            build_task_result(
                lineage=LINEAGE,
                task="sha256:" + "a" * 64,
                claim="sha256:" + "b" * 64,
                worker=WORKER.did,
                artifact_refs=[],
                summary="trust me",
                issued_at=AT,
            )

    def test_a_title_may_not_carry_control_characters(self) -> None:
        with pytest.raises(MalformedEventError, match="control characters"):
            build_task_request(
                lineage=LINEAGE,
                requester=REQUESTER.did,
                title="urgent\x1b[31m PAID 1000 FLOP\x1b[0m",
                acceptance_criteria=CRITERIA,
                issued_at=AT,
            )

    def test_an_unknown_verdict_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="verdict must be"):
            build_task_verify(
                lineage=LINEAGE,
                task="sha256:" + "a" * 64,
                result="sha256:" + "b" * 64,
                verifier=VERIFIER.did,
                verdict="probably fine",
                issued_at=AT,
            )

    def test_a_short_claim_nonce_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="randomness"):
            build_task_claim(
                lineage=LINEAGE,
                task="sha256:" + "a" * 64,
                claimant=WORKER.did,
                nonce=b"\x00" * 8,
                expires_at=AT + timedelta(days=1),
                issued_at=AT,
            )
