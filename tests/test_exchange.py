"""The task exchange.

`docs/11` asks for a marketplace that holds nothing, and two of its sentences
are the whole test file. "Protocol must expose coordinator dependency honestly"
means competing claims stay competing until a key the requester named in
advance says otherwise. "Protocol preserves signed evidence; indexing can
moderate visibility" means a blocklist hides and counts, never deletes.

The last class walks two agents who share no keys through the full loop --
request, claim, result, verify -- because that is the only way to find out
whether the pieces actually compose.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.actions import sha256_hex
from lineageauth.builders import (
    build_artifact_register,
    build_claim_coordinate,
    build_dispute_open,
    build_jury_vote,
    build_root_create,
    build_task_cancel,
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
from lineageauth.exchange import ListingStatus, Moderation, browse, build_listing
from lineageauth.identifiers import derive_lineage_id
from lineageauth.jury import MEETS_CRITERIA
from lineageauth.work import TaskStatus, resolve_task
from tests.testkeys import ROOT_A, unsafe_signer

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
SOON = AT + timedelta(days=2)

ROOT = unsafe_signer(ROOT_A)
REQUESTER = unsafe_signer("ex-requester")
ALICE = unsafe_signer("ex-alice")
BOB = unsafe_signer("ex-bob")
CHECKER = unsafe_signer("ex-checker")
COORDINATOR = unsafe_signer("ex-coordinator")
SPAMMER = unsafe_signer("ex-spammer")
JURORS = [unsafe_signer(f"ex-juror-{n}") for n in range(1, 4)]

LINEAGE: str = derive_lineage_id(ROOT.did)


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def request(
    *,
    by: LocalSigner = REQUESTER,
    title: str = "index the room list",
    allowed_claims: int = 1,
    **kwargs: object,
) -> Envelope:
    fields: dict[str, object] = {
        "lineage": LINEAGE,
        "requester": by.did,
        "title": title,
        "acceptance_criteria": ["every room reachable"],
        "allowed_claims": allowed_claims,
        "issued_at": AT,
    }
    fields.update(kwargs)
    return sign_payload(build_task_request(**fields), [by])  # type: ignore[arg-type]


def claim(*, task: Envelope, by: LocalSigner, nonce: bytes | None = None) -> Envelope:
    payload = build_task_claim(
        lineage=LINEAGE,
        task=task.event_id,
        claimant=by.did,
        nonce=nonce or by.did.encode()[:16].ljust(16, b"."),
        expires_at=SOON,
        issued_at=AT,
    )
    return sign_payload(payload, [by])


def deliver(*, task: Envelope, held: Envelope, by: LocalSigner) -> list[Envelope]:
    artifact = sha256_hex(by.did.encode())
    return [
        sign_payload(
            build_artifact_register(
                lineage=LINEAGE, artifact_id=artifact, created_by=by.did, issued_at=AT
            ),
            [by],
        ),
        sign_payload(
            build_task_result(
                lineage=LINEAGE,
                task=task.event_id,
                claim=held.event_id,
                worker=by.did,
                artifact_refs=[artifact],
                summary="indexed 41 rooms",
                issued_at=AT,
            ),
            [by],
        ),
    ]


def listing_of(task: Envelope, *envelopes: Envelope, at: datetime = AT):
    bundle = EventBundle.from_envelopes([genesis(), task, *envelopes])
    return build_listing(bundle, lineage=LINEAGE, task_id=task.event_id, at=at)


# ------------------------------------------------------------ competing claims


class TestClaimContest:
    def test_one_claim_on_a_single_claimant_task_is_no_contest(self) -> None:
        task = request()
        found = listing_of(task, claim(task=task, by=ALICE))
        assert found.contest is None
        assert found.status is ListingStatus.CLAIMED
        assert found.open_slots == 0

    def test_a_multi_claimant_task_stays_claimable_while_a_slot_is_free(self) -> None:
        """One claim on a three-worker task does not close it."""
        task = request(allowed_claims=3)
        found = listing_of(task, claim(task=task, by=ALICE))
        assert found.status is ListingStatus.CLAIMED
        assert found.open_slots == 2
        assert found.is_claimable

    def test_a_full_multi_claimant_task_is_no_longer_claimable(self) -> None:
        task = request(allowed_claims=2)
        found = listing_of(task, claim(task=task, by=ALICE), claim(task=task, by=BOB))
        assert found.open_slots == 0
        assert not found.is_claimable
        assert found.contest is None

    def test_two_claims_are_both_listed_and_neither_wins(self) -> None:
        """Nothing signed says who was first, so nothing here pretends to know."""
        task = request()
        found = listing_of(task, claim(task=task, by=ALICE), claim(task=task, by=BOB))
        assert found.contest is not None
        assert {c.claimant for c in found.contest.competing} == {ALICE.did, BOB.did}
        assert found.contest.awarded_claim is None
        assert "whoever backdates best" in found.contest.note

    def test_a_named_coordinator_can_settle_it(self) -> None:
        task = request(coordinator=COORDINATOR.did)
        alice = claim(task=task, by=ALICE)
        award = sign_payload(
            build_claim_coordinate(
                lineage=LINEAGE,
                task=task.event_id,
                coordinator=COORDINATOR.did,
                claim=alice.event_id,
                issued_at=AT,
            ),
            [COORDINATOR],
        )
        found = listing_of(task, alice, claim(task=task, by=BOB), award)
        assert found.contest is not None
        assert found.contest.awarded_claim == alice.event_id
        assert found.contest.is_settled

    def test_the_award_says_what_it_rests_on(self) -> None:
        task = request(coordinator=COORDINATOR.did)
        alice = claim(task=task, by=ALICE)
        award = sign_payload(
            build_claim_coordinate(
                lineage=LINEAGE,
                task=task.event_id,
                coordinator=COORDINATOR.did,
                claim=alice.event_id,
                issued_at=AT,
            ),
            [COORDINATOR],
        )
        found = listing_of(task, alice, claim(task=task, by=BOB), award)
        assert found.contest is not None
        assert "does not make the choice fair" in found.contest.note

    def test_only_the_coordinator_the_task_named_may_award(self) -> None:
        task = request(coordinator=COORDINATOR.did)
        alice = claim(task=task, by=ALICE)
        forged = sign_payload(
            build_claim_coordinate(
                lineage=LINEAGE,
                task=task.event_id,
                coordinator=REQUESTER.did,
                claim=alice.event_id,
                issued_at=AT,
            ),
            [REQUESTER],
        )
        found = listing_of(task, alice, claim(task=task, by=BOB), forged)
        assert found.contest is not None
        assert found.contest.awarded_claim is None
        assert any("but the task names" in w for w in found.warnings)

    def test_an_award_must_be_signed_by_the_coordinator(self) -> None:
        task = request(coordinator=COORDINATOR.did)
        alice = claim(task=task, by=ALICE)
        forged = sign_payload(
            build_claim_coordinate(
                lineage=LINEAGE,
                task=task.event_id,
                coordinator=COORDINATOR.did,
                claim=alice.event_id,
                issued_at=AT,
            ),
            [ALICE],
        )
        found = listing_of(task, alice, claim(task=task, by=BOB), forged)
        assert found.contest is not None
        assert found.contest.awarded_claim is None

    def test_a_coordinator_awarding_twice_awards_nothing(self) -> None:
        """Choosing between them would be the ordering this layer just refused."""
        task = request(coordinator=COORDINATOR.did)
        alice, bob = claim(task=task, by=ALICE), claim(task=task, by=BOB)
        awards = [
            sign_payload(
                build_claim_coordinate(
                    lineage=LINEAGE,
                    task=task.event_id,
                    coordinator=COORDINATOR.did,
                    claim=held.event_id,
                    issued_at=AT,
                ),
                [COORDINATOR],
            )
            for held in (alice, bob)
        ]
        found = listing_of(task, alice, bob, *awards)
        assert found.contest is not None
        assert found.contest.awarded_claim is None
        assert any("awarded more than one claim" in w for w in found.warnings)

    def test_no_coordinator_means_no_award_is_even_looked_for(self) -> None:
        task = request()
        alice = claim(task=task, by=ALICE)
        stray = sign_payload(
            build_claim_coordinate(
                lineage=LINEAGE,
                task=task.event_id,
                coordinator=COORDINATOR.did,
                claim=alice.event_id,
                issued_at=AT,
            ),
            [COORDINATOR],
        )
        found = listing_of(task, alice, claim(task=task, by=BOB), stray)
        assert found.contest is not None
        assert found.contest.awarded_claim is None


# ------------------------------------------------------------ cancellation


class TestCancellation:
    def _cancel(self, task: Envelope, *, by: LocalSigner = REQUESTER) -> Envelope:
        return sign_payload(
            build_task_cancel(
                lineage=LINEAGE,
                task=task.event_id,
                requester=by.did,
                reason="no longer needed",
                issued_at=AT,
            ),
            [by],
        )

    def test_an_unclaimed_task_can_be_withdrawn(self) -> None:
        task = request()
        found = listing_of(task, self._cancel(task))
        assert found.status is ListingStatus.CANCELLED

    def test_a_claimed_task_cannot_be_pulled_out_from_under_the_worker(self) -> None:
        task = request()
        found = listing_of(task, claim(task=task, by=ALICE), self._cancel(task))
        assert found.status is ListingStatus.CLAIMED
        assert any("already holding" in w for w in found.warnings)

    def test_a_submitted_result_protects_the_task_too(self) -> None:
        task = request()
        held = claim(task=task, by=ALICE)
        found = listing_of(task, held, *deliver(task=task, held=held, by=ALICE), self._cancel(task))
        assert found.status is ListingStatus.SUBMITTED

    def test_only_the_requester_may_cancel(self) -> None:
        task = request()
        found = listing_of(task, self._cancel(task, by=ALICE))
        assert found.status is ListingStatus.OPEN
        assert any("but this task was requested by" in w for w in found.warnings)

    def test_a_task_published_as_uncancellable_stays_open(self) -> None:
        """A commitment that can be withdrawn is not one."""
        task = request(cancellable=False)
        found = listing_of(task, self._cancel(task))
        assert found.status is ListingStatus.OPEN
        assert any("not cancellable" in w for w in found.warnings)

    def test_a_lapsed_claim_stops_protecting_the_task(self) -> None:
        task = request()
        found = listing_of(
            task,
            claim(task=task, by=ALICE),
            self._cancel(task),
            at=SOON + timedelta(days=1),
        )
        assert found.status is ListingStatus.CANCELLED


# ------------------------------------------------------------ disputes overlay


class TestDisputeOverlay:
    def _disputed(self, *, resolve_it: bool) -> tuple[Envelope, list[Envelope]]:
        task = request()
        held = claim(task=task, by=ALICE)
        produced = deliver(task=task, held=held, by=ALICE)
        result = produced[-1]
        rejection = sign_payload(
            build_task_verify(
                lineage=LINEAGE,
                task=task.event_id,
                result=result.event_id,
                verifier=CHECKER.did,
                verdict="rejected",
                issued_at=AT,
            ),
            [CHECKER],
        )
        case = sign_payload(
            build_dispute_open(
                lineage=LINEAGE,
                opener=ALICE.did,
                task=task.event_id,
                result=result.event_id,
                reason_code="criteria-misread",
                statement="the checker tested a stale snapshot",
                jurors=[j.did for j in JURORS],
                quorum=2,
                threshold=2,
                issued_at=AT,
            ),
            [ALICE],
        )
        votes = (
            [
                sign_payload(
                    build_jury_vote(
                        lineage=LINEAGE,
                        case=case.event_id,
                        juror=j.did,
                        finding=MEETS_CRITERIA,
                        reason_code="reviewed-evidence",
                        issued_at=AT,
                    ),
                    [j],
                )
                for j in JURORS[:2]
            ]
            if resolve_it
            else []
        )
        return task, [held, *produced, rejection, case, *votes]

    def test_an_open_case_shows_as_disputed(self) -> None:
        task, envelopes = self._disputed(resolve_it=False)
        found = listing_of(task, *envelopes)
        assert found.status is ListingStatus.DISPUTED
        assert len(found.open_disputes) == 1

    def test_the_underlying_verdict_is_still_carried(self) -> None:
        """The overlay is a view. A dispute must not erase the verifications."""
        task, envelopes = self._disputed(resolve_it=False)
        found = listing_of(task, *envelopes)
        assert found.task_status is TaskStatus.VERIFIED_REJECTED
        assert "still VERIFIED_REJECTED" in found.detail

    def test_a_decided_case_stops_overriding_the_status(self) -> None:
        task, envelopes = self._disputed(resolve_it=True)
        found = listing_of(task, *envelopes)
        assert found.status is ListingStatus.VERIFIED_REJECTED
        assert found.open_disputes == ()
        assert found.resolved_disputes[0][1] == "MET_CRITERIA"

    def test_the_jury_never_rewrites_the_task_status(self) -> None:
        task, envelopes = self._disputed(resolve_it=True)
        bundle = EventBundle.from_envelopes([genesis(), task, *envelopes])
        state = resolve_task(bundle, lineage=LINEAGE, task_id=task.event_id, at=AT)
        assert state.status is TaskStatus.VERIFIED_REJECTED


# ------------------------------------------------------------ browsing


class TestBrowse:
    def _bundle(self) -> tuple[EventBundle, Envelope, Envelope]:
        open_task = request(title="index the room list")
        taken = request(title="write the migration notes")
        spam = request(by=SPAMMER, title="FREE TOKENS CLICK HERE")
        return (
            EventBundle.from_envelopes(
                [genesis(), open_task, taken, spam, claim(task=taken, by=BOB)]
            ),
            open_task,
            spam,
        )

    def test_every_task_is_listed_by_default(self) -> None:
        bundle, _, _ = self._bundle()
        found = browse(bundle, lineage=LINEAGE, at=AT)
        assert len(found.listings) == 3

    def test_status_filters_narrow_without_hiding(self) -> None:
        bundle, _, _ = self._bundle()
        found = browse(bundle, lineage=LINEAGE, at=AT, status=["CLAIMED"])
        assert [listing.status for listing in found.listings] == [ListingStatus.CLAIMED]
        assert found.hidden == ()

    def test_claimable_only_leaves_out_what_is_taken(self) -> None:
        bundle, _, _ = self._bundle()
        found = browse(bundle, lineage=LINEAGE, at=AT, claimable_only=True)
        assert all(listing.is_claimable for listing in found.listings)
        assert len(found.listings) == 2

    def test_a_requester_filter_narrows_to_one_key(self) -> None:
        bundle, _, _ = self._bundle()
        found = browse(bundle, lineage=LINEAGE, at=AT, requester=SPAMMER.did)
        assert len(found.listings) == 1

    def test_a_blocklist_hides_and_says_how_many(self) -> None:
        """A filter that silently shrank the results would look like an empty exchange."""
        bundle, _, _ = self._bundle()
        found = browse(
            bundle,
            lineage=LINEAGE,
            at=AT,
            moderation=Moderation.of(dids=[SPAMMER.did]),
        )
        assert len(found.listings) == 2
        assert len(found.hidden) == 1
        assert found.hidden[0][1] == "requester is on the reader's blocklist"

    def test_hiding_is_the_readers_choice_not_a_property_of_the_bundle(self) -> None:
        bundle, _, _ = self._bundle()
        unfiltered = browse(bundle, lineage=LINEAGE, at=AT)
        filtered = browse(
            bundle, lineage=LINEAGE, at=AT, moderation=Moderation.of(dids=[SPAMMER.did])
        )
        assert len(unfiltered.listings) == len(filtered.listings) + 1
        assert "removes nothing" in filtered.note

    def test_a_single_task_can_be_blocked_by_id(self) -> None:
        bundle, open_task, _ = self._bundle()
        found = browse(
            bundle,
            lineage=LINEAGE,
            at=AT,
            moderation=Moderation.of(tasks=[open_task.event_id]),
        )
        assert open_task.event_id not in {listing.task.event_id for listing in found.listings}

    def test_the_note_refuses_custody(self) -> None:
        bundle, _, _ = self._bundle()
        found = browse(bundle, lineage=LINEAGE, at=AT)
        assert "escrows nothing" in found.note
        assert "Nothing here is an offer or a contract" in found.note

    def test_an_unknown_status_filter_is_an_error_not_an_empty_page(self) -> None:
        bundle, _, _ = self._bundle()
        with pytest.raises(MalformedEventError, match="unknown listing status"):
            browse(bundle, lineage=LINEAGE, at=AT, status=["ARCHIVED"])

    def test_a_blocklist_entry_must_be_a_real_identifier(self) -> None:
        with pytest.raises(MalformedEventError):
            Moderation.of(tasks=["not-an-event-id"])


# ------------------------------------------------------------ end to end


class TestTwoIndependentAgents:
    """Two agents that share no keys, all the way through the loop.

    Every other test in this file exercises one seam. This one is here to find
    out whether they compose, which is a different question and the only one a
    marketplace claim actually rests on.
    """

    def test_the_whole_loop_leaves_a_checkable_trail(self) -> None:
        task = request(by=REQUESTER, title="index the room list")
        held = claim(task=task, by=ALICE)
        produced = deliver(task=task, held=held, by=ALICE)
        accepted = sign_payload(
            build_task_verify(
                lineage=LINEAGE,
                task=task.event_id,
                result=produced[-1].event_id,
                verifier=CHECKER.did,
                verdict="accepted",
                issued_at=AT,
            ),
            [CHECKER],
        )
        bundle = EventBundle.from_envelopes([genesis(), task, held, *produced, accepted])

        found = browse(bundle, lineage=LINEAGE, at=AT)
        assert len(found.listings) == 1
        listing = found.listings[0]
        assert listing.status is ListingStatus.VERIFIED_ACCEPTED
        assert listing.workers == (ALICE.did,)
        assert not listing.is_claimable

        # Three distinct keys, and the record says which did what.
        assert listing.task.requester == REQUESTER.did
        state = resolve_task(bundle, lineage=LINEAGE, task_id=task.event_id, at=AT)
        assert [v.verifier for v in state.verifications] == [CHECKER.did]
        assert state.warnings == ()

    def test_a_worker_cannot_verify_their_own_work_into_acceptance_unnoticed(self) -> None:
        task = request()
        held = claim(task=task, by=ALICE)
        produced = deliver(task=task, held=held, by=ALICE)
        self_accepted = sign_payload(
            build_task_verify(
                lineage=LINEAGE,
                task=task.event_id,
                result=produced[-1].event_id,
                verifier=ALICE.did,
                verdict="accepted",
                issued_at=AT,
            ),
            [ALICE],
        )
        bundle = EventBundle.from_envelopes([genesis(), task, held, *produced, self_accepted])
        from lineageauth.work import build_work_receipt

        receipt = build_work_receipt(bundle, lineage=LINEAGE, task_id=task.event_id, at=AT)
        assert receipt.signals.self_verified
        assert receipt.signals.independent_verifiers == ()


class TestApi:
    def test_the_exchange_is_served_with_its_filter_disclosed(self) -> None:
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app
        from lineageauth.index import EventIndex

        open_task = request()
        spam = request(by=SPAMMER, title="FREE TOKENS")
        index = EventIndex()
        index.ingest_all([genesis(), open_task, spam])
        client = TestClient(create_app(index))

        response = client.get(
            "/v1/exchange",
            params={
                "lineage": LINEAGE,
                "at": "2026-08-27T12:00:00Z",
                "blocked_did": SPAMMER.did,
            },
        )
        body = response.json()
        assert response.status_code == 200
        assert len(body["listings"]) == 1
        assert body["hiddenCount"] == 1
        assert "removes nothing" in body["note"]
