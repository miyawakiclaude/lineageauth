"""Exact-action approval, replay protection, and the execution gate.

docs/23_TESTING.md requires that approval never grant missing base authority.
docs/06 adds the rest of what has to hold: a receipt binds one destination and
one content hash, carries real randomness, expires, and is spendable once.

The interesting cases are all substitutions -- take a receipt obtained for one
thing and try to spend it on another.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from lineageauth.actions import ActionRequest
from lineageauth.approval import (
    InMemorySpentStore,
    SqliteSpentStore,
    check_execution,
)
from lineageauth.builders import (
    build_approval_receipt,
    build_delegation_grant,
    build_root_create,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError, ReasonCode
from tests.testkeys import AGENT_1, OUTSIDER, RECOVERY_1, ROOT_A, unsafe_signer

AT = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
FROM = AT - timedelta(days=1)
UNTIL = AT + timedelta(days=30)

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
OPERATOR = unsafe_signer(RECOVERY_1)
STRANGER = unsafe_signer(OUTSIDER)

LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]
NONCE = b"\x11" * 16

MESSAGE = b"LINEAGEAUTH/0.1 ANNOUNCE lineage=... event=..."
DESTINATION = "https://technocore.chat/r/lobby"


def request(content: bytes = MESSAGE, destination: str = DESTINATION) -> ActionRequest:
    return ActionRequest.over_bytes(
        namespace="technocore",
        resource="room:lobby",
        action="write",
        destination=destination,
        content=content,
    )


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, approval: str = "required", subject: LocalSigner = AGENT) -> Envelope:
    payload = build_delegation_grant(
        lineage=LINEAGE,
        issuer=ROOT.did,
        subject=subject.did,
        epoch=0,
        scopes=[
            {"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "write"]}
        ],
        not_before=FROM,
        expires_at=UNTIL,
        max_depth=0,
        approval=approval,
        issued_at=AT,
    )
    return sign_payload(payload, [ROOT])


def receipt(
    *,
    approver: LocalSigner = ROOT,
    agent: LocalSigner = AGENT,
    action: ActionRequest | None = None,
    nonce: bytes = NONCE,
    issued_at: datetime = AT - timedelta(minutes=1),
    expires_at: datetime | None = None,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_approval_receipt(
        lineage=LINEAGE,
        approver=approver.did,
        agent=agent.did,
        request=action if action is not None else request(),
        nonce=nonce,
        expires_at=expires_at if expires_at is not None else AT + timedelta(minutes=10),
        issued_at=issued_at,
    )
    return sign_payload(payload, signers if signers is not None else [approver])


def execute(
    *envelopes: Envelope,
    action: ActionRequest | None = None,
    agent: LocalSigner = AGENT,
    at: datetime = AT,
    store: Any = None,
    external: bool = True,
    reserve: bool = True,
) -> Any:
    return check_execution(
        EventBundle.from_envelopes(envelopes),
        lineage=LINEAGE,
        agent=agent.did,
        request=action if action is not None else request(),
        at=at,
        store=store,
        external=external,
        reserve=reserve,
    )


# ----------------------------------------------- approval does not create authority


class TestApprovalIsNotAuthority:
    def test_a_receipt_without_a_grant_is_denied(self) -> None:
        """D-010 / docs/06: the headline rule of this whole layer.

        A human consenting to a consequence says nothing about whether the agent
        was entitled to cause it.
        """
        decision = execute(genesis(), receipt())
        assert not decision.may_execute
        assert decision.reason is ReasonCode.DENIED
        assert decision.reason is not ReasonCode.APPROVAL_REQUIRED

    def test_a_receipt_cannot_widen_a_grant(self) -> None:
        # The grant covers room:lobby; the receipt approves a write to room:ops.
        elsewhere = ActionRequest.over_bytes(
            namespace="technocore",
            resource="room:ops",
            action="write",
            destination="https://technocore.chat/r/ops",
            content=MESSAGE,
        )
        decision = execute(genesis(), grant(), receipt(action=elsewhere), action=elsewhere)
        assert not decision.may_execute
        assert decision.reason is ReasonCode.SCOPE_VIOLATION

    def test_a_revoked_chain_is_refused_before_the_receipt_is_read(self) -> None:
        from lineageauth.builders import build_delegation_revoke

        target = grant()
        revocation = sign_payload(
            build_delegation_revoke(
                lineage=LINEAGE, issuer=ROOT.did, grant=target.event_id, issued_at=AT
            ),
            [ROOT],
        )
        decision = execute(genesis(), target, revocation, receipt())
        assert decision.reason is ReasonCode.REVOKED


# ------------------------------------------------------------------ exact binding


class TestExactBinding:
    def test_a_valid_receipt_permits_execution(self) -> None:
        decision = execute(genesis(), grant(), receipt())
        assert decision.may_execute
        assert decision.approver == ROOT.did

    def test_a_receipt_for_different_content_does_not_apply(self) -> None:
        """The substitution this layer exists to stop."""
        approved = receipt(action=request(content=b"harmless announcement"))
        decision = execute(genesis(), grant(), approved, action=request(content=b"rm -rf"))
        assert not decision.may_execute
        assert decision.reason is ReasonCode.APPROVAL_REQUIRED
        assert "no approval receipt" in decision.detail

    def test_a_receipt_for_a_different_destination_does_not_apply(self) -> None:
        # Same bytes, different place. A receipt to post in the lobby must not
        # authorize posting the identical text somewhere else.
        approved = receipt(action=request(destination="https://technocore.chat/r/lobby"))
        elsewhere = request(destination="https://evil.example/r/lobby")
        decision = execute(genesis(), grant(), approved, action=elsewhere)
        assert not decision.may_execute

    def test_a_receipt_issued_for_another_agent_does_not_apply(self) -> None:
        approved = receipt(agent=STRANGER)
        decision = execute(genesis(), grant(), approved)
        assert not decision.may_execute
        assert decision.reason is ReasonCode.APPROVAL_REQUIRED

    def test_a_receipt_whose_hash_disagrees_with_its_fields_is_ignored(self) -> None:
        """A receipt that displays one action and binds another is refused."""
        good = receipt()
        tampered_payload = dict(good.payload) | {"destination": "https://evil.example/r/lobby"}
        forged = sign_payload(tampered_payload, [ROOT])
        decision = execute(genesis(), grant(), forged)
        assert not decision.may_execute
        assert any("binds something other than" in w for w in decision.warnings)

    def test_a_receipt_not_signed_by_its_approver_is_ignored(self) -> None:
        forged = receipt(approver=ROOT, signers=[STRANGER])
        decision = execute(genesis(), grant(), forged)
        assert not decision.may_execute
        assert any("not signed by its declared approver" in w for w in decision.warnings)

    def test_a_stranger_may_not_approve(self) -> None:
        """D-042: consent must come from someone in the authority above the agent."""
        decision = execute(genesis(), grant(), receipt(approver=STRANGER))
        assert not decision.may_execute
        assert decision.reason is ReasonCode.DENIED
        assert "neither the current root nor an issuer" in decision.detail

    def test_an_intermediate_issuer_may_approve(self) -> None:
        parent = build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=OPERATOR.did,
            epoch=0,
            scopes=[
                {"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "write"]}
            ],
            not_before=FROM,
            expires_at=UNTIL,
            max_depth=1,
            approval="required",
            issued_at=AT,
        )
        parent_env = sign_payload(parent, [ROOT])
        child = sign_payload(
            build_delegation_grant(
                lineage=LINEAGE,
                issuer=OPERATOR.did,
                subject=AGENT.did,
                epoch=0,
                scopes=[
                    {
                        "namespace": "technocore",
                        "resource": "room:lobby",
                        "actions": ["read", "write"],
                    }
                ],
                not_before=FROM,
                expires_at=UNTIL,
                max_depth=0,
                approval="required",
                parent=parent_env.event_id,
                issued_at=AT,
            ),
            [OPERATOR],
        )
        decision = execute(genesis(), parent_env, child, receipt(approver=OPERATOR))
        assert decision.may_execute
        assert decision.approver == OPERATOR.did


# ------------------------------------------------------------------ time


class TestExpiry:
    def test_an_expired_receipt_is_refused(self) -> None:
        stale = receipt(issued_at=AT - timedelta(hours=2), expires_at=AT - timedelta(hours=1))
        decision = execute(genesis(), grant(), stale)
        assert decision.reason is ReasonCode.EXPIRED

    def test_expiry_is_exclusive_at_the_boundary(self) -> None:
        exact = receipt(issued_at=AT - timedelta(minutes=5), expires_at=AT)
        assert not execute(genesis(), grant(), exact).may_execute

    def test_a_receipt_issued_in_the_future_is_refused(self) -> None:
        future = receipt(issued_at=AT + timedelta(hours=1), expires_at=AT + timedelta(hours=2))
        decision = execute(genesis(), grant(), future)
        assert decision.reason is ReasonCode.NOT_YET_VALID


# ------------------------------------------------------------------ replay


class TestReplay:
    def test_a_receipt_may_be_spent_once(self) -> None:
        store = InMemorySpentStore()
        events = (genesis(), grant(), receipt())
        first = execute(*events, store=store)
        assert first.may_execute
        assert first.reserved

        second = execute(*events, store=store)
        assert not second.may_execute
        assert second.reason is ReasonCode.REVOKED
        assert "already been used" in second.detail

    def test_a_preview_does_not_consume_the_receipt(self) -> None:
        store = InMemorySpentStore()
        events = (genesis(), grant(), receipt())
        preview = execute(*events, store=store, reserve=False)
        assert preview.may_execute
        assert not preview.reserved
        assert execute(*events, store=store).may_execute

    def test_a_failed_check_does_not_burn_the_receipt(self) -> None:
        """Reserving before the checks would let a refusal cost the approver.

        They would have to approve again to recover from a decision that never
        permitted anything in the first place.
        """
        store = InMemorySpentStore()
        approved = receipt()
        # No grant: the authority check refuses before any receipt is consulted.
        assert not execute(genesis(), approved, store=store).may_execute
        assert not store.is_spent(approved.event_id)
        # With the grant present, the same receipt still works.
        assert execute(genesis(), grant(), approved, store=store).may_execute

    def test_only_one_of_two_racing_executors_may_win(self) -> None:
        store = InMemorySpentStore()
        events = (genesis(), grant(), receipt())
        results: list[bool] = []
        lock = threading.Lock()

        def run() -> None:
            outcome = execute(*events, store=store)
            with lock:
                results.append(outcome.may_execute)

        threads = [threading.Thread(target=run) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sum(results) == 1


class TestSqliteSpentStore:
    def test_reservation_is_durable(self, tmp_path: Any) -> None:
        path = tmp_path / "spent.sqlite"
        assert SqliteSpentStore(path).reserve("sha256:" + "a" * 64)
        # A fresh instance over the same file must still refuse it. An in-memory
        # store would forget on restart and make every past receipt replayable.
        assert not SqliteSpentStore(path).reserve("sha256:" + "a" * 64)

    def test_distinct_receipts_do_not_collide(self, tmp_path: Any) -> None:
        store = SqliteSpentStore(tmp_path / "spent.sqlite")
        assert store.reserve("sha256:" + "a" * 64)
        assert store.reserve("sha256:" + "b" * 64)

    def test_is_spent_reports_without_reserving(self, tmp_path: Any) -> None:
        store = SqliteSpentStore(tmp_path / "spent.sqlite")
        assert not store.is_spent("sha256:" + "c" * 64)
        assert store.reserve("sha256:" + "c" * 64)
        assert store.is_spent("sha256:" + "c" * 64)

    def test_concurrent_reservations_elect_one_winner(self, tmp_path: Any) -> None:
        store = SqliteSpentStore(tmp_path / "spent.sqlite")
        receipt_id = "sha256:" + "d" * 64
        wins: list[bool] = []
        lock = threading.Lock()

        def run() -> None:
            got = store.reserve(receipt_id)
            with lock:
                wins.append(got)

        threads = [threading.Thread(target=run) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sum(wins) == 1


# ------------------------------------------------------------------ builder rules


class TestBuilder:
    def test_a_short_nonce_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="16 bytes"):
            build_approval_receipt(
                lineage=LINEAGE,
                approver=ROOT.did,
                agent=AGENT.did,
                request=request(),
                nonce=b"\x00" * 8,
                expires_at=AT + timedelta(minutes=10),
                issued_at=AT,
            )

    def test_an_agent_may_not_approve_itself(self) -> None:
        with pytest.raises(MalformedEventError, match="may not approve its own"):
            build_approval_receipt(
                lineage=LINEAGE,
                approver=AGENT.did,
                agent=AGENT.did,
                request=request(),
                nonce=NONCE,
                expires_at=AT + timedelta(minutes=10),
                issued_at=AT,
            )

    def test_expiry_must_follow_issuance(self) -> None:
        with pytest.raises(MalformedEventError, match="after issuedAt"):
            build_approval_receipt(
                lineage=LINEAGE,
                approver=ROOT.did,
                agent=AGENT.did,
                request=request(),
                nonce=NONCE,
                expires_at=AT,
                issued_at=AT,
            )


class TestActionRequest:
    def test_the_hash_covers_every_field(self) -> None:
        base = request()
        for variant in (
            request(content=b"other"),
            request(destination="https://technocore.chat/r/ops"),
            ActionRequest.over_bytes(
                namespace="technocore",
                resource="room:ops",
                action="write",
                destination=DESTINATION,
                content=MESSAGE,
            ),
            ActionRequest.over_bytes(
                namespace="technocore",
                resource="room:lobby",
                action="read",
                destination=DESTINATION,
                content=MESSAGE,
            ),
        ):
            assert not base.matches(variant)

    def test_the_hash_is_stable(self) -> None:
        assert request().request_hash == request().request_hash

    def test_a_destination_may_not_carry_control_characters(self) -> None:
        # The destination is what the human reads before consenting.
        with pytest.raises(MalformedEventError, match="control characters"):
            ActionRequest.over_bytes(
                namespace="technocore",
                resource="room:lobby",
                action="write",
                destination="https://good.example\x1b[2K\rhttps://evil.example",
                content=MESSAGE,
            )

    def test_an_unregistered_action_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="no action"):
            ActionRequest.over_bytes(
                namespace="technocore",
                resource="room:lobby",
                action="merge",
                destination=DESTINATION,
                content=MESSAGE,
            )


# ------------------------------------------------------------------ no approval needed


class TestApprovalNotRequired:
    def test_a_chain_needing_no_approval_executes_without_a_receipt(self) -> None:
        decision = execute(genesis(), grant(approval="none"))
        assert decision.may_execute
        assert decision.receipt_id is None

    def test_external_only_needs_a_receipt_for_an_external_action(self) -> None:
        assert not execute(genesis(), grant(approval="external-only")).may_execute

    def test_external_only_executes_an_internal_action_without_one(self) -> None:
        decision = execute(genesis(), grant(approval="external-only"), external=False)
        assert decision.may_execute


class TestTimeOfCheckTimeOfUse:
    def test_the_decision_is_re_evaluated_on_every_call(self) -> None:
        """docs/06: re-check immediately before executing, not once per session.

        An executor that cached an earlier `may_execute` would act on a state
        that has since changed. `check_execution` recomputes everything -- the
        lineage, the chain, the receipt window -- at the instant it is asked.
        """
        events = (genesis(), grant(), receipt())
        assert execute(*events, at=AT).may_execute

        later = AT + timedelta(hours=1)  # past the receipt's ten-minute window
        assert not execute(*events, at=later).may_execute
        assert execute(*events, at=later).reason is ReasonCode.EXPIRED

    def test_a_revocation_arriving_between_calls_flips_the_answer(self) -> None:
        from lineageauth.builders import build_delegation_revoke

        target = grant()
        approved = receipt()
        assert execute(genesis(), target, approved).may_execute

        revocation = sign_payload(
            build_delegation_revoke(
                lineage=LINEAGE, issuer=ROOT.did, grant=target.event_id, issued_at=AT
            ),
            [ROOT],
        )
        after = execute(genesis(), target, approved, revocation)
        assert not after.may_execute
        assert after.reason is ReasonCode.REVOKED

    def test_nothing_is_reserved_when_the_state_has_moved_on(self) -> None:
        store = InMemorySpentStore()
        events = (genesis(), grant(), receipt())
        assert not execute(*events, at=AT + timedelta(hours=1), store=store).may_execute
        # The receipt was never usable at that time, so it must remain unspent.
        assert not store.is_spent(receipt().event_id)


class TestAnAgentCannotApproveItselfThroughALoop:
    """The end-to-end shape of the audit finding, 2026-08-28.

    Every edge attenuates properly, so nothing in the delegation rules objects.
    What the attacker gains is not authority -- it is *standing*: by routing the
    chain through a key it also controls, the agent appears among the issuers
    that `_approvers_entitled` reads, and a receipt it signed itself then counts
    as somebody else consenting.

    Three separate locks were added, and this test only passes if the whole
    door holds: the chain refuses a repeated subject, the entitled set discards
    the requester, and `read_receipt` refuses `approver == agent`.
    """

    def _loop(self) -> tuple[Envelope, Envelope, Envelope]:
        """ROOT -> AGENT (depth 2), AGENT -> OPERATOR, OPERATOR -> AGENT."""
        scopes = [
            {"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "write"]}
        ]

        def edge(issuer: LocalSigner, subject: LocalSigner, depth: int, parent: str | None):
            return sign_payload(
                build_delegation_grant(
                    lineage=LINEAGE,
                    issuer=issuer.did,
                    subject=subject.did,
                    epoch=0,
                    scopes=scopes,
                    not_before=FROM,
                    expires_at=UNTIL,
                    max_depth=depth,
                    approval="required",
                    parent=parent,
                    issued_at=AT,
                ),
                [issuer],
            )

        g1 = edge(ROOT, AGENT, 2, None)
        g2 = edge(AGENT, OPERATOR, 1, g1.event_id)
        g3 = edge(OPERATOR, AGENT, 0, g2.event_id)
        return g1, g2, g3

    def test_a_receipt_from_a_key_the_agent_controls_is_refused(self) -> None:
        g1, g2, g3 = self._loop()
        # OPERATOR here stands for a throwaway key the agent generated. Nothing
        # in the bundle distinguishes it from a real second party -- which is
        # the point, and why the fix cannot depend on telling them apart.
        decision = execute(genesis(), g1, g2, g3, receipt(approver=OPERATOR))
        assert not decision.may_execute
        assert decision.reason is ReasonCode.DENIED

    def test_the_builder_will_not_even_draft_a_self_receipt(self) -> None:
        """The blunt version is refused one step earlier, at drafting."""
        with pytest.raises(MalformedEventError, match="own action"):
            receipt(approver=AGENT, agent=AGENT)

    def test_the_verifier_refuses_a_self_receipt_the_builder_never_drafts(self) -> None:
        """`build_approval_receipt` refuses this, so the payload is hand-made.

        A rule only the drafting side enforces is a rule an attacker skips by
        not using the drafting side.
        """
        from lineageauth.approval import read_receipt

        drafted = build_approval_receipt(
            lineage=LINEAGE,
            approver=ROOT.did,
            agent=AGENT.did,
            request=request(),
            nonce=NONCE,
            expires_at=AT + timedelta(minutes=10),
            issued_at=AT - timedelta(minutes=1),
        )
        forged = {**drafted, "approver": AGENT.did}
        envelope = sign_payload(forged, [AGENT])
        admitted = EventBundle.from_envelopes([envelope]).admitted[0]

        complaint = read_receipt(admitted)
        assert isinstance(complaint, str)
        assert "own action" in complaint

    def test_an_honest_two_party_approval_still_works(self) -> None:
        """The negative control. All of the above must not cost the feature."""
        decision = execute(genesis(), grant(), receipt(approver=ROOT))
        assert decision.may_execute, decision.detail
