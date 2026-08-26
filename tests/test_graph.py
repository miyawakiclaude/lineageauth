"""The authority graph projection.

docs/17 fixes the vocabulary a rendering may use. The point of these tests is
that the picture and the verifier cannot drift apart: every status the graph
shows is read off the resolver, so an edge is drawn as live exactly when the
authority layer says the grant is usable -- never on the graph's own reckoning.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.authority import describe_grants
from lineageauth.builders import (
    build_approval_receipt,
    build_delegation_grant,
    build_delegation_revoke,
    build_recovery_policy,
    build_root_create,
    build_root_succession,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.errors import ReasonCode
from lineageauth.graph import AuthorityGraph, EdgeKind, NodeKind, build_graph
from tests.testkeys import (
    AGENT_1,
    OUTSIDER,
    RECOVERY_1,
    RECOVERY_2,
    RECOVERY_3,
    ROOT_A,
    ROOT_B,
    unsafe_signer,
)

AT = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
ROOT = unsafe_signer(ROOT_A)
NEXT_ROOT = unsafe_signer(ROOT_B)
AGENT = unsafe_signer(AGENT_1)
STRANGER = unsafe_signer(OUTSIDER)
MEMBERS = [unsafe_signer(n) for n in (RECOVERY_1, RECOVERY_2, RECOVERY_3)]
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

SCOPE = {"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "write"]}


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def policy(*, seq: int = 1, previous: str | None = None) -> Envelope:
    return sign_payload(
        build_recovery_policy(
            lineage=LINEAGE,
            epoch=0,
            policy_seq=seq,
            members=[m.did for m in MEMBERS],
            threshold=2,
            previous_policy=previous,
            issued_at=AT,
        ),
        [ROOT],
    )


def grant(*, expires_at: datetime | None = None, approval: str = "none") -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=AGENT.did,
            epoch=0,
            scopes=[SCOPE],
            not_before=AT - timedelta(days=1),
            expires_at=expires_at or AT + timedelta(days=30),
            max_depth=0,
            approval=approval,
            issued_at=AT,
        ),
        [ROOT],
    )


def graph_of(*envelopes: Envelope, at: datetime = AT) -> AuthorityGraph:
    return build_graph(EventBundle.from_envelopes(envelopes), lineage=LINEAGE, at=at)


def edges_of(projection: AuthorityGraph, kind: EdgeKind) -> list:
    return [edge for edge in projection.edges if edge.kind is kind]


class TestNodes:
    def test_the_genesis_root_is_both_genesis_and_current(self) -> None:
        projection = graph_of(genesis())
        node = next(n for n in projection.nodes if n.did == ROOT.did)
        assert set(node.kinds) == {NodeKind.GENESIS_ROOT, NodeKind.CURRENT_ROOT}

    def test_a_succession_marks_the_old_root_superseded(self) -> None:
        move = sign_payload(
            build_root_succession(
                lineage=LINEAGE,
                from_root=ROOT.did,
                to_root=NEXT_ROOT.did,
                from_epoch=0,
                mode="normal",
                issued_at=AT,
            ),
            [ROOT],
        )
        projection = graph_of(genesis(), move)
        old = next(n for n in projection.nodes if n.did == ROOT.did)
        new = next(n for n in projection.nodes if n.did == NEXT_ROOT.did)
        assert NodeKind.SUPERSEDED_ROOT in old.kinds
        assert NodeKind.CURRENT_ROOT not in old.kinds
        assert NodeKind.CURRENT_ROOT in new.kinds

    def test_a_grant_subject_is_an_agent(self) -> None:
        projection = graph_of(genesis(), grant())
        node = next(n for n in projection.nodes if n.did == AGENT.did)
        assert node.kinds == (NodeKind.AGENT,)

    def test_recovery_members_are_marked(self) -> None:
        projection = graph_of(genesis(), policy())
        for member in MEMBERS:
            node = next(n for n in projection.nodes if n.did == member.did)
            assert NodeKind.RECOVERY_MEMBER in node.kinds

    def test_no_node_kind_reads_as_a_verdict(self) -> None:
        # docs/17: never "trusted", "official", or "safe".
        forbidden = {"trust", "official", "safe", "verified-human", "good"}
        for kind in NodeKind:
            assert not any(word in str(kind).lower() for word in forbidden)


class TestEdgesMatchTheVerifier:
    def test_a_live_grant_is_drawn_live(self) -> None:
        projection = graph_of(genesis(), grant())
        edge = edges_of(projection, EdgeKind.DELEGATED)[0]
        assert edge.live
        assert edge.source == ROOT.did
        assert edge.target == AGENT.did

    def test_a_revoked_grant_is_drawn_revoked_and_names_the_revocation(self) -> None:
        target = grant()
        revocation = sign_payload(
            build_delegation_revoke(
                lineage=LINEAGE, issuer=ROOT.did, grant=target.event_id, issued_at=AT
            ),
            [ROOT],
        )
        edge = edges_of(graph_of(genesis(), target, revocation), EdgeKind.DELEGATED)[0]
        assert not edge.live
        assert edge.reason is ReasonCode.REVOKED
        assert revocation.event_id in edge.detail

    def test_an_expired_grant_is_drawn_expired(self) -> None:
        edge = edges_of(
            graph_of(genesis(), grant(expires_at=AT - timedelta(seconds=1))), EdgeKind.DELEGATED
        )[0]
        assert not edge.live
        assert edge.reason is ReasonCode.EXPIRED

    def test_edge_liveness_always_agrees_with_the_authority_layer(self) -> None:
        """The property that keeps the picture honest.

        A drawing that worked out its own answers could disagree with the
        verifier, and people believe pictures.
        """
        target = grant()
        revocation = sign_payload(
            build_delegation_revoke(
                lineage=LINEAGE, issuer=ROOT.did, grant=target.event_id, issued_at=AT
            ),
            [ROOT],
        )
        for events in (
            (genesis(), grant()),
            (genesis(), target, revocation),
            (genesis(), grant(expires_at=AT - timedelta(seconds=1))),
        ):
            bundle = EventBundle.from_envelopes(events)
            projection = build_graph(bundle, lineage=LINEAGE, at=AT)
            standings = {
                s.grant.event_id: s for s in describe_grants(bundle, lineage=LINEAGE, at=AT)
            }
            for edge in edges_of(projection, EdgeKind.DELEGATED):
                assert edge.live == standings[edge.event_id].usable
                assert edge.reason == standings[edge.event_id].reason

    def test_a_recovery_succession_is_drawn_as_recovered(self) -> None:
        active = policy()
        move = sign_payload(
            build_root_succession(
                lineage=LINEAGE,
                from_root=ROOT.did,
                to_root=NEXT_ROOT.did,
                from_epoch=0,
                mode="recovery",
                recovery_policy_ref=active.event_id,
                issued_at=AT,
            ),
            [MEMBERS[0], MEMBERS[1]],
        )
        projection = graph_of(genesis(), active, move)
        assert edges_of(projection, EdgeKind.RECOVERED)
        assert not edges_of(projection, EdgeKind.SUCCEEDED)

    def test_a_replaced_recovery_policy_is_drawn_superseded(self) -> None:
        first = policy(seq=1)
        second = policy(seq=2, previous=first.event_id)
        projection = graph_of(genesis(), first, second)
        by_event = {e.event_id: e for e in edges_of(projection, EdgeKind.RECOVERY_MEMBER_OF)}
        assert by_event[second.event_id].live
        assert not by_event[first.event_id].live
        assert by_event[first.event_id].reason is ReasonCode.SUPERSEDED

    def test_an_approval_is_drawn_and_expires(self) -> None:
        from lineageauth.actions import ActionRequest

        request = ActionRequest.over_bytes(
            namespace="technocore",
            resource="room:lobby",
            action="write",
            destination="https://technocore.chat/r/lobby",
            content=b"hello",
        )
        receipt = sign_payload(
            build_approval_receipt(
                lineage=LINEAGE,
                approver=ROOT.did,
                agent=AGENT.did,
                request=request,
                nonce=b"\x11" * 16,
                expires_at=AT + timedelta(minutes=10),
                issued_at=AT,
            ),
            [ROOT],
        )
        live = edges_of(graph_of(genesis(), grant(), receipt), EdgeKind.APPROVED)[0]
        assert live.live

        later = edges_of(
            graph_of(genesis(), grant(), receipt, at=AT + timedelta(hours=1)), EdgeKind.APPROVED
        )[0]
        assert not later.live
        assert later.reason is ReasonCode.EXPIRED


class TestProjectionProperties:
    def test_it_is_deterministic_under_input_order(self) -> None:
        import itertools

        events = [genesis(), policy(), grant()]
        renderings = {
            str(build_graph(EventBundle.from_envelopes(order), lineage=LINEAGE, at=AT).to_dict())
            for order in itertools.permutations(events)
        }
        assert len(renderings) == 1

    def test_every_edge_names_the_event_that_asserts_it(self) -> None:
        projection = graph_of(genesis(), policy(), grant())
        assert projection.edges
        for edge in projection.edges:
            assert edge.event_id.startswith("sha256:")

    def test_an_unresolved_lineage_reports_no_current_root(self) -> None:
        projection = graph_of(grant())  # no genesis
        assert not projection.resolved
        assert projection.to_dict()["root"] is None

    def test_the_note_refuses_to_imply_trustworthiness(self) -> None:
        projection = graph_of(genesis())
        assert "not a person" in projection.note
        assert "trustworthy" in projection.note

    @pytest.mark.parametrize("kind", list(EdgeKind))
    def test_no_edge_kind_reads_as_a_verdict(self, kind: EdgeKind) -> None:
        assert not any(w in str(kind).lower() for w in ("trust", "safe", "official"))
