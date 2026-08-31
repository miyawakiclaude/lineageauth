"""One walk, one answer: grant standing must agree with the permission gate.

`describe_grants` once judged each grant on its own -- not revoked, in its
window, right epoch -- and said so with `VALID_AUTHORITY_CHAIN`. That reading was
documented, and it was still a trap, because nothing consumes a grant's standing
in isolation. The graph draws an edge with it, the passport lists scopes with it,
the MCP `list_grants` tool ships it to an agent, and `check_receipt_authority`
turns it into a claim that past work was done under authority.

So revoking a parent produced two answers from one bundle: `check_permission`
said REVOKED, and all four of those surfaces said the child was live (D-103).

The whole suite passed while that was true, which is why these tests exist. They
pin the invariant rather than the four symptoms: whatever `check_permission`
refuses, standing must refuse too.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from lineageauth.actions import sha256_hex
from lineageauth.authority import check_permission, describe_grants
from lineageauth.builders import (
    build_artifact_receipt,
    build_artifact_register,
    build_delegation_grant,
    build_delegation_revoke,
    build_root_create,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.errors import ReasonCode
from lineageauth.evidence import check_receipt_authority, collect_evidence
from lineageauth.graph import build_graph
from lineageauth.passport import build_passport
from tests.testkeys import AGENT_1, RECOVERY_1, ROOT_A, unsafe_signer

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
MIDDLE = unsafe_signer(RECOVERY_1)
WORKER = unsafe_signer(AGENT_1)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

SCOPE = {"namespace": "github", "resource": "repo:owner/list", "actions": ["commit"]}
CONTENT = b"work done under a delegation that was later cut off\n"
ARTIFACT = sha256_hex(CONTENT)


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def hop(
    issuer: LocalSigner,
    subject: LocalSigner,
    *,
    depth: int,
    parent: str | None = None,
    expires_in_days: int = 30,
) -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=issuer.did,
            subject=subject.did,
            epoch=0,
            scopes=[SCOPE],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=expires_in_days),
            max_depth=depth,
            parent=parent,
            issued_at=AT,
        ),
        [issuer],
    )


def cut(target: Envelope) -> Envelope:
    return sign_payload(
        build_delegation_revoke(
            lineage=LINEAGE, issuer=ROOT.did, grant=target.event_id, issued_at=AT
        ),
        [ROOT],
    )


def work(*, cites: list[str]) -> tuple[Envelope, Envelope]:
    register = sign_payload(
        build_artifact_register(
            lineage=LINEAGE,
            artifact_id=ARTIFACT,
            media_type="text/plain",
            byte_length=len(CONTENT),
            created_by=WORKER.did,
            issued_at=AT,
        ),
        [WORKER],
    )
    receipt = sign_payload(
        build_artifact_receipt(
            lineage=LINEAGE,
            artifact_id=ARTIFACT,
            worker=WORKER.did,
            authority_refs=cites,
            issued_at=AT,
        ),
        [WORKER],
    )
    return register, receipt


def standing_of(bundle: EventBundle, event_id: str, *, at: datetime = AT):
    return {s.grant.event_id: s for s in describe_grants(bundle, lineage=LINEAGE, at=at)}[event_id]


def gate(bundle: EventBundle, *, at: datetime = AT):
    return check_permission(
        bundle,
        lineage=LINEAGE,
        agent=WORKER.did,
        namespace=SCOPE["namespace"],
        resource=SCOPE["resource"],
        action="commit",
        at=at,
    )


class TestParentRevoked:
    """The case that was wrong on every surface at once."""

    def _bundle(self) -> tuple[EventBundle, Envelope, Envelope]:
        g1 = hop(ROOT, MIDDLE, depth=1)
        g2 = hop(MIDDLE, WORKER, depth=0, parent=g1.event_id)
        register, receipt = work(cites=[g2.event_id])
        events = [genesis(), g1, g2, cut(g1), register, receipt]
        return EventBundle.from_envelopes(events), g1, g2

    def test_the_gate_refuses(self) -> None:
        bundle, _, _ = self._bundle()
        assert gate(bundle).reason is ReasonCode.REVOKED

    def test_the_child_grant_is_not_usable(self) -> None:
        bundle, _, g2 = self._bundle()
        child = standing_of(bundle, g2.event_id)
        assert not child.usable
        assert child.reason is ReasonCode.REVOKED

    def test_the_graph_draws_no_live_edge_below_a_dead_one(self) -> None:
        bundle, _, _ = self._bundle()
        delegated = [
            e
            for e in build_graph(bundle, lineage=LINEAGE, at=AT).edges
            if e.kind.value == "delegated"
        ]
        assert len(delegated) == 2
        assert not any(e.live for e in delegated)

    def test_the_passport_lists_no_scopes(self) -> None:
        bundle, _, _ = self._bundle()
        passport = build_passport(bundle, lineage=LINEAGE, did=WORKER.did, at=AT)
        assert passport.authority_scopes == ()

    def test_the_receipt_is_not_supported(self) -> None:
        bundle, _, _ = self._bundle()
        found = collect_evidence(bundle, lineage=LINEAGE, artifact_id=ARTIFACT)
        result = check_receipt_authority(bundle, lineage=LINEAGE, receipt=found.receipts[0], at=AT)
        assert not result.supported
        assert result.reason is ReasonCode.REVOKED

    def test_the_receipt_remains_a_signed_statement(self) -> None:
        # Refusing to call it supported is not the same as erasing it. The worker
        # really did sign the claim, and the evidence layer still carries it.
        bundle, _, _ = self._bundle()
        found = collect_evidence(bundle, lineage=LINEAGE, artifact_id=ARTIFACT)
        assert found.receipts[0].worker == WORKER.did


class TestItStillPermitsWhatItShould:
    """Negative controls. A check that refuses everything refuses nothing."""

    def _healthy(self) -> tuple[EventBundle, Envelope, Envelope]:
        g1 = hop(ROOT, MIDDLE, depth=1)
        g2 = hop(MIDDLE, WORKER, depth=0, parent=g1.event_id)
        register, receipt = work(cites=[g2.event_id])
        events = [genesis(), g1, g2, register, receipt]
        return EventBundle.from_envelopes(events), g1, g2

    def test_an_intact_chain_is_usable_at_every_hop(self) -> None:
        bundle, g1, g2 = self._healthy()
        assert standing_of(bundle, g1.event_id).usable
        assert standing_of(bundle, g2.event_id).usable
        assert gate(bundle).reason is ReasonCode.VALID_AUTHORITY_CHAIN

    def test_an_intact_chain_supports_the_receipt(self) -> None:
        bundle, _, _ = self._healthy()
        found = collect_evidence(bundle, lineage=LINEAGE, artifact_id=ARTIFACT)
        result = check_receipt_authority(bundle, lineage=LINEAGE, receipt=found.receipts[0], at=AT)
        assert result.supported

    def test_revoking_the_child_leaves_the_parent_alone(self) -> None:
        # Revocation runs from the root down, never upward.
        g1 = hop(ROOT, MIDDLE, depth=1)
        g2 = hop(MIDDLE, WORKER, depth=0, parent=g1.event_id)
        bundle = EventBundle.from_envelopes([genesis(), g1, g2, cut(g2)])
        assert standing_of(bundle, g1.event_id).usable
        assert not standing_of(bundle, g2.event_id).usable

    def test_a_root_grant_needs_no_chain(self) -> None:
        direct = hop(ROOT, WORKER, depth=0)
        bundle = EventBundle.from_envelopes([genesis(), direct])
        assert standing_of(bundle, direct.event_id).usable


class TestOtherWaysAParentDies:
    """Revocation is one of several. Standing has to follow all of them upward."""

    def test_an_expired_parent_takes_the_child_with_it(self) -> None:
        g1 = hop(ROOT, MIDDLE, depth=1, expires_in_days=2)
        g2 = hop(MIDDLE, WORKER, depth=0, parent=g1.event_id, expires_in_days=2)
        bundle = EventBundle.from_envelopes([genesis(), g1, g2])
        later = AT + timedelta(days=10)
        child = standing_of(bundle, g2.event_id, at=later)
        assert not child.usable
        assert child.reason is ReasonCode.EXPIRED
        assert gate(bundle, at=later).reason is ReasonCode.EXPIRED

    def test_a_child_cannot_be_issued_outliving_its_parent(self) -> None:
        # Which is why the case above has to give both hops the same window: a
        # long-lived child of a short-lived parent is refused at the edge, so
        # "parent expired, child still running" cannot be built in the first
        # place. Attenuation covers time, not only scope.
        g1 = hop(ROOT, MIDDLE, depth=1, expires_in_days=2)
        g2 = hop(MIDDLE, WORKER, depth=0, parent=g1.event_id, expires_in_days=90)
        bundle = EventBundle.from_envelopes([genesis(), g1, g2])
        child = standing_of(bundle, g2.event_id)
        assert not child.usable
        assert child.reason is ReasonCode.SCOPE_VIOLATION
        assert "outlives the grant it derives from" in child.detail

    def test_a_missing_parent_is_unresolved_not_usable(self) -> None:
        g1 = hop(ROOT, MIDDLE, depth=1)
        g2 = hop(MIDDLE, WORKER, depth=0, parent=g1.event_id)
        bundle = EventBundle.from_envelopes([genesis(), g2])  # g1 withheld
        child = standing_of(bundle, g2.event_id)
        assert not child.usable
        assert child.reason is ReasonCode.UNRESOLVED_PARENT


class TestTheTwoAnswersAgree:
    """The invariant itself, rather than any one of its symptoms."""

    def test_standing_never_disagrees_with_the_gate(self) -> None:
        g1 = hop(ROOT, MIDDLE, depth=1, expires_in_days=2)
        g2 = hop(MIDDLE, WORKER, depth=0, parent=g1.event_id, expires_in_days=2)
        cases = {
            "intact": [genesis(), g1, g2],
            "parent revoked": [genesis(), g1, g2, cut(g1)],
            "child revoked": [genesis(), g1, g2, cut(g2)],
            "parent withheld": [genesis(), g2],
        }
        checked = 0
        for label, events in cases.items():
            for at in (AT, AT + timedelta(days=10)):
                bundle = EventBundle.from_envelopes(events)
                decision = gate(bundle, at=at)
                grants = {
                    s.grant.event_id: s for s in describe_grants(bundle, lineage=LINEAGE, at=at)
                }
                leaf = grants.get(g2.event_id)
                assert leaf is not None, f"{label}: the leaf grant went missing"
                permitted = decision.reason is ReasonCode.VALID_AUTHORITY_CHAIN
                assert leaf.usable == permitted, (
                    f"{label} at {at.date()}: standing said usable={leaf.usable} "
                    f"while the gate said {decision.reason}"
                )
                checked += 1
        assert checked == 8  # a loop that silently stopped iterating proves nothing
