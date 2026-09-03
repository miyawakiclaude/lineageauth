"""Delegation chains and the permission decision.

docs/23_TESTING.md names the authority properties this file defends:

    a child never has a permission its parent lacks;
    revocation monotonically removes authority;
    a higher valid epoch never restores an old current root;
    approval never grants missing base authority;
    time window narrowing is monotonic.

Most of what follows is written from the attacker's side: what would someone
holding one key try, and does it get refused with an accurate reason.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from lineageauth.authority import AuthorityDecision, Grant, check_permission, read_grant
from lineageauth.builders import (
    build_delegation_grant,
    build_delegation_revoke,
    build_root_create,
    build_root_succession,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError, ReasonCode
from lineageauth.scopes import ApprovalMode
from tests.testkeys import AGENT_1, OUTSIDER, RECOVERY_1, ROOT_A, ROOT_B, unsafe_signer

AT = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
FROM = AT - timedelta(days=1)
UNTIL = AT + timedelta(days=30)

ROOT = unsafe_signer(ROOT_A)
NEXT_ROOT = unsafe_signer(ROOT_B)
AGENT = unsafe_signer(AGENT_1)
SUB_AGENT = unsafe_signer(RECOVERY_1)
STRANGER = unsafe_signer(OUTSIDER)

LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

LOBBY_WRITE = {"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "write"]}
ANY_ROOM_READ = {"namespace": "technocore", "resource": "room:*", "actions": ["read"]}


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(
    *,
    issuer: LocalSigner = ROOT,
    subject: LocalSigner = AGENT,
    scopes: list[dict[str, Any]] | None = None,
    epoch: int = 0,
    not_before: datetime = FROM,
    expires_at: datetime = UNTIL,
    max_depth: int = 1,
    approval: str = "none",
    approvers: list[str] | None = None,
    parent: str | None = None,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    # D-107: a grant that demands approval must name who gives it. ROOT, unless told.
    if approvers is None and approval != "none":
        approvers = [ROOT.did]
    payload = build_delegation_grant(
        lineage=LINEAGE,
        issuer=issuer.did,
        subject=subject.did,
        epoch=epoch,
        scopes=scopes if scopes is not None else [LOBBY_WRITE],
        not_before=not_before,
        expires_at=expires_at,
        max_depth=max_depth,
        approval=approval,
        approvers=approvers,
        parent=parent,
        issued_at=AT,
    )
    return sign_payload(payload, signers if signers is not None else [issuer])


def revoke(
    *, issuer: LocalSigner, target: Envelope, signers: list[LocalSigner] | None = None
) -> Envelope:
    payload = build_delegation_revoke(
        lineage=LINEAGE, issuer=issuer.did, grant=target.event_id, issued_at=AT
    )
    return sign_payload(payload, signers if signers is not None else [issuer])


def check(
    *envelopes: Envelope,
    agent: LocalSigner = AGENT,
    namespace: str = "technocore",
    resource: str = "room:lobby",
    action: str = "write",
    at: datetime = AT,
    external: bool = True,
) -> AuthorityDecision:
    return check_permission(
        EventBundle.from_envelopes(envelopes),
        lineage=LINEAGE,
        agent=agent.did,
        namespace=namespace,
        resource=resource,
        action=action,
        at=at,
        external=external,
    )


# ------------------------------------------------------------------ the happy path


class TestValidChains:
    def test_a_root_grant_authorizes_its_subject(self) -> None:
        decision = check(genesis(), grant())
        assert decision.allowed
        assert decision.reason is ReasonCode.VALID_AUTHORITY_CHAIN
        assert decision.epoch == 0
        assert decision.root == ROOT.did

    def test_the_decision_names_the_path_that_justified_it(self) -> None:
        root_grant = grant()
        decision = check(genesis(), root_grant)
        assert decision.path == (root_grant.event_id,)

    def test_a_two_level_chain_authorizes_the_sub_agent(self) -> None:
        first = grant(max_depth=1)
        second = grant(
            issuer=AGENT,
            subject=SUB_AGENT,
            scopes=[LOBBY_WRITE],
            max_depth=0,
            parent=first.event_id,
        )
        decision = check(genesis(), first, second, agent=SUB_AGENT)
        assert decision.allowed
        assert decision.path == (first.event_id, second.event_id)

    def test_a_wildcard_grant_covers_a_concrete_room(self) -> None:
        decision = check(
            genesis(), grant(scopes=[ANY_ROOM_READ]), resource="room:ops", action="read"
        )
        assert decision.allowed

    def test_a_positive_decision_still_carries_the_provider_auth_caveat(self) -> None:
        decision = check(genesis(), grant())
        assert "never bypassed" in decision.note
        assert "never bypassed" in decision.detail


# ------------------------------------------------------------------ deny by default


class TestDenyByDefault:
    def test_an_agent_with_no_grant_is_denied(self) -> None:
        decision = check(genesis(), grant(), agent=STRANGER)
        assert not decision.allowed
        assert decision.reason is ReasonCode.DENIED

    def test_an_action_outside_the_granted_scope_is_a_scope_violation(self) -> None:
        decision = check(genesis(), grant(scopes=[ANY_ROOM_READ]), action="write")
        assert decision.reason is ReasonCode.SCOPE_VIOLATION

    def test_a_resource_outside_the_granted_scope_is_refused(self) -> None:
        decision = check(genesis(), grant(), resource="room:ops")
        assert decision.reason is ReasonCode.SCOPE_VIOLATION

    def test_a_different_namespace_is_refused(self) -> None:
        decision = check(genesis(), grant(), namespace="github", resource="repo:o/r", action="read")
        assert not decision.allowed

    def test_a_grant_not_signed_by_its_issuer_is_ignored(self) -> None:
        # Otherwise anyone could mint a payload naming the root as issuer.
        forged = grant(issuer=ROOT, subject=STRANGER, signers=[STRANGER])
        decision = check(genesis(), forged, agent=STRANGER)
        assert not decision.allowed
        assert any(r.reason is ReasonCode.MALFORMED for r in decision.refusals)

    def test_a_chain_terminating_at_a_stranger_is_denied(self) -> None:
        # A grant with no parent claims to come from the root itself.
        decision = check(genesis(), grant(issuer=STRANGER), agent=AGENT)
        assert not decision.allowed
        assert decision.reason is ReasonCode.DENIED


# ------------------------------------------------------------------ attenuation


class TestAttenuation:
    def _child(self, parent_env: Envelope, **kwargs: Any) -> Envelope:
        defaults: dict[str, Any] = {
            "issuer": AGENT,
            "subject": SUB_AGENT,
            "parent": parent_env.event_id,
            "max_depth": 0,
        }
        return grant(**(defaults | kwargs))

    def test_a_child_may_not_add_an_action(self) -> None:
        parent = grant(scopes=[ANY_ROOM_READ], max_depth=1)
        child = self._child(
            parent,
            scopes=[
                {"namespace": "technocore", "resource": "room:*", "actions": ["read", "write"]}
            ],
        )
        decision = check(genesis(), parent, child, agent=SUB_AGENT, resource="room:ops")
        assert decision.reason is ReasonCode.SCOPE_VIOLATION

    def test_a_child_may_not_broaden_the_resource(self) -> None:
        parent = grant(scopes=[LOBBY_WRITE], max_depth=1)
        child = self._child(
            parent,
            scopes=[{"namespace": "technocore", "resource": "room:*", "actions": ["write"]}],
        )
        decision = check(genesis(), parent, child, agent=SUB_AGENT, resource="room:ops")
        assert not decision.allowed

    def test_a_child_may_not_outlive_its_parent(self) -> None:
        parent = grant(max_depth=1, expires_at=AT + timedelta(days=1))
        child = self._child(parent, expires_at=AT + timedelta(days=365))
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.SCOPE_VIOLATION

    def test_a_child_may_not_start_before_its_parent(self) -> None:
        parent = grant(max_depth=1, not_before=AT - timedelta(hours=1))
        child = self._child(parent, not_before=AT - timedelta(days=100))
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.SCOPE_VIOLATION

    def test_a_child_may_not_exceed_the_remaining_depth(self) -> None:
        parent = grant(max_depth=1)
        child = self._child(parent, max_depth=1)  # delegating consumes one level
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.SCOPE_VIOLATION

    def test_a_leaf_grant_may_not_be_delegated_from(self) -> None:
        parent = grant(max_depth=0)
        child = self._child(parent)
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.SCOPE_VIOLATION
        assert any("no further delegation" in r.detail for r in decision.refusals)

    def test_a_child_may_not_weaken_the_approval_requirement(self) -> None:
        parent = grant(max_depth=1, approval="required")
        child = self._child(parent, approval="none")
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.SCOPE_VIOLATION
        assert any("only strengthen" in r.detail for r in decision.refusals)

    def test_a_child_may_strengthen_the_approval_requirement(self) -> None:
        parent = grant(max_depth=1, approval="none")
        child = self._child(parent, approval="required")
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.APPROVAL_REQUIRED
        assert decision.approval is ApprovalMode.REQUIRED

    def test_a_child_may_not_widen_the_designated_approvers(self) -> None:
        """D-107: the approver list attenuates like everything else."""
        parent = grant(max_depth=1, approval="required", approvers=[ROOT.did])
        child = self._child(parent, approval="required", approvers=[ROOT.did, STRANGER.did])
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.SCOPE_VIOLATION
        assert any("only narrow the set of approvers" in r.detail for r in decision.refusals)

    def test_a_child_may_narrow_the_designated_approvers(self) -> None:
        parent = grant(max_depth=1, approval="required", approvers=[ROOT.did, STRANGER.did])
        child = self._child(parent, approval="required", approvers=[STRANGER.did])
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.APPROVAL_REQUIRED

    def test_a_child_may_introduce_approvers_when_its_parent_named_none(self) -> None:
        """A parent needing no approval constrains nothing; strengthening is free."""
        parent = grant(max_depth=1, approval="none")
        child = self._child(parent, approval="required", approvers=[STRANGER.did])
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.APPROVAL_REQUIRED

    def test_only_the_holder_of_a_grant_may_delegate_from_it(self) -> None:
        parent = grant(subject=AGENT, max_depth=1)
        # STRANGER did not receive the parent grant, but names it as their parent.
        child = grant(issuer=STRANGER, subject=SUB_AGENT, parent=parent.event_id, max_depth=0)
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.SCOPE_VIOLATION
        assert any("only the holder" in r.detail for r in decision.refusals)

    def test_a_missing_parent_is_unresolved_not_allowed(self) -> None:
        orphan = grant(issuer=AGENT, subject=SUB_AGENT, parent="sha256:" + "a" * 64, max_depth=0)
        decision = check(genesis(), orphan, agent=SUB_AGENT)
        assert decision.reason is ReasonCode.UNRESOLVED_PARENT


# ------------------------------------------------------------------ revocation


class TestRevocation:
    def test_a_revoked_grant_no_longer_authorizes(self) -> None:
        target = grant()
        decision = check(genesis(), target, revoke(issuer=ROOT, target=target))
        assert not decision.allowed
        assert decision.reason is ReasonCode.REVOKED

    def test_the_issuer_of_a_grant_may_revoke_it(self) -> None:
        parent = grant(max_depth=1)
        child = grant(issuer=AGENT, subject=SUB_AGENT, parent=parent.event_id, max_depth=0)
        decision = check(
            genesis(), parent, child, revoke(issuer=AGENT, target=child), agent=SUB_AGENT
        )
        assert decision.reason is ReasonCode.REVOKED

    def test_revoking_a_parent_removes_the_whole_subtree(self) -> None:
        """Revocation is monotonic: it must not be escapable by delegating onward."""
        parent = grant(max_depth=1)
        child = grant(issuer=AGENT, subject=SUB_AGENT, parent=parent.event_id, max_depth=0)
        decision = check(
            genesis(), parent, child, revoke(issuer=ROOT, target=parent), agent=SUB_AGENT
        )
        assert not decision.allowed
        assert decision.reason is ReasonCode.REVOKED

    def test_a_stranger_may_not_revoke(self) -> None:
        # Revocation only subtracts authority, but an unbounded revoker set
        # would let anyone switch off a lineage.
        target = grant()
        decision = check(genesis(), target, revoke(issuer=STRANGER, target=target))
        assert decision.allowed
        assert any(r.reason is ReasonCode.DENIED for r in decision.refusals)

    def test_a_subject_may_not_revoke_the_grant_above_their_own(self) -> None:
        parent = grant(subject=AGENT, max_depth=1)
        # SUB_AGENT holds nothing above `parent` and must not be able to drop it.
        decision = check(genesis(), parent, revoke(issuer=SUB_AGENT, target=parent))
        assert decision.allowed

    def test_a_revocation_of_an_absent_grant_is_reported(self) -> None:
        target = grant()
        decision = check(genesis(), revoke(issuer=ROOT, target=target), agent=AGENT)
        assert any(r.reason is ReasonCode.UNRESOLVED_PARENT for r in decision.refusals)

    def test_a_revocation_not_signed_by_its_issuer_is_ignored(self) -> None:
        target = grant()
        forged = revoke(issuer=ROOT, target=target, signers=[STRANGER])
        decision = check(genesis(), target, forged)
        assert decision.allowed


# ------------------------------------------------------------------ time and epoch


class TestTimeAndEpoch:
    def test_a_grant_is_not_valid_before_its_window(self) -> None:
        decision = check(genesis(), grant(not_before=AT + timedelta(days=1)))
        assert decision.reason is ReasonCode.NOT_YET_VALID

    def test_a_grant_is_not_valid_after_its_window(self) -> None:
        decision = check(genesis(), grant(expires_at=AT - timedelta(seconds=1)))
        assert decision.reason is ReasonCode.EXPIRED

    def test_expiry_is_exclusive_at_the_boundary(self) -> None:
        assert not check(genesis(), grant(expires_at=AT)).allowed
        assert check(genesis(), grant(expires_at=AT + timedelta(seconds=1))).allowed

    def test_a_grant_from_a_replaced_epoch_is_superseded(self) -> None:
        """D-040: authority handed out by a replaced root does not survive it.

        This is what makes recovery mean anything. If a compromised root's
        delegations kept working after the lineage moved to a new root, the
        recovery would have changed who can sign new grants and nothing else.
        """
        old_grant = grant(epoch=0)
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
        decision = check(genesis(), old_grant, move)
        assert not decision.allowed
        assert decision.reason is ReasonCode.SUPERSEDED
        assert decision.epoch == 1

    def test_a_grant_claiming_a_future_epoch_is_unresolved(self) -> None:
        decision = check(genesis(), grant(epoch=5))
        assert decision.reason is ReasonCode.UNRESOLVED_PARENT

    def test_a_new_root_can_re_grant_after_a_succession(self) -> None:
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
        fresh = grant(issuer=NEXT_ROOT, epoch=1)
        assert check(genesis(), move, fresh).allowed


# ------------------------------------------------------------------ approval


class TestApproval:
    def test_a_required_approval_is_not_a_denial(self) -> None:
        decision = check(genesis(), grant(approval="required"))
        assert not decision.allowed
        assert decision.reason is ReasonCode.APPROVAL_REQUIRED
        # The chain is sound; what is missing is a receipt, so the path that
        # would authorize the action is still reported.
        assert decision.path

    def test_external_only_demands_approval_for_an_external_action(self) -> None:
        decision = check(genesis(), grant(approval="external-only"), external=True)
        assert decision.reason is ReasonCode.APPROVAL_REQUIRED

    def test_external_only_permits_an_internal_action(self) -> None:
        decision = check(genesis(), grant(approval="external-only"), external=False)
        assert decision.allowed

    def test_external_defaults_to_the_cautious_assumption(self) -> None:
        # A caller that forgets to say gets the answer that fails safe.
        assert check(genesis(), grant(approval="external-only")).reason is (
            ReasonCode.APPROVAL_REQUIRED
        )

    def test_approval_does_not_supply_missing_authority(self) -> None:
        """D-010: a receipt cannot conjure a base grant that never existed."""
        decision = check(genesis(), grant(approval="required"), agent=STRANGER)
        assert decision.reason is ReasonCode.DENIED
        assert decision.reason is not ReasonCode.APPROVAL_REQUIRED

    def test_the_strictest_requirement_on_the_chain_wins(self) -> None:
        parent = grant(max_depth=1, approval="external-only")
        child = grant(
            issuer=AGENT,
            subject=SUB_AGENT,
            parent=parent.event_id,
            max_depth=0,
            approval="required",
        )
        decision = check(genesis(), parent, child, agent=SUB_AGENT)
        assert decision.approval is ApprovalMode.REQUIRED

    def test_a_required_grant_that_designates_nobody_is_refused(self) -> None:
        """D-107, option A: fail closed at the builder and again at the verifier.

        The builder is a convenience; the verifier is the rule. A hand-built
        grant demanding approval with no `approvers` is not read as "anyone on
        the chain may consent". It is not a usable grant.
        """
        with pytest.raises(MalformedEventError, match="designate"):
            grant(approval="required", approvers=[])
        payload = build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=AGENT.did,
            epoch=0,
            scopes=[LOBBY_WRITE],
            not_before=FROM,
            expires_at=UNTIL,
            max_depth=0,
            approval="required",
            approvers=[ROOT.did],
            issued_at=AT,
        )
        del payload["approvers"]
        decision = check(genesis(), sign_payload(payload, [ROOT]))
        assert not decision.allowed
        assert decision.reason is not ReasonCode.APPROVAL_REQUIRED
        assert any("designates no approver" in r.detail for r in decision.refusals)

    def test_a_grant_needing_no_approval_need_not_name_anyone(self) -> None:
        decision = check(genesis(), grant(approval="none"))
        assert decision.allowed


# ------------------------------------------------------------------ lineage coupling


class TestLineageCoupling:
    def test_an_unresolvable_lineage_reports_its_own_reason(self) -> None:
        # Two incompatible successions out of epoch 0 leave no current root for
        # a chain to terminate at. Reporting CONFLICTED is more useful than a
        # generic denial, and it is the honest answer.
        a = sign_payload(
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
        b = sign_payload(
            build_root_succession(
                lineage=LINEAGE,
                from_root=ROOT.did,
                to_root=STRANGER.did,
                from_epoch=0,
                mode="normal",
                issued_at=AT,
            ),
            [ROOT],
        )
        decision = check(genesis(), grant(), a, b)
        assert not decision.allowed
        assert decision.reason is ReasonCode.CONFLICTED
        assert decision.root is None

    def test_a_bundle_without_a_genesis_cannot_authorize(self) -> None:
        decision = check(grant())
        assert not decision.allowed
        assert decision.reason is ReasonCode.UNRESOLVED_PARENT

    def test_a_tampered_grant_never_reaches_the_resolver(self) -> None:
        good = grant()
        tampered = Envelope(payload=dict(good.payload) | {"maxDepth": 99}, proofs=list(good.proofs))
        decision = check(genesis(), tampered)
        assert not decision.allowed


# ------------------------------------------------------------------ misc hardening


class TestHardening:
    def test_a_malformed_agent_did_is_refused(self) -> None:
        bundle = EventBundle.from_envelopes([genesis(), grant()])
        decision = check_permission(
            bundle,
            lineage=LINEAGE,
            agent="not-a-did",
            namespace="technocore",
            resource="room:lobby",
            action="write",
            at=AT,
        )
        assert decision.reason is ReasonCode.MALFORMED

    def test_a_naive_evaluation_time_is_refused(self) -> None:
        from lineageauth.errors import MalformedEventError

        with pytest.raises(MalformedEventError, match="timezone-aware"):
            check_permission(
                EventBundle.from_envelopes([genesis()]),
                lineage=LINEAGE,
                agent=AGENT.did,
                namespace="technocore",
                resource="room:lobby",
                action="write",
                at=datetime(2026, 8, 26, 12, 0, 0),
            )

    def test_input_order_cannot_change_the_decision(self) -> None:
        import itertools

        events = [genesis(), grant(max_depth=1)]
        events.append(
            grant(issuer=AGENT, subject=SUB_AGENT, parent=events[1].event_id, max_depth=0)
        )
        outcomes = {
            (check(*order, agent=SUB_AGENT).allowed, check(*order, agent=SUB_AGENT).reason)
            for order in itertools.permutations(events)
        }
        assert len(outcomes) == 1

    def test_a_self_referential_grant_is_refused(self) -> None:
        # A cycle must terminate as a refusal, not as a hang.
        payload = build_delegation_grant(
            lineage=LINEAGE,
            issuer=AGENT.did,
            subject=SUB_AGENT.did,
            epoch=0,
            scopes=[LOBBY_WRITE],
            not_before=FROM,
            expires_at=UNTIL,
            max_depth=0,
            issued_at=AT,
        )
        placeholder = sign_payload(payload, [AGENT])
        payload["parent"] = placeholder.event_id
        cyclic = sign_payload(payload, [AGENT])
        decision = check(genesis(), placeholder, cyclic, agent=SUB_AGENT)
        assert not decision.allowed


def _grants_of(bundle: EventBundle) -> dict[str, Grant]:
    """The grants map `check_execution` builds, so the tests judge what it judges."""
    parsed = (read_grant(e) for e in bundle.of_type("delegation.grant", lineage=LINEAGE))
    return {g.event_id: g for g in parsed if not isinstance(g, str)}


class TestADelegationLoopIsWalkedNotRefused:
    """The loop is legitimate, and refusing it never closed what it was for.

    An audit on 2026-08-28 found that an agent A holding a throwaway key B could
    publish A->B and B->A, appear on its own authorizing path as an issuer, and
    so land in `_approvers_entitled` (D-042). The fix was an invariant: no DID is
    the subject of two grants on one chain.

    Alan Karp refuted both halves of that on ucan-wg/spec#206, and both refutations
    were reproduced here before this class was rewritten (D-105).

    It refuses something legitimate. When B asks A to act on a resource, A must
    exercise B's authority rather than its own or it is a confused deputy -- and
    that chain repeats A by construction.

    It does not close the hole. The operator issues the last hop to a *second* key
    it controls: R->A->B->A'. Every subject is distinct, the walk is happy, and A
    is still an issuer entitled to approve A'. A DID costs nothing, so no rule
    about the shape of a chain separates a throwaway key from a second party.

    What replaced it is not a rule about the chain at all. D-107 has the grant
    *designate* its approvers, narrowing down the chain, so a key on the path is
    entitled to nothing unless the party above named it. `_approvers_entitled`
    still excludes the agent and any DID a *disclosure* ties to it; what it
    cannot check is whether a named key is the person the delegator believed.
    """

    def _looped_bundle(self) -> tuple[EventBundle, str]:
        """R -> AGENT, then AGENT -> SUB_AGENT -> AGENT, all attenuating."""
        g1 = grant(issuer=ROOT, subject=AGENT, max_depth=2, approval="required", parent=None)
        g2 = grant(
            issuer=AGENT,
            subject=SUB_AGENT,
            max_depth=1,
            approval="required",
            parent=g1.event_id,
            signers=[AGENT],
        )
        g3 = grant(
            issuer=SUB_AGENT,
            subject=AGENT,
            max_depth=0,
            approval="required",
            parent=g2.event_id,
            signers=[SUB_AGENT],
        )
        return EventBundle.from_envelopes([genesis(), g1, g2, g3]), g3.event_id

    def _decision(self, bundle: EventBundle):
        return check_permission(
            bundle,
            lineage=LINEAGE,
            agent=AGENT.did,
            namespace="technocore",
            resource="room:lobby",
            action="write",
            at=AT,
        )

    def test_the_loop_resolves_instead_of_failing(self) -> None:
        """R->A->B->A is a chain the walk must be able to follow.

        Karp's confused-deputy case needs it: A exercising B's authority is the
        correct behaviour, not an attack, and it puts A on the chain twice.
        """
        bundle, _ = self._looped_bundle()
        decision = self._decision(bundle)
        assert decision.reason is not ReasonCode.MALFORMED
        assert decision.path, "the walk produced no authorizing path at all"

    def test_the_agent_is_never_entitled_to_approve_itself(self) -> None:
        """The exclusion that survived, and the one that actually gets read.

        The agent may sit on its own path as an issuer now. What it must never do
        is end up in the set of parties entitled to consent on its behalf.
        """
        from lineageauth.approval import _approvers_entitled
        from lineageauth.fleet import resolve_fleets

        bundle, _ = self._looped_bundle()
        decision = self._decision(bundle)
        entitled = _approvers_entitled(
            decision, _grants_of(bundle), resolve_fleets(bundle, lineage=LINEAGE, at=AT)
        )
        assert AGENT.did not in entitled
        # Not vacuous: somebody is still entitled, or the check proves nothing.
        assert entitled

    def test_a_straight_chain_of_three_still_works(self) -> None:
        """The negative control. A rule that refuses loops must not refuse
        ordinary sub-delegation, which is the feature it sits next to."""
        g1 = grant(issuer=ROOT, subject=AGENT, max_depth=2, parent=None)
        g2 = grant(
            issuer=AGENT,
            subject=SUB_AGENT,
            max_depth=1,
            parent=g1.event_id,
            signers=[AGENT],
        )
        g3 = grant(
            issuer=SUB_AGENT,
            subject=STRANGER,
            max_depth=0,
            parent=g2.event_id,
            signers=[SUB_AGENT],
        )
        bundle = EventBundle.from_envelopes([genesis(), g1, g2, g3])
        decision = check_permission(
            bundle,
            lineage=LINEAGE,
            agent=STRANGER.did,
            namespace="technocore",
            resource="room:lobby",
            action="write",
            at=AT,
        )
        assert decision.allowed, decision.detail
        assert len(decision.path) == 3
