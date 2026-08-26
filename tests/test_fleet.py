"""Fleet transparency.

docs/13 makes two demands that pull in opposite directions unless you are
careful. Disclosure has to be *useful* -- a sibling verifying your work is not
independent review. And disclosure must not be *penalised in a hidden way*, or
the honest operator pays for what the quiet one gets free.

The resolution these tests defend: a disclosed sibling stops counting as
independent, and never subtracts. The two are different rules and only one of
them is safe to publish.
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
    build_fleet_bind,
    build_fleet_create,
    build_fleet_unbind,
    build_root_create,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError
from lineageauth.fleet import resolve_fleets
from lineageauth.identifiers import derive_lineage_id
from lineageauth.passport import build_passport
from lineageauth.router import Query, search
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
OPERATOR = unsafe_signer(RECOVERY_1)
ALICE = unsafe_signer(AGENT_1)
SIBLING = unsafe_signer(RECOVERY_3)
OUTSIDE = unsafe_signer(RECOVERY_2)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE: str = derive_lineage_id(ROOT.did)

ARTIFACT = sha256_hex(b"alice's work")
SCOPE = {"namespace": "technocore", "resource": "room:lobby", "actions": ["write"]}


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def fleet(*, controller: LocalSigner = OPERATOR, signers: list[LocalSigner] | None = None):
    payload = build_fleet_create(
        lineage=LINEAGE, controller=controller.did, name="acme agents", issued_at=AT
    )
    return sign_payload(payload, signers or [controller])


def bind(
    *,
    group: Envelope,
    member: LocalSigner,
    controller: LocalSigner = OPERATOR,
    expires_at: datetime | None = None,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_fleet_bind(
        lineage=LINEAGE,
        fleet=group.event_id,
        controller=controller.did,
        member=member.did,
        role="worker",
        expires_at=expires_at,
        issued_at=AT,
    )
    return sign_payload(payload, signers or [controller])


def view_of(*envelopes: Envelope, at: datetime = AT):
    return resolve_fleets(
        EventBundle.from_envelopes([genesis(), *envelopes]), lineage=LINEAGE, at=at
    )


class TestDisclosure:
    def test_a_binding_puts_two_dids_in_one_fleet(self) -> None:
        group = fleet()
        view = view_of(group, bind(group=group, member=ALICE), bind(group=group, member=SIBLING))
        assert view.same_fleet(ALICE.did, SIBLING.did)
        assert set(view.members_of(group.event_id)) == {ALICE.did, SIBLING.did, OPERATOR.did}

    def test_the_controller_counts_as_part_of_its_own_fleet(self) -> None:
        group = fleet()
        view = view_of(group, bind(group=group, member=ALICE))
        assert view.same_fleet(ALICE.did, OPERATOR.did)

    def test_an_unrelated_did_is_not_in_the_fleet(self) -> None:
        group = fleet()
        view = view_of(group, bind(group=group, member=ALICE))
        assert not view.same_fleet(ALICE.did, OUTSIDE.did)

    def test_only_the_fleets_controller_may_bind_to_it(self) -> None:
        # Otherwise a stranger could tar an unrelated agent as part of their group.
        group = fleet(controller=OPERATOR)
        forged = bind(group=group, member=ALICE, controller=STRANGER, signers=[STRANGER])
        view = view_of(group, forged)
        assert view.bindings == ()
        assert any("controlled by" in w for w in view.warnings)

    def test_a_binding_must_be_signed_by_its_controller(self) -> None:
        group = fleet()
        forged = bind(group=group, member=ALICE, signers=[STRANGER])
        view = view_of(group, forged)
        assert view.bindings == ()

    def test_an_unbind_ends_the_relationship_going_forward(self) -> None:
        group = fleet()
        binding = bind(group=group, member=ALICE)
        ended = sign_payload(
            build_fleet_unbind(
                lineage=LINEAGE,
                bind=binding.event_id,
                controller=OPERATOR.did,
                issued_at=AT,
            ),
            [OPERATOR],
        )
        assert view_of(group, binding).same_fleet(ALICE.did, OPERATOR.did)
        assert not view_of(group, binding, ended).same_fleet(ALICE.did, OPERATOR.did)

    def test_only_the_controller_may_unbind(self) -> None:
        group = fleet()
        binding = bind(group=group, member=ALICE)
        forged = sign_payload(
            build_fleet_unbind(
                lineage=LINEAGE,
                bind=binding.event_id,
                controller=STRANGER.did,
                issued_at=AT,
            ),
            [STRANGER],
        )
        view = view_of(group, binding, forged)
        assert view.same_fleet(ALICE.did, OPERATOR.did)

    def test_an_expired_binding_lapses(self) -> None:
        group = fleet()
        binding = bind(group=group, member=ALICE, expires_at=AT + timedelta(hours=1))
        assert not view_of(group, binding, at=AT + timedelta(days=1)).bindings

    def test_a_binding_to_an_unknown_fleet_is_reported(self) -> None:
        payload = build_fleet_bind(
            lineage=LINEAGE,
            fleet="sha256:" + "a" * 64,
            controller=OPERATOR.did,
            member=ALICE.did,
            issued_at=AT,
        )
        view = view_of(sign_payload(payload, [OPERATOR]))
        assert view.bindings == ()
        assert any("no fleet.create" in w for w in view.warnings)


class TestWhatDisclosureDoesNotProve:
    def test_no_disclosure_is_not_independence(self) -> None:
        """An agent with no fleet has said nothing, not proved something."""
        view = view_of()
        assert view.fleets_of(ALICE.did) == ()
        assert not view.same_fleet(ALICE.did, OUTSIDE.did)
        assert "has said nothing rather than proved anything" in view.note or (
            "said nothing" in view.note
        )

    def test_the_note_refuses_the_stronger_claims(self) -> None:
        view = view_of()
        assert "not that one legal person holds both keys" in view.note
        assert "never that every DID an operator runs has been disclosed" in view.note


class TestDisclosureIsNotPenalised:
    """The rule that makes disclosure safe to make.

    A sibling stops *counting as independent*. It never subtracts. Otherwise the
    operator who discloses pays exactly what the operator who stays quiet saves,
    and nobody discloses again.
    """

    def _work(self, *, attester: LocalSigner) -> list[Envelope]:
        return [
            sign_payload(
                build_delegation_grant(
                    lineage=LINEAGE,
                    issuer=ROOT.did,
                    subject=ALICE.did,
                    epoch=0,
                    scopes=[SCOPE],
                    not_before=AT - timedelta(days=1),
                    expires_at=AT + timedelta(days=30),
                    max_depth=0,
                    issued_at=AT,
                ),
                [ROOT],
            ),
            sign_payload(
                build_artifact_register(
                    lineage=LINEAGE, artifact_id=ARTIFACT, created_by=ALICE.did, issued_at=AT
                ),
                [ALICE],
            ),
            sign_payload(
                build_artifact_receipt(
                    lineage=LINEAGE, artifact_id=ARTIFACT, worker=ALICE.did, issued_at=AT
                ),
                [ALICE],
            ),
            sign_payload(
                build_attestation(
                    lineage=LINEAGE,
                    issuer=attester.did,
                    subject_ref=ARTIFACT,
                    predicate="artifact.reviewed",
                    issued_at=AT,
                ),
                [attester],
            ),
        ]

    def _candidate(self, *envelopes: Envelope):
        found = search(
            EventBundle.from_envelopes([genesis(), *envelopes]),
            lineage=LINEAGE,
            query=Query(),
            at=AT,
        )
        return next(c for c in found.candidates if c.did == ALICE.did)

    def test_a_disclosed_sibling_does_not_count_as_independent(self) -> None:
        group = fleet()
        candidate = self._candidate(
            group,
            bind(group=group, member=ALICE),
            bind(group=group, member=SIBLING),
            *self._work(attester=SIBLING),
        )
        assert candidate.shape.independent_counterparties == 0
        assert candidate.shape.same_fleet_counterparties == (SIBLING.did,)

    def test_an_outsider_does_count(self) -> None:
        group = fleet()
        candidate = self._candidate(
            group, bind(group=group, member=ALICE), *self._work(attester=OUTSIDE)
        )
        assert candidate.shape.independent_counterparties == 1

    def test_disclosing_never_lowers_the_relevance(self) -> None:
        """The whole point. Compare the same evidence with and without a fleet.

        Disclosure removes a counterparty from the independent count, so the
        relevance may fall by what that counterparty was contributing -- but it
        must never fall *further*, which is what a penalty would do.
        """
        group = fleet()
        undisclosed = self._candidate(*self._work(attester=SIBLING))
        disclosed = self._candidate(
            group,
            bind(group=group, member=ALICE),
            bind(group=group, member=SIBLING),
            *self._work(attester=SIBLING),
        )
        weight = next(
            c.weight for c in undisclosed.contributions if c.name == "independent_counterparty"
        )
        # Exactly the uncounted counterparty, and not a point more.
        assert disclosed.relevance == undisclosed.relevance - weight

    def test_no_contribution_is_named_for_being_in_a_fleet(self) -> None:
        group = fleet()
        candidate = self._candidate(
            group,
            bind(group=group, member=ALICE),
            bind(group=group, member=SIBLING),
            *self._work(attester=SIBLING),
        )
        assert not any("fleet" in c.name for c in candidate.contributions)

    def test_the_note_says_disclosure_is_not_penalised(self) -> None:
        found = search(
            EventBundle.from_envelopes([genesis()]), lineage=LINEAGE, query=Query(), at=AT
        )
        assert "A disclosed fleet is not penalised" in found.note

    def test_the_passport_shows_disclosure_without_judging_it(self) -> None:
        group = fleet()
        passport = build_passport(
            EventBundle.from_envelopes([genesis(), group, bind(group=group, member=ALICE)]),
            lineage=LINEAGE,
            did=ALICE.did,
            at=AT,
        )
        body = passport.to_dict()["cryptographicallyLinked"]
        assert body["disclosedFleets"] == [group.event_id]
        assert "not that this agent is independent" in body["fleetDisclosureNote"]

    def test_fleet_bindings_left_the_not_included_list(self) -> None:
        passport = build_passport(
            EventBundle.from_envelopes([genesis()]), lineage=LINEAGE, did=ALICE.did, at=AT
        )
        sections = {item["section"] for item in passport.to_dict()["notIncluded"]}
        assert "fleetBindings" not in sections


class TestBuilderRules:
    def test_a_fleet_name_may_not_carry_control_characters(self) -> None:
        with pytest.raises(MalformedEventError, match="control characters"):
            build_fleet_create(
                lineage=LINEAGE,
                controller=OPERATOR.did,
                name="acme\x1b[32m VERIFIED\x1b[0m",
                issued_at=AT,
            )

    def test_a_binding_needs_a_real_fleet_reference(self) -> None:
        with pytest.raises(MalformedEventError, match=r"fleet\.create"):
            build_fleet_bind(
                lineage=LINEAGE,
                fleet="not-an-id",
                controller=OPERATOR.did,
                member=ALICE.did,
                issued_at=AT,
            )
