"""The impact graph.

docs/14 draws one line and holds it: demonstrable downstream use, not vanity
activity. So the tests are about the ways a use count lies -- the author reusing
their own work, one enthusiast reusing it ten times, a disclosed sibling
vouching -- and about the flags being heuristics rather than accusations.

This is also the layer that makes "discovery plus proof" mean something. A
directory can say a tool exists; only signed downstream use can say anybody
picked it up.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from lineageauth.actions import sha256_hex
from lineageauth.builders import (
    build_artifact_improve,
    build_artifact_receipt,
    build_artifact_register,
    build_artifact_reuse,
    build_fleet_bind,
    build_fleet_create,
    build_impact_attest,
    build_root_create,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError
from lineageauth.identifiers import derive_lineage_id
from lineageauth.impact import EdgeKind, Independence, collect_impact
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
AUTHOR = unsafe_signer(AGENT_1)
USER_A = unsafe_signer(RECOVERY_1)
USER_B = unsafe_signer(RECOVERY_2)
SIBLING = unsafe_signer(RECOVERY_3)
OPERATOR = unsafe_signer(OUTSIDER)
LINEAGE: str = derive_lineage_id(ROOT.did)

TOOL = sha256_hex(b"# awesome-technocore\n")
DOWNSTREAM = sha256_hex(b"a project that used the list")


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def produced(*, by: LocalSigner = AUTHOR, artifact: str = TOOL) -> list[Envelope]:
    return [
        sign_payload(
            build_artifact_register(
                lineage=LINEAGE, artifact_id=artifact, created_by=by.did, issued_at=AT
            ),
            [by],
        ),
        sign_payload(
            build_artifact_receipt(
                lineage=LINEAGE, artifact_id=artifact, worker=by.did, issued_at=AT
            ),
            [by],
        ),
    ]


def reuse(
    *,
    by: LocalSigner,
    used: str = TOOL,
    used_in: str = DOWNSTREAM,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_artifact_reuse(
        lineage=LINEAGE, reuser=by.did, used=used, used_in=used_in, issued_at=AT
    )
    return sign_payload(payload, signers or [by])


def impact_of(*envelopes: Envelope, artifact: str = TOOL, at: datetime = AT):
    return collect_impact(
        EventBundle.from_envelopes([genesis(), *envelopes]),
        lineage=LINEAGE,
        artifact_id=artifact,
        at=at,
    )


# ------------------------------------------------------------ what counts


class TestIndependentUse:
    def test_an_outsider_reusing_it_is_independent(self) -> None:
        found = impact_of(*produced(), reuse(by=USER_A))
        assert found.independent_reusers == (USER_A.did,)
        assert found.edges[0].independence is Independence.INDEPENDENT

    def test_the_author_reusing_their_own_work_is_not_adoption(self) -> None:
        found = impact_of(*produced(), reuse(by=AUTHOR))
        assert found.independent_reusers == ()
        assert found.self_reuses == 1

    def test_ten_reuses_by_one_key_are_one_adopter(self) -> None:
        """Edge count is the vanity number; distinct keys is the real one."""
        reuses = [reuse(by=USER_A, used_in=sha256_hex(f"project {n}".encode())) for n in range(10)]
        found = impact_of(*produced(), *reuses)
        assert len(found.edges) == 10
        assert found.independent_reusers == (USER_A.did,)

    def test_two_keys_are_two_adopters(self) -> None:
        found = impact_of(*produced(), reuse(by=USER_A), reuse(by=USER_B))
        assert len(found.independent_reusers) == 2

    def test_a_disclosed_sibling_is_its_own_tier(self) -> None:
        group = sign_payload(
            build_fleet_create(lineage=LINEAGE, controller=OPERATOR.did, name="acme", issued_at=AT),
            [OPERATOR],
        )
        bindings = [
            sign_payload(
                build_fleet_bind(
                    lineage=LINEAGE,
                    fleet=group.event_id,
                    controller=OPERATOR.did,
                    member=member.did,
                    issued_at=AT,
                ),
                [OPERATOR],
            )
            for member in (AUTHOR, SIBLING)
        ]
        found = impact_of(*produced(), group, *bindings, reuse(by=SIBLING))
        assert found.same_fleet_reusers == (SIBLING.did,)
        assert found.independent_reusers == ()

    def test_independent_means_no_disclosure_ties_them(self) -> None:
        # Not "these two are unrelated" -- an undisclosed fleet looks identical.
        found = impact_of(*produced(), reuse(by=USER_A))
        assert "weaker than knowing they are unrelated" in found.note


class TestSignatureBinding:
    def test_a_reuse_must_be_signed_by_the_reuser(self) -> None:
        """Otherwise an author could manufacture their own adoption."""
        forged = reuse(by=USER_A, signers=[AUTHOR])
        found = impact_of(*produced(), forged)
        assert found.edges == ()
        assert any("not signed by the reuser" in w for w in found.warnings)

    def test_an_improvement_must_be_signed_by_its_author(self) -> None:
        payload = build_artifact_improve(
            lineage=LINEAGE,
            author=USER_A.did,
            improves=TOOL,
            artifact=DOWNSTREAM,
            issued_at=AT,
        )
        found = impact_of(*produced(), sign_payload(payload, [AUTHOR]))
        assert found.edges == ()

    def test_an_improvement_by_an_outsider_is_independent(self) -> None:
        payload = build_artifact_improve(
            lineage=LINEAGE,
            author=USER_A.did,
            improves=TOOL,
            artifact=DOWNSTREAM,
            note="fixed the dead links",
            issued_at=AT,
        )
        found = impact_of(*produced(), sign_payload(payload, [USER_A]))
        assert found.edges[0].kind is EdgeKind.IMPROVED
        assert found.edges[0].independence is Independence.INDEPENDENT
        assert found.edges[0].note == "fixed the dead links"

    def test_a_third_party_observation_is_its_own_edge_kind(self) -> None:
        # Distinct from a reuse in who is speaking: the user's own statement
        # versus somebody else reporting that use happened.
        payload = build_impact_attest(
            lineage=LINEAGE,
            issuer=USER_B.did,
            subject_ref=TOOL,
            observed="seen vendored into three repositories",
            issued_at=AT,
        )
        found = impact_of(*produced(), sign_payload(payload, [USER_B]))
        assert found.edges[0].kind is EdgeKind.OBSERVED
        assert found.edges[0].actor == USER_B.did


# ------------------------------------------------------------ flags


class TestFlagsAreHeuristics:
    def test_reuse_concentrated_in_one_key_is_flagged(self) -> None:
        reuses = [reuse(by=USER_A, used_in=sha256_hex(f"p{n}".encode())) for n in range(3)]
        found = impact_of(*produced(), *reuses, reuse(by=USER_B))
        names = {f.name for f in found.flags}
        assert "reuse_concentration" in names

    def test_the_concentration_flag_does_not_accuse(self) -> None:
        reuses = [reuse(by=USER_A, used_in=sha256_hex(f"p{n}".encode())) for n in range(4)]
        found = impact_of(*produced(), *reuses)
        flag = next(f for f in found.flags if f.name == "reuse_concentration")
        assert "may be" in flag.detail and "innocent" in flag.detail

    def test_only_self_reuse_is_flagged(self) -> None:
        found = impact_of(*produced(), reuse(by=AUTHOR))
        flag = next(f for f in found.flags if f.name == "only_self_reuse")
        assert "is not evidence anyone else did" in flag.detail

    def test_only_disclosed_siblings_is_flagged(self) -> None:
        group = sign_payload(
            build_fleet_create(lineage=LINEAGE, controller=OPERATOR.did, name="acme", issued_at=AT),
            [OPERATOR],
        )
        bindings = [
            sign_payload(
                build_fleet_bind(
                    lineage=LINEAGE,
                    fleet=group.event_id,
                    controller=OPERATOR.did,
                    member=member.did,
                    issued_at=AT,
                ),
                [OPERATOR],
            )
            for member in (AUTHOR, SIBLING)
        ]
        found = impact_of(*produced(), group, *bindings, reuse(by=SIBLING))
        flag = next(f for f in found.flags if f.name == "only_disclosed_siblings")
        # And it names the asymmetry: this is only visible because someone said.
        assert "undisclosed equivalent would look independent" in flag.detail

    def test_an_artifact_with_no_signed_producer_is_flagged(self) -> None:
        # Independence is measured against the producers, so with none there is
        # nothing to measure against.
        found = impact_of(reuse(by=USER_A))
        assert any(f.name == "no_signed_producer" for f in found.flags)

    def test_the_note_says_flags_are_not_proof(self) -> None:
        found = impact_of(*produced(), reuse(by=AUTHOR))
        assert "never proof of wrongdoing" in found.note


# ------------------------------------------------------------ no score here


class TestNoScore:
    def test_the_module_computes_features_not_a_number(self) -> None:
        """docs/14: no magic score. The router owns ranking, and only one thing
        should, or there are two rankings to reconcile."""
        body = impact_of(*produced(), reuse(by=USER_A)).to_dict()

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
            for word in ("score", "rating", "rank", "trust", "impactValue"):
                assert word not in name.lower(), f"{name} reads as a score"

    def test_it_reports_keys_alongside_edges(self) -> None:
        # So a reader can see the difference between adoption and one
        # enthusiastic author without doing the arithmetic themselves.
        body = impact_of(*produced(), reuse(by=USER_A), reuse(by=USER_B)).to_dict()
        assert len(body["edges"]) == 2
        assert len(body["independentReusers"]) == 2


class TestPassportIntegration:
    def test_downstream_use_appears_in_the_passport(self) -> None:
        from lineageauth.passport import build_passport

        bundle = EventBundle.from_envelopes(
            [genesis(), *produced(), reuse(by=USER_A), reuse(by=USER_B)]
        )
        passport = build_passport(bundle, lineage=LINEAGE, did=AUTHOR.did, at=AT)
        body = passport.to_dict()["evidenceSupported"]["downstreamUse"]
        assert body[0]["artifactId"] == TOOL
        assert body[0]["independentReusers"] == 2

    def test_impact_left_the_not_included_list(self) -> None:
        from lineageauth.passport import build_passport

        passport = build_passport(
            EventBundle.from_envelopes([genesis()]), lineage=LINEAGE, did=AUTHOR.did, at=AT
        )
        body = passport.to_dict()
        assert {i["section"] for i in body["notIncluded"]} == set()
        # The key stays so "nothing missing" and "not tracked" stay distinct.
        assert "notIncluded" in body


class TestBuilderRules:
    def test_an_artifact_cannot_be_reused_in_itself(self) -> None:
        with pytest.raises(MalformedEventError, match="reused in itself"):
            build_artifact_reuse(
                lineage=LINEAGE, reuser=USER_A.did, used=TOOL, used_in=TOOL, issued_at=AT
            )

    def test_an_artifact_cannot_improve_on_itself(self) -> None:
        with pytest.raises(MalformedEventError, match="improve on itself"):
            build_artifact_improve(
                lineage=LINEAGE,
                author=USER_A.did,
                improves=TOOL,
                artifact=TOOL,
                issued_at=AT,
            )

    def test_references_must_be_content_ids(self) -> None:
        with pytest.raises(MalformedEventError, match="sha256"):
            build_artifact_reuse(
                lineage=LINEAGE,
                reuser=USER_A.did,
                used="the list",
                used_in=DOWNSTREAM,
                issued_at=AT,
            )

    def test_a_note_may_not_carry_control_characters(self) -> None:
        with pytest.raises(MalformedEventError, match="control characters"):
            build_artifact_reuse(
                lineage=LINEAGE,
                reuser=USER_A.did,
                used=TOOL,
                used_in=DOWNSTREAM,
                note="used\x1b[32m OFFICIALLY ENDORSED\x1b[0m",
                issued_at=AT,
            )
