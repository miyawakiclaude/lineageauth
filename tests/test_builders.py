"""Phase 1 draft builders.

The builders enforce the structural rules a verifier would otherwise have to
discover late: distinct recovery members, a threshold inside range, an ordering
signal on policy replacement, and a succession that actually moves the root.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from lineageauth.builders import (
    NORMAL_SUCCESSION,
    RECOVERY_SUCCESSION,
    build_recovery_policy,
    build_root_create,
    build_root_succession,
    sign_payload,
)
from lineageauth.crypto import LocalSigner
from lineageauth.didkey import UnsupportedDidMethodError
from lineageauth.errors import MalformedEventError
from lineageauth.identifiers import derive_lineage_id
from lineageauth.verify import verify_event
from tests.testkeys import (
    RECOVERY_1,
    RECOVERY_2,
    RECOVERY_3,
    ROOT_B,
    unsafe_signer,
)

AT = datetime(2026, 8, 26, 9, 0, 0, tzinfo=UTC)


class TestRootCreate:
    def test_opens_the_lineage_at_epoch_zero(self, root_a: LocalSigner) -> None:
        payload = build_root_create(root_did=root_a.did, issued_at=AT)
        assert payload["epoch"] == 0
        assert payload["root"] == root_a.did

    def test_lineage_identifier_is_derived_from_the_genesis_root(self, root_a: LocalSigner) -> None:
        payload = build_root_create(root_did=root_a.did, issued_at=AT)
        assert payload["lineage"] == derive_lineage_id(root_a.did)

    def test_the_result_verifies_once_signed(self, root_a: LocalSigner) -> None:
        payload = build_root_create(root_did=root_a.did, issued_at=AT)
        assert verify_event(sign_payload(payload, [root_a])).integrity_ok

    def test_rejects_an_unsupported_root_did(self) -> None:
        with pytest.raises(UnsupportedDidMethodError, match="only did:key"):
            build_root_create(root_did="did:web:example.com", issued_at=AT)

    def test_requires_an_aware_timestamp(self, root_a: LocalSigner) -> None:
        with pytest.raises(MalformedEventError, match="naive datetime"):
            build_root_create(root_did=root_a.did, issued_at=datetime(2026, 8, 26, 9, 0, 0))

    def test_timestamps_are_normalised_to_utc(self, root_a: LocalSigner) -> None:
        from datetime import timedelta, timezone

        jst = timezone(timedelta(hours=9))
        payload = build_root_create(
            root_did=root_a.did, issued_at=datetime(2026, 8, 26, 18, 0, 0, tzinfo=jst)
        )
        assert payload["issuedAt"] == "2026-08-26T09:00:00Z"


class TestRecoveryPolicy:
    def members(self) -> list[str]:
        return [unsafe_signer(label).did for label in (RECOVERY_1, RECOVERY_2, RECOVERY_3)]

    def test_builds_the_recommended_two_of_three_policy(self, root_a: LocalSigner) -> None:
        payload = build_recovery_policy(
            lineage=derive_lineage_id(root_a.did),
            epoch=0,
            policy_seq=1,
            members=self.members(),
            threshold=2,
            issued_at=AT,
        )
        assert payload["threshold"] == 2
        assert len(payload["members"]) == 3

    def test_members_are_stored_sorted_for_stable_canonical_bytes(
        self, root_a: LocalSigner
    ) -> None:
        members = self.members()
        forward = build_recovery_policy(
            lineage=derive_lineage_id(root_a.did),
            epoch=0,
            policy_seq=1,
            members=members,
            threshold=2,
            issued_at=AT,
        )
        reversed_input = build_recovery_policy(
            lineage=derive_lineage_id(root_a.did),
            epoch=0,
            policy_seq=1,
            members=list(reversed(members)),
            threshold=2,
            issued_at=AT,
        )
        assert forward == reversed_input

    def test_rejects_duplicate_members(self, root_a: LocalSigner) -> None:
        duplicate = unsafe_signer(RECOVERY_1).did
        with pytest.raises(MalformedEventError, match="distinct"):
            build_recovery_policy(
                lineage=derive_lineage_id(root_a.did),
                epoch=0,
                policy_seq=1,
                members=[duplicate, duplicate],
                threshold=1,
                issued_at=AT,
            )

    @pytest.mark.parametrize("threshold", [0, -1, 4])
    def test_rejects_an_unsatisfiable_or_meaningless_threshold(
        self, root_a: LocalSigner, threshold: int
    ) -> None:
        with pytest.raises(MalformedEventError, match="threshold"):
            build_recovery_policy(
                lineage=derive_lineage_id(root_a.did),
                epoch=0,
                policy_seq=1,
                members=self.members(),
                threshold=threshold,
                issued_at=AT,
            )

    def test_rejects_an_empty_member_set(self, root_a: LocalSigner) -> None:
        with pytest.raises(MalformedEventError, match="at least one member"):
            build_recovery_policy(
                lineage=derive_lineage_id(root_a.did),
                epoch=0,
                policy_seq=1,
                members=[],
                threshold=1,
                issued_at=AT,
            )

    def test_a_replacement_policy_must_reference_what_it_replaces(
        self, root_a: LocalSigner
    ) -> None:
        # docs/05: unordered competing policies must fail closed rather than be
        # resolved by timestamp, so the ordering link is mandatory.
        with pytest.raises(MalformedEventError, match="must reference the policy"):
            build_recovery_policy(
                lineage=derive_lineage_id(root_a.did),
                epoch=0,
                policy_seq=2,
                members=self.members(),
                threshold=2,
                issued_at=AT,
            )

    def test_a_replacement_policy_with_a_reference_is_accepted(self, root_a: LocalSigner) -> None:
        payload = build_recovery_policy(
            lineage=derive_lineage_id(root_a.did),
            epoch=0,
            policy_seq=2,
            members=self.members(),
            threshold=2,
            previous_policy="sha256:" + "0" * 64,
            issued_at=AT,
        )
        assert payload["policySeq"] == 2
        assert payload["previousPolicy"].startswith("sha256:")


class TestRootSuccession:
    def test_normal_succession_increments_the_epoch(self, root_a: LocalSigner) -> None:
        payload = build_root_succession(
            lineage=derive_lineage_id(root_a.did),
            from_root=root_a.did,
            to_root=unsafe_signer(ROOT_B).did,
            from_epoch=0,
            mode=NORMAL_SUCCESSION,
            issued_at=AT,
        )
        assert (payload["fromEpoch"], payload["toEpoch"]) == (0, 1)

    def test_recovery_succession_must_name_the_policy_it_satisfies(
        self, root_a: LocalSigner
    ) -> None:
        with pytest.raises(MalformedEventError, match="reference the recovery policy"):
            build_root_succession(
                lineage=derive_lineage_id(root_a.did),
                from_root=root_a.did,
                to_root=unsafe_signer(ROOT_B).did,
                from_epoch=0,
                mode=RECOVERY_SUCCESSION,
                issued_at=AT,
            )

    def test_recovery_succession_with_a_policy_reference_is_accepted(
        self, root_a: LocalSigner
    ) -> None:
        payload = build_root_succession(
            lineage=derive_lineage_id(root_a.did),
            from_root=root_a.did,
            to_root=unsafe_signer(ROOT_B).did,
            from_epoch=0,
            mode=RECOVERY_SUCCESSION,
            recovery_policy_ref="sha256:" + "0" * 64,
            issued_at=AT,
        )
        assert payload["mode"] == RECOVERY_SUCCESSION
        assert payload["recoveryPolicyRef"].startswith("sha256:")

    def test_rejects_a_succession_that_does_not_move_the_root(self, root_a: LocalSigner) -> None:
        with pytest.raises(MalformedEventError, match="different DID"):
            build_root_succession(
                lineage=derive_lineage_id(root_a.did),
                from_root=root_a.did,
                to_root=root_a.did,
                from_epoch=0,
                mode=NORMAL_SUCCESSION,
                issued_at=AT,
            )

    def test_rejects_an_unknown_mode(self, root_a: LocalSigner) -> None:
        with pytest.raises(MalformedEventError, match="mode must be"):
            build_root_succession(
                lineage=derive_lineage_id(root_a.did),
                from_root=root_a.did,
                to_root=unsafe_signer(ROOT_B).did,
                from_epoch=0,
                mode="emergency",
                issued_at=AT,
            )

    def test_rejects_a_negative_epoch(self, root_a: LocalSigner) -> None:
        with pytest.raises(MalformedEventError, match="fromEpoch"):
            build_root_succession(
                lineage=derive_lineage_id(root_a.did),
                from_root=root_a.did,
                to_root=unsafe_signer(ROOT_B).did,
                from_epoch=-1,
                mode=NORMAL_SUCCESSION,
                issued_at=AT,
            )


class TestSigning:
    def test_requires_at_least_one_signer(self, root_create_payload: dict[str, object]) -> None:
        with pytest.raises(MalformedEventError, match="at least one signer"):
            sign_payload(root_create_payload, [])

    def test_signing_does_not_modify_the_payload(
        self, root_create_payload: dict[str, object], root_a: LocalSigner
    ) -> None:
        before = dict(root_create_payload)
        sign_payload(root_create_payload, [root_a])
        assert root_create_payload == before

    def test_signer_repr_never_leaks_key_material(self, root_a: LocalSigner) -> None:
        rendered = repr(root_a)
        assert root_a.did in rendered
        assert "seed" not in rendered.lower()
        assert "private" not in rendered.lower()
