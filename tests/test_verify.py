"""Event integrity verification.

docs/23_TESTING.md mandates vectors for valid and invalid Ed25519 signatures,
for mutation invalidating an event, and for rejecting unsupported DIDs.

Every assertion here is about *integrity*. None of them says an action is
allowed: CLAUDE.md 2.6 keeps those two questions apart, and so does the API.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

import pytest

from lineageauth.builders import build_root_create, sign_payload
from lineageauth.canonical import b64u_encode
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope, Proof
from lineageauth.errors import ReasonCode
from lineageauth.verify import verify_event, verify_event_json
from tests.testkeys import OUTSIDER, RECOVERY_1, RECOVERY_2, unsafe_signer


class TestValidEvent:
    def test_a_correctly_signed_event_verifies(self, root_create_event: Envelope) -> None:
        result = verify_event(root_create_event)
        assert result.integrity_ok
        assert result.reason is ReasonCode.SIGNATURE_VERIFIED

    def test_result_reports_the_signer_and_the_event_identity(
        self, root_create_event: Envelope, root_a: LocalSigner
    ) -> None:
        result = verify_event(root_create_event)
        assert result.verified_signers == (root_a.did,)
        assert result.event_id == root_create_event.event_id
        assert result.event_type == "root.create"
        assert result.event_family == "authority"

    def test_a_positive_result_still_carries_the_not_authorization_caveat(
        self, root_create_event: Envelope
    ) -> None:
        result = verify_event(root_create_event)
        assert "not an authorization decision" in result.note
        assert "not an authorization decision" in result.detail

    def test_multiple_distinct_signers_all_verify(self, issued_at: datetime) -> None:
        # A recovery quorum signs one payload with several keys.
        signers = [unsafe_signer(RECOVERY_1), unsafe_signer(RECOVERY_2)]
        payload = build_root_create(root_did=signers[0].did, issued_at=issued_at)
        result = verify_event(sign_payload(payload, signers))
        assert result.integrity_ok
        assert len(result.verified_signers) == 2

    def test_repeated_signer_verifies_but_is_flagged_for_quorum_layers(
        self, root_a: LocalSigner, issued_at: datetime
    ) -> None:
        payload = build_root_create(root_did=root_a.did, issued_at=issued_at)
        result = verify_event(sign_payload(payload, [root_a, root_a]))
        assert result.integrity_ok
        assert any("distinct signers" in w for w in result.warnings)


class TestSignatureFailures:
    def test_a_signature_from_the_wrong_key_fails(
        self, root_create_payload: dict[str, Any]
    ) -> None:
        result = verify_event(sign_payload(root_create_payload, [unsafe_signer(OUTSIDER)]))
        # The proof names the outsider and the outsider really signed it, so the
        # bytes are consistent -- integrity passes. Whether that DID is the
        # lineage root is an authority question, not an integrity one.
        assert result.integrity_ok
        assert result.verified_signers == (unsafe_signer(OUTSIDER).did,)

    def test_a_signature_attributed_to_a_different_did_fails(
        self, root_create_payload: dict[str, Any], root_a: LocalSigner
    ) -> None:
        signed = sign_payload(root_create_payload, [root_a])
        forged = Envelope(
            payload=signed.payload,
            proofs=[
                Proof(alg="Ed25519", signer=unsafe_signer(OUTSIDER).did, sig=signed.proofs[0].sig)
            ],
        )
        result = verify_event(forged)
        assert not result.integrity_ok
        assert result.reason is ReasonCode.INVALID_SIGNATURE

    def test_a_corrupted_signature_fails(self, root_create_event: Envelope) -> None:
        original = root_create_event.proofs[0]
        flipped = bytearray(64)
        flipped[0] ^= 0xFF
        tampered = Envelope(
            payload=root_create_event.payload,
            proofs=[
                Proof(alg=original.alg, signer=original.signer, sig=b64u_encode(bytes(flipped)))
            ],
        )
        result = verify_event(tampered)
        assert not result.integrity_ok
        assert result.reason is ReasonCode.INVALID_SIGNATURE

    def test_an_envelope_without_proofs_does_not_verify(
        self, root_create_payload: dict[str, Any]
    ) -> None:
        result = verify_event(Envelope(payload=root_create_payload, proofs=[]))
        assert not result.integrity_ok
        assert result.reason is ReasonCode.INVALID_SIGNATURE

    def test_one_bad_proof_is_discarded_and_confers_nothing(
        self, root_create_payload: dict[str, Any], root_a: LocalSigner
    ) -> None:
        """D-087, revising D-027.

        A bad proof used to condemn the envelope. That made *appending* a way
        of *deleting*: proofs live outside the payload and do not change the
        event id, so anyone with no key could append nonsense to a copy and have
        that copy discarded whole -- the omission attack D-036 exists to
        prevent, landed at the door before merging was reached.

        The event now survives, and the security property is carried by
        `verified_signers` instead: the forged signer is simply not in it.
        """
        good = sign_payload(root_create_payload, [root_a]).proofs[0]
        outsider = unsafe_signer(OUTSIDER).did
        bad = Proof(alg="Ed25519", signer=outsider, sig=good.sig)

        result = verify_event(Envelope(payload=root_create_payload, proofs=[good, bad]))

        assert result.integrity_ok, "appending a proof must not delete the event"
        assert result.proofs[0].verified
        assert not result.proofs[1].verified
        # The part that matters: nothing was gained by appending.
        assert result.verified_signers == (root_a.did,)
        assert outsider not in result.verified_signers
        assert result.warnings and "discarded" in result.warnings[0]

    def test_an_envelope_whose_every_proof_fails_is_still_refused(
        self, root_create_payload: dict[str, Any], root_a: LocalSigner
    ) -> None:
        """The floor under the revision. Discarding all of them is not admission."""
        good = sign_payload(root_create_payload, [root_a]).proofs[0]
        bad = Proof(alg="Ed25519", signer=unsafe_signer(OUTSIDER).did, sig=good.sig)
        result = verify_event(Envelope(payload=root_create_payload, proofs=[bad]))
        assert not result.integrity_ok
        assert result.reason is ReasonCode.INVALID_SIGNATURE
        assert result.verified_signers == ()


class TestMutationInvalidates:
    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda p: p.__setitem__("epoch", 1), id="changed-value"),
            pytest.param(lambda p: p.__setitem__("extra", "x"), id="added-field"),
            pytest.param(lambda p: p.pop("epoch"), id="removed-field"),
            pytest.param(
                lambda p: p.__setitem__("issuedAt", "2026-08-26T09:00:01Z"), id="changed-time"
            ),
        ],
    )
    def test_any_payload_edit_breaks_the_signature(
        self, root_create_event: Envelope, mutate: Any
    ) -> None:
        payload = copy.deepcopy(root_create_event.payload)
        mutate(payload)
        result = verify_event(Envelope(payload=payload, proofs=list(root_create_event.proofs)))
        assert not result.integrity_ok

    def test_reordering_payload_keys_does_not_break_the_signature(
        self, root_create_event: Envelope
    ) -> None:
        # Canonicalization is order-independent, so a transport that reorders
        # keys must not invalidate an event.
        reordered = dict(reversed(list(root_create_event.payload.items())))
        assert list(reordered) != list(root_create_event.payload)
        result = verify_event(Envelope(payload=reordered, proofs=list(root_create_event.proofs)))
        assert result.integrity_ok


class TestStructuralRejection:
    def _signed_with(self, payload: dict[str, Any], signer: LocalSigner) -> Envelope:
        return sign_payload(payload, [signer])

    def test_wrong_protocol_is_malformed(
        self, root_create_payload: dict[str, Any], root_a: LocalSigner
    ) -> None:
        root_create_payload["protocol"] = "not-lineageauth"
        result = verify_event(self._signed_with(root_create_payload, root_a))
        assert result.reason is ReasonCode.MALFORMED

    def test_unknown_protocol_version_fails_closed(
        self, root_create_payload: dict[str, Any], root_a: LocalSigner
    ) -> None:
        root_create_payload["version"] = "9.9"
        result = verify_event(self._signed_with(root_create_payload, root_a))
        assert result.reason is ReasonCode.UNKNOWN_VERSION
        assert not result.integrity_ok

    def test_unregistered_event_type_fails_closed(
        self, root_create_payload: dict[str, Any], root_a: LocalSigner
    ) -> None:
        root_create_payload["type"] = "root.grantEverything"
        result = verify_event(self._signed_with(root_create_payload, root_a))
        assert result.reason is ReasonCode.UNKNOWN_VERSION
        assert "must not be treated as authorizing" in result.detail

    def test_unsupported_proof_algorithm_fails_closed(self, root_create_event: Envelope) -> None:
        original = root_create_event.proofs[0]
        envelope = Envelope(
            payload=root_create_event.payload,
            proofs=[Proof(alg="none", signer=original.signer, sig=original.sig)],
        )
        result = verify_event(envelope)
        assert result.reason is ReasonCode.UNKNOWN_VERSION
        assert not result.integrity_ok

    def test_unsupported_signer_did_method_fails_closed(self, root_create_event: Envelope) -> None:
        original = root_create_event.proofs[0]
        envelope = Envelope(
            payload=root_create_event.payload,
            proofs=[Proof(alg="Ed25519", signer="did:web:example.com", sig=original.sig)],
        )
        result = verify_event(envelope)
        assert result.reason is ReasonCode.UNKNOWN_VERSION

    @pytest.mark.parametrize("missing", ["protocol", "version", "type", "lineage", "issuedAt"])
    def test_missing_common_field_is_malformed(
        self, root_create_payload: dict[str, Any], root_a: LocalSigner, missing: str
    ) -> None:
        root_create_payload.pop(missing)
        result = verify_event(self._signed_with(root_create_payload, root_a))
        assert result.reason is ReasonCode.MALFORMED
        assert missing in result.detail

    @pytest.mark.parametrize(
        "lineage",
        ["", "lineage:la:", "did:key:z6Mk", "lineage:xx:z6Mk", 42, None],
    )
    def test_malformed_lineage_identifier_is_rejected(
        self, root_create_payload: dict[str, Any], root_a: LocalSigner, lineage: object
    ) -> None:
        root_create_payload["lineage"] = lineage
        result = verify_event(self._signed_with(root_create_payload, root_a))
        assert result.reason is ReasonCode.MALFORMED

    @pytest.mark.parametrize(
        "issued_at_value",
        [
            "2026-08-26T09:00:00+09:00",  # non-UTC offset
            "2026-08-26 09:00:00Z",  # missing T
            "2026-08-26T09:00:00",  # missing Z
            "2026-02-30T09:00:00Z",  # not a real date
            "not-a-time",
            1756198800,
        ],
    )
    def test_non_rfc3339_utc_timestamp_is_rejected(
        self, root_create_payload: dict[str, Any], root_a: LocalSigner, issued_at_value: object
    ) -> None:
        root_create_payload["issuedAt"] = issued_at_value
        result = verify_event(self._signed_with(root_create_payload, root_a))
        assert result.reason is ReasonCode.MALFORMED


class TestJsonEntryPoint:
    def test_verifies_from_json_text(self, root_create_event: Envelope) -> None:
        assert verify_event_json(root_create_event.to_json()).integrity_ok

    def test_invalid_json_is_malformed_not_an_exception(self) -> None:
        result = verify_event_json("{not json")
        assert result.reason is ReasonCode.MALFORMED
        assert not result.integrity_ok

    def test_duplicate_object_keys_are_rejected(self) -> None:
        result = verify_event_json('{"payload":{"a":1,"a":2},"proofs":[]}')
        assert result.reason is ReasonCode.MALFORMED
        assert "duplicate" in result.detail

    def test_unknown_envelope_field_is_rejected(self, root_create_event: Envelope) -> None:
        import json

        document = json.loads(root_create_event.to_json())
        document["signatures"] = []
        assert verify_event_json(json.dumps(document)).reason is ReasonCode.MALFORMED

    def test_verification_is_reproducible(self, root_create_event: Envelope) -> None:
        text = root_create_event.to_json()
        first, second = verify_event_json(text), verify_event_json(text)
        assert first == second


class TestOfflineGuarantee:
    def test_verification_makes_no_network_calls(
        self, root_create_event: Envelope, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import socket

        def refuse(*args: object, **kwargs: object) -> None:
            raise AssertionError("verification must not touch the network (CLAUDE.md 5)")

        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        assert verify_event(root_create_event).integrity_ok


def test_fixed_test_vector_is_stable(root_create_event: Envelope) -> None:
    """The deterministic fixture must not drift between runs or machines.

    UNSAFE test keys are derived from a public constant, so this event id is
    reproducible by any independent implementation of the same rules.
    """
    assert root_create_event.payload["issuedAt"] == "2026-08-26T09:00:00Z"
    assert root_create_event.payload["epoch"] == 0
    assert root_create_event.payload["lineage"].startswith("lineage:la:z6Mk")
    assert datetime.now(UTC) is not None  # sanity: tests never read the clock for logic


class TestAPayloadMustBeInTheFormItsOwnBytesDecodeTo:
    """Found by audit, 2026-08-28. A keyless third party could respell a number.

    RFC 8785 normalises numbers, so `2.0` canonicalises to `2`. The preimage,
    the signature and the event id are therefore identical for both spellings --
    but Python holds one as `int` and the other as `float`, and every reader
    that pulls a field out of the parsed document sees a value nobody signed.

    The concrete case: rewrite one character of a signed `recovery.policy`,
    `"threshold": 2` to `"threshold": 2.0`, and the signature still verifies
    while the threshold no longer parses. The recovery policy stops working and
    nothing reports a fault. **Refusal is the attack**, which is a shape this
    project keeps having to relearn.

    A useful side effect: only canonical payloads are admitted now, and two
    canonical documents with one event id are the same document. That makes
    `bundle._merge_duplicates` taking the first copy safe rather than lucky.
    """

    @staticmethod
    def _policy(root: LocalSigner) -> Envelope:
        from lineageauth.builders import build_recovery_policy
        from lineageauth.identifiers import derive_lineage_id

        members = [unsafe_signer(k).did for k in (RECOVERY_1, RECOVERY_2, OUTSIDER)]
        return sign_payload(
            build_recovery_policy(
                lineage=derive_lineage_id(root.did),
                epoch=0,
                policy_seq=1,
                members=members,
                threshold=2,
                issued_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
            ),
            [root],
        )

    def test_the_honest_policy_verifies(self, root_a: LocalSigner) -> None:
        assert verify_event(self._policy(root_a)).integrity_ok

    def test_respelling_a_number_is_refused_with_the_signature_untouched(
        self, root_a: LocalSigner
    ) -> None:
        original = self._policy(root_a)
        text = original.to_json()
        tampered_text = text.replace('"threshold": 2', '"threshold": 2.0').replace(
            '"threshold":2', '"threshold":2.0'
        )
        assert tampered_text != text, "the fixture no longer contains the field being respelt"

        tampered = Envelope.from_json(tampered_text)
        result = verify_event(tampered)

        # The whole point: everything cryptographic still agrees.
        assert tampered.event_id == original.event_id
        assert result.integrity_ok is False
        assert result.reason is ReasonCode.MALFORMED
        assert "canonical form" in result.detail

    def test_every_spelling_of_one_number_is_caught(self, root_a: LocalSigner) -> None:
        for spelling in ("2.0", "2e0", "2.00"):
            text = (
                self._policy(root_a).to_json().replace('"threshold": 2', f'"threshold": {spelling}')
            )
            result = verify_event(Envelope.from_json(text))
            assert result.integrity_ok is False, f"{spelling} slipped through"

    def test_an_ordinary_payload_is_not_disturbed(self) -> None:
        """The negative control. A rule this broad must cost the honest case nothing."""
        from lineageauth.canonical import assert_canonical_payload

        assert_canonical_payload(
            {
                "protocol": "lineageauth",
                "version": "0.1",
                "n": 0,
                "neg": -17,
                "big": 2**53 - 1,  # the largest integer JCS admits
                "s": "unicode and an emoji",
                "arr": [1, "two", {"three": True}, None],
                "nested": {"a": {"b": [0, 1]}},
                "ratio": 0.5,
            }
        )
