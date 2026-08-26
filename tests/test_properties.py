"""Property-based tests.

docs/23_TESTING.md puts property tests at level 2. Example-based tests confirm
the cases already thought of; these search for the ones that were not.
"""

from __future__ import annotations

from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from lineageauth.canonical import b64u_decode, b64u_encode, compute_event_id, jcs, preimage
from lineageauth.crypto import verify_detached
from lineageauth.didkey import did_key_from_public_key, public_key_from_did_key
from lineageauth.envelope import Envelope
from lineageauth.identifiers import derive_lineage_id, genesis_did_from_lineage_id, is_lineage_id
from lineageauth.verify import verify_event
from tests.testkeys import ROOT_A, unsafe_signer

# JSON values a signed payload can legitimately contain.
json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
    st.text(max_size=40),
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=12), children, max_size=4),
    ),
    max_leaves=12,
)
json_objects = st.dictionaries(st.text(min_size=1, max_size=12), json_values, max_size=6)

ed25519_public_keys = st.binary(min_size=32, max_size=32)


class TestCanonicalizationProperties:
    @given(json_objects)
    def test_canonicalization_is_deterministic(self, payload: dict[str, Any]) -> None:
        assert jcs(payload) == jcs(payload)

    @given(json_objects)
    def test_key_order_never_affects_the_event_id(self, payload: dict[str, Any]) -> None:
        shuffled = dict(reversed(list(payload.items())))
        assert compute_event_id(payload) == compute_event_id(shuffled)

    @given(json_objects)
    def test_preimage_always_starts_with_the_domain_prefix(self, payload: dict[str, Any]) -> None:
        assert preimage(payload).startswith(b"lineageauth:event:v1\n")

    @given(json_objects, json_objects)
    def test_distinct_payloads_get_distinct_ids(
        self, left: dict[str, Any], right: dict[str, Any]
    ) -> None:
        if jcs(left) != jcs(right):
            assert compute_event_id(left) != compute_event_id(right)


class TestEncodingProperties:
    @given(st.binary(max_size=200))
    def test_base64url_roundtrips(self, data: bytes) -> None:
        assert b64u_decode(b64u_encode(data)) == data

    @given(st.binary(max_size=200))
    def test_base64url_encoding_stays_in_the_url_safe_alphabet(self, data: bytes) -> None:
        encoded = b64u_encode(data)
        assert set(encoded) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )

    @given(ed25519_public_keys)
    def test_did_key_roundtrips_for_any_32_byte_key(self, key: bytes) -> None:
        assert public_key_from_did_key(did_key_from_public_key(key)) == key

    @given(ed25519_public_keys)
    def test_lineage_identifier_roundtrips_to_its_genesis_root(self, key: bytes) -> None:
        did = did_key_from_public_key(key)
        lineage = derive_lineage_id(did)
        assert is_lineage_id(lineage)
        assert genesis_did_from_lineage_id(lineage) == did

    @given(ed25519_public_keys, ed25519_public_keys)
    def test_distinct_keys_never_share_a_lineage_identifier(
        self, left: bytes, right: bytes
    ) -> None:
        if left != right:
            assert derive_lineage_id(did_key_from_public_key(left)) != derive_lineage_id(
                did_key_from_public_key(right)
            )


class TestSignatureProperties:
    @given(st.binary(max_size=200))
    @settings(max_examples=25)
    def test_a_signature_verifies_over_exactly_the_bytes_it_signed(self, message: bytes) -> None:
        signer = unsafe_signer(ROOT_A)
        assert verify_detached(signer.public_key_bytes, message, signer.sign(message))

    @given(st.binary(max_size=200), st.binary(max_size=200))
    @settings(max_examples=25)
    def test_a_signature_does_not_verify_over_different_bytes(
        self, signed: bytes, other: bytes
    ) -> None:
        signer = unsafe_signer(ROOT_A)
        if signed != other:
            assert not verify_detached(signer.public_key_bytes, other, signer.sign(signed))

    @given(st.binary(max_size=200))
    @settings(max_examples=25)
    def test_another_key_never_verifies_a_signature(self, message: bytes) -> None:
        signer = unsafe_signer(ROOT_A)
        other_key = bytes(32)
        assert not verify_detached(other_key, message, signer.sign(message))

    @given(st.integers(min_value=0, max_value=63), st.integers(min_value=1, max_value=255))
    @settings(max_examples=40)
    def test_flipping_any_signature_byte_invalidates_it(self, index: int, delta: int) -> None:
        signer = unsafe_signer(ROOT_A)
        message = b"lineageauth property test"
        signature = bytearray(signer.sign(message))
        signature[index] = (signature[index] + delta) % 256
        assert not verify_detached(signer.public_key_bytes, message, bytes(signature))


class TestEnvelopeProperties:
    @given(json_objects)
    def test_editing_any_payload_field_invalidates_the_envelope(
        self, extra: dict[str, Any]
    ) -> None:
        from lineageauth.builders import build_root_create, sign_payload
        from tests.conftest import FIXED_ISSUED_AT

        signer = unsafe_signer(ROOT_A)
        payload = build_root_create(root_did=signer.did, issued_at=FIXED_ISSUED_AT)
        envelope = sign_payload(payload, [signer])

        tampered_payload = dict(payload) | extra
        if jcs(tampered_payload) == jcs(payload):
            return  # the "edit" was a no-op
        tampered = Envelope(payload=tampered_payload, proofs=list(envelope.proofs))
        assert not verify_event(tampered).integrity_ok
