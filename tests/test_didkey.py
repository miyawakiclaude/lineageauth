"""Ed25519 `did:key` handling.

docs/23_TESTING.md requires that an unsupported DID be rejected. The published
vectors below come from the W3C did:key specification, so they exercise real
encodings rather than ones this implementation produced itself.
"""

from __future__ import annotations

import pytest

from lineageauth.didkey import (
    ED25519_PUBLIC_KEY_LENGTH,
    DidKeyError,
    UnsupportedDidMethodError,
    did_key_from_public_key,
    is_did_key,
    public_key_from_did_key,
)

# W3C did:key test vectors.
ED25519_VECTOR = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
X25519_VECTOR = "did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
SECP256K1_VECTOR = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
P256_VECTOR = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"


class TestDecoding:
    def test_decodes_the_published_ed25519_vector(self) -> None:
        key = public_key_from_did_key(ED25519_VECTOR)
        assert len(key) == ED25519_PUBLIC_KEY_LENGTH

    def test_reencoding_the_published_vector_reproduces_it(self) -> None:
        key = public_key_from_did_key(ED25519_VECTOR)
        assert did_key_from_public_key(key) == ED25519_VECTOR

    def test_ed25519_dids_carry_the_expected_multicodec_prefix(self) -> None:
        assert did_key_from_public_key(bytes(32)).startswith("did:key:z6Mk")


class TestUnsupportedKeyTypes:
    @pytest.mark.parametrize(
        ("did", "described"),
        [
            (X25519_VECTOR, "X25519"),
            (SECP256K1_VECTOR, "secp256k1"),
            (P256_VECTOR, "P-256"),
        ],
    )
    def test_other_key_types_are_rejected_not_ignored(self, did: str, described: str) -> None:
        with pytest.raises(UnsupportedDidMethodError, match=described):
            public_key_from_did_key(did)
        assert not is_did_key(did)

    def test_other_did_methods_are_rejected(self) -> None:
        with pytest.raises(UnsupportedDidMethodError, match="only did:key"):
            public_key_from_did_key("did:web:example.com")

    def test_a_non_did_string_is_rejected(self) -> None:
        assert not is_did_key("https://example.com/agent")
        assert not is_did_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


class TestMalformedInput:
    @pytest.mark.parametrize(
        "did",
        [
            f"{ED25519_VECTOR}#{ED25519_VECTOR.removeprefix('did:key:')}",  # DID URL fragment
            f"{ED25519_VECTOR}?service=agent",
            f"{ED25519_VECTOR}/path",
            f"{ED25519_VECTOR};param=1",
        ],
    )
    def test_did_urls_are_not_accepted_as_signer_identities(self, did: str) -> None:
        # did:key:zAAA#zBBB must never be silently read as did:key:zAAA.
        with pytest.raises(DidKeyError, match="DID URL syntax"):
            public_key_from_did_key(did)

    def test_requires_multibase_base58btc(self) -> None:
        with pytest.raises(DidKeyError, match="base58btc"):
            public_key_from_did_key("did:key:f6Mkhaxg")

    def test_rejects_empty_identifier(self) -> None:
        with pytest.raises(DidKeyError):
            public_key_from_did_key("did:key:")
        with pytest.raises(DidKeyError, match="empty"):
            public_key_from_did_key("did:key:z")

    def test_rejects_invalid_base58(self) -> None:
        with pytest.raises(DidKeyError, match="base58btc"):
            public_key_from_did_key("did:key:z0OIl")  # 0, O, I, l are not in the alphabet

    def test_rejects_truncated_key_bytes(self) -> None:
        import base58

        truncated = base58.b58encode(b"\xed\x01" + bytes(31)).decode()
        with pytest.raises(DidKeyError, match="32 key bytes"):
            public_key_from_did_key(f"did:key:z{truncated}")

    def test_rejects_non_string_input(self) -> None:
        for value in (None, 42, b"did:key:z6Mk", ["did:key:z6Mk"]):
            with pytest.raises(DidKeyError, match="must be a string"):
                public_key_from_did_key(value)


class TestEncoding:
    def test_roundtrip_for_every_byte_pattern(self) -> None:
        for key in (bytes(32), b"\xff" * 32, bytes(range(32))):
            assert public_key_from_did_key(did_key_from_public_key(key)) == key

    @pytest.mark.parametrize("length", [0, 31, 33, 64])
    def test_rejects_wrong_public_key_length(self, length: int) -> None:
        with pytest.raises(DidKeyError, match="must be 32 bytes"):
            did_key_from_public_key(bytes(length))

    def test_distinct_keys_produce_distinct_dids(self) -> None:
        assert did_key_from_public_key(bytes(32)) != did_key_from_public_key(b"\x01" + bytes(31))
