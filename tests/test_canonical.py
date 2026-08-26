"""Canonicalization, preimage, and event id.

docs/23_TESTING.md lists JCS ordering, Unicode, and event id among the
mandatory core vectors. The golden digests below were produced outside this
implementation (`printf … | sha256sum`), so they check the whole pipeline rather
than restating what the code already does.
"""

from __future__ import annotations

import hashlib

import pytest

from lineageauth.canonical import (
    EVENT_PREIMAGE_PREFIX,
    b64u_decode,
    b64u_encode,
    compute_event_id,
    is_event_id,
    jcs,
    preimage,
    sha256_content_id,
)
from lineageauth.errors import MalformedEventError


class TestCanonicalJson:
    def test_keys_are_sorted_regardless_of_insertion_order(self) -> None:
        assert jcs({"b": "x", "a": 1}) == b'{"a":1,"b":"x"}'
        assert jcs({"a": 1, "b": "x"}) == jcs({"b": "x", "a": 1})

    def test_no_insignificant_whitespace(self) -> None:
        assert b" " not in jcs({"a": [1, 2], "b": {"c": 3}})

    def test_non_ascii_is_emitted_as_utf8_not_escaped(self) -> None:
        # JCS escapes only what JSON requires; it does not \\u-escape by default.
        assert jcs({"key": "café"}) == '{"key":"café"}'.encode()

    def test_nested_objects_sort_at_every_level(self) -> None:
        assert jcs({"z": {"b": 1, "a": 2}}) == b'{"z":{"a":2,"b":1}}'

    def test_array_order_is_significant(self) -> None:
        assert jcs({"a": [1, 2]}) != jcs({"a": [2, 1]})

    def test_rejects_values_json_cannot_canonicalize(self) -> None:
        with pytest.raises(MalformedEventError):
            jcs({"a": float("nan")})
        with pytest.raises(MalformedEventError):
            jcs({"a": float("inf")})


class TestPreimage:
    def test_prefix_is_pinned(self) -> None:
        assert EVENT_PREIMAGE_PREFIX == b"lineageauth:event:v1\n"

    def test_preimage_is_prefix_then_canonical_bytes(self) -> None:
        payload = {"b": "x", "a": 1}
        assert preimage(payload) == EVENT_PREIMAGE_PREFIX + jcs(payload)

    def test_payload_must_be_an_object(self) -> None:
        for not_an_object in ([1, 2], "string", 7, None):
            with pytest.raises(MalformedEventError):
                preimage(not_an_object)


class TestEventId:
    # Independently computed: printf 'lineageauth:event:v1\n{"a":1,"b":"x"}' | sha256sum
    GOLDEN_SIMPLE = "sha256:1bfbc4628eddebf2a2d3db3662b693d50e5fb89d3f41d496118d23d38227df1d"
    GOLDEN_UNICODE = "sha256:9c2e92d14ccf62a27ad28336a6577b0434e64255b1d53e38ce5f714b0cab5a37"

    def test_golden_ascii_vector(self) -> None:
        assert compute_event_id({"b": "x", "a": 1}) == self.GOLDEN_SIMPLE

    def test_golden_unicode_vector(self) -> None:
        assert compute_event_id({"key": "café", "emoji": "\U0001f511"}) == self.GOLDEN_UNICODE

    def test_id_is_lowercase_hex_with_sha256_prefix(self) -> None:
        event_id = compute_event_id({"a": 1})
        assert is_event_id(event_id)
        assert event_id.startswith("sha256:")
        assert event_id[7:] == event_id[7:].lower()
        assert len(event_id[7:]) == 64

    def test_any_field_change_changes_the_id(self) -> None:
        base = compute_event_id({"a": 1, "b": "x"})
        assert compute_event_id({"a": 2, "b": "x"}) != base
        assert compute_event_id({"a": 1, "b": "y"}) != base
        assert compute_event_id({"a": 1, "b": "x", "c": None}) != base

    def test_reordering_does_not_change_the_id(self) -> None:
        assert compute_event_id({"a": 1, "b": "x"}) == compute_event_id({"b": "x", "a": 1})

    @pytest.mark.parametrize(
        "value",
        [
            "sha256:" + "A" * 64,  # uppercase
            "sha256:" + "a" * 63,  # too short
            "sha256:" + "a" * 65,  # too long
            "sha1:" + "a" * 64,  # wrong algorithm
            "a" * 64,  # no prefix
            None,
            42,
        ],
    )
    def test_rejects_malformed_event_ids(self, value: object) -> None:
        assert not is_event_id(value)


class TestContentId:
    def test_matches_plain_sha256_of_the_bytes(self) -> None:
        data = b"artifact bytes"
        assert sha256_content_id(data) == "sha256:" + hashlib.sha256(data).hexdigest()

    def test_empty_input_is_addressable(self) -> None:
        assert is_event_id(sha256_content_id(b""))


class TestBase64Url:
    def test_roundtrip(self) -> None:
        for data in (b"", b"\x00", b"\xff" * 64, bytes(range(256))):
            assert b64u_decode(b64u_encode(data)) == data

    def test_encoding_is_unpadded(self) -> None:
        assert "=" not in b64u_encode(b"\x00")

    def test_uses_the_url_safe_alphabet(self) -> None:
        encoded = b64u_encode(bytes(range(256)))
        assert "+" not in encoded
        assert "/" not in encoded

    def test_rejects_padded_input(self) -> None:
        with pytest.raises(MalformedEventError, match="must not be padded"):
            b64u_decode("AA==")

    def test_rejects_standard_base64_alphabet(self) -> None:
        with pytest.raises(MalformedEventError, match="outside the alphabet"):
            b64u_decode("a+b/c")

    def test_rejects_non_canonical_trailing_bits(self) -> None:
        # 'AB' and 'AC' both decode to b'\x00' under a lenient decoder; only one
        # is the canonical encoding. Two spellings of one signature would let an
        # attacker re-encode a proof without invalidating it.
        assert b64u_encode(b"\x00") == "AA"
        with pytest.raises(MalformedEventError, match="not canonically encoded"):
            b64u_decode("AB")

    def test_rejects_non_string_input(self) -> None:
        with pytest.raises(MalformedEventError):
            b64u_decode(b"AA")  # type: ignore[arg-type]
