"""The Technocore adapter.

docs/23_TESTING.md pins three things for this integration: GET-write
classification works, there are zero live writes in the test suite, and
untrusted URLs are inert. All three are asserted below, the second by refusing
the network outright rather than by trusting that nobody typed a URL.
"""

from __future__ import annotations

import json
import socket
from urllib.parse import quote

import pytest

from lineageauth.adapters.technocore import (
    MAX_MESSAGE_CHARS,
    Consequence,
    assert_safe_to_read,
    build_signed_message,
    classify,
    format_announcement,
    is_write,
    note_signing_bytes,
    prepare_signed_message,
    sweep,
)
from lineageauth.crypto import verify_detached
from lineageauth.errors import MalformedEventError
from tests.testkeys import AGENT_1, unsafe_signer

AGENT = unsafe_signer(AGENT_1)
ORIGIN = "https://technocore.chat"


# ------------------------------------------------------------ no live network


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse the network for every test in this file.

    docs/18: "Live network prohibited in normal test suite." Asserting it beats
    assuming it -- an adapter that quietly grew a fetch would fail here rather
    than reach a service that belongs to somebody else.
    """

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the Technocore adapter must not touch the network in tests")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


# ------------------------------------------------------------ classification


class TestWritesReachableByGet:
    """The rule that makes this table necessary: a GET here can be a write."""

    @pytest.mark.parametrize(
        "path",
        [
            "/r/lobby/say/nick/hello",
            "/r/lobby/say-signed/did:key:z6Mk/sig/7/hello",
            "/kv/ns/key/set/value",
            "/kv/room-owners/d-lobby/set-signed/did:key:z6Mk/sig/7/did:key:z6Mk",
        ],
    )
    def test_a_plain_get_can_be_a_write(self, path: str) -> None:
        assert is_write(f"{ORIGIN}{path}")
        assert classify(f"{ORIGIN}{path}").consequence is Consequence.WRITE
        assert not classify(f"{ORIGIN}{path}").safe_to_call_automatically

    @pytest.mark.parametrize(
        "path",
        [
            "/r/lobby",
            "/r/events",
            "/kv/ns/key",
            "/kv/ns",
            "/rooms",
            "/openapi.json",
            "/.well-known/agent.json",
            "/healthz",
            "/llms.txt",
            "/auth.md",
            "/",
        ],
    )
    def test_documented_reads_are_reads(self, path: str) -> None:
        assert classify(f"{ORIGIN}{path}").consequence is Consequence.READ
        assert assert_safe_to_read(f"{ORIGIN}{path}")

    def test_a_write_route_is_not_shadowed_by_the_room_read_pattern(self) -> None:
        # `/r/<room>` would match `/r/lobby/say/...` under a looser pattern, and
        # the result would be a write classified as a read.
        assert classify(f"{ORIGIN}/r/lobby/say/nick/hi").consequence is Consequence.WRITE
        assert classify(f"{ORIGIN}/r/lobby").consequence is Consequence.READ

    def test_post_to_a_room_is_the_same_write_by_another_spelling(self) -> None:
        assert classify(f"{ORIGIN}/r/lobby", method="POST").consequence is Consequence.UNKNOWN


class TestUnknownIsUnsafe:
    def test_an_unrecognised_route_is_unknown_not_read(self) -> None:
        # Upstream can add routes at any time, and the one added while nobody is
        # looking must fail closed.
        result = classify(f"{ORIGIN}/r/lobby/some-new-verb/x")
        assert result.consequence is Consequence.UNKNOWN
        assert not result.safe_to_call_automatically

    def test_assert_safe_to_read_refuses_an_unknown_route(self) -> None:
        with pytest.raises(MalformedEventError, match="refusing to fetch"):
            assert_safe_to_read(f"{ORIGIN}/r/lobby/some-new-verb/x")

    def test_assert_safe_to_read_refuses_a_write(self) -> None:
        with pytest.raises(MalformedEventError, match="refusing to fetch"):
            assert_safe_to_read(f"{ORIGIN}/r/lobby/say/nick/hi")

    @pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "get"])
    def test_an_undocumented_method_is_unknown(self, method: str) -> None:
        assert classify(f"{ORIGIN}/r/lobby", method=method).consequence is Consequence.UNKNOWN


class TestUntrustedUrlsAreInert:
    """A URL that arrives inside a message is data, never an instruction."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example/r/lobby",
            "http://technocore.chat/r/lobby",  # not https
            "https://technocore.chat.evil.example/r/lobby",
            "https://technocore.chat:8443/r/lobby",
            "https://user@evil.example/r/lobby",
            "file:///etc/passwd",
            "ftp://technocore.chat/r/lobby",
            "//technocore.chat/r/lobby",
        ],
    )
    def test_off_origin_urls_are_never_classified_as_safe(self, url: str) -> None:
        result = classify(url)
        assert result.consequence is Consequence.UNKNOWN
        assert not result.safe_to_call_automatically

    def test_a_lookalike_host_does_not_pass(self) -> None:
        assert not classify(
            "https://technocore.chat.attacker.test/rooms"
        ).safe_to_call_automatically

    def test_an_empty_url_is_refused(self) -> None:
        with pytest.raises(MalformedEventError):
            classify("")


# ------------------------------------------------------------ the sweep


class TestSingleLineSweep:
    @pytest.mark.parametrize(
        "raw",
        [
            "a\nb",
            "a\rb",
            "a\tb",
            "a\x00b",
            "a\x1bb",  # escape: the start of an ANSI sequence
            "a\x7fb",
            "a‍b",  # zero-width joiner
            "a‮b",  # right-to-left override
            "a﻿b",  # byte order mark
            "a­b",  # soft hyphen
        ],
    )
    def test_invisibles_become_spaces(self, raw: str) -> None:
        assert sweep(raw) == "a b"

    def test_visible_text_is_untouched(self) -> None:
        for text in ("hello", "こんにちは", "🔑 key", "a  b", "café"):
            assert sweep(text) == text

    def test_the_sweep_is_one_for_one(self) -> None:
        # A replacement, not a normalisation: runs are not collapsed, so lengths
        # match and an offset into the original still means something.
        raw = "a\n\n\nb"
        assert sweep(raw) == "a   b"
        assert len(sweep(raw)) == len(raw)

    def test_the_sweep_is_idempotent(self) -> None:
        raw = "a\nb‍c"
        assert sweep(sweep(raw)) == sweep(raw)

    def test_an_unpaired_surrogate_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="surrogate"):
            sweep("a\ud800b")


class TestSignedPreimage:
    def test_the_preimage_is_room_nonce_text(self) -> None:
        message = build_signed_message(room="lobby", nonce=7, text="hello")
        assert message.signing_bytes == b"lobby|7|hello"

    def test_the_preimage_uses_the_swept_text(self) -> None:
        """Upstream signs what gets stored, not what the caller typed."""
        message = build_signed_message(room="lobby", nonce=7, text="hel\nlo")
        assert message.signing_bytes == b"lobby|7|hel lo"
        assert message.was_swept

    def test_notes_have_a_different_preimage_shape(self) -> None:
        # Reusing the message shape for a note would sign the wrong bytes and
        # still look plausible.
        assert note_signing_bytes(namespace="ns", key="k", nonce=7, value="v") == b"ns|k|7|v"

    def test_an_empty_message_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="empty after"):
            build_signed_message(room="lobby", nonce=1, text="\n\n")

    def test_the_length_limit_applies_after_the_sweep(self) -> None:
        with pytest.raises(MalformedEventError, match="limit"):
            build_signed_message(room="lobby", nonce=1, text="a" * (MAX_MESSAGE_CHARS + 1))

    @pytest.mark.parametrize("room", ["a/b", "a b", "a%2fb", "..", "a\nb", "", "a?b", "a#b"])
    def test_a_room_name_that_could_disguise_itself_is_refused(self, room: str) -> None:
        with pytest.raises(MalformedEventError):
            build_signed_message(room=room, nonce=1, text="hi")

    @pytest.mark.parametrize("nonce", [-1, 10**19, "7", True, None, 1.5])
    def test_a_malformed_nonce_is_refused(self, nonce: object) -> None:
        with pytest.raises(MalformedEventError):
            build_signed_message(room="lobby", nonce=nonce, text="hi")  # type: ignore[arg-type]


# ------------------------------------------------------------ dry-run prepare


class TestPrepare:
    def test_it_builds_a_url_that_classifies_as_a_write(self) -> None:
        prepared = prepare_signed_message(room="lobby", text="hello", nonce=7, signer=AGENT)
        assert prepared.consequence is Consequence.WRITE
        assert prepared.url.startswith(f"{ORIGIN}/r/lobby/say-signed/")

    def test_the_signature_verifies_over_the_upstream_preimage(self) -> None:
        prepared = prepare_signed_message(room="lobby", text="hello", nonce=7, signer=AGENT)
        from lineageauth.canonical import b64u_decode

        assert verify_detached(
            AGENT.public_key_bytes,
            prepared.message.signing_bytes,
            b64u_decode(prepared.signature),
        )

    def test_the_signature_is_86_unpadded_base64url_characters(self) -> None:
        # Upstream states the width explicitly; a padded or shorter signature
        # would be rejected by the service.
        prepared = prepare_signed_message(room="lobby", text="hello", nonce=7, signer=AGENT)
        assert len(prepared.signature) == 86
        assert "=" not in prepared.signature

    def test_the_content_hash_covers_the_swept_text(self) -> None:
        """The approval binds the stored bytes, not the caller's bytes."""
        from lineageauth.actions import sha256_hex

        prepared = prepare_signed_message(room="lobby", text="hel\nlo", nonce=7, signer=AGENT)
        assert prepared.request.content_hash == sha256_hex(b"hel lo")
        assert prepared.request.content_hash != sha256_hex(b"hel\nlo")

    def test_text_is_percent_encoded_so_it_cannot_add_path_segments(self) -> None:
        # Unescaped, a slash in the text would change which route the URL names.
        prepared = prepare_signed_message(room="lobby", text="a/b", nonce=7, signer=AGENT)
        assert prepared.url.endswith(quote("a/b", safe=""))
        assert prepared.consequence is Consequence.WRITE

    def test_different_text_produces_a_different_request_hash(self) -> None:
        one = prepare_signed_message(room="lobby", text="hello", nonce=7, signer=AGENT)
        two = prepare_signed_message(room="lobby", text="goodbye", nonce=7, signer=AGENT)
        assert not one.request.matches(two.request)

    def test_different_rooms_produce_different_requests(self) -> None:
        one = prepare_signed_message(room="lobby", text="hello", nonce=7, signer=AGENT)
        two = prepare_signed_message(room="ops", text="hello", nonce=7, signer=AGENT)
        assert not one.request.matches(two.request)

    def test_an_oversized_url_is_refused_rather_than_truncated(self) -> None:
        # Non-Latin scripts blow the URL budget long before the character limit.
        with pytest.raises(MalformedEventError, match="POST form"):
            prepare_signed_message(room="lobby", text="鍵" * 2000, nonce=7, signer=AGENT)

    def test_the_preview_shows_the_swept_text_and_says_so(self) -> None:
        prepared = prepare_signed_message(room="lobby", text="hel\nlo", nonce=7, signer=AGENT)
        preview = prepared.preview()
        assert "hel lo" in preview
        assert "single-line sweep" in preview
        assert "NOT SENT" in preview

    def test_preparing_sends_nothing(self) -> None:
        # The autouse fixture would have raised on any socket use; this states
        # the intent explicitly so the guarantee is not merely incidental.
        prepared = prepare_signed_message(room="lobby", text="hello", nonce=7, signer=AGENT)
        assert prepared.url  # built, never fetched


class TestAnnouncement:
    def test_it_is_one_line_in_the_documented_shape(self) -> None:
        line = format_announcement(
            event_type="ROOT",
            lineage="lineage:la:z6Mk",
            event_id="sha256:" + "a" * 64,
            url="https://example.test/e",
        )
        assert line.startswith("LINEAGEAUTH/0.1 ROOT lineage=")
        assert "\n" not in line

    def test_the_url_is_optional(self) -> None:
        line = format_announcement(
            event_type="GRANT", lineage="lineage:la:z6Mk", event_id="sha256:" + "b" * 64
        )
        assert "url=" not in line


# ------------------------------------------------------------ read-only client


class TestReader:
    def _reader(self, responses: dict[str, object]) -> tuple[object, object]:
        from lineageauth.adapters.technocore import MockTransport, TechnocoreReader

        transport = MockTransport(responses)  # type: ignore[arg-type]
        return TechnocoreReader(transport), transport

    def test_it_reads_a_room_and_returns_untrusted_messages(self) -> None:
        body = json.dumps(
            {
                "room": "lobby",
                "count": 1,
                "first_seq": 1,
                "last_seq": 1,
                "messages": [
                    {"seq": 1, "ts": "2026-08-26T09:00:00.000000Z", "from": "nick", "text": "hi"}
                ],
            }
        )
        reader, transport = self._reader({f"{ORIGIN}/r/lobby?format=json": body})
        messages = reader.room("lobby")  # type: ignore[attr-defined]
        assert len(messages) == 1
        assert messages[0].text == "hi"
        assert messages[0].sender == "nick"
        assert transport.requested == [f"{ORIGIN}/r/lobby?format=json"]  # type: ignore[attr-defined]

    def test_every_read_passes_the_classifier(self) -> None:
        reader, transport = self._reader({})
        with pytest.raises(MalformedEventError):
            reader.note("..", "x")  # type: ignore[attr-defined]
        # Nothing was attempted: the refusal happens before the transport.
        assert transport.requested == []  # type: ignore[attr-defined]

    def test_a_room_name_that_could_change_the_route_is_refused(self) -> None:
        reader, transport = self._reader({})
        for room in ("lobby/say/nick/hi", "..", "a b"):
            with pytest.raises(MalformedEventError):
                reader.room_raw(room)  # type: ignore[attr-defined]
        assert transport.requested == []  # type: ignore[attr-defined]

    def test_rate_limiting_is_surfaced_not_swallowed(self) -> None:
        from lineageauth.adapters.technocore import Response, TransportError

        reader, _ = self._reader(
            {
                f"{ORIGIN}/r/lobby?format=json": Response(
                    status=429,
                    body="",
                    url=f"{ORIGIN}/r/lobby?format=json",
                    headers={"Retry-After": "30"},
                )
            }
        )
        with pytest.raises(TransportError, match="retry after 30"):
            reader.room("lobby")  # type: ignore[attr-defined]

    def test_service_metadata_must_be_a_json_object(self) -> None:
        reader, _ = self._reader({f"{ORIGIN}/.well-known/agent.json": "not json"})
        with pytest.raises(MalformedEventError, match="not JSON"):
            reader.service_metadata()  # type: ignore[attr-defined]


class TestDefensiveParsing:
    """Upstream's shape can change; a reader that crashes on that is a liability."""

    def test_unknown_fields_are_kept_rather_than_dropped(self) -> None:
        from lineageauth.adapters.technocore import parse_messages

        body = json.dumps({"messages": [{"seq": 1, "text": "hi", "somethingNew": 42}]})
        message = parse_messages(body)[0]
        assert message.raw["somethingNew"] == 42

    def test_a_field_of_the_wrong_type_becomes_none(self) -> None:
        from lineageauth.adapters.technocore import parse_messages

        body = json.dumps({"messages": [{"seq": "not-an-int", "text": None, "from": 7}]})
        message = parse_messages(body)[0]
        assert (message.seq, message.text, message.sender) == (None, None, None)

    def test_a_missing_messages_array_yields_nothing(self) -> None:
        from lineageauth.adapters.technocore import parse_messages

        assert parse_messages(json.dumps({"room": "lobby"})) == ()

    def test_non_json_is_refused(self) -> None:
        from lineageauth.adapters.technocore import parse_messages

        with pytest.raises(MalformedEventError, match="not JSON"):
            parse_messages("<html>")


class TestSignedLaneVerification:
    def test_a_prepared_message_verifies_through_the_reader_helper(self) -> None:
        from lineageauth.adapters.technocore import verify_message_signature

        prepared = prepare_signed_message(room="lobby", text="hello", nonce=7, signer=AGENT)
        assert verify_message_signature(
            room="lobby", nonce=7, text="hello", did=AGENT.did, signature=prepared.signature
        )

    def test_altering_any_part_of_the_preimage_fails(self) -> None:
        from lineageauth.adapters.technocore import verify_message_signature

        prepared = prepare_signed_message(room="lobby", text="hello", nonce=7, signer=AGENT)
        for kwargs in (
            {"room": "ops"},
            {"nonce": 8},
            {"text": "hell0"},
        ):
            args = {"room": "lobby", "nonce": 7, "text": "hello"} | kwargs
            assert not verify_message_signature(did=AGENT.did, signature=prepared.signature, **args)


class TestTransportSafety:
    def test_the_transport_refuses_an_off_origin_url_before_opening_a_socket(self) -> None:
        from lineageauth.adapters.technocore import HttpsTransport

        # The autouse fixture makes any socket use an error, so reaching the
        # refusal at all proves nothing was attempted.
        with pytest.raises(MalformedEventError, match="refusing to fetch"):
            HttpsTransport().get("https://evil.example/r/lobby")

    def test_the_transport_refuses_a_write_url(self) -> None:
        from lineageauth.adapters.technocore import HttpsTransport

        with pytest.raises(MalformedEventError, match="refusing to fetch"):
            HttpsTransport().get(f"{ORIGIN}/r/lobby/say/nick/hi")

    def test_redirects_are_refused(self) -> None:
        """Following one would fetch a URL the classifier never saw."""
        from lineageauth.adapters.technocore.client import _NoRedirects

        assert (
            _NoRedirects().redirect_request(None, None, 302, "Found", {}, "https://evil.test")
            is None
        )


class TestDotSegments:
    """`urlsplit` does not normalise `..`; proxies and servers may.

    That gap means a URL can be classified as one route here and resolved as a
    different one there, so dot segments are refused before the route table is
    consulted at all.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "/kv/../x",
            "/kv/ns/..",
            "/r/../lobby",
            "/./rooms",
            "/r/lobby/../lobby/say/nick/hi",
        ],
    )
    def test_a_path_with_a_dot_segment_is_unknown(self, path: str) -> None:
        result = classify(f"{ORIGIN}{path}")
        assert result.consequence is Consequence.UNKNOWN
        assert not result.safe_to_call_automatically

    def test_percent_encoding_does_not_smuggle_one_past(self) -> None:
        # `quote` leaves '.' alone, so a caller escaping its inputs correctly
        # still produces a dot segment. The guard has to be on the path.
        assert not classify(f"{ORIGIN}/kv/{quote('..', safe='')}/x").safe_to_call_automatically
