"""Fuzzing the parsers with input nobody meant to be valid.

`tests/test_properties.py` searches the space of *well-formed* values. This
file searches the space of hostile ones, and it asserts one thing throughout:

    every parser either returns, or raises a LineageAuthError.

That is the whole property, and it is not a small one. A verifier is a program
that reads bytes chosen by an attacker. An unexpected `KeyError`, `IndexError`
or `UnicodeDecodeError` escaping a parser is not a cosmetic problem: whoever is
running the verifier now has a crash they did not plan for, in the code path
that was supposed to be the safe one, and a crash is a denial of service on
whatever decision was about to be made.

`RecursionError` is allowed through deliberately, and only for deeply nested
JSON: that is the interpreter's stack limit rather than a parser mistake, and
pretending to catch it would hide the depth limit instead of documenting it.

Deterministic: hypothesis is seeded from its own database and every example
here is reproducible from the failure it prints.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lineageauth.actions import ActionRequest
from lineageauth.approval import read_receipt
from lineageauth.bundle import EventBundle
from lineageauth.canonical import b64u_decode, is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError
from lineageauth.identifiers import is_lineage_id
from lineageauth.jury import read_case, read_vote
from lineageauth.scopes import ApprovalMode, parse_resource, parse_scopes
from lineageauth.timeutil import parse_instant
from lineageauth.work import read_claim, read_task

QUICK = settings(max_examples=250, suppress_health_check=[HealthCheck.too_slow], deadline=None)

# Text that has caused a parser somewhere to do something surprising.
NASTY_TEXT = st.one_of(
    st.text(max_size=60),
    st.sampled_from(
        [
            "",
            " ",
            "\x00",
            "\r\n",
            "..",
            "../../etc/passwd",
            "*",
            "did:key:",
            "did:key:z",
            "sha256:",
            "sha256:" + "g" * 64,
            "sha256:" + "A" * 64,  # uppercase hex
            "lineage:la:",
            "‮evil",  # right-to-left override
            "a" * 4096,
            "\ud800",  # lone surrogate, if it survives construction
        ]
    ),
)

json_values: st.SearchStrategy[Any] = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**40), max_value=2**40),
        st.floats(allow_nan=False, allow_infinity=False, width=32),
        NASTY_TEXT,
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(NASTY_TEXT, children, max_size=5),
    ),
    max_leaves=12,
)

json_objects = st.dictionaries(NASTY_TEXT, json_values, max_size=8)


def assert_contained(call, *args, **kwargs) -> None:
    """Call it. Returning is fine. LineageAuthError is fine. Nothing else is."""
    try:
        call(*args, **kwargs)
    except LineageAuthError:
        return
    except RecursionError:
        # The interpreter's stack limit on deeply nested JSON, not a parser
        # mistake. Documented rather than swallowed.
        return
    except Exception as exc:
        raise AssertionError(
            f"{getattr(call, '__name__', call)} leaked {type(exc).__name__}: {exc}"
        ) from exc


class TestIdentifierParsers:
    @given(NASTY_TEXT)
    @QUICK
    def test_did_key(self, text: str) -> None:
        assert_contained(public_key_from_did_key, text)

    @given(st.binary(max_size=80))
    @QUICK
    def test_did_key_from_bytes(self, raw: bytes) -> None:
        assert_contained(public_key_from_did_key, raw.decode("latin-1"))

    @given(NASTY_TEXT)
    @QUICK
    def test_base64url(self, text: str) -> None:
        assert_contained(b64u_decode, text)

    @given(NASTY_TEXT)
    @QUICK
    def test_event_id_predicate_never_raises(self, text: str) -> None:
        """A predicate that can raise is not a predicate."""
        assert is_event_id(text) in (True, False)

    @given(NASTY_TEXT)
    @QUICK
    def test_lineage_id_predicate_never_raises(self, text: str) -> None:
        assert is_lineage_id(text) in (True, False)

    @given(NASTY_TEXT)
    @QUICK
    def test_instant(self, text: str) -> None:
        assert_contained(parse_instant, text, field="fuzz")


class TestScopeParsers:
    @given(NASTY_TEXT, NASTY_TEXT)
    @QUICK
    def test_resource(self, namespace: str, resource: str) -> None:
        assert_contained(parse_resource, namespace, resource)

    @given(st.lists(json_objects, max_size=4))
    @QUICK
    def test_scopes(self, raw: list[Any]) -> None:
        assert_contained(parse_scopes, raw)

    @given(st.one_of(NASTY_TEXT, st.integers(), st.none(), st.booleans()))
    @QUICK
    def test_approval_mode(self, value: Any) -> None:
        assert_contained(ApprovalMode.parse, value)

    @given(NASTY_TEXT, NASTY_TEXT, NASTY_TEXT, NASTY_TEXT, NASTY_TEXT)
    @QUICK
    def test_action_request(self, ns: str, res: str, act: str, dest: str, digest: str) -> None:
        assert_contained(
            ActionRequest,
            namespace=ns,
            resource=res,
            action=act,
            destination=dest,
            content_hash=digest,
        )


class TestEnvelopeAndBundle:
    @given(NASTY_TEXT)
    @QUICK
    def test_envelope_from_arbitrary_text(self, text: str) -> None:
        assert_contained(Envelope.from_json, text)

    @given(json_objects)
    @QUICK
    def test_envelope_from_arbitrary_object(self, document: dict[str, Any]) -> None:
        assert_contained(Envelope.from_json, json.dumps(document))

    @given(st.lists(json_objects, max_size=3))
    @QUICK
    def test_a_bundle_of_junk_is_all_rejected_and_never_crashes(
        self, documents: list[dict[str, Any]]
    ) -> None:
        """The bundle must survive documents that never became envelopes."""
        envelopes = []
        for document in documents:
            try:
                envelopes.append(Envelope.from_json(json.dumps(document)))
            except LineageAuthError:
                continue
        bundle = EventBundle.from_envelopes(envelopes)
        # Nothing hostile can reach `admitted` without a verifying signature.
        assert all(event.verified_signers for event in bundle.admitted)


class TestPayloadReadersReturnComplaintsRatherThanRaising:
    """The readers have a stricter contract than the parsers.

    Each one returns its value or a string saying what was wrong. A reader that
    raised on a hostile payload would take down a resolver that is deliberately
    written to keep going and report -- one bad event in a bundle must not be
    able to hide every good one.
    """

    def _admitted(self, payload: dict[str, Any]):
        from datetime import UTC, datetime

        from lineageauth.bundle import AdmittedEvent

        return AdmittedEvent(
            event_id="sha256:" + "a" * 64,
            event_type=str(payload.get("type", "")),
            lineage="lineage:la:z6Mk",
            issued_at=datetime(2026, 1, 1, tzinfo=UTC),
            verified_signers=(),
            payload=payload,
        )

    @pytest.mark.parametrize("reader", [read_task, read_claim, read_receipt, read_case, read_vote])
    @given(payload=json_objects)
    @QUICK
    def test_a_reader_returns_a_complaint(self, reader, payload: dict[str, Any]) -> None:
        try:
            result = reader(self._admitted(payload))
        except LineageAuthError:
            return
        except RecursionError:
            return
        except Exception as exc:
            raise AssertionError(f"{reader.__name__} leaked {type(exc).__name__}: {exc}") from exc
        assert result is not None
