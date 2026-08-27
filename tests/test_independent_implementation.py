"""The two implementations, made to disagree.

`CONTRIBUTING.md` asks for an independent implementation that reaches a
different verdict, and `RELEASE.md` puts it first for v1. `packages/js/` is that
second side. This file is the differential test between them.

The conformance vectors compare **verdicts**, which is a coarse signal: two
implementations can both answer "verify" while disagreeing about the bytes they
verified, and that only surfaces much later as an event id nobody can resolve.
So the tests that matter here compare **canonical output** -- the JCS string and
the event id -- over payloads hypothesis generates, including the shapes that
break naive canonicalizers:

    key ordering beyond the BMP, -0, escapes, empty keys, deep nesting.

A disagreement is the most useful thing this repository can produce. Which side
is wrong is an open question, and the failure message says so rather than
assuming the Python one is right.

Skipped when Node is absent. The Python side is the one that must work
everywhere; a second implementation that needs a second runtime is still worth
having, and requiring it here would make the suite fail for the wrong reason.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lineageauth.canonical import compute_event_id, jcs

REPO = Path(__file__).resolve().parents[1]
JS = REPO / "packages" / "js"

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

SLOW = settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)


def canonicalize_with_js(values: list[Any]) -> list[dict[str, Any]]:
    """Ask the JavaScript implementation to canonicalize each value."""
    # ensure_ascii on purpose: everything crosses the pipe as escapes, so
    # neither side's console encoding can change what the other one reads. The
    # first version sent raw UTF-8 and a generated string broke the JSON.
    payload = "\n".join(json.dumps(v, ensure_ascii=True) for v in values)
    done = subprocess.run(
        [str(NODE), str(JS / "canonicalize.mjs")],
        input=payload.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr.decode("utf-8", errors="replace")
    # split("\n"), never splitlines(). Python's splitlines() also breaks on
    # U+0085, U+2028, U+2029, VT and FF, and JSON.stringify emits those raw
    # because they are above U+001F. A payload with U+0085 in a key therefore
    # arrived here cut in half -- a bug in this harness, found by the very
    # property test it exists to run.
    text = done.stdout.decode("utf-8")
    return [json.loads(line) for line in text.split("\n") if line.strip()]


# Values chosen to hurt: the ones a canonicalizer written from memory gets wrong.
# Lone surrogates are not valid JSON string content and are not what is under
# test here; `test_fuzz.py` is where malformed input belongs.
safe_text = st.text(alphabet=st.characters(exclude_categories=["Cs"]), max_size=30)

json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
    st.sampled_from([0, -0.0, 1.0, -1.5, 1e21, 1e-7, 0.1, 123456789.123]),
    safe_text,
    st.sampled_from(
        [
            "",
            '"',
            "\\",
            "\n\t\r",
            "\x00\x1f",
            "é",
            "日本語",
            "\U0001f600",  # outside the BMP: code-unit vs code-point ordering
            "﻿",
        ]
    ),
)

json_keys = st.one_of(
    st.text(alphabet=st.characters(exclude_categories=["Cs"]), max_size=12),
    st.sampled_from(["", "a", "A", "z", "\U0001f600", "￿", "é", "0", "-0"]),
)

json_values: st.SearchStrategy[Any] = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(json_keys, children, max_size=5),
    ),
    max_leaves=10,
)

json_objects = st.dictionaries(json_keys, json_values, max_size=6)


class TestCanonicalizationAgrees:
    """The property everything else rests on.

    One byte of disagreement here changes every event id, and every reference
    between events breaks at once.
    """

    @given(value=json_objects)
    @SLOW
    def test_the_two_produce_identical_jcs(self, value: dict[str, Any]) -> None:
        [result] = canonicalize_with_js([value])
        assert "error" not in result, result.get("error")
        assert result["jcs"] == jcs(value).decode("utf-8"), (
            "the implementations canonicalize this differently, so they would "
            "compute different event ids for the same payload. Which one is "
            "wrong is an open question -- see CONTRIBUTING.md."
        )

    @given(value=json_objects)
    @SLOW
    def test_the_two_produce_identical_event_ids(self, value: dict[str, Any]) -> None:
        [result] = canonicalize_with_js([value])
        assert result["eventId"] == compute_event_id(value)

    @pytest.mark.parametrize(
        "value",
        [
            {},
            {"": ""},
            {"b": 1, "a": 2},
            {"a": {"b": {"c": [1, 2, {"d": None}]}}},
            {"�": 1, "\U0001f600": 2},  # the pair that separates the two orderings
            # The fullwidth A is the point: a canonicalizer that normalised it
            # would collapse two distinct keys into one. The linter's warning
            # about a confusable character describes the case being tested.
            {"Ａ": 1, "A": 2},  # noqa: RUF001
            {"n": -0.0},
            {"n": 1e21},
            {"n": 1e-7},
            {"s": '"\\\n\t'},
            {"s": "\x00\x01\x1f"},
            {"nested": [[[[[1]]]]]},
        ],
        ids=lambda v: str(v)[:40],
    )
    def test_the_shapes_that_break_naive_canonicalizers(self, value: dict[str, Any]) -> None:
        [result] = canonicalize_with_js([value])
        assert "error" not in result, result.get("error")
        assert result["jcs"] == jcs(value).decode("utf-8")
        assert result["eventId"] == compute_event_id(value)

    def test_key_order_is_by_code_unit_not_code_point(self) -> None:
        """The one pair that actually tells the two orderings apart.

        The obvious test -- "z" against U+1F600 -- proves nothing. 0x7A is below
        both 0xD83D and 0x1F600, so code-unit and code-point ordering agree on
        it and a wrong implementation passes. This test was written that way
        first, and asserted the wrong direction into the bargain.

        The discriminating pair is a high BMP character against a supplementary
        one::

            U+FFFD   code unit 0xFFFD          code point 0xFFFD
            U+1F600  code units 0xD83D 0xDE00  code point 0x1F600

        By code unit the emoji sorts first (0xD83D < 0xFFFD); by code point it
        sorts last. RFC 8785 requires code units, and both implementations have
        to agree or every event id carrying such a key diverges.
        """
        value = {"�": 1, "\U0001f600": 2}
        canonical = jcs(value).decode("utf-8")
        [result] = canonicalize_with_js([value])
        assert result["jcs"] == canonical
        assert canonical.index("\U0001f600") < canonical.index("�"), (
            "this is code-point ordering; RFC 8785 requires UTF-16 code units"
        )


class TestRealEventsAgree:
    def _envelopes(self) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for directory in (REPO / "examples", REPO / "conformance" / "vectors"):
            for path in sorted(directory.glob("*.json")):
                raw = json.loads(path.read_text(encoding="utf-8"))
                found.extend(raw if isinstance(raw, list) else [raw])
        return found

    def test_every_published_payload_gets_the_same_event_id(self) -> None:
        payloads = [e["payload"] for e in self._envelopes() if isinstance(e.get("payload"), dict)]
        assert payloads, "no payloads found to compare"
        results = canonicalize_with_js(payloads)
        for payload, result in zip(payloads, results, strict=True):
            assert result["eventId"] == compute_event_id(payload)


class TestVerdictsAgree:
    def test_the_js_verifier_agrees_with_every_conformance_vector(self) -> None:
        """The runner exits non-zero on any disagreement, and says which."""
        done = subprocess.run(
            [str(NODE), str(JS / "run-conformance.mjs")],
            capture_output=True,
            check=False,
            cwd=str(REPO),
        )
        out = done.stdout.decode("utf-8", errors="replace")
        assert done.returncode == 0, out + done.stderr.decode("utf-8", errors="replace")
        assert "vectors agree with the package" in out

    def test_a_disagreement_would_be_reported_rather_than_swallowed(self) -> None:
        source = (JS / "run-conformance.mjs").read_text(encoding="utf-8")
        assert "process.exit(1)" in source
        assert "may be the" in source or "which side is wrong" in source.lower()


class TestItIsIndependentRatherThanAPort:
    """A second implementation that shares the first one's machinery proves nothing."""

    def _source(self) -> str:
        return (JS / "lineageauth.js").read_text(encoding="utf-8")

    def test_it_implements_canonicalization_itself(self) -> None:
        """The Python side delegates JCS to a library so it cannot be got wrong.

        This side writes it out so that a subtle mistake in either becomes
        visible. Two implementations calling the same library agree by
        construction.
        """
        source = self._source()
        assert "export function jcs" in source
        assert "rfc8785" not in source.lower()

    def test_it_decodes_base58_and_the_multicodec_itself(self) -> None:
        source = self._source()
        assert "base58Decode" in source
        assert "ED25519_MULTICODEC" in source

    def test_it_writes_the_preimage_prefix_out_literally(self) -> None:
        """So a one-character divergence is visible in a diff rather than derived."""
        from lineageauth.canonical import EVENT_PREIMAGE_PREFIX

        source = self._source()
        assert "lineageauth:event:v1" in source
        assert EVENT_PREIMAGE_PREFIX.decode("ascii").startswith("lineageauth:event:v1")

    def test_it_takes_primitives_from_webcrypto_and_says_why(self) -> None:
        """Hand-rolling a curve adds risk without adding evidence."""
        source = self._source()
        assert "crypto.subtle" in source
        assert "without adding evidence" in source

    def test_it_has_no_dependencies(self) -> None:
        """No package.json, no lockfile, no build step -- it is readable as it ships."""
        assert not (JS / "package.json").exists()
        assert not (JS / "node_modules").exists()
        source = self._source()
        assert "require(" not in source
        assert 'from "' not in source.replace('from "./lineageauth.js"', "")
