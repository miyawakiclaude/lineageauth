"""The implementer's guide restates the protocol, so it can silently go wrong.

`docs/IMPLEMENTERS_GUIDE.md` exists because the bottleneck on v1 is an outside
implementation, and a stranger will not read 4,000 lines of specification to
decide whether to spend an afternoon. Compressing it to one page is worth doing.

Compressing it also creates a second normative source. A guide that drifts from
the code is worse than no guide: it is a document that reads as authoritative
while teaching an implementation that will fail the vectors, and the person it
misleads will conclude the protocol is broken rather than the prose.

So every constant the guide states is checked against the thing it describes,
every link is resolved, and every claim about the vectors is read out of the
manifest. If someone changes the protocol and not the page, this fails.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from lineageauth import didkey
from lineageauth.canonical import EVENT_ID_RE, EVENT_PREIMAGE_PREFIX, jcs

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "IMPLEMENTERS_GUIDE.md"
MANIFEST = ROOT / "conformance" / "manifest.json"

PUBLISHED_BASE = "https://miyawakiclaude.github.io/lineageauth/"


@pytest.fixture(scope="module")
def guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def test_guide_exists() -> None:
    assert GUIDE.is_file(), "the guide the README and CONTRIBUTING both point at"


def test_states_the_real_preimage_prefix(guide: str) -> None:
    # The one byte-exact detail that makes interoperability possible at all.
    # chr() rather than an escape, so this line means the same thing in the
    # file and in the guide it is comparing against.
    literal = EVENT_PREIMAGE_PREFIX.decode("ascii").replace(chr(10), chr(92) + "n")
    assert f'b"{literal}"' in guide, (
        f"the guide must state the preimage prefix as {literal!r}; "
        "a reader who copies a wrong prefix produces signatures nothing accepts"
    )


def test_states_the_real_event_id_shape(guide: str) -> None:
    assert '"sha256:" + hex(SHA-256(preimage))' in guide
    assert EVENT_ID_RE.match("sha256:" + "0" * 64), "the shape the guide describes"


def test_states_the_real_multicodec(guide: str) -> None:
    ed = didkey.ED25519_PUB_MULTICODEC
    assert ed == b"\xed\x01"
    assert "`0xED 0x01` (Ed25519)" in guide

    # The guide singles out X25519 because it is the one that looks right.
    x25519 = b"\xec\x01"
    described = didkey._KNOWN_UNSUPPORTED_MULTICODECS.get(x25519)
    assert described is not None and "X25519" in described
    assert "`0xEC 0x01` is X25519" in guide


def test_states_the_real_decoded_length(guide: str) -> None:
    expected = len(didkey.ED25519_PUB_MULTICODEC) + didkey.ED25519_PUBLIC_KEY_LENGTH
    assert expected == 34
    assert f"**{expected} bytes**" in guide
    assert f"{didkey.ED25519_PUBLIC_KEY_LENGTH}-byte key" in guide


def test_the_utf16_ordering_example_is_true(guide: str) -> None:
    """The guide's one worked example. If it is backwards it teaches the bug.

    U+FFFD and U+1F600 separate UTF-16 code-unit ordering from code-point
    ordering; a pair inside the BMP agrees under both and proves nothing. This
    is the pair the differential test found, and the guide quotes its direction.
    """
    out = jcs({"�": 1, "\U0001f600": 2})
    text = out.decode("utf-8")
    assert text.index("\U0001f600") < text.index("�"), (
        "U+1F600 must sort before U+FFFD under UTF-16 code-unit ordering; "
        "the guide says so, and a code-point sort gives the opposite"
    )
    assert "sorts *after*" in guide and "0xD83D < 0xFFFD" in guide


def test_every_vector_claim_matches_the_manifest(guide: str) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    # The guide tells a stranger that every entry carries the rule behind it.
    for vector in manifest["vectors"]:
        assert vector.get("rule"), f"{vector['name']} has no rule; the guide promises one"

    assert {"must-verify", "must-refuse"} == {v["expect"] for v in manifest["vectors"]}, (
        "the guide documents exactly these two verdicts"
    )

    named = re.findall(r"`([a-z0-9-]+)`", guide)
    highlighted = "receipt-not-signed-by-its-worker"
    assert highlighted in named, "the guide's worked vector"
    assert any(v["name"] == highlighted for v in manifest["vectors"]), (
        f"the guide walks through {highlighted}, which must still exist"
    )


def test_relative_links_resolve(guide: str) -> None:
    for target in re.findall(r"\]\((?!https?:)([^)#]+)\)", guide):
        assert (GUIDE.parent / target).exists(), f"broken link in the guide: {target}"


def test_published_urls_have_a_file_behind_them(guide: str) -> None:
    """A stranger's first action is fetching a URL. A 404 ends the attempt."""
    for url in re.findall(rf"{re.escape(PUBLISHED_BASE)}([^\s`)]+)", guide):
        assert (ROOT / url).exists(), (
            f"the guide publishes {PUBLISHED_BASE}{url}, but {url} is not in the repository"
        )


def test_the_second_implementation_is_still_roughly_that_size(guide: str) -> None:
    """The guide sells the JS file as short enough to read. Keep that honest."""
    js = (ROOT / "packages" / "js" / "lineageauth.js").read_text(encoding="utf-8")
    lines = len(js.splitlines())
    claimed = int(re.search(r"~(\d+) lines", guide).group(1))
    assert abs(lines - claimed) <= 75, (
        f"the guide says ~{claimed} lines, the file has {lines}; update the guide"
    )
