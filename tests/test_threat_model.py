"""The threat model asks somebody to review it, so it has to be worth reviewing.

`RELEASE.md` lists "the threat model has been reviewed by somebody else" as a v1
requirement. Before asking, `docs/22_SECURITY.md` was 84 lines of threat *names*:
"resolver omission", "confused deputy", "replay". Names are a checklist, and a
reviewer reading one spends their first hour discovering things the author
already knows.

It now also records what attacking this code actually found, and where a second
opinion would help most. That section makes claims -- decision numbers, counts,
which threats had instances -- and a document that asks for scrutiny should
survive some.

The one thing this cannot test is whether the threat model is *right*. That is
the whole reason it asks.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "docs" / "22_SECURITY.md"
DECISIONS = REPO / "docs" / "29_DECISIONS.md"


@pytest.fixture(scope="module")
def raw() -> str:
    """The file as written, for anything that cares about structure."""
    return PAGE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def page(raw: str) -> str:
    """The same text with runs of whitespace collapsed.

    These assertions are about what the document says, and a sentence that
    happens to wrap across two lines says the same thing. Matching the raw text
    made the tests fail on the line width rather than on the content, which is
    a test that reports the wrong problem.
    """
    return " ".join(raw.split())


class TestItRecordsWhatWasActuallyFound:
    """A threat class nobody has instantiated is a word."""

    def test_it_names_the_recurring_shape(self, page: str) -> None:
        """The finding that generalises: closing can be the attack."""
        assert "Refusal is the attack" in page

    @pytest.mark.parametrize(
        "instance",
        [
            "Appending a proof deleted an event",
            "could veto its own replacement",
            "Respelling a number",
        ],
    )
    def test_each_instance_of_that_shape_is_named(self, page: str, instance: str) -> None:
        assert instance in page

    def test_it_says_where_the_controls_list_is_misleading(self, page: str) -> None:
        """`conflict fail-closed` reads as a safety property and is one only
        where a stranger cannot reach the switch. The document has to say so
        rather than leave the reader to find out."""
        assert "closing *is* the attack" in page

    def test_it_names_the_builder_versus_verifier_shape(self, page: str) -> None:
        assert "A builder is a convenience; a verifier is a rule" in page
        for instance in ("availability.statement", "dispute.open", "mcp"):
            assert instance in page

    def test_it_distinguishes_standing_from_authority(self, page: str) -> None:
        assert "Standing, not authority" in page
        assert "could not widen its own scope" in page


class TestTheReferencesResolve:
    """Today's third citation check. Two of the first two did not survive one."""

    def test_every_decision_it_cites_exists(self, page: str) -> None:
        decisions = DECISIONS.read_text(encoding="utf-8")
        cited = sorted(set(re.findall(r"\bD-\d+b?\b", page)))
        assert cited, "the section cites no decisions at all"
        missing = [d for d in cited if not re.search(rf"\n## {re.escape(d)}[:\s]", decisions)]
        assert not missing, f"the threat model cites decisions that do not exist: {missing}"

    def test_it_points_at_a_reporting_route_that_is_there(self, page: str) -> None:
        assert "SECURITY.md" in page
        assert (REPO / "SECURITY.md").is_file()


class TestItAsksForSomethingSpecific:
    """ "Please review this" is not a request anybody can act on."""

    def test_it_says_why_one_reader_is_not_enough(self, page: str) -> None:
        assert "share an assumption" in page

    def test_it_lists_where_a_second_opinion_would_help(self, raw: str) -> None:
        section = raw[raw.index("What a second reader is for") :]
        numbered = re.findall(r"^\d+\. \*\*", section, re.M)
        assert len(numbered) >= 4, (
            "the ask is not specific enough to act on; a reviewer needs places to look"
        )

    def test_it_admits_what_has_never_been_exercised(self, page: str) -> None:
        assert "never been wired into anything that actually executes" in page
        assert "Reviewed by nobody" in page

    def test_it_invites_being_told_the_document_is_wrong(self, page: str) -> None:
        assert "wrong about its own threats" in page

    def test_it_is_no_longer_only_a_list_of_names(self, raw: str) -> None:
        assert len(raw.splitlines()) > 150, "the reasoning has shrunk back to a checklist"
