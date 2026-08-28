"""The limitations page is normative, and it was rewritten. Nothing may be lost.

`docs/28_NON_GOALS_LIMITATIONS.md` was a 28-line list written for somebody who
already knew why each line was there. `RELEASE.md` asked for it to be rewritten
for somebody who has just arrived and is deciding whether to depend on this.

Rewriting a normative page is the risky kind of edit: prose improves, a fact
quietly goes missing, and the missing fact is the one somebody needed. Every
claim the old list made is asserted here individually, so a future edit that
drops one fails rather than reads well.

The page also has a job beyond completeness -- it has to be usable by a stranger
making a decision -- so the parts that do that job are pinned too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "docs" / "28_NON_GOALS_LIMITATIONS.md"


@pytest.fixture(scope="module")
def page() -> str:
    return PAGE.read_text(encoding="utf-8").lower()


class TestNothingTheOldListSaidWasLost:
    """Each of these was a line in the original. None may disappear silently."""

    @pytest.mark.parametrize(
        "claim",
        [
            "human",  # does not prove a human's identity
            "legal entity",
            "company employment",
            "honesty",
            "competence",
            "hidden fleet",
            "sybil",
            "truth of an attestation",
            "payment settlement",
            "reward eligibility",
            "airdrop",
        ],
    )
    def test_it_still_says_what_is_not_proven(self, page: str, claim: str) -> None:
        assert claim in page

    @pytest.mark.parametrize(
        "never",
        [
            "wallet key",
            "transfer tokens",
            "escrow rewards",
            "bypass provider",  # OAuth and every other provider authorization
            "technocore durable",
        ],
    )
    def test_it_still_says_what_the_core_will_never_do(self, page: str, never: str) -> None:
        assert never in page

    def test_it_still_says_a_superseded_key_keeps_signing(self, page: str) -> None:
        """The limitation people most often assume away."""
        assert "mathematically valid signatures" in page
        assert "no revocation" in page

    def test_it_still_says_omission_is_the_standing_risk(self, page: str) -> None:
        assert "omission" in page
        assert "freshness" in page
        assert "several sources" in page

    def test_it_still_says_a_jury_verdict_is_not_a_ruling(self, page: str) -> None:
        assert "not legal arbitration" in page


class TestItIsUsableBySomebodyDeciding:
    """The point of the rewrite, and the part prose alone would let slip."""

    def test_it_states_the_largest_true_claim_plainly(self, page: str) -> None:
        """A reader should not have to infer what a positive result means."""
        assert "the events you supplied" in page
        assert 'never returns "trusted"' in page

    def test_it_tells_the_reader_not_to_depend_on_this_yet(self, page: str) -> None:
        assert "do not put real authority behind this yet" in page

    def test_it_names_what_to_use_instead(self, page: str) -> None:
        """A limitations page that cannot point elsewhere is a sales page."""
        assert "ucan" in page
        assert "biscuit" in page
        assert "in-toto" in page
        assert "prior_art.md" in page

    def test_it_allows_the_reader_to_walk_away(self, page: str) -> None:
        assert "perfectly good outcome" in page

    def test_it_is_no_longer_a_bare_list(self, page: str) -> None:
        """The original was 28 lines with no explanation of consequence."""
        assert len(page.splitlines()) > 80, "the rewrite has shrunk back toward a list"

    def test_the_readme_and_security_page_still_reach_it(self) -> None:
        for name in ("README.md", "SECURITY.md"):
            text = (REPO / name).read_text(encoding="utf-8")
            assert "28_NON_GOALS_LIMITATIONS.md" in text, f"{name} lost the link"
