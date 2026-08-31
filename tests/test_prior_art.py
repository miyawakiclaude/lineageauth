"""The prior-art page makes checkable claims, so they are checked here.

Until 2026-08-28 this repository named no prior art at all. Searching every
document for UCAN, ZCAP, Biscuit, macaroon, KERI, in-toto, SLSA, Sigstore,
SPIFFE and DSSE returned nothing, which a fair reader would take as a claim of
novelty that had never been examined. `docs/PRIOR_ART.md` is the answer.

A page like that fails in two opposite directions and both are tested for.

It can **overclaim** -- drift back toward "this is new" as the project grows
attached to itself. The honest sentences are asserted, not assumed.

It can **misclaim** -- cite a standard that does not exist, or a paper whose
identifier is wrong. That is worse than saying nothing: one fabricated citation
in a public repository costs more credibility than the whole page earns. The
citations are checked for shape here, and were checked to resolve by hand on
2026-08-28; the network is deliberately not touched from a test, because a test
that fails when a server is down teaches people to ignore it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "docs" / "PRIOR_ART.md"


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


class TestThePageExistsAndIsReachable:
    def test_it_exists(self) -> None:
        assert PAGE.is_file()

    def test_the_readme_points_at_it(self) -> None:
        """A page nobody walks past is not an answer to anything."""
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        assert "docs/PRIOR_ART.md" in readme

    def test_it_is_reachable_before_the_reader_has_to_look_for_it(self) -> None:
        """The link belongs near the top, with the other "what this is not" text."""
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        position = readme.index("docs/PRIOR_ART.md") / len(readme)
        assert position < 0.35, "the prior-art link is buried below where people stop reading"


class TestItDoesNotOverclaim:
    def test_it_says_plainly_that_no_primitive_is_new(self) -> None:
        assert "claims no novelty in any single primitive" in _page()

    def test_it_names_the_uncomfortable_one(self) -> None:
        """AIP addresses the same problem for the same two agent protocols.

        A prior-art page that lists only distant relatives is a marketing page.
        """
        page = _page()
        assert "AIP" in page
        assert "same problem for the same two agent protocols" in page

    def test_it_admits_the_combination_claim_is_unverified(self) -> None:
        page = _page()
        assert "that claim is unverified" in page

    def test_it_tells_the_reader_what_to_prefer_today(self) -> None:
        """The test of an honest comparison is whether it can point elsewhere."""
        page = _page()
        assert "more mature" in page
        assert "safer choice" in page

    def test_it_does_not_claim_priority_over_kERI(self) -> None:
        page = _page()
        assert "no priority claim" in page


class TestTheCitationsAreWellFormed:
    """Assessments of overlap are judgements. Citations are facts."""

    EXPECTED: ClassVar[frozenset[str]] = frozenset(
        {
            "https://www.w3.org/TR/vc-di-eddsa/",
            "https://github.com/ucan-wg/spec",
            "https://w3c-ccg.github.io/zcap-spec/",
            "https://github.com/eclipse-biscuit/biscuit",
            "https://github.com/in-toto/attestation",
            "https://arxiv.org/abs/2603.24775",
            # The approval-audit schema that narrowed the second residual claim.
            # Pinned because dropping it would quietly restore an overclaim this
            # page exists to prevent (D-104).
            "https://gist.github.com/renezander030/ad81c7a805a09a844983f881e2c487e5",
            "https://github.com/renezander030/draftcat",
        }
    )

    def test_every_expected_source_is_cited(self) -> None:
        page = _page()
        for url in self.EXPECTED:
            assert url in page, f"the page stopped citing {url}"

    def test_the_arxiv_identifier_is_well_formed(self) -> None:
        """A wrong identifier points at a real paper that is not the one meant.

        This one was checked by hand on 2026-08-28 and carries the title
        "AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and
        A2A". Changing the number without re-checking is the failure mode.
        """
        found = re.findall(r"arxiv\.org/abs/(\d{4}\.\d{4,5})", _page())
        assert found == ["2603.24775"], f"the arXiv citation changed to {found}"

    def test_no_citation_is_a_bare_assertion(self) -> None:
        """Every named standard carries a link the reader can follow."""
        page = _page()
        for name in ("UCAN", "ZCAP-LD", "Biscuit", "in-toto"):
            assert f"[{name}" in page or f"[{name.lower()}" in page, (
                f"{name} is named without a link, so the reader has to take it on trust"
            )

    def test_it_records_when_the_links_were_checked(self) -> None:
        page = _page()
        assert "checked to resolve" in page
        assert "2026-08-28" in page
