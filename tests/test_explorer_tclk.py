"""The Explorer's tclk/1 deal inspector screen.

`tests/test_explorer.py` already holds every screen to the same rules (no markup
sink, textContent only, no inline script, same-origin, no storage, palette
tokens). This file checks only what is specific to the ninth screen: that it
exists, that it says what it is before it shows anything, and that it reaches
the three read-only endpoints and nothing that could post.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HTML = (REPO / "apps" / "explorer" / "index.html").read_text(encoding="utf-8")
SCRIPT = (REPO / "apps" / "explorer" / "app.js").read_text(encoding="utf-8")


class TestTheScreenExists:
    def test_it_is_the_ninth_screen_with_a_tab(self) -> None:
        assert 'data-screen="tclk"' in HTML
        assert 'id="screen-tclk"' in HTML and 'data-index="09"' in HTML

    def test_it_states_its_limits_before_anything_renders(self) -> None:
        section = HTML[HTML.index('id="screen-tclk"') : HTML.index("</main>")]
        lowered = section.lower()
        for phrase in ("read-only", "no wallet", "no settlement"):
            assert phrase in lowered, phrase
        assert "nothing on this screen posts a frame" in lowered

    def test_the_form_asks_for_an_instant_rather_than_assuming_one(self) -> None:
        assert 'id="tclk-now"' in HTML
        assert "no default clock" in SCRIPT


class TestItReadsAndOnlyReads:
    def test_it_calls_exactly_two_read_only_endpoints(self) -> None:
        """simulate and authorize. inspect exists for callers that hold one line;
        the screen always has a transcript, so it never needs it."""
        called = set(re.findall(r'api\("(/v1/tclk/[a-z]+)"', SCRIPT))
        assert called == {"/v1/tclk/simulate", "/v1/tclk/authorize"}
        for verb in ("post", "publish", "lock", "claim", "refund", "reveal", "pay", "send"):
            assert f"/v1/tclk/{verb}" not in SCRIPT

    def test_authority_is_asked_for_the_last_line_and_needs_a_lineage(self) -> None:
        handler = SCRIPT[SCRIPT.index('getElementById("tclk-form")') :]
        assert "lines[lines.length - 1]" in handler
        assert "currentLineage" in handler
        assert "Pick a lineage" in handler

    def test_every_value_goes_through_the_text_helpers(self) -> None:
        handler = SCRIPT[SCRIPT.index('getElementById("tclk-form")') :]
        assert "innerHTML" not in handler and "insertAdjacentHTML" not in handler
        assert handler.count("pairs(") >= 4 and handler.count("card(") >= 4
