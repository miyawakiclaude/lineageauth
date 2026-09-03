"""The FLOP Console: markup discipline, CSP, wording, and how it is served.

Mirrors `tests/test_explorer.py`'s central rule -- every value this page shows
was written by somebody else (an activity title, a prompt, a rule's quoted
statement, a room name from Technocore), and a viewer that turned one of those
strings into markup would be a worse problem than anything the page was built
to display. Text reaches the DOM through `textContent` and through nothing
else, and this file reads the source and fails on any construct that could
turn a string into markup.

It also fixes the one thing that is easy to get right once and then drift
from: `apps/flop/tokens.css` is generated from
`conformance/flop/ui-tokens.json` by `scripts/generate_flop_tokens.py`, and a
hand edit to either file, on its own, is a build that no longer matches its
own record of where every colour came from.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
FLOP = REPO / "apps" / "flop"
HTML = FLOP / "index.html"
SCRIPT = FLOP / "app.js"
STYLE = FLOP / "app.css"
TOKENS = FLOP / "tokens.css"
TOKENS_JSON = REPO / "conformance" / "flop" / "ui-tokens.json"

# Anything that turns a string into markup, or a string into code. Same list
# `tests/test_explorer.py` checks the Explorer against.
MARKUP_SINKS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function",
    'setTimeout("',
    "srcdoc",
)

REQUIRED_SCREENS = (
    "overview",
    "activity",
    "evidence",
    "technocore",
    "tclk",
    "inference",
    "passport",
    "safety",
    "sources",
    "settings",
)

# docs' fixed vocabulary (`lineageauth.flop.model`): must appear verbatim
# somewhere a viewer will actually see it, not paraphrased.
REQUIRED_NOTICES = (
    "Independent tool for the FLOP ecosystem - not affiliated with or endorsed by FLOP Labs.",
    "Testnet tokens have no assumed monetary value.",
)

# Words this product may not use about a person's activity
# (`lineageauth.flop.model.FORBIDDEN_VOCABULARY` plus the directive's own
# list). A UI author retyping a promise the API already refuses to make is
# exactly the failure this repeats the check for.
FORBIDDEN_PHRASES = (
    "you will receive",
    "guaranteed eligible",
    "official airdrop rank",
    "estimated allocation",
    "eligibility score",
)


class TestUntrustedContentIsNeverMarkup:
    def test_the_script_uses_no_markup_sink(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        found = [sink for sink in MARKUP_SINKS if sink in source]
        assert found == [], f"the FLOP Console must not be able to render markup: {found}"

    def test_text_reaches_the_dom_only_through_textContent(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        assert source.count("textContent") >= 1
        assert "createElement" in source

    def test_the_page_carries_no_inline_script_or_style(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\bsrc=)", html)
        assert "<style" not in html
        assert not re.search(r"\son\w+\s*=", html), "no inline event handler attributes"

    def test_no_request_is_rooted_at_another_origin(self) -> None:
        """Same-origin only. Absolute-rooted paths are fine here (single mount, no prefix)."""
        source = SCRIPT.read_text(encoding="utf-8")
        for match in re.findall(r"fetch\(([^,)]+)", source):
            literal = match.strip().strip("\"'")
            if literal.startswith("path") or not literal.startswith("/"):
                continue
            assert "://" not in literal

    def test_html_asset_references_are_same_origin(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        for match in re.findall(r'(?:href|src)="([^"]+)"', html):
            assert "://" not in match, f"cross-origin resource: {match}"
            assert not match.startswith("//"), f"protocol-relative resource: {match}"


class TestSecurityPolicy:
    def test_the_meta_csp_is_strict(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        match = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', html)
        assert match, "no CSP meta tag"
        policy = match.group(1)
        for directive in (
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "img-src 'none'",
            "font-src 'none'",
        ):
            assert directive in policy, f"missing {directive!r} in {policy!r}"
        assert "unsafe-inline" not in policy
        assert "unsafe-eval" not in policy

    def test_no_web_font_is_loaded(self) -> None:
        """`design.md` names Space Mono and Inter; this page loads neither over the network."""
        html = HTML.read_text(encoding="utf-8")
        css = STYLE.read_text(encoding="utf-8") + TOKENS.read_text(encoding="utf-8")
        assert "fonts.googleapis.com" not in html + css
        assert "fonts.gstatic.com" not in html + css
        assert "@font-face" not in css


class TestRequiredWording:
    def test_the_persistent_notices_appear(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        collapsed = re.sub(r"\s+", " ", html)
        for phrase in REQUIRED_NOTICES:
            assert phrase in collapsed, f"missing notice: {phrase!r}"

    def test_the_seed_warning_is_rendered_from_the_api_not_retyped_wrong(self) -> None:
        """The seed warning's exact wording lives in `lineageauth.flop.model`.

        The page renders whatever the API sends rather than a second copy of
        the sentence, so there is exactly one place that sentence can drift.
        """
        script = SCRIPT.read_text(encoding="utf-8")
        assert "notice-seed" in script
        assert "status.notices.seedPhrase" in script

    def test_no_forbidden_airdrop_vocabulary_is_hard_coded(self) -> None:
        html = HTML.read_text(encoding="utf-8").lower()
        script = SCRIPT.read_text(encoding="utf-8").lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in html
            assert phrase not in script

    def test_coverage_label_is_never_shown_as_a_score_synonym(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        assert "airdrop score" not in html.lower()


class TestNavigationCoversEveryScreen:
    def test_every_screen_has_a_section(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        for screen in REQUIRED_SCREENS:
            assert f'id="screen-{screen}"' in html, f"missing section for {screen!r}"

    def test_the_sidenav_links_every_screen(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        sidenav = re.search(r"<nav class=\"sidenav\".*?</nav>", html, re.S)
        assert sidenav, "no sidenav"
        for screen in REQUIRED_SCREENS:
            assert f'data-screen="{screen}"' in sidenav.group(0), f"sidenav is missing {screen!r}"

    def test_the_bottom_nav_carries_the_compact_set_and_a_more_button(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        bottomnav = re.search(r"<nav class=\"bottomnav\".*?</nav>", html, re.S)
        assert bottomnav, "no bottom nav"
        for screen in ("overview", "activity", "passport", "safety"):
            assert f'data-screen="{screen}"' in bottomnav.group(0)

    def test_the_nav_has_an_aria_label(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        assert re.search(r'<nav class="sidenav" aria-label="[^"]+"', html)
        assert re.search(r'<nav class="bottomnav" aria-label="[^"]+"', html)

    def test_the_script_knows_every_screen_the_markup_declares(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        match = re.search(r"const SCREENS = \[(.*?)\];", script, re.S)
        assert match, "no SCREENS list in app.js"
        listed = set(re.findall(r'"([a-z]+)"', match.group(1)))
        assert listed == set(REQUIRED_SCREENS)


class TestAccessibility:
    def test_buttons_are_button_elements_not_divs_with_a_click_handler(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        for screen in REQUIRED_SCREENS:
            assert f'data-screen="{screen}"' in html
        assert 'role="button"' not in html, "use a real <button>, not role=button"

    def test_a_live_region_exists_for_screen_change_announcements(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        assert re.search(r'id="live-region"[^>]*aria-live="polite"', html)
        script = SCRIPT.read_text(encoding="utf-8")
        assert "live-region" in script

    def test_a_skip_link_is_present(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        assert 'class="skip-link"' in html
        assert 'href="#main"' in html
        assert 'id="main"' in html

    def test_focus_is_never_hidden(self) -> None:
        css = STYLE.read_text(encoding="utf-8")
        assert re.sub(r"\s+", "", css).find("outline:none") == -1
        assert ":focus-visible" in css


class TestTokensAreGenerated:
    def test_regenerating_the_tokens_reproduces_the_checked_in_file(self, tmp_path: Path) -> None:
        """`scripts/generate_flop_tokens.py` is the only place allowed to write this file.

        Regenerated into a scratch path rather than over the real file, so a
        failing test never leaves the working tree looking like it passed.
        """
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "generate_flop_tokens", REPO / "scripts" / "generate_flop_tokens.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        generated = module.generate()
        checked_in = TOKENS.read_text(encoding="utf-8")
        assert generated == checked_in, (
            "apps/flop/tokens.css does not match what "
            "scripts/generate_flop_tokens.py produces from ui-tokens.json -- regenerate it"
        )

    def test_tokens_css_has_no_hand_written_hex_outside_the_generator(self) -> None:
        """app.css never spells out a colour; every one comes from a custom property."""
        css = STYLE.read_text(encoding="utf-8")
        css_no_comments = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        literal_colours = re.findall(r"(?<!--)\bcolor:\s*(#[0-9a-fA-F]{3,8})", css_no_comments)
        assert literal_colours == [], f"literal colours bypass tokens.css: {literal_colours}"

    def test_app_css_loads_tokens_relatively(self) -> None:
        css = STYLE.read_text(encoding="utf-8")
        assert '@import url("tokens.css");' in css


class TestServedByTheApi:
    @pytest.fixture
    def client(self):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app
        from lineageauth.index import EventIndex

        with EventIndex() as index:
            yield TestClient(create_app(index))

    def test_the_flop_route_serves_the_page(self, client) -> None:
        response = client.get("/flop")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert "FLOP Activity Console" in response.text

    def test_the_assets_are_served_with_their_own_types(self, client) -> None:
        css = client.get("/flop/app.css")
        js = client.get("/flop/app.js")
        tokens = client.get("/flop/tokens.css")
        assert css.headers["content-type"].startswith("text/css")
        assert js.headers["content-type"].startswith("text/javascript")
        assert tokens.headers["content-type"].startswith("text/css")

    def test_the_passport_deep_link_serves_the_same_page(self, client) -> None:
        response = client.get("/flop/passport/did:key:z6MkExample")
        assert response.status_code == 200
        assert "FLOP Activity Console" in response.text

    @pytest.mark.parametrize("path", ["/flop", "/flop/app.css", "/flop/app.js", "/flop/tokens.css"])
    def test_the_strict_csp_is_applied(self, client, path: str) -> None:
        policy = client.get(path).headers["content-security-policy"]
        assert "unsafe-inline" not in policy
        assert "unsafe-eval" not in policy
        assert "default-src 'none'" in policy
        assert "script-src 'self'" in policy
        assert "connect-src 'self'" in policy

    def test_no_cors_header_is_needed_or_sent(self, client) -> None:
        for path in ("/flop", "/v1/flop/status"):
            assert "access-control-allow-origin" not in client.get(path).headers

    def test_the_demo_flag_is_off_by_default_so_mock_data_never_leaks_into_production(
        self, client
    ) -> None:
        status = client.get("/v1/flop/status").json()
        assert status["syntheticDataEnabled"] is False

    def test_the_demo_flag_turns_the_mock_adapter_on_when_asked(self) -> None:
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app
        from lineageauth.index import EventIndex

        with EventIndex() as index:
            demo_client = TestClient(create_app(index, flop_demo_mode=True))
            status = demo_client.get("/v1/flop/status").json()
            assert status["syntheticDataEnabled"] is True
