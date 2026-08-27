"""The Explorer.

`docs/17` lists five security requirements for the UI and four of them are
checkable from here: escape untrusted content, strict CSP, no auto-open links,
no secrets in localStorage. The fifth -- no browser key generation -- is
checked by the page having no crypto in it at all.

The one that matters most is the first. This page displays room names, task
titles, dispute statements and profile text, every one of them written by
somebody else. The builders refuse control characters, but that is a different
defence at a different layer. A viewer that executed what it displayed would be
a worse problem than anything it was built to show, so the test below reads the
source and fails on any construct that could turn a string into markup.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EXPLORER = REPO / "apps" / "explorer"
HTML = EXPLORER / "index.html"
SCRIPT = EXPLORER / "app.js"
STYLE = EXPLORER / "app.css"

# Anything that turns a string into markup, or a string into code.
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

# docs/17: never say these.
FORBIDDEN_STATUS_LANGUAGE = ("trusted human", "official", "guaranteed safe")

# docs/17: the vocabulary a status is allowed to use.
REQUIRED_STATUS_LANGUAGE = ("valid authority chain", "superseded")


# The only destinations an anchor on this page may name. A link a person chooses
# to follow is not a resource this page loads, but it is still a place this page
# sends somebody, so the set is written down rather than merely same-origin.
ALLOWED_LINK_PREFIXES = ("https://github.com/miyawakiclaude/lineageauth/",)


class TestUntrustedContentIsNeverMarkup:
    def test_the_script_uses_no_markup_sink(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        found = [sink for sink in MARKUP_SINKS if sink in source]
        assert found == [], f"the Explorer must not be able to render markup: {found}"

    def test_text_reaches_the_dom_only_through_textContent(self) -> None:
        """One helper writes text, so there is one place to get this right."""
        source = SCRIPT.read_text(encoding="utf-8")
        assert source.count("textContent") >= 1
        assert "createElement" in source

    def test_the_page_carries_no_inline_script_or_style(self) -> None:
        """Which is why its CSP needs no 'unsafe-inline'."""
        html = HTML.read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\bsrc=)", html)
        assert "<style" not in html
        assert not re.search(r"\son\w+\s*=", html), "no inline event handler attributes"

    def test_nothing_is_loaded_from_another_origin(self) -> None:
        """Same origin, and relative rather than rooted.

        The rule used to be "must start with /", which was wrong once this page
        had to work under a path prefix as well as at a domain root: a leading
        slash reaches for the root and breaks on a project page. What actually
        matters is that no reference names another host.

        Subresources only. An `<a href>` is a place a reader may choose to go,
        not a thing this page fetches, and conflating the two would either ban
        every outbound link or let a script-loading host in through the same
        rule. They are checked separately, and more specifically, below.
        """
        html = HTML.read_text(encoding="utf-8")
        subresources = re.findall(r'src="([^"]+)"', html)
        subresources += re.findall(r'<link[^>]*href="([^"]+)"', html)
        assert subresources, "the page loads a stylesheet and a script; found neither"
        for match in subresources:
            assert "://" not in match, f"external resource: {match}"
            assert not match.startswith("//"), f"protocol-relative resource: {match}"
            assert not match.startswith("/"), f"rooted path breaks under a prefix: {match}"

    def test_every_outbound_link_is_one_this_project_chose(self) -> None:
        """Anchors may leave, but only to destinations written down here."""
        html = HTML.read_text(encoding="utf-8")
        for href in re.findall(r'<a[^>]*href="([^"]+)"', html):
            if "://" not in href:
                assert not href.startswith("/"), f"rooted path breaks under a prefix: {href}"
                continue
            assert href.startswith(ALLOWED_LINK_PREFIXES), f"unlisted destination: {href}"

    def test_no_link_opens_a_new_window(self) -> None:
        """`target=_blank` hands the opened page a handle back to this one."""
        html = HTML.read_text(encoding="utf-8")
        assert "target=" not in html

    def test_no_link_is_built_from_data(self) -> None:
        """A literal anchor is a decision; an anchor from a feed is an injection."""
        source = SCRIPT.read_text(encoding="utf-8")
        for api in ("href", 'createElement("a")', "createElement('a')"):
            assert api not in source, f"the script constructs links: {api}"

    def test_no_request_is_rooted_at_the_domain(self) -> None:
        """A rooted path silently drops the project-page prefix."""
        source = SCRIPT.read_text(encoding="utf-8")
        assert 'fetch("/' not in source
        assert "fetch('/" not in source


class TestTheAskIsActuallyReadable:
    """A request nobody can read is the same as a request nobody made.

    `footer p` is set to a deliberately dim grey. That is a reasonable choice
    for a note that exists to be available rather than consumed, and a poor one
    for the single thing this project is asking a stranger to do. The numbers
    are pinned here because a colour token is exactly the kind of thing that
    gets tidied back to matching its neighbours.
    """

    @staticmethod
    def _channel(value: float) -> float:
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    @classmethod
    def _luminance(cls, hex_colour: str) -> float:
        raw = hex_colour.lstrip("#")
        r, g, b = (cls._channel(int(raw[i : i + 2], 16) / 255) for i in (0, 2, 4))
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    @classmethod
    def _contrast(cls, a: str, b: str) -> float:
        high, low = sorted((cls._luminance(a), cls._luminance(b)), reverse=True)
        return (high + 0.05) / (low + 0.05)

    @staticmethod
    def _token(name: str) -> str:
        css = STYLE.read_text(encoding="utf-8")
        match = re.search(rf"--{name}:\s*(#[0-9a-fA-F]{{6}})", css)
        assert match, f"palette token --{name} is gone"
        return match.group(1)

    def test_the_ask_uses_the_body_token_and_not_the_footer_grey(self) -> None:
        css = STYLE.read_text(encoding="utf-8")
        rule = re.search(r"footer \.ask \{([^}]*)\}", css)
        assert rule, "the ask has no styling of its own, so it inherits the dim note"
        assert "color: var(--body)" in rule.group(1)

    def test_the_ask_clears_wcag_aa_against_the_page(self) -> None:
        ratio = self._contrast(self._token("body"), self._token("bg"))
        assert ratio >= 4.5, f"the ask sits at {ratio:.2f}:1 against the page background"

    def test_its_links_clear_wcag_aa_too(self) -> None:
        ratio = self._contrast(self._token("accent"), self._token("bg"))
        assert ratio >= 4.5, f"the ask's links sit at {ratio:.2f}:1"

    def test_the_ask_is_not_set_in_fine_print(self) -> None:
        css = STYLE.read_text(encoding="utf-8")
        ask = re.search(r"footer \.ask \{([^}]*)\}", css).group(1)
        note = re.search(r"footer p \{([^}]*)\}", css).group(1)
        ask_size = float(re.search(r"font-size:\s*([\d.]+)rem", ask).group(1))
        note_size = float(re.search(r"font-size:\s*([\d.]+)rem", note).group(1))
        assert ask_size > note_size, (
            f"the ask ({ask_size}rem) is no larger than the footnote ({note_size}rem)"
        )


class TestItKeepsNoSecretsAndOpensNothing:
    def test_no_storage_is_touched(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for api in ("localStorage", "sessionStorage", "indexedDB", "document.cookie"):
            assert api not in source

    def test_no_link_is_opened_and_no_navigation_is_performed(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for api in ("window.open", "location.href", "location.assign", "location.replace"):
            assert api not in source

    def test_no_key_material_is_generated_in_the_browser(self) -> None:
        """docs/17 excludes key generation from the MVP. Verification is not that.

        The page now *verifies* in the browser, which needs `crypto.subtle`, so
        the old blanket ban on that name was measuring the wrong thing. What
        docs/17 actually excludes is producing key material, and that is what is
        checked: no keypair generation, no randomness, nothing private.
        """
        sources = [
            SCRIPT.read_text(encoding="utf-8"),
            (REPO / "packages" / "js" / "lineageauth.js").read_text(encoding="utf-8"),
        ]
        for source in sources:
            for api in ("generateKey", "getRandomValues", "exportKey", "privateKey"):
                assert api not in source

    def test_the_verifier_only_ever_verifies(self) -> None:
        """It imports a verify usage and nothing else."""
        source = (REPO / "packages" / "js" / "lineageauth.js").read_text(encoding="utf-8")
        assert '"verify"' in source
        assert '"sign"' not in source


class TestStatusLanguage:
    def test_the_forbidden_words_appear_nowhere(self) -> None:
        for path in (HTML, SCRIPT, STYLE):
            text = path.read_text(encoding="utf-8").lower()
            for phrase in FORBIDDEN_STATUS_LANGUAGE:
                assert phrase not in text, f"{path.name} says {phrase!r}"

    def test_the_required_words_are_used(self) -> None:
        source = (HTML.read_text(encoding="utf-8") + SCRIPT.read_text(encoding="utf-8")).lower()
        for phrase in REQUIRED_STATUS_LANGUAGE:
            assert phrase in source

    def test_the_page_says_it_verifies_nothing(self) -> None:
        """A viewer that looks like a verifier gets believed like one."""
        html = HTML.read_text(encoding="utf-8")
        assert "holds no keys" in html
        assert "cannot make any event" in html

    def test_it_repeats_that_provenance_is_not_permission(self) -> None:
        html = HTML.read_text(encoding="utf-8")
        assert "provenance, never permission" in html


class TestServedByTheApi:
    @pytest.fixture
    def client(self):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app
        from lineageauth.index import EventIndex

        with EventIndex() as index:
            yield TestClient(create_app(index))

    def test_the_root_serves_the_page(self, client) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert "LineageAuth Explorer" in response.text

    def test_the_assets_are_served_with_their_own_types(self, client) -> None:
        css = client.get("/explorer/app.css")
        js = client.get("/explorer/app.js")
        assert css.headers["content-type"].startswith("text/css")
        assert js.headers["content-type"].startswith("text/javascript")

    @pytest.mark.parametrize("path", ["/", "/explorer/app.css", "/explorer/app.js"])
    def test_the_strict_csp_is_applied_and_allows_no_inline_code(self, client, path: str) -> None:
        policy = client.get(path).headers["content-security-policy"]
        assert "unsafe-inline" not in policy
        assert "unsafe-eval" not in policy
        assert "default-src 'none'" in policy
        assert "script-src 'self'" in policy
        assert "connect-src 'self'" in policy
        assert "frame-ancestors 'none'" in policy
        assert "form-action 'none'" in policy

    def test_the_api_keeps_its_own_stricter_policy(self, client) -> None:
        """The Explorer's looser policy must not leak onto the data endpoints."""
        policy = client.get("/v1/meta").headers["content-security-policy"]
        assert "script-src" not in policy
        assert policy.startswith("default-src 'none'")

    def test_the_page_is_same_origin_so_no_cors_header_is_needed(self, client) -> None:
        """A read-only API that hands out no cross-origin permission has none to misuse."""
        for path in ("/", "/v1/meta"):
            assert "access-control-allow-origin" not in client.get(path).headers
