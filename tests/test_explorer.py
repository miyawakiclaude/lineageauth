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
        html = HTML.read_text(encoding="utf-8")
        for match in re.findall(r'(?:src|href)="([^"]+)"', html):
            assert match.startswith("/"), f"external or relative resource: {match}"


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
        """docs/17 excludes it from the MVP until it is separately threat-modelled."""
        source = SCRIPT.read_text(encoding="utf-8")
        for api in ("crypto.subtle", "generateKey", "getRandomValues"):
            assert api not in source


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
