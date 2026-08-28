"""The static site published to GitHub Pages.

Publishing is the part that cannot be taken back, so most of this file is about
what the page must say before it says anything else, and about the one bug
class a static build introduces that a live one hides.

That bug class is worth naming. In live mode a server decodes the request path
before routing, so `lineage%3Ala%3A...` and `lineage:la:...` are the same
request. In static mode the route key is matched **literally**, so they are not.
The first build got this wrong: the client encodes with `encodeURIComponent`
and the builder wrote raw keys, every screen past the first failed with "not
precomputed", and nothing in the live deployment could ever have shown it.

`test_every_route_the_explorer_can_build_exists` is the cross-check. It derives
the keys the way the client does and asserts the build produced them.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

import pytest

REPO = Path(__file__).resolve().parents[1]
BUILDER = REPO / "scripts" / "build_site.py"
EXPLORER = REPO / "apps" / "explorer"


def flat(path: Path) -> str:
    """File text with runs of whitespace collapsed.

    Prose in this repository is wrapped for reading. Asserting on a phrase that
    happens to straddle a line break tests the wrapping instead of the phrase,
    and it has broken a test twice now.
    """
    return " ".join(path.read_text(encoding="utf-8").split())


@pytest.fixture(scope="module")
def site(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("site") / "build"
    done = subprocess.run(
        [sys.executable, str(BUILDER), "--out", str(out)],
        capture_output=True,
        check=False,
        cwd=str(REPO),
    )
    assert done.returncode == 0, done.stderr.decode("utf-8", errors="replace")
    return out


@pytest.fixture(scope="module")
def data(site: Path) -> dict:
    return json.loads((site / "data" / "site.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------ what it must say


class TestTheThingsAReaderMustNotGetWrong:
    def test_the_keys_are_declared_public(self, site: Path, data: dict) -> None:
        """Anybody can reproduce these signatures. Nobody should mistake them."""
        # Collapse the wrapping first. The page is wrapped for reading, and an
        # assertion that depends on where a line broke is testing the wrapping.
        page = flat(site / "index.html")
        assert "Public and reproducible" in page
        assert "No DID here belongs to anybody" in page
        assert "may be used for anything real" in page

        note = data["unsafeKeysNote"]
        assert "reproducible test keys" in note
        assert "belongs to any person or organisation" in note

    def test_the_page_verifies_in_the_browser_and_says_by_what(self, site: Path) -> None:
        """This used to say the page verified nothing. It does now.

        The claim got stronger, so the guard had to move with it -- a banner
        left saying "verifies no signature" would now be understating the page,
        which is a different failure from overstating it and just as wrong.
        """
        page = flat(site / "index.html")
        assert "Verified in your browser" in page
        assert "written to disagree" in page
        assert (site / "explorer" / "lineageauth.js").is_file()

    def test_it_still_says_what_verification_does_not_establish(self) -> None:
        """A signature covering a payload is not the signer holding authority."""
        source = (EXPLORER / "app.js").read_text(encoding="utf-8")
        assert "establishes nothing about whether" in source
        assert "signer held authority" in source

    def test_the_notice_is_scannable_rather_than_a_paragraph(self) -> None:
        """A caveat nobody finishes is a caveat that did not land.

        The first version said all of this correctly, in one dense block, at the
        top of the page. Saying it correctly and saying it readably are not the
        same thing, and only the second one works.
        """
        page = (EXPLORER / "index.html").read_text(encoding="utf-8")
        notice = page[page.index('id="snapshot"') : page.index("</aside>")]
        facts = notice.count("<li>")
        assert facts >= 3, "the notice collapsed back into prose"
        for line in re.findall(r"<li>(.*?)</li>", notice, re.S):
            assert len(" ".join(line.split())) < 130, f"one fact is a paragraph: {line[:60]}"

    def test_it_says_it_is_a_snapshot_and_stamps_when(self, data: dict) -> None:
        """A page serving stale answers as current is the thing freshness rules stop."""
        assert "static snapshot" in data["snapshotNote"].lower()
        assert re.fullmatch(r"20\d\d-\d\d-\d\dT[\d:.]+Z", data["builtAt"]), data["builtAt"]

    def test_the_builder_refuses_to_ship_a_page_missing_the_banner(self, tmp_path: Path) -> None:
        """The guard is in the builder, not only in review."""
        source = BUILDER.read_text(encoding="utf-8")
        assert "refusing to build" in source
        for required in ("Static snapshot", "Public and reproducible", "Verified in your browser"):
            assert f'"{required}"' in source or f"'{required}'" in source


# ------------------------------------------------------------ the route keys


class TestEveryQuestionTheExplorerAsksIsAnswered:
    def _routes(self, data: dict) -> dict:
        return data["routes"]

    def test_every_route_the_explorer_can_build_exists(self, data: dict) -> None:
        """Derived the way the client derives them: encodeURIComponent, then no leading slash.

        This is the cross-check that the first build failed. A live server
        decodes the path before routing; a static lookup does not, so the two
        sides have to agree on encoding and only a static build can tell.
        """
        routes = self._routes(data)
        lineage = data["routes"]["v1/lineages"]["lineages"][0]
        key = quote(lineage, safe="")

        required = [
            "v1/meta",
            "v1/lineages",
            f"v1/lineages/{key}",
            f"v1/lineages/{key}/graph",
            f"v1/exchange?lineage={key}",
            "v1/router/search",
        ]
        for path in required:
            assert path in routes, f"the Explorer would ask for {path!r} and get nothing"

    def test_the_keys_are_percent_encoded_rather_than_raw(self, data: dict) -> None:
        """The exact mistake: a raw colon where the client sends %3A."""
        routes = self._routes(data)
        lineage = routes["v1/lineages"]["lineages"][0]
        assert f"v1/lineages/{lineage}" not in routes, "raw key: the client never asks for this"
        assert f"v1/lineages/{quote(lineage, safe='')}" in routes

    def test_a_passport_and_a_did_route_exist_for_every_signer_shown(self, data: dict) -> None:
        routes = self._routes(data)
        lineage_key = quote(routes["v1/lineages"]["lineages"][0], safe="")
        dids = {k.removeprefix("v1/dids/") for k in routes if k.startswith("v1/dids/")}
        assert dids, "no DID was precomputed"
        for did in dids:
            assert f"v1/passports/{did}?lineage={lineage_key}" in routes

    def test_every_event_in_the_demo_is_fetchable(self, data: dict) -> None:
        routes = self._routes(data)
        events = [k for k in routes if k.startswith("v1/events/")]
        assert len(events) >= 10
        for key in events:
            assert "payload" in routes[key]
            assert "proofs" in routes[key]

    def test_the_dispute_route_matches_the_case_in_the_exchange(self, data: dict) -> None:
        """The Explorer reaches the dispute from the exchange listing, so they must agree."""
        routes = self._routes(data)
        lineage_key = quote(routes["v1/lineages"]["lineages"][0], safe="")
        listings = routes[f"v1/exchange?lineage={lineage_key}"]["listings"]
        cases = [c for listing in listings for c in listing["openDisputes"]]
        assert cases, "the demo has no open dispute, so that screen shows nothing"
        for case in cases:
            assert f"v1/disputes/{quote(case, safe='')}?lineage={lineage_key}" in routes

    def test_an_unprecomputed_question_says_so_rather_than_looking_empty(self) -> None:
        """An empty answer and 'not tracked' are different facts, on a static host too."""
        source = (EXPLORER / "app.js").read_text(encoding="utf-8")
        assert "was not precomputed" in source


# ------------------------------------------------------------ the shape on disk


class TestTheBuildOutput:
    def test_it_serves_from_a_path_prefix(self, site: Path) -> None:
        """A project page lives under /<repo>/, so nothing may be rooted at /.

        This is about what the built page *reaches for* relative to its own
        location. An absolute outbound link is unaffected by a path prefix and
        is checked for its destination instead, in the test below.
        """
        page = (site / "index.html").read_text(encoding="utf-8")
        references = re.findall(r'src="([^"]+)"', page)
        references += re.findall(r'<link[^>]*href="([^"]+)"', page)
        references += [h for h in re.findall(r'<a[^>]*href="([^"]+)"', page) if "://" not in h]
        assert references, "the built page references nothing at all"
        for match in references:
            assert not match.startswith("/"), f"rooted path breaks under a prefix: {match}"
            assert "://" not in match, f"external resource: {match}"

    def test_the_built_page_still_asks_for_an_outside_implementation(self, site: Path) -> None:
        """The published page is where a stranger arrives; the ask must survive the build."""
        page = (site / "index.html").read_text(encoding="utf-8")
        assert "IMPLEMENTERS_GUIDE.md" in page, "the guide link did not reach the built page"
        assert "conformance/manifest.json" in page
        assert (site / "conformance" / "manifest.json").is_file(), (
            "the page links the vectors relative to itself, so they must be published beside it"
        )

    def test_jekyll_is_disabled(self, site: Path) -> None:
        """Pages runs Jekyll by default and would drop files beginning with _."""
        assert (site / ".nojekyll").is_file()

    @pytest.mark.parametrize(
        "relative",
        [
            "index.html",
            "explorer/app.css",
            "explorer/app.js",
            "explorer/lineageauth.js",
            "data/site.json",
            "conformance/manifest.json",
            "schemas/envelope.schema.json",
        ],
    )
    def test_the_file_is_present(self, site: Path, relative: str) -> None:
        assert (site / relative).is_file()

    def test_the_conformance_package_is_published_whole(self, site: Path) -> None:
        """The point of vectors is that somebody else can fetch them."""
        manifest = json.loads((site / "conformance" / "manifest.json").read_text("utf-8"))
        for entry in manifest["vectors"]:
            assert (site / "conformance" / entry["file"]).is_file()

    def test_nothing_secret_reached_the_build(self, site: Path) -> None:
        patterns = (
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            re.compile(r'"d"\s*:\s*"[A-Za-z0-9_-]{20,}"'),
            re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
        )
        for path in site.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".json", ".html", ".js", ".css"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern in patterns:
                assert not pattern.search(text), f"{path.name} matches {pattern.pattern}"

    def test_no_private_seed_appears_anywhere_in_the_output(self, site: Path) -> None:
        """The test keys are derived from a public string; the seeds still never ship."""
        from tests.testkeys import ROOT_A, unsafe_seed

        seed = unsafe_seed(ROOT_A)
        needles = {seed.hex(), seed.hex().upper()}
        for path in site.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for needle in needles:
                assert needle not in text, f"a private seed reached {path.name}"


class TestTheStaticBuildDefendsItself:
    """A header the published copy never receives is a header that does not exist.

    `api.py` sends a strict CSP, and `tests/test_explorer.py` checks it. But the
    copy strangers load is on GitHub Pages, and static hosting cannot set
    headers -- so the policy was present exactly where nobody is attacking and
    absent on the one copy that is reachable. Found by audit, 2026-08-28.
    """

    REQUIRED = ("default-src 'none'", "script-src 'self'", "connect-src 'self'")

    def test_the_published_page_carries_the_policy_as_a_meta_tag(self, site: Path) -> None:
        page = (site / "index.html").read_text(encoding="utf-8")
        assert 'http-equiv="Content-Security-Policy"' in page, (
            "the built page has no CSP at all; GitHub Pages cannot supply one"
        )
        for directive in self.REQUIRED:
            assert directive in page, f"the meta policy is missing {directive!r}"

    def test_it_allows_no_inline_or_eval(self, site: Path) -> None:
        page = (site / "index.html").read_text(encoding="utf-8")
        policy = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', page)
        assert policy, "the meta tag is present but its content could not be read"
        assert "unsafe-inline" not in policy.group(1)
        assert "unsafe-eval" not in policy.group(1)

    def test_the_meta_policy_matches_the_header_the_api_sends(self, site: Path) -> None:
        """Two copies of one policy drift. Check the directives that must agree.

        `frame-ancestors` and `form-action` are header-only and ignored in a
        meta tag, so they are deliberately not required here -- asserting them
        would make the tag look wrong for doing what the spec says.
        """
        from lineageauth.api import EXPLORER_CSP

        page = (site / "index.html").read_text(encoding="utf-8")
        policy = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', page).group(
            1
        )
        header_only = {"frame-ancestors", "form-action"}
        for directive in EXPLORER_CSP.split(";"):
            name = directive.strip().split(" ")[0]
            if not name or name in header_only:
                continue
            assert directive.strip() in policy, (
                f"the header sends {directive.strip()!r} and the meta tag does not"
            )
