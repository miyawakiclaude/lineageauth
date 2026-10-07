"""`scripts/flop_sources.py`: what it refuses, and that it refuses before fetching (D-123).

`build_sources_document` has its own tests; these hold the command line to the
same rules. Without them the `--add` checks could loosen or disappear and the
gate would still pass, and a wrong `--status` would cost twenty fetches before
the library noticed. No test here opens a connection: `fetch` is replaced in
every test that could reach it, and the replacement records what it was asked.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from lineageauth.errors import MalformedEventError

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "flop_sources_script", REPO / "scripts" / "flop_sources.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fetched(script: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[str]:
    """Every URL the script tries to fetch; the body is a stub, never the network."""
    calls: list[str] = []

    def fake_fetch(url: str) -> tuple[int, bytes]:
        calls.append(url)
        return 200, b"<p>stub</p>"

    monkeypatch.setattr(script, "fetch", fake_fetch)
    # Bodies kept by a test land in its own folder, never in the repository's.
    monkeypatch.setattr(script, "REPO", tmp_path)
    monkeypatch.setattr(script, "BODIES_ROOT", tmp_path / "bodies")
    return calls


def document() -> dict[str, object]:
    return {
        "sources": [
            {"id": "flop-finance-home", "url": "https://flop.finance/", "sha256": "sha256:aa"},
            {
                "id": "flop-finance-teaser",
                "url": "https://flop.finance/teaser/",
                "sha256": "sha256:bb",
            },
        ]
    }


class TestAddingASource:
    def test_a_new_official_page_is_accepted(self, script: ModuleType) -> None:
        added = script.parse_additions(["flop-finance-new=https://flop.finance/new/"], document())
        assert added == [
            {"id": "flop-finance-new", "url": "https://flop.finance/new/", "sha256": "new"}
        ]

    @pytest.mark.parametrize(
        ("value", "message"),
        [
            ("flop-finance-teaser=https://flop.finance/x/", "already a source"),
            ("Bad=https://flop.finance/x/", "not a valid source id"),
            ("-x=https://flop.finance/x/", "not a valid source id"),
            ("n=http://flop.finance/x/", "not an official HTTPS source"),
            ("n=https://flop.finance.example/x/", "not an official HTTPS source"),
            ("n=https://user@flop.finance/x/", "not an official HTTPS source"),
            ("n=https://flop.finance:8443/x/", "not an official HTTPS source"),
            ("n=https://github.com/flop-labs/../evil", "not an official HTTPS source"),
            ("n=https://flop.finance/", "already recorded as 'flop-finance-home'"),
            ("n=https://FLOP.finance/teaser", "already recorded as 'flop-finance-teaser'"),
        ],
    )
    def test_what_is_refused(self, script: ModuleType, value: str, message: str) -> None:
        with pytest.raises(SystemExit, match=message):
            script.parse_additions([value], document())

    def test_the_same_id_twice_is_refused_not_kept_last(self, script: ModuleType) -> None:
        with pytest.raises(SystemExit, match="more than once"):
            script.parse_additions(
                ["n=https://flop.finance/one/", "n=https://flop.finance/two/"], document()
            )

    def test_the_same_page_under_two_new_ids_is_refused(self, script: ModuleType) -> None:
        with pytest.raises(SystemExit, match="already recorded as 'a'"):
            script.parse_additions(
                ["a=https://flop.finance/new/", "b=https://flop.finance/new"], document()
            )

    def test_an_added_source_is_fetched_with_the_rest(
        self, script: ModuleType, fetched: list[str]
    ) -> None:
        additions = script.parse_additions(["n=https://flop.finance/new/"], document())
        bodies, statuses, failures = script.fetch_all(document(), additions)
        assert [body.source_id for body in bodies] == [
            "flop-finance-home",
            "flop-finance-teaser",
            "n",
        ]
        assert fetched[-1] == "https://flop.finance/new/"
        assert statuses == {}
        assert failures == []


class TestPairs:
    def test_a_repeated_id_is_refused(self, script: ModuleType) -> None:
        with pytest.raises(SystemExit, match="--status: 'a' is given more than once"):
            script.parse_pairs(["a=official-draft", "a=official-final"], flag="--status")

    def test_distinct_ids_are_kept(self, script: ModuleType) -> None:
        assert script.parse_pairs(["a=x", "b=y=z"]) == {"a": "x", "b": "y=z"}


class TestRefusedBeforeAnythingIsFetched:
    @pytest.mark.parametrize(
        ("extra", "message"),
        [
            (["--add", "flop-finance-new=https://flop.finance/new/"], "needs --status"),
            (["--status", "flop-finance-teaser=final"], "must be one of"),
            (["--status", "nosuch=official-draft"], "--status names sources that do not exist"),
            (["--hint", "nosuch=text"], "--hint names sources that do not exist"),
            (["--source-note", "nosuch=text"], "--source-note names sources"),
            (["--rule-source", "nosuch=v|2026-10-07"], "--rule-source names sources"),
            (
                [
                    "--status",
                    "flop-finance-teaser=official-draft",
                    "--status",
                    "flop-finance-teaser=official-final",
                ],
                "more than once",
            ),
            (
                [
                    "--add",
                    "dup-url=https://flop.finance/",
                    "--status",
                    "dup-url=official-reference",
                ],
                "already recorded as 'flop-finance-home'",
            ),
        ],
    )
    def test_a_bad_override_costs_no_fetch(
        self, script: ModuleType, fetched: list[str], extra: list[str], message: str
    ) -> None:
        with pytest.raises(SystemExit, match=message):
            script.main(["snapshot", "--note", "n", "--dry-run", *extra])
        assert fetched == []

    def test_a_library_refusal_still_ends_in_one_line(
        self, script: ModuleType, fetched: list[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Whatever the early checks miss reaches the user as a message, not a traceback."""

        def refuse(*args: object, **kwargs: object) -> dict[str, object]:
            raise MalformedEventError("synthetic refusal")

        monkeypatch.setattr(script, "build_sources_document", refuse)
        with pytest.raises(SystemExit, match="snapshot refused: synthetic refusal"):
            script.main(["snapshot", "--note", "n", "--dry-run", "--allow-stale"])
        assert fetched, "this path is reached only after the fetch"
