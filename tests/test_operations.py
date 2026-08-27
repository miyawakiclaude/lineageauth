"""Running the thing: health, restore, and what depends on what.

`docs/25` asks for observability, a backup drill and a dependency audit, and
`docs/31` caps all three at zero yen. That constraint turns out to be the
useful one -- it rules out the versions of these that are a subscription and
leaves the versions that are a question you can answer offline:

    observability   does the index still agree with the store?
    backup          delete the index and see whether it comes back identical
    dependencies    what exactly is this trusting, and is that list a decision?

The third has a limit worth stating rather than papering over: a real
vulnerability audit needs a vulnerability database, which needs a network
service. There isn't one here, deliberately, so the audit that runs is the one
that can run offline -- and the tests below say what it does not cover.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pytest
from typer.testing import CliRunner

from lineageauth.builders import build_delegation_grant, build_root_create, sign_payload
from lineageauth.cli import app
from lineageauth.envelope import Envelope
from lineageauth.identifiers import derive_lineage_id
from lineageauth.index import EventIndex
from lineageauth.store import FileEventStore
from tests.testkeys import AGENT_1, ROOT_A, unsafe_signer

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "packages" / "py" / "lineageauth"

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
AT_TEXT = "2026-08-27T12:00:00Z"

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
LINEAGE: str = derive_lineage_id(ROOT.did)

runner = CliRunner()


def events() -> list[Envelope]:
    genesis = sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])
    grant = sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=AGENT.did,
            epoch=0,
            scopes=[{"namespace": "technocore", "resource": "room:lobby", "actions": ["write"]}],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            issued_at=AT,
        ),
        [ROOT],
    )
    return [genesis, grant]


@pytest.fixture
def deployment(tmp_path: Path) -> tuple[Path, Path]:
    """A store with events in it and an index built from them."""
    store_path = tmp_path / "events"
    db_path = tmp_path / "index.sqlite3"
    store = FileEventStore(store_path)
    for envelope in events():
        store.put(envelope)
    with EventIndex(str(db_path)) as index:
        index.rebuild(store)
    return store_path, db_path


# ------------------------------------------------------------ observability


class TestDoctor:
    def test_a_healthy_deployment_exits_zero(self, deployment: tuple[Path, Path]) -> None:
        store_path, db_path = deployment
        result = runner.invoke(
            app, ["doctor", str(store_path), "--db", str(db_path), "--at", AT_TEXT]
        )
        assert result.exit_code == 0
        assert "the index agrees with the store" in result.stdout

    def test_an_index_missing_an_event_is_reported_and_exits_non_zero(self, tmp_path: Path) -> None:
        store_path = tmp_path / "events"
        db_path = tmp_path / "index.sqlite3"
        store = FileEventStore(store_path)
        for envelope in events():
            store.put(envelope)
        with EventIndex(str(db_path)) as index:
            index.ingest_all(events()[:1])  # only the genesis

        result = runner.invoke(
            app, ["doctor", str(store_path), "--db", str(db_path), "--at", AT_TEXT]
        )
        assert result.exit_code == 1
        assert "not in the index" in result.stdout

    def test_an_event_the_index_has_and_the_store_does_not_is_the_loud_one(
        self, tmp_path: Path
    ) -> None:
        """The dangerous direction: something wrote to the index directly."""
        store_path = tmp_path / "events"
        db_path = tmp_path / "index.sqlite3"
        FileEventStore(store_path).put(events()[0])
        with EventIndex(str(db_path)) as index:
            index.ingest_all(events())  # both, but only one is in the store

        result = runner.invoke(
            app, ["doctor", str(store_path), "--db", str(db_path), "--at", AT_TEXT]
        )
        assert result.exit_code == 1
        assert "did not come from the store" in result.stdout

    def test_the_json_output_is_machine_readable(self, deployment: tuple[Path, Path]) -> None:
        store_path, db_path = deployment
        result = runner.invoke(
            app,
            ["doctor", str(store_path), "--db", str(db_path), "--at", AT_TEXT, "--json"],
        )
        report = json.loads(result.stdout)
        assert report["storeEvents"] == report["indexEvents"] == 2
        assert report["problems"] == []
        assert report["lineages"][0]["resolved"] is True

    def test_it_says_a_disagreement_is_not_a_reason_to_trust_the_index(
        self, deployment: tuple[Path, Path]
    ) -> None:
        store_path, db_path = deployment
        result = runner.invoke(
            app, ["doctor", str(store_path), "--db", str(db_path), "--at", AT_TEXT]
        )
        assert "never a reason to trust it" in result.stdout

    def test_it_reaches_no_network(self) -> None:
        """`docs/31`: observability that costs nothing and phones nobody."""
        source = (PACKAGE / "cli.py").read_text(encoding="utf-8")
        for sink in ("urlopen", "requests.", "httpx.", "socket."):
            assert sink not in source


# ------------------------------------------------------------ the drill


class TestRebuildDrill:
    def _run(self, store_path: Path, db_path: Path) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts" / "rebuild_drill.py"),
                str(store_path),
                "--db",
                str(db_path),
            ],
            capture_output=True,
            check=False,
            cwd=str(REPO),
        )

    def test_the_index_comes_back_identical_after_being_deleted(
        self, deployment: tuple[Path, Path]
    ) -> None:
        store_path, db_path = deployment
        done = self._run(store_path, db_path)
        out = done.stdout.decode("utf-8", errors="replace")
        assert done.returncode == 0, out + done.stderr.decode("utf-8", errors="replace")
        assert "PASS" in out
        assert "byte for byte" in out

    def test_the_index_file_is_really_deleted_first(self, deployment: tuple[Path, Path]) -> None:
        """Otherwise the drill proves the old file still exists, which nobody doubted."""
        store_path, db_path = deployment
        out = self._run(store_path, db_path).stdout.decode("utf-8", errors="replace")
        assert "deleted" in out
        assert "does not read it" in out

    def test_the_store_is_untouched(self, deployment: tuple[Path, Path]) -> None:
        store_path, db_path = deployment
        before = {p.name: p.read_bytes() for p in sorted(store_path.rglob("*")) if p.is_file()}
        self._run(store_path, db_path)
        after = {p.name: p.read_bytes() for p in sorted(store_path.rglob("*")) if p.is_file()}
        assert before == after

    def test_the_rebuilt_index_still_answers(self, deployment: tuple[Path, Path]) -> None:
        store_path, db_path = deployment
        self._run(store_path, db_path)
        result = runner.invoke(
            app, ["doctor", str(store_path), "--db", str(db_path), "--at", AT_TEXT]
        )
        assert result.exit_code == 0


# ------------------------------------------------------------ dependencies


class TestDependencyAudit:
    """What this trusts at runtime, and why each one is there.

    The list is short because every entry is a decision. Anything added has to
    be added here too, which is the point: a dependency that arrives without
    anybody noticing is the one that will not be looked at again.
    """

    RUNTIME_REASONS: ClassVar[dict[str, str]] = {
        "pydantic": "envelope shape validation, and it refuses unknown fields for us",
        "cryptography": "Ed25519. Never hand-rolled",
        "rfc8785": "JCS canonicalization. Never hand-rolled -- one byte of "
        "disagreement changes every event id",
        "base58": "multibase base58btc for did:key",
        "typer": "the CLI, which is the offline verifier -- docs/22 requires "
        "verification to work with no network and no service",
    }

    def _declared(self) -> dict[str, list[str]]:
        project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        return {
            "runtime": list(project["dependencies"]),
            **{k: list(v) for k, v in project.get("optional-dependencies", {}).items()},
        }

    @staticmethod
    def _names(requirements: list[str]) -> set[str]:
        return {r.split(">")[0].split("=")[0].split("[")[0].strip().lower() for r in requirements}

    def test_the_runtime_dependency_set_is_exactly_what_is_accounted_for(self) -> None:
        assert self._names(self._declared()["runtime"]) == set(self.RUNTIME_REASONS)

    def test_every_runtime_dependency_has_a_stated_reason(self) -> None:
        for name, reason in self.RUNTIME_REASONS.items():
            assert len(reason) > 15, name

    def test_the_two_that_must_never_be_hand_rolled_are_dependencies(self) -> None:
        """JCS and Ed25519. A checker that disagrees with the spec is worse than none."""
        runtime = self._names(self._declared()["runtime"])
        assert "rfc8785" in runtime
        assert "cryptography" in runtime

    def test_the_optional_extras_are_not_needed_by_the_core(self) -> None:
        for extra in ("api", "mcp"):
            assert self._names(self._declared()[extra]) & set(self.RUNTIME_REASONS) == set()

    def test_every_dependency_is_installed_and_reports_a_version(self) -> None:
        from importlib.metadata import PackageNotFoundError, version

        for name in self.RUNTIME_REASONS:
            try:
                assert version(name)
            except PackageNotFoundError:  # pragma: no cover - a broken environment
                pytest.fail(f"{name} is declared and not installed")

    def test_the_lockfile_exists_so_the_set_is_reproducible(self) -> None:
        assert (REPO / "uv.lock").is_file()

    def test_what_this_audit_does_not_cover_is_written_down(self) -> None:
        """A vulnerability database is a network service, and there is not one here.

        Saying so is the honest version. An audit that quietly checks nothing
        about known vulnerabilities, while being called an audit, is worse than
        no audit at all.
        """
        runbook = (REPO / "RUNBOOK.md").read_text(encoding="utf-8")
        assert "vulnerability database" in runbook
