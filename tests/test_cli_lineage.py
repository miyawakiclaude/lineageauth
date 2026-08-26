"""`la lineage show` exit codes and output.

The exit code is the contract CI gates on: 0 resolved, 1 unresolved, 2 the
bundle could not be read. A conflict must never exit 0.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lineageauth.cli import app
from tests.test_lineage import AT, LINEAGE, NEXT_ROOT, RIVAL_ROOT, ROOT, genesis, succession

runner = CliRunner()


def _bundle_file(tmp_path: Path, *envelopes: object, name: str = "bundle.json") -> str:
    path = tmp_path / name
    path.write_text(
        json.dumps([json.loads(e.to_json(indent=None)) for e in envelopes]),  # type: ignore[attr-defined]
        encoding="utf-8",
    )
    return str(path)


def test_show_resolves_and_exits_zero(tmp_path: Path) -> None:
    path = _bundle_file(tmp_path, genesis(), succession())

    result = runner.invoke(app, ["lineage", "show", path, "--at", "2026-08-26T09:00:00Z", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["root"] == NEXT_ROOT.did
    assert payload["epoch"] == 1
    assert payload["evaluatedAt"] == "2026-08-26T09:00:00Z"
    assert payload["supersededRoots"] == [ROOT.did]
    assert "no revocation" in payload["note"]


def test_show_exits_one_on_a_conflict(tmp_path: Path) -> None:
    left, right = succession(to_root=NEXT_ROOT), succession(to_root=RIVAL_ROOT)
    path = _bundle_file(tmp_path, genesis(), left, right)

    result = runner.invoke(app, ["lineage", "show", path, "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["reason"] == "CONFLICTED"
    assert payload["conflictingEventIds"] == sorted([left.event_id, right.event_id])


def test_human_output_always_states_the_superseded_caveat(tmp_path: Path) -> None:
    path = _bundle_file(tmp_path, genesis(), succession())

    result = runner.invoke(app, ["lineage", "show", path, "--lineage", LINEAGE])

    assert result.exit_code == 0
    assert "no revocation" in result.stdout
    assert LINEAGE in result.stdout


def test_jsonl_bundles_are_accepted(tmp_path: Path) -> None:
    path = tmp_path / "bundle.jsonl"
    path.write_text(
        "\n".join(e.to_json(indent=None) for e in (genesis(), succession())),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["lineage", "show", str(path), "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["epoch"] == 1


def test_an_unreadable_bundle_exits_two(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    assert runner.invoke(app, ["lineage", "show", str(path)]).exit_code == 2
    assert runner.invoke(app, ["lineage", "show", str(tmp_path / "missing.json")]).exit_code == 2


def test_an_ambiguous_bundle_demands_an_explicit_lineage(tmp_path: Path) -> None:
    from lineageauth.builders import build_root_create, sign_payload
    from tests.testkeys import ROOT_B, unsafe_signer

    other = unsafe_signer(ROOT_B)
    other_genesis = sign_payload(build_root_create(root_did=other.did, issued_at=AT), [other])
    path = _bundle_file(tmp_path, genesis(), other_genesis)

    result = runner.invoke(app, ["lineage", "show", path])

    assert result.exit_code == 2
