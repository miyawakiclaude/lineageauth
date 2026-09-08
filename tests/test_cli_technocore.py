"""`la technocore delegations`: the delegation reader from the command line."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from lineageauth.adapters.technocore.delegation import signing_message
from lineageauth.cli import app
from tests.testkeys import AGENT_1, OUTSIDER, ROOT_A, unsafe_signer

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
STRANGER = unsafe_signer(OUTSIDER)
AT = "2026-09-08T12:00:00Z"
EXPIRES = str(int((datetime(2026, 9, 8, tzinfo=UTC) + timedelta(days=30)).timestamp()))

runner = CliRunner()


def record(*, nonce: str = "5", scope: str = "*", signer=ROOT) -> str:  # type: ignore[no-untyped-def]
    sig = signer.sign_b64u(signing_message(ROOT.did, AGENT.did, scope, EXPIRES, nonce).encode())
    return f"delegate: {AGENT.did} {scope} {EXPIRES} {nonce} {sig}"


def note(tmp_path: Path, body: str) -> str:
    path = tmp_path / "note.txt"
    path.write_text(body, encoding="utf-8")
    return str(path)


class TestDelegations:
    def test_a_live_record_prints_ok_and_exits_zero(self, tmp_path: Path) -> None:
        path = note(tmp_path, f"mailbox: mb-x {record()}")
        result = runner.invoke(
            app, ["technocore", "delegations", "--root", ROOT.did, "--note", path, "--at", AT]
        )
        assert result.exit_code == 0, result.output
        assert "OK" in result.output and "1 live delegation(s)" in result.output
        assert "not a LineageAuth grant" in result.output
        assert result.output.isascii()

    def test_issue_782_a_forged_high_nonce_does_not_hide_the_real_grant(
        self, tmp_path: Path
    ) -> None:
        forged = f"delegate: {AGENT.did} r:lobby {EXPIRES} 999 " + "A" * 86
        path = note(tmp_path, record(nonce="5") + " " + forged)
        result = runner.invoke(
            app, ["technocore", "delegations", "--root", ROOT.did, "--note", path, "--at", AT]
        )
        assert result.exit_code == 0
        lines = [
            line for line in result.output.splitlines() if line.strip().startswith(("OK", "FORGED"))
        ]
        assert lines[0].strip().startswith("OK") and lines[1].strip().startswith("FORGED")
        assert "SUPERSEDED" not in result.output

    def test_nothing_live_exits_one_but_still_prints_every_verdict(self, tmp_path: Path) -> None:
        path = note(tmp_path, record(signer=STRANGER))
        result = runner.invoke(
            app, ["technocore", "delegations", "--root", ROOT.did, "--note", path, "--at", AT]
        )
        assert result.exit_code == 1
        assert "FORGED" in result.output and "0 live delegation(s)" in result.output

    def test_json_carries_every_record_and_the_note_path(self, tmp_path: Path) -> None:
        path = note(tmp_path, record())
        result = runner.invoke(
            app,
            ["technocore", "delegations", "--root", ROOT.did, "--note", path, "--at", AT, "--json"],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["notePath"].startswith("/kv/did-")
        assert body["live"] == 1
        assert body["records"][0]["verdict"] == "OK"
        assert "creates no LAP authority" in body["note"]

    def test_a_root_that_is_not_a_key_is_a_usage_error(self, tmp_path: Path) -> None:
        path = note(tmp_path, record())
        result = runner.invoke(
            app, ["technocore", "delegations", "--root", "did:key:zNope", "--note", path]
        )
        assert result.exit_code == 2
