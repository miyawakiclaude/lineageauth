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


class TestItReadsWhatTheShellActuallyWrote:
    """Found during the recovery drill, on the operator's own machine.

    `docs/RECOVERY.md` tells somebody to save a signed event to a file. On
    Windows the natural way to do that is `la sign ... > proof.json`, and
    PowerShell writes UTF-16 with a byte order mark. Read as UTF-8 that raised
    `UnicodeDecodeError` and Typer printed a traceback -- on, of all days, the
    one where the reader has already lost their root key and is following the
    runbook line by line.

    The file is not salvageable by guessing at its encoding: re-decoding it
    silently would mean the tool accepted bytes the operator did not intend to
    produce. Naming the cause and the fix is the whole remedy.
    """

    UTF16_LE = bytes([0xFF, 0xFE])
    UTF16_BE = bytes([0xFE, 0xFF])

    def test_a_powershell_redirect_is_explained_rather_than_traced(self, tmp_path) -> None:
        target = tmp_path / "redirected.json"
        target.write_bytes(self.UTF16_LE + '{"a": 1}'.encode("utf-16-le"))

        result = runner.invoke(app, ["verify", str(target)])

        assert result.exit_code == 2
        message = (result.stderr or "") + (result.stdout or "")
        assert "not UTF-8" in message
        assert "UTF-16" in message
        assert "Set-Content" in message, "the message must name the fix, not only the fault"
        assert "Traceback" not in message

    def test_a_big_endian_file_is_named_too(self, tmp_path) -> None:
        target = tmp_path / "be.json"
        target.write_bytes(self.UTF16_BE + '{"a": 1}'.encode("utf-16-be"))
        result = runner.invoke(app, ["verify", str(target)])
        assert result.exit_code == 2
        assert "UTF-16" in (result.stderr or "") + (result.stdout or "")

    def test_a_utf8_bom_is_consumed_rather_than_refused(self, tmp_path) -> None:
        """Several Windows editors add one without saying so.

        A BOM in front of the opening brace is not an encoding this tool cannot
        read; it is a stray character. Refusing the file for it would strand
        somebody whose only mistake was using Notepad.
        """
        target = tmp_path / "bom.json"
        target.write_bytes(b"\xef\xbb\xbf" + b'{"protocol": "lineageauth"}')

        result = runner.invoke(app, ["verify", str(target)])

        message = (result.stderr or "") + (result.stdout or "")
        assert "not UTF-8" not in message, "a UTF-8 BOM must not be reported as a bad encoding"
        # MALFORMED alone does not discriminate: an unparsed file and a parsed
        # one that is not an envelope both reach it. What separates them is
        # whether the JSON was read at all.
        assert "invalid JSON" not in message, (
            "the BOM reached the JSON parser, so it was not consumed on read"
        )
        assert "envelope does not match" in message, (
            "it should get as far as judging the shape of a parsed payload"
        )

    def test_ordinary_utf8_still_reads(self, tmp_path) -> None:
        """The negative control: the fix must not have broken the normal path."""
        target = tmp_path / "plain.json"
        target.write_text('{"protocol": "lineageauth"}', encoding="utf-8")
        result = runner.invoke(app, ["verify", str(target)])
        message = (result.stderr or "") + (result.stdout or "")
        assert "not UTF-8" not in message
        assert "invalid JSON" not in message
        assert "envelope does not match" in message
