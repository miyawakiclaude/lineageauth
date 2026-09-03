"""D-110: an anchored audit head is tamper-evident; an unanchored one is not, and says so."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lineageauth.builders import sign_payload
from lineageauth.bundle import EventBundle
from lineageauth.cli import app
from lineageauth.errors import MalformedEventError
from lineageauth.evidence import read_artifact
from lineageauth.flop.testnet.audit import (
    AUDIT_ANCHOR_MEDIA_TYPE,
    AuditLine,
    InMemoryAuditLog,
    anchor_payload,
    line_hash,
    read_jsonl_lines,
    verify_anchor,
    verify_chain,
)
from lineageauth.verify import verify_event
from tests.flop_testnet_fixtures import LINEAGE, ROOT

AT = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
runner = CliRunner()


def log_of(n: int) -> InMemoryAuditLog:
    log = InMemoryAuditLog()
    for i in range(n):
        log.append("prepare", {"at": AT + timedelta(minutes=i), "actionId": f"a-{i}"})
    return log


def rewritten(lines: tuple[AuditLine, ...], index: int) -> tuple[AuditLine, ...]:
    """What an editor with write access does: change one line, recompute every hash after."""
    out: list[AuditLine] = []
    prev = "sha256:" + "0" * 64
    for line in lines:
        if not out:
            prev = line.prev
        entry = dict(line.entry)
        if line.seq == index:
            entry["actionId"] = "forged"
        digest = line_hash(seq=line.seq, at=line.at, kind=line.kind, prev=prev, entry=entry)
        out.append(
            AuditLine(seq=line.seq, at=line.at, kind=line.kind, prev=prev, hash=digest, entry=entry)
        )
        prev = digest
    return tuple(out)


class TestAnchorPayload:
    def test_the_anchor_is_a_signable_artifact_whose_id_is_the_head(self) -> None:
        log = log_of(3)
        payload = anchor_payload(log.head, lineage=LINEAGE, registrant=ROOT.did, issued_at=AT)
        envelope = sign_payload(payload, [ROOT])
        assert verify_event(envelope).integrity_ok
        bundle = EventBundle.from_envelopes([envelope])
        (event,) = bundle.of_type("artifact.register")
        artifact = read_artifact(event)
        assert not isinstance(artifact, str)
        assert artifact.artifact_id == log.head
        assert artifact.media_type == AUDIT_ANCHOR_MEDIA_TYPE

    def test_an_empty_log_has_nothing_to_anchor(self) -> None:
        with pytest.raises(MalformedEventError, match="nothing to anchor"):
            anchor_payload(
                InMemoryAuditLog().head, lineage=LINEAGE, registrant=ROOT.did, issued_at=AT
            )


class TestVerifyAnchor:
    def test_an_untouched_log_matches_its_anchor(self) -> None:
        log = log_of(3)
        ok, detail = verify_anchor(log.entries(), log.head)
        assert ok and "line 3 of 3" in detail

    def test_a_rewritten_prefix_still_chains_but_no_longer_matches(self) -> None:
        """The whole point: the chain alone passes, the anchor catches it."""
        log = log_of(3)
        anchored = log.head
        forged = rewritten(log.entries(), 2)
        assert verify_chain(forged)[0] is True
        ok, detail = verify_anchor(forged, anchored)
        assert ok is False and "rewritten" in detail

    def test_lines_after_the_anchor_are_reported_not_passed(self) -> None:
        log = log_of(2)
        anchored = log.head
        log.append("execute", {"at": AT + timedelta(hours=1), "actionId": "a-late"})
        ok, detail = verify_anchor(log.entries(), anchored)
        assert ok and "1 line(s) after it are not covered" in detail

    def test_a_broken_chain_fails_before_the_anchor_is_consulted(self) -> None:
        log = log_of(2)
        lines = log.entries()
        broken = (
            lines[0],
            AuditLine(
                seq=2,
                at=lines[1].at,
                kind=lines[1].kind,
                prev="sha256:" + "f" * 64,
                hash=lines[1].hash,
                entry=lines[1].entry,
            ),
        )
        ok, detail = verify_anchor(broken, log.head)
        assert ok is False and "follows" in detail


class TestCli:
    def write(self, tmp_path: Path, lines) -> Path:  # type: ignore[no-untyped-def]
        path = tmp_path / "audit.jsonl"
        path.write_text(
            "".join(json.dumps(line.to_dict(), sort_keys=True) + "\n" for line in lines),
            encoding="utf-8",
            newline="\n",
        )
        return path

    def test_anchor_prints_an_unsigned_payload_and_signs_nothing(self, tmp_path: Path) -> None:
        log = log_of(2)
        path = self.write(tmp_path, log.entries())
        result = runner.invoke(
            app,
            [
                "flop",
                "audit",
                "anchor",
                "--log",
                str(path),
                "--lineage",
                LINEAGE,
                "--registrant",
                ROOT.did,
                "--at",
                "2026-09-03T12:00:00Z",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.stdout
        payload = json.loads(result.stdout)
        assert payload["type"] == "artifact.register"
        assert log.head in json.dumps(payload)
        assert "proofs" not in payload
        assert result.stdout.isascii()

    def test_verify_passes_the_untouched_log_and_fails_the_rewritten_one(
        self, tmp_path: Path
    ) -> None:
        log = log_of(3)
        good = self.write(tmp_path, log.entries())
        ok = runner.invoke(
            app, ["flop", "audit", "verify", "--log", str(good), "--anchor", log.head]
        )
        assert ok.exit_code == 0 and "ok" in ok.stdout and ok.stdout.isascii()
        bad = tmp_path / "bad.jsonl"
        bad.write_text(
            "".join(
                json.dumps(line.to_dict(), sort_keys=True) + "\n"
                for line in rewritten(log.entries(), 1)
            ),
            encoding="utf-8",
            newline="\n",
        )
        failed = runner.invoke(
            app, ["flop", "audit", "verify", "--log", str(bad), "--anchor", log.head]
        )
        assert failed.exit_code == 1 and "FAILED" in failed.stdout

    def test_the_reader_round_trips_what_the_log_wrote(self, tmp_path: Path) -> None:
        log = log_of(2)
        path = self.write(tmp_path, log.entries())
        assert read_jsonl_lines(path) == log.entries()
