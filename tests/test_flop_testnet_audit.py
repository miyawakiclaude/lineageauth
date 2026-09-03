"""The append-only log: each line commits to the last, and secrets never enter it."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from lineageauth.errors import MalformedEventError
from lineageauth.flop.testnet.audit import (
    GENESIS_HASH,
    AuditLine,
    InMemoryAuditLog,
    JsonlAuditLog,
    verify_chain,
)

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)


class TestChaining:
    def test_the_first_line_follows_the_genesis_hash(self) -> None:
        log = InMemoryAuditLog()
        log.append("prepared", {"at": AT, "actionId": "a1"})
        assert log.entries()[0].prev == GENESIS_HASH
        assert log.entries()[0].seq == 1

    def test_each_line_commits_to_the_one_before(self) -> None:
        log = InMemoryAuditLog()
        log.append("prepared", {"at": AT, "actionId": "a1"})
        log.append("approved", {"at": AT, "actionId": "a1"})
        first, second = log.entries()
        assert second.prev == first.hash
        ok, note = log.verify_chain()
        assert ok is True, note

    def test_an_edited_line_breaks_the_chain_and_the_report_says_where(self) -> None:
        log = InMemoryAuditLog()
        log.append("prepared", {"at": AT, "actionId": "a1"})
        log.append("approved", {"at": AT, "actionId": "a1"})
        log.append("executed", {"at": AT, "actionId": "a1"})
        tampered = [
            log.entries()[0],
            AuditLine(
                seq=2,
                at=log.entries()[1].at,
                kind="approved",
                prev=log.entries()[1].prev,
                hash=log.entries()[1].hash,
                entry={"actionId": "something-else"},
            ),
            log.entries()[2],
        ]
        ok, note = verify_chain(tampered)
        assert ok is False
        assert "line 2" in note

    def test_a_removed_line_breaks_the_chain(self) -> None:
        log = InMemoryAuditLog()
        log.append("one", {"at": AT})
        log.append("two", {"at": AT})
        log.append("three", {"at": AT})
        ok, note = verify_chain((log.entries()[0], log.entries()[2]))
        assert ok is False
        assert "not contiguous" in note or "hashed to" in note

    def test_an_empty_log_verifies(self) -> None:
        ok, note = InMemoryAuditLog().verify_chain()
        assert ok is True
        assert "0 line" in note


class TestSecrets:
    def test_a_forbidden_key_is_dropped_rather_than_masked(self) -> None:
        log = InMemoryAuditLog()
        log.append("prepared", {"at": AT, "seed": "correct horse battery staple", "ok": 1})
        entry = log.entries()[0].entry
        assert "seed" not in entry
        assert entry["ok"] == 1

    def test_forbidden_keys_are_dropped_at_every_depth(self) -> None:
        log = InMemoryAuditLog()
        log.append("prepared", {"at": AT, "nested": {"privateKey": "abc", "kept": "yes"}})
        assert log.entries()[0].entry["nested"] == {"kept": "yes"}

    def test_a_secret_shaped_value_is_redacted(self) -> None:
        log = InMemoryAuditLog()
        log.append("prepared", {"at": AT, "detail": "the value is " + "a" * 64})
        assert "a" * 64 not in str(log.entries()[0].entry)
        assert "[REDACTED]" in str(log.entries()[0].entry)

    def test_bytes_are_recorded_as_a_hash_rather_than_content(self) -> None:
        log = InMemoryAuditLog()
        log.append("prepared", {"at": AT, "body": b"some request bytes"})
        assert str(log.entries()[0].entry["body"]).startswith("sha256:")


class TestTime:
    def test_an_entry_without_an_instant_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="must state the instant"):
            InMemoryAuditLog().append("prepared", {"actionId": "a1"})

    def test_the_instant_is_hoisted_out_of_the_entry(self) -> None:
        log = InMemoryAuditLog()
        log.append("prepared", {"at": AT, "actionId": "a1"})
        line = log.entries()[0]
        assert line.at == "2026-09-03T12:00:00Z"
        assert "at" not in line.entry


class TestJsonl:
    def test_lines_are_appended_with_lf_and_read_back(self, tmp_path: Path) -> None:
        path = tmp_path / "audit" / "flop.jsonl"
        log = JsonlAuditLog(path=path)
        log.append("prepared", {"at": AT, "actionId": "a1"})
        log.append("executed", {"at": AT, "actionId": "a1"})
        raw = path.read_bytes()
        assert b"\r\n" not in raw
        assert raw.count(b"\n") == 2
        assert [line.kind for line in log.entries()] == ["prepared", "executed"]
        ok, note = log.verify_chain()
        assert ok is True, note

    def test_a_missing_file_is_an_empty_log(self, tmp_path: Path) -> None:
        assert JsonlAuditLog(path=tmp_path / "nothing.jsonl").entries() == ()

    def test_reopening_continues_the_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "flop.jsonl"
        JsonlAuditLog(path=path).append("one", {"at": AT})
        second = JsonlAuditLog(path=path)
        second.append("two", {"at": AT})
        ok, _ = second.verify_chain()
        assert ok is True
        assert second.entries()[1].prev == second.entries()[0].hash
