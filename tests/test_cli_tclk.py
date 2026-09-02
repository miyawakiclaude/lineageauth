"""`la tclk inspect | simulate | authorize | prepare`.

Read-only by construction: the test that matters most is the one asserting the
command group has no `send`, `publish`, `lock`, `claim`, `refund`, `reveal` or
`pay` -- a CLI is the surface an operator reaches for, and the safe direction
has to be the only one that exists.
"""

from __future__ import annotations

import hashlib
import json
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lineageauth.adapters import tclk
from lineageauth.builders import build_delegation_grant, build_root_create, sign_payload
from lineageauth.cli import app
from lineageauth.envelope import Envelope
from lineageauth.timeutil import format_instant
from tests.testkeys import AGENT_1, RECOVERY_1, ROOT_A, unsafe_signer

runner = CliRunner()

AT = datetime(2026, 9, 2, 12, 0, 0, tzinfo=UTC)
AT_TEXT = format_instant(AT)
T0 = 1_756_700_000_000

ROOT = unsafe_signer(ROOT_A)
PAYER = unsafe_signer(AGENT_1)
PAYEE = unsafe_signer(RECOVERY_1)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

PREIMAGE = "0x" + "11" * 32
STATEMENT = "0x" + hashlib.sha256(bytes.fromhex("11" * 32)).hexdigest()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("la tclk must not touch the network")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def offer_line() -> str:
    fields = {
        "type": "offer",
        "from": PAYER.did,
        "role": "payer",
        "amount": "1000000",
        "asset": "FLOP",
        "lock": "hash",
        "rails": ["flop-htlc", "x402"],
        "claimByMs": T0 + 3_600_000,
        "refundAfterMs": T0 + 7_200_000,
        "expiresMs": T0 + 600_000,
        "nonce": "9f2c81d04c9e1f7a",
    }
    fields["id"] = tclk.offer_id(fields)
    return tclk.encode_frame(fields)


def transcript() -> list[str]:
    of = tclk.decode_frame(offer_line())
    core = {
        "from": PAYEE.did,
        "ref": of.fields["id"],
        "statement": STATEMENT,
        "nonce": "0011223344556677",
    }
    accept = tclk.encode_frame(
        {"type": "accept", **core, "contract": tclk.contract_id(of.fields, core)}
    )
    contract = tclk.decode_frame(accept).contract
    assert contract is not None
    lock = tclk.encode_frame(
        {"type": "lock", "from": PAYER.did, "contract": contract, "rail": "x402", "ref": "escrow-1"}
    )
    reveal = tclk.encode_frame(
        {"type": "reveal", "from": PAYEE.did, "contract": contract, "secret": PREIMAGE}
    )
    return [of.line, accept, lock, reveal]


def write_bundle(path: Path, envelopes: list[Envelope]) -> str:
    path.write_text(
        json.dumps([json.loads(e.model_dump_json()) for e in envelopes]), encoding="utf-8"
    )
    return str(path)


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(room: str = tclk.OFFER_ROOM) -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=PAYER.did,
            epoch=0,
            scopes=[{"namespace": "technocore", "resource": f"room:{room}", "actions": ["write"]}],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            issued_at=AT,
        ),
        [ROOT],
    )


class TestTheGroupIsReadOnly:
    def test_no_value_moving_command_exists(self) -> None:
        result = runner.invoke(app, ["tclk", "--help"])
        assert result.exit_code == 0
        for verb in ("send", "publish", "lock", "claim", "refund", "reveal", "pay"):
            assert f"\n  {verb} " not in result.output and f"│ {verb} " not in result.output, verb
        for verb in ("inspect", "simulate", "authorize", "prepare"):
            assert verb in result.output


class TestInspect:
    def test_a_valid_frame_is_parsed_and_labelled(self, tmp_path: Path) -> None:
        path = tmp_path / "offer.txt"
        path.write_text(offer_line(), encoding="utf-8")
        result = runner.invoke(app, ["tclk", "inspect", str(path)])
        assert result.exit_code == 0, result.output
        assert "PARSED" in result.output and "not authority" in result.output
        as_json = runner.invoke(app, ["tclk", "inspect", str(path), "--json"])
        assert json.loads(as_json.output)["room"] == tclk.OFFER_ROOM

    def test_a_malformed_line_exits_one(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.txt"
        path.write_text('tclk1 {"type":"offer"}', encoding="utf-8")
        result = runner.invoke(app, ["tclk", "inspect", str(path)])
        assert result.exit_code == 1 and "refused" in result.output

    def test_two_lines_are_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "two.txt"
        path.write_text(offer_line() + "\n" + offer_line(), encoding="utf-8")
        assert runner.invoke(app, ["tclk", "inspect", str(path)]).exit_code == 2


class TestSimulate:
    def test_a_transcript_folds_to_claimed(self, tmp_path: Path) -> None:
        path = tmp_path / "t.json"
        path.write_text(json.dumps(transcript()), encoding="utf-8")
        result = runner.invoke(app, ["tclk", "simulate", str(path), "--now", str(T0 + 1), "--json"])
        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert body["status"] == "claimed" and body["a2a"] == "completed"
        assert body["evidence"]["secretRevealed"] is True
        assert "money" in " ".join(body["evidence"]["doesNotProve"])

    def test_rejected_steps_are_shown_not_hidden(self, tmp_path: Path) -> None:
        lines = transcript()
        lines.insert(2, lines[1])  # replayed accept
        path = tmp_path / "t.txt"
        path.write_text("\n".join(lines), encoding="utf-8")
        result = runner.invoke(app, ["tclk", "simulate", str(path), "--now", str(T0 + 1)])
        assert result.exit_code == 0, result.output
        assert "ignored" in result.output and "status       claimed" in result.output


class TestAuthorize:
    def test_allowed_with_a_room_grant(self, tmp_path: Path) -> None:
        bundle = write_bundle(tmp_path / "b.json", [genesis(), grant()])
        frame = tmp_path / "offer.txt"
        frame.write_text(offer_line(), encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "tclk",
                "authorize",
                bundle,
                "--agent",
                PAYER.did,
                "--frame",
                str(frame),
                "--at",
                AT_TEXT,
            ],
        )
        assert result.exit_code == 0, result.output
        assert "ALLOWED" in result.output and "spend-limit" in result.output

    def test_not_allowed_without_one_and_json_names_the_gaps(self, tmp_path: Path) -> None:
        bundle = write_bundle(tmp_path / "b.json", [genesis()])
        frame = tmp_path / "offer.txt"
        frame.write_text(offer_line(), encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "tclk",
                "authorize",
                bundle,
                "--agent",
                PAYER.did,
                "--frame",
                str(frame),
                "--at",
                AT_TEXT,
                "--json",
            ],
        )
        assert result.exit_code == 1
        body = json.loads(result.output)
        assert body["reason"] == "DENIED" and "settlement" in body["unchecked"]

    def test_a_malformed_frame_never_reaches_the_bundle(self, tmp_path: Path) -> None:
        bundle = write_bundle(tmp_path / "b.json", [genesis(), grant()])
        frame = tmp_path / "bad.txt"
        frame.write_text("tclk2 {}", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "tclk",
                "authorize",
                bundle,
                "--agent",
                PAYER.did,
                "--frame",
                str(frame),
                "--at",
                AT_TEXT,
                "--json",
            ],
        )
        assert result.exit_code == 1
        assert json.loads(result.output)["reason"] == "UNKNOWN_VERSION"


class TestPrepare:
    def test_prints_the_bytes_the_hash_and_the_challenge_and_sends_nothing(
        self, tmp_path: Path
    ) -> None:
        frame = tmp_path / "offer.txt"
        frame.write_text(offer_line(), encoding="utf-8")
        result = runner.invoke(
            app, ["tclk", "prepare", str(frame), "--nonce", "1756700000000", "--json"]
        )
        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert body["sent"] is False
        assert body["contentHash"] == "sha256:" + hashlib.sha256(offer_line().encode()).hexdigest()
        assert body["signingChallenge"].startswith(f"{tclk.OFFER_ROOM}|1756700000000|tclk1 ")
        human = runner.invoke(app, ["tclk", "prepare", str(frame)])
        assert "NOT SENT" in human.output and "no rail is touched" in human.output
