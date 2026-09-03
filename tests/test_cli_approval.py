"""`la approval draft` and `la execute`.

`docs/06` is the exact-action approval layer and `docs/17` says what a human
must be shown before consenting. This is the surface where those two meet, so
the tests are mostly about what the operator sees and what a mistake costs:
the preview names every field the approval binds, the draft cannot approve
anything because it is unsigned, and a preview cannot burn a receipt.

The last one is the reason `--dry-run` is the default. Reserving is a commit
point -- once spent, the approver has to approve again -- so the safe direction
has to be the one you get by not thinking about it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lineageauth.actions import ActionRequest, sha256_hex
from lineageauth.builders import (
    build_approval_receipt,
    build_delegation_grant,
    build_root_create,
    sign_payload,
)
from lineageauth.cli import app
from lineageauth.envelope import Envelope
from lineageauth.identifiers import derive_lineage_id
from lineageauth.timeutil import format_instant
from tests.testkeys import AGENT_1, OUTSIDER, ROOT_A, unsafe_signer

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
AT_TEXT = format_instant(AT)

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE: str = derive_lineage_id(ROOT.did)

ROOM = "room:lobby"
DESTINATION = "https://technocore.chat/r/lobby"
CONTENT = sha256_hex(b"hello from an agent")

runner = CliRunner()


def request() -> ActionRequest:
    return ActionRequest(
        namespace="technocore",
        resource=ROOM,
        action="write",
        destination=DESTINATION,
        content_hash=CONTENT,
    )


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, approval: str = "required") -> Envelope:
    payload = build_delegation_grant(
        lineage=LINEAGE,
        issuer=ROOT.did,
        subject=AGENT.did,
        epoch=0,
        scopes=[{"namespace": "technocore", "resource": ROOM, "actions": ["write"]}],
        not_before=AT - timedelta(days=1),
        expires_at=AT + timedelta(days=30),
        max_depth=0,
        approval=approval,
        approvers=[ROOT.did] if approval != "none" else None,
        issued_at=AT,
    )
    return sign_payload(payload, [ROOT])


def receipt(*, approver=ROOT, nonce: bytes = b"n" * 32) -> Envelope:
    payload = build_approval_receipt(
        lineage=LINEAGE,
        approver=approver.did,
        agent=AGENT.did,
        request=request(),
        nonce=nonce,
        expires_at=AT + timedelta(minutes=10),
        issued_at=AT,
    )
    return sign_payload(payload, [approver])


def bundle_file(tmp_path: Path, *envelopes: Envelope) -> str:
    path = tmp_path / "bundle.json"
    path.write_text(
        json.dumps([json.loads(e.to_json()) for e in envelopes], indent=2),
        encoding="utf-8",
    )
    return str(path)


def execute_args(bundle: str, **overrides: str) -> list[str]:
    args = {
        "--lineage": LINEAGE,
        "--agent": AGENT.did,
        "--namespace": "technocore",
        "--resource": ROOM,
        "--action": "write",
        "--destination": DESTINATION,
        "--content-hash": CONTENT,
        "--at": AT_TEXT,
    }
    args.update(overrides)
    flat: list[str] = ["execute", bundle]
    for key, value in args.items():
        flat.extend([key, value])
    return flat


# ------------------------------------------------------------ the draft


class TestDraft:
    def _draft(self, *extra: str):
        return runner.invoke(
            app,
            [
                "approval",
                "draft",
                "--lineage",
                LINEAGE,
                "--approver",
                ROOT.did,
                "--agent",
                AGENT.did,
                "--namespace",
                "technocore",
                "--resource",
                ROOM,
                "--action",
                "write",
                "--destination",
                DESTINATION,
                "--content-hash",
                CONTENT,
                "--at",
                AT_TEXT,
                *extra,
            ],
        )

    def test_it_prints_every_field_a_human_has_to_see(self) -> None:
        """docs/17 lists them. All of them, or the consent is uninformed."""
        result = self._draft()
        assert result.exit_code == 0
        for expected in (
            AGENT.did,
            ROOT.did,
            "technocore",
            ROOM,
            "write",
            DESTINATION,
            CONTENT,
            "request hash",
            "expires",
        ):
            assert expected in result.stdout

    def test_the_draft_says_it_is_unsigned_and_grants_nothing(self) -> None:
        result = self._draft()
        assert "UNSIGNED" in result.stdout
        assert "grants nothing" in result.stdout

    def test_the_payload_is_a_receipt_that_carries_no_proof(self) -> None:
        result = self._draft()
        start = result.stdout.index("{")
        end = result.stdout.rindex("}") + 1
        payload = json.loads(result.stdout[start:end])
        assert payload["type"] == "approval.receipt"
        assert "proofs" not in payload

    def test_two_drafts_of_the_same_action_differ(self) -> None:
        """Because the nonce is fresh. A reused nonce is a replayable approval."""
        first, second = self._draft(), self._draft()
        assert first.stdout != second.stdout

    def test_a_zero_expiry_is_refused(self) -> None:
        result = self._draft("--expires-in", "0")
        assert result.exit_code == 2

    def test_an_unknown_action_is_refused_rather_than_drafted(self) -> None:
        result = runner.invoke(
            app,
            [
                "approval",
                "draft",
                "--lineage",
                LINEAGE,
                "--approver",
                ROOT.did,
                "--agent",
                AGENT.did,
                "--namespace",
                "technocore",
                "--resource",
                ROOM,
                "--action",
                "detonate",
                "--destination",
                DESTINATION,
                "--content-hash",
                CONTENT,
            ],
        )
        assert result.exit_code == 2
        assert "refused" in result.stdout + str(result.stderr)


# ------------------------------------------------------------ execute


class TestExecute:
    def test_a_matching_receipt_allows_the_exact_action(self, tmp_path: Path) -> None:
        path = bundle_file(tmp_path, genesis(), grant(), receipt())
        result = runner.invoke(app, execute_args(path))
        assert result.exit_code == 0
        assert "MAY EXECUTE" in result.stdout

    def test_a_different_destination_is_a_different_action(self, tmp_path: Path) -> None:
        """The whole point of binding the destination into the receipt."""
        path = bundle_file(tmp_path, genesis(), grant(), receipt())
        result = runner.invoke(
            app,
            execute_args(path, **{"--destination": "https://technocore.chat/r/private"}),
        )
        assert result.exit_code == 1
        assert "REFUSED" in result.stdout

    def test_a_different_content_hash_is_a_different_action(self, tmp_path: Path) -> None:
        path = bundle_file(tmp_path, genesis(), grant(), receipt())
        result = runner.invoke(
            app, execute_args(path, **{"--content-hash": sha256_hex(b"something else")})
        )
        assert result.exit_code == 1

    def test_no_receipt_means_refused_when_approval_is_required(self, tmp_path: Path) -> None:
        path = bundle_file(tmp_path, genesis(), grant())
        result = runner.invoke(app, execute_args(path))
        assert result.exit_code == 1
        assert "REFUSED" in result.stdout

    def test_a_stranger_cannot_execute(self, tmp_path: Path) -> None:
        path = bundle_file(tmp_path, genesis(), grant(), receipt())
        result = runner.invoke(app, execute_args(path, **{"--agent": STRANGER.did}))
        assert result.exit_code == 1

    def test_the_result_carries_the_standing_note(self, tmp_path: Path) -> None:
        path = bundle_file(tmp_path, genesis(), grant(), receipt())
        result = runner.invoke(app, execute_args(path))
        assert "never bypassed by this result" in result.stdout


class TestAPreviewCannotBurnAReceipt:
    """`--dry-run` is the default, and that is a safety decision, not a taste one."""

    def test_a_dry_run_does_not_spend(self, tmp_path: Path) -> None:
        spent = str(tmp_path / "spent.sqlite3")
        path = bundle_file(tmp_path, genesis(), grant(), receipt())

        first = runner.invoke(app, [*execute_args(path), "--spent-db", spent])
        second = runner.invoke(app, [*execute_args(path), "--spent-db", spent])
        assert first.exit_code == 0
        assert second.exit_code == 0, "a preview consumed the receipt"
        assert "nothing was consumed" in first.stdout

    def test_reserving_spends_it_once(self, tmp_path: Path) -> None:
        spent = str(tmp_path / "spent.sqlite3")
        path = bundle_file(tmp_path, genesis(), grant(), receipt())

        first = runner.invoke(app, [*execute_args(path), "--spent-db", spent, "--reserve"])
        second = runner.invoke(app, [*execute_args(path), "--spent-db", spent, "--reserve"])
        assert first.exit_code == 0
        assert "receipt spent  True" in first.stdout
        assert second.exit_code == 1, "the receipt was replayable"

    def test_reserving_without_a_store_warns_that_it_is_not_replay_protection(
        self, tmp_path: Path
    ) -> None:
        path = bundle_file(tmp_path, genesis(), grant(), receipt())
        result = runner.invoke(app, [*execute_args(path), "--reserve"])
        combined = result.stdout + str(result.stderr)
        assert "not replay protection" in combined

    def test_the_command_performs_nothing(self) -> None:
        """It answers a question. Anything that acted would belong somewhere else."""
        source = Path(__import__("lineageauth.cli", fromlist=["x"]).__file__).read_text(
            encoding="utf-8"
        )
        for sink in ("urlopen", "requests.", "httpx.", "subprocess"):
            assert sink not in source


class TestTheCliStillHoldsNoKeys:
    def test_no_command_accepts_a_seed(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for word in ("--seed", "--private", "--secret"):
            assert word not in result.stdout

    @pytest.mark.parametrize("command", [["approval", "draft", "--help"], ["execute", "--help"]])
    def test_the_new_commands_take_no_key_material(self, command: list[str]) -> None:
        result = runner.invoke(app, command)
        assert result.exit_code == 0
        for word in ("--seed", "--private-key", "--signer-key"):
            assert word not in result.stdout
