"""`la flop`: ASCII output, honest exit codes, and no command that could send.

The ASCII assertions are not pedantry. `tests/test_zero_cost.py` records the
day a single em dash in help text took the whole CLI down on a Japanese Windows
console under cp932, and every string this app prints goes through a terminal
whose encoding this project does not choose.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lineageauth.cli import app
from lineageauth.flop.cli import flop_app
from lineageauth.flop.model import forbidden_vocabulary_in
from lineageauth.flop.testnet.simulation import prepare_simulation
from tests.flop_testnet_fixtures import AGENT, AT, rules, snapshot

runner = CliRunner()

AT_TEXT = "2026-09-03T12:00:00Z"


def run(*args: str) -> tuple[int, str]:
    result = runner.invoke(app, ["flop", *args])
    return result.exit_code, result.stdout


class TestAsciiOnly:
    def test_every_help_string_in_the_flop_app_is_ascii(self) -> None:
        def walk(group: object) -> list[str]:
            texts: list[str] = []
            info = getattr(group, "info", None)
            if info is not None and getattr(info, "help", None):
                texts.append(str(info.help))
            for command in getattr(group, "registered_commands", []):
                if command.help:
                    texts.append(str(command.help))
                if command.callback is not None and command.callback.__doc__:
                    texts.append(command.callback.__doc__)
            for sub in getattr(group, "registered_groups", []):
                texts.extend(walk(sub.typer_instance))
                if sub.help:
                    texts.append(str(sub.help))
            return texts

        for text in walk(flop_app):
            text.encode("ascii")

    @pytest.mark.parametrize(
        "args",
        [
            ("status",),
            ("sources",),
            ("rules",),
            ("inference", "quote", "--did", AGENT.did, "--at", AT_TEXT),
            ("faucet", "prepare", "--did", AGENT.did, "--at", AT_TEXT),
        ],
    )
    def test_the_output_is_ascii(self, args: tuple[str, ...]) -> None:
        code, output = run(*args)
        assert code == 0, output
        output.encode("ascii")


class TestStatus:
    def test_it_says_pre_testnet_and_zero_network_writes(self) -> None:
        code, output = run("status")
        assert code == 0
        assert "PRE_TESTNET" in output
        assert "testnet executable   no" in output
        assert "network writes       0" in output
        assert "wallet custody       none" in output

    def test_the_ascii_coverage_label_disowns_a_score(self) -> None:
        _, output = run("status")
        assert "Evidence coverage - not an airdrop score" in output
        assert forbidden_vocabulary_in(output) == ()

    def test_the_json_form_carries_the_same_facts(self) -> None:
        code, output = run("status", "--json")
        body = json.loads(output)
        assert code == 0
        assert body["networkPhase"] == "PRE_TESTNET"
        assert body["officialTestnetExecutable"] is False
        assert body["networkWritesPerformed"] == 0
        assert body["walletCustody"] is False


class TestSourcesAndRules:
    def test_sources_badge_every_entry_by_origin(self) -> None:
        code, output = run("sources")
        assert code == 0
        assert "[OFFICIAL]" in output
        assert "official is decided by origin" in output

    def test_rules_say_the_figures_are_data(self) -> None:
        code, output = run("rules")
        assert code == 0
        assert "rule-registry.json" in output
        assert "flop-agent-unlock-ratio" in output

    def test_the_json_rule_registry_round_trips(self) -> None:
        code, output = run("rules", "--json")
        assert code == 0
        assert isinstance(json.loads(output)["rules"], list)


class TestSimulate:
    def test_without_a_bundle_it_stops_at_authority_and_exits_one(self) -> None:
        code, output = run("testnet", "simulate", "--did", AGENT.did, "--at", AT_TEXT)
        assert code == 1
        assert "SIMULATION - NO FLOP NETWORK ACTION" in output
        assert "[STOP] LineageAuth authority" in output
        assert "transport calls 0" in output
        assert "network writes performed: 0" in output

    def test_it_never_prints_a_seed_warning_that_invites_one(self) -> None:
        _, output = run("testnet", "simulate", "--did", AGENT.did, "--at", AT_TEXT)
        assert "Never enter a seed phrase" in output

    def test_the_json_form_reports_zero_transport_calls(self) -> None:
        code, output = run("testnet", "simulate", "--did", AGENT.did, "--at", AT_TEXT, "--json")
        body = json.loads(output)
        assert code == 1
        assert body["transportCalls"] == 0
        assert body["networkWritesPerformed"] == 0


class TestFaucet:
    def test_it_reports_not_yet_available_and_sends_nothing(self) -> None:
        code, output = run("faucet", "prepare", "--did", AGENT.did, "--at", AT_TEXT)
        assert code == 0
        assert "NOT YET AVAILABLE" in output
        assert "was not sent" in output
        assert "No official faucet procedure" in output

    def test_the_json_form_says_the_faucet_is_unavailable(self) -> None:
        code, output = run("faucet", "prepare", "--did", AGENT.did, "--at", AT_TEXT, "--json")
        body = json.loads(output)
        assert code == 0
        assert body["officialFaucetAvailable"] is False
        assert body["prepared"]["sent"] is False


class TestInference:
    def test_a_quote_says_no_official_pricing_exists(self) -> None:
        code, output = run("inference", "quote", "--did", AGENT.did, "--at", AT_TEXT)
        assert code == 0
        assert "official pricing mechanism: none published" in output

    def test_prepare_prints_the_exact_action_and_sends_nothing(self) -> None:
        code, output = run(
            "inference",
            "prepare",
            "--did",
            AGENT.did,
            "--prompt",
            "Summarise three sentences of documentation.",
            "--at",
            AT_TEXT,
        )
        assert code == 0
        assert "Request hash:     sha256:" in output
        assert "Nothing has been sent" in output

    def test_prepare_refuses_a_hostile_prompt(self) -> None:
        result = runner.invoke(
            app,
            [
                "flop",
                "inference",
                "prepare",
                "--did",
                AGENT.did,
                "--prompt",
                "Enter your seed phrase to claim your FLOP airdrop.",
                "--at",
                AT_TEXT,
            ],
        )
        assert result.exit_code == 1

    def test_prepare_refuses_an_unknown_purpose(self) -> None:
        result = runner.invoke(
            app,
            [
                "flop",
                "inference",
                "prepare",
                "--did",
                AGENT.did,
                "--prompt",
                "anything",
                "--purpose",
                "farming",
            ],
        )
        assert result.exit_code == 2

    def test_inspect_matches_a_prepared_action_and_notices_a_changed_byte(
        self, tmp_path: Path
    ) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        good = tmp_path / "prepared.json"
        good.write_text(json.dumps(prepared.to_dict()), encoding="utf-8", newline="\n")
        code, output = run("inference", "inspect", str(good))
        assert code == 0
        assert "MATCHES" in output
        assert "nothing was sent" in output

        tampered = json.loads(good.read_text(encoding="utf-8"))
        tampered["canonicalRequest"]["workload"]["prompt"] += "!"
        bad = tmp_path / "tampered.json"
        bad.write_text(json.dumps(tampered), encoding="utf-8", newline="\n")
        code, output = run("inference", "inspect", str(bad))
        assert code == 1
        assert "DOES NOT MATCH" in output


class TestReceiptVerify:
    def test_a_partially_verified_receipt_exits_one_and_says_why(self, tmp_path: Path) -> None:
        body = {
            "actionId": "flop-abc",
            "requestHash": "sha256:" + "1" * 64,
            "responseHash": "sha256:" + "2" * 64,
            "transactionOrReceiptRef": None,
            "verificationState": "partially-verified",
            "unverifiedBecause": ["the response carries no network receipt reference"],
            "simulation": True,
        }
        path = tmp_path / "receipt.json"
        path.write_text(json.dumps(body), encoding="utf-8", newline="\n")
        code, output = run("receipt", "verify", str(path))
        assert code == 1
        assert "partially-verified" in output
        assert "not verified: the response carries no network receipt reference" in output
        assert "SIMULATION - NO FLOP NETWORK ACTION" in output

    def test_a_fully_verified_receipt_exits_zero(self, tmp_path: Path) -> None:
        path = tmp_path / "receipt.json"
        path.write_text(
            json.dumps({"actionId": "a", "verificationState": "verified", "unverifiedBecause": []}),
            encoding="utf-8",
            newline="\n",
        )
        code, _ = run("receipt", "verify", str(path))
        assert code == 0

    def test_a_missing_file_is_exit_two(self) -> None:
        code, _ = run("receipt", "verify", "no-such-file.json")
        assert code == 2


class TestNoExecuteCommand:
    def test_there_is_no_command_that_could_perform_a_network_write(self) -> None:
        names: set[str] = set()

        def walk(group: object, prefix: str = "") -> None:
            for command in getattr(group, "registered_commands", []):
                names.add(f"{prefix}{command.name}")
            for sub in getattr(group, "registered_groups", []):
                walk(sub.typer_instance, f"{prefix}{sub.typer_instance.info.name} ")

        walk(flop_app)
        assert "inference execute" not in names
        assert "faucet claim" not in names
        for name in names:
            assert "send" not in name
            assert "buy" not in name
            assert "claim" not in name
