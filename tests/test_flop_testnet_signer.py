"""No custody: the package has no parameter that could receive key material.

Directive 11 in the form that survives a refactor. `NoSigner` refusing is easy
to check; what matters more is that nothing in `flop/**` has a parameter named
for a secret, so a future signer cannot be wired in by accident.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from lineageauth.flop.model import TestnetFailure, TestnetRefusedError
from lineageauth.flop.testnet.mainnet import NotYetAvailableMainnetAdapter
from lineageauth.flop.testnet.signer import NoSigner
from tests.flop_testnet_fixtures import AGENT, registry_with_formula, rules

FLOP_PACKAGE = Path("packages/py/lineageauth/flop")

SECRET_PARAMETER_NAMES = frozenset(
    {
        "seed",
        "seed_phrase",
        "mnemonic",
        "private_key",
        "privatekey",
        "secret",
        "secret_key",
        "passphrase",
        "password",
        "keyfile",
        "key_path",
        "signing_key",
    }
)


class TestNoSigner:
    def test_it_says_it_is_unavailable(self) -> None:
        signer = NoSigner()
        assert signer.available is False
        assert signer.signer_id == "none"
        assert signer.to_dict()["holdsPrivateKeys"] is False
        assert signer.to_dict()["custody"] == "none"

    def test_it_refuses_rather_than_returning_empty_bytes(self) -> None:
        with pytest.raises(TestnetRefusedError) as caught:
            NoSigner().sign(b"anything")
        assert caught.value.refusal.failure is TestnetFailure.SIGNER_NOT_CONFIGURED

    def test_the_refusal_says_where_a_key_would_live_instead(self) -> None:
        with pytest.raises(TestnetRefusedError) as caught:
            NoSigner().sign(b"x")
        assert "outside this process" in caught.value.refusal.detail


class TestNoParameterCouldHoldASecret:
    def test_no_function_in_the_flop_layer_takes_a_secret_shaped_parameter(self) -> None:
        offenders: list[str] = []
        for path in sorted(FLOP_PACKAGE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                arguments = node.args
                names = [
                    argument.arg
                    for argument in (
                        *arguments.posonlyargs,
                        *arguments.args,
                        *arguments.kwonlyargs,
                    )
                ]
                for name in names:
                    if name.lower() in SECRET_PARAMETER_NAMES:
                        offenders.append(f"{path}:{node.name}({name})")
        assert offenders == []

    def test_the_flop_layer_never_imports_a_key_holding_signer(self) -> None:
        """Prose may mention `LocalSigner`; an import statement may not name it."""
        offenders: list[str] = []
        for path in sorted(FLOP_PACKAGE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    names = {alias.name for alias in node.names}
                    if node.module == "lineageauth.crypto" or "LocalSigner" in names:
                        offenders.append(f"{path}: from {node.module} import {sorted(names)}")
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "lineageauth.crypto":
                            offenders.append(f"{path}: import {alias.name}")
        assert offenders == []

    def test_no_string_in_the_flop_layer_names_a_key_file(self) -> None:
        offenders: list[str] = []
        for path in sorted(FLOP_PACKAGE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                text = node.value
                # `url.technocore-get-write` is a pattern id, not a path. What
                # must not appear is a file under the user's key directory.
                markers = ("~/.technocore", ".technocore/", "identity.encrypted", "id_ed25519")
                if any(marker in text for marker in markers):
                    offenders.append(f"{path}:{node.lineno} {text!r}")
        assert offenders == []


class TestMainnetAdapter:
    def test_the_ratio_is_read_from_the_registry_and_not_written_in_python(self) -> None:
        """D-123: the airdrop page and the Yellow Paper give 3:1 again; the registry
        carries it and the adapter reads it."""
        adapter = NotYetAvailableMainnetAdapter(registry=rules())
        observation = adapter.discover_rule()
        assert observation.ratio == 3
        assert observation.status.value == "not-yet-available"
        assert observation.source_url == "https://flop.finance/airdrop/"
        source = (FLOP_PACKAGE / "testnet" / "mainnet.py").read_text(encoding="utf-8")
        assert "spentPerUnlocked" not in source
        assert "= 3" not in source

    def test_an_allocation_cannot_be_reported_because_the_type_has_no_field_for_it(self) -> None:
        import dataclasses

        from lineageauth.flop.testnet.mainnet import AllocationObservation

        fields = {f.name for f in dataclasses.fields(AllocationObservation)}
        assert "amount" not in fields
        assert "estimate" not in fields

    def test_nothing_is_observed_and_the_status_says_why(self) -> None:
        adapter = NotYetAvailableMainnetAdapter(registry=rules())
        body = adapter.to_dict(AGENT.did)
        assert body["mainnetExecutable"] is False
        assert body["allocation"]["observed"] is False
        assert body["allocation"]["status"] == "not-yet-available"
        assert body["unlock"]["observedSpend"] is None

    @pytest.mark.parametrize("spend", [10, -5])
    def test_an_observed_spend_unlocks_nothing_without_a_formula(
        self, spend: int, tmp_path: Path
    ) -> None:
        """The detail must not claim a computation that did not happen."""
        from tests.flop_testnet_fixtures import registry_without_formula

        adapter = NotYetAvailableMainnetAdapter(registry=registry_without_formula(tmp_path))
        state = adapter.unlock_state(AGENT.did, observed_spend=spend)
        assert state.unlocked is None
        assert state.status.value == "not-yet-available"
        # What the registry records, not a claim about every official page: the Yellow
        # Paper's own 3:1 sentence could still be registered under another id.
        assert "carries no unlock formula" in state.detail
        assert "official text" not in state.detail
        assert "computed from the registered" not in state.detail

    def test_an_observed_spend_uses_a_registered_formula(self, tmp_path: Path) -> None:
        """The mechanism is kept: a formula in the data is applied by the adapter. 5 and
        2 are neither the dropped 3 nor the default 1."""
        adapter = NotYetAvailableMainnetAdapter(
            registry=registry_with_formula(tmp_path, spent=5, unlocked=2)
        )
        observation = adapter.discover_rule()
        assert observation.ratio == 5
        assert "read from the rule registry and is provisional" in observation.detail
        state = adapter.unlock_state(AGENT.did, observed_spend=10)
        assert state.unlocked == 4
        assert "computed from the registered provisional formula" in state.detail
        negative = adapter.unlock_state(AGENT.did, observed_spend=-5)
        assert negative.unlocked is None
        assert "negative spend" in negative.detail

    def test_an_unappliable_formula_is_not_reported_as_the_official_texts_silence(
        self,
    ) -> None:
        """A registry built in code can bypass the loader's formula check; the adapter
        still must not blame the official text for the registry's mistake."""
        from dataclasses import replace

        from lineageauth.flop.rules import UNLOCK_RULE_ID, FlopRuleRegistry

        shipped = rules().get(UNLOCK_RULE_ID)
        assert shipped is not None
        broken = replace(shipped, formula={"kind": "unlock-ratio", "spentPerUnlocked": 0})
        adapter = NotYetAvailableMainnetAdapter(registry=FlopRuleRegistry(rules=(broken,)))
        observation = adapter.discover_rule()
        assert observation.ratio is None
        assert "cannot be applied" in observation.detail
        assert "official text" not in observation.detail
        state = adapter.unlock_state(AGENT.did, observed_spend=10)
        assert state.unlocked is None
        assert "cannot be applied" in state.detail

    def test_the_registry_missing_the_rule_reports_not_observed(self) -> None:
        from lineageauth.flop.rules import FlopRuleRegistry

        adapter = NotYetAvailableMainnetAdapter(registry=FlopRuleRegistry(rules=()))
        observation = adapter.discover_rule()
        assert observation.ratio is None
        assert observation.status.value == "not-observed"
        state = adapter.unlock_state(AGENT.did, observed_spend=10)
        assert state.unlocked is None
        assert "not in the rule registry" in state.detail
