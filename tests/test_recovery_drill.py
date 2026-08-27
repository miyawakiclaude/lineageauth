"""The recovery drill runs here, so "rehearsed" means "still rehearsed".

`RELEASE.md` asks for recovery to be rehearsed rather than only unit-tested.
A rehearsal done once is a fact about one afternoon; the interesting property is
that the procedure *still* works after the next change to the resolver, and that
is what running it here buys.

`tests/test_lineage.py` already covers succession, quorums and `CONFLICTED` with
payloads built in memory. This is deliberately the slower, clumsier version:
real encrypted key files on disk, the root file actually deleted, and everything
after that read back out of the published bundle rather than out of the
variables that produced it. The failure it exists to catch is not a wrong
verdict. It is a procedure that cannot be followed, because a step nobody wrote
down turns out to be required.

The drill costs a few seconds, almost all of it scrypt at N=2^17 -- the cost is
the point of that parameter, and paying it here is how the test stays honest
about what an operator pays.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from scripts.recovery_drill import DrillFailure, run

REPO = Path(__file__).resolve().parents[1]
RUNBOOK = REPO / "docs" / "RECOVERY.md"


@pytest.fixture(scope="module")
def drill(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    """Run the whole drill once; every test below reads its result."""
    return run(tmp_path_factory.mktemp("recovery-drill"), verbose=False)


class TestTheDrillItself:
    def test_a_lost_root_is_recoverable_by_a_quorum(self, drill: list[str]) -> None:
        assert any("2-of-3 quorum moves the lineage" in check for check in drill), (
            "the drill did not reach the successful recovery"
        )

    def test_it_refuses_everything_it_must(self, drill: list[str]) -> None:
        refusals = [check for check in drill if check.startswith("refuses:")]
        assert len(refusals) == 4, f"expected four refusals, ran {len(refusals)}: {refusals}"

    @pytest.mark.parametrize(
        "must_refuse",
        [
            "below the threshold",
            "not a policy member",
            "same member, duplicated",
            "policy that does not exist",
        ],
    )
    def test_each_named_refusal_actually_ran(self, drill: list[str], must_refuse: str) -> None:
        assert any(must_refuse in check for check in drill)

    def test_the_drill_can_fail(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A drill that cannot fail proves nothing about the day it matters.

        Weakening the policy to threshold 1 must make the first refusal stop
        refusing, and the drill must notice rather than reporting success.
        """
        from lineageauth import builders

        original = builders.build_recovery_policy

        def weakened(**kwargs: object) -> dict:
            return original(**{**kwargs, "threshold": 1})  # type: ignore[arg-type]

        monkeypatch.setattr("scripts.recovery_drill.build_recovery_policy", weakened)
        with pytest.raises(DrillFailure, match="must refuse"):
            run(tmp_path, verbose=False)


class TestTheRunbookMatchesTheDrill:
    """A runbook that drifts from the procedure is worse than no runbook.

    It reads as authoritative on the one day somebody is following it exactly,
    which is the day they have already lost the key.
    """

    @staticmethod
    def _runbook() -> str:
        return RUNBOOK.read_text(encoding="utf-8")

    def test_the_runbook_exists(self) -> None:
        assert RUNBOOK.is_file(), "docs/05 specifies recovery; this is the procedure"

    def test_every_refusal_the_drill_runs_is_documented(self, drill: list[str]) -> None:
        text = self._runbook().lower()
        expected = {
            "below the threshold": "fewer signatures than the threshold",
            "not a policy member": "the policy does not name",
            "same member, duplicated": "signing twice",
            "policy that does not exist": "policy that does not exist",
        }
        for ran, documented in expected.items():
            assert any(ran in check for check in drill), f"the drill stopped running {ran!r}"
            assert documented in text, f"the drill refuses {ran!r} but the runbook never says so"

    def test_it_names_the_reference_that_costs_people_time(self) -> None:
        """`recoveryPolicyRef` is mandatory and `docs/05` never says what it is."""
        text = self._runbook()
        assert "recoveryPolicyRef" in text
        assert "event id" in text, "the runbook must say the reference is an event id"

    def test_it_is_honest_that_there_is_no_cli_for_this(self) -> None:
        text = self._runbook().lower()
        assert "no cli command" in text, (
            "`la` cannot issue events; a runbook that implies otherwise strands the reader"
        )

    def test_it_says_old_signatures_stay_valid(self) -> None:
        """docs/28 calls this out as a limitation; the runbook must not soften it."""
        text = self._runbook().lower()
        assert "stay cryptographically valid" in text or "remain cryptographically valid" in text

    def test_the_command_it_tells_you_to_rehearse_with_exists(self) -> None:
        text = self._runbook()
        referenced = re.findall(r"scripts/[a-z_]+\.py", text)
        assert "scripts/recovery_drill.py" in referenced
        for script in set(referenced):
            assert (REPO / script).is_file(), f"the runbook points at a missing {script}"
