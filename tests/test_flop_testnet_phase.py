"""The lifecycle gate: the edge that does not exist, and the switch that locks on."""

from __future__ import annotations

import pytest

from lineageauth.flop.model import NetworkPhase, TestnetFailure
from lineageauth.flop.testnet.phase import (
    ACTIVATION_CHECKLIST,
    PhaseEvidence,
    PhaseGate,
    PhaseTransitionError,
)


def evidence(*, complete: bool = True) -> PhaseEvidence:
    return PhaseEvidence(
        source_id="flop-finance-teaser",
        source_url="https://flop.finance/teaser/",
        source_sha256="sha256:" + "a" * 64,
        verified_at="2026-09-03T00:00:00Z",
        checklist=frozenset(ACTIVATION_CHECKLIST) if complete else frozenset({"parser-tests-pass"}),
    )


class TestDefaults:
    def test_the_default_phase_is_pre_testnet_with_the_switch_on(self) -> None:
        gate = PhaseGate()
        assert gate.phase is NetworkPhase.PRE_TESTNET
        assert gate.kill_switch_engaged is True
        assert gate.kill_switch_locked is True
        assert gate.network_writes_allowed is False

    def test_the_refusal_names_the_phase_before_it_names_the_switch(self) -> None:
        refusal = PhaseGate().refusal()
        assert refusal is not None
        assert refusal.failure is TestnetFailure.TESTNET_NOT_LIVE
        assert refusal.stage == "phase"

    def test_an_enabled_phase_with_the_switch_on_still_refuses(self) -> None:
        gate = PhaseGate(phase=NetworkPhase.TESTNET_ENABLED, kill_switch_engaged=True)
        refusal = gate.refusal()
        assert refusal is not None
        assert refusal.failure is TestnetFailure.KILL_SWITCH_ENGAGED

    def test_verified_is_not_live(self) -> None:
        assert NetworkPhase.TESTNET_VERIFIED.testnet_is_live is False
        assert NetworkPhase.TESTNET_ENABLED.testnet_is_live is True


class TestTransitions:
    def test_pre_testnet_may_not_reach_enabled_directly(self) -> None:
        with pytest.raises(PhaseTransitionError, match="never reach TESTNET_ENABLED directly"):
            PhaseGate().transition(NetworkPhase.TESTNET_ENABLED, evidence=evidence())

    def test_pre_testnet_may_not_skip_to_verified(self) -> None:
        with pytest.raises(PhaseTransitionError):
            PhaseGate().transition(NetworkPhase.TESTNET_VERIFIED, evidence=evidence())

    def test_the_path_runs_through_discovery_and_verification(self) -> None:
        gate = PhaseGate().transition(NetworkPhase.TESTNET_DISCOVERED_UNVERIFIED)
        gate = gate.transition(NetworkPhase.TESTNET_VERIFIED, evidence=evidence())
        assert gate.phase is NetworkPhase.TESTNET_VERIFIED
        assert gate.kill_switch_locked is False
        assert gate.kill_switch_engaged is True

    def test_verifying_without_evidence_is_refused(self) -> None:
        gate = PhaseGate().transition(NetworkPhase.TESTNET_DISCOVERED_UNVERIFIED)
        with pytest.raises(PhaseTransitionError, match="requires the official source evidence"):
            gate.transition(NetworkPhase.TESTNET_VERIFIED)

    def test_enabling_needs_the_whole_activation_checklist(self) -> None:
        gate = PhaseGate().transition(NetworkPhase.TESTNET_DISCOVERED_UNVERIFIED)
        gate = gate.transition(NetworkPhase.TESTNET_VERIFIED, evidence=evidence())
        with pytest.raises(PhaseTransitionError, match="checklist is incomplete"):
            gate.transition(NetworkPhase.TESTNET_ENABLED, evidence=evidence(complete=False))

    def test_enabling_re_engages_the_switch(self) -> None:
        gate = PhaseGate().transition(NetworkPhase.TESTNET_DISCOVERED_UNVERIFIED)
        gate = gate.transition(NetworkPhase.TESTNET_VERIFIED, evidence=evidence())
        gate = gate.transition(NetworkPhase.TESTNET_ENABLED, evidence=evidence())
        assert gate.kill_switch_engaged is True
        assert gate.network_writes_allowed is False

    def test_a_downgrade_is_always_available_and_re_arms_the_switch(self) -> None:
        gate = PhaseGate(phase=NetworkPhase.TESTNET_ENABLED, kill_switch_engaged=False)
        dropped = gate.transition(NetworkPhase.PRE_TESTNET)
        assert dropped.phase is NetworkPhase.PRE_TESTNET
        assert dropped.kill_switch_engaged is True


class TestKillSwitch:
    def test_it_cannot_be_released_below_verified(self) -> None:
        with pytest.raises(PhaseTransitionError, match="locked ON"):
            PhaseGate().release_kill_switch(reason="I am in a hurry")

    def test_releasing_needs_a_reason(self) -> None:
        gate = PhaseGate(phase=NetworkPhase.TESTNET_VERIFIED)
        with pytest.raises(PhaseTransitionError, match="stated reason"):
            gate.release_kill_switch(reason="   ")

    def test_released_at_enabled_permits_writes_and_re_engaging_stops_them(self) -> None:
        gate = PhaseGate(phase=NetworkPhase.TESTNET_ENABLED).release_kill_switch(
            reason="the activation checklist is complete and I am watching"
        )
        assert gate.network_writes_allowed is True
        assert gate.engage_kill_switch().network_writes_allowed is False

    def test_the_switch_can_never_grant_what_the_phase_forbids(self) -> None:
        gate = PhaseGate(phase=NetworkPhase.TESTNET_VERIFIED).release_kill_switch(
            reason="verified, but not enabled"
        )
        assert gate.network_writes_allowed is False
        refusal = gate.refusal()
        assert refusal is not None
        assert refusal.failure is TestnetFailure.TESTNET_NOT_LIVE


class TestRendering:
    def test_the_dict_says_what_is_locked_and_what_comes_next(self) -> None:
        body = PhaseGate().to_dict()
        assert body["networkPhase"] == "PRE_TESTNET"
        assert body["killSwitch"]["locked"] is True
        assert "ON (locked" in body["killSwitch"]["display"]
        assert body["networkWritesAllowed"] is False
        assert body["nextPhases"] == ["TESTNET_DISCOVERED_UNVERIFIED"]
        assert len(body["activationChecklist"]) == len(ACTIVATION_CHECKLIST)
