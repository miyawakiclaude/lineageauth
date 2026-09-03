"""The lifecycle gate, and the switch a person keeps their hand on.

Two separate ideas that a boolean would merge. The *phase* is what this tool
believes about the network, and it is source-driven: it moves because a
snapshot changed, not because somebody wanted it to. The *kill switch* is what
the operator wants, and it overrides the phase in one direction only -- it can
stop a write that the phase would permit, and it can never permit one the phase
forbids.

The edge that does not exist is `PRE_TESTNET -> TESTNET_ENABLED`. Directive 2
forbids it in words; here it is absent from the transition table, which is the
version that survives somebody being in a hurry. Getting to `TESTNET_ENABLED`
means discovering a candidate, verifying it against an official snapshot, and
then a person saying so.

Downgrading is always allowed. A gate that could not be dropped back to
`PRE_TESTNET` would make a mistaken promotion permanent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from lineageauth.flop.model import NetworkPhase, TestnetFailure, TestnetRefusal

KILL_SWITCH_LABEL = "Disable all FLOP network writes"

KILL_SWITCH_ON_NOTE = (
    "Disable all FLOP network writes: ON (locked while the network phase is PRE_TESTNET)"
)

# Which phase may become which. Every promotion is one rung. A rung that could
# be skipped is a rung that will be.
_PROMOTIONS: dict[NetworkPhase, frozenset[NetworkPhase]] = {
    NetworkPhase.PRE_TESTNET: frozenset({NetworkPhase.TESTNET_DISCOVERED_UNVERIFIED}),
    NetworkPhase.TESTNET_DISCOVERED_UNVERIFIED: frozenset({NetworkPhase.TESTNET_VERIFIED}),
    NetworkPhase.TESTNET_VERIFIED: frozenset({NetworkPhase.TESTNET_ENABLED}),
    NetworkPhase.TESTNET_ENABLED: frozenset({NetworkPhase.MAINNET_DISCOVERED_UNVERIFIED}),
    NetworkPhase.MAINNET_DISCOVERED_UNVERIFIED: frozenset({NetworkPhase.MAINNET_VERIFIED}),
    NetworkPhase.MAINNET_VERIFIED: frozenset(),
}

_ORDER: tuple[NetworkPhase, ...] = (
    NetworkPhase.PRE_TESTNET,
    NetworkPhase.TESTNET_DISCOVERED_UNVERIFIED,
    NetworkPhase.TESTNET_VERIFIED,
    NetworkPhase.TESTNET_ENABLED,
    NetworkPhase.MAINNET_DISCOVERED_UNVERIFIED,
    NetworkPhase.MAINNET_VERIFIED,
)

# Directive 26. A phase gate that let somebody enable execution with an
# unchecked box would be a checklist in a document rather than in the code.
ACTIVATION_CHECKLIST: tuple[str, ...] = (
    "official-testnet-url-confirmed",
    "official-spec-version-confirmed",
    "official-faucet-mechanism-confirmed",
    "official-inference-schema-confirmed",
    "official-pricing-mechanism-confirmed",
    "official-network-identifier-confirmed",
    "official-auth-signing-mechanism-confirmed",
    "endpoint-registry-updated",
    "official-fixtures-captured",
    "parser-tests-pass",
    "executor-contract-tests-pass",
    "security-tests-pass",
    "no-wallet-no-secret-policy-reviewed",
    "ui-shows-draft-or-final-status",
    "user-explicitly-enables-testnet-execution",
)


class PhaseTransitionError(Exception):
    """A transition the state machine does not have an edge for."""


@dataclass(frozen=True, slots=True)
class PhaseEvidence:
    """What was actually checked before a phase moved.

    A promotion with no evidence is a wish. `source_sha256` binds the belief to
    a specific document, so a later snapshot that differs can invalidate it
    instead of quietly inheriting the promotion.
    """

    source_id: str
    source_url: str
    source_sha256: str | None
    verified_at: str
    note: str = ""
    checklist: frozenset[str] = field(default_factory=frozenset)

    @property
    def checklist_complete(self) -> bool:
        return set(ACTIVATION_CHECKLIST) <= set(self.checklist)

    @property
    def missing_checklist_items(self) -> tuple[str, ...]:
        return tuple(item for item in ACTIVATION_CHECKLIST if item not in self.checklist)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sourceId": self.source_id,
            "sourceUrl": self.source_url,
            "sourceSha256": self.source_sha256,
            "verifiedAt": self.verified_at,
            "note": self.note,
            "checklistComplete": self.checklist_complete,
            "missingChecklistItems": list(self.missing_checklist_items),
        }


@dataclass(frozen=True, slots=True)
class PhaseGate:
    """The current phase, the kill switch, and whether a write may happen.

    Frozen: a transition returns a new gate rather than mutating this one, so a
    component that captured the gate before a promotion cannot find itself
    holding a more permissive object than the one it checked.
    """

    phase: NetworkPhase = NetworkPhase.PRE_TESTNET
    kill_switch_engaged: bool = True
    evidence: PhaseEvidence | None = None

    @property
    def kill_switch_locked(self) -> bool:
        """The switch cannot be released below `TESTNET_VERIFIED`.

        Locked-on rather than merely on: there is nothing to enable, so an
        operator who turns it off has not gained a capability, only lost a
        safeguard they will forget to restore.
        """
        return _ORDER.index(self.phase) < _ORDER.index(NetworkPhase.TESTNET_VERIFIED)

    @property
    def network_writes_allowed(self) -> bool:
        """Both conditions, never either. The switch cannot grant, only deny."""
        return self.phase.testnet_is_live and not self.kill_switch_engaged

    def refusal(self) -> TestnetRefusal | None:
        """Why a write may not happen, or None when it may.

        Order matters for the message, not the outcome: an operator in
        `PRE_TESTNET` should be told the network does not exist rather than
        that their switch is on, because turning the switch off would not help.
        """
        if not self.phase.testnet_is_live:
            return TestnetRefusal(
                failure=TestnetFailure.TESTNET_NOT_LIVE,
                detail=(
                    f"the network phase is {self.phase} and no official FLOP testnet endpoint "
                    "has been published; nothing here can reach a network"
                ),
                stage="phase",
            )
        if self.kill_switch_engaged:
            return TestnetRefusal(
                failure=TestnetFailure.KILL_SWITCH_ENGAGED,
                detail=f"{KILL_SWITCH_LABEL} is ON; release it explicitly before executing",
                stage="phase",
            )
        return None

    def transition(self, to: NetworkPhase, *, evidence: PhaseEvidence | None = None) -> PhaseGate:
        """Move one rung, or downgrade, or refuse.

        A promotion into `TESTNET_VERIFIED` or beyond needs evidence. Reaching
        `TESTNET_ENABLED` needs the activation checklist complete as well, and
        re-engages the kill switch: verifying a network is not the same as
        deciding to write to it, and the operator says the second part
        separately with `release_kill_switch`.
        """
        if to is self.phase:
            return self
        here, there = _ORDER.index(self.phase), _ORDER.index(to)
        if there < here:
            # Downgrades are always available, and always re-arm the switch.
            return PhaseGate(phase=to, kill_switch_engaged=True, evidence=None)
        if to not in _PROMOTIONS[self.phase]:
            raise PhaseTransitionError(
                f"no transition from {self.phase} to {to}: the path runs through "
                f"{sorted(_PROMOTIONS[self.phase]) or 'nothing -- this is the last phase'}, "
                "and PRE_TESTNET may never reach TESTNET_ENABLED directly"
            )
        if to in (
            NetworkPhase.TESTNET_VERIFIED,
            NetworkPhase.TESTNET_ENABLED,
            NetworkPhase.MAINNET_VERIFIED,
        ):
            if evidence is None:
                raise PhaseTransitionError(
                    f"moving to {to} requires the official source evidence it is based on"
                )
            if to is NetworkPhase.TESTNET_ENABLED and not evidence.checklist_complete:
                raise PhaseTransitionError(
                    "the live-activation checklist is incomplete: "
                    f"{', '.join(evidence.missing_checklist_items)}"
                )
        return PhaseGate(phase=to, kill_switch_engaged=True, evidence=evidence)

    def release_kill_switch(self, *, reason: str) -> PhaseGate:
        """Turn the switch off, with a reason, once the phase permits it."""
        if not reason.strip():
            raise PhaseTransitionError("releasing the kill switch requires a stated reason")
        if self.kill_switch_locked:
            raise PhaseTransitionError(
                f"the kill switch is locked ON while the phase is {self.phase}; "
                "verify an official testnet source first"
            )
        return PhaseGate(phase=self.phase, kill_switch_engaged=False, evidence=self.evidence)

    def engage_kill_switch(self) -> PhaseGate:
        """Turn the switch on. Always available, needs no reason."""
        return PhaseGate(phase=self.phase, kill_switch_engaged=True, evidence=self.evidence)

    def to_dict(self) -> dict[str, Any]:
        refusal = self.refusal()
        return {
            "networkPhase": str(self.phase),
            "networkPhaseBadge": self.phase.badge,
            "killSwitch": {
                "label": KILL_SWITCH_LABEL,
                "engaged": self.kill_switch_engaged,
                "locked": self.kill_switch_locked,
                "display": KILL_SWITCH_ON_NOTE if self.kill_switch_locked else KILL_SWITCH_LABEL,
            },
            "networkWritesAllowed": self.network_writes_allowed,
            "testnetIsLive": self.phase.testnet_is_live,
            "refusal": None if refusal is None else refusal.to_dict(),
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
            "activationChecklist": list(ACTIVATION_CHECKLIST),
            "nextPhases": sorted(str(phase) for phase in _PROMOTIONS[self.phase]),
        }


__all__ = [
    "ACTIVATION_CHECKLIST",
    "KILL_SWITCH_LABEL",
    "KILL_SWITCH_ON_NOTE",
    "PhaseEvidence",
    "PhaseGate",
    "PhaseTransitionError",
]
