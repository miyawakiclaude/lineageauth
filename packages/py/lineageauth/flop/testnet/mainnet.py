"""The mainnet unlock interface, built now and answering "not yet" to everything.

Directive 17 asks for the interface without the execution, and directive 18 for
the rule to be data. Both matter for one reason: the published draft says three
$FLOP spent on inference unlocks one airdropped $FLOP, and that figure sits in a
document whose own front matter calls its figures provisional. Writing `3` into
Python would make a draft into a constant, and the day it changes the code would
disagree with the source while looking authoritative.

So the ratio is read from `conformance/flop/rule-registry.json` via
`rules.unlock_ratio`, and when the rule is missing or carries no formula the
answer is "not yet available" rather than a guess. Nothing here claims an
allocation, and the observation types have no field that could hold one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from lineageauth.flop.model import (
    COVERAGE_LABEL,
    UNKNOWN_FROM_OFFICIAL_SPEC,
    FeatureStatus,
    NetworkPhase,
)
from lineageauth.flop.rules import (
    UNLOCK_RULE_ID,
    FlopRuleRegistry,
    unlock_ratio,
    unlocked_from_spend,
)

MAINNET_NOT_LIVE_NOTE = (
    "No official FLOP mainnet exists. Nothing here claims, spends, or estimates an "
    "allocation, and no figure below is a promise of anything."
)


@dataclass(frozen=True, slots=True)
class UnlockRuleObservation:
    """What the registry currently says about unlocking, and where it says it."""

    rule_id: str
    status: FeatureStatus
    ratio: int | None
    statement: str | None
    source_url: str | None
    source_version: str | None
    detail: str

    def unlocked_from(self, spend: int) -> int | None:
        """Apply the registered formula, or return None when there is none."""
        return None if self.ratio is None else (spend // self.ratio)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "status": str(self.status),
            "ratio": self.ratio,
            "statement": self.statement,
            "sourceUrl": self.source_url,
            "sourceVersion": self.source_version,
            "detail": self.detail,
            "isProvisional": True,
            "note": MAINNET_NOT_LIVE_NOTE,
        }


@dataclass(frozen=True, slots=True)
class AllocationObservation:
    """What has been observed about a subject's allocation. Currently nothing.

    There is no `amount` field and no `estimate` field, on purpose. A type that
    cannot hold a number cannot be made to report one by a caller in a hurry.
    """

    subject_did: str
    status: FeatureStatus
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "subjectDid": self.subject_did,
            "status": str(self.status),
            "detail": self.detail,
            "observed": False,
            "isEligibilityClaim": False,
            "coverageLabel": COVERAGE_LABEL,
        }


@dataclass(frozen=True, slots=True)
class UnlockObservation:
    """Observed inference spend and what the registered rule would unlock from it.

    `observed_spend` is an integer of test FLOP actually recorded in receipts. If
    it is zero because no testnet exists, the status says `not-yet-available`
    rather than reporting a zero that reads like a measurement.
    """

    subject_did: str
    status: FeatureStatus
    observed_spend: int | None
    unlocked: int | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "subjectDid": self.subject_did,
            "status": str(self.status),
            "observedSpend": self.observed_spend,
            "unlocked": self.unlocked,
            "detail": self.detail,
            "isEligibilityClaim": False,
        }


class MainnetUnlockAdapter(Protocol):
    """The shape a real mainnet adapter will satisfy (directive 17)."""

    def discover_rule(self) -> UnlockRuleObservation: ...

    def allocation(self, subject_did: str) -> AllocationObservation: ...

    def unlock_state(
        self, subject_did: str, *, observed_spend: int | None
    ) -> UnlockObservation: ...


@dataclass(frozen=True, slots=True)
class NotYetAvailableMainnetAdapter:
    """The only implementation. Reads the rule, and refuses to invent the rest."""

    registry: FlopRuleRegistry
    network_phase: NetworkPhase = NetworkPhase.PRE_TESTNET

    def discover_rule(self) -> UnlockRuleObservation:
        rule = self.registry.get(UNLOCK_RULE_ID)
        ratio = unlock_ratio(self.registry)
        if rule is None:
            return UnlockRuleObservation(
                rule_id=UNLOCK_RULE_ID,
                status=FeatureStatus.NOT_OBSERVED,
                ratio=None,
                statement=None,
                source_url=None,
                source_version=None,
                detail=(
                    f"{UNLOCK_RULE_ID} is not in the rule registry; {UNKNOWN_FROM_OFFICIAL_SPEC}"
                ),
            )
        return UnlockRuleObservation(
            rule_id=rule.rule_id,
            status=FeatureStatus.NOT_YET_AVAILABLE,
            ratio=ratio,
            statement=rule.statement,
            source_url=rule.source.source_url,
            source_version=rule.source.source_version,
            detail=(
                "the ratio is read from the rule registry and is provisional; "
                "no mainnet exists to apply it to"
            ),
        )

    def allocation(self, subject_did: str) -> AllocationObservation:
        return AllocationObservation(
            subject_did=subject_did,
            status=FeatureStatus.NOT_YET_AVAILABLE,
            detail=(
                "no official mainnet allocation API exists, so nothing has been observed. "
                "This is not zero: it is the absence of a place to look."
            ),
        )

    def unlock_state(self, subject_did: str, *, observed_spend: int | None) -> UnlockObservation:
        if observed_spend is None:
            return UnlockObservation(
                subject_did=subject_did,
                status=FeatureStatus.NOT_YET_AVAILABLE,
                observed_spend=None,
                unlocked=None,
                detail=(
                    "no testnet inference spend has been observed, because no official "
                    "testnet exists to spend on"
                ),
            )
        return UnlockObservation(
            subject_did=subject_did,
            status=FeatureStatus.NOT_YET_AVAILABLE,
            observed_spend=observed_spend,
            unlocked=unlocked_from_spend(self.registry, observed_spend),
            detail=(
                "computed from the registered provisional formula against observed spend; "
                "the mainnet does not exist and nothing has been unlocked"
            ),
        )

    def to_dict(self, subject_did: str, *, observed_spend: int | None = None) -> dict[str, Any]:
        return {
            "networkPhase": str(self.network_phase),
            "rule": self.discover_rule().to_dict(),
            "allocation": self.allocation(subject_did).to_dict(),
            "unlock": self.unlock_state(subject_did, observed_spend=observed_spend).to_dict(),
            "mainnetExecutable": False,
            "note": MAINNET_NOT_LIVE_NOTE,
        }


__all__ = [
    "MAINNET_NOT_LIVE_NOTE",
    "AllocationObservation",
    "MainnetUnlockAdapter",
    "NotYetAvailableMainnetAdapter",
    "UnlockObservation",
    "UnlockRuleObservation",
]
