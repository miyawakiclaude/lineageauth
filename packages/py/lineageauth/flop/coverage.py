"""Evidence coverage: ten categories, five states, and no total.

The temptation this module exists to refuse is obvious. Ten categories with
states that sort naturally could be summed, weighted, normalised to a hundred
and put in a ring, and the ring would be read as an allocation forecast within a
day of shipping. `COVERAGE_LABEL` is rendered wherever coverage is, and there is
no field anywhere in the output that adds the categories into one number.

Two of the five states carry most of the honesty.

`NOT_YET_AVAILABLE` is for a network feature that does not exist. In
`PRE_TESTNET`, inference, broker demand, creator attribution and mainnet
continuation are all in this state, and a category in it is excluded from the
denominator's meaning rather than counted as a failure -- the directive's fifth
acceptance test is precisely that a missing testnet must not read as `0 FLOP
spent`.

`SOURCE_UNKNOWN` is for a category whose only records came from origins the
source classifier does not recognise. Something was observed; nothing that
observed it can be trusted to have observed it correctly. Calling that "some
evidence" would launder an unknown source into a verdict.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from lineageauth.flop.model import (
    COVERAGE_LABEL,
    COVERAGE_LABEL_ASCII,
    SYNTHETIC_BANNER,
    ActivityCategory,
    ActivityRecord,
    CoverageCategory,
    CoverageState,
    EvidenceLevel,
    NetworkPhase,
    SourceClass,
)

# `STRONG_EVIDENCE` needs externally supported records, not merely several
# records. Three self-signed registrations are one agent saying the same thing
# three times.
_STRONG_THRESHOLD = 2


@dataclass(frozen=True, slots=True)
class _CategorySpec:
    """One coverage category and how to fill it."""

    category_id: str
    label: str
    matches: frozenset[ActivityCategory]
    requires_phase: NetworkPhase | None = None
    unavailable_reason: str = ""


COVERAGE_CATEGORIES: tuple[_CategorySpec, ...] = (
    _CategorySpec(
        "identity",
        "Identity continuity",
        frozenset({ActivityCategory.IDENTITY}),
    ),
    _CategorySpec(
        "useful-work",
        "Useful work",
        frozenset(
            {
                ActivityCategory.CODE_CONTRIBUTION,
                ActivityCategory.CONNECTOR,
                ActivityCategory.DOCUMENTATION,
                ActivityCategory.TRANSLATION,
                ActivityCategory.BUG_REPORT,
                ActivityCategory.REPRODUCIBLE_TEST,
                ActivityCategory.SECURITY_FINDING,
                ActivityCategory.USEFUL_ARTIFACT,
                ActivityCategory.PROTOCOL_IMPLEMENTATION,
            }
        ),
    ),
    _CategorySpec(
        "external-verification",
        "External verification",
        frozenset({ActivityCategory.EXTERNAL_VERIFICATION}),
    ),
    _CategorySpec(
        "collaboration",
        "Agent collaboration",
        frozenset({ActivityCategory.AGENT_COLLABORATION}),
    ),
    _CategorySpec(
        "technocore",
        "Technocore participation",
        frozenset({ActivityCategory.ROOM_PARTICIPATION}),
    ),
    _CategorySpec(
        "tclk",
        "tclk activity",
        frozenset({ActivityCategory.TCLK_DEAL}),
    ),
    _CategorySpec(
        "inference",
        "Testnet inference",
        frozenset({ActivityCategory.INFERENCE}),
        requires_phase=NetworkPhase.TESTNET_ENABLED,
        unavailable_reason=(
            "No official FLOP testnet endpoint is published, so there is nothing to observe. "
            "This is not zero spend; it is a network that has not launched."
        ),
    ),
    _CategorySpec(
        "broker",
        "Broker demand contribution",
        frozenset(),
        requires_phase=NetworkPhase.TESTNET_ENABLED,
        unavailable_reason=(
            "The broker market described by the teaser does not exist on the current phase."
        ),
    ),
    _CategorySpec(
        "creator",
        "Creator attribution",
        frozenset(),
        requires_phase=NetworkPhase.TESTNET_ENABLED,
        unavailable_reason=("No official creator-attribution mechanism has been published."),
    ),
    _CategorySpec(
        "mainnet",
        "Mainnet continuation",
        frozenset(),
        requires_phase=NetworkPhase.MAINNET_VERIFIED,
        unavailable_reason=(
            "Mainnet is planned for Q1 2027 in a draft whose figures are provisional."
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """Ten categories and their states. Deliberately without a total score."""

    categories: tuple[CoverageCategory, ...]
    network_phase: NetworkPhase
    contains_synthetic: bool = False

    @property
    def covered(self) -> int:
        return sum(1 for category in self.categories if category.state.is_covered)

    @property
    def total(self) -> int:
        return len(self.categories)

    @property
    def not_yet_available(self) -> int:
        return sum(
            1 for category in self.categories if category.state is CoverageState.NOT_YET_AVAILABLE
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": COVERAGE_LABEL,
            "labelAscii": COVERAGE_LABEL_ASCII,
            "covered": self.covered,
            "total": self.total,
            "notYetAvailable": self.not_yet_available,
            "networkPhase": str(self.network_phase),
            "isAirdropScore": False,
            "aggregateScore": None,
            # Coverage is the first number anybody reads, so it carries the
            # synthetic flag itself rather than relying on the screen that draws
            # it to remember. An unlabelled count computed from mock records is
            # the most misleading thing this console could show.
            "containsSyntheticData": self.contains_synthetic,
            **({"banner": SYNTHETIC_BANNER} if self.contains_synthetic else {}),
            "note": (
                "A ring showing covered categories shows how much of your activity has "
                "evidence behind it. It does not predict an allocation."
            ),
            "categories": [category.to_dict() for category in self.categories],
        }


def _phase_reached(current: NetworkPhase, required: NetworkPhase) -> bool:
    """Whether the network has actually got as far as this category needs.

    Only the enabled and verified rungs count. A testnet that has been
    discovered but not verified is a URL somebody published, and a category that
    lit up on that would be reporting on an unverified endpoint.
    """
    if required is NetworkPhase.TESTNET_ENABLED:
        return current in (
            NetworkPhase.TESTNET_ENABLED,
            NetworkPhase.MAINNET_VERIFIED,
        )
    if required is NetworkPhase.MAINNET_VERIFIED:
        return current is NetworkPhase.MAINNET_VERIFIED
    return current is required  # pragma: no cover - no other requirement exists yet


def _state_for(records: Sequence[ActivityRecord]) -> tuple[CoverageState, str]:
    if not records:
        return CoverageState.NOT_OBSERVED, "nothing observed in this category"

    classes = {record.source_class for record in records}
    if classes <= {SourceClass.UNKNOWN, SourceClass.SUSPICIOUS}:
        return (
            CoverageState.SOURCE_UNKNOWN,
            (
                "records exist, but every one of them came from an origin the source "
                "classifier does not recognise"
            ),
        )

    supported = [
        record
        for record in records
        if record.evidence_level.is_externally_supported
        and record.source_class not in (SourceClass.UNKNOWN, SourceClass.SUSPICIOUS)
    ]
    if len(supported) >= _STRONG_THRESHOLD:
        return (
            CoverageState.STRONG_EVIDENCE,
            f"{len(supported)} records are supported by something other than the subject's word",
        )
    if supported:
        return (
            CoverageState.SOME_EVIDENCE,
            "one record is externally supported; a second would make this category strong",
        )
    return (
        CoverageState.SOME_EVIDENCE,
        (
            f"{len(records)} records observed, none of them externally supported yet; "
            "they rest on the subject's own signature"
        ),
    )


def compute_coverage(
    records: Iterable[ActivityRecord],
    *,
    network_phase: NetworkPhase = NetworkPhase.PRE_TESTNET,
) -> CoverageReport:
    """Fill the ten categories from the records, and refuse to add them up.

    Secondary records -- message volume and the like -- are excluded before
    anything is counted. Keeping them out here rather than filtering at the call
    site means no future caller can accidentally let volume into coverage.
    """
    all_records = list(records)
    synthetic = any(record.synthetic for record in all_records)
    primary = [record for record in all_records if not record.secondary]
    categories: list[CoverageCategory] = []
    for spec in COVERAGE_CATEGORIES:
        if spec.requires_phase is not None and not _phase_reached(
            network_phase, spec.requires_phase
        ):
            categories.append(
                CoverageCategory(
                    category_id=spec.category_id,
                    label=spec.label,
                    state=CoverageState.NOT_YET_AVAILABLE,
                    observed=0,
                    reason=spec.unavailable_reason,
                )
            )
            continue
        matched = [record for record in primary if record.category in spec.matches]
        state, reason = _state_for(matched)
        categories.append(
            CoverageCategory(
                category_id=spec.category_id,
                label=spec.label,
                state=state,
                observed=len(matched),
                reason=reason,
            )
        )
    return CoverageReport(
        categories=tuple(categories),
        network_phase=network_phase,
        contains_synthetic=synthetic,
    )


def category_state(report: CoverageReport, category_id: str) -> CoverageState | None:
    for category in report.categories:
        if category.category_id == category_id:
            return category.state
    return None


def strongest_level(records: Iterable[ActivityRecord]) -> EvidenceLevel | None:
    """The best-supported record in a set, for a detail panel to explain itself."""
    order = (
        EvidenceLevel.SELF_CLAIMED,
        EvidenceLevel.CRYPTOGRAPHICALLY_LINKED,
        EvidenceLevel.EVIDENCE_SUPPORTED,
        EvidenceLevel.THIRD_PARTY_ATTESTED,
    )
    best: EvidenceLevel | None = None
    for record in records:
        if best is None or order.index(record.evidence_level) > order.index(best):
            best = record.evidence_level
    return best


__all__ = [
    "COVERAGE_CATEGORIES",
    "CoverageReport",
    "category_state",
    "compute_coverage",
    "strongest_level",
]
