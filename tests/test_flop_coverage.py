"""Evidence coverage, and the wash signals that sit next to it.

The fifth acceptance case is the important one here: a testnet that has not
launched must read as "not yet available" and never as zero. Zero is an
observation about something that exists.

The wash tests are in this file because both modules answer the same kind of
question -- what can be honestly said about a set of records -- and both are
graded on their wording as much as their logic. `wash.py` may not accuse
anybody, and a test asserts the word.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from lineageauth.flop.coverage import (
    COVERAGE_CATEGORIES,
    category_state,
    compute_coverage,
    strongest_level,
)
from lineageauth.flop.model import (
    COVERAGE_LABEL,
    ActivityCategory,
    ActivityRecord,
    CoverageState,
    EvidenceLevel,
    NetworkPhase,
    SourceClass,
    VerificationState,
    forbidden_vocabulary_in,
)
from lineageauth.flop.wash import POSSIBLE_LOW_VALUE_LABEL, detect_wash_signals

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
DID = "did:key:z6MkExampleSubjectOnly"
OTHER = "did:key:z6MkExampleCounterparty"


def record(
    record_id: str,
    category: ActivityCategory,
    *,
    level: EvidenceLevel = EvidenceLevel.CRYPTOGRAPHICALLY_LINKED,
    source_class: SourceClass = SourceClass.VERIFIED_THIRD_PARTY,
    at: datetime = AT,
    artifact_hash: str | None = None,
    counterparties: tuple[str, ...] = (),
    secondary: bool = False,
    title: str = "a thing",
) -> ActivityRecord:
    return ActivityRecord(
        record_id=record_id,
        subject_did=DID,
        category=category,
        title=title,
        occurred_at=at,
        source_id="local-events",
        source_class=source_class,
        evidence_level=level,
        verification_state=VerificationState.VERIFIED,
        artifact_hash=artifact_hash,
        counterparties=counterparties,
        secondary=secondary,
    )


class TestTheTenCategories:
    def test_there_are_exactly_ten(self) -> None:
        assert len(COVERAGE_CATEGORIES) == 10
        assert compute_coverage([]).total == 10

    def test_the_label_is_carried_on_every_report(self) -> None:
        rendered = compute_coverage([]).to_dict()
        assert rendered["label"] == COVERAGE_LABEL
        assert rendered["isAirdropScore"] is False
        assert rendered["aggregateScore"] is None

    def test_no_forbidden_vocabulary_reaches_the_rendered_report(self) -> None:
        rendered = json.dumps(compute_coverage([]).to_dict())
        assert forbidden_vocabulary_in(rendered) == ()


class TestAcceptance5AMissingTestnetIsNotZero:
    def test_acceptance_5_inference_reads_not_yet_available_in_pre_testnet(self) -> None:
        """Acceptance test 5: no endpoint, so nothing to observe and no zero."""
        report = compute_coverage([], network_phase=NetworkPhase.PRE_TESTNET)
        inference = next(c for c in report.categories if c.category_id == "inference")
        assert inference.state is CoverageState.NOT_YET_AVAILABLE
        assert inference.state is not CoverageState.NOT_OBSERVED
        assert "has not launched" in inference.reason
        assert "0 FLOP" not in json.dumps(report.to_dict())

    def test_acceptance_5_not_yet_available_is_not_counted_as_covered(self) -> None:
        report = compute_coverage([], network_phase=NetworkPhase.PRE_TESTNET)
        assert report.covered == 0
        assert report.not_yet_available == 4

    def test_a_verified_but_unenabled_testnet_is_still_not_available(self) -> None:
        """Discovering an endpoint is not the same as switching it on."""
        for phase in (
            NetworkPhase.TESTNET_DISCOVERED_UNVERIFIED,
            NetworkPhase.TESTNET_VERIFIED,
        ):
            assert (
                category_state(compute_coverage([], network_phase=phase), "inference")
                is CoverageState.NOT_YET_AVAILABLE
            )

    def test_an_enabled_testnet_lets_the_category_report_what_is_observed(self) -> None:
        report = compute_coverage([], network_phase=NetworkPhase.TESTNET_ENABLED)
        assert category_state(report, "inference") is CoverageState.NOT_OBSERVED


class TestStates:
    def test_nothing_observed_reads_not_observed(self) -> None:
        report = compute_coverage([])
        assert category_state(report, "useful-work") is CoverageState.NOT_OBSERVED

    def test_one_externally_supported_record_is_some_evidence(self) -> None:
        report = compute_coverage(
            [record("r1", ActivityCategory.CONNECTOR, level=EvidenceLevel.EVIDENCE_SUPPORTED)]
        )
        assert category_state(report, "useful-work") is CoverageState.SOME_EVIDENCE

    def test_two_externally_supported_records_are_strong(self) -> None:
        report = compute_coverage(
            [
                record("r1", ActivityCategory.CONNECTOR, level=EvidenceLevel.EVIDENCE_SUPPORTED),
                record(
                    "r2",
                    ActivityCategory.DOCUMENTATION,
                    level=EvidenceLevel.THIRD_PARTY_ATTESTED,
                ),
            ]
        )
        assert category_state(report, "useful-work") is CoverageState.STRONG_EVIDENCE

    def test_self_signed_records_alone_never_reach_strong(self) -> None:
        """Three registrations by one key is one agent saying it three times."""
        report = compute_coverage(
            [record(f"r{index}", ActivityCategory.CONNECTOR) for index in range(5)]
        )
        assert category_state(report, "useful-work") is CoverageState.SOME_EVIDENCE

    def test_records_from_unknown_origins_only_read_source_unknown(self) -> None:
        report = compute_coverage(
            [
                record(
                    "r1",
                    ActivityCategory.CONNECTOR,
                    level=EvidenceLevel.EVIDENCE_SUPPORTED,
                    source_class=SourceClass.UNKNOWN,
                )
            ]
        )
        assert category_state(report, "useful-work") is CoverageState.SOURCE_UNKNOWN

    def test_volume_records_are_excluded_before_anything_is_counted(self) -> None:
        report = compute_coverage(
            [
                record(
                    "r-volume",
                    ActivityCategory.CONNECTOR,
                    level=EvidenceLevel.EVIDENCE_SUPPORTED,
                    secondary=True,
                )
            ]
        )
        assert category_state(report, "useful-work") is CoverageState.NOT_OBSERVED

    def test_strongest_level_reports_the_best_supported_record(self) -> None:
        assert strongest_level([]) is None
        assert (
            strongest_level(
                [
                    record("a", ActivityCategory.CONNECTOR),
                    record(
                        "b",
                        ActivityCategory.CONNECTOR,
                        level=EvidenceLevel.THIRD_PARTY_ATTESTED,
                    ),
                ]
            )
            is EvidenceLevel.THIRD_PARTY_ATTESTED
        )


class TestWashSignalsDoNotAccuse:
    def test_a_repeated_content_hash_is_reported(self) -> None:
        signals = detect_wash_signals(
            [
                record("r1", ActivityCategory.CONNECTOR, artifact_hash="sha256:aa"),
                record("r2", ActivityCategory.CONNECTOR, artifact_hash="sha256:aa"),
            ]
        )
        assert [signal.pattern_id for signal in signals] == ["wash.duplicate-artifact-hash"]
        assert signals[0].label == POSSIBLE_LOW_VALUE_LABEL

    def test_self_dealing_is_reported(self) -> None:
        signals = detect_wash_signals(
            [record("r1", ActivityCategory.TCLK_DEAL, counterparties=(DID,))]
        )
        assert any(signal.pattern_id == "wash.self-dealing" for signal in signals)

    def test_a_burst_with_nothing_produced_is_reported(self) -> None:
        signals = detect_wash_signals(
            [
                record(
                    f"r{index}",
                    ActivityCategory.ROOM_PARTICIPATION,
                    at=AT + timedelta(minutes=index),
                    title=f"post {index}",
                )
                for index in range(6)
            ]
        )
        assert any(signal.pattern_id == "wash.rapid-churn-without-artifact" for signal in signals)

    def test_distinct_useful_work_produces_no_signal(self) -> None:
        signals = detect_wash_signals(
            [
                record("r1", ActivityCategory.CONNECTOR, artifact_hash="sha256:aa", title="one"),
                record(
                    "r2",
                    ActivityCategory.DOCUMENTATION,
                    artifact_hash="sha256:bb",
                    title="two",
                    at=AT + timedelta(days=3),
                ),
            ]
        )
        assert signals == ()

    def test_nothing_is_called_fraud(self) -> None:
        """The wording is the feature. An outside observer's difficulty, not a verdict."""
        signals = detect_wash_signals(
            [
                record("r1", ActivityCategory.CONNECTOR, artifact_hash="sha256:aa"),
                record("r2", ActivityCategory.CONNECTOR, artifact_hash="sha256:aa"),
                record("r3", ActivityCategory.TCLK_DEAL, counterparties=(DID,)),
            ]
        )
        rendered = json.dumps([signal.to_dict() for signal in signals]).lower()
        for word in ("fraud", "cheat", "sybil attack", "banned", "disqualif"):
            assert word not in rendered
        for signal in signals:
            assert signal.to_dict()["isAccusation"] is False
            assert "not a finding that anything improper happened" in signal.reason

    def test_an_undisclosed_counterparty_is_not_assumed_related(self) -> None:
        """No disclosure means no disclosure -- never that two keys are independent."""
        signals = detect_wash_signals(
            [record("r1", ActivityCategory.TCLK_DEAL, counterparties=(OTHER,))]
        )
        assert signals == ()
