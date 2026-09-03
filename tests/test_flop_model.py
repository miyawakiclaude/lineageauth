"""The FLOP vocabulary, and the two things it refuses to represent.

A safety finding that recorded an execution, and a passport that added its
categories into one number, would each be a product decision reversed by a
data model. Both are tested here rather than assumed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import (
    COVERAGE_LABEL,
    COVERAGE_LABEL_ASCII,
    NOT_AFFILIATED_NOTICE,
    SEED_WARNING_NOTICE,
    SYNTHETIC_BANNER,
    ActivityCategory,
    ActivityRecord,
    CoverageCategory,
    CoverageState,
    EvidenceLevel,
    FeatureStatus,
    FlopActivityPassport,
    NetworkPhase,
    PassportSection,
    Recommendation,
    RecommendationType,
    SafetyFinding,
    SafetyLevel,
    SourceClass,
    VerificationState,
    forbidden_vocabulary_in,
    sort_records,
)

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
DID = "did:key:z6MkExampleSubjectOnly"


def record(**overrides: object) -> ActivityRecord:
    base: dict[str, object] = {
        "record_id": "r-1",
        "subject_did": DID,
        "category": ActivityCategory.USEFUL_ARTIFACT,
        "title": "a thing that happened",
        "occurred_at": AT,
        "source_id": "local-events",
        "source_class": SourceClass.VERIFIED_THIRD_PARTY,
        "evidence_level": EvidenceLevel.CRYPTOGRAPHICALLY_LINKED,
        "verification_state": VerificationState.VERIFIED,
    }
    base.update(overrides)
    return ActivityRecord(**base)  # type: ignore[arg-type]


class TestTheScannerCannotAuthorise:
    def test_a_finding_may_not_record_an_execution(self) -> None:
        """The one value the type refuses to hold."""
        with pytest.raises(MalformedEventError, match="authorises nothing"):
            SafetyFinding(
                finding_id="f-1",
                level=SafetyLevel.BLOCKED,
                pattern_id="secret.seed-phrase",
                reason="asked for a seed phrase",
                source_class=SourceClass.UNKNOWN,
                executed=True,
            )

    def test_a_rendered_finding_always_says_executed_false(self) -> None:
        finding = SafetyFinding(
            finding_id="f-1",
            level=SafetyLevel.HIGH_RISK,
            pattern_id="url.technocore-get-write",
            reason="would write when fetched",
            source_class=SourceClass.COMMUNITY,
            url="https://technocore.chat/r/lobby/say/nonce/hello",
        )
        rendered = finding.to_dict()
        assert rendered["executed"] is False
        assert rendered["autoOpened"] is False
        assert rendered["display"] == "HIGH RISK"


class TestEvidenceLevels:
    def test_self_claimed_and_crypto_linked_are_not_external_support(self) -> None:
        """A signature proves key control. It does not add a second party."""
        assert not EvidenceLevel.SELF_CLAIMED.is_externally_supported
        assert not EvidenceLevel.CRYPTOGRAPHICALLY_LINKED.is_externally_supported
        assert EvidenceLevel.EVIDENCE_SUPPORTED.is_externally_supported
        assert EvidenceLevel.THIRD_PARTY_ATTESTED.is_externally_supported

    def test_there_is_no_numeric_ordering_exposed(self) -> None:
        """No `.score`, no `.weight`: a rating is what these four are not."""
        for level in EvidenceLevel:
            assert not hasattr(level, "score")
            assert not hasattr(level, "weight")


class TestCoverageStates:
    def test_not_yet_available_is_not_counted_as_covered(self) -> None:
        assert not CoverageState.NOT_YET_AVAILABLE.is_covered
        assert not CoverageState.NOT_OBSERVED.is_covered
        assert not CoverageState.SOURCE_UNKNOWN.is_covered
        assert CoverageState.SOME_EVIDENCE.is_covered
        assert CoverageState.STRONG_EVIDENCE.is_covered


class TestNetworkPhase:
    def test_only_the_enabled_rung_is_live(self) -> None:
        """Verified means somebody checked. Enabled means it is switched on."""
        assert NetworkPhase.TESTNET_ENABLED.testnet_is_live
        assert not NetworkPhase.TESTNET_VERIFIED.testnet_is_live
        assert not NetworkPhase.TESTNET_DISCOVERED_UNVERIFIED.testnet_is_live
        assert not NetworkPhase.PRE_TESTNET.testnet_is_live

    def test_badges_collapse_to_the_three_a_user_reads(self) -> None:
        assert NetworkPhase.PRE_TESTNET.badge == "PRE-TESTNET"
        assert NetworkPhase.TESTNET_VERIFIED.badge == "TESTNET"
        assert NetworkPhase.MAINNET_VERIFIED.badge == "MAINNET"


class TestRecommendationsCannotClaimOfficialByAccident:
    def test_an_official_type_without_a_rule_is_not_official(self) -> None:
        item = Recommendation(
            recommendation_id="rec-1",
            title="wait for the testnet",
            recommendation_type=RecommendationType.OFFICIAL_DIRECTION,
            reason="no endpoint is published",
            confidence="high",
        )
        assert item.official is False

    def test_an_inferred_type_stays_unofficial_even_with_a_rule(self) -> None:
        item = Recommendation(
            recommendation_id="rec-2",
            title="seek verification",
            recommendation_type=RecommendationType.EVIDENCE_GAP,
            reason="nobody else has vouched",
            confidence="high",
            rule_id="flop-testnet-schedule",
        )
        assert item.official is False


class TestUsefulWork:
    def test_acceptance_8_an_activity_without_evidence_stays_self_claimed(self) -> None:
        """Acceptance test 8: convincing prose does not upgrade anything.

        The record below describes itself in the strongest terms available and
        carries no artifact and no third party. Its level is whatever the
        importer assigned, and nothing in the model reads the title.
        """
        claimed = record(
            record_id="r-selfclaim",
            title="Groundbreaking, independently confirmed, official reference implementation",
            evidence_level=EvidenceLevel.SELF_CLAIMED,
            verification_state=VerificationState.UNVERIFIED,
            artifact_hash=None,
            third_party_ref=None,
        )
        assert claimed.evidence_level is EvidenceLevel.SELF_CLAIMED
        assert claimed.to_dict()["evidenceLevel"] == "self-claimed"
        assert claimed.to_dict()["artifactHash"] is None

    def test_a_secondary_record_is_never_useful_work(self) -> None:
        """Volume stays visible and stays out of the count, whatever its category."""
        volume = record(
            record_id="r-volume",
            category=ActivityCategory.USEFUL_ARTIFACT,
            secondary=True,
        )
        assert volume.is_useful_work is False

    def test_records_sort_deterministically(self) -> None:
        early = record(record_id="b", occurred_at=datetime(2026, 1, 1, tzinfo=UTC))
        late = record(record_id="a", occurred_at=datetime(2026, 6, 1, tzinfo=UTC))
        assert [item.record_id for item in sort_records([late, early])] == ["b", "a"]


class TestThePassportRefusesToTotalItself:
    def build(self) -> FlopActivityPassport:
        return FlopActivityPassport(
            subject_did=DID,
            lineage="sha256:" + "ab" * 32,
            generated_at=AT,
            network_phase=NetworkPhase.PRE_TESTNET,
            sections=(
                PassportSection(
                    section_id="inference",
                    status=FeatureStatus.NOT_YET_AVAILABLE,
                    reason="no official endpoint is published",
                ),
            ),
            coverage=(
                CoverageCategory("useful-work", "Useful work", CoverageState.SOME_EVIDENCE, 1, "x"),
                CoverageCategory(
                    "inference", "Testnet inference", CoverageState.NOT_YET_AVAILABLE, 0, "y"
                ),
            ),
            activities=(record(),),
        )

    def test_there_is_no_aggregate_score_field(self) -> None:
        rendered = json.dumps(self.build().to_dict())
        for banned in ("airdropScore", "eligibilityScore", "allocationEstimate", "rank"):
            assert banned not in rendered

    def test_the_coverage_label_is_carried_verbatim(self) -> None:
        coverage = self.build().to_dict()["evidenceCoverage"]
        assert coverage["label"] == COVERAGE_LABEL
        assert coverage["labelAscii"] == COVERAGE_LABEL_ASCII
        assert coverage["isAirdropScore"] is False

    def test_the_ascii_label_survives_a_cp932_console(self) -> None:
        """The em-dash lesson from tests/test_zero_cost.py, kept learned."""
        COVERAGE_LABEL_ASCII.encode("cp932")
        NOT_AFFILIATED_NOTICE.encode("cp932")
        SEED_WARNING_NOTICE.encode("cp932")

    def test_the_required_notices_are_present(self) -> None:
        notices = self.build().to_dict()["notices"]
        assert notices["affiliation"] == NOT_AFFILIATED_NOTICE
        assert notices["seedPhrase"] == SEED_WARNING_NOTICE
        assert "seed phrase" in notices["seedPhrase"]

    def test_no_forbidden_vocabulary_appears_anywhere(self) -> None:
        rendered = json.dumps(self.build().to_dict())
        assert forbidden_vocabulary_in(rendered) == ()

    def test_it_states_that_it_holds_no_keys_and_takes_no_custody(self) -> None:
        rendered = self.build().to_dict()
        assert rendered["holdsPrivateKeys"] is False
        assert rendered["walletCustody"] is False

    def test_synthetic_data_carries_the_banner(self) -> None:
        synthetic = record(record_id="r-mock", synthetic=True)
        assert synthetic.to_dict()["banner"] == SYNTHETIC_BANNER
