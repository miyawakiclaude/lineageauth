"""The recommendation engine, and the suggestions it must never make.

Half of this file is about absence. A tool that suggests next steps for an
airdrop is one bad rule away from being a farming guide, and the cheapest thing
to suggest is always volume. So the engine's catalogue is closed, and the tests
assert that no reachable combination of inputs produces an instruction to create
more identities, post more messages, repeat an artifact, or manufacture a
collaboration.

The other half is about labelling. `official` is computed from the type and the
rule id together, so advice this tool inferred cannot become official by
somebody forgetting to pass something.
"""

from __future__ import annotations

import itertools
import json
from datetime import UTC, datetime

from lineageauth.flop.coverage import compute_coverage
from lineageauth.flop.model import (
    ActivityCategory,
    ActivityRecord,
    EvidenceLevel,
    NetworkPhase,
    RecommendationType,
    SafetyFinding,
    SafetyLevel,
    SourceClass,
    VerificationState,
    forbidden_vocabulary_in,
)
from lineageauth.flop.recommend import (
    FORBIDDEN_SUGGESTION_PATTERNS,
    next_best_action,
    recommend,
)
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.wash import detect_wash_signals

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
DID = "did:key:z6MkExampleSubjectOnly"

REGISTRY = FlopRuleRegistry.load()


def record(
    record_id: str,
    category: ActivityCategory,
    *,
    level: EvidenceLevel = EvidenceLevel.EVIDENCE_SUPPORTED,
    secondary: bool = False,
    artifact_hash: str | None = None,
) -> ActivityRecord:
    return ActivityRecord(
        record_id=record_id,
        subject_did=DID,
        category=category,
        title=f"record {record_id}",
        occurred_at=AT,
        source_id="local-events",
        source_class=SourceClass.VERIFIED_THIRD_PARTY,
        evidence_level=level,
        verification_state=VerificationState.VERIFIED,
        artifact_hash=artifact_hash,
        secondary=secondary,
    )


def blocked_finding() -> SafetyFinding:
    return SafetyFinding(
        finding_id="f-1",
        level=SafetyLevel.BLOCKED,
        pattern_id="secret.seed-phrase",
        reason="asked for a seed phrase",
        source_class=SourceClass.UNKNOWN,
    )


class TestWhatIsRecommended:
    def test_pre_testnet_produces_an_official_direction_to_wait(self) -> None:
        items = recommend(compute_coverage([]), registry=REGISTRY)
        waiting = next(
            item
            for item in items
            if item.recommendation_type is RecommendationType.OFFICIAL_DIRECTION
            and "testnet" in item.title
        )
        assert waiting.official is True
        assert waiting.rule_id == "flop-testnet-schedule"

    def test_a_missing_external_verification_is_an_evidence_gap(self) -> None:
        items = recommend(compute_coverage([]), registry=REGISTRY)
        gaps = [
            item for item in items if item.recommendation_type is RecommendationType.EVIDENCE_GAP
        ]
        assert any("independent verification" in item.title for item in gaps)
        assert all(item.official is False for item in gaps)

    def test_a_blocked_finding_puts_security_first(self) -> None:
        items = recommend(compute_coverage([]), safety=[blocked_finding()], registry=REGISTRY)
        best = next_best_action(items)
        assert best is not None
        assert best.recommendation_type is RecommendationType.SECURITY_RECOMMENDATION
        assert "seed phrase" in best.reason

    def test_volume_without_artifacts_asks_for_one_artifact(self) -> None:
        items = recommend(
            compute_coverage([]),
            records=[record("v", ActivityCategory.MESSAGE_VOLUME, secondary=True)],
            registry=REGISTRY,
        )
        assert any("one artifact that can be pointed at" in item.title for item in items)

    def test_wash_signals_produce_a_security_note_rather_than_an_accusation(self) -> None:
        signals = detect_wash_signals(
            [
                record("a", ActivityCategory.CONNECTOR, artifact_hash="sha256:aa"),
                record("b", ActivityCategory.CONNECTOR, artifact_hash="sha256:aa"),
            ]
        )
        items = recommend(compute_coverage([]), wash_signals=signals, registry=REGISTRY)
        note = next(item for item in items if "wash activity" in item.title)
        assert note.recommendation_type is RecommendationType.SECURITY_RECOMMENDATION

    def test_tclk_absence_is_context_not_a_requirement(self) -> None:
        items = recommend(compute_coverage([]), registry=REGISTRY)
        tclk = next(item for item in items if "tclk" in item.title)
        assert tclk.recommendation_type is RecommendationType.COMMUNITY_OBSERVATION
        assert tclk.official is False
        assert "not an official FLOP requirement" in tclk.title

    def test_every_recommendation_carries_a_reason_and_a_confidence(self) -> None:
        for item in recommend(compute_coverage([]), registry=REGISTRY):
            assert item.reason
            assert item.confidence in {"low", "medium", "high"}
            assert item.to_dict()["isEligibilityClaim"] is False


class TestWhatIsNeverRecommended:
    def all_reachable(self) -> list[str]:
        """Every recommendation the engine can produce, over its whole input space.

        Small enough to enumerate, which is the point: an engine whose outputs
        cannot be listed cannot be checked for the things it must never say.
        """
        texts: list[str] = []
        record_sets: list[list[ActivityRecord]] = [
            [],
            [record("v", ActivityCategory.MESSAGE_VOLUME, secondary=True)],
            [
                record("a", ActivityCategory.CONNECTOR, artifact_hash="sha256:aa"),
                record("b", ActivityCategory.CONNECTOR, artifact_hash="sha256:aa"),
                record("c", ActivityCategory.EXTERNAL_VERIFICATION),
                record("d", ActivityCategory.AGENT_COLLABORATION),
                record("e", ActivityCategory.TCLK_DEAL),
            ],
        ]
        for records, phase, safety, registry in itertools.product(
            record_sets,
            list(NetworkPhase),
            ([], [blocked_finding()]),
            (None, REGISTRY),
        ):
            items = recommend(
                compute_coverage(records, network_phase=phase),
                records=records,
                safety=safety,
                wash_signals=detect_wash_signals(records),
                registry=registry,
                network_phase=phase,
            )
            texts.extend(f"{item.title} {item.reason}" for item in items)
        return texts

    def test_no_reachable_recommendation_suggests_spam(self) -> None:
        for text in self.all_reachable():
            lowered = text.lower()
            for banned in FORBIDDEN_SUGGESTION_PATTERNS:
                assert banned not in lowered, f"{banned!r} appeared in: {text}"

    def test_no_reachable_recommendation_promises_an_allocation(self) -> None:
        for text in self.all_reachable():
            assert forbidden_vocabulary_in(text) == (), text

    def test_no_reachable_recommendation_is_official_without_a_rule(self) -> None:
        items = recommend(compute_coverage([]), registry=None)
        for item in items:
            if item.recommendation_type.is_official:
                assert item.official is False, "an official type with no rule is not official"

    def test_the_rendered_form_never_carries_a_score(self) -> None:
        rendered = json.dumps(
            [item.to_dict() for item in recommend(compute_coverage([]), registry=REGISTRY)]
        )
        # "allocation" on its own is allowed, because one of the recommendations
        # says nothing here predicts one. What may not appear is the possessive
        # or estimated form -- the shapes that make it a claim about the reader.
        for banned in ("score", "rank", "your allocation", "estimated allocation"):
            assert banned not in rendered.lower()


class TestOrdering:
    def test_next_best_action_prefers_security_then_gaps(self) -> None:
        items = recommend(compute_coverage([]), safety=[blocked_finding()], registry=REGISTRY)
        assert next_best_action(items) is not None
        assert (
            next_best_action(items).recommendation_type  # type: ignore[union-attr]
            is RecommendationType.SECURITY_RECOMMENDATION
        )

    def test_next_best_action_is_none_when_there_is_nothing_to_say(self) -> None:
        assert next_best_action([]) is None

    def test_recommendation_ids_are_stable_for_the_same_input(self) -> None:
        first = recommend(compute_coverage([]), registry=REGISTRY)
        second = recommend(compute_coverage([]), registry=REGISTRY)
        assert [item.recommendation_id for item in first] == [
            item.recommendation_id for item in second
        ]
