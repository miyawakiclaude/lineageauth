"""Rule-based recommendations. Never an eligibility claim, never a spam plan.

Rules rather than a model, for two reasons. A suggestion has to say which rule
produced it and whether that rule is official, and a generated sentence cannot
honestly do either. And a suggestion engine trained to maximise anything will
eventually suggest volume, because volume is the easiest thing to maximise.

So the catalogue below is closed and every entry is written out. What is absent
matters as much as what is present: nothing here proposes creating more DIDs,
posting more messages, repeating an artifact, arranging a collaboration for the
record, or buying inference to move a number. A test asserts that the imperative
forms of those never appear in any generated recommendation.

`Recommendation.official` is computed rather than set: it is true only when the
type is one of the two official kinds *and* a rule id from the registry is
attached. Advice this tool inferred cannot be labelled official by forgetting to
pass something.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from lineageauth.flop.coverage import CoverageReport, category_state
from lineageauth.flop.model import (
    ActivityRecord,
    CoverageState,
    NetworkPhase,
    Recommendation,
    RecommendationType,
    SafetyFinding,
    SafetyLevel,
    WashSignal,
)
from lineageauth.flop.rules import FlopRuleRegistry

# Phrasings that would turn this into the thing the product refuses to be.
# Checked by a test against every recommendation the engine can emit.
FORBIDDEN_SUGGESTION_PATTERNS: tuple[str, ...] = (
    "create more did",
    "create additional did",
    "create 500",
    "more dids",
    "post more",
    "repeat the same",
    "flood",
    "farm the airdrop",
    "maximise your allocation",
    "maximize your allocation",
    "guaranteed",
    "you will receive",
    "eligible",
)


def _next_index(counter: list[int]) -> int:
    counter[0] += 1
    return counter[0]


def recommend(
    coverage: CoverageReport,
    *,
    records: Sequence[ActivityRecord] = (),
    safety: Iterable[SafetyFinding] = (),
    wash_signals: Iterable[WashSignal] = (),
    registry: FlopRuleRegistry | None = None,
    network_phase: NetworkPhase = NetworkPhase.PRE_TESTNET,
) -> tuple[Recommendation, ...]:
    """Suggest next steps from what was observed. Nothing here is a promise."""
    counter = [0]
    out: list[Recommendation] = []

    findings = list(safety)
    signals = list(wash_signals)

    serious = [
        finding
        for finding in findings
        if finding.level in (SafetyLevel.HIGH_RISK, SafetyLevel.BLOCKED)
    ]
    if serious:
        out.append(
            Recommendation(
                recommendation_id=f"rec-{_next_index(counter):03d}",
                title="Review the blocked and high-risk items before acting on anything",
                recommendation_type=RecommendationType.SECURITY_RECOMMENDATION,
                reason=(
                    f"{len(serious)} pieces of untrusted content were flagged and none of them "
                    "were opened or executed. Read them yourself before deciding. No FLOP "
                    "process needs a seed phrase or a private key."
                ),
                confidence="high",
            )
        )

    if not network_phase.testnet_is_live:
        rule_id = None
        if registry is not None and registry.get("flop-testnet-schedule") is not None:
            rule_id = "flop-testnet-schedule"
        out.append(
            Recommendation(
                recommendation_id=f"rec-{_next_index(counter):03d}",
                title="Wait for an official FLOP testnet endpoint before any inference activity",
                recommendation_type=RecommendationType.OFFICIAL_DIRECTION,
                reason=(
                    "The published draft plans a testnet for Q4 2026 and no endpoint has been "
                    "announced. Until one is published by an official origin, inference "
                    "tracking stays inactive and this tool refuses to reach any network."
                ),
                confidence="high",
                rule_id=rule_id,
            )
        )

    external = category_state(coverage, "external-verification")
    if external in (CoverageState.NOT_OBSERVED, CoverageState.SOURCE_UNKNOWN):
        out.append(
            Recommendation(
                recommendation_id=f"rec-{_next_index(counter):03d}",
                title="Seek one independent verification of work you have already published",
                recommendation_type=RecommendationType.EVIDENCE_GAP,
                reason=(
                    "Nothing observed shows somebody other than you vouching for your work. "
                    "One independent verification changes more than any amount of additional "
                    "self-signed activity."
                ),
                confidence="high",
            )
        )
    elif external is CoverageState.SOME_EVIDENCE:
        out.append(
            Recommendation(
                recommendation_id=f"rec-{_next_index(counter):03d}",
                title="A second independent verification would make external verification strong",
                recommendation_type=RecommendationType.EVIDENCE_GAP,
                reason=(
                    "One external record was observed. A second, from a different party, is "
                    "what separates a one-off from a pattern."
                ),
                confidence="medium",
            )
        )

    collaboration = category_state(coverage, "collaboration")
    if collaboration is CoverageState.NOT_OBSERVED:
        out.append(
            Recommendation(
                recommendation_id=f"rec-{_next_index(counter):03d}",
                title="Complete one reproducible collaboration with an agent you do not operate",
                recommendation_type=RecommendationType.EVIDENCE_GAP,
                reason=(
                    "No collaboration was observed. What counts here is a counterparty nobody "
                    "can tie to you; two keys under one operator produce a record that reads "
                    "as one party talking to itself."
                ),
                confidence="medium",
            )
        )

    tclk = category_state(coverage, "tclk")
    if tclk is CoverageState.NOT_OBSERVED:
        out.append(
            Recommendation(
                recommendation_id=f"rec-{_next_index(counter):03d}",
                title="tclk activity is a community protocol, not an official FLOP requirement",
                recommendation_type=RecommendationType.COMMUNITY_OBSERVATION,
                reason=(
                    "No tclk deal was observed. Nothing published by FLOP Labs says tclk "
                    "participation is required for anything, so this is context rather than "
                    "a gap to close."
                ),
                confidence="low",
            )
        )

    if signals:
        out.append(
            Recommendation(
                recommendation_id=f"rec-{_next_index(counter):03d}",
                title=(
                    "Vary what you produce so your activity is distinguishable from wash activity"
                ),
                recommendation_type=RecommendationType.SECURITY_RECOMMENDATION,
                reason=(
                    f"{len(signals)} patterns were noticed that an outside observer cannot tell "
                    "apart from circular or low-value activity. Distinct artifacts and "
                    "counterparties you do not operate are what makes the difference visible."
                ),
                confidence="medium",
            )
        )

    useful = [record for record in records if record.is_useful_work]
    secondary = [record for record in records if record.secondary]
    if secondary and not useful:
        out.append(
            Recommendation(
                recommendation_id=f"rec-{_next_index(counter):03d}",
                title="Publish one artifact that can be pointed at",
                recommendation_type=RecommendationType.EVIDENCE_GAP,
                reason=(
                    "Message volume was observed and no artifact was. Volume is not evidence "
                    "of useful participation, and a single addressable artifact carries more "
                    "than any number of messages."
                ),
                confidence="high",
            )
        )

    if registry is not None:
        unknown = registry.unknown_rules
        if unknown:
            out.append(
                Recommendation(
                    recommendation_id=f"rec-{_next_index(counter):03d}",
                    title="Treat every FLOP figure as provisional",
                    recommendation_type=RecommendationType.OFFICIAL_DIRECTION,
                    reason=(
                        f"{len(unknown)} things this tool would need are not stated by any "
                        "official source, and the published document says of itself that its "
                        "figures may change. Nothing here predicts an allocation."
                    ),
                    confidence="high",
                    rule_id=(
                        "flop-figures-provisional"
                        if registry.get("flop-figures-provisional") is not None
                        else None
                    ),
                )
            )

    return tuple(out)


def next_best_action(recommendations: Sequence[Recommendation]) -> Recommendation | None:
    """The one to show under the hero. Security first, then evidence gaps."""
    order = (
        RecommendationType.SECURITY_RECOMMENDATION,
        RecommendationType.EVIDENCE_GAP,
        RecommendationType.OFFICIAL_REQUIREMENT,
        RecommendationType.OFFICIAL_DIRECTION,
        RecommendationType.COMMUNITY_OBSERVATION,
    )
    for wanted in order:
        for recommendation in recommendations:
            if recommendation.recommendation_type is wanted:
                return recommendation
    return None


__all__ = [
    "FORBIDDEN_SUGGESTION_PATTERNS",
    "next_best_action",
    "recommend",
]
