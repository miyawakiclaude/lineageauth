"""The FLOP Activity Passport: a projection over the core passport, not a rival to it.

`lineageauth.passport` already answers "what does this bundle say about this
DID", in four categories it refuses to merge. This module answers a narrower
question -- "what of that is relevant to participating in FLOP, and what is
still unknown" -- and it answers it by layering on top rather than by
recomputing. There is no combined figure here for the same reason there is none
there: the four categories are different kinds of claim, and adding them
produces a number nobody signed.

Every section carries a `FeatureStatus`. That is the difference between "you
have done nothing here" and "there is nothing here to do yet", and a dashboard
that cannot say which one it means will show a zero for a network that has not
launched. In `PRE_TESTNET` the inference, broker, creator and mainnet sections
are `not-yet-available`, and they say why.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime

from lineageauth.bundle import EventBundle
from lineageauth.errors import LineageAuthError
from lineageauth.fleet import FleetView, resolve_fleets
from lineageauth.flop.activity import (
    ActivityCollection,
    ActivitySourceAdapter,
    ActivitySubject,
    collect_activities,
)
from lineageauth.flop.coverage import compute_coverage
from lineageauth.flop.model import (
    ActivityCategory,
    FeatureStatus,
    FlopActivityPassport,
    NetworkPhase,
    PassportSection,
    SafetyFinding,
    SourceClass,
)
from lineageauth.flop.recommend import recommend
from lineageauth.flop.rules import (
    UNLOCK_RULE_ID,
    FlopRuleRegistry,
    unlock_ratio,
    unlock_ratio_gap,
    unlocked_per_ratio,
)
from lineageauth.flop.sources import SourceSnapshotSet
from lineageauth.flop.wash import detect_wash_signals
from lineageauth.passport import build_passport

_NOT_YET = FeatureStatus.NOT_YET_AVAILABLE

_FUTURE_SECTIONS: tuple[tuple[str, str], ...] = (
    (
        "inference",
        "Testnet inference tracking will activate when an official compatible endpoint is "
        "available. No official FLOP testnet endpoint is published, so there is nothing to "
        "observe and nothing to report as zero.",
    ),
    (
        "broker",
        "The broker side of the market described by the published draft does not exist on the "
        "current network phase.",
    ),
    (
        "creator",
        "No official creator-attribution mechanism has been published.",
    ),
    (
        "validator",
        "Validator participation requires a running network. None is available.",
    ),
    (
        "miner",
        "Miner participation requires a running network. None is available.",
    ),
)

_MAINNET_PLAN = "Mainnet is planned for Q1 2027 in a draft whose figures are provisional."


_GENESIS_RULE_ID = "flop-agent-grant-no-end-block"
"""The registered rule that says nothing of an Agent grant unlocks at its start block."""


def _mainnet_unlock_reason(
    registry: FlopRuleRegistry | None, snapshot: SourceSnapshotSet | None = None
) -> str:
    """Why the mainnet-unlock section is empty.

    The rule ids and the figures are read from the registry; the remaining wording
    is fixed text. The figure is never written here: D-122 had to rewrite a
    hard-coded sentence when the teaser withdrew the ratio, and D-123 when the
    airdrop page restored it. "Nothing liquid at genesis" is said only while the
    registry carries the rule that states it, and no figure is shown from a rule
    whose source has moved since it was recorded, or that cannot be checked.
    """
    if registry is None:
        return f"{_MAINNET_PLAN} No rule registry was supplied, so no unlock rule is shown."
    gap = unlock_ratio_gap(registry)
    rule = registry.get(UNLOCK_RULE_ID)
    ratio = unlock_ratio(registry)
    if gap is not None or rule is None or ratio is None:
        return f"{_MAINNET_PLAN} No unlock rule is shown: {gap}."
    standing = {e.rule_id: e for e in registry.freshness(snapshot)} if snapshot is not None else {}
    unlock_standing = standing.get(UNLOCK_RULE_ID)
    if unlock_standing is not None and not unlock_standing.may_be_treated_as_current:
        return (
            f"{_MAINNET_PLAN} The registered unlock rule ({rule.rule_id}) is not shown: "
            f"{unlock_standing.detail}."
        )
    genesis_standing = standing.get(_GENESIS_RULE_ID)
    genesis = (
        f", with nothing liquid at genesis ({_GENESIS_RULE_ID})"
        if registry.get(_GENESIS_RULE_ID) is not None
        and (genesis_standing is None or genesis_standing.may_be_treated_as_current)
        else ""
    )
    return (
        f"{_MAINNET_PLAN} The draft rule in the registry ({rule.rule_id}) unlocks "
        f"{unlocked_per_ratio(registry)} $FLOP of a locked agent airdrop for every {ratio} "
        f"$FLOP of the locked balance spent in settled sessions{genesis}. There is no mainnet "
        "to observe it on."
    )


def _identity_section(
    bundle: EventBundle,
    *,
    lineage: str,
    did: str,
    at: datetime,
    collection: ActivityCollection,
) -> PassportSection:
    """Continuity, taken from the core passport rather than recomputed.

    DID age is reported and deliberately not valued. An old key that did
    nothing is an old key.
    """
    try:
        core = build_passport(bundle, lineage=lineage, did=did, at=at)
    except LineageAuthError as exc:
        return PassportSection(
            section_id="identity",
            status=FeatureStatus.NOT_CONFIGURED,
            reason=f"the lineage could not be resolved: {exc}",
        )

    observed = [record.occurred_at for record in collection.records]
    days = len({moment.date() for moment in observed})
    return PassportSection(
        section_id="identity",
        status=FeatureStatus.AVAILABLE if core.lineage_resolved else FeatureStatus.NOT_CONFIGURED,
        reason=(
            "resolved from signed events"
            if core.lineage_resolved
            else f"lineage did not resolve: {core.lineage_reason}"
        ),
        detail={
            "did": did,
            "lineage": lineage,
            "lineageResolved": core.lineage_resolved,
            "epoch": core.epoch,
            "holdsLiveAuthority": core.holds_live_authority,
            "disclosedFleets": list(core.disclosed_fleets),
            "firstObserved": min(observed).isoformat() if observed else None,
            "lastObserved": max(observed).isoformat() if observed else None,
            "signedActivityDays": days,
            "ageIsNotValue": (
                "Continuity is shown because it is a fact. It is not evidence of useful work "
                "and carries no allocation meaning."
            ),
        },
    )


def _useful_section(collection: ActivityCollection) -> PassportSection:
    useful = collection.useful_work
    return PassportSection(
        section_id="usefulParticipation",
        status=FeatureStatus.AVAILABLE if useful else FeatureStatus.NOT_OBSERVED,
        reason=(
            f"{len(useful)} records qualify as useful work"
            if useful
            else "no useful-work record was observed"
        ),
        detail={
            "count": len(useful),
            "secondaryCount": len(collection.secondary),
            "records": [record.record_id for record in useful],
        },
    )


def _category_section(
    section_id: str, collection: ActivityCollection, categories: frozenset[ActivityCategory]
) -> PassportSection:
    matched = [record for record in collection.records if record.category in categories]
    configured = any(
        record.source_id.startswith(section_id) for record in collection.records
    ) or bool(matched)
    return PassportSection(
        section_id=section_id,
        status=(
            FeatureStatus.AVAILABLE
            if matched
            else (FeatureStatus.NOT_OBSERVED if configured else FeatureStatus.NOT_CONFIGURED)
        ),
        reason=(
            f"{len(matched)} records observed"
            if matched
            else "no record from this source was observed"
        ),
        detail={"records": [record.record_id for record in matched]},
    )


def build_flop_passport(
    bundle: EventBundle,
    *,
    lineage: str,
    did: str,
    at: datetime,
    adapters: Iterable[ActivitySourceAdapter] = (),
    registry: FlopRuleRegistry | None = None,
    snapshot: SourceSnapshotSet | None = None,
    network_phase: NetworkPhase = NetworkPhase.PRE_TESTNET,
    safety: Sequence[SafetyFinding] = (),
) -> FlopActivityPassport:
    """Build the passport from signed events plus whatever the adapters found.

    `at` is a parameter, never the clock: the same bundle and the same instant
    must produce the same passport, or two people comparing what they see cannot
    tell a disagreement from a timing difference.
    """
    subject = ActivitySubject(did=did, lineage=lineage, at=at)
    collection = collect_activities(adapters, subject)

    fleets: FleetView | None
    try:
        fleets = resolve_fleets(bundle, lineage=lineage, at=at)
    except LineageAuthError:
        fleets = None

    coverage = compute_coverage(collection.records, network_phase=network_phase)
    signals = detect_wash_signals(collection.records, fleets=fleets)
    recommendations = recommend(
        coverage,
        records=collection.records,
        safety=safety,
        wash_signals=signals,
        registry=registry,
        network_phase=network_phase,
    )

    sections = [
        _identity_section(bundle, lineage=lineage, did=did, at=at, collection=collection),
        _useful_section(collection),
        _category_section(
            "technocore",
            collection,
            frozenset({ActivityCategory.ROOM_PARTICIPATION, ActivityCategory.MESSAGE_VOLUME}),
        ),
        _category_section("tclk", collection, frozenset({ActivityCategory.TCLK_DEAL})),
    ]
    for section_id, reason in _FUTURE_SECTIONS:
        sections.append(PassportSection(section_id=section_id, status=_NOT_YET, reason=reason))
    sections.append(
        PassportSection(
            section_id="mainnetUnlock",
            status=_NOT_YET,
            reason=_mainnet_unlock_reason(registry, snapshot),
        )
    )

    warnings = list(collection.warnings)
    if snapshot is not None and registry is not None:
        stale = registry.stale_rules(snapshot)
        warnings.extend(entry.detail for entry in stale)

    unknown_sources = {
        record.source_class
        for record in collection.records
        if record.source_class in (SourceClass.UNKNOWN, SourceClass.SUSPICIOUS)
    }
    if unknown_sources:
        warnings.append(
            "some records came from origins the source classifier does not recognise; "
            "they are shown without an official badge"
        )

    return FlopActivityPassport(
        subject_did=did,
        lineage=lineage,
        generated_at=at,
        network_phase=network_phase,
        sections=tuple(sections),
        coverage=coverage.categories,
        activities=collection.records,
        safety=tuple(safety),
        wash_signals=signals,
        recommendations=recommendations,
        sources=snapshot.snapshots if snapshot is not None else (),
        warnings=tuple(warnings),
        contains_synthetic=collection.contains_synthetic,
    )


__all__ = ["build_flop_passport"]
