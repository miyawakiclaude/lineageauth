"""The FLOP passport: a projection, with every section saying why it is empty.

The distinction the whole type exists for is `not-observed` against
`not-yet-available`. One means you have not done it; the other means there is
nothing to do yet, and a dashboard that cannot tell them apart will show a zero
for a network that has not launched.

Everything else here is about what the passport must not become: a total, a
rating, a place where a private key could appear, or a document that quietly
serves a rule whose source has moved.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta

from lineageauth.builders import (
    build_artifact_receipt,
    build_artifact_register,
    build_attestation,
    build_root_create,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.flop.activity import LocalEventsAdapter, MockAdapter
from lineageauth.flop.model import (
    COVERAGE_LABEL,
    NOT_AFFILIATED_NOTICE,
    SEED_WARNING_NOTICE,
    SYNTHETIC_BANNER,
    CoverageState,
    FeatureStatus,
    NetworkPhase,
    SafetyFinding,
    SafetyLevel,
    SourceClass,
    forbidden_vocabulary_in,
)
from lineageauth.flop.passport import build_flop_passport
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.sources import load_snapshot
from tests.testkeys import AGENT_1, OUTSIDER, ROOT_A, unsafe_signer

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
REVIEWER = unsafe_signer(OUTSIDER)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]


def artifact_id(marker: str) -> str:
    return "sha256:" + hashlib.sha256(marker.encode("utf-8")).hexdigest()


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def evidenced(marker: str) -> list[Envelope]:
    return [
        sign_payload(
            build_artifact_register(
                lineage=LINEAGE,
                artifact_id=artifact_id(marker),
                uri=f"https://github.com/flop-labs/tclk/pull/{marker}",
                created_by=AGENT.did,
                issued_at=AT - timedelta(days=2),
            ),
            [AGENT],
        ),
        sign_payload(
            build_artifact_receipt(
                lineage=LINEAGE,
                artifact_id=artifact_id(marker),
                worker=AGENT.did,
                issued_at=AT - timedelta(days=2),
            ),
            [AGENT],
        ),
        sign_payload(
            build_attestation(
                lineage=LINEAGE,
                issuer=REVIEWER.did,
                subject_ref=artifact_id(marker),
                predicate="artifact.reproduced",
                issued_at=AT - timedelta(days=1),
            ),
            [REVIEWER],
        ),
    ]


def bundle(*envelopes: Envelope) -> EventBundle:
    return EventBundle.from_envelopes([genesis(), *envelopes])


def build(*envelopes: Envelope, **kwargs: object):  # type: ignore[no-untyped-def]
    events = bundle(*envelopes)
    return build_flop_passport(
        events,
        lineage=LINEAGE,
        did=AGENT.did,
        at=AT,
        adapters=[LocalEventsAdapter(events)],
        **kwargs,  # type: ignore[arg-type]
    )


class TestSectionsSayWhyTheyAreEmpty:
    def test_future_network_sections_are_not_yet_available(self) -> None:
        sections = {section.section_id: section for section in build().sections}
        for name in ("inference", "broker", "creator", "validator", "miner", "mainnetUnlock"):
            assert sections[name].status is FeatureStatus.NOT_YET_AVAILABLE, name
            assert sections[name].reason, name

    def test_the_inference_section_explains_rather_than_showing_a_zero(self) -> None:
        sections = {section.section_id: section for section in build().sections}
        reason = sections["inference"].reason
        assert "official compatible endpoint" in reason
        assert "nothing to report as zero" in reason

    def test_useful_participation_is_not_observed_rather_than_unavailable(self) -> None:
        """Nothing done is a different sentence from nothing to do."""
        sections = {section.section_id: section for section in build().sections}
        assert sections["usefulParticipation"].status is FeatureStatus.NOT_OBSERVED

    def test_useful_participation_becomes_available_once_work_exists(self) -> None:
        sections = {section.section_id: section for section in build(*evidenced("290")).sections}
        assert sections["usefulParticipation"].status is FeatureStatus.AVAILABLE
        assert sections["usefulParticipation"].detail["count"] == 1

    def test_identity_reports_continuity_without_valuing_it(self) -> None:
        identity = next(s for s in build(*evidenced("290")).sections if s.section_id == "identity")
        assert identity.status is FeatureStatus.AVAILABLE
        assert identity.detail["signedActivityDays"] >= 1
        assert "carries no allocation meaning" in identity.detail["ageIsNotValue"]


class TestCoverageAndEvidence:
    def test_an_attested_artifact_lights_external_verification(self) -> None:
        passport = build(*evidenced("290"))
        states = {category.category_id: category.state for category in passport.coverage}
        assert states["external-verification"] is CoverageState.SOME_EVIDENCE
        assert states["useful-work"] is CoverageState.SOME_EVIDENCE
        assert states["inference"] is CoverageState.NOT_YET_AVAILABLE

    def test_the_covered_count_never_includes_unavailable_categories(self) -> None:
        passport = build(*evidenced("290"))
        assert passport.covered_categories == 2
        assert len(passport.coverage) == 10

    def test_useful_work_count_is_reported_without_a_total_score(self) -> None:
        rendered = build(*evidenced("290")).to_dict()
        assert rendered["summary"]["usefulWork"] == 1
        assert rendered["evidenceCoverage"]["isAirdropScore"] is False
        assert rendered["evidenceCoverage"]["label"] == COVERAGE_LABEL


class TestTheRenderedPassport:
    def test_it_carries_the_required_notices(self) -> None:
        notices = build().to_dict()["notices"]
        assert notices["affiliation"] == NOT_AFFILIATED_NOTICE
        assert notices["seedPhrase"] == SEED_WARNING_NOTICE

    def test_it_contains_no_forbidden_vocabulary(self) -> None:
        rendered = json.dumps(build(*evidenced("290")).to_dict())
        assert forbidden_vocabulary_in(rendered) == ()

    def test_it_says_it_holds_no_keys_and_takes_no_custody(self) -> None:
        rendered = build().to_dict()
        assert rendered["holdsPrivateKeys"] is False
        assert rendered["walletCustody"] is False

    def test_no_key_material_can_appear_in_it(self) -> None:
        """Only DIDs, hashes and URLs go in. A seed would have nowhere to sit."""
        rendered = json.dumps(build(*evidenced("290")).to_dict())
        assert AGENT.did in rendered
        # The warning notice is the one place the words appear, and it is there
        # to tell a reader never to type one.
        body = rendered.replace(SEED_WARNING_NOTICE, " ")
        for banned in ("seed phrase", "privateKey", "secretKey", "mnemonic", "-----BEGIN"):
            assert banned not in body
        # An Ed25519 seed is 64 hex characters, which is also the shape of an
        # event id -- so the check is for a bare run, the way
        # `scripts/pre_push_check.py` looks for one.
        assert re.search(r"(?<!sha256:)(?<![0-9a-fA-F])[0-9a-f]{64}(?![0-9a-fA-F])", body) is None

    def test_safety_findings_travel_with_it_and_stay_unexecuted(self) -> None:
        finding = SafetyFinding(
            finding_id="f-1",
            level=SafetyLevel.BLOCKED,
            pattern_id="secret.seed-phrase",
            reason="asked for a seed phrase",
            source_class=SourceClass.UNKNOWN,
        )
        rendered = build(safety=[finding]).to_dict()
        assert rendered["safety"][0]["executed"] is False
        assert rendered["summary"]["safetyFindings"] == 1

    def test_it_is_deterministic_for_the_same_bundle_and_instant(self) -> None:
        first = json.dumps(build(*evidenced("290")).to_dict(), sort_keys=True)
        second = json.dumps(build(*evidenced("290")).to_dict(), sort_keys=True)
        assert first == second


class TestSyntheticData:
    def test_a_mock_adapter_makes_the_whole_passport_say_so(self) -> None:
        events = bundle()
        passport = build_flop_passport(
            events,
            lineage=LINEAGE,
            did=AGENT.did,
            at=AT,
            adapters=[LocalEventsAdapter(events), MockAdapter()],
        )
        assert passport.contains_synthetic is True
        assert passport.to_dict()["banner"] == SYNTHETIC_BANNER

    def test_without_a_mock_adapter_there_is_no_banner(self) -> None:
        assert "banner" not in build().to_dict()


class TestStaleRulesSurfaceAsWarnings:
    def test_a_moved_source_warns_on_the_passport(self) -> None:
        from dataclasses import replace

        snapshot = load_snapshot()
        moved = replace(
            snapshot,
            snapshots=tuple(
                replace(entry, sha256="sha256:" + "ef" * 32)
                if entry.source_id == "flop-finance-teaser"
                else entry
                for entry in snapshot.snapshots
            ),
        )
        passport = build(registry=FlopRuleRegistry.load(), snapshot=moved)
        assert any("RULE UPDATED" in warning for warning in passport.warnings)

    def test_the_current_snapshot_produces_no_stale_warning(self) -> None:
        passport = build(registry=FlopRuleRegistry.load(), snapshot=load_snapshot())
        assert not any("RULE UPDATED" in warning for warning in passport.warnings)

    def test_the_snapshot_travels_with_the_passport(self) -> None:
        rendered = build(snapshot=load_snapshot()).to_dict()
        assert len(rendered["sources"]) >= 8
        assert all(entry["bodyStored"] is False for entry in rendered["sources"])


class TestPhase:
    def test_the_badge_reads_pre_testnet_by_default(self) -> None:
        rendered = build().to_dict()
        assert rendered["networkPhase"] == "PRE_TESTNET"
        assert rendered["networkPhaseBadge"] == "PRE-TESTNET"

    def test_an_enabled_testnet_changes_the_sections_without_a_code_change(self) -> None:
        passport = build(network_phase=NetworkPhase.TESTNET_ENABLED)
        states = {category.category_id: category.state for category in passport.coverage}
        assert states["inference"] is CoverageState.NOT_OBSERVED
