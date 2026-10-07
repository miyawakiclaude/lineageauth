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

import pytest

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
from lineageauth.flop.rules import RULE_REGISTRY_FILE, FlopRuleRegistry
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

    def test_the_mainnet_unlock_section_matches_the_registry(self) -> None:
        """D-123: the shipped registry carries the airdrop page's 3:1 rule, and the
        passport says what the registry says, figure included."""
        from lineageauth.flop.rules import FlopRuleRegistry, unlock_ratio

        registry = FlopRuleRegistry.load()
        assert unlock_ratio(registry) == 3
        sections = {s.section_id: s for s in build(registry=registry).sections}
        reason = sections["mainnetUnlock"].reason
        # Only spend of the locked balance counts (airdrop page, Yellow Paper R8.7).
        assert "for every 3 $FLOP of the locked balance spent in settled sessions" in reason
        assert "flop-agent-unlock-ratio" in reason
        assert "nothing liquid at genesis (flop-agent-grant-no-end-block)" in reason

    def test_the_mainnet_unlock_figure_is_read_not_written(self, tmp_path) -> None:
        """5 and 2 come only from the data; a constant in the code could not produce them.
        The one-rule registry has no genesis rule, so nothing is said about genesis."""
        from tests.flop_testnet_fixtures import registry_with_formula

        registry = registry_with_formula(tmp_path, spent=5, unlocked=2)
        reason = {s.section_id: s for s in build(registry=registry).sections}[
            "mainnetUnlock"
        ].reason
        assert "unlocks 2 $FLOP" in reason
        assert "for every 5 $FLOP of the locked balance spent" in reason
        assert "genesis" not in reason

    def test_without_a_formula_the_passport_says_what_the_registry_records(self, tmp_path) -> None:
        """No formula is the registry's record, not proof that no official page states a
        ratio, so the passport does not speak for the official text."""
        from tests.flop_testnet_fixtures import registry_without_formula

        sections = {
            s.section_id: s for s in build(registry=registry_without_formula(tmp_path)).sections
        }
        reason = sections["mainnetUnlock"].reason
        assert "carries no unlock formula" in reason
        assert "official text" not in reason
        assert "for every" not in reason

    def test_a_registry_without_the_rule_is_not_the_official_texts_silence(self) -> None:
        reason = {s.section_id: s for s in build(registry=FlopRuleRegistry(rules=())).sections}[
            "mainnetUnlock"
        ].reason
        assert "not in the rule registry" in reason
        assert "UNKNOWN_FROM_OFFICIAL_SPEC" in reason
        assert "official text" not in reason
        assert "for every" not in reason

    def test_an_unappliable_formula_is_reported_as_the_registrys_mistake(self) -> None:
        """A registry built in code bypasses the loader's check; same words as the
        mainnet adapter, which reads the same judgement."""
        from dataclasses import replace

        from lineageauth.flop.rules import UNLOCK_RULE_ID

        shipped = FlopRuleRegistry.load().get(UNLOCK_RULE_ID)
        assert shipped is not None
        broken = replace(shipped, formula={"kind": "unlock-ratio", "spentPerUnlocked": 0})
        reason = {
            s.section_id: s for s in build(registry=FlopRuleRegistry(rules=(broken,))).sections
        }["mainnetUnlock"].reason
        assert "cannot be applied" in reason
        assert "official text" not in reason
        assert "for every" not in reason

    @pytest.mark.parametrize("per", ["null", "absent", 0, "two", True])
    def test_the_unlocked_figure_is_the_one_the_computation_uses(self, tmp_path, per) -> None:
        """Whatever unlockedPerRatio holds, the passport shows the figure that
        unlocked_from_spend applies: never 'None', '0' or 'two' beside a computation
        that used 1. null loads (the field is optional); the rest are built in code."""
        from dataclasses import replace

        from lineageauth.flop.rules import UNLOCK_RULE_ID, unlocked_from_spend
        from tests.flop_testnet_fixtures import registry_with_formula

        if per == "null":
            shipped = json.loads(RULE_REGISTRY_FILE.read_text(encoding="utf-8"))
            rule = next(r for r in shipped["rules"] if r["id"] == UNLOCK_RULE_ID)
            formula = {"kind": "unlock-ratio", "spentPerUnlocked": 4, "unlockedPerRatio": None}
            path = tmp_path / "registry-null.json"
            path.write_text(
                json.dumps({"_meta": {}, "rules": [dict(rule, formula=formula)]}),
                encoding="utf-8",
            )
            registry = FlopRuleRegistry.load(path)
        elif per == "absent":
            registry = registry_with_formula(tmp_path, spent=4)
        else:
            base = registry_with_formula(tmp_path, spent=4).get(UNLOCK_RULE_ID)
            assert base is not None
            built = replace(
                base,
                formula={"kind": "unlock-ratio", "spentPerUnlocked": 4, "unlockedPerRatio": per},
            )
            registry = FlopRuleRegistry(rules=(built,))
        assert unlocked_from_spend(registry, 8) == 2
        reason = {s.section_id: s for s in build(registry=registry).sections}[
            "mainnetUnlock"
        ].reason
        assert "unlocks 1 $FLOP" in reason
        assert "for every 4 $FLOP" in reason
        for wrong in ("None", "unlocks 0", "two", "True"):
            assert wrong not in reason

    def test_without_a_registry_no_rule_is_claimed(self) -> None:
        sections = {s.section_id: s for s in build().sections}
        assert "No rule registry was supplied" in sections["mainnetUnlock"].reason

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

    def test_a_stale_unlock_rule_shows_no_figure(self) -> None:
        """The section text carries figures since D-123, so it must honour freshness
        itself: a moved airdrop page (say, now 4:1) must not leave 'for every 3' on
        the passport as though it were current. It names the rule and says why."""
        from dataclasses import replace

        snapshot = load_snapshot()
        moved = replace(
            snapshot,
            snapshots=tuple(
                replace(entry, sha256="sha256:" + "ef" * 32)
                if entry.source_id == "flop-finance-airdrop"
                else entry
                for entry in snapshot.snapshots
            ),
        )
        passport = build(registry=FlopRuleRegistry.load(), snapshot=moved)
        reason = {s.section_id: s for s in passport.sections}["mainnetUnlock"].reason
        assert "RULE UPDATED" in reason
        assert "flop-agent-unlock-ratio" in reason
        assert "for every" not in reason

    def test_a_current_unlock_rule_shows_its_figure_with_a_snapshot(self) -> None:
        passport = build(registry=FlopRuleRegistry.load(), snapshot=load_snapshot())
        reason = {s.section_id: s for s in passport.sections}["mainnetUnlock"].reason
        assert "for every 3 $FLOP of the locked balance" in reason
        assert "RULE UPDATED" not in reason
        assert "nothing liquid at genesis" in reason

    def test_a_stale_genesis_rule_drops_the_genesis_clause(self) -> None:
        """'Nothing liquid at genesis' comes from the Yellow Paper's rule; if that page
        moved, the clause goes, while the airdrop page's figure stays."""
        from dataclasses import replace

        snapshot = load_snapshot()
        moved = replace(
            snapshot,
            snapshots=tuple(
                replace(entry, sha256="sha256:" + "ef" * 32)
                if entry.source_id == "flop-finance-yellowpaper"
                else entry
                for entry in snapshot.snapshots
            ),
        )
        passport = build(registry=FlopRuleRegistry.load(), snapshot=moved)
        reason = {s.section_id: s for s in passport.sections}["mainnetUnlock"].reason
        assert "for every 3 $FLOP of the locked balance" in reason
        assert "genesis" not in reason

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
