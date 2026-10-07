"""The rule registry: what FLOP has published, quoted, dated, and hashed.

Two properties carry the module. Nothing about FLOP economics may be written in
Python -- the 3-to-1 unlock ratio has to come out of the registry or not at all
-- and a rule has to know when its source moved underneath it. Both are tested
against the registry that actually ships, not against a fixture, because a
fixture would pass while the real file drifted.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import replace

import pytest

from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import UNKNOWN_FROM_OFFICIAL_SPEC, RuleStatus
from lineageauth.flop.rules import (
    RULE_REGISTRY_FILE,
    UNLOCK_RULE_ID,
    FlopRuleRegistry,
    Freshness,
    rules_for_phase,
    unlock_ratio,
    unlocked_from_spend,
)
from lineageauth.flop.sources import RULE_UPDATED_LABEL, load_snapshot
from tests.flop_testnet_fixtures import registry_with_formula


@pytest.fixture
def registry() -> FlopRuleRegistry:
    return FlopRuleRegistry.load()


class TestEveryRuleCarriesItsSource:
    def test_each_rule_names_a_url_a_version_a_date_and_a_fetch(
        self, registry: FlopRuleRegistry
    ) -> None:
        for rule in registry.rules:
            assert rule.source.source_url.startswith("https://")
            assert rule.source.source_version
            assert rule.source.source_date
            assert rule.source.fetched_at

    def test_nothing_claims_to_be_final_while_the_yellow_paper_is_a_draft(
        self, registry: FlopRuleRegistry
    ) -> None:
        """The Yellow Paper calls itself a draft and an implementation spec, iterating."""
        assert registry.with_status(RuleStatus.OFFICIAL_FINAL) == ()

    def test_a_derived_statement_may_not_claim_to_be_a_quotation(
        self, registry: FlopRuleRegistry
    ) -> None:
        for rule in registry.rules:
            if rule.derivation == "derived":
                assert rule.statement_is_quotation is False
                assert rule.derivation_note

    def test_the_technocore_coordination_claim_is_registered_as_derived(
        self, registry: FlopRuleRegistry
    ) -> None:
        """It appears in the directive and verbatim in no official FLOP document.

        The whitepaper says something close (Technocore settles nothing), and the
        derivation note names it; registering the directive's sentence as a quotation
        would still attribute a sentence to a source that does not contain it.
        """
        rule = registry.get("technocore-not-a-settlement-system")
        assert rule is not None
        assert rule.derivation == "derived"
        assert rule.statement_is_quotation is False
        assert rule.source.hash is None
        assert rule.derivation_note is not None and "whitepaper" in rule.derivation_note

    def test_teaser_rules_carry_the_version_panels_date(self, registry: FlopRuleRegistry) -> None:
        """D-123: the teaser's footer moved to 2026-10-05 with the navigation; its version
        panel, the date earlier snapshots used, still says 2026-09-30."""
        teaser = [r for r in registry.rules if r.source.source_id == "flop-finance-teaser"]
        assert teaser
        assert {r.source.source_date for r in teaser} == {"2026-09-30"}

    def test_all_four_testnet_fairness_rules_are_registered(
        self, registry: FlopRuleRegistry
    ) -> None:
        """The testnet page lists four; the minimum-activity floor is under 'what counts'."""
        for rule_id in (
            "flop-one-participant-one-score",
            "flop-independent-demand-only",
            "flop-fraud-forfeits",
            "flop-security-disclosure",
        ):
            rule = registry.get(rule_id)
            assert rule is not None, rule_id
            assert rule.source.source_id == "flop-finance-testnet"
            assert rule.statement_is_quotation is True


class TestUnknownIsRecordedRatherThanFilledIn:
    def test_the_six_unanswered_questions_are_present(self, registry: FlopRuleRegistry) -> None:
        """Six since D-123: the Yellow Paper's R8.8 specifies the claim (claim_vested), so
        flop-airdrop-claim-path is a quotation now, not an unknown."""
        ids = {rule.rule_id for rule in registry.unknown_rules}
        assert ids == {
            "flop-testnet-endpoint",
            "flop-faucet-procedure",
            "flop-inference-api",
            "flop-inference-pricing",
            "flop-network-identifier",
            "flop-auth-signing-scheme",
        }
        claim = registry.get("flop-airdrop-claim-path")
        assert claim is not None and claim.status is RuleStatus.OFFICIAL_DRAFT
        assert "claim_vested" in claim.statement

    def test_the_yellow_paper_is_now_a_draft_source_not_an_unknown(
        self, registry: FlopRuleRegistry
    ) -> None:
        """Second snapshot: the definitive spec was published, as a draft (D-112)."""
        assert registry.get("flop-yellow-paper") is None
        status = registry.get("flop-yellow-paper-status")
        assert status is not None and status.status is RuleStatus.OFFICIAL_DRAFT
        genesis = registry.get("flop-genesis-supply-parameter")
        # The parameter of record moved between snapshots; the statement carries the
        # current figure and the teaser rule's consequence keeps the previous one.
        assert genesis is not None and "4,400,000,000" in genesis.statement
        teaser_pool = registry.get("flop-genesis-airdrop-pool")
        assert teaser_pool is not None and teaser_pool.consequence
        assert "2,483,460,000" in teaser_pool.consequence

    def test_an_unknown_rule_says_so_in_the_statement(self, registry: FlopRuleRegistry) -> None:
        for rule in registry.unknown_rules:
            assert rule.statement == UNKNOWN_FROM_OFFICIAL_SPEC
            assert rule.consequence

    def test_a_paraphrase_dressed_as_an_unknown_rule_is_refused(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """An unknown rule that reads like an answer is worse than no rule."""
        path = tmp_path / "registry.json"
        path.write_text(
            """{"rules":[{"id":"x","statement":"probably about a week",
            "status":"unknown","effectiveNetworkPhase":"testnet",
            "source":{"sourceId":"s","sourceUrl":"https://flop.finance/","sourceVersion":"0.1",
            "sourceDate":"2026-08-26","fetchedAt":"2026-09-03T04:25:46Z","hash":null}}]}""",
            encoding="utf-8",
        )
        with pytest.raises(MalformedEventError, match=UNKNOWN_FROM_OFFICIAL_SPEC):
            FlopRuleRegistry.load(path)


class TestTheUnlockRatioIsData:
    def test_the_ratio_returns_from_the_airdrop_page_as_data(
        self, registry: FlopRuleRegistry
    ) -> None:
        """D-122 removed the formula when the teaser dropped 3:1; D-123 restores it from
        the airdrop page, which the Yellow Paper's normative Agent grant rule backs. The
        teaser's lagging sentence is kept as its own rule so the conflict stays visible."""
        rule = registry.get(UNLOCK_RULE_ID)
        assert rule is not None and rule.formula is not None
        assert rule.source.source_url == "https://flop.finance/airdrop/"
        assert "Every 3 $FLOP of the locked balance" in rule.statement
        assert unlock_ratio(registry) == 3
        assert unlocked_from_spend(registry, 9) == 3
        lagging = registry.get("flop-teaser-agent-release-unset")
        assert lagging is not None and "not yet set" in lagging.statement
        normative = registry.get("flop-agent-unlock-yellowpaper")
        assert normative is not None and "each three FLOP" in normative.statement

    def test_the_number_three_is_not_written_in_the_module(self) -> None:
        """Read the source: the ratio must not be a literal in Python."""
        from lineageauth.flop import rules as rules_module

        source = rules_module.__file__
        assert source is not None
        text = pathlib.Path(source).read_text(encoding="utf-8")
        assert "spentPerUnlocked" in text
        assert "// 3" not in text
        assert "spend // 3" not in text

    def test_a_registered_formula_still_applies_to_an_observed_spend(
        self, tmp_path: pathlib.Path
    ) -> None:
        """The mechanism survives the change: a formula in the data is applied, and no
        number in the code is. 5 and 2 are neither the dropped 3 nor the default 1, so
        both fields have to be read for this to pass."""
        synthetic = registry_with_formula(tmp_path, spent=5, unlocked=2)
        assert unlock_ratio(synthetic) == 5
        assert unlocked_from_spend(synthetic, 10) == 4
        assert unlocked_from_spend(synthetic, 9) == 2
        assert unlocked_from_spend(synthetic, 4) == 0
        assert unlocked_from_spend(synthetic, -5) is None

    @pytest.mark.parametrize(
        "formula",
        [
            {"kind": "unlock-ratio", "spentPerUnlocked": 0},
            {"kind": "unlock-ratio", "spentPerUnlocked": -3},
            {"kind": "unlock-ratio", "spentPerUnlocked": True},
            {"kind": "unlock-ratio", "spentPerUnlocked": "5"},
            {"kind": "unlock-ratio", "spentPerUnlocked": 5, "unlockedPerRatio": 0},
            {"kind": "something-else", "spentPerUnlocked": 5},
            [5, 2],
            "5:2",
        ],
    )
    def test_a_malformed_formula_is_refused_rather_than_read_as_no_ratio(
        self, tmp_path: pathlib.Path, formula: object
    ) -> None:
        """A typo in the registry must not reach a screen as 'the official text sets
        no ratio'."""
        shipped = json.loads(RULE_REGISTRY_FILE.read_text(encoding="utf-8"))
        rule = next(r for r in shipped["rules"] if r["id"] == UNLOCK_RULE_ID)
        path = tmp_path / "registry.json"
        path.write_text(
            json.dumps({"_meta": {}, "rules": [dict(rule, formula=formula)]}), encoding="utf-8"
        )
        with pytest.raises(MalformedEventError, match="formula"):
            FlopRuleRegistry.load(path)

    def test_a_registry_without_the_rule_returns_none_rather_than_a_guess(self) -> None:
        empty = FlopRuleRegistry(rules=())
        assert unlock_ratio(empty) is None
        assert unlocked_from_spend(empty, 100) is None

    def test_the_rule_is_marked_draft_and_provisional(self, registry: FlopRuleRegistry) -> None:
        rule = registry.get(UNLOCK_RULE_ID)
        assert rule is not None
        assert rule.status is RuleStatus.OFFICIAL_DRAFT


class TestFreshness:
    def test_every_hashed_rule_matches_the_shipped_snapshot(
        self, registry: FlopRuleRegistry
    ) -> None:
        snapshot = load_snapshot()
        for entry in registry.freshness(snapshot):
            assert entry.freshness in (Freshness.CURRENT, Freshness.UNVERIFIABLE), entry.detail

    def test_acceptance_6_a_changed_official_source_marks_its_rules_stale(
        self, registry: FlopRuleRegistry
    ) -> None:
        """Acceptance test 6: the source moves, the rule is not silently current.

        The snapshot is edited to a different body hash, as it would be after a
        refetch of a document FLOP had updated. Every rule taken from it is
        reported `RULE UPDATED`, and `may_be_treated_as_current` goes false --
        the flag anything downstream has to consult before using the rule.
        """
        snapshot = load_snapshot()
        moved = replace(
            snapshot,
            snapshots=tuple(
                replace(entry, sha256="sha256:" + "cd" * 32)
                if entry.source_id == "flop-finance-teaser"
                else entry
                for entry in snapshot.snapshots
            ),
        )
        stale = registry.stale_rules(moved)
        assert stale, "a changed teaser must invalidate the rules quoted from it"
        stale_ids = {entry.rule_id for entry in stale}
        teaser_rules = {
            r.rule_id for r in registry.rules if r.source.source_id == "flop-finance-teaser"
        }
        assert teaser_rules and teaser_rules <= stale_ids
        assert "flop-teaser-agent-release-unset" in stale_ids
        for entry in stale:
            assert entry.label == RULE_UPDATED_LABEL
            assert entry.may_be_treated_as_current is False
            assert "re-read it" in entry.detail

    def test_a_rule_without_a_body_hash_is_unverifiable_not_current(
        self, registry: FlopRuleRegistry
    ) -> None:
        snapshot = load_snapshot()
        by_rule = {entry.rule_id: entry for entry in registry.freshness(snapshot)}
        derived = by_rule["technocore-not-a-settlement-system"]
        assert derived.freshness is Freshness.UNVERIFIABLE
        assert derived.may_be_treated_as_current is False

    def test_a_missing_source_is_reported_rather_than_ignored(
        self, registry: FlopRuleRegistry
    ) -> None:
        snapshot = load_snapshot()
        emptied = replace(snapshot, snapshots=())
        kinds = {entry.freshness for entry in registry.freshness(emptied)}
        assert kinds == {Freshness.SOURCE_MISSING}


class TestRendering:
    def test_the_rendered_registry_says_it_is_not_an_eligibility_rule_set(
        self, registry: FlopRuleRegistry
    ) -> None:
        rendered = registry.to_dict(load_snapshot())
        assert "eligibility rule" in rendered["note"]
        assert rendered["unknownCount"] == 6

    def test_rules_can_be_selected_by_phase(self, registry: FlopRuleRegistry) -> None:
        testnet = {rule.rule_id for rule in rules_for_phase(registry, ["testnet"])}
        assert "flop-testnet-schedule" in testnet
        # "any" rules always come along: a document that says its own figures
        # are provisional applies to every phase.
        assert "flop-figures-provisional" in testnet

    def test_a_duplicate_rule_id_is_refused(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        path = tmp_path / "registry.json"
        entry = """{"id":"x","statement":"s","status":"official-draft",
        "effectiveNetworkPhase":"any","statementIsQuotation":true,
        "source":{"sourceId":"s","sourceUrl":"https://flop.finance/","sourceVersion":"0.1",
        "sourceDate":"2026-08-26","fetchedAt":"2026-09-03T04:25:46Z","hash":null}}"""
        path.write_text(f'{{"rules":[{entry},{entry}]}}', encoding="utf-8")
        with pytest.raises(MalformedEventError, match="registered twice"):
            FlopRuleRegistry.load(path)
