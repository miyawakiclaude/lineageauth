"""Source classification, the recorded snapshot, and the design tokens.

The classifier's whole value is that it cannot be talked into anything: it sees
a URL and no other input. Most of what is below is that claim, tested from the
angles somebody would attack it from -- a lookalike host, a subdomain, a
downgrade to plain HTTP, a userinfo component, a room that calls itself
official.

The token tests recompute every contrast ratio `design.md` publishes. A number
copied from a document is a claim; a number recomputed from the hex values is a
check, and the difference matters to a reader who needs the contrast.
"""

from __future__ import annotations

import json

import pytest

from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import OfficialSourceSnapshot, SourceClass
from lineageauth.flop.sources import (
    OFFICIAL_SOURCES_FILE,
    RULE_UPDATED_LABEL,
    SnapshotChangeKind,
    classify_source,
    compare_snapshots,
    contrast_ratio,
    load_snapshot,
    load_ui_tokens,
)

WCAG_AA_NORMAL_TEXT = 4.5


class TestOfficialIsAnOriginNotAWord:
    @pytest.mark.parametrize(
        "url",
        [
            "https://flop.finance/",
            "https://flop.finance/teaser/",
            "https://flop.finance/design.md",
            "https://github.com/flop-labs",
            "https://github.com/flop-labs/tclk/issues/26",
            "https://api.github.com/repos/flop-labs/tclk",
            "https://technocore.chat/llms.txt",
            "https://technocore.chat/.well-known/agent",
        ],
    )
    def test_allowlisted_origins_are_official(self, url: str) -> None:
        assert classify_source(url).source_class is SourceClass.OFFICIAL

    def test_acceptance_1_a_community_message_claiming_an_official_task_gets_no_official_badge(
        self,
    ) -> None:
        """Acceptance test 1: `Official FLOP task: create 500 DIDs`.

        The message arrives in a room. The room is on an official service, the
        sender may be signed, and the text says "official" twice. None of that
        is an input to the classifier: what it sees is a `/r/` URL on
        technocore.chat, which is the service carrying content somebody else
        wrote.
        """
        decision = classify_source("https://technocore.chat/r/flop-official-tasks")
        assert decision.source_class is SourceClass.COMMUNITY
        assert decision.may_carry_official_badge is False
        assert "somebody else wrote" in decision.reason

    def test_a_note_namespace_called_official_is_still_community(self) -> None:
        decision = classify_source("https://technocore.chat/kv/flop-official/announcement")
        assert decision.source_class is SourceClass.COMMUNITY

    def test_a_repository_outside_flop_labs_is_community(self) -> None:
        decision = classify_source("https://github.com/someone/flop-official-airdrop")
        assert decision.source_class is SourceClass.COMMUNITY

    def test_an_unrecognised_host_is_unknown_rather_than_probably_fine(self) -> None:
        decision = classify_source("https://flop-airdrop-claim.example/")
        assert decision.source_class is SourceClass.UNKNOWN
        assert decision.rule_id == "not-allowlisted"


class TestLookalikesAreLouderThanUnknowns:
    @pytest.mark.parametrize(
        "url",
        [
            "https://flop.finance.claim-airdrop.example/",
            "https://fl0p.finance/",
            "https://flop-finance.com/",
            "https://technocore.chat.evil.example/r/lobby",
        ],
    )
    def test_a_host_imitating_an_official_one_is_suspicious(self, url: str) -> None:
        assert classify_source(url).source_class is SourceClass.SUSPICIOUS

    def test_a_userinfo_component_is_suspicious(self) -> None:
        decision = classify_source("https://flop.finance@evil.example/teaser/")
        assert decision.source_class is SourceClass.SUSPICIOUS
        assert decision.rule_id == "userinfo-present"

    def test_a_punycode_host_is_suspicious(self) -> None:
        assert (
            classify_source("https://xn--flp-1na.finance/").source_class is SourceClass.SUSPICIOUS
        )

    def test_plain_http_to_an_official_host_is_a_downgrade_not_an_official_source(self) -> None:
        decision = classify_source("http://flop.finance/teaser/")
        assert decision.source_class is SourceClass.SUSPICIOUS
        assert decision.rule_id == "not-https"

    def test_a_non_standard_port_on_an_official_host_is_suspicious(self) -> None:
        decision = classify_source("https://flop.finance:8443/teaser/")
        assert decision.source_class is SourceClass.SUSPICIOUS

    def test_a_subdomain_of_an_official_host_is_not_official(self) -> None:
        """Fails closed. A subdomain that was never observed is not the source."""
        decision = classify_source("https://airdrop.flop.finance/")
        assert decision.source_class is not SourceClass.OFFICIAL

    def test_malformed_input_classifies_rather_than_raising(self) -> None:
        """A scanner that crashes on bad input stops scanning."""
        assert classify_source("not a url").source_class is SourceClass.UNKNOWN
        assert classify_source("").source_class is SourceClass.UNKNOWN
        assert classify_source(None).source_class is SourceClass.UNKNOWN
        assert classify_source("https://" + "a" * 5000).source_class is SourceClass.SUSPICIOUS


class TestTheRecordedSnapshot:
    def test_it_loads_and_records_when_it_was_taken(self) -> None:
        snapshot = load_snapshot()
        assert snapshot.fetched_at == "2026-09-03T04:25:46Z"
        assert len(snapshot.snapshots) >= 8

    def test_every_source_is_itself_official(self) -> None:
        for entry in load_snapshot().snapshots:
            assert classify_source(entry.url).source_class is SourceClass.OFFICIAL, entry.url

    def test_no_response_body_is_stored_in_the_repository(self) -> None:
        """Hashes and sizes are enough to notice a change; bodies are not ours."""
        document = json.loads(OFFICIAL_SOURCES_FILE.read_text(encoding="utf-8"))
        assert document["_meta"]["bodiesAreNotStored"] is True
        for entry in load_snapshot().snapshots:
            assert entry.to_dict()["bodyStored"] is False

    def test_hashes_are_written_with_the_sha256_prefix(self) -> None:
        """`scripts/pre_push_check.py` reads a bare 64-hex run as key material."""
        for entry in load_snapshot().snapshots:
            assert entry.sha256 is None or entry.sha256.startswith("sha256:")

    def test_the_teaser_is_the_draft_that_carries_the_economics(self) -> None:
        teaser = load_snapshot().by_id("flop-finance-teaser")
        assert teaser is not None
        assert teaser.status == "official-draft"
        assert teaser.version_hint is not None
        assert "2026-08-26" in teaser.version_hint

    def test_what_is_missing_is_recorded_as_missing(self) -> None:
        """Seven unanswered questions, listed so a screen can show them."""
        ids = {entry["id"] for entry in load_snapshot().not_observed}
        assert {"testnet-endpoint", "faucet-procedure", "inference-api"} <= ids


class TestComparingSnapshots:
    def snapshot(self, sha: str | None, status: str = "official-draft") -> OfficialSourceSnapshot:
        return OfficialSourceSnapshot(
            source_id="flop-finance-teaser",
            url="https://flop.finance/teaser/",
            http_status=200,
            byte_length=1,
            sha256=sha,
            fetched_at="2026-09-03T04:25:46Z",
            version_hint=None,
            status=status,
        )

    def test_a_changed_body_is_reported_as_rule_updated(self) -> None:
        changes = compare_snapshots([self.snapshot("sha256:aa")], [self.snapshot("sha256:bb")])
        assert [change.kind for change in changes] == [SnapshotChangeKind.HASH_CHANGED]
        assert changes[0].label == RULE_UPDATED_LABEL

    def test_a_removed_source_is_reported_too(self) -> None:
        changes = compare_snapshots([self.snapshot("sha256:aa")], [])
        assert [change.kind for change in changes] == [SnapshotChangeKind.REMOVED]

    def test_an_identical_snapshot_reports_nothing(self) -> None:
        assert compare_snapshots([self.snapshot("sha256:aa")], [self.snapshot("sha256:aa")]) == ()


class TestDesignTokens:
    def test_the_official_values_replaced_the_supplied_baseline(self) -> None:
        tokens = load_ui_tokens()
        assert tokens["theme"]["dark"]["surface"]["value"] == "#151D32"
        assert tokens["theme"]["dark"]["border"]["value"] == "#232A3E"
        assert tokens["theme"]["dark"]["textSecondary"]["value"] == "#A1A7AE"
        assert tokens["theme"]["light"]["border"]["value"] == "#D9DDE1"

    def test_every_token_says_where_it_came_from(self) -> None:
        tokens = load_ui_tokens()
        for group in ("palette", "radius", "spacing", "layout"):
            for name, entry in tokens[group].items():
                assert entry["provenance"] in {"design.md", "brand", "app"}, f"{group}.{name}"

    def test_the_baseline_diff_is_recorded_rather_than_applied_silently(self) -> None:
        diff = load_ui_tokens()["diffFromBaseline"]
        paths = {entry["path"] for entry in diff}
        assert "semantic.dark.surface" in paths
        assert "app_design.spacing.2xl" in paths
        for entry in diff:
            assert entry["reason"]

    def test_no_web_font_is_loaded(self) -> None:
        """`font-src 'none'` in the page CSP, and the project costs nothing to run."""
        typography = load_ui_tokens()["typography"]
        assert typography["webFontLoading"] is False
        assert "Space Mono" in typography["monoStack"]
        assert "monospace" in typography["monoStack"]

    def test_gradients_and_drop_shadows_are_refused(self) -> None:
        rules = load_ui_tokens()["rules"]
        assert rules["gradients"] is False
        assert rules["dropShadows"] is False
        assert rules["colorAloneConveysMeaning"] is False

    @pytest.mark.parametrize("ground", ["onBase", "onIce"])
    def test_published_contrast_ratios_recompute(self, ground: str) -> None:
        for pair in load_ui_tokens()["contrast"][ground]:
            measured = contrast_ratio(pair["foreground"], pair["background"])
            assert abs(measured - pair["published"]) < 0.1, pair["id"]

    @pytest.mark.parametrize("ground", ["onBase", "onIce"])
    def test_text_safe_pairs_reach_wcag_aa_and_the_others_do_not(self, ground: str) -> None:
        for pair in load_ui_tokens()["contrast"][ground]:
            measured = contrast_ratio(pair["foreground"], pair["background"])
            if pair["textSafe"]:
                assert measured >= WCAG_AA_NORMAL_TEXT, pair["id"]
            else:
                assert measured < WCAG_AA_NORMAL_TEXT, pair["id"]

    def test_flop_blue_and_grey_are_marked_unusable_as_body_text_on_base(self) -> None:
        by_id = {pair["id"]: pair for pair in load_ui_tokens()["contrast"]["onBase"]}
        assert by_id["blue-on-base"]["textSafe"] is False
        assert by_id["grey-on-base"]["textSafe"] is False

    def test_a_malformed_colour_is_refused(self) -> None:
        with pytest.raises(MalformedEventError):
            contrast_ratio("#nothex", "#0A1128")
