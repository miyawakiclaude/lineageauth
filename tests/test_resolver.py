"""The multi-source resolver.

`docs/15` says the resolver must never become protocol authority, and the whole
file is about what that costs. It cannot pick between disagreeing mirrors. It
cannot declare a view complete. It cannot let a quiet source pass for an
agreeing one.

The attack it exists to make visible is omission: a mirror that forwards
everything except the revocation. The merge is a union so that mirror cannot
suppress anything another source supplies, and the conflict report names it by
source so a reader can see which one was economical with the truth.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from lineageauth.builders import (
    build_delegation_grant,
    build_delegation_revoke,
    build_root_create,
    sign_payload,
)
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError, ReasonCode
from lineageauth.identifiers import derive_lineage_id
from lineageauth.resolver import (
    DirectorySource,
    FreshnessPolicy,
    MemorySource,
    StaleViewError,
    collect,
)
from tests.testkeys import AGENT_1, ROOT_A, unsafe_signer

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
LATER = AT + timedelta(hours=6)

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
LINEAGE: str = derive_lineage_id(ROOT.did)


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant() -> Envelope:
    payload = build_delegation_grant(
        lineage=LINEAGE,
        issuer=ROOT.did,
        subject=AGENT.did,
        epoch=0,
        scopes=[{"namespace": "technocore", "resource": "room:lobby", "actions": ["write"]}],
        not_before=AT - timedelta(days=1),
        expires_at=AT + timedelta(days=30),
        max_depth=0,
        issued_at=AT,
    )
    return sign_payload(payload, [ROOT])


def revoke(target: Envelope) -> Envelope:
    payload = build_delegation_revoke(
        lineage=LINEAGE,
        issuer=ROOT.did,
        grant=target.event_id,
        reason="key rotated",
        issued_at=LATER,
    )
    return sign_payload(payload, [ROOT])


class Exploding:
    """A source that raises. Somebody else's code always eventually does."""

    name = "broken-mirror"

    def envelopes(self) -> list[Envelope]:
        raise RuntimeError("connection reset")


# ------------------------------------------------------------ omission


class TestTheOmissionAttack:
    def _two_mirrors(self) -> tuple[MemorySource, MemorySource, Envelope]:
        held = grant()
        withdrawn = revoke(held)
        complete = MemorySource("complete", [genesis(), held, withdrawn])
        economical = MemorySource("economical", [genesis(), held])
        return complete, economical, withdrawn

    def test_a_union_means_one_mirror_cannot_suppress_a_revocation(self) -> None:
        """The point of the whole module."""
        complete, economical, withdrawn = self._two_mirrors()
        view = collect([economical, complete], checked_at=LATER, policy=None)
        assert withdrawn.event_id in {e.event_id for e in view.bundle.admitted}

    def test_the_order_the_mirrors_are_read_in_changes_nothing(self) -> None:
        complete, economical, _ = self._two_mirrors()
        one = collect([complete, economical], checked_at=LATER)
        other = collect([economical, complete], checked_at=LATER)
        assert {e.event_id for e in one.bundle.admitted} == {
            e.event_id for e in other.bundle.admitted
        }

    def test_the_mirror_that_omitted_it_is_named(self) -> None:
        complete, economical, withdrawn = self._two_mirrors()
        view = collect([complete, economical], checked_at=LATER)
        conflict = next(c for c in view.conflicts if c.event_id == withdrawn.event_id)
        assert conflict.present_in == ("complete",)
        assert conflict.absent_from == ("economical",)

    def test_a_missing_revocation_is_marked_authority_critical(self) -> None:
        complete, economical, _ = self._two_mirrors()
        view = collect([complete, economical], checked_at=LATER)
        assert len(view.critical_conflicts) == 1
        assert view.critical_conflicts[0].event_type == "delegation.revoke"

    def test_critical_conflicts_are_reported_first(self) -> None:
        """A reader who stops after two lines should see the dangerous one."""
        complete, economical, _ = self._two_mirrors()
        extra = MemorySource("partial", [genesis()])
        view = collect([complete, economical, extra], checked_at=LATER)
        assert view.conflicts[0].authority_critical

    def test_one_source_alone_reports_no_conflicts(self) -> None:
        """Nothing to disagree with is not agreement, and is not reported as one."""
        complete, _, _ = self._two_mirrors()
        view = collect([complete], checked_at=LATER)
        assert view.conflicts == ()


# ------------------------------------------------------------ freshness


class TestFreshness:
    def test_the_age_is_measured_from_the_newest_event_anyone_had(self) -> None:
        view = collect(
            [MemorySource("local", [genesis(), grant()])],
            checked_at=AT + timedelta(hours=2),
        )
        assert view.freshness_age == timedelta(hours=2)

    def test_an_age_beyond_the_policy_is_stale(self) -> None:
        view = collect(
            [MemorySource("local", [genesis()])],
            checked_at=AT + timedelta(days=3),
            policy=FreshnessPolicy(max_age=timedelta(hours=1)),
        )
        assert not view.fresh
        assert view.status is ReasonCode.STALE_STATUS

    def test_a_met_policy_has_no_affirmative_status(self) -> None:
        """Freshness is the absence of a problem, not a verdict about the events."""
        view = collect(
            [MemorySource("local", [genesis()])],
            checked_at=AT + timedelta(minutes=5),
            policy=FreshnessPolicy(max_age=timedelta(hours=1)),
        )
        assert view.fresh
        assert view.status is None

    def test_the_high_risk_path_raises_rather_than_returning_a_value(self) -> None:
        view = collect(
            [MemorySource("local", [genesis()])],
            checked_at=AT + timedelta(days=3),
            policy=FreshnessPolicy(max_age=timedelta(hours=1)),
        )
        with pytest.raises(StaleViewError):
            view.require_fresh()

    def test_a_fresh_view_passes_the_high_risk_check_quietly(self) -> None:
        view = collect([MemorySource("local", [genesis()])], checked_at=AT)
        view.require_fresh()

    def test_freshness_never_claims_completeness(self) -> None:
        """A recent event and a withheld revocation coexist happily."""
        held = grant()
        economical = MemorySource("economical", [genesis(), held])
        view = collect(
            [economical],
            checked_at=LATER + timedelta(minutes=1),
            policy=FreshnessPolicy(max_age=timedelta(days=30)),
        )
        assert view.fresh
        assert "never completeness" in view.note

    def test_too_few_sources_answered(self) -> None:
        view = collect(
            [MemorySource("local", [genesis()]), Exploding()],
            checked_at=AT,
            policy=FreshnessPolicy(min_sources=2),
        )
        assert not view.fresh
        assert "1 of 2 source(s) answered" in view.detail

    def test_a_quiet_source_does_not_pass_for_an_agreeing_one(self) -> None:
        view = collect(
            [MemorySource("local", [genesis()]), Exploding()],
            checked_at=AT,
            policy=FreshnessPolicy(require_all_sources=True),
        )
        assert not view.fresh
        assert "indistinguishable from one that is withholding" in view.detail

    def test_no_dated_event_means_no_age_to_check(self) -> None:
        view = collect(
            [MemorySource("empty", [])],
            checked_at=AT,
            policy=FreshnessPolicy(max_age=timedelta(hours=1)),
        )
        assert view.freshness_age is None
        assert not view.fresh


# ------------------------------------------------------------ sources


class TestSources:
    def test_a_source_that_throws_is_reported_and_does_not_stop_the_others(self) -> None:
        view = collect([Exploding(), MemorySource("local", [genesis(), grant()])], checked_at=AT)
        broken = next(s for s in view.sources if s.name == "broken-mirror")
        assert not broken.reachable
        assert "connection reset" in (broken.error or "")
        assert len(view.bundle.admitted) == 2

    def test_a_failed_source_is_distinguishable_from_an_empty_one(self) -> None:
        view = collect([Exploding(), MemorySource("empty", [])], checked_at=AT)
        by_name = {s.name: s for s in view.sources}
        assert by_name["broken-mirror"].reachable is False
        assert by_name["empty"].reachable is True

    def test_two_sources_with_one_name_are_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="both called"):
            collect(
                [MemorySource("mirror", []), MemorySource("mirror", [])],
                checked_at=AT,
            )

    def test_a_directory_of_envelopes_reads(self, tmp_path: Path) -> None:
        for envelope in (genesis(), grant()):
            (tmp_path / f"{envelope.event_id[7:19]}.json").write_text(
                envelope.to_json(), encoding="utf-8"
            )
        view = collect([DirectorySource("disk", tmp_path)], checked_at=AT)
        assert len(view.bundle.admitted) == 2

    def test_one_corrupt_file_does_not_hide_the_rest(self, tmp_path: Path) -> None:
        (tmp_path / "good.json").write_text(genesis().to_json(), encoding="utf-8")
        (tmp_path / "truncated.json").write_text("{not json", encoding="utf-8")
        view = collect([DirectorySource("disk", tmp_path)], checked_at=AT)
        assert len(view.bundle.admitted) == 1

    def test_a_tampered_event_is_rejected_by_the_bundle_not_admitted_by_the_source(
        self, tmp_path: Path
    ) -> None:
        """A source cannot launder an event; it still has to verify."""
        forged = json.loads(grant().to_json())
        forged["payload"]["subject"] = ROOT.did
        (tmp_path / "forged.json").write_text(json.dumps(forged), encoding="utf-8")
        (tmp_path / "good.json").write_text(genesis().to_json(), encoding="utf-8")
        view = collect([DirectorySource("hostile", tmp_path)], checked_at=AT)
        assert len(view.bundle.admitted) == 1
        assert view.to_dict()["rejectedEvents"] == 1

    def test_a_naive_clock_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="timezone-aware"):
            collect([MemorySource("local", [])], checked_at=datetime(2026, 8, 27))


# ------------------------------------------------------------ what it refuses


class TestItIsNotAuthority:
    def test_the_note_says_conflicts_are_not_resolved(self) -> None:
        view = collect([MemorySource("local", [genesis()])], checked_at=AT)
        assert "surfaced and not resolved" in view.note
        assert "would be acting as authority" in view.note

    def test_the_note_explains_why_the_merge_is_a_union(self) -> None:
        view = collect([MemorySource("local", [genesis()])], checked_at=AT)
        assert "no source can remove an event another source supplied" in view.note

    def test_the_report_carries_the_metadata_docs_15_names(self) -> None:
        complete = MemorySource("complete", [genesis(), grant()])
        body = collect([complete], checked_at=LATER).to_dict()
        for key in (
            "checkedAt",
            "sources",
            "newestEventSeen",
            "freshnessAgeSeconds",
            "conflicts",
        ):
            assert key in body

    def test_nothing_in_the_view_reads_as_a_verdict(self) -> None:
        view = collect([MemorySource("local", [genesis()])], checked_at=AT)
        flat = repr(view.to_dict()).lower()
        for word in ("score", "trusted", "authoritative", "canonical"):
            assert word not in flat
