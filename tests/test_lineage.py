"""Epoch resolution tests.

docs/23_TESTING.md pins the properties that matter here: a threshold counts
distinct signers, duplicates do not count, non-members do not count, and
competing successions are CONFLICTED. The rest of this file guards the two
things that are easy to lose in a refactor -- that no decision is made by a
timestamp, and that input order cannot change an answer.
"""

from __future__ import annotations

import itertools
import random
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from lineageauth.builders import (
    build_recovery_policy,
    build_root_create,
    build_root_succession,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError, ReasonCode
from lineageauth.lineage import LineageState, resolve_lineage
from tests.testkeys import (
    AGENT_1,
    OUTSIDER,
    RECOVERY_1,
    RECOVERY_2,
    RECOVERY_3,
    ROOT_A,
    ROOT_B,
    unsafe_signer,
)

AT = datetime(2026, 8, 26, 9, 0, 0, tzinfo=UTC)
EARLIER = AT - timedelta(days=1)
LATER = AT - timedelta(hours=1)

ROOT = unsafe_signer(ROOT_A)
NEXT_ROOT = unsafe_signer(ROOT_B)
RIVAL_ROOT = unsafe_signer(AGENT_1)
MEMBERS = [unsafe_signer(name) for name in (RECOVERY_1, RECOVERY_2, RECOVERY_3)]
STRANGER = unsafe_signer(OUTSIDER)

GENESIS_PAYLOAD = build_root_create(root_did=ROOT.did, issued_at=AT)
LINEAGE: str = GENESIS_PAYLOAD["lineage"]


def genesis(*, issued_at: datetime = AT, signers: list[LocalSigner] | None = None) -> Envelope:
    payload = build_root_create(root_did=ROOT.did, issued_at=issued_at)
    return sign_payload(payload, signers if signers is not None else [ROOT])


def policy(
    *,
    epoch: int = 0,
    policy_seq: int = 1,
    members: list[LocalSigner] | None = None,
    threshold: int = 2,
    previous_policy: str | None = None,
    issued_at: datetime = AT,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_recovery_policy(
        lineage=LINEAGE,
        epoch=epoch,
        policy_seq=policy_seq,
        members=[m.did for m in (members if members is not None else MEMBERS)],
        threshold=threshold,
        previous_policy=previous_policy,
        issued_at=issued_at,
    )
    return sign_payload(payload, signers if signers is not None else [ROOT])


def succession(
    *,
    from_root: LocalSigner = ROOT,
    to_root: LocalSigner = NEXT_ROOT,
    from_epoch: int = 0,
    mode: str = "normal",
    recovery_policy_ref: str | None = None,
    issued_at: datetime = AT,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_root_succession(
        lineage=LINEAGE,
        from_root=from_root.did,
        to_root=to_root.did,
        from_epoch=from_epoch,
        mode=mode,
        recovery_policy_ref=recovery_policy_ref,
        issued_at=issued_at,
    )
    return sign_payload(payload, signers if signers is not None else [from_root])


def resolve(*envelopes: Envelope, at: datetime = AT) -> LineageState:
    return resolve_lineage(EventBundle.from_envelopes(envelopes), lineage=LINEAGE, at=at)


def denial_for(state: LineageState, event: Envelope) -> ReasonCode:
    for item in state.denied:
        if item.event_id == event.event_id:
            return item.reason
    raise AssertionError(f"{event.event_id} was not recorded as denied: {state.denied}")


# --------------------------------------------------------------------------- genesis


def test_genesis_alone_resolves_epoch_zero() -> None:
    state = resolve(genesis())

    assert state.resolved
    assert state.reason is ReasonCode.VALID_AUTHORITY_CHAIN
    assert (state.root, state.epoch) == (ROOT.did, 0)
    assert state.genesis_root == ROOT.did
    assert state.history == ()
    assert state.evaluated_at == AT


def test_missing_genesis_is_unresolved_not_empty() -> None:
    state = resolve()

    assert not state.resolved
    assert state.reason is ReasonCode.UNRESOLVED_PARENT
    assert state.root is None
    assert state.standing_of(ROOT.did) is ReasonCode.UNRESOLVED_PARENT


def test_genesis_must_be_signed_by_the_root_it_installs() -> None:
    """D-029: opening a lineage requires proof of control of the declared key."""
    forged = genesis(signers=[STRANGER])

    state = resolve(forged)

    assert not state.resolved
    assert state.reason is ReasonCode.UNRESOLVED_PARENT
    assert denial_for(state, forged) is ReasonCode.DENIED


def test_two_genesis_events_conflict() -> None:
    first, second = genesis(issued_at=EARLIER), genesis(issued_at=LATER)

    state = resolve(first, second)

    assert not state.resolved
    assert state.reason is ReasonCode.CONFLICTED
    assert state.conflicting_event_ids == tuple(sorted((first.event_id, second.event_id)))


def test_a_malformed_lineage_identifier_is_refused() -> None:
    state = resolve_lineage(EventBundle.from_envelopes([genesis()]), lineage="not-a-lineage", at=AT)

    assert not state.resolved
    assert state.reason is ReasonCode.MALFORMED


# ----------------------------------------------------------------- normal succession


def test_normal_succession_signed_by_the_outgoing_root_advances() -> None:
    move = succession()

    state = resolve(genesis(), move)

    assert state.resolved
    assert (state.root, state.epoch) == (NEXT_ROOT.did, 1)
    assert state.superseded_roots == (ROOT.did,)
    assert state.history[0].via_event_ids == (move.event_id,)
    assert state.history[0].mode == "normal"


def test_normal_succession_not_signed_by_the_root_does_not_advance() -> None:
    forged = succession(signers=[STRANGER])

    state = resolve(genesis(), forged)

    assert state.resolved
    assert (state.root, state.epoch) == (ROOT.did, 0)
    assert denial_for(state, forged) is ReasonCode.DENIED


def test_a_succession_leaving_the_wrong_root_is_not_a_candidate() -> None:
    """D-032: naming the right epoch number is not the same as holding it."""
    stale = succession(from_root=RIVAL_ROOT, to_root=NEXT_ROOT, signers=[RIVAL_ROOT])

    state = resolve(genesis(), stale)

    assert state.resolved
    assert state.epoch == 0
    assert denial_for(state, stale) is ReasonCode.DENIED


def test_old_root_is_superseded_not_invalidated() -> None:
    state = resolve(genesis(), succession())

    assert state.standing_of(ROOT.did) is ReasonCode.SUPERSEDED
    assert state.standing_of(NEXT_ROOT.did) is ReasonCode.VALID_AUTHORITY_CHAIN
    assert state.standing_of(STRANGER.did) is ReasonCode.DENIED
    assert "no revocation" in state.note


# --------------------------------------------------------------- recovery succession


def test_recovery_succession_needs_threshold_distinct_members() -> None:
    active = policy(threshold=2)
    move = succession(
        mode="recovery",
        recovery_policy_ref=active.event_id,
        signers=[MEMBERS[0], MEMBERS[1]],
    )

    state = resolve(genesis(), active, move)

    assert state.resolved
    assert (state.root, state.epoch) == (NEXT_ROOT.did, 1)
    assert state.history[0].mode == "recovery"


def test_duplicate_recovery_signers_count_once() -> None:
    active = policy(threshold=2)
    move = succession(
        mode="recovery",
        recovery_policy_ref=active.event_id,
        signers=[MEMBERS[0], MEMBERS[0]],
    )

    state = resolve(genesis(), active, move)

    assert state.epoch == 0
    assert denial_for(state, move) is ReasonCode.INSUFFICIENT_RECOVERY_PROOFS


def test_non_members_do_not_count_toward_the_threshold() -> None:
    active = policy(threshold=2)
    move = succession(
        mode="recovery",
        recovery_policy_ref=active.event_id,
        signers=[MEMBERS[0], STRANGER, RIVAL_ROOT],
    )

    state = resolve(genesis(), active, move)

    assert state.epoch == 0
    assert denial_for(state, move) is ReasonCode.INSUFFICIENT_RECOVERY_PROOFS


def test_recovery_without_an_active_policy_is_denied() -> None:
    move = succession(
        mode="recovery",
        recovery_policy_ref="sha256:" + "0" * 64,
        signers=[MEMBERS[0], MEMBERS[1]],
    )

    state = resolve(genesis(), move)

    assert state.resolved  # D-034: a stranger's junk must not freeze the lineage
    assert state.epoch == 0
    assert denial_for(state, move) is ReasonCode.DENIED


def test_a_dangling_policy_reference_denies_the_candidate_only() -> None:
    """D-034: an outsider can author this, so it must not halt resolution."""
    active = policy(threshold=2)
    move = succession(
        mode="recovery",
        recovery_policy_ref="sha256:" + "f" * 64,
        signers=[MEMBERS[0], MEMBERS[1]],
    )

    state = resolve(genesis(), active, move)

    assert state.resolved
    assert state.epoch == 0
    assert denial_for(state, move) is ReasonCode.UNRESOLVED_PARENT


def test_a_recovery_succession_citing_a_rotated_policy_is_superseded() -> None:
    """D-030: rotation would be cosmetic if the old membership still authorized."""
    first = policy(policy_seq=1, members=MEMBERS, threshold=2)
    second = policy(
        policy_seq=2,
        members=[MEMBERS[1], MEMBERS[2]],
        threshold=2,
        previous_policy=first.event_id,
    )
    move = succession(
        mode="recovery",
        recovery_policy_ref=first.event_id,
        signers=[MEMBERS[0], MEMBERS[1]],
    )

    state = resolve(genesis(), first, second, move)

    assert state.epoch == 0
    assert state.active_recovery_policy is not None
    assert state.active_recovery_policy.event_id == second.event_id
    assert denial_for(state, move) is ReasonCode.SUPERSEDED


def test_a_recovery_policy_survives_a_normal_succession() -> None:
    """D-031: a normal succession must not silently destroy recovery capability."""
    active = policy(epoch=0, threshold=2)
    first_move = succession(from_epoch=0, to_root=NEXT_ROOT)
    second_move = succession(
        from_root=NEXT_ROOT,
        to_root=RIVAL_ROOT,
        from_epoch=1,
        mode="recovery",
        recovery_policy_ref=active.event_id,
        signers=[MEMBERS[0], MEMBERS[2]],
    )

    state = resolve(genesis(), active, first_move, second_move)

    assert state.resolved
    assert (state.root, state.epoch) == (RIVAL_ROOT.did, 2)
    assert state.superseded_roots == (ROOT.did, NEXT_ROOT.did)


# ---------------------------------------------------------------- policy consistency


def test_two_policies_at_one_sequence_fail_closed() -> None:
    first = policy(policy_seq=1, threshold=1, issued_at=EARLIER)
    second = policy(policy_seq=1, threshold=3, issued_at=LATER)

    state = resolve(genesis(), first, second)

    assert not state.resolved
    assert state.reason is ReasonCode.CONFLICTED
    assert state.conflicting_event_ids == tuple(sorted((first.event_id, second.event_id)))


def test_a_policy_not_signed_by_the_current_root_is_ignored() -> None:
    """An outsider must not be able to install -- or contest -- a policy."""
    forged = policy(threshold=1, signers=[STRANGER])

    state = resolve(genesis(), forged)

    assert state.resolved
    assert state.active_recovery_policy is None
    assert denial_for(state, forged) is ReasonCode.DENIED


def test_a_replacement_policy_that_does_not_attach_fails_closed() -> None:
    first = policy(policy_seq=1, threshold=2)
    orphan = policy(
        policy_seq=2,
        threshold=1,
        previous_policy="sha256:" + "a" * 64,
    )

    state = resolve(genesis(), first, orphan)

    assert not state.resolved
    assert state.reason is ReasonCode.UNRESOLVED_PARENT


def test_a_policy_that_does_not_advance_the_sequence_is_superseded() -> None:
    first = policy(policy_seq=1, threshold=2, issued_at=EARLIER)
    replay = policy(policy_seq=1, threshold=2, issued_at=EARLIER, members=MEMBERS)
    assert replay.event_id == first.event_id  # identical content, one event

    later = policy(policy_seq=2, threshold=1, previous_policy=first.event_id)
    stale = policy(policy_seq=2, threshold=3, previous_policy=first.event_id, issued_at=LATER)

    state = resolve(genesis(), first, later, stale)

    assert not state.resolved  # two distinct policies claim policySeq 2
    assert state.reason is ReasonCode.CONFLICTED


# ------------------------------------------------------------------------- conflicts


def test_competing_successions_are_conflicted() -> None:
    left = succession(to_root=NEXT_ROOT)
    right = succession(to_root=RIVAL_ROOT)

    state = resolve(genesis(), left, right)

    assert not state.resolved
    assert state.reason is ReasonCode.CONFLICTED
    assert state.conflicting_event_ids == tuple(sorted((left.event_id, right.event_id)))
    # The last position the resolver could justify is still reported.
    assert (state.root, state.epoch) == (ROOT.did, 0)
    assert state.standing_of(ROOT.did) is ReasonCode.CONFLICTED
    assert state.standing_of(NEXT_ROOT.did) is ReasonCode.CONFLICTED


def test_a_normal_and_a_recovery_succession_can_conflict() -> None:
    active = policy(threshold=2)
    by_root = succession(to_root=NEXT_ROOT)
    by_quorum = succession(
        to_root=RIVAL_ROOT,
        mode="recovery",
        recovery_policy_ref=active.event_id,
        signers=[MEMBERS[0], MEMBERS[1]],
    )

    state = resolve(genesis(), active, by_root, by_quorum)

    assert state.reason is ReasonCode.CONFLICTED
    assert state.conflicting_event_ids == tuple(sorted((by_root.event_id, by_quorum.event_id)))


def test_successions_agreeing_on_the_destination_are_not_a_conflict() -> None:
    """Nothing incompatible happened, so there is no winner to pick."""
    active = policy(threshold=2)
    by_root = succession(to_root=NEXT_ROOT)
    by_quorum = succession(
        to_root=NEXT_ROOT,
        mode="recovery",
        recovery_policy_ref=active.event_id,
        signers=[MEMBERS[0], MEMBERS[1]],
    )

    state = resolve(genesis(), active, by_root, by_quorum)

    assert state.resolved
    assert (state.root, state.epoch) == (NEXT_ROOT.did, 1)
    assert state.history[0].via_event_ids == tuple(sorted((by_root.event_id, by_quorum.event_id)))
    assert state.history[0].mode == "normal+recovery"


def test_issued_at_never_breaks_ties() -> None:
    """D-033 regression guard.

    Swap which competing succession was signed first. If any timestamp were
    consulted -- as an ordering, or as an `at` filter that quietly removes the
    future-dated one -- the winner would change and the conflict would vanish.
    Whoever signs last would take the lineage, which is the attacker holding a
    stolen key.
    """
    orderings = [(EARLIER, LATER), (LATER, EARLIER)]
    evaluation_times = [AT, EARLIER, EARLIER - timedelta(days=365)]

    for left_time, right_time in orderings:
        left = succession(to_root=NEXT_ROOT, issued_at=left_time)
        right = succession(to_root=RIVAL_ROOT, issued_at=right_time)
        expected = tuple(sorted((left.event_id, right.event_id)))
        for moment in evaluation_times:
            state = resolve(genesis(issued_at=EARLIER), left, right, at=moment)
            assert state.reason is ReasonCode.CONFLICTED
            assert state.conflicting_event_ids == expected
            assert state.root == ROOT.did


def test_future_dated_events_are_warned_about_but_still_counted() -> None:
    """`at` reports; it does not filter (D-033)."""
    move = succession(issued_at=AT + timedelta(days=30))

    state = resolve(genesis(), move, at=AT)

    assert state.resolved
    assert (state.root, state.epoch) == (NEXT_ROOT.did, 1)
    assert any(move.event_id in warning for warning in state.warnings)


def test_a_naive_evaluation_time_is_refused() -> None:
    with pytest.raises(MalformedEventError):
        resolve_lineage(
            EventBundle.from_envelopes([genesis()]),
            lineage=LINEAGE,
            at=datetime(2026, 8, 26, 9, 0, 0),
        )


# ----------------------------------------------------------------------- determinism


def _snapshot(state: LineageState) -> tuple[Any, ...]:
    return (
        state.resolved,
        state.reason,
        state.detail,
        state.root,
        state.epoch,
        state.history,
        state.superseded_roots,
        state.active_recovery_policy,
        state.conflicting_event_ids,
        tuple(sorted((d.event_id, d.reason) for d in state.denied)),
    )


def _chain() -> list[Envelope]:
    first = policy(policy_seq=1, threshold=2)
    second = policy(policy_seq=2, threshold=2, previous_policy=first.event_id)
    move = succession(
        mode="recovery",
        recovery_policy_ref=second.event_id,
        signers=[MEMBERS[0], MEMBERS[2], MEMBERS[0]],
    )
    noise = [
        succession(to_root=RIVAL_ROOT, signers=[STRANGER]),
        policy(policy_seq=7, threshold=1, previous_policy=first.event_id, signers=[STRANGER]),
        genesis(signers=[STRANGER, ROOT]),
    ]
    return [genesis(), first, second, move, *noise]


def test_input_order_cannot_change_the_result() -> None:
    events = _chain()
    baseline = _snapshot(resolve(*events))
    assert baseline[0] is True

    rng = random.Random(20260826)
    for _ in range(40):
        shuffled = events[:]
        rng.shuffle(shuffled)
        assert _snapshot(resolve(*shuffled)) == baseline


def test_small_bundles_are_order_independent_under_every_permutation() -> None:
    events = [genesis(), policy(threshold=2), succession()]
    baseline = _snapshot(resolve(*events))

    for permutation in itertools.permutations(events):
        assert _snapshot(resolve(*permutation)) == baseline


def test_repeated_resolution_is_stable() -> None:
    events = _chain()
    assert _snapshot(resolve(*events)) == _snapshot(resolve(*events))
