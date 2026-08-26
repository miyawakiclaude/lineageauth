"""QA adversarial pass over `lineage.py` / `bundle.py` (Phase 1 epoch resolver).

Independent verification requested for the epoch-resolution layer. Existing
`tests/test_lineage.py` and `tests/test_bundle.py` already cover most of the
attack list; this file (a) re-derives the ones already covered, written from
scratch and without reusing the existing helper fixtures, to check they are
not passing by construction, and (b) adds cases that were not covered,
including one that reproduces an exploitable bug in the duplicate-envelope
tie-break rule in `bundle.py::_collapse_duplicates`.

Anything here that fails is a finding, not an implementation bug in this file
-- do not "fix" a failing assertion by loosening it, that defeats the point.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from lineageauth.builders import (
    build_recovery_policy,
    build_root_create,
    build_root_succession,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.errors import ReasonCode
from lineageauth.lineage import resolve_lineage
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

ROOT = unsafe_signer(ROOT_A)
SUCCESSOR = unsafe_signer(ROOT_B)
RIVAL = unsafe_signer(AGENT_1)
M1, M2, M3 = (unsafe_signer(name) for name in (RECOVERY_1, RECOVERY_2, RECOVERY_3))
OUTSIDER_KEY = unsafe_signer(OUTSIDER)

GENESIS_PAYLOAD = build_root_create(root_did=ROOT.did, issued_at=AT)
LINEAGE = GENESIS_PAYLOAD["lineage"]


def _genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def _resolve(*envelopes: Envelope, at: datetime = AT):
    return resolve_lineage(EventBundle.from_envelopes(envelopes), lineage=LINEAGE, at=at)


# --------------------------------------------------------------------------------------
# 1. Two valid, incompatible successions out of the same fromEpoch -> CONFLICTED.
# --------------------------------------------------------------------------------------


def test_two_valid_successions_from_the_same_epoch_conflict() -> None:
    left = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=SUCCESSOR.did,
            from_epoch=0,
            mode="normal",
            issued_at=AT,
        ),
        [ROOT],
    )
    right = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=RIVAL.did,
            from_epoch=0,
            mode="normal",
            issued_at=AT,
        ),
        [ROOT],
    )

    state = _resolve(_genesis(), left, right)

    assert state.resolved is False
    assert state.reason is ReasonCode.CONFLICTED
    assert set(state.conflicting_event_ids) == {left.event_id, right.event_id}
    # Fail closed at the last epoch it could justify -- root has NOT moved.
    assert state.root == ROOT.did
    assert state.epoch == 0


# --------------------------------------------------------------------------------------
# 2. Time must never break the tie. Swap which side is "older" and confirm the
#    outcome (CONFLICTED, same two event ids) is byte-for-byte identical.
# --------------------------------------------------------------------------------------


def test_the_later_signed_event_does_not_win_the_conflict() -> None:
    old_time = AT - timedelta(days=400)
    new_time = AT

    # Scenario A: the "left" candidate is signed first (older issuedAt).
    left_old = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=SUCCESSOR.did,
            from_epoch=0,
            mode="normal",
            issued_at=old_time,
        ),
        [ROOT],
    )
    right_new = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=RIVAL.did,
            from_epoch=0,
            mode="normal",
            issued_at=new_time,
        ),
        [ROOT],
    )
    state_a = _resolve(_genesis(), left_old, right_new)

    # Scenario B: exact opposite -- "right" is now the older signature, i.e. the
    # attacker who signs *last* now holds the same wall-clock advantage the
    # other side held in scenario A. If issuedAt influenced the outcome, one of
    # these two scenarios would resolve while the other stays conflicted, or
    # the reported root/epoch would differ between them.
    left_new = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=SUCCESSOR.did,
            from_epoch=0,
            mode="normal",
            issued_at=new_time,
        ),
        [ROOT],
    )
    right_old = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=RIVAL.did,
            from_epoch=0,
            mode="normal",
            issued_at=old_time,
        ),
        [ROOT],
    )
    state_b = _resolve(_genesis(), left_new, right_old)

    for state in (state_a, state_b):
        assert state.resolved is False
        assert state.reason is ReasonCode.CONFLICTED
        assert state.root == ROOT.did
        assert state.epoch == 0

    # Both scenarios must be CONFLICTED regardless of which side's signature is
    # chronologically newer -- neither "the newer claim" nor "the older claim"
    # is allowed to be a privileged position.


# --------------------------------------------------------------------------------------
# 3. Recovery quorum: signers outside `members` must not count toward threshold.
# --------------------------------------------------------------------------------------


def test_outsiders_padding_a_recovery_quorum_do_not_reach_threshold() -> None:
    policy_payload = build_recovery_policy(
        lineage=LINEAGE,
        epoch=0,
        policy_seq=1,
        members=[M1.did, M2.did, M3.did],
        threshold=3,
        issued_at=AT,
    )
    active_policy = sign_payload(policy_payload, [ROOT])

    # Only ONE real member signs; two outsiders (real, verifiable keys, just
    # not on the policy) sign alongside to try to pad the count to 3.
    forged = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=SUCCESSOR.did,
            from_epoch=0,
            mode="recovery",
            recovery_policy_ref=active_policy.event_id,
            issued_at=AT,
        ),
        [M1, OUTSIDER_KEY, unsafe_signer("second-outsider")],
    )

    state = _resolve(_genesis(), active_policy, forged)

    assert state.resolved is True  # candidate-level denial only (D-034)
    assert state.epoch == 0  # succession must NOT have gone through
    assert state.root == ROOT.did
    reasons = {d.event_id: d.reason for d in state.denied}
    assert reasons[forged.event_id] is ReasonCode.INSUFFICIENT_RECOVERY_PROOFS


# --------------------------------------------------------------------------------------
# 4. Recovery quorum: one member re-signing repeatedly must count once.
# --------------------------------------------------------------------------------------


def test_one_member_signing_five_times_still_counts_as_one_vote() -> None:
    policy_payload = build_recovery_policy(
        lineage=LINEAGE,
        epoch=0,
        policy_seq=1,
        members=[M1.did, M2.did, M3.did],
        threshold=2,
        issued_at=AT,
    )
    active_policy = sign_payload(policy_payload, [ROOT])

    forged = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=SUCCESSOR.did,
            from_epoch=0,
            mode="recovery",
            recovery_policy_ref=active_policy.event_id,
            issued_at=AT,
        ),
        [M1, M1, M1, M1, M1],  # five proofs, one distinct signer
    )

    state = _resolve(_genesis(), active_policy, forged)

    assert state.resolved is True
    assert state.epoch == 0
    reasons = {d.event_id: d.reason for d in state.denied}
    assert reasons[forged.event_id] is ReasonCode.INSUFFICIENT_RECOVERY_PROOFS


# --------------------------------------------------------------------------------------
# 5. recoveryPolicyRef pointing at an event that plain does not exist.
# --------------------------------------------------------------------------------------


def test_recovery_policy_ref_to_a_nonexistent_event_is_unresolved_parent() -> None:
    # An active policy must exist so this exercises "ref does not resolve",
    # not the (also DENIED, but differently-coded) "no policy is active" path.
    active_policy = sign_payload(
        build_recovery_policy(
            lineage=LINEAGE,
            epoch=0,
            policy_seq=1,
            members=[M1.did, M2.did, M3.did],
            threshold=2,
            issued_at=AT,
        ),
        [ROOT],
    )
    ghost_id = "sha256:" + "9" * 64
    forged = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=SUCCESSOR.did,
            from_epoch=0,
            mode="recovery",
            recovery_policy_ref=ghost_id,
            issued_at=AT,
        ),
        [M1, M2],
    )

    state = _resolve(_genesis(), active_policy, forged)

    reasons = {d.event_id: d.reason for d in state.denied}
    assert reasons[forged.event_id] is ReasonCode.UNRESOLVED_PARENT
    # D-034: an outsider can author this (no policy signature required to
    # *reference* an id), so it must deny the one candidate, not the lineage.
    assert state.resolved is True


# --------------------------------------------------------------------------------------
# 6. Epoch-skipping succession (0 -> 2), crafted as a raw payload so the
#    builder's own `toEpoch = fromEpoch + 1` guard cannot save us from testing
#    what the *resolver* does with an attacker-constructed payload.
# --------------------------------------------------------------------------------------


def test_an_epoch_skipping_succession_does_not_advance_the_chain() -> None:
    from lineageauth import catalog

    forged_payload = {
        "protocol": catalog.PROTOCOL,
        "version": catalog.CORE_VERSION,
        "type": "root.succession",
        "lineage": LINEAGE,
        "issuedAt": "2026-08-26T09:00:00Z",
        "fromRoot": ROOT.did,
        "toRoot": SUCCESSOR.did,
        "fromEpoch": 0,
        "toEpoch": 2,  # skips epoch 1 entirely
        "mode": "normal",
    }
    forged = sign_payload(forged_payload, [ROOT])

    state = _resolve(_genesis(), forged)

    assert state.resolved is True  # genesis alone still resolves
    assert state.epoch == 0  # the forged jump must not be honored
    assert state.root == ROOT.did
    reasons = {d.event_id: d.reason for d in state.denied}
    assert reasons[forged.event_id] is ReasonCode.MALFORMED


# --------------------------------------------------------------------------------------
# 7. Two root.create events for one lineage -- and separately, a root.create
#    whose declared `lineage` field does not match what its `root` derives to.
# --------------------------------------------------------------------------------------


def test_two_genesis_events_for_one_lineage_conflict() -> None:
    first = sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])
    second = sign_payload(
        build_root_create(root_did=ROOT.did, issued_at=AT + timedelta(seconds=1)), [ROOT]
    )
    assert first.event_id != second.event_id  # different issuedAt -> different event

    state = _resolve(first, second)

    assert state.resolved is False
    assert state.reason is ReasonCode.CONFLICTED
    assert set(state.conflicting_event_ids) == {first.event_id, second.event_id}


def test_a_genesis_with_a_forged_lineage_field_is_malformed_not_admitted() -> None:
    other_root = unsafe_signer("some-other-root")
    genuine_payload = build_root_create(root_did=other_root.did, issued_at=AT)
    forged_payload = dict(genuine_payload) | {"lineage": LINEAGE}  # claim ROOT's lineage
    forged = sign_payload(forged_payload, [other_root])

    # This must NOT be able to open (or contest) ROOT's lineage.
    state = _resolve(_genesis(), forged)

    assert state.resolved is True
    assert state.root == ROOT.did
    assert state.epoch == 0
    reasons = {d.event_id: d.reason for d in state.denied}
    assert reasons[forged.event_id] is ReasonCode.MALFORMED


# --------------------------------------------------------------------------------------
# 8. An event whose signature was invalidated by tampering must be fully
#    excluded from admission -- it cannot even show up as a denied candidate
#    with authority-shaped detail, and it cannot manufacture a conflict.
# --------------------------------------------------------------------------------------


def test_a_tampered_signature_event_cannot_manufacture_a_conflict() -> None:
    legit = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=SUCCESSOR.did,
            from_epoch=0,
            mode="normal",
            issued_at=AT,
        ),
        [ROOT],
    )
    # Flip the destination after signing; the old proof no longer covers this
    # payload's preimage, so it must fail integrity, not become a competitor.
    tampered = Envelope(
        payload=dict(legit.payload) | {"toRoot": RIVAL.did},
        proofs=list(legit.proofs),
    )

    bundle = EventBundle.from_envelopes([_genesis(), legit, tampered])
    assert any(r.reason is ReasonCode.INVALID_SIGNATURE for r in bundle.rejected)
    assert tampered.event_id not in {e.event_id for e in bundle.admitted}

    state = resolve_lineage(bundle, lineage=LINEAGE, at=AT)

    assert state.resolved is True
    assert state.root == SUCCESSOR.did  # the untampered succession still applies
    assert state.epoch == 1
    assert RIVAL.did not in (state.root, *state.superseded_roots)


# --------------------------------------------------------------------------------------
# 9. Input-order independence for the exact bundles built above.
# --------------------------------------------------------------------------------------


def test_shuffling_a_conflicted_bundle_does_not_change_the_verdict() -> None:
    left = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=SUCCESSOR.did,
            from_epoch=0,
            mode="normal",
            issued_at=AT - timedelta(days=1),
        ),
        [ROOT],
    )
    right = sign_payload(
        build_root_succession(
            lineage=LINEAGE,
            from_root=ROOT.did,
            to_root=RIVAL.did,
            from_epoch=0,
            mode="normal",
            issued_at=AT,
        ),
        [ROOT],
    )
    events = [_genesis(), left, right]
    baseline = _resolve(*events)

    rng = random.Random(9)
    for _ in range(30):
        shuffled = events[:]
        rng.shuffle(shuffled)
        state = _resolve(*shuffled)
        assert state.resolved == baseline.resolved
        assert state.reason == baseline.reason
        assert state.conflicting_event_ids == baseline.conflicting_event_ids
        assert (state.root, state.epoch) == (baseline.root, baseline.epoch)


# --------------------------------------------------------------------------------------
# 10. FINDING: a stripped duplicate of a legitimate multi-signer envelope can
#     suppress a valid recovery quorum. No private key is required -- the
#     attacker only needs to see the broadcast envelope and remove proofs from
#     a copy of it. `EventBundle._collapse_duplicates` breaks ties between two
#     admitted copies of the same event_id by comparing `sorted(verified_signers)`
#     as tuples and keeping the smaller one. A tuple with fewer elements that
#     shares a prefix with a longer tuple sorts smaller in Python, so a
#     single-proof copy that keeps only the globally-smallest-DID signer will
#     always be chosen over a copy carrying additional, quorum-completing
#     signers -- regardless of which one the bundle assembler actually wanted
#     kept, and regardless of arrival order.
# --------------------------------------------------------------------------------------


def test_stripped_duplicate_suppresses_a_legitimate_recovery_quorum() -> None:
    policy_payload = build_recovery_policy(
        lineage=LINEAGE,
        epoch=0,
        policy_seq=1,
        members=[M1.did, M2.did, M3.did],
        threshold=2,
        issued_at=AT,
    )
    active_policy = sign_payload(policy_payload, [ROOT])

    # A genuinely-authorized 2-of-3 recovery succession: M1 and M2 both sign.
    succession_payload = build_root_succession(
        lineage=LINEAGE,
        from_root=ROOT.did,
        to_root=SUCCESSOR.did,
        from_epoch=0,
        mode="recovery",
        recovery_policy_ref=active_policy.event_id,
        issued_at=AT,
    )
    legit = sign_payload(succession_payload, [M1, M2])
    assert len(legit.proofs) == 2

    # Attacker strips the proof list down to whichever single signer's DID
    # sorts smallest. This requires no private key: it is public information
    # manipulation on an envelope the attacker can observe in transit or in
    # any public relay/mirror of the bundle.
    smaller_did = min(M1.did, M2.did)
    kept_proof = next(p for p in legit.proofs if p.signer == smaller_did)
    stripped = Envelope(payload=dict(legit.payload), proofs=[kept_proof])

    assert stripped.event_id == legit.event_id  # event_id is payload-only
    assert len(stripped.proofs) == 1

    bundle = EventBundle.from_envelopes([_genesis(), active_policy, legit, stripped])

    # If admission behaved as the module's own docstring promises --
    # "keeping one copy can only deny, never admit" relative to the *union* --
    # the survivor should retain at least as much signing power as the
    # legitimate copy, or the ambiguity should be surfaced, not silently
    # resolved in the attacker's favor. Confirm which copy actually survives:
    survivor = bundle.by_id(legit.event_id)
    assert survivor is not None

    state = resolve_lineage(bundle, lineage=LINEAGE, at=AT)

    if len(survivor.verified_signers) == 1:
        # BUG REPRODUCED: the stripped, single-signer copy won the tie-break
        # over the fully-quorate 2-signer original, so a recovery succession
        # that 2 of 3 legitimate recovery-committee members actually signed
        # is reported as denied for insufficient proofs -- purely because an
        # observer without any signing key removed a proof from a copy of a
        # public envelope.
        assert state.epoch == 0
        reasons = {d.event_id: d.reason for d in state.denied}
        assert reasons.get(legit.event_id) is ReasonCode.INSUFFICIENT_RECOVERY_PROOFS
        raise AssertionError(
            "SECURITY FINDING: EventBundle._collapse_duplicates (bundle.py) keeps the "
            "duplicate copy with the lexicographically smaller sorted(verified_signers) "
            "tuple. Since a shorter tuple that shares a prefix with a longer one sorts "
            "smaller in Python, an attacker who observes a legitimate multi-signer "
            "envelope can strip it down to a single proof (the signer whose DID is "
            "globally smallest) and that stripped copy will deterministically be chosen "
            "over the original, fully-quorate copy -- with no private key required. "
            "Result: a real 2-of-3 recovery quorum "
            f"({legit.event_id}, signed by {[M1.did, M2.did]}) is silently reduced to "
            f"{survivor.verified_signers}, and the succession denies with "
            "INSUFFICIENT_RECOVERY_PROOFS even though the quorum was actually met. This "
            "is a denial-of-service against legitimate root recovery that needs no "
            "compromised key -- only visibility into the bundle."
        )
    else:
        # If this branch runs, the bug has been fixed (or was already not
        # present) and the fully-signed copy survives as intended.
        assert state.resolved is True
        assert state.root == SUCCESSOR.did
        assert state.epoch == 1
