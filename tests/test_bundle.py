"""Admission-layer tests.

The bundle's job is narrow: keep unverifiable events out of authority
resolution, and hand the resolver an order that does not depend on how the
caller happened to iterate.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime

from lineageauth.builders import build_recovery_policy, build_root_create, sign_payload
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope, Proof
from lineageauth.errors import ReasonCode
from tests.testkeys import OUTSIDER, RECOVERY_1, RECOVERY_2, ROOT_A, ROOT_B, unsafe_signer

AT = datetime(2026, 8, 26, 9, 0, 0, tzinfo=UTC)


def _genesis(label: str = ROOT_A) -> tuple[Envelope, str]:
    signer = unsafe_signer(label)
    payload = build_root_create(root_did=signer.did, issued_at=AT)
    return sign_payload(payload, [signer]), payload["lineage"]


def test_verified_events_are_admitted() -> None:
    envelope, lineage = _genesis()
    bundle = EventBundle.from_envelopes([envelope])

    assert len(bundle.admitted) == 1
    assert bundle.rejected == ()
    admitted = bundle.admitted[0]
    assert admitted.event_id == envelope.event_id
    assert admitted.lineage == lineage
    assert admitted.issued_at == AT


def test_tampered_events_never_reach_the_resolver() -> None:
    envelope, _ = _genesis()
    tampered = Envelope(
        payload=dict(envelope.payload) | {"issuedAt": "2030-01-01T00:00:00Z"},
        proofs=list(envelope.proofs),
    )

    bundle = EventBundle.from_envelopes([tampered])

    assert bundle.admitted == ()
    assert bundle.rejected[0].reason is ReasonCode.INVALID_SIGNATURE


def test_admission_order_is_independent_of_input_order() -> None:
    root = unsafe_signer(ROOT_A)
    genesis, lineage = _genesis()
    policies = [
        sign_payload(
            build_recovery_policy(
                lineage=lineage,
                epoch=0,
                policy_seq=1,
                members=[unsafe_signer(RECOVERY_1).did, unsafe_signer(RECOVERY_2).did],
                threshold=threshold,
                issued_at=AT,
            ),
            [root],
        )
        for threshold in (1, 2)
    ]
    events = [genesis, *policies]

    baseline = [event.event_id for event in EventBundle.from_envelopes(events).admitted]
    rng = random.Random(20260826)
    for _ in range(25):
        shuffled = events[:]
        rng.shuffle(shuffled)
        assert [e.event_id for e in EventBundle.from_envelopes(shuffled).admitted] == baseline
    assert baseline == sorted(baseline)


def test_lookup_helpers_scope_by_type_and_lineage() -> None:
    genesis_a, lineage_a = _genesis(ROOT_A)
    genesis_b, lineage_b = _genesis(ROOT_B)
    bundle = EventBundle.from_envelopes([genesis_a, genesis_b])

    assert bundle.lineages() == tuple(sorted((lineage_a, lineage_b)))
    assert [e.event_id for e in bundle.of_type("root.create", lineage=lineage_a)] == [
        genesis_a.event_id
    ]
    assert bundle.of_type("recovery.policy") == ()
    assert bundle.by_id(genesis_b.event_id) is not None
    assert bundle.by_id("sha256:" + "0" * 64) is None
    assert bundle.by_id(None) is None


def test_duplicate_copies_of_one_event_union_their_signers() -> None:
    """D-036: one event id is one payload, so its proofs accumulate."""
    envelope, _ = _genesis()
    extra_signer = unsafe_signer(RECOVERY_1)
    second_copy = Envelope(
        payload=dict(envelope.payload),
        proofs=[
            *envelope.proofs,
            Proof(
                alg="Ed25519",
                signer=extra_signer.did,
                sig=extra_signer.sign_b64u(envelope.signing_bytes),
            ),
        ],
    )

    bundle = EventBundle.from_envelopes([envelope, second_copy])
    reversed_bundle = EventBundle.from_envelopes([second_copy, envelope])

    assert len(bundle.admitted) == 1
    signers = bundle.admitted[0].verified_signers
    assert set(signers) == {unsafe_signer(ROOT_A).did, extra_signer.did}
    assert any("D-036" in warning for warning in bundle.warnings)
    # Merging is a union, so arrival order cannot change the outcome.
    assert signers == reversed_bundle.admitted[0].verified_signers


def test_a_keyless_attacker_cannot_strip_proofs_from_a_published_event() -> None:
    """Regression: selecting one copy let a third party suppress real proofs.

    Anyone who can see a published envelope can republish it with proofs
    removed. When admission *chose* between copies, the stripped copy could win
    and starve a recovery quorum below its threshold -- freezing a lineage at an
    epoch it had already left, with no private key involved anywhere.
    """
    root = unsafe_signer(ROOT_A)
    member = unsafe_signer(RECOVERY_1)
    payload = build_root_create(root_did=root.did, issued_at=AT)
    full = sign_payload(payload, [root, member])
    assert len(full.proofs) == 2

    # The attacker keeps whichever single proof suits them and drops the rest.
    for kept in (0, 1):
        stripped = Envelope(payload=dict(full.payload), proofs=[full.proofs[kept]])
        bundle = EventBundle.from_envelopes([full, stripped])
        admitted = bundle.admitted[0]
        assert admitted.distinct_signers() == {root.did, member.did}

    # Nor can they gain anything by publishing only the stripped copy alongside
    # a copy signed by themselves.
    outsider = unsafe_signer(OUTSIDER)
    forged = Envelope(
        payload=dict(full.payload),
        proofs=[
            Proof(
                alg="Ed25519",
                signer=outsider.did,
                sig=outsider.sign_b64u(full.signing_bytes),
            )
        ],
    )
    bundle = EventBundle.from_envelopes([full, forged])
    signers = bundle.admitted[0].distinct_signers()
    assert {root.did, member.did} <= signers
    # The forged proof is real -- the outsider does control that key -- so it is
    # retained. It buys nothing: the outsider is neither a root nor a policy
    # member, and every decision the resolver makes intersects against those.
    assert outsider.did in signers


def test_distinct_signers_collapses_repeats() -> None:
    root = unsafe_signer(ROOT_A)
    payload = build_root_create(root_did=root.did, issued_at=AT)
    envelope = sign_payload(payload, [root, root])

    admitted = EventBundle.from_envelopes([envelope]).admitted[0]

    # One key is one signer, whether it signed once or twice.
    assert admitted.verified_signers == (root.did,)
    assert admitted.distinct_signers() == frozenset({root.did})
    assert admitted.signed_by(root.did)
    assert admitted.get("nope") is None


def test_admitted_payload_does_not_alias_the_caller_s_envelope() -> None:
    """A bundle whose contents can change under the resolver is not a bundle."""
    root = unsafe_signer(ROOT_A)
    payload = build_root_create(root_did=root.did, issued_at=AT)
    payload["nested"] = {"members": ["a"]}
    envelope = sign_payload(payload, [root])

    admitted = EventBundle.from_envelopes([envelope]).admitted[0]
    payload["nested"]["members"].append("b")

    assert admitted.payload["nested"]["members"] == ["a"]
