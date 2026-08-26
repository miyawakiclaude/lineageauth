"""Artifacts, receipts, and attestations.

docs/23_TESTING.md pins three properties for this layer: changed bytes change
the id, an attestation's signature proves only its issuer, and a receipt can
verify while the content itself is unavailable.

The rest is about categories staying apart. `docs/09` requires that a
self-asserted claim, a signed claim, and a third-party opinion never merge into
one unlabelled truth -- and a passport can only present what this layer hands
it, so the separation has to hold here or nowhere.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.actions import sha256_hex
from lineageauth.builders import (
    build_artifact_receipt,
    build_artifact_register,
    build_attestation,
    build_delegation_grant,
    build_delegation_revoke,
    build_root_create,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError, ReasonCode
from lineageauth.evidence import (
    KNOWN_PREDICATES,
    check_receipt_authority,
    collect_evidence,
    read_artifact,
    read_attestation,
)
from tests.testkeys import (
    AGENT_1,
    OUTSIDER,
    RECOVERY_1,
    RECOVERY_2,
    ROOT_A,
    unsafe_signer,
)

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
WORKER = unsafe_signer(AGENT_1)
REVIEWER = unsafe_signer(RECOVERY_1)
REVIEWER_2 = unsafe_signer(RECOVERY_2)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

CONTENT = b"# Awesome Technocore\n\nA curated list.\n"
ARTIFACT = sha256_hex(CONTENT)

SCOPE = {"namespace": "github", "resource": "repo:owner/list", "actions": ["commit"]}


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, subject: LocalSigner = WORKER) -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=subject.did,
            epoch=0,
            scopes=[SCOPE],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            issued_at=AT,
        ),
        [ROOT],
    )


def register(
    *,
    created_by: LocalSigner | None = WORKER,
    signers: list[LocalSigner] | None = None,
    uri: str | None = None,
    artifact_id: str = ARTIFACT,
) -> Envelope:
    payload = build_artifact_register(
        lineage=LINEAGE,
        artifact_id=artifact_id,
        media_type="text/markdown",
        byte_length=len(CONTENT),
        uri=uri,
        created_by=created_by.did if created_by else None,
        issued_at=AT,
    )
    return sign_payload(payload, signers or [WORKER])


def receipt(
    *,
    worker: LocalSigner = WORKER,
    authority_refs: list[str] | None = None,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_artifact_receipt(
        lineage=LINEAGE,
        artifact_id=ARTIFACT,
        worker=worker.did,
        authority_refs=authority_refs,
        issued_at=AT,
    )
    return sign_payload(payload, signers or [worker])


def attest(
    *,
    issuer: LocalSigner = REVIEWER,
    subject: str = ARTIFACT,
    predicate: str = "artifact.reviewed",
    expires_at: datetime | None = None,
    signers: list[LocalSigner] | None = None,
) -> Envelope:
    payload = build_attestation(
        lineage=LINEAGE,
        issuer=issuer.did,
        subject_ref=subject,
        predicate=predicate,
        value="looks correct",
        expires_at=expires_at,
        issued_at=AT,
    )
    return sign_payload(payload, signers or [issuer])


def evidence_of(*envelopes: Envelope):
    return collect_evidence(
        EventBundle.from_envelopes(envelopes), lineage=LINEAGE, artifact_id=ARTIFACT
    )


# ------------------------------------------------------------ artifact identity


class TestArtifactIdentity:
    def test_changed_bytes_change_the_id(self) -> None:
        assert sha256_hex(CONTENT) != sha256_hex(CONTENT + b" ")

    def test_the_id_must_be_a_content_hash(self) -> None:
        with pytest.raises(MalformedEventError, match="content hash"):
            build_artifact_register(lineage=LINEAGE, artifact_id="not-a-hash", issued_at=AT)

    def test_an_artifact_may_have_no_uri_at_all(self) -> None:
        """A hash binds bytes nobody hosts. Private content is a normal case."""
        found = evidence_of(register(uri=None))
        assert found.registrations[0].uri is None
        assert found.registrations[0].artifact_id == ARTIFACT

    def test_a_hash_is_never_a_promise_of_availability(self) -> None:
        # There is no "available" field to be wrong about, and the note says so.
        found = evidence_of(register())
        assert "not a promise that anyone hosts" in found.note

    def test_a_uri_may_not_carry_control_characters(self) -> None:
        payload = build_artifact_register(
            lineage=LINEAGE,
            artifact_id=ARTIFACT,
            uri="https://good.example\x1b[2K\rhttps://evil.example",
            issued_at=AT,
        )
        event = EventBundle.from_envelopes([sign_payload(payload, [WORKER])]).admitted[0]
        assert isinstance(read_artifact(event), str)


# ------------------------------------------------------------ claims stay apart


class TestClaimsStayApart:
    def test_a_creator_field_alone_is_self_asserted(self) -> None:
        """Anyone may register an artifact and name anyone as its creator."""
        found = evidence_of(register(created_by=WORKER, signers=[STRANGER]))
        assert found.self_asserted_creators == (WORKER.did,)
        assert found.signed_producers == ()

    def test_a_creator_who_signed_the_registration_is_not_self_asserted(self) -> None:
        found = evidence_of(register(created_by=WORKER, signers=[WORKER]))
        assert found.self_asserted_creators == ()

    def test_a_receipt_signed_by_the_worker_is_a_signed_claim(self) -> None:
        found = evidence_of(register(), receipt())
        assert found.signed_producers == (WORKER.did,)

    def test_a_receipt_naming_a_worker_who_did_not_sign_is_ignored(self) -> None:
        # Otherwise anyone could mint a receipt borrowing someone else's name.
        found = evidence_of(register(), receipt(worker=WORKER, signers=[STRANGER]))
        assert found.receipts == ()
        assert any("not signed by the worker" in w for w in found.warnings)

    def test_a_signed_producer_claim_is_still_not_evidence_of_quality(self) -> None:
        found = evidence_of(register(), receipt())
        assert "not that the artifact is correct" in found.note


# ------------------------------------------------------------ attestations


class TestAttestations:
    def test_an_attestation_proves_only_its_issuer(self) -> None:
        """docs/23: the signature says who signed, not that they are right."""
        found = evidence_of(register(), attest(issuer=REVIEWER))
        assert found.attestations[0].issuer == REVIEWER.did
        assert found.attestations[0].value == "looks correct"
        # There is no field claiming the assessment is correct.
        assert not hasattr(found.attestations[0], "correct")

    def test_one_key_attesting_repeatedly_is_one_attester(self) -> None:
        """Counting rows would let a single key manufacture a consensus."""
        found = evidence_of(
            register(),
            attest(issuer=REVIEWER, predicate="artifact.reviewed"),
            attest(issuer=REVIEWER, predicate="artifact.reproduced"),
        )
        assert len(found.attestations) == 2
        assert found.independent_attesters(at=AT) == (REVIEWER.did,)

    def test_distinct_keys_count_separately(self) -> None:
        found = evidence_of(register(), attest(issuer=REVIEWER), attest(issuer=REVIEWER_2))
        assert len(found.independent_attesters(at=AT)) == 2

    def test_a_caller_may_exclude_the_producers(self) -> None:
        # An author attesting to their own work is not independent. The caller
        # decides that, because this layer does not rank anything.
        found = evidence_of(register(), receipt(), attest(issuer=WORKER))
        assert found.independent_attesters(at=AT) == (WORKER.did,)
        assert found.independent_attesters(at=AT, exclude=frozenset(found.signed_producers)) == ()

    def test_an_expired_attestation_stops_counting(self) -> None:
        found = evidence_of(register(), attest(issuer=REVIEWER, expires_at=AT + timedelta(hours=1)))
        assert found.independent_attesters(at=AT) == (REVIEWER.did,)
        assert found.independent_attesters(at=AT + timedelta(days=1)) == ()

    def test_an_attestation_not_signed_by_its_issuer_is_ignored(self) -> None:
        found = evidence_of(register(), attest(issuer=REVIEWER, signers=[STRANGER]))
        assert found.attestations == ()
        assert any("not signed by its declared issuer" in w for w in found.warnings)

    def test_an_unknown_predicate_is_kept_but_marked(self) -> None:
        """docs/07: displayable, but it may not silently take effect."""
        found = evidence_of(register(), attest(predicate="is.definitely.trustworthy"))
        assert len(found.attestations) == 1
        assert not found.attestations[0].predicate_is_known
        assert found.has_unknown_predicates

    def test_the_known_predicates_are_the_documented_set(self) -> None:
        assert "result.accepted" in KNOWN_PREDICATES
        assert "security.finding.confirmed" in KNOWN_PREDICATES
        # Nothing in the registry reads as a verdict about a person.
        assert not any("trust" in p for p in KNOWN_PREDICATES)

    def test_an_attestation_about_the_receipt_is_collected_too(self) -> None:
        signed = receipt()
        found = evidence_of(register(), signed, attest(subject=signed.event_id))
        assert len(found.attestations) == 1

    def test_an_attestation_about_something_else_is_not(self) -> None:
        other = sha256_hex(b"different bytes")
        found = evidence_of(register(), attest(subject=other))
        assert found.attestations == ()


# ------------------------------------------------------------ authority


class TestReceiptAuthority:
    def _check(self, *envelopes: Envelope, at: datetime = AT):
        bundle = EventBundle.from_envelopes(envelopes)
        found = collect_evidence(bundle, lineage=LINEAGE, artifact_id=ARTIFACT)
        return check_receipt_authority(bundle, lineage=LINEAGE, receipt=found.receipts[0], at=at)

    def test_a_receipt_citing_a_live_grant_is_supported(self) -> None:
        held = grant()
        result = self._check(genesis(), held, register(), receipt(authority_refs=[held.event_id]))
        assert result.supported
        assert result.reason is ReasonCode.VALID_AUTHORITY_CHAIN
        # And it says what it does not mean.
        assert "not that the work is correct" in result.detail

    def test_a_receipt_citing_a_revoked_grant_is_not(self) -> None:
        held = grant()
        revocation = sign_payload(
            build_delegation_revoke(
                lineage=LINEAGE, issuer=ROOT.did, grant=held.event_id, issued_at=AT
            ),
            [ROOT],
        )
        result = self._check(
            genesis(), held, revocation, register(), receipt(authority_refs=[held.event_id])
        )
        assert not result.supported
        assert result.reason is ReasonCode.REVOKED

    def test_a_receipt_citing_a_grant_held_by_someone_else_is_not(self) -> None:
        # Citing a grant is not the same as holding it.
        other = grant(subject=REVIEWER)
        result = self._check(genesis(), other, register(), receipt(authority_refs=[other.event_id]))
        assert not result.supported
        assert result.reason is ReasonCode.DENIED
        assert "not to the worker" in result.detail

    def test_a_receipt_citing_an_absent_grant_is_unresolved(self) -> None:
        result = self._check(genesis(), register(), receipt(authority_refs=["sha256:" + "a" * 64]))
        assert not result.supported
        assert result.reason is ReasonCode.UNRESOLVED_PARENT

    def test_a_receipt_citing_nothing_remains_a_signed_claim(self) -> None:
        # It is not an error to claim authorship without citing authority.
        result = self._check(genesis(), register(), receipt())
        assert not result.supported
        assert "remains a signed claim of authorship" in result.detail

    def test_an_unsupported_citation_never_reads_as_supported(self) -> None:
        held = grant()
        expired = self._check(
            genesis(),
            held,
            register(),
            receipt(authority_refs=[held.event_id]),
            at=AT + timedelta(days=365),
        )
        assert not expired.supported


# ------------------------------------------------------------ collection


class TestCollection:
    def test_it_is_deterministic_under_input_order(self) -> None:
        import itertools

        events = [register(), receipt(), attest()]
        results = {
            str(
                collect_evidence(
                    EventBundle.from_envelopes(order), lineage=LINEAGE, artifact_id=ARTIFACT
                )
            )
            for order in itertools.permutations(events)
        }
        assert len(results) == 1

    def test_claims_without_a_registration_are_reported_not_dropped(self) -> None:
        found = evidence_of(receipt(), attest())
        assert found.registrations == ()
        assert found.receipts
        assert any("no artifact.register" in w for w in found.warnings)

    def test_a_different_artifact_is_not_collected(self) -> None:
        other = sha256_hex(b"other")
        found = evidence_of(register(artifact_id=other))
        assert found.registrations == ()

    def test_a_malformed_artifact_id_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="sha256"):
            collect_evidence(EventBundle.from_envelopes([]), lineage=LINEAGE, artifact_id="nope")

    def test_an_attestation_with_a_bad_expiry_is_ignored(self) -> None:
        payload = build_attestation(
            lineage=LINEAGE,
            issuer=REVIEWER.did,
            subject_ref=ARTIFACT,
            predicate="artifact.reviewed",
            issued_at=AT,
        )
        payload["expiresAt"] = "not-a-time"
        event = EventBundle.from_envelopes([sign_payload(payload, [REVIEWER])]).admitted[0]
        assert isinstance(read_attestation(event), str)


class TestBuilderRules:
    def test_an_attestation_may_not_expire_before_it_is_issued(self) -> None:
        with pytest.raises(MalformedEventError, match="after issuedAt"):
            build_attestation(
                lineage=LINEAGE,
                issuer=REVIEWER.did,
                subject_ref=ARTIFACT,
                predicate="artifact.reviewed",
                expires_at=AT - timedelta(hours=1),
                issued_at=AT,
            )

    def test_a_negative_byte_length_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="negative"):
            build_artifact_register(
                lineage=LINEAGE, artifact_id=ARTIFACT, byte_length=-1, issued_at=AT
            )

    def test_references_must_be_content_ids(self) -> None:
        with pytest.raises(MalformedEventError, match="sourceRef"):
            build_artifact_register(
                lineage=LINEAGE,
                artifact_id=ARTIFACT,
                source_refs=["../etc/passwd"],
                issued_at=AT,
            )
        with pytest.raises(MalformedEventError, match="authorityRef"):
            build_artifact_receipt(
                lineage=LINEAGE,
                artifact_id=ARTIFACT,
                worker=WORKER.did,
                authority_refs=["nope"],
                issued_at=AT,
            )

    def test_an_unregistered_predicate_may_still_be_drafted(self) -> None:
        # Refusing to let anyone express a new kind of claim would be the wrong
        # failure. It just must never take effect.
        payload = build_attestation(
            lineage=LINEAGE,
            issuer=REVIEWER.did,
            subject_ref=ARTIFACT,
            predicate="something.new",
            issued_at=AT,
        )
        assert payload["predicate"] == "something.new"
