"""The read-only importers.

Three of the directive's acceptance cases live here, because all three are
really about what an importer is allowed to conclude: volume is not work, a
third party is worth more than any amount of self-signing, and synthetic data
stays labelled forever.

Every adapter is driven without a network. The Technocore reader gets a
`MockTransport`, the local one gets a bundle built from unsafe test keys, and
the two file-backed adapters read files. A test suite that needed the internet
to check an importer would be checking the internet.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

from lineageauth.adapters.technocore import MockTransport, TechnocoreReader
from lineageauth.builders import (
    build_artifact_receipt,
    build_artifact_register,
    build_attestation,
    build_delegation_grant,
    build_profile_statement,
    build_root_create,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.flop.activity import (
    ActivitySubject,
    LocalEventsAdapter,
    MockAdapter,
    PublicEvidenceAdapter,
    TechnocoreAdapter,
    collect_activities,
)
from lineageauth.flop.model import (
    SYNTHETIC_BANNER,
    VOLUME_NOTE,
    ActivityCategory,
    EvidenceLevel,
    SourceClass,
    VerificationState,
)
from tests.testkeys import AGENT_1, OUTSIDER, ROOT_A, unsafe_signer

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
ORIGIN = "https://technocore.chat"

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
REVIEWER = unsafe_signer(OUTSIDER)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

SCOPE = {"namespace": "http", "resource": "host:technocore.chat", "actions": ["get"]}


def artifact_id(marker: str) -> str:
    return "sha256:" + hashlib.sha256(marker.encode("utf-8")).hexdigest()


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant() -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=AGENT.did,
            epoch=0,
            scopes=[SCOPE],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            approval="none",
            issued_at=AT,
        ),
        [ROOT],
    )


def register(marker: str, *, uri: str, at: datetime = AT) -> Envelope:
    return sign_payload(
        build_artifact_register(
            lineage=LINEAGE,
            artifact_id=artifact_id(marker),
            uri=uri,
            created_by=AGENT.did,
            issued_at=at,
        ),
        [AGENT],
    )


def receipt(marker: str, *, at: datetime = AT) -> Envelope:
    return sign_payload(
        build_artifact_receipt(
            lineage=LINEAGE,
            artifact_id=artifact_id(marker),
            worker=AGENT.did,
            issued_at=at,
        ),
        [AGENT],
    )


def attestation(marker: str, *, at: datetime = AT) -> Envelope:
    return sign_payload(
        build_attestation(
            lineage=LINEAGE,
            issuer=REVIEWER.did,
            subject_ref=artifact_id(marker),
            predicate="artifact.reproduced",
            value="reproduced from source",
            issued_at=at,
        ),
        [REVIEWER],
    )


def subject() -> ActivitySubject:
    return ActivitySubject(did=AGENT.did, lineage=LINEAGE, at=AT)


def bundle(*envelopes: Envelope) -> EventBundle:
    return EventBundle.from_envelopes([genesis(), grant(), *envelopes])


def room_body(sender: str, count: int) -> str:
    return json.dumps(
        {
            "room": "d-technocore-jp",
            "count": count,
            "messages": [
                {
                    "seq": index,
                    "ts": "2026-09-01T09:00:00.000000Z",
                    "from": sender,
                    "text": f"message {index}",
                }
                for index in range(1, count + 1)
            ],
        }
    )


class TestLocalEvents:
    def test_a_registered_artifact_is_cryptographically_linked(self) -> None:
        records = LocalEventsAdapter(bundle(register("a", uri="https://example/a"))).fetch(
            subject()
        )
        assert len(records) == 1
        assert records[0].evidence_level is EvidenceLevel.CRYPTOGRAPHICALLY_LINKED
        assert records[0].artifact_hash == artifact_id("a")

    def test_a_receipted_artifact_is_evidence_supported(self) -> None:
        records = LocalEventsAdapter(
            bundle(register("a", uri="https://example/a"), receipt("a"))
        ).fetch(subject())
        assert records[0].evidence_level is EvidenceLevel.EVIDENCE_SUPPORTED

    def test_acceptance_4_a_third_party_verification_is_surfaced_as_attested(self) -> None:
        """Acceptance test 4: one independently verified connector.

        The reviewer is a different key, and the attestation names an artifact
        this agent actually signed a receipt for. That combination -- and only
        that combination -- reaches `third-party-attested`.
        """
        records = LocalEventsAdapter(
            bundle(
                register("connector", uri="https://github.com/flop-labs/tclk/pull/1"),
                receipt("connector"),
                attestation("connector"),
            )
        ).fetch(subject())
        attested = [
            record
            for record in records
            if record.evidence_level is EvidenceLevel.THIRD_PARTY_ATTESTED
        ]
        assert len(attested) == 1
        assert attested[0].category is ActivityCategory.EXTERNAL_VERIFICATION
        assert attested[0].third_party_ref == REVIEWER.did
        assert attested[0].counterparties == (REVIEWER.did,)
        assert "not that it is correct" in attested[0].detail

    def test_an_attestation_about_someone_elses_artifact_is_not_borrowed(self) -> None:
        """The subject never registered this artifact, so it is not their evidence."""
        stranger_artifact = sign_payload(
            build_artifact_register(
                lineage=LINEAGE, artifact_id=artifact_id("theirs"), issued_at=AT
            ),
            [REVIEWER],
        )
        records = LocalEventsAdapter(bundle(stranger_artifact, attestation("theirs"))).fetch(
            subject()
        )
        assert records == ()

    def test_a_self_statement_stays_self_claimed(self) -> None:
        profile = sign_payload(
            build_profile_statement(
                lineage=LINEAGE,
                subject=AGENT.did,
                nickname="the official flop agent",
                issued_at=AT,
            ),
            [AGENT],
        )
        records = LocalEventsAdapter(bundle(profile)).fetch(subject())
        assert records[0].evidence_level is EvidenceLevel.SELF_CLAIMED
        assert records[0].verification_state is VerificationState.UNVERIFIED


class TestTechnocoreVolume:
    def reader(self, count: int, sender: str) -> TechnocoreReader:
        return TechnocoreReader(
            MockTransport({f"{ORIGIN}/r/d-technocore-jp?format=json": room_body(sender, count)})
        )

    def test_acceptance_3_five_hundred_messages_and_no_artifact_inflate_nothing(
        self,
    ) -> None:
        """Acceptance test 3: volume is visible, and it is not useful work.

        The number is kept -- hiding it would be its own dishonesty -- and the
        record that carries it is `secondary`, which `is_useful_work` refuses
        for any category.
        """
        adapter = TechnocoreAdapter(self.reader(500, AGENT.did), rooms=["d-technocore-jp"])
        collection = collect_activities([adapter], subject())

        volume = [
            record
            for record in collection.records
            if record.category is ActivityCategory.MESSAGE_VOLUME
        ]
        assert len(volume) == 1
        assert "500 messages" in volume[0].title
        assert volume[0].secondary is True
        assert volume[0].is_useful_work is False
        assert collection.useful_work == ()
        assert collection.to_dict()["usefulWorkCount"] == 0
        assert collection.to_dict()["volumeNote"] == VOLUME_NOTE

    def test_a_sender_label_never_raises_the_evidence_level(self) -> None:
        """The service authenticates nobody, so `from` is a label, not a name."""
        adapter = TechnocoreAdapter(self.reader(3, AGENT.did), rooms=["d-technocore-jp"])
        for record in adapter.fetch(subject()):
            assert record.evidence_level is EvidenceLevel.SELF_CLAIMED
            assert record.source_class is SourceClass.COMMUNITY

    def test_an_unreachable_room_becomes_a_warning_not_an_empty_console(self) -> None:
        adapter = TechnocoreAdapter(TechnocoreReader(MockTransport({})), rooms=["d-technocore-jp"])
        collection = collect_activities([adapter], subject())
        assert collection.records == ()

    def test_the_adapter_reads_only_the_rooms_it_was_given(self) -> None:
        transport = MockTransport(
            {f"{ORIGIN}/r/d-technocore-jp?format=json": room_body(AGENT.did, 1)}
        )
        TechnocoreAdapter(TechnocoreReader(transport), rooms=["d-technocore-jp"]).fetch(subject())
        assert transport.requested == [f"{ORIGIN}/r/d-technocore-jp?format=json"]


class TestPublicEvidence:
    def test_it_reads_the_shipped_file_for_its_own_subject(self) -> None:
        adapter = PublicEvidenceAdapter()
        assert adapter.subject_did is not None
        records = adapter.fetch(ActivitySubject(did=adapter.subject_did, lineage=LINEAGE, at=AT))
        assert len(records) >= 10

    def test_nothing_claims_to_have_been_verified_in_this_session(self) -> None:
        """The URL was recorded. Nobody went and looked, so nothing says verified."""
        adapter = PublicEvidenceAdapter()
        assert adapter.subject_did is not None
        for record in adapter.fetch(
            ActivitySubject(did=adapter.subject_did, lineage=LINEAGE, at=AT)
        ):
            assert record.verification_state is VerificationState.PARTIALLY_VERIFIED
            assert record.synthetic is False

    def test_a_third_party_citation_stops_short_of_attested(self) -> None:
        """A public comment is a citation. Only a signed attestation is one."""
        adapter = PublicEvidenceAdapter()
        assert adapter.subject_did is not None
        records = {
            record.record_id: record
            for record in adapter.fetch(
                ActivitySubject(did=adapter.subject_did, lineage=LINEAGE, at=AT)
            )
        }
        citation = records["public-evidence-pub-tclk-23-citation"]
        assert citation.evidence_level is EvidenceLevel.EVIDENCE_SUPPORTED
        assert citation.evidence_level is not EvidenceLevel.THIRD_PARTY_ATTESTED
        assert "a comment is a citation, not a signature" in citation.detail

    def test_it_returns_nothing_for_a_different_subject(self) -> None:
        assert PublicEvidenceAdapter().fetch(subject()) == ()


class TestMockDataStaysLabelled:
    def test_acceptance_7_every_mock_record_carries_the_synthetic_banner(self) -> None:
        """Acceptance test 7: loaded mock data is visibly mock data.

        The flag is forced by the adapter rather than read from the file, so a
        mock file edited to claim otherwise still produces labelled records.
        """
        records = MockAdapter().fetch(subject())
        assert records
        for record in records:
            assert record.synthetic is True
            assert record.to_dict()["banner"] == SYNTHETIC_BANNER

        collection = collect_activities([MockAdapter()], subject())
        assert collection.contains_synthetic is True
        assert collection.to_dict()["banner"] == SYNTHETIC_BANNER

    def test_the_shipped_mock_file_declares_itself_synthetic(self) -> None:
        from lineageauth.flop.activity import MOCK_ACTIVITY_FILE

        document = json.loads(MOCK_ACTIVITY_FILE.read_text(encoding="utf-8"))
        assert document["_meta"]["synthetic"] is True
        assert SYNTHETIC_BANNER in document["_meta"]["warning"]

    def test_real_and_synthetic_records_stay_distinguishable_when_merged(self) -> None:
        adapter = PublicEvidenceAdapter()
        assert adapter.subject_did is not None
        collection = collect_activities(
            [adapter, MockAdapter()],
            ActivitySubject(did=adapter.subject_did, lineage=LINEAGE, at=AT),
        )
        synthetic = {record.synthetic for record in collection.records}
        assert synthetic == {True, False}


class TestAdaptersAreReadOnly:
    def test_every_adapter_declares_itself_read_only(self) -> None:
        adapters = [
            LocalEventsAdapter(bundle()),
            TechnocoreAdapter(TechnocoreReader(MockTransport({}))),
            PublicEvidenceAdapter(),
            MockAdapter(),
        ]
        for adapter in adapters:
            assert adapter.read_only is True
            assert not hasattr(adapter, "post")
            assert not hasattr(adapter, "write")

    def test_collecting_is_deterministic(self) -> None:
        adapters = [LocalEventsAdapter(bundle(register("a", uri="https://example/a")))]
        first = collect_activities(adapters, subject())
        second = collect_activities(adapters, subject())
        assert [r.record_id for r in first.records] == [r.record_id for r in second.records]
