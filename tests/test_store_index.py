"""The event store and the derived index.

docs/21: the database is derived, not authority. docs/25 turns that into a
drill -- rebuild from an empty database and compare projections. If a rebuild
can produce something different, the index is holding state nobody signed, and
these tests are where that would show up.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from lineageauth.builders import (
    build_delegation_grant,
    build_recovery_policy,
    build_root_create,
    sign_payload,
)
from lineageauth.envelope import Envelope, Proof
from lineageauth.index import EventIndex
from lineageauth.lineage import resolve_lineage
from lineageauth.store import (
    FileEventStore,
    MemoryEventStore,
    StoreError,
    canonical_document,
    merge_proofs,
)
from tests.testkeys import (
    AGENT_1,
    OUTSIDER,
    RECOVERY_1,
    RECOVERY_2,
    RECOVERY_3,
    ROOT_A,
    unsafe_signer,
)

AT = datetime(2026, 8, 26, 9, 0, 0, tzinfo=UTC)
ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
STRANGER = unsafe_signer(OUTSIDER)
MEMBERS = [unsafe_signer(n) for n in (RECOVERY_1, RECOVERY_2, RECOVERY_3)]
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def policy() -> Envelope:
    return sign_payload(
        build_recovery_policy(
            lineage=LINEAGE,
            epoch=0,
            policy_seq=1,
            members=[m.did for m in MEMBERS],
            threshold=2,
            issued_at=AT,
        ),
        [ROOT],
    )


def grant() -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=AGENT.did,
            epoch=0,
            scopes=[
                {"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "write"]}
            ],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            issued_at=AT,
        ),
        [ROOT],
    )


def sample() -> list[Envelope]:
    return [genesis(), policy(), grant()]


# ------------------------------------------------------------------ the store


class TestFileEventStore:
    def test_it_round_trips_an_event(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path)
        event = genesis()
        event_id = store.put(event)
        assert store.get(event_id) is not None
        assert store.get(event_id).payload == event.payload  # type: ignore[union-attr]

    def test_the_file_is_named_by_the_content_hash(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path)
        event_id = store.put(genesis())
        digest = event_id.removeprefix("sha256:")
        assert (tmp_path / "sha256" / digest[:2] / f"{digest[2:]}.json").is_file()

    def test_storing_twice_is_idempotent(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path)
        event = genesis()
        assert store.put(event) == store.put(event)
        assert len(store) == 1

    def test_it_refuses_an_event_that_does_not_verify(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path)
        good = genesis()
        tampered = Envelope(payload=dict(good.payload) | {"epoch": 1}, proofs=list(good.proofs))
        with pytest.raises(StoreError, match="does not verify"):
            store.put(tampered)
        assert len(store) == 0

    def test_proofs_from_separate_copies_are_unioned(self, tmp_path: Path) -> None:
        """D-036 again: storing one copy must not discard another's signatures.

        A quorum whose members sign separately arrives as several envelopes with
        one id. Keeping whichever landed first would let an observer suppress
        proofs by racing a stripped copy in.
        """
        store = FileEventStore(tmp_path)
        payload = build_root_create(root_did=ROOT.did, issued_at=AT)
        store.put(sign_payload(payload, [ROOT]))
        event_id = store.put(sign_payload(payload, [MEMBERS[0]]))

        held = store.get(event_id)
        assert held is not None
        assert {p.signer for p in held.proofs} == {ROOT.did, MEMBERS[0].did}

    def test_the_union_does_not_depend_on_arrival_order(self, tmp_path: Path) -> None:
        payload = build_root_create(root_did=ROOT.did, issued_at=AT)
        first, second = tmp_path / "a", tmp_path / "b"
        one, two = FileEventStore(first), FileEventStore(second)
        one.put(sign_payload(payload, [ROOT]))
        one.put(sign_payload(payload, [MEMBERS[0]]))
        two.put(sign_payload(payload, [MEMBERS[0]]))
        two.put(sign_payload(payload, [ROOT]))

        assert canonical_document(next(iter(one))) == canonical_document(next(iter(two)))

    def test_stored_bytes_are_deterministic(self, tmp_path: Path) -> None:
        # Two stores holding the same events hold byte-identical files, which is
        # what makes a backup diffable and a rebuild checkable.
        one, two = FileEventStore(tmp_path / "a"), FileEventStore(tmp_path / "b")
        for event in sample():
            one.put(event)
        for event in reversed(sample()):
            two.put(event)
        assert [canonical_document(e) for e in one] == [canonical_document(e) for e in two]

    def test_iteration_is_ordered_by_event_id(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path)
        store.extend(sample())
        ids = [event_id for event_id in store.event_ids()]
        assert ids == sorted(ids)

    def test_a_file_whose_name_disagrees_with_its_contents_is_refused(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path)
        event_id = store.put(genesis())
        digest = event_id.removeprefix("sha256:")
        path = tmp_path / "sha256" / digest[:2] / f"{digest[2:]}.json"
        path.write_text(canonical_document(policy()), encoding="utf-8")

        # One of the name and the contents is wrong and there is no way to tell
        # which, so refusing beats guessing.
        with pytest.raises(StoreError, match="its filename claims"):
            store.get(event_id)

    def test_a_partial_write_leaves_no_temporary_file_behind(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path)
        store.extend(sample())
        assert not list(tmp_path.rglob(".tmp-*"))

    def test_a_store_reopened_from_disk_sees_the_same_events(self, tmp_path: Path) -> None:
        FileEventStore(tmp_path).extend(sample())
        assert len(FileEventStore(tmp_path)) == 3

    def test_merging_different_payloads_is_refused(self) -> None:
        with pytest.raises(StoreError, match="different payloads"):
            merge_proofs(genesis(), policy())


class TestMemoryEventStore:
    def test_it_behaves_like_the_file_store(self) -> None:
        store = MemoryEventStore()
        event_id = store.put(genesis())
        assert event_id in store
        assert len(store) == 1
        assert store.get(event_id) is not None

    def test_it_unions_proofs_too(self) -> None:
        store = MemoryEventStore()
        payload = build_root_create(root_did=ROOT.did, issued_at=AT)
        store.put(sign_payload(payload, [ROOT]))
        event_id = store.put(sign_payload(payload, [MEMBERS[0]]))
        held = store.get(event_id)
        assert held is not None
        assert len(held.proofs) == 2


# ------------------------------------------------------------------ the index


class TestIndex:
    def test_it_indexes_and_returns_events_unchanged(self) -> None:
        index = EventIndex()
        event = genesis()
        event_id = index.ingest(event)
        assert event_id is not None
        assert index.get(event_id).payload == event.payload  # type: ignore[union-attr]

    def test_an_event_that_does_not_verify_is_not_indexed(self) -> None:
        index = EventIndex()
        good = genesis()
        tampered = Envelope(payload=dict(good.payload) | {"epoch": 9}, proofs=list(good.proofs))
        assert index.ingest(tampered) is None
        assert len(index) == 0

    def test_queries_are_ordered_and_reproducible(self) -> None:
        index = EventIndex()
        index.ingest_all(sample())
        first = [e.event_id for e in index.envelopes(lineage=LINEAGE)]
        assert first == sorted(first)
        assert first == [e.event_id for e in index.envelopes(lineage=LINEAGE)]

    def test_it_filters_by_type(self) -> None:
        index = EventIndex()
        index.ingest_all(sample())
        assert len(index.envelopes(event_type="root.create")) == 1
        assert index.counts_by_type()["delegation.grant"] == 1

    def test_signed_by_attributes_signatures_not_authority(self) -> None:
        index = EventIndex()
        index.ingest_all(sample())
        assert len(index.signed_by(ROOT.did)) == 3
        assert index.signed_by(STRANGER.did) == ()

    def test_it_produces_a_bundle_the_resolver_accepts(self) -> None:
        index = EventIndex()
        index.ingest_all(sample())
        state = resolve_lineage(index.bundle(lineage=LINEAGE), lineage=LINEAGE, at=AT)
        assert state.resolved
        assert state.root == ROOT.did

    def test_lineages_are_listed(self) -> None:
        index = EventIndex()
        index.ingest_all(sample())
        assert index.lineages() == (LINEAGE,)


class TestRebuildDrill:
    """docs/25: empty the database, rebuild from events, compare projections."""

    def test_a_rebuild_reproduces_every_projection(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path / "events")
        store.extend(sample())

        index = EventIndex(tmp_path / "index.sqlite")
        index.ingest_all(store)
        before = index.checksum()

        assert index.rebuild(store) == (3, 0)
        assert index.checksum() == before

    def test_a_fresh_database_rebuilds_to_the_same_checksum(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path / "events")
        store.extend(sample())

        one = EventIndex(tmp_path / "one.sqlite")
        one.ingest_all(store)

        two = EventIndex(tmp_path / "two.sqlite")
        two.rebuild(store)

        assert one.checksum() == two.checksum()

    def test_ingest_order_does_not_change_the_checksum(self) -> None:
        one, two = EventIndex(), EventIndex()
        one.ingest_all(sample())
        two.ingest_all(reversed(sample()))
        assert one.checksum() == two.checksum()

    def test_rebuilding_drops_events_no_longer_in_the_store(self, tmp_path: Path) -> None:
        store = FileEventStore(tmp_path / "events")
        store.put(genesis())

        index = EventIndex(tmp_path / "index.sqlite")
        index.ingest_all(sample())  # more than the store holds
        assert len(index) == 3

        # The store is authority; the index follows it, never the other way.
        index.rebuild(store)
        assert len(index) == 1

    def test_the_index_holds_no_key_material(self, tmp_path: Path) -> None:
        # docs/25: a public indexer must never need or hold a private key.
        store = FileEventStore(tmp_path / "events")
        store.extend(sample())
        index = EventIndex(tmp_path / "index.sqlite")
        index.rebuild(store)

        blob = (tmp_path / "index.sqlite").read_bytes()
        # Public DIDs are expected to be in there -- that is what an index is
        # for. What must never appear is anything that could sign.
        assert ROOT.did.encode() in blob
        assert b"PRIVATE KEY" not in blob
        assert b"-----BEGIN" not in blob
        from tests.testkeys import unsafe_seed

        for label in (ROOT_A, AGENT_1, OUTSIDER):
            assert unsafe_seed(label) not in blob


class TestIndexIsNotAuthority:
    def test_a_forged_proof_cannot_enter_through_the_index(self) -> None:
        index = EventIndex()
        good = genesis()
        forged = Envelope(
            payload=good.payload,
            proofs=[Proof(alg="Ed25519", signer=STRANGER.did, sig=good.proofs[0].sig)],
        )
        assert index.ingest(forged) is None

    def test_the_bundle_verifies_again_rather_than_trusting_the_index(self) -> None:
        # The resolver's guarantee is that it checks everything itself. An index
        # that could shortcut that would become authority by the back door.
        index = EventIndex()
        index.ingest_all(sample())
        bundle = index.bundle(lineage=LINEAGE)
        assert len(bundle.admitted) == 3
        assert bundle.rejected == ()


class TestIndexLifecycle:
    def test_it_works_as_a_context_manager(self, tmp_path: Path) -> None:
        path = tmp_path / "index.sqlite"
        with EventIndex(path) as index:
            index.ingest_all(sample())
            assert len(index) == 3
        # Closed, so the file can be removed. Holding the connection for the
        # object's lifetime keeps it open, and on Windows an open file cannot be
        # deleted -- an index nobody can clean up is a poor kind of disposable.
        path.unlink()

    def test_reopening_a_file_index_sees_what_was_written(self, tmp_path: Path) -> None:
        path = tmp_path / "index.sqlite"
        with EventIndex(path) as index:
            index.ingest_all(sample())
            checksum = index.checksum()
        with EventIndex(path) as reopened:
            assert len(reopened) == 3
            assert reopened.checksum() == checksum


class TestIndexConcurrency:
    def test_it_can_be_read_from_several_threads(self, tmp_path: Path) -> None:
        """An index behind an HTTP API is read from worker threads.

        sqlite3 binds a connection to its creating thread by default, so this is
        the case that caught the first version of the design out.
        """
        import threading

        with EventIndex(tmp_path / "index.sqlite") as index:
            index.ingest_all(sample())
            results: list[int] = []
            errors: list[BaseException] = []
            lock = threading.Lock()

            def read() -> None:
                try:
                    count = len(index.envelopes(lineage=LINEAGE))
                    with lock:
                        results.append(count)
                except BaseException as exc:
                    with lock:
                        errors.append(exc)

            threads = [threading.Thread(target=read) for _ in range(12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            assert errors == []
            assert results == [3] * 12

    def test_a_rebuild_running_alongside_reads_stays_consistent(self, tmp_path: Path) -> None:
        import threading

        store = FileEventStore(tmp_path / "events")
        store.extend(sample())

        with EventIndex(tmp_path / "index.sqlite") as index:
            index.ingest_all(store)
            seen: list[int] = []
            errors: list[BaseException] = []
            lock = threading.Lock()

            def read() -> None:
                try:
                    for _ in range(20):
                        count = len(index)
                        with lock:
                            seen.append(count)
                except BaseException as exc:
                    with lock:
                        errors.append(exc)

            def rebuild() -> None:
                try:
                    for _ in range(5):
                        index.rebuild(store)
                except BaseException as exc:
                    with lock:
                        errors.append(exc)

            threads = [threading.Thread(target=read) for _ in range(4)]
            threads.append(threading.Thread(target=rebuild))
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            assert errors == []
            # A reader never observes a half-rebuilt index. This is the whole
            # reason `rebuild` is one transaction: a permission check computed
            # against a partially repopulated index could come out ALLOW because
            # the revocation had not been reinserted yet.
            assert set(seen) == {3}
            assert len(index) == 3
