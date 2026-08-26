"""Content-addressed, append-only storage for signed events.

`docs/21_DATABASE.md` draws the line this module sits on: the store holds the
authoritative objects, and everything downstream -- indexes, projections,
searches -- is derived and disposable. Delete the index and it can be rebuilt.
Delete the store and the events are gone.

Append-only is not a policy here, it is arithmetic. A file is named by the hash
of the payload it contains, so "overwriting" an event with different content
means writing a different file. Correction is a new event (D-018); there is no
update path because there is nowhere for one to write.

One subtlety carries over from D-036. An event id covers the *payload*, and
proofs live outside it, so two envelopes can share an id and carry different
signatures -- which is exactly what happens when a recovery quorum's members
sign separately. Storing whichever arrived first would let an observer suppress
proofs by racing a stripped copy into the store. `put` unions them instead.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Protocol

from lineageauth.canonical import EVENT_ID_RE, compute_event_id
from lineageauth.envelope import Envelope, Proof
from lineageauth.errors import LineageAuthError, MalformedEventError
from lineageauth.verify import verify_event


class StoreError(LineageAuthError):
    """The store could not satisfy a request."""


class EventStore(Protocol):
    """Where authoritative signed events live."""

    def put(self, envelope: Envelope) -> str:
        """Store an envelope and return its event id."""
        ...

    def get(self, event_id: str) -> Envelope | None:
        """Return the envelope for `event_id`, or None."""
        ...

    def __iter__(self) -> Iterator[Envelope]:
        """Iterate every stored envelope in a deterministic order."""
        ...


def canonical_document(envelope: Envelope) -> str:
    """Render an envelope for storage, deterministically.

    Sorted keys, sorted proofs, no insignificant whitespace. Two stores holding
    the same events then hold byte-identical files, which is what makes a
    backup diffable and a rebuild checkable. This is *not* the signing
    encoding -- signatures are over JCS of the payload alone, and nothing here
    changes that.
    """
    proofs = sorted(
        ({"alg": p.alg, "signer": p.signer, "sig": p.sig} for p in envelope.proofs),
        key=lambda p: (p["signer"], p["sig"], p["alg"]),
    )
    return json.dumps(
        {"payload": envelope.payload, "proofs": proofs},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def merge_proofs(left: Envelope, right: Envelope) -> Envelope:
    """Union the proofs of two envelopes sharing one payload (D-036)."""
    if compute_event_id(left.payload) != compute_event_id(right.payload):
        raise StoreError("refusing to merge envelopes with different payloads")
    seen: dict[tuple[str, str, str], Proof] = {}
    for proof in (*left.proofs, *right.proofs):
        seen.setdefault((proof.signer, proof.sig, proof.alg), proof)
    ordered = [seen[key] for key in sorted(seen)]
    return Envelope(payload=left.payload, proofs=ordered)


class FileEventStore:
    """An event store backed by a directory of immutable files.

    Layout mirrors the event id, sharded so a directory listing stays usable:

        <root>/sha256/<first two hex chars>/<remaining 62>.json

    No database, no daemon, no service. The whole store is a folder that can be
    copied, diffed, checksummed, and handed to someone else -- which is the
    property `CLAUDE.md` 2.7.2 is after when it says the protocol core must stay
    fully useful locally.
    """

    __slots__ = ("_root", "_verify")

    def __init__(self, root: str | Path, *, verify: bool = True) -> None:
        self._root = Path(root)
        # Verification on write is on by default. An event store that accepts
        # unverifiable events is a store whose contents cannot be trusted to
        # rebuild anything, and the cost is paid once per event rather than on
        # every read.
        self._verify = verify
        (self._root / "sha256").mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        return self._root

    def _path_for(self, event_id: str) -> Path:
        if EVENT_ID_RE.fullmatch(event_id) is None:
            raise MalformedEventError(f"not an event id: {event_id!r}")
        digest = event_id.removeprefix("sha256:")
        return self._root / "sha256" / digest[:2] / f"{digest[2:]}.json"

    def put(self, envelope: Envelope) -> str:
        """Store an envelope, unioning proofs with any copy already held."""
        if self._verify:
            result = verify_event(envelope)
            if not result.integrity_ok:
                raise StoreError(
                    f"refusing to store an event that does not verify: {result.reason} "
                    f"-- {result.detail}"
                )

        event_id = compute_event_id(envelope.payload)
        existing = self.get(event_id)
        if existing is not None:
            envelope = merge_proofs(existing, envelope)
            if canonical_document(envelope) == canonical_document(existing):
                return event_id

        path = self._path_for(event_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._write_atomic(path, canonical_document(envelope) + "\n")
        return event_id

    @staticmethod
    def _write_atomic(path: Path, text: str) -> None:
        """Write via a temporary file and a rename.

        A partially written event is worse than a missing one: it would fail to
        parse on the next rebuild and look like corruption rather than an
        interrupted write. `os.replace` is atomic on every platform this runs on.
        """
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=".tmp-",
            delete=False,
        )
        try:
            with handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, path)
        except BaseException:
            Path(handle.name).unlink(missing_ok=True)
            raise

    def get(self, event_id: str) -> Envelope | None:
        path = self._path_for(event_id)
        if not path.is_file():
            return None
        envelope = Envelope.from_json(path.read_text(encoding="utf-8"))
        stored_id = compute_event_id(envelope.payload)
        if stored_id != event_id:
            # The file's name and its contents disagree, so one of them is
            # wrong and there is no way to tell which. Refusing beats guessing.
            raise StoreError(
                f"stored event at {path} hashes to {stored_id}, not the {event_id} its "
                "filename claims"
            )
        return envelope

    def event_ids(self) -> tuple[str, ...]:
        """Every stored event id, sorted."""
        found: list[str] = []
        for shard in sorted((self._root / "sha256").iterdir()):
            if not shard.is_dir():
                continue
            for entry in sorted(shard.iterdir()):
                if entry.suffix == ".json" and not entry.name.startswith(".tmp-"):
                    found.append(f"sha256:{shard.name}{entry.stem}")
        return tuple(found)

    def __iter__(self) -> Iterator[Envelope]:
        for event_id in self.event_ids():
            envelope = self.get(event_id)
            if envelope is not None:
                yield envelope

    def __len__(self) -> int:
        return len(self.event_ids())

    def __contains__(self, event_id: object) -> bool:
        return isinstance(event_id, str) and self._path_for(event_id).is_file()

    def extend(self, envelopes: Iterable[Envelope]) -> tuple[str, ...]:
        """Store several envelopes, returning their ids in input order."""
        return tuple(self.put(envelope) for envelope in envelopes)


class MemoryEventStore:
    """An in-memory store with the same semantics. For tests and short-lived work."""

    __slots__ = ("_events",)

    def __init__(self) -> None:
        self._events: dict[str, Envelope] = {}

    def put(self, envelope: Envelope) -> str:
        result = verify_event(envelope)
        if not result.integrity_ok:
            raise StoreError(f"refusing to store an event that does not verify: {result.reason}")
        event_id = compute_event_id(envelope.payload)
        existing = self._events.get(event_id)
        self._events[event_id] = envelope if existing is None else merge_proofs(existing, envelope)
        return event_id

    def get(self, event_id: str) -> Envelope | None:
        return self._events.get(event_id)

    def event_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._events))

    def __iter__(self) -> Iterator[Envelope]:
        for event_id in self.event_ids():
            yield self._events[event_id]

    def __len__(self) -> int:
        return len(self._events)

    def __contains__(self, event_id: object) -> bool:
        return isinstance(event_id, str) and event_id in self._events
