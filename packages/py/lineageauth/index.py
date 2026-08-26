"""A derived SQLite index over an event store.

`docs/21_DATABASE.md` opens with the only rule that matters here: the database
is derived, not authority. Nothing in this file may decide anything. It answers
"which events exist and how do I find them quickly", and every answer it gives
is a pointer back to a signed object that a verifier re-checks for itself.

The test of that claim is `rebuild`. Drop the file, rebuild from the store, and
the projections must come out identical -- `docs/25` asks for exactly this drill
as disaster recovery. If a rebuild could produce something different, the index
would be holding state nobody signed.

SQLite because `CLAUDE.md` 2.7.7 makes it the default and it costs nothing.
There is no server, no credential, and no key material anywhere in here: an
indexer never needs a private key, and `docs/25` requires that a public one
never hold one.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from lineageauth.bundle import EventBundle
from lineageauth.canonical import compute_event_id
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError
from lineageauth.store import EventStore, canonical_document
from lineageauth.verify import verify_event

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The ingest table. `document` is the canonical rendering of the whole
-- envelope, so an event can be handed back exactly as stored and re-verified
-- by the caller rather than trusted because it came from here.
CREATE TABLE IF NOT EXISTS events (
    event_id  TEXT PRIMARY KEY,
    type      TEXT NOT NULL,
    family    TEXT NOT NULL,
    lineage   TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    document  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS events_by_lineage ON events (lineage, type, event_id);
CREATE INDEX IF NOT EXISTS events_by_type ON events (type, event_id);

-- Which key signed which event. A projection of the proofs, useful for "what
-- has this DID signed" without reading every event. It attributes signatures,
-- never authority.
CREATE TABLE IF NOT EXISTS event_signers (
    event_id TEXT NOT NULL,
    signer   TEXT NOT NULL,
    PRIMARY KEY (event_id, signer),
    FOREIGN KEY (event_id) REFERENCES events (event_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS signers_by_did ON event_signers (signer, event_id);
"""


class IndexError_(LineageAuthError):
    """The index could not satisfy a request."""


class EventIndex:
    """A rebuildable, read-optimised view over an event store."""

    __slots__ = ("_connection", "_path")

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        # One connection for the object's lifetime. `:memory:` demands it -- a
        # second connect() to that name is a *different* empty database, so a
        # per-call connection would lose the schema between statements. Holding
        # it for file paths too keeps one code path instead of two, and an index
        # is a single-process read cache rather than a shared server.
        self._connection = sqlite3.connect(self._path)
        self._connection.execute("PRAGMA foreign_keys=ON")
        with self._cursor() as connection:
            connection.executescript(_SCHEMA)
            connection.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('version', ?)",
                (str(SCHEMA_VERSION),),
            )

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Connection]:
        yield self._connection
        self._connection.commit()

    def close(self) -> None:
        """Release the connection. The index is a cache; closing loses nothing."""
        self._connection.close()

    def __enter__(self) -> EventIndex:
        return self

    def __exit__(self, *exc: object) -> None:
        # Worth having rather than leaving to the garbage collector: holding the
        # connection for the object's lifetime keeps the file open, and on
        # Windows an open file cannot be deleted. An index nobody can clean up
        # is a poor kind of disposable.
        self.close()

    # ---------------------------------------------------------------- ingest

    def ingest(self, envelope: Envelope) -> str | None:
        """Index one envelope. Returns its id, or None when it does not verify.

        An event that fails verification is not indexed at all. It would only
        ever be handed back to a caller who then has to reject it, and an index
        that carries invalid events is one a reader has to distrust wholesale.
        """
        result = verify_event(envelope)
        if not result.integrity_ok:
            return None
        if result.event_id is None or result.event_type is None or result.lineage is None:
            return None  # pragma: no cover - verify_event guarantees these on a pass

        with self._cursor() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO events "
                "(event_id, type, family, lineage, issued_at, document) VALUES (?,?,?,?,?,?)",
                (
                    result.event_id,
                    result.event_type,
                    result.event_family or "",
                    result.lineage,
                    str(envelope.payload.get("issuedAt", "")),
                    canonical_document(envelope),
                ),
            )
            connection.execute("DELETE FROM event_signers WHERE event_id = ?", (result.event_id,))
            connection.executemany(
                "INSERT OR IGNORE INTO event_signers (event_id, signer) VALUES (?,?)",
                [(result.event_id, signer) for signer in sorted(set(result.verified_signers))],
            )
        return result.event_id

    def ingest_all(self, envelopes: Iterable[Envelope]) -> tuple[int, int]:
        """Index many envelopes. Returns (indexed, rejected)."""
        indexed = rejected = 0
        for envelope in envelopes:
            if self.ingest(envelope) is None:
                rejected += 1
            else:
                indexed += 1
        return indexed, rejected

    def rebuild(self, store: EventStore) -> tuple[int, int]:
        """Discard every projection and rebuild it from the store.

        The whole point of the index being derived is that this is always safe.
        If it is ever not, something in here is holding state that never came
        from a signed event.
        """
        with self._cursor() as connection:
            connection.execute("DELETE FROM event_signers")
            connection.execute("DELETE FROM events")
        return self.ingest_all(store)

    # ---------------------------------------------------------------- reads

    def get(self, event_id: str) -> Envelope | None:
        """Return one indexed envelope, exactly as stored."""
        with self._cursor() as connection:
            row = connection.execute(
                "SELECT document FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            return None
        envelope = Envelope.from_json(row[0])
        if compute_event_id(envelope.payload) != event_id:
            raise IndexError_(  # pragma: no cover - defensive
                f"indexed document for {event_id} does not hash to its key"
            )
        return envelope

    def envelopes(
        self, *, lineage: str | None = None, event_type: str | None = None
    ) -> tuple[Envelope, ...]:
        """Indexed envelopes, ordered by event id so results are reproducible.

        One fixed statement with optional filters, rather than assembling a
        WHERE clause. Building SQL by concatenation is safe *here* -- the
        fragments are literals and the values are bound -- but it is the shape
        of the mistake, and a query that never gets assembled cannot be
        assembled wrongly by the next person to add a filter.
        """
        with self._cursor() as connection:
            rows = connection.execute(
                "SELECT document FROM events "
                "WHERE (:lineage IS NULL OR lineage = :lineage) "
                "  AND (:event_type IS NULL OR type = :event_type) "
                "ORDER BY event_id",
                {"lineage": lineage, "event_type": event_type},
            ).fetchall()
        return tuple(Envelope.from_json(row[0]) for row in rows)

    def bundle(self, *, lineage: str | None = None) -> EventBundle:
        """Build an `EventBundle` for the resolver.

        The index has already verified everything it holds, but the bundle
        verifies again on admission. That is not waste: the resolver's guarantee
        is that it trusts nothing it did not check itself, and an index that
        could shortcut that would become authority by the back door.
        """
        return EventBundle.from_envelopes(self.envelopes(lineage=lineage))

    def lineages(self) -> tuple[str, ...]:
        with self._cursor() as connection:
            rows = connection.execute(
                "SELECT DISTINCT lineage FROM events ORDER BY lineage"
            ).fetchall()
        return tuple(row[0] for row in rows)

    def signed_by(self, did: str) -> tuple[str, ...]:
        """Event ids carrying a verifying proof from `did`.

        Signing is not authority. This says a key produced a signature, nothing
        about whether the signer was entitled to.
        """
        with self._cursor() as connection:
            rows = connection.execute(
                "SELECT event_id FROM event_signers WHERE signer = ? ORDER BY event_id", (did,)
            ).fetchall()
        return tuple(row[0] for row in rows)

    def counts_by_type(self) -> dict[str, int]:
        with self._cursor() as connection:
            rows = connection.execute(
                "SELECT type, COUNT(*) FROM events GROUP BY type ORDER BY type"
            ).fetchall()
        return {row[0]: row[1] for row in rows}

    def __len__(self) -> int:
        with self._cursor() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    # ---------------------------------------------------------------- checks

    def checksum(self) -> str:
        """A digest of every projection this index holds.

        For the rebuild drill in `docs/25`: index, checksum, rebuild, checksum
        again. Equal digests mean the projections really are a pure function of
        the events, which is the claim that lets an operator throw the database
        away without losing anything.
        """
        digest = hashlib.sha256()
        with self._cursor() as connection:
            for row in connection.execute(
                "SELECT event_id, type, family, lineage, issued_at, document "
                "FROM events ORDER BY event_id"
            ):
                digest.update(json.dumps(row, sort_keys=True).encode())
            for row in connection.execute(
                "SELECT event_id, signer FROM event_signers ORDER BY event_id, signer"
            ):
                digest.update(json.dumps(row, sort_keys=True).encode())
        return "sha256:" + digest.hexdigest()
