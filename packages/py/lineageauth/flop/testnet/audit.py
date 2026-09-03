"""An append-only local log where each line commits to the one before it.

Every line carries `prev`, the previous line's `hash`, and its own `hash` over
the canonical bytes of everything else. Removing or editing a line breaks the
chain from that point on, so `verify_chain` reports *where* the log stopped
adding up rather than a bare false -- an operator who has to explain a gap needs
the position, not the verdict.

This is a local record, not evidence. It is not signed, it is not an event, and
nothing in the protocol reads it. It exists so that a person can reconstruct
what this tool did and in what order, which is directive 31.

The chain is not tamper-evident against anyone who can write the file. There is
no key in it, so an editor who changes a line can recompute every hash after it
and `verify_chain` will agree. What the chain catches is a line removed, a line
reordered and a file truncated part-way -- accidents and crashes, not an
adversary with write access. Calling this "tamper detection" in a UI would be a
claim the construction cannot support; the day one is needed, the chain head is
what would get signed as a LineageAuth event.

Secrets never enter it. `client.redact` runs over every string on the way in,
and keys whose names look like secrets are dropped entirely rather than
redacted, because a log line that records `"seed": "[REDACTED]"` still records
that a seed was handled here, and this tool handles none.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from lineageauth import jsonio
from lineageauth.canonical import jcs
from lineageauth.errors import MalformedEventError
from lineageauth.flop.testnet.client import redact
from lineageauth.timeutil import format_instant

# Enough to hold the last line of any log this tool writes.
_TAIL_WINDOW_BYTES = 65_536

AUDIT_PROFILE = "flop.testnet.audit/0.1"

GENESIS_HASH = "sha256:" + "0" * 64

# Names whose values this tool never has and never wants recorded. Dropped,
# not masked: masking documents that the field existed.
_FORBIDDEN_KEYS = frozenset(
    {
        "seed",
        "mnemonic",
        "privatekey",
        "private_key",
        "secretkey",
        "secret_key",
        "secret",
        "passphrase",
        "password",
        "authorization",
        "cookie",
        "token",
        "apikey",
        "api_key",
        "signature",
    }
)


def _clean(value: Any) -> Any:
    """Recursively drop forbidden keys and redact secret-shaped strings."""
    if isinstance(value, Mapping):
        return {
            str(key): _clean(item)
            for key, item in value.items()
            if str(key).lower().replace("-", "_") not in _FORBIDDEN_KEYS
        }
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, bytes):
        return f"sha256:{hashlib.sha256(value).hexdigest()}"
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [_clean(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class AuditLine:
    """One recorded step, and the hash that ties it to its predecessor."""

    seq: int
    at: str
    kind: str
    prev: str
    hash: str
    entry: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": AUDIT_PROFILE,
            "seq": self.seq,
            "at": self.at,
            "kind": self.kind,
            "prev": self.prev,
            "hash": self.hash,
            "entry": dict(self.entry),
        }


def line_hash(*, seq: int, at: str, kind: str, prev: str, entry: Mapping[str, Any]) -> str:
    """The chain hash: everything about this line except the hash itself."""
    material = {
        "profile": AUDIT_PROFILE,
        "seq": seq,
        "at": at,
        "kind": kind,
        "prev": prev,
        "entry": dict(entry),
    }
    return "sha256:" + hashlib.sha256(jcs(material)).hexdigest()


@dataclass(slots=True)
class InMemoryAuditLog:
    """The default sink. Holds lines for this process and writes nothing."""

    lines: list[AuditLine] = field(default_factory=list)

    @property
    def head(self) -> str:
        return self.lines[-1].hash if self.lines else GENESIS_HASH

    def append(self, kind: str, entry: Mapping[str, Any]) -> str:
        cleaned = _clean(entry)
        if not isinstance(cleaned, dict):  # pragma: no cover - _clean preserves mappings
            raise MalformedEventError("an audit entry must be a JSON object")
        at = format_instant(_instant_of(entry))
        cleaned.pop("at", None)
        seq = len(self.lines) + 1
        prev = self.head
        digest = line_hash(seq=seq, at=at, kind=kind, prev=prev, entry=cleaned)
        self.lines.append(
            AuditLine(seq=seq, at=at, kind=kind, prev=prev, hash=digest, entry=cleaned)
        )
        return digest

    def entries(self) -> tuple[AuditLine, ...]:
        return tuple(self.lines)

    def verify_chain(self) -> tuple[bool, str]:
        return verify_chain(self.entries())


@dataclass(slots=True)
class JsonlAuditLog:
    """The same log, one JSON object per line, LF, appended and never rewritten.

    Appending takes an exclusive lock file and reads only the last line. Both
    matter for the same reason: `seq` and `prev` are computed from the tail, so
    two writers that read that tail at the same time compute the same pair and
    the chain they leave behind does not verify. Reading the whole file to find
    its last line also made appending cost more the longer the log got, which is
    the wrong shape for the one operation this class exists to do.
    """

    path: Path
    lock_timeout_seconds: float = 10.0

    @property
    def _lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.lock_timeout_seconds
        while True:
            try:
                handle = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except (FileExistsError, PermissionError):  # pragma: no cover - timing dependent
                # Windows reports a delete-pending lock file as PermissionError
                # rather than FileExistsError, and both mean the same thing here:
                # somebody else is mid-append.
                if time.monotonic() >= deadline:
                    raise MalformedEventError(
                        f"another writer holds {self._lock_path} and did not release it "
                        f"within {self.lock_timeout_seconds} seconds"
                    ) from None
                time.sleep(0.005)
                continue
            break
        try:
            os.close(handle)
            yield
        finally:
            self._lock_path.unlink(missing_ok=True)

    def _tail(self) -> AuditLine | None:
        """The last line, read without loading the whole file."""
        if not self.path.is_file():
            return None
        size = self.path.stat().st_size
        window = min(size, _TAIL_WINDOW_BYTES)
        with self.path.open("rb") as handle:
            handle.seek(size - window)
            chunk = handle.read(window)
        # A window that starts mid-character damages only the first line in it,
        # which is never the line being read.
        for raw in reversed(chunk.decode("utf-8", errors="replace").splitlines()):
            if raw.strip():
                return _line_from(jsonio.loads(raw))
        return None

    @property
    def head(self) -> str:
        tail = self._tail()
        return tail.hash if tail is not None else GENESIS_HASH

    def append(self, kind: str, entry: Mapping[str, Any]) -> str:
        cleaned = _clean(entry)
        if not isinstance(cleaned, dict):  # pragma: no cover
            raise MalformedEventError("an audit entry must be a JSON object")
        at = format_instant(_instant_of(entry))
        cleaned.pop("at", None)
        with self._locked():
            tail = self._tail()
            seq = 1 if tail is None else tail.seq + 1
            prev = GENESIS_HASH if tail is None else tail.hash
            digest = line_hash(seq=seq, at=at, kind=kind, prev=prev, entry=cleaned)
            line = AuditLine(seq=seq, at=at, kind=kind, prev=prev, hash=digest, entry=cleaned)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                # One object per line. `jsonio.dumps` indents for human display,
                # and an indented object spans several lines, which is not a
                # JSONL line.
                handle.write(jsonio.dumps(line.to_dict(), indent=None) + "\n")
        return digest

    def entries(self) -> tuple[AuditLine, ...]:
        if not self.path.is_file():
            return ()
        lines: list[AuditLine] = []
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            lines.append(_line_from(jsonio.loads(raw)))
        return tuple(lines)

    def verify_chain(self) -> tuple[bool, str]:
        return verify_chain(self.entries())


def _line_from(loaded: object) -> AuditLine:
    if not isinstance(loaded, dict):
        raise MalformedEventError("every audit line must be a JSON object")
    entry = loaded.get("entry")
    return AuditLine(
        seq=int(loaded["seq"]),
        at=str(loaded["at"]),
        kind=str(loaded["kind"]),
        prev=str(loaded["prev"]),
        hash=str(loaded["hash"]),
        entry=entry if isinstance(entry, dict) else {},
    )


def verify_chain(lines: Sequence[AuditLine]) -> tuple[bool, str]:
    """Whether the log still adds up, and where it stopped if it does not."""
    prev = GENESIS_HASH
    for index, line in enumerate(lines, start=1):
        if line.seq != index:
            return False, f"line {index} is numbered {line.seq}; the log is not contiguous"
        if line.prev != prev:
            return False, f"line {index} follows {line.prev}, but line {index - 1} hashed to {prev}"
        expected = line_hash(
            seq=line.seq, at=line.at, kind=line.kind, prev=line.prev, entry=line.entry
        )
        if expected != line.hash:
            return False, f"line {index} does not hash to its recorded value"
        prev = line.hash
    return True, f"{len(lines)} line(s) chain from the genesis hash"


def _instant_of(entry: Mapping[str, Any]) -> datetime:
    """The instant an entry states. Refuses to invent one from the wall clock."""
    candidate = entry.get("at")
    if isinstance(candidate, datetime):
        return candidate
    raise MalformedEventError(
        "every audit entry must state the instant it happened in an 'at' field; "
        "reading the clock here would make the log depend on when it was written"
    )


__all__ = [
    "AUDIT_PROFILE",
    "GENESIS_HASH",
    "AuditLine",
    "InMemoryAuditLog",
    "JsonlAuditLog",
    "line_hash",
    "verify_chain",
]
