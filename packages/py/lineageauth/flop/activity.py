"""Read-only importers. Five sources, one record shape, no writes anywhere.

An adapter's contract is deliberately narrow: given a subject, return records.
It may not post, sign, spend, or follow a link it found. `read_only` is on the
protocol as an attribute rather than a comment because it is asserted by a test
over every registered adapter.

The interesting design decision is what happens to volume. A room with five
hundred messages in it is a real fact about an agent, and it is not useful work;
the directive's third acceptance test is exactly this case. Dropping the number
would hide something true, and counting it would inflate the thing the product
exists to measure honestly. So a volume record is kept, marked `secondary`, and
`ActivityRecord.is_useful_work` returns False for it whatever its category --
the analytics view can show the number, and the evidence view cannot be made to
count it.

`MockAdapter` forces `synthetic=True` on everything it emits, and the flag rides
all the way to the rendered response. Synthetic and real data never share a
file, an adapter, or a code path that could lose the distinction.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from lineageauth.adapters.tclk.frames import Frame, try_decode_frame
from lineageauth.adapters.technocore.client import (
    TechnocoreReader,
    TransportError,
    UntrustedMessage,
)
from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.errors import LineageAuthError
from lineageauth.evidence import read_artifact, read_attestation, read_receipt
from lineageauth.flop.model import (
    SYNTHETIC_BANNER,
    VOLUME_NOTE,
    ActivityCategory,
    ActivityRecord,
    EvidenceLevel,
    SourceClass,
    VerificationState,
    sort_records,
)
from lineageauth.flop.sources import CONFORMANCE_ROOT, classify_source, read_json
from lineageauth.timeutil import parse_instant

PUBLIC_EVIDENCE_FILE = CONFORMANCE_ROOT / "public-evidence.json"
MOCK_ACTIVITY_FILE = CONFORMANCE_ROOT / "mock-activity.json"

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

_CATEGORY_BY_NAME: Mapping[str, ActivityCategory] = {
    str(category): category for category in ActivityCategory
}

_EVIDENCE_BY_NAME: Mapping[str, EvidenceLevel] = {str(level): level for level in EvidenceLevel}

_VERIFICATION_BY_NAME: Mapping[str, VerificationState] = {
    str(state): state for state in VerificationState
}


@dataclass(frozen=True, slots=True)
class ActivitySubject:
    """Who the records are about, in which lineage, evaluated when.

    `at` is a parameter rather than the wall clock for the same reason the core
    takes one: the same events at the same instant must produce the same answer,
    or nothing downstream is reproducible.
    """

    did: str
    lineage: str
    at: datetime


@runtime_checkable
class ActivitySourceAdapter(Protocol):
    """A read-only source of activity records."""

    source_id: str
    source_class: SourceClass
    read_only: bool

    def fetch(self, subject: ActivitySubject) -> tuple[ActivityRecord, ...]:
        """Return this source's records for the subject. Must not write."""
        ...


@dataclass(frozen=True, slots=True)
class ActivityCollection:
    """Everything the adapters returned, plus what went wrong getting it."""

    records: tuple[ActivityRecord, ...]
    warnings: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()

    @property
    def contains_synthetic(self) -> bool:
        return any(record.synthetic for record in self.records)

    @property
    def useful_work(self) -> tuple[ActivityRecord, ...]:
        return tuple(record for record in self.records if record.is_useful_work)

    @property
    def secondary(self) -> tuple[ActivityRecord, ...]:
        """Volume-shaped records, kept visible and kept out of the evidence count."""
        return tuple(record for record in self.records if record.secondary)

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [record.to_dict() for record in self.records],
            "usefulWorkCount": len(self.useful_work),
            "secondaryCount": len(self.secondary),
            "volumeNote": VOLUME_NOTE,
            "sourceIds": list(self.source_ids),
            "warnings": list(self.warnings),
            "containsSyntheticData": self.contains_synthetic,
            **({"banner": SYNTHETIC_BANNER} if self.contains_synthetic else {}),
        }


def _instant(value: object, *, fallback: datetime) -> datetime:
    try:
        return parse_instant(value)
    except LineageAuthError:
        return fallback


class LocalEventsAdapter:
    """Signed LineageAuth events: the only source that proves anything by itself.

    Everything else in this module reports what some service said. This one
    reports what a key signed, which is why its records are the ones allowed to
    reach `cryptographically-linked` and above without a third party.
    """

    __slots__ = ("_bundle", "read_only", "source_class", "source_id")

    def __init__(self, bundle: EventBundle, *, source_id: str = "local-events") -> None:
        self._bundle = bundle
        self.source_id = source_id
        self.source_class = SourceClass.VERIFIED_THIRD_PARTY
        self.read_only = True

    def _events(self, subject: ActivitySubject, event_type: str) -> tuple[AdmittedEvent, ...]:
        return tuple(
            event
            for event in self._bundle.admitted
            if event.event_type == event_type and event.lineage == subject.lineage
        )

    def fetch(self, subject: ActivitySubject) -> tuple[ActivityRecord, ...]:
        records: list[ActivityRecord] = []
        own_artifacts: set[str] = set()
        receipted: set[str] = set()

        for event in self._events(subject, "artifact.receipt"):
            receipt = read_receipt(event)
            if isinstance(receipt, str) or not event.signed_by(subject.did):
                continue
            receipted.add(receipt.artifact_id)

        for event in self._events(subject, "artifact.register"):
            artifact = read_artifact(event)
            if isinstance(artifact, str):
                continue
            if not event.signed_by(subject.did):
                continue
            own_artifacts.add(artifact.artifact_id)
            supported = artifact.artifact_id in receipted
            records.append(
                ActivityRecord(
                    record_id=f"local-artifact-{event.event_id}",
                    subject_did=subject.did,
                    category=ActivityCategory.USEFUL_ARTIFACT,
                    title=artifact.uri or artifact.artifact_id,
                    occurred_at=event.issued_at,
                    source_id=self.source_id,
                    source_class=self.source_class,
                    evidence_level=(
                        EvidenceLevel.EVIDENCE_SUPPORTED
                        if supported
                        else EvidenceLevel.CRYPTOGRAPHICALLY_LINKED
                    ),
                    verification_state=VerificationState.VERIFIED,
                    artifact_hash=artifact.artifact_id,
                    artifact_ref=artifact.uri,
                    event_id=event.event_id,
                    detail=(
                        "registered and receipted by this key"
                        if supported
                        else "registered by this key; no receipt signed for it yet"
                    ),
                )
            )

        for event in self._events(subject, "attestation.issue"):
            attestation = read_attestation(event)
            if isinstance(attestation, str):
                continue
            if attestation.issuer == subject.did:
                continue
            if attestation.subject_ref not in own_artifacts:
                continue
            records.append(
                ActivityRecord(
                    record_id=f"local-attestation-{event.event_id}",
                    subject_did=subject.did,
                    category=ActivityCategory.EXTERNAL_VERIFICATION,
                    title=f"attestation {attestation.predicate} on {attestation.subject_ref}",
                    occurred_at=attestation.issued_at,
                    source_id=self.source_id,
                    source_class=self.source_class,
                    evidence_level=EvidenceLevel.THIRD_PARTY_ATTESTED,
                    verification_state=VerificationState.VERIFIED,
                    artifact_hash=attestation.subject_ref,
                    event_id=event.event_id,
                    counterparties=(attestation.issuer,),
                    third_party_ref=attestation.issuer,
                    detail=(
                        "another key signed an opinion about this artifact; the signature "
                        "proves who said it, not that it is correct"
                    ),
                )
            )

        for event_type in ("task.claim", "task.result", "task.verify"):
            for event in self._events(subject, event_type):
                if not event.signed_by(subject.did):
                    continue
                task_id = event.get("taskId")
                records.append(
                    ActivityRecord(
                        record_id=f"local-{event_type}-{event.event_id}",
                        subject_did=subject.did,
                        category=ActivityCategory.AGENT_COLLABORATION,
                        title=f"{event_type} {task_id if isinstance(task_id, str) else ''}".strip(),
                        occurred_at=event.issued_at,
                        source_id=self.source_id,
                        source_class=self.source_class,
                        evidence_level=EvidenceLevel.CRYPTOGRAPHICALLY_LINKED,
                        verification_state=VerificationState.VERIFIED,
                        event_id=event.event_id,
                        detail="signed participation in a task",
                    )
                )

        for event_type in ("profile.statement", "skill.claim"):
            for event in self._events(subject, event_type):
                if not event.signed_by(subject.did):
                    continue
                records.append(
                    ActivityRecord(
                        record_id=f"local-{event_type}-{event.event_id}",
                        subject_did=subject.did,
                        category=ActivityCategory.IDENTITY,
                        title=f"{event_type} by this key",
                        occurred_at=event.issued_at,
                        source_id=self.source_id,
                        source_class=self.source_class,
                        evidence_level=EvidenceLevel.SELF_CLAIMED,
                        verification_state=VerificationState.UNVERIFIED,
                        event_id=event.event_id,
                        detail=(
                            "the subject said this about itself; a signature makes it theirs, "
                            "not true"
                        ),
                    )
                )

        return sort_records(records)


class TechnocoreAdapter:
    """Read rooms and notes. Never posts, never follows a URL it reads.

    The transport is injected, so the test suite drives this with no network at
    all. Volume is emitted as a secondary record: honest about the number,
    unable to inflate the evidence count with it.
    """

    __slots__ = ("_reader", "_rooms", "read_only", "source_class", "source_id")

    def __init__(
        self,
        reader: TechnocoreReader,
        *,
        rooms: Sequence[str] = (),
        source_id: str = "technocore",
    ) -> None:
        self._reader = reader
        self._rooms = tuple(rooms)
        self.source_id = source_id
        # An official service carrying content somebody else wrote. The
        # transport being official says nothing about the message.
        self.source_class = SourceClass.COMMUNITY
        self.read_only = True

    def _sender_matches(self, message: UntrustedMessage, did: str) -> bool:
        """The `from` field is a self-asserted label, so this proves nothing.

        Used only to decide which rows to show, never to raise an evidence
        level: `https://technocore.chat/auth.md` says the service authenticates
        nobody.
        """
        return message.sender == did

    def fetch(self, subject: ActivitySubject) -> tuple[ActivityRecord, ...]:
        records: list[ActivityRecord] = []
        for room in self._rooms:
            try:
                messages = self._reader.room(room)
            except (TransportError, LineageAuthError):
                continue
            mine = [message for message in messages if self._sender_matches(message, subject.did)]
            if not mine:
                continue
            latest = max(
                (_instant(message.ts, fallback=subject.at) for message in mine),
                default=subject.at,
            )
            records.append(
                ActivityRecord(
                    record_id=f"technocore-room-{room}",
                    subject_did=subject.did,
                    category=ActivityCategory.ROOM_PARTICIPATION,
                    title=f"participated in room {room}",
                    occurred_at=latest,
                    source_id=self.source_id,
                    source_class=self.source_class,
                    evidence_level=EvidenceLevel.SELF_CLAIMED,
                    verification_state=VerificationState.UNVERIFIED,
                    artifact_ref=f"https://technocore.chat/r/{room}",
                    detail=(
                        "the sender field is a self-asserted label; the service authenticates "
                        "nobody, so this is a claim rather than an attribution"
                    ),
                )
            )
            records.append(
                ActivityRecord(
                    record_id=f"technocore-volume-{room}",
                    subject_did=subject.did,
                    category=ActivityCategory.MESSAGE_VOLUME,
                    title=f"{len(mine)} messages in room {room}",
                    occurred_at=latest,
                    source_id=self.source_id,
                    source_class=self.source_class,
                    evidence_level=EvidenceLevel.SELF_CLAIMED,
                    verification_state=VerificationState.UNVERIFIED,
                    secondary=True,
                    detail=VOLUME_NOTE,
                )
            )
        return sort_records(records)


class TclkAdapter:
    """Deals read off a tclk/1 transcript. Decodes; settles nothing.

    A tclk frame proves those bytes existed and named those DIDs. It does not
    prove money moved, that the work was any good, or that the two parties are
    two people -- `adapters/tclk/evidence.py` says so in its own words, and this
    adapter does not quietly upgrade any of it.
    """

    __slots__ = ("_lines", "read_only", "source_class", "source_id")

    def __init__(self, lines: Sequence[str], *, source_id: str = "tclk") -> None:
        self._lines = tuple(lines)
        self.source_id = source_id
        self.source_class = SourceClass.COMMUNITY
        self.read_only = True

    def fetch(self, subject: ActivitySubject) -> tuple[ActivityRecord, ...]:
        decoded: list[tuple[int, Frame]] = []
        for index, line in enumerate(self._lines):
            frame = try_decode_frame(line)
            if frame is not None:
                decoded.append((index, frame))

        # Who else posted on the same contract. A counterparty is read off the
        # transcript rather than off any single frame: a tclk frame names its
        # sender and its contract, and the other side is whoever else appears.
        senders_by_contract: dict[str, set[str]] = {}
        for _, frame in decoded:
            contract = frame.contract
            if contract is not None:
                senders_by_contract.setdefault(contract, set()).add(frame.sender)

        records: list[ActivityRecord] = []
        for index, frame in decoded:
            if frame.sender != subject.did:
                continue
            contract = frame.contract
            others = senders_by_contract.get(contract or "", set()) - {subject.did}
            records.append(
                ActivityRecord(
                    record_id=f"tclk-{index:03d}-{frame.kind}",
                    subject_did=subject.did,
                    category=ActivityCategory.TCLK_DEAL,
                    title=f"tclk {frame.kind}",
                    occurred_at=subject.at,
                    source_id=self.source_id,
                    source_class=self.source_class,
                    evidence_level=EvidenceLevel.CRYPTOGRAPHICALLY_LINKED,
                    verification_state=VerificationState.PARTIALLY_VERIFIED,
                    artifact_ref=contract,
                    counterparties=tuple(sorted(others)),
                    detail=(
                        "the frame bytes existed and named these DIDs; nothing here says value "
                        "moved on any rail"
                    ),
                )
            )
        return sort_records(records)


class PublicEvidenceAdapter:
    """Real public contributions, read from a file. No network access at all.

    Every entry stays at `partially-verified`: the URL is recorded, and this
    session did not go and fetch it. Claiming `verified` for something nobody
    checked in this run is the exact failure the verification vocabulary exists
    to prevent.
    """

    __slots__ = ("_document", "read_only", "source_class", "source_id")

    def __init__(self, path: Path | None = None, *, source_id: str = "public-evidence") -> None:
        self._document = read_json(path or PUBLIC_EVIDENCE_FILE)
        self.source_id = source_id
        self.source_class = SourceClass.VERIFIED_THIRD_PARTY
        self.read_only = True

    @property
    def subject_did(self) -> str | None:
        candidate = self._document.get("subjectDid")
        return candidate if isinstance(candidate, str) else None

    def fetch(self, subject: ActivitySubject) -> tuple[ActivityRecord, ...]:
        if self.subject_did is not None and self.subject_did != subject.did:
            return ()
        raw = self._document.get("entries")
        if not isinstance(raw, list):
            return ()
        records: list[ActivityRecord] = []
        for entry in raw:
            if not isinstance(entry, Mapping):
                continue
            record = _record_from_mapping(
                entry,
                subject=subject,
                source_id=self.source_id,
                default_source_class=SourceClass.COMMUNITY,
                synthetic=False,
            )
            if record is not None:
                records.append(record)
        return sort_records(records)


class MockAdapter:
    """Synthetic records for the UI. Marked as such, permanently.

    `synthetic=True` is forced here rather than read from the file, so a mock
    file edited to say otherwise still produces records the console will label.

    The file names one subject and this adapter is asked about another every
    time it runs outside its own demo, so each record also says, in its own
    detail, that it is not a record about the DID that was asked for. The banner
    says the data is synthetic; this says whose it is not, which is the half a
    reader would otherwise fill in wrongly. The source class is clamped to
    `UNKNOWN` by `_clamped_source_class` for the same reason: a mock file may
    not hand itself a badge.
    """

    __slots__ = ("_document", "read_only", "source_class", "source_id")

    def __init__(self, path: Path | None = None, *, source_id: str = "mock") -> None:
        self._document = read_json(path or MOCK_ACTIVITY_FILE)
        self.source_id = source_id
        self.source_class = SourceClass.UNKNOWN
        self.read_only = True

    @property
    def banner(self) -> str:
        return SYNTHETIC_BANNER

    @property
    def declared_subject_did(self) -> str | None:
        passport = self._document.get("passport")
        if not isinstance(passport, Mapping):  # pragma: no cover - guarded by fetch
            return None
        candidate = passport.get("subjectDid")
        return candidate if isinstance(candidate, str) else None

    def fetch(self, subject: ActivitySubject) -> tuple[ActivityRecord, ...]:
        passport = self._document.get("passport")
        if not isinstance(passport, Mapping):
            return ()
        raw = passport.get("activities")
        if not isinstance(raw, list):
            return ()
        records: list[ActivityRecord] = []
        for entry in raw:
            if not isinstance(entry, Mapping):
                continue
            record = _record_from_mapping(
                entry,
                subject=subject,
                source_id=self.source_id,
                default_source_class=SourceClass.UNKNOWN,
                synthetic=True,
            )
            if record is not None:
                records.append(replace(record, detail=self._disclaim(record.detail, subject)))
        return sort_records(records)

    def _disclaim(self, detail: str, subject: ActivitySubject) -> str:
        declared = self.declared_subject_did
        whose = (
            f"the mock file's own subject {declared}"
            if declared is not None
            else "no subject at all"
        )
        note = (
            f"[SYNTHETIC MOCK DATA: this record is layout material written against {whose}; "
            f"it is not an observation about {subject.did}]"
        )
        return f"{detail} {note}".strip()


def _category_for(entry: Mapping[str, Any]) -> ActivityCategory:
    raw = entry.get("category")
    if isinstance(raw, str):
        direct = _CATEGORY_BY_NAME.get(raw)
        if direct is not None:
            return direct
        # The mock file uses short names. Map the ones it uses and fall back to
        # a useful artifact rather than inventing a category.
        aliases = {
            "connector": ActivityCategory.CONNECTOR,
            "protocol": ActivityCategory.PROTOCOL_IMPLEMENTATION,
            "docs": ActivityCategory.DOCUMENTATION,
        }
        aliased = aliases.get(raw)
        if aliased is not None:
            return aliased
    return ActivityCategory.USEFUL_ARTIFACT


# How much authority a class carries. A record file may say anything about
# itself; what it says is capped by the adapter that read it, because the
# adapter is the thing whose provenance was decided by code rather than by the
# file's own text.
_CLASS_RANK: dict[SourceClass, int] = {
    SourceClass.SUSPICIOUS: 0,
    SourceClass.UNKNOWN: 1,
    SourceClass.COMMUNITY: 2,
    SourceClass.VERIFIED_THIRD_PARTY: 3,
    SourceClass.OFFICIAL: 4,
}


def _clamped_source_class(
    raw: object,
    *,
    adapter_class: SourceClass,
    url: str | None,
) -> tuple[SourceClass, str]:
    """The class a record may carry, and why it is not the one it asked for.

    `sources.classify_source` exists because official is an origin. A record
    file that writes `"sourceClass": "official"` next to itself was, until this
    function, believed -- which put the whole point of the classifier back into
    the hands of whoever could edit a JSON file, mock data included.

    Two rules, both downgrades. A declared class may never outrank the adapter
    that produced the record, and `official` additionally has to survive
    `classify_source` on the record's own URL. Nothing here upgrades: an entry
    that declares less than its adapter is taken at its word, because claiming
    less is not the direction anybody lies in.
    """
    if not isinstance(raw, str) or raw not in tuple(SourceClass):
        return adapter_class, ""
    declared = SourceClass(raw)
    if declared is SourceClass.OFFICIAL:
        decided = classify_source(url) if url is not None else None
        if decided is None or decided.source_class is not SourceClass.OFFICIAL:
            fallback = min(adapter_class, SourceClass.COMMUNITY, key=lambda item: _CLASS_RANK[item])
            because = (
                "no URL to check"
                if decided is None
                else f"{url} classifies as {decided.source_class}"
            )
            return (
                fallback,
                (
                    f"[this record declared sourceClass official; it is shown as {fallback} "
                    f"because official is decided by origin and {because}]"
                ),
            )
    if _CLASS_RANK[declared] > _CLASS_RANK[adapter_class]:
        return (
            adapter_class,
            (
                f"[this record declared sourceClass {declared}; it is shown as {adapter_class}, "
                "which is as far as the adapter that read it can vouch]"
            ),
        )
    return declared, ""


def _record_from_mapping(
    entry: Mapping[str, Any],
    *,
    subject: ActivitySubject,
    source_id: str,
    default_source_class: SourceClass,
    synthetic: bool,
) -> ActivityRecord | None:
    record_id = entry.get("id")
    title = entry.get("title")
    if not isinstance(record_id, str) or not isinstance(title, str):
        return None
    url = entry.get("url")
    source_class, provenance_note = _clamped_source_class(
        entry.get("sourceClass"),
        adapter_class=default_source_class,
        url=url if isinstance(url, str) else None,
    )
    raw_level = entry.get("evidenceLevel")
    level = (
        _EVIDENCE_BY_NAME.get(raw_level, EvidenceLevel.SELF_CLAIMED)
        if isinstance(raw_level, str)
        else EvidenceLevel.SELF_CLAIMED
    )
    raw_state = entry.get("verificationState")
    state = (
        _VERIFICATION_BY_NAME.get(raw_state, VerificationState.UNVERIFIED)
        if isinstance(raw_state, str)
        else VerificationState.UNVERIFIED
    )
    occurred = entry.get("occurredAt")
    artifact_hash = entry.get("artifactHash")
    third_party = entry.get("thirdParty")
    note = entry.get("note")
    detail = note if isinstance(note, str) else ""
    if provenance_note:
        detail = f"{detail} {provenance_note}".strip()
    return ActivityRecord(
        record_id=f"{source_id}-{record_id}",
        subject_did=subject.did,
        category=_category_for(entry),
        title=title,
        occurred_at=_instant(occurred, fallback=_EPOCH),
        source_id=source_id,
        source_class=source_class,
        evidence_level=level,
        verification_state=state,
        artifact_hash=artifact_hash if isinstance(artifact_hash, str) else None,
        artifact_ref=url if isinstance(url, str) else None,
        third_party_ref=third_party if isinstance(third_party, str) else None,
        synthetic=synthetic,
        detail=detail,
    )


def collect_activities(
    adapters: Iterable[ActivitySourceAdapter], subject: ActivitySubject
) -> ActivityCollection:
    """Run every adapter and merge what they return.

    An adapter that fails becomes a warning rather than an exception. One
    unreachable service should not empty a console that has four other sources,
    and a silent empty section would be worse than either.
    """
    records: list[ActivityRecord] = []
    warnings: list[str] = []
    source_ids: list[str] = []
    for adapter in adapters:
        source_ids.append(adapter.source_id)
        if not adapter.read_only:  # pragma: no cover - defensive
            warnings.append(f"adapter {adapter.source_id} is not read-only and was skipped")
            continue
        try:
            records.extend(adapter.fetch(subject))
        except (LineageAuthError, TransportError, ValueError) as exc:
            warnings.append(f"adapter {adapter.source_id} failed: {exc}")
    return ActivityCollection(
        records=sort_records(records),
        warnings=tuple(warnings),
        source_ids=tuple(source_ids),
    )


__all__ = [
    "MOCK_ACTIVITY_FILE",
    "PUBLIC_EVIDENCE_FILE",
    "ActivityCollection",
    "ActivitySourceAdapter",
    "ActivitySubject",
    "LocalEventsAdapter",
    "MockAdapter",
    "PublicEvidenceAdapter",
    "TclkAdapter",
    "TechnocoreAdapter",
    "collect_activities",
]
