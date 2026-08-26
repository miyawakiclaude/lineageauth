"""Admission of a set of signed envelopes into an authority-resolvable bundle.

This is the gate in front of `lineageauth.lineage`. It answers "which of these
envelopes are even eligible to influence an authority decision?" and nothing
more -- it never reads `fromEpoch`, never compares roots, never counts a quorum.

Three properties are worth stating outright, because the resolver above depends
on all three and none of them is free:

*Integrity first.* Every envelope goes through `verify_event`. Anything that
fails is moved to `rejected` and is invisible to the resolver, so a tampered
event cannot manufacture a conflict, pad a quorum, or shadow a real event.

*Order-independence.* Callers hand over events in whatever order a file, a
network, or a directory listing produced. Every accessor here returns a tuple
sorted by `event_id`, so downstream results cannot depend on that order. This
matters more than it looks: the resolver deliberately has no timestamp tiebreak
(D-033), which leaves iteration order as the only remaining way for input order
to leak into an authority decision. Closing it here closes it everywhere.

*Proof accumulation.* Copies of one event id are merged by taking the union of
their verifying signers (D-036). Anything that instead *selects* one copy hands
a keyless third party control over which proofs survive.

Offline like the rest of the package: no network, no database, no private keys.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError, ReasonCode
from lineageauth.timeutil import parse_instant
from lineageauth.verify import verify_event


@dataclass(frozen=True, slots=True)
class AdmittedEvent:
    """One event whose integrity verified, flattened for the resolver's use.

    `verified_signers` is sorted and distinct. Within a single envelope a
    repeated signer is already only one key; across merged copies proof order
    carries no meaning at all, so imposing a canonical order is the only way to
    keep the result independent of how the copies arrived. Quorum counting still
    does its own set intersection -- one key, one vote is a quorum rule (D-027),
    not something this layer is trusted to have done.
    """

    event_id: str
    event_type: str
    lineage: str
    issued_at: datetime
    verified_signers: tuple[str, ...]
    payload: Mapping[str, Any]

    def signed_by(self, did: str) -> bool:
        """True when `did` produced at least one verifying proof on this event."""
        return did in self.verified_signers

    def distinct_signers(self) -> frozenset[str]:
        """The signer set with duplicates collapsed -- one key, one vote."""
        return frozenset(self.verified_signers)

    def get(self, name: str) -> Any:
        """Read a payload field, or None when absent."""
        return self.payload.get(name)


@dataclass(frozen=True, slots=True)
class RejectedEvent:
    """An envelope that may not influence any authority decision, and why."""

    event_id: str | None
    event_type: str | None
    lineage: str | None
    reason: ReasonCode
    detail: str


@dataclass(frozen=True, slots=True)
class EventBundle:
    """An integrity-checked, deterministically ordered view over a set of events."""

    admitted: tuple[AdmittedEvent, ...] = ()
    rejected: tuple[RejectedEvent, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    # Lookup indices. The resolver walks one epoch at a time and asks for the
    # same event types on every pass, so a linear scan per question turns a
    # bundle of N events into O(N^2) work for an attacker who only had to pay
    # O(N) to send it.
    _by_id: Mapping[str, AdmittedEvent] = field(
        init=False, repr=False, compare=False, default_factory=dict
    )
    _by_type: Mapping[str, tuple[AdmittedEvent, ...]] = field(
        init=False, repr=False, compare=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        buckets: dict[str, list[AdmittedEvent]] = {}
        for event in self.admitted:
            buckets.setdefault(event.event_type, []).append(event)
        object.__setattr__(self, "_by_id", MappingProxyType({e.event_id: e for e in self.admitted}))
        object.__setattr__(
            self, "_by_type", MappingProxyType({k: tuple(v) for k, v in buckets.items()})
        )

    @classmethod
    def from_envelopes(cls, envelopes: Iterable[Envelope]) -> EventBundle:
        """Verify every envelope and split the input into admitted and rejected."""
        admitted: list[AdmittedEvent] = []
        rejected: list[RejectedEvent] = []
        warnings: list[str] = []

        for envelope in envelopes:
            result = verify_event(envelope)
            if not result.integrity_ok:
                rejected.append(
                    RejectedEvent(
                        event_id=result.event_id,
                        event_type=result.event_type,
                        lineage=result.lineage,
                        reason=result.reason,
                        detail=result.detail,
                    )
                )
                continue

            # verify_event fills these in on a pass. Checked rather than
            # asserted: `python -O` strips assertions, and an invariant that
            # guards an authority decision must not be one of the things an
            # optimisation flag can switch off.
            if result.event_id is None or result.event_type is None or result.lineage is None:
                rejected.append(  # pragma: no cover - defensive
                    RejectedEvent(
                        event_id=result.event_id,
                        event_type=result.event_type,
                        lineage=result.lineage,
                        reason=ReasonCode.MALFORMED,
                        detail="verifier reported success without an identity; refusing to admit",
                    )
                )
                continue

            try:
                issued_at = parse_instant(envelope.payload["issuedAt"], field="issuedAt")
            except LineageAuthError as exc:  # pragma: no cover - verify_event checked it
                rejected.append(
                    RejectedEvent(
                        event_id=result.event_id,
                        event_type=result.event_type,
                        lineage=result.lineage,
                        reason=ReasonCode.MALFORMED,
                        detail=str(exc),
                    )
                )
                continue

            warnings.extend(result.warnings)
            admitted.append(
                AdmittedEvent(
                    event_id=result.event_id,
                    event_type=result.event_type,
                    lineage=result.lineage,
                    issued_at=issued_at,
                    verified_signers=tuple(sorted(set(result.verified_signers))),
                    # Deep copy: the caller keeps its Envelope and may mutate a
                    # nested object afterwards. A bundle whose contents can
                    # change under the resolver is not a bundle.
                    payload=MappingProxyType(copy.deepcopy(dict(envelope.payload))),
                )
            )

        merged, merge_warnings = _merge_duplicates(admitted)
        return cls(
            admitted=merged,
            rejected=tuple(rejected),
            warnings=tuple(warnings + merge_warnings),
        )

    def by_id(self, event_id: object) -> AdmittedEvent | None:
        """Look up one admitted event, or None when the bundle does not carry it."""
        if not isinstance(event_id, str):
            return None
        return self._by_id.get(event_id)

    def of_type(self, event_type: str, *, lineage: str | None = None) -> tuple[AdmittedEvent, ...]:
        """Admitted events of one type, ordered by event id."""
        events = self._by_type.get(event_type, ())
        if lineage is None:
            return events
        return tuple(event for event in events if event.lineage == lineage)

    def lineages(self) -> tuple[str, ...]:
        """Every lineage identifier the admitted events mention, sorted."""
        return tuple(sorted({event.lineage for event in self.admitted}))


def _merge_duplicates(
    events: list[AdmittedEvent],
) -> tuple[tuple[AdmittedEvent, ...], list[str]]:
    """Merge copies of one event id by taking the union of their signers (D-036).

    One event id means one payload, hence one signing preimage, so every proof
    on every copy is a statement about the same bytes. Proofs are therefore
    additive evidence: a copy carrying more of them is strictly more informative
    than a copy carrying fewer, and the union is the only merge rule that is
    both order-independent and monotone.

    Selecting a single copy instead -- by any total order over the content --
    is exploitable *without a private key*. An observer who sees a published
    envelope can republish it with proofs removed, or with a proof of their own
    added, and thereby decide which proofs the resolver gets to see. That either
    starves a legitimate recovery quorum below its threshold, freezing the
    lineage at an epoch it has already left, or shadows the real event outright.
    Union removes the choice: nothing an attacker adds can subtract.

    Union cannot inflate authority either. A forged copy can only contribute
    signatures the forger can actually produce, and a signer who is neither the
    current root nor a member of the referenced recovery policy contributes
    nothing to any decision the resolver makes.
    """
    grouped: dict[str, list[AdmittedEvent]] = {}
    for event in events:
        grouped.setdefault(event.event_id, []).append(event)

    merged: list[AdmittedEvent] = []
    warnings: list[str] = []
    for event_id in sorted(grouped):
        copies = grouped[event_id]
        first = copies[0]
        if len(copies) == 1:
            merged.append(first)
            continue

        signers = tuple(sorted({signer for copy_ in copies for signer in copy_.verified_signers}))
        if any(tuple(c.verified_signers) != signers for c in copies):
            warnings.append(
                f"bundle carries {len(copies)} copies of {event_id} with differing proof "
                f"sets; their verifying signers were merged into a union of "
                f"{len(signers)} (D-036)"
            )
        merged.append(
            AdmittedEvent(
                event_id=first.event_id,
                event_type=first.event_type,
                lineage=first.lineage,
                issued_at=first.issued_at,
                verified_signers=signers,
                payload=first.payload,
            )
        )
    return tuple(merged), warnings
