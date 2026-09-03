"""Anti-wash signals, phrased as a difficulty rather than an accusation.

Every pattern here has an innocent explanation. Registering the same artifact
hash twice is what happens when a script is re-run; trading only with the same
counterparty is what happens when you have one collaborator; a burst of activity
in an hour is what happens on the day a project ships. None of that makes the
pattern useless -- an observer who cannot tell your activity apart from wash
activity will not be able to tell it apart either, and that is worth knowing
before someone else decides.

So the wording is fixed and it is fixed in one place. `POSSIBLE_LOW_VALUE_LABEL`
is what the UI shows, `WashSignal.reason` says what is hard to distinguish, and
the word "fraud" does not appear in this module. A test asserts that.

`fleet.resolve_fleets` does the circular-counterparty work: an operator who has
disclosed that two DIDs are theirs has already told us the pair is not
independent, and re-deriving that here would be a second answer to a question
the core already answers.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import timedelta

from lineageauth.fleet import FleetView
from lineageauth.flop.model import ActivityRecord, WashSignal

POSSIBLE_LOW_VALUE_LABEL = "Possible low-value / circular activity"

NOT_AN_ACCUSATION = (
    "This is a note about what an outside observer cannot distinguish, not a finding "
    "that anything improper happened."
)

# A burst this tight, with nothing produced, is the shape a volume script makes.
_CHURN_WINDOW = timedelta(hours=1)
_CHURN_COUNT = 5


def _signal(index: int, pattern_id: str, reason: str, record_ids: Iterable[str]) -> WashSignal:
    return WashSignal(
        signal_id=f"wash-{index:03d}",
        pattern_id=pattern_id,
        label=POSSIBLE_LOW_VALUE_LABEL,
        reason=f"{reason} {NOT_AN_ACCUSATION}",
        record_ids=tuple(sorted(record_ids)),
    )


def detect_wash_signals(
    records: Iterable[ActivityRecord], *, fleets: FleetView | None = None
) -> tuple[WashSignal, ...]:
    """Report the patterns that are hard to tell apart from wash activity."""
    items = list(records)
    signals: list[WashSignal] = []
    index = 0

    by_hash: dict[str, list[str]] = defaultdict(list)
    for record in items:
        if record.artifact_hash is not None:
            by_hash[record.artifact_hash].append(record.record_id)
    for artifact_hash, ids in sorted(by_hash.items()):
        if len(ids) > 1:
            index += 1
            signals.append(
                _signal(
                    index,
                    "wash.duplicate-artifact-hash",
                    (
                        f"{len(ids)} records carry the same content hash ({artifact_hash}). "
                        "The same bytes submitted repeatedly look identical to a resubmission "
                        "whether or not that is what happened."
                    ),
                    ids,
                )
            )

    by_title: Counter[str] = Counter(record.title.strip().lower() for record in items)
    for title, count in sorted(by_title.items()):
        if count > 2:
            index += 1
            signals.append(
                _signal(
                    index,
                    "wash.repeated-title",
                    (
                        f"{count} records share the title {title!r}. Repeated identical "
                        "descriptions are difficult to distinguish from generated volume."
                    ),
                    (record.record_id for record in items if record.title.strip().lower() == title),
                )
            )

    subjects = {record.subject_did for record in items}
    disclosed: set[str] = set()
    if fleets is not None:
        for subject in subjects:
            disclosed |= set(fleets.related_to(subject))
        disclosed -= subjects

    counterparty_records: dict[str, list[str]] = defaultdict(list)
    for record in items:
        for counterparty in record.counterparties:
            counterparty_records[counterparty].append(record.record_id)
    for counterparty, ids in sorted(counterparty_records.items()):
        if counterparty in subjects:
            index += 1
            signals.append(
                _signal(
                    index,
                    "wash.self-dealing",
                    (
                        "the subject appears on both sides of these records, so nobody "
                        "independent is involved in them."
                    ),
                    ids,
                )
            )
            continue
        if counterparty in disclosed and len(ids) > 1:
            index += 1
            signals.append(
                _signal(
                    index,
                    "wash.same-operator-counterparty",
                    (
                        f"{counterparty} has been disclosed as being under the same operator, "
                        "so these exchanges are between two keys of one party."
                    ),
                    ids,
                )
            )

    ordered = sorted(items, key=lambda record: record.occurred_at)
    window: list[ActivityRecord] = []
    for record in ordered:
        window = [
            candidate
            for candidate in window
            if record.occurred_at - candidate.occurred_at <= _CHURN_WINDOW
        ]
        window.append(record)
        without_artifact = [item for item in window if item.artifact_hash is None]
        if len(without_artifact) >= _CHURN_COUNT:
            index += 1
            signals.append(
                _signal(
                    index,
                    "wash.rapid-churn-without-artifact",
                    (
                        f"{len(without_artifact)} records inside one hour produced no artifact "
                        "or result. Activity that leaves nothing behind is the shape a volume "
                        "script makes."
                    ),
                    (item.record_id for item in without_artifact),
                )
            )
            window = []

    return tuple(signals)


__all__ = [
    "NOT_AN_ACCUSATION",
    "POSSIBLE_LOW_VALUE_LABEL",
    "detect_wash_signals",
]
