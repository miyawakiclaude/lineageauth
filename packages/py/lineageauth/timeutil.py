"""Strict RFC 3339 UTC time handling.

docs/02_LAP_CORE.md requires RFC3339 UTC and lets a verifier be given an
explicit evaluation time so results are reproducible.

Protocol 0.1 accepts only the `Z` spelling. A local-offset timestamp denotes
the same instant but is a different byte string, so it would canonicalize --
and therefore hash and sign -- differently while looking equivalent to a
reader. One instant gets one spelling.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from lineageauth.errors import MalformedEventError

RFC3339_UTC_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})"
    r"T(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<frac>\.\d{1,9})?"
    r"Z$"
)


def parse_instant(value: object, *, field: str = "timestamp") -> datetime:
    """Parse a strict RFC3339 UTC timestamp into an aware datetime."""
    if not isinstance(value, str):
        raise MalformedEventError(f"{field} must be a string")
    match = RFC3339_UTC_RE.fullmatch(value)
    if match is None:
        raise MalformedEventError(
            f"{field} must be RFC3339 UTC ending in 'Z' (e.g. 2026-08-26T09:00:00Z), got '{value}'"
        )
    frac = match.group("frac") or ""
    # datetime.fromisoformat handles at most microsecond precision.
    micro = (frac[1:] + "000000")[:6] if frac else "000000"
    try:
        parsed = datetime.strptime(
            f"{match.group('date')}T{match.group('time')}.{micro}",
            "%Y-%m-%dT%H:%M:%S.%f",
        )
    except ValueError as exc:
        raise MalformedEventError(f"{field} is not a real date/time: {exc}") from exc
    return parsed.replace(tzinfo=UTC)


def format_instant(moment: datetime) -> str:
    """Render an aware datetime as a strict RFC3339 UTC string."""
    if moment.tzinfo is None:
        raise MalformedEventError("refusing to format a naive datetime as UTC")
    utc = moment.astimezone(UTC)
    if utc.microsecond:
        return utc.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0") + "Z"
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
