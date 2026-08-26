"""Strict JSON loading for signed material.

`json.loads` keeps the last value when an object repeats a key. Two different
documents would then parse to the same dict, so an attacker could append a
duplicate key to a signed envelope and change what a lenient reader sees while
a strict canonicalizer still produced the original signed bytes. Reject
duplicates instead.
"""

from __future__ import annotations

import json
from typing import Any

from lineageauth.errors import MalformedEventError


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise MalformedEventError(f"duplicate JSON object key: {key!r}")
        seen[key] = value
    return seen


def loads(text: str | bytes) -> Any:
    """Parse JSON, rejecting duplicate object keys."""
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except MalformedEventError:
        raise
    except json.JSONDecodeError as exc:
        raise MalformedEventError(f"invalid JSON: {exc}") from exc


def dumps(value: Any, *, indent: int | None = 2) -> str:
    """Render JSON for human display. Never use this output for signing."""
    return json.dumps(value, indent=indent, ensure_ascii=False, sort_keys=False)
