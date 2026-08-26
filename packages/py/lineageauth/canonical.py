"""Canonicalization, signing preimage, and event identifiers.

CLAUDE.md 5 ("Cryptography") pins these and forbids home-grown canonical JSON,
so RFC 8785 canonicalization is delegated to the `rfc8785` library.

    preimage  = b"lineageauth:event:v1\n" + JCS(payload)
    event id  = "sha256:" + lowercase_hex(SHA-256(preimage))

The payload passed here MUST be the payload exactly as received. Never
re-serialize through a schema model first: dropping or reordering a field the
model does not know about would change the bytes the issuer actually signed.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

import rfc8785

from lineageauth.errors import MalformedEventError

EVENT_PREIMAGE_PREFIX = b"lineageauth:event:v1\n"
EVENT_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def jcs(payload: Any) -> bytes:
    """Return RFC 8785 canonical JSON bytes for `payload`."""
    try:
        return rfc8785.dumps(payload)
    except Exception as exc:  # rfc8785 raises on NaN/Infinity, cycles, bad keys
        raise MalformedEventError(f"payload is not JCS-canonicalizable: {exc}") from exc


def preimage(payload: Any) -> bytes:
    """Return the exact byte string that an Ed25519 proof signs."""
    if not isinstance(payload, dict):
        raise MalformedEventError("event payload must be a JSON object")
    return EVENT_PREIMAGE_PREFIX + jcs(payload)


def compute_event_id(payload: Any) -> str:
    """Return `sha256:<64 lowercase hex>` for `payload`."""
    return "sha256:" + hashlib.sha256(preimage(payload)).hexdigest()


def is_event_id(value: object) -> bool:
    """True if `value` is a syntactically valid event id."""
    return isinstance(value, str) and EVENT_ID_RE.fullmatch(value) is not None


def sha256_content_id(data: bytes) -> str:
    """Content address for artifact bytes (docs/07_EVIDENCE_ARTIFACTS.md)."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def b64u_encode(data: bytes) -> str:
    """base64url without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(value: str) -> bytes:
    """Decode base64url without padding.

    Rejects padding characters and any alphabet outside base64url so that a
    signature has exactly one valid encoding. Two spellings of one signature
    would let an attacker mutate an event without invalidating its proof.
    """
    if not isinstance(value, str):
        raise MalformedEventError("base64url value must be a string")
    if "=" in value:
        raise MalformedEventError("base64url value must not be padded")
    if re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        raise MalformedEventError("base64url value contains characters outside the alphabet")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise MalformedEventError(f"invalid base64url value: {exc}") from exc
    # Reject non-canonical trailing bits: re-encoding must reproduce the input.
    if b64u_encode(decoded) != value:
        raise MalformedEventError("base64url value is not canonically encoded")
    return decoded
