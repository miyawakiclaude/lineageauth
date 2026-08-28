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


def _same_document(left: Any, right: Any) -> bool:
    """Equal *and* of the same type, all the way down.

    `1 == 1.0` in Python, and that is exactly the equality this must not use.
    """
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _same_document(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_document(a, b) for a, b in zip(left, right, strict=True)
        )
    return bool(left == right)


def assert_canonical_payload(payload: Any) -> None:
    """Refuse a payload that is not already in the form its own bytes decode to.

    RFC 8785 normalises numbers: `2.0` canonicalises to `2`. So two documents
    that Python holds as different values -- `int` and `float` -- produce the
    same JCS bytes, the same preimage, the same signature and the same event id.
    A reader that pulls a field out of the *parsed* document therefore sees a
    value nobody signed, while every cryptographic check still passes.

    That is not theoretical. A third party holding no key can rewrite one
    character of a signed `recovery.policy` -- `"threshold":2` to
    `"threshold":2.0` -- and produce an event whose signature verifies, whose id
    is unchanged, and whose threshold no longer parses. The policy stops working
    and nothing reports a fault. Refusal is the attack.

    The round trip catches the whole family at once: `1.0`/`1`, `-0.0`/`0`,
    `1e2`/`100`. If re-parsing the canonical bytes yields a different document,
    the payload had a second spelling, and a second spelling of one event id is
    the bug.
    """
    from lineageauth import jsonio

    if not _same_document(payload, jsonio.loads(jcs(payload))):
        raise MalformedEventError(
            "payload is not in canonical form: re-parsing its own JCS bytes yields a "
            "different document, so two spellings would share one event id"
        )


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
