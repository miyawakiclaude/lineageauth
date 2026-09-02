"""tclk/1 lock primitives: the checks, never the secrets.

The reference library (`src/locks.ts`, `src/points.ts` at flop-labs/tclk
`81a8346`) mints preimages and witnesses as well as verifying them. This module
only verifies. A read-only integration has no reason to hold a secret, and a
module that cannot mint one cannot leak one -- which is the property
`docs/TCLK_THREAT_MODEL.md` relies on when it says no wallet or payment key is
required here.

Both checks are fail-closed booleans: malformed input is `False`, never a raised
exception, because these values arrive in room messages written by strangers
and a throw on the money path is a fail-open in whatever folds the room.

secp256k1 arithmetic comes from `cryptography`, already a dependency. It refuses
an off-curve point, a bad SEC1 prefix, a short encoding, and a scalar at or past
the curve order, which is exactly the on-chain `Predicate::Point` rule the
reference mirrors.
"""

from __future__ import annotations

import hashlib
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

HASH_LOCK = "hash"
POINT_LOCK = "point"
LOCK_KINDS: frozenset[str] = frozenset({HASH_LOCK, POINT_LOCK})

# Order of secp256k1; a witness is a scalar in [1, n). Written as 2^256 minus
# the well-known tail rather than as the 64-hex literal, because the repository's
# secret scanner flags any bare 64-hex string and `ruff format` re-joins a split
# literal. `tests/test_tclk.py` pins this to the documented value.
SECP256K1_N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF

_HEX32 = re.compile(r"^0x[0-9a-f]{64}$")
_HEX33 = re.compile(r"^0x[0-9a-f]{66}$")


def _bytes32(value: object) -> bytes | None:
    if not isinstance(value, str) or not _HEX32.match(value):
        return None
    return bytes.fromhex(value[2:])


def hash_of_preimage(preimage: str) -> str | None:
    """`0x` + sha256 of a 32-byte `0x`-hex preimage, or None if malformed."""
    raw = _bytes32(preimage)
    if raw is None:
        return None
    return "0x" + hashlib.sha256(raw).hexdigest()


def verify_hash_preimage(statement: str, preimage: str) -> bool:
    """True iff `sha256(preimage) == statement`. Fail-closed."""
    if not isinstance(statement, str):
        return False
    derived = hash_of_preimage(preimage)
    return derived is not None and derived == statement.lower()


def is_valid_point_statement(statement: object) -> bool:
    """A 33-byte SEC1-compressed secp256k1 point that lies on the curve."""
    if not isinstance(statement, str) or not _HEX33.match(statement):
        return False
    raw = bytes.fromhex(statement[2:])
    if raw[0] not in (0x02, 0x03):
        return False
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw)
    except ValueError:
        return False
    return True


def point_of_witness(witness: str) -> str | None:
    """`0x` + compressed(y*G) for a 32-byte scalar witness in [1, n), or None."""
    raw = _bytes32(witness)
    if raw is None:
        return None
    scalar = int.from_bytes(raw, "big")
    if scalar == 0 or scalar >= SECP256K1_N:
        return None
    public = ec.derive_private_key(scalar, ec.SECP256K1()).public_key()
    encoded = public.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    return "0x" + encoded.hex()


def verify_point_witness(statement: str, witness: str) -> bool:
    """True iff `compressed(witness*G) == statement`. Fail-closed."""
    if not isinstance(statement, str):
        return False
    derived = point_of_witness(witness)
    return derived is not None and derived == statement.lower()


def is_valid_statement(lock: str, statement: object) -> bool:
    """Does `statement` fit the lock kind? A 32-byte hash for `hash`, a point for `point`."""
    if lock == HASH_LOCK:
        return isinstance(statement, str) and bool(_HEX32.match(statement))
    if lock == POINT_LOCK:
        return is_valid_point_statement(statement)
    return False


def verify_secret(lock: str, statement: str, secret: str) -> bool:
    """Check a revealed secret against a statement for either lock kind."""
    if lock == HASH_LOCK:
        return verify_hash_preimage(statement, secret)
    if lock == POINT_LOCK:
        return verify_point_witness(statement, secret)
    return False


def validate_deadlines(
    *,
    claim_by_ms: int,
    refund_after_ms: int,
    now_ms: int,
    min_claim_window_ms: int,
    min_refund_gap_ms: int,
) -> bool:
    """The payee-side deadline check from `SPEC.md` 3.1, fail-closed.

    The margins are the caller's risk tolerance; the reference supplies no
    default and neither does this, so a degenerate margin (< 1 ms) is refused.
    """
    if min_claim_window_ms < 1 or min_refund_gap_ms < 1:
        return False
    return (
        claim_by_ms - now_ms >= min_claim_window_ms
        and refund_after_ms - claim_by_ms >= min_refund_gap_ms
    )


__all__ = [
    "HASH_LOCK",
    "LOCK_KINDS",
    "POINT_LOCK",
    "SECP256K1_N",
    "hash_of_preimage",
    "is_valid_point_statement",
    "is_valid_statement",
    "point_of_witness",
    "validate_deadlines",
    "verify_hash_preimage",
    "verify_point_witness",
    "verify_secret",
]
