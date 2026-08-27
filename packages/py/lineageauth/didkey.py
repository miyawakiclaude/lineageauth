"""Ed25519 `did:key` encoding and decoding.

CLAUDE.md D-003 makes Ed25519 `did:key` the only DID method the MVP accepts.
Any other method or multicodec is rejected outright rather than ignored: an
unrecognised key type must never silently resolve to "no signature required".

Layout:

    did:key:z<base58btc( 0xed 0x01 || raw_ed25519_public_key_32_bytes )>

CLAUDE.md 2.6 -- a valid did:key proves control of the matching private key.
It proves nothing about legal identity, affiliation, honesty, or safety.
"""

from __future__ import annotations

import base58

from lineageauth.errors import LineageAuthError, ReasonCode

DID_KEY_PREFIX = "did:key:"
MULTIBASE_BASE58BTC = "z"

# multicodec identifiers (unsigned-varint encoded)
ED25519_PUB_MULTICODEC = b"\xed\x01"
ED25519_PUBLIC_KEY_LENGTH = 32

# Recognised but deliberately unsupported, so the error can say *why*.
_KNOWN_UNSUPPORTED_MULTICODECS: dict[bytes, str] = {
    b"\xec\x01": "X25519 (key agreement, not signing)",
    b"\xe7\x01": "secp256k1",
    b"\x80\x24": "P-256",
    b"\x81\x24": "P-384",
    b"\x82\x24": "P-521",
    b"\x85\x24": "RSA",
}


class DidKeyError(LineageAuthError):
    """Raised when a DID string is malformed or uses an unsupported method."""

    reason = ReasonCode.MALFORMED


class UnsupportedDidMethodError(DidKeyError):
    """Raised for syntactically valid DIDs this protocol version cannot verify."""

    reason = ReasonCode.UNKNOWN_VERSION


def did_key_from_public_key(public_key: bytes) -> str:
    """Encode a raw 32-byte Ed25519 public key as a `did:key` string."""
    if len(public_key) != ED25519_PUBLIC_KEY_LENGTH:
        raise DidKeyError(
            f"Ed25519 public key must be {ED25519_PUBLIC_KEY_LENGTH} bytes, got {len(public_key)}"
        )
    multicodec = ED25519_PUB_MULTICODEC + public_key
    return DID_KEY_PREFIX + MULTIBASE_BASE58BTC + base58.b58encode(multicodec).decode("ascii")


def public_key_from_did_key(did: object) -> bytes:
    """Decode a `did:key` string to its raw 32-byte Ed25519 public key.

    Rejects DID URLs (fragments, paths, queries, parameters) so that
    `did:key:zAAA#zBBB` can never be treated as `did:key:zAAA`.
    """
    if not isinstance(did, str):
        raise DidKeyError("DID must be a string")
    if not did.startswith(DID_KEY_PREFIX):
        method = did.split(":")[1] if did.count(":") >= 2 else "<unparseable>"
        raise UnsupportedDidMethodError(
            f"only did:key is supported in protocol 0.1, got method '{method}'"
        )

    identifier = did[len(DID_KEY_PREFIX) :]
    for separator in ("#", "?", "/", ";"):
        if separator in identifier:
            raise DidKeyError(
                f"DID URL syntax is not accepted as a signer identity (found '{separator}')"
            )
    if not identifier.startswith(MULTIBASE_BASE58BTC):
        raise DidKeyError(
            f"did:key identifier must use multibase base58btc ('z' prefix), got '{identifier[:1]}'"
        )

    encoded = identifier[1:]
    if not encoded:
        raise DidKeyError("did:key identifier is empty")
    try:
        decoded = base58.b58decode(encoded)
    except Exception as exc:
        raise DidKeyError(f"did:key identifier is not valid base58btc: {exc}") from exc

    multicodec, key = decoded[:2], decoded[2:]
    if multicodec != ED25519_PUB_MULTICODEC:
        described = _KNOWN_UNSUPPORTED_MULTICODECS.get(multicodec)
        detail = f" ({described})" if described else ""
        raise UnsupportedDidMethodError(
            f"unsupported did:key multicodec 0x{multicodec.hex()}{detail}; "
            "protocol 0.1 verifies Ed25519 only"
        )
    if len(key) != ED25519_PUBLIC_KEY_LENGTH:
        raise DidKeyError(
            f"Ed25519 did:key must carry {ED25519_PUBLIC_KEY_LENGTH} key bytes, got {len(key)}"
        )

    # One key must have exactly one spelling; otherwise the same signer could
    # appear under two DIDs and defeat revocation or recovery-member matching.
    if did_key_from_public_key(key) != did:
        raise DidKeyError("did:key is not canonically encoded")
    return key


def is_did_key(value: object) -> bool:
    """True if `value` is a well-formed, supported Ed25519 did:key."""
    try:
        public_key_from_did_key(value)
    except LineageAuthError:
        return False
    return True
