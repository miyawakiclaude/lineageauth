"""Ed25519 signature verification and local signing.

CLAUDE.md 5 forbids home-grown signature math, so this delegates to
`cryptography`. CLAUDE.md 5 ("Separation") also keeps signing local-only:
nothing here reads a key from the network, and the CLI never accepts a raw
private seed as an argument (docs/16_API_SDK_CLI.md).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from lineageauth.canonical import b64u_decode, b64u_encode
from lineageauth.didkey import did_key_from_public_key, public_key_from_did_key
from lineageauth.errors import MalformedEventError

ED25519_SIGNATURE_LENGTH = 64
ED25519_SEED_LENGTH = 32


def verify_detached(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True when `signature` is a valid Ed25519 signature over `message`."""
    if len(signature) != ED25519_SIGNATURE_LENGTH:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_by_did(did: str, message: bytes, signature_b64u: str) -> bool:
    """Verify a base64url signature against the key encoded in a `did:key`."""
    public_key = public_key_from_did_key(did)
    return verify_detached(public_key, message, b64u_decode(signature_b64u))


class LocalSigner:
    """An in-memory Ed25519 signing key.

    For local development, test vectors, and offline operator tooling. Test
    material must be labelled unsafe (CLAUDE.md 2.1); real seeds never enter a
    prompt, a log, a fixture, or version control.
    """

    __slots__ = ("_private_key",)

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> LocalSigner:
        """Create a fresh random signing key."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> LocalSigner:
        """Load a signer from a 32-byte Ed25519 seed."""
        if len(seed) != ED25519_SEED_LENGTH:
            raise MalformedEventError(
                f"Ed25519 seed must be {ED25519_SEED_LENGTH} bytes, got {len(seed)}"
            )
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key."""
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def did(self) -> str:
        """This signer's `did:key` identifier."""
        return did_key_from_public_key(self.public_key_bytes)

    def sign(self, message: bytes) -> bytes:
        """Sign raw bytes."""
        return self._private_key.sign(message)

    def sign_b64u(self, message: bytes) -> str:
        """Sign raw bytes and return an unpadded base64url signature."""
        return b64u_encode(self.sign(message))

    def __repr__(self) -> str:
        # Never let a private key reach a log line or a traceback.
        return f"LocalSigner(did={self.did!r})"
