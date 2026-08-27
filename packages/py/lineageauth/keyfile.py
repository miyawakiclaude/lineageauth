"""An Ed25519 signing key, encrypted at rest with a passphrase.

This is operator tooling, deliberately kept at arm's length from the protocol.
Nothing in the core reads it, the API cannot reach it, and the verifier neither
needs nor accepts a private key -- verification is a public-key operation and
always was.

The rules this file exists to keep, and why each one matters:

*The seed never becomes a string anybody can read.* Not printed, not logged, not
returned, not put in an argument. `CLAUDE.md` 2.1 forbids it, and the reason is
that every one of those places is somewhere a seed gets copied to by accident --
a shell history, a CI log, a screenshot.

*The passphrase is never an argument either.* A command line is visible in the
process table and lands in shell history. It is read from a prompt or from
stdin, and nowhere else.

*Encrypted at rest, always.* A plaintext key on a development machine is the
failure this project has already decided not to have. scrypt turns the
passphrase into a key, ChaCha20-Poly1305 encrypts the seed under it, and the
DID travels in the clear because a DID is public by construction.

*Losing the passphrase is not losing the identity, if you plan ahead.* `did:key`
has no revocation, but this protocol has succession: publish a
`recovery.policy` while the key still works and a quorum can move the lineage to
a new root later. That is the entire point of `docs/05`, and it only helps
somebody who did it in advance.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from lineageauth.canonical import b64u_decode, b64u_encode
from lineageauth.crypto import LocalSigner
from lineageauth.didkey import did_key_from_public_key
from lineageauth.errors import LineageAuthError, MalformedEventError

FORMAT = "lineageauth-keyfile-v1"

SALT_BYTES = 16
NONCE_BYTES = 12

# scrypt at these parameters costs roughly 100 MB and a noticeable fraction of a
# second. That is the point: it is the only thing standing between a stolen file
# and the identity in it, and a fast KDF there is not a KDF.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

# The associated data binds the ciphertext to the DID printed beside it, so a
# file whose public half was swapped fails to decrypt rather than producing a
# key that signs for a different identity.
AAD_PREFIX = b"lineageauth:keyfile:v1:"

MIN_PASSPHRASE = 12


class KeyfileError(LineageAuthError):
    """The key file is unusable, or the passphrase is wrong."""


@dataclass(frozen=True, slots=True)
class Keyfile:
    """The public half of a key file. There is deliberately no private half here.

    Holding the DID and the path is enough for everything except signing, and
    signing loads the seed, uses it, and drops it inside one function.
    """

    did: str
    path: Path

    def to_dict(self) -> dict[str, Any]:
        return {"did": self.did, "path": str(self.path)}


def _derive(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < MIN_PASSPHRASE:
        raise KeyfileError(
            f"a passphrase of at least {MIN_PASSPHRASE} characters is required; this file "
            "is the only thing protecting an identity that cannot be revoked"
        )
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def create(path: Path, passphrase: str) -> Keyfile:
    """Generate a fresh signing key and write it encrypted.

    Refuses to overwrite. A key file that can be replaced by a typo is a key
    file that will be, and the old identity does not come back.
    """
    if path.exists():
        raise KeyfileError(
            f"{path} already exists. Refusing to overwrite: the identity in it cannot "
            "be recovered once replaced"
        )

    # The seed is generated here rather than pulled out of a LocalSigner,
    # because LocalSigner deliberately has no way to hand one back. Adding an
    # accessor for the convenience of this one function would put a seed-shaped
    # hole in the class every other caller shares.
    seed = secrets.token_bytes(32)
    signer = LocalSigner.from_seed(seed)
    did = did_key_from_public_key(signer.public_key_bytes)

    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = _derive(passphrase, salt)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, seed, AAD_PREFIX + did.encode("ascii"))

    document = {
        "format": FORMAT,
        "did": did,
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
        "salt": b64u_encode(salt),
        "nonce": b64u_encode(nonce),
        "ciphertext": b64u_encode(ciphertext),
        "note": (
            "The private key in this file is encrypted with a passphrase. Losing the "
            "passphrase loses the identity: did:key has no revocation. Publish a "
            "recovery.policy while this key still works, so a quorum can move the "
            "lineage to a new root later."
        ),
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    # Written with 0600 from the start rather than chmod'd afterwards, so the
    # file is never briefly world-readable. On Windows the mode is advisory and
    # the real protection is the passphrase, which is why there is one.
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")

    return Keyfile(did=did, path=path)


def read_did(path: Path) -> str:
    """The DID in a key file, without touching the encrypted half."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KeyfileError(f"{path} is not a readable key file: {exc}") from exc
    if document.get("format") != FORMAT:
        raise KeyfileError(f"{path} is not a {FORMAT} file")
    did = document.get("did")
    if not isinstance(did, str):
        raise KeyfileError(f"{path} carries no DID")
    return did


def unlock(path: Path, passphrase: str) -> LocalSigner:
    """Decrypt the seed and return a signer.

    The seed exists as bytes for as long as this call takes and is never
    returned, printed or stored. Callers get something that can sign, not
    something that can be copied.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KeyfileError(f"{path} is not a readable key file: {exc}") from exc
    if document.get("format") != FORMAT:
        raise KeyfileError(f"{path} is not a {FORMAT} file")

    did = document.get("did")
    if not isinstance(did, str):
        raise KeyfileError("the key file carries no DID")

    try:
        salt = b64u_decode(document["salt"])
        nonce = b64u_decode(document["nonce"])
        ciphertext = b64u_decode(document["ciphertext"])
    except (KeyError, MalformedEventError) as exc:
        raise KeyfileError(f"the key file is malformed: {exc}") from exc

    key = _derive(passphrase, salt)
    try:
        seed = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, AAD_PREFIX + did.encode("ascii"))
    except InvalidTag as exc:
        # One message for both cases on purpose. Distinguishing "wrong
        # passphrase" from "tampered file" tells an attacker which one they are
        # making progress on.
        raise KeyfileError(
            "could not decrypt: the passphrase is wrong, or the file has been altered"
        ) from exc

    signer = LocalSigner.from_seed(seed)
    if did_key_from_public_key(signer.public_key_bytes) != did:
        raise KeyfileError(
            "the decrypted key does not match the DID this file claims; do not use it"
        )
    return signer


__all__ = [
    "FORMAT",
    "Keyfile",
    "KeyfileError",
    "b64u_decode",
    "b64u_encode",
    "create",
    "read_did",
    "unlock",
]
