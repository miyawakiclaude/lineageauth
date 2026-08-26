"""Deterministic UNSAFE test keys.

!!  THIS IS NOT SAFE KEY MATERIAL.  !!

Every seed here is derived from a public constant and a public label, so anyone
reading this file can reproduce every private key it produces. That is the
point: conformance vectors have to be reproducible by an independent
implementation. It also means these keys must never sign anything real.

CLAUDE.md 2.1 permits disposable deterministic test keys in test vectors only,
labelled as unsafe test material.
"""

from __future__ import annotations

import hashlib
from functools import cache

from lineageauth.crypto import LocalSigner

UNSAFE_SEED_DOMAIN = b"lineageauth:unsafe-test-key:v1:"


def unsafe_seed(label: str) -> bytes:
    """Derive a reproducible 32-byte Ed25519 seed. UNSAFE by construction."""
    return hashlib.sha256(UNSAFE_SEED_DOMAIN + label.encode("utf-8")).digest()


@cache
def unsafe_signer(label: str) -> LocalSigner:
    """Return the UNSAFE test signer for `label`."""
    return LocalSigner.from_seed(unsafe_seed(label))


# Named roles used across the suite and the published vectors.
ROOT_A = "root-a"
ROOT_B = "root-b"
RECOVERY_1 = "recovery-1"
RECOVERY_2 = "recovery-2"
RECOVERY_3 = "recovery-3"
AGENT_1 = "agent-1"
OUTSIDER = "outsider"
