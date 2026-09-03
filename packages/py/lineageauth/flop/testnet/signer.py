"""Signing, arranged so this process never gains custody of a key.

Directive 11: no seed phrases, no wallet private keys, no raw signing material.
The way to keep that true through future edits is not a rule in a document but
the absence of a parameter -- nothing in this package takes a seed, a key, a
keyfile path or a passphrase, and `tests/test_flop_testnet_signer.py` walks the
package's syntax tree to say so.

`NoSigner` is the only implementation shipped, and it refuses. That is not a
placeholder for a real one to be dropped in here later: when the official
testnet publishes a signing scheme, the signer that satisfies this protocol will
live wherever the key already lives -- an external process, an OS keychain, a
hardware device -- and this package will call it and never see the material.

`LocalSigner` from `lineageauth.crypto` is deliberately not wired in. It holds a
seed in memory, which is right for signing one's own lineage events in a CLI and
wrong for a long-lived web process that also talks to a network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from lineageauth.flop.model import TestnetFailure, TestnetRefusal, TestnetRefusedError


@dataclass(frozen=True, slots=True)
class NoSigner:
    """The default. Announces itself, and refuses to sign.

    Refusing rather than returning empty bytes: an empty signature would travel
    somewhere and be rejected there, and the reason would come back from a
    network instead of from the line that knew it.
    """

    reason: str = (
        "no signer is configured, and this process does not hold signing material; "
        "when the official FLOP testnet publishes a signing scheme, the key stays "
        "outside this process"
    )

    @property
    def signer_id(self) -> str:
        return "none"

    @property
    def available(self) -> bool:
        return False

    @property
    def holds_private_keys(self) -> bool:
        """Custody, as a property of the signer rather than a constant elsewhere.

        The API used to answer `walletCustody` with a literal `False` next to a
        signer that already knew the answer. One fact, two places to edit, and
        the header is the one nobody would remember.
        """
        return False

    def sign(self, data: bytes) -> bytes:
        raise TestnetRefusedError(
            TestnetRefusal(
                failure=TestnetFailure.SIGNER_NOT_CONFIGURED,
                detail=f"{self.reason} ({len(data)} bytes were not signed)",
                stage="network",
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "signerId": self.signer_id,
            "available": self.available,
            "custody": "none",
            "holdsPrivateKeys": self.holds_private_keys,
            "reason": self.reason,
        }


__all__ = ["NoSigner"]
