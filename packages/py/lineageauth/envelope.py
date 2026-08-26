"""Signed event envelope.

docs/02_LAP_CORE.md:

    {"payload": {...}, "proofs": [{"alg": "Ed25519", "signer": "did:key:...",
                                   "sig": "<base64url-no-padding>"}]}

Proofs sit outside the payload, so a proof signs the payload only. Several
proofs may accompany one payload -- recovery quorums (docs/05) need exactly
that. The envelope keeps `payload` as the raw parsed object; canonicalization
always runs over those bytes, never over a schema round-trip.
"""

from __future__ import annotations

from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

from lineageauth import jsonio
from lineageauth.canonical import compute_event_id, preimage
from lineageauth.errors import MalformedEventError

ALG_ED25519 = "Ed25519"


class Proof(BaseModel):
    """One signature over an event payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # `alg` is typed loosely on purpose: an unrecognised algorithm must surface
    # as UNKNOWN_VERSION from the verifier, not as a parse failure that a
    # caller might mistake for a malformed document.
    alg: str
    signer: str
    sig: str


class Envelope(BaseModel):
    """A payload plus the proofs asserted over it."""

    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any]
    proofs: list[Proof] = Field(default_factory=list)

    @classmethod
    def from_json(cls, text: str | bytes) -> Self:
        """Parse an envelope from JSON text, rejecting duplicate object keys."""
        parsed = jsonio.loads(text)
        if not isinstance(parsed, dict):
            raise MalformedEventError("envelope must be a JSON object")
        try:
            return cls.model_validate(parsed)
        except MalformedEventError:
            raise
        except Exception as exc:
            raise MalformedEventError(
                f"envelope does not match the LAP envelope shape: {exc}"
            ) from exc

    @property
    def event_id(self) -> str:
        """`sha256:<64 lowercase hex>` over this envelope's signing preimage."""
        return compute_event_id(self.payload)

    @property
    def signing_bytes(self) -> bytes:
        """The exact bytes each proof signs."""
        return preimage(self.payload)

    @property
    def event_type(self) -> str | None:
        """The declared event type, or None when absent/not a string."""
        declared = self.payload.get("type")
        return declared if isinstance(declared, str) else None

    def signer_dids(self) -> list[str]:
        """Signer DIDs in proof order, duplicates preserved."""
        return [proof.signer for proof in self.proofs]

    def to_json(self, *, indent: int | None = 2) -> str:
        """Render for display or storage. Not a canonicalization."""
        return jsonio.dumps(
            {"payload": self.payload, "proofs": [p.model_dump() for p in self.proofs]},
            indent=indent,
        )
