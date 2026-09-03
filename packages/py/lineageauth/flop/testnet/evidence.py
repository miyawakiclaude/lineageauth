"""Turning an execution receipt into LineageAuth evidence, and stopping there.

Two artifacts and one attestation, all unsigned drafts. Signing is the holder's
act and nothing here submits anything, exactly as `adapters/tclk/evidence.py`
does for deal frames.

The predicate is `flop.testnet.inference` and it is **not** registered in
`catalog.KNOWN_PREDICATES`. Registering one is a protocol vocabulary change this
integration does not make; an unregistered predicate stays displayable and can
never silently affect a ranking, which is the right standing for a claim about a
network that does not exist yet.

Synthetic evidence is marked twice over. The wrapper carries `synthetic: true`
and the simulation banner, and the attestation itself carries
`reasonCode: SYNTHETIC_SIMULATION_NO_NETWORK_ACTION`, so the marker survives
into the signed event rather than living only in the envelope around it. The
event payloads themselves are exactly what the core builders produce -- no extra
keys are injected into a signed object, because a payload this layer invented a
field for is a payload the core verifier has never seen.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from lineageauth.builders import build_artifact_register, build_attestation
from lineageauth.flop.model import SIMULATION_BANNER, SYNTHETIC_BANNER, VerificationState
from lineageauth.flop.testnet.receipts import FlopTestnetExecutionReceipt
from lineageauth.flop.testnet.spend import format_amount

INFERENCE_PREDICATE = "flop.testnet.inference"
"""Unregistered by design; see the module docstring."""

REQUEST_MEDIA_TYPE = "application/json; profile=flop.testnet.request/0.1"
RESPONSE_MEDIA_TYPE = "application/json; profile=flop.testnet.response/0.1"

SYNTHETIC_REASON_CODE = "SYNTHETIC_SIMULATION_NO_NETWORK_ACTION"

PROVES: tuple[str, ...] = (
    "these request bytes were prepared and approved for this exact destination",
    "an answer with this hash was received by this process at the stated instant",
)

DOES_NOT_PROVE: tuple[str, ...] = (
    "that the inference was actually performed by anyone",
    "that the result is correct, useful, or original",
    "that any test FLOP moved on any ledger",
    "that the counterparty is who the response says it is",
)


@dataclass(frozen=True, slots=True)
class FlopEvidenceDraft:
    """Unsigned payloads plus the honest description of what they show."""

    receipt: FlopTestnetExecutionReceipt
    artifacts: tuple[dict[str, Any], ...]
    attestation: dict[str, Any]
    verification_state: VerificationState

    @property
    def synthetic(self) -> bool:
        return self.receipt.synthetic

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "predicate": INFERENCE_PREDICATE,
            "predicateRegistered": False,
            "artifacts": [dict(payload) for payload in self.artifacts],
            "attestation": dict(self.attestation),
            "verificationState": str(self.verification_state),
            "signed": False,
            "submitted": False,
            "synthetic": self.receipt.synthetic,
            "simulation": self.receipt.simulation,
            "proves": list(PROVES),
            "doesNotProve": list(DOES_NOT_PROVE),
        }
        if self.receipt.synthetic:
            body["banner"] = SYNTHETIC_BANNER
        if self.receipt.simulation:
            body["simulationBanner"] = SIMULATION_BANNER
        return body


def draft_request_artifact(
    receipt: FlopTestnetExecutionReceipt,
    *,
    lineage: str,
    issued_at: datetime,
    byte_length: int | None = None,
) -> dict[str, Any]:
    """An `artifact.register` for the exact request bytes that were approved."""
    return build_artifact_register(
        lineage=lineage,
        artifact_id=receipt.request_hash,
        media_type=REQUEST_MEDIA_TYPE,
        byte_length=byte_length,
        created_by=receipt.subject_did,
        issued_at=issued_at,
    )


def draft_response_artifact(
    receipt: FlopTestnetExecutionReceipt,
    *,
    lineage: str,
    issued_at: datetime,
    byte_length: int | None = None,
) -> dict[str, Any] | None:
    """An `artifact.register` for the answer, when there was one.

    `created_by` is left unset. Whoever produced the answer is exactly what this
    process cannot check, and naming the subject as its author would be a claim
    the receipt does not support.
    """
    if receipt.response_hash is None:
        return None
    return build_artifact_register(
        lineage=lineage,
        artifact_id=receipt.response_hash,
        media_type=RESPONSE_MEDIA_TYPE,
        byte_length=byte_length,
        source_refs=[receipt.request_hash],
        issued_at=issued_at,
    )


def draft_inference_attestation(
    receipt: FlopTestnetExecutionReceipt,
    *,
    lineage: str,
    issuer: str,
    issued_at: datetime,
) -> dict[str, Any]:
    """One DID's signed statement that it observed this execution.

    `value` is the verification state rather than a success flag, so a
    partially-verified execution attests to being partially verified. A claim
    that says "done" when three fields were missing is worse than no claim.
    """
    evidence_refs = [receipt.request_hash]
    if receipt.response_hash is not None:
        evidence_refs.append(receipt.response_hash)
    return build_attestation(
        lineage=lineage,
        issuer=issuer,
        subject_ref=receipt.request_hash,
        predicate=INFERENCE_PREDICATE,
        value=str(receipt.verification_state),
        reason_code=SYNTHETIC_REASON_CODE if receipt.synthetic else None,
        evidence_refs=evidence_refs,
        issued_at=issued_at,
    )


def draft_evidence(
    receipt: FlopTestnetExecutionReceipt,
    *,
    lineage: str,
    issuer: str,
    issued_at: datetime,
    request_bytes: int | None = None,
    response_bytes: int | None = None,
) -> FlopEvidenceDraft:
    """Everything an execution becomes, unsigned and unsubmitted."""
    artifacts: list[dict[str, Any]] = [
        draft_request_artifact(
            receipt, lineage=lineage, issued_at=issued_at, byte_length=request_bytes
        )
    ]
    response_artifact = draft_response_artifact(
        receipt, lineage=lineage, issued_at=issued_at, byte_length=response_bytes
    )
    if response_artifact is not None:
        artifacts.append(response_artifact)
    return FlopEvidenceDraft(
        receipt=receipt,
        artifacts=tuple(artifacts),
        attestation=draft_inference_attestation(
            receipt, lineage=lineage, issuer=issuer, issued_at=issued_at
        ),
        verification_state=receipt.verification_state,
    )


def inference_summary(receipts: tuple[FlopTestnetExecutionReceipt, ...]) -> dict[str, Any]:
    """The passport's inference section: observed counts, never a score.

    An empty tuple does not report zero spend. There is no testnet, so the
    honest statement is that the category is not yet available, and
    `coverage.CoverageState.NOT_YET_AVAILABLE` says exactly that.
    """
    total: Decimal | None = None
    for item in receipts:
        amount = item.observed_spend
        if amount is None:
            continue
        total = amount if total is None else total + amount
    return {
        "observedRequests": len(receipts),
        "evidenceSupported": sum(1 for item in receipts if item.fully_verified),
        "observedSpend": None if total is None else format_amount(total),
        "uniqueResults": len({item.response_hash for item in receipts if item.result_available}),
        "lastActivity": (
            None if not receipts else max(item.completed_at for item in receipts).isoformat()
        ),
        "containsSynthetic": any(item.synthetic for item in receipts),
        "isAirdropScore": False,
    }


__all__ = [
    "DOES_NOT_PROVE",
    "INFERENCE_PREDICATE",
    "PROVES",
    "REQUEST_MEDIA_TYPE",
    "RESPONSE_MEDIA_TYPE",
    "SYNTHETIC_REASON_CODE",
    "FlopEvidenceDraft",
    "draft_evidence",
    "draft_inference_attestation",
    "draft_request_artifact",
    "draft_response_artifact",
    "inference_summary",
]
