"""What an execution produced, and how much of it was actually checked.

`verification_state` is the field that matters. A response arriving is not a
receipt; a receipt is not proof the inference was performed; and none of it is
proof the *result* is true. So a response with no network receipt reference
comes back `partially-verified` with a reason, which is acceptance L, and the
console shows that rather than a green tick.

Observed spend is read from the response, never from the quote. A quote is what
the network said it would charge; recording it as spend would be a number this
tool made up, and `docs/FLOP_DATA_MODEL` is explicit that the passport reports
observed activity only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from lineageauth.flop.model import (
    SIMULATION_BANNER,
    SYNTHETIC_BANNER,
    VerificationState,
)
from lineageauth.flop.testnet.spend import format_amount, to_amount
from lineageauth.timeutil import format_instant

RECEIPT_PROFILE = "flop.testnet.receipt/0.1"

NOT_PROOF_NOTE = (
    "A receipt records that a request was made and an answer came back. It does not "
    "make the answer true, and it is not proof that any work was useful."
)

# On every receipt, including a complete one. The fields a response fills in are
# the counterparty's account of its own behaviour, so a full response is a full
# account and not a confirmed one.
SELF_REPORTED_REASON = (
    "every field in this receipt is the endpoint's own statement about itself, including "
    "the observed spend; nothing here was checked against a party other than the one "
    "being checked"
)


@dataclass(frozen=True, slots=True)
class FlopTestnetExecutionReceipt:
    """One execution, described by hashes and by what was not confirmed."""

    action_id: str
    subject_did: str
    network: str
    action_type: str
    endpoint_id: str
    request_hash: str
    response_hash: str | None
    observed_spend: Decimal | None
    started_at: datetime
    completed_at: datetime
    source_snapshot_id: str
    verification_state: VerificationState
    quote_amount: Decimal | None = None
    model: str | None = None
    miner: str | None = None
    validator: str | None = None
    transaction_ref: str | None = None
    result_available: bool = False
    synthetic: bool = False
    simulation: bool = False
    unverified_because: tuple[str, ...] = ()

    @property
    def fully_verified(self) -> bool:
        return self.verification_state is VerificationState.VERIFIED

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "profile": RECEIPT_PROFILE,
            "actionId": self.action_id,
            "subjectDid": self.subject_did,
            "network": self.network,
            "actionType": self.action_type,
            "endpointId": self.endpoint_id,
            "requestHash": self.request_hash,
            "responseHash": self.response_hash,
            "observedSpend": (
                None if self.observed_spend is None else format_amount(self.observed_spend)
            ),
            "quote": None if self.quote_amount is None else format_amount(self.quote_amount),
            "model": self.model,
            "miner": self.miner,
            "validator": self.validator,
            "transactionOrReceiptRef": self.transaction_ref,
            "startedAt": format_instant(self.started_at),
            "completedAt": format_instant(self.completed_at),
            "sourceSnapshotId": self.source_snapshot_id,
            "verificationState": str(self.verification_state),
            "resultAvailable": self.result_available,
            "usefulResultProduced": self.result_available,
            "synthetic": self.synthetic,
            "simulation": self.simulation,
            "unverifiedBecause": list(self.unverified_because),
            "note": NOT_PROOF_NOTE,
        }
        if self.synthetic:
            body["banner"] = SYNTHETIC_BANNER
        if self.simulation:
            body["simulationBanner"] = SIMULATION_BANNER
        return body


def receipt_from_response(
    payload: Mapping[str, Any],
    *,
    action_id: str,
    subject_did: str,
    network: str,
    action_type: str,
    endpoint_id: str,
    request_hash: str,
    response_hash: str,
    started_at: datetime,
    completed_at: datetime,
    source_snapshot_id: str,
    quote_amount: Decimal | None = None,
    model: str | None = None,
    synthetic: bool = False,
    simulation: bool = False,
) -> FlopTestnetExecutionReceipt:
    """Read a response into a receipt. Nothing read here reaches `VERIFIED`.

    Three things can be absent, and each one costs the same amount of certainty:
    a network receipt reference, an observed spend, and a result. Each missing
    one is recorded as its own reason so the UI can say which.

    Present ones cost nothing back. Every field in this payload is the far side
    describing its own behaviour -- including `observedSpend`, which is the
    counterparty stating what it charged -- and a counterparty's own statement
    is the weakest evidence this codebase recognises, not the strongest. So the
    ceiling is `PARTIALLY_VERIFIED` and there is no path from a response to
    `VERIFIED`: that word is reserved for something checked against a source
    that is not the party being checked. `PublicEvidenceAdapter` refuses to say
    `verified` for a URL it did not re-fetch; a receipt saying it about the
    endpoint's own arithmetic would be the same mistake with more at stake.
    """
    missing: list[str] = []
    raw_ref = payload.get("receiptRef") or payload.get("transactionRef")
    transaction_ref = raw_ref if isinstance(raw_ref, str) and raw_ref else None
    if transaction_ref is None:
        missing.append(
            "the response carries no network receipt reference, so the execution cannot be "
            "checked against anything outside this process"
        )
    observed: Decimal | None = None
    raw_spend = payload.get("observedSpend")
    if isinstance(raw_spend, str | int):
        observed = to_amount(raw_spend, field_name="observedSpend")
    else:
        missing.append("the response states no observed spend, so none is recorded")
    raw_result = payload.get("result")
    result_available = isinstance(raw_result, str) and bool(raw_result)
    if not result_available:
        missing.append("the response carries no result, so no useful output was produced")
    miner = payload.get("miner")
    validator = payload.get("validator")
    missing.append(SELF_REPORTED_REASON)
    state = VerificationState.PARTIALLY_VERIFIED
    return FlopTestnetExecutionReceipt(
        action_id=action_id,
        subject_did=subject_did,
        network=network,
        action_type=action_type,
        endpoint_id=endpoint_id,
        request_hash=request_hash,
        response_hash=response_hash,
        observed_spend=observed,
        started_at=started_at,
        completed_at=completed_at,
        source_snapshot_id=source_snapshot_id,
        verification_state=state,
        quote_amount=quote_amount,
        model=model if isinstance(model, str) else None,
        miner=miner if isinstance(miner, str) else None,
        validator=validator if isinstance(validator, str) else None,
        transaction_ref=transaction_ref,
        result_available=result_available,
        synthetic=synthetic,
        simulation=simulation,
        unverified_because=tuple(missing),
    )


def render_receipt(receipt: FlopTestnetExecutionReceipt) -> str:
    """The completion panel from directive 15, ASCII only for a cp932 console."""
    spend = (
        "not stated by the response"
        if receipt.observed_spend is None
        else format_amount(receipt.observed_spend)
    )
    lines = [
        "INFERENCE COMPLETE",
        "",
        f"Status:            {receipt.verification_state}",
        f"Test FLOP spent:   {spend}",
        f"Result:            {'Received' if receipt.result_available else 'Not received'}",
        f"Request:           {receipt.request_hash}",
        f"Response:          {receipt.response_hash or 'none'}",
        f"Network receipt:   {receipt.transaction_ref or 'none'}",
        f"Action:            {receipt.action_id}",
    ]
    if receipt.simulation:
        lines.insert(1, SIMULATION_BANNER)
    if receipt.unverified_because:
        lines.append("")
        lines.append("Not verified:")
        lines.extend(f"  - {reason}" for reason in receipt.unverified_because)
    lines.append("")
    lines.append(NOT_PROOF_NOTE)
    return "\n".join(lines)


__all__ = [
    "NOT_PROOF_NOTE",
    "RECEIPT_PROFILE",
    "SELF_REPORTED_REASON",
    "FlopTestnetExecutionReceipt",
    "receipt_from_response",
    "render_receipt",
]
