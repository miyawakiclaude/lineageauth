"""Nine checks in a fixed order, and the fact that the network is the last one.

Directive 10 lists eight steps and says "fail closed at every step". The order
is the security property, not the presence of the checks: a spend policy
consulted after the request has been sent is a report, and an authority check
made before the request was validated has verified authority over something
other than what will be transmitted.

So the order is a constant, `STAGES`, and a test walks it. The phase gate is
first because it is the only check that can refuse without reading anything
else, and the network is ninth because nothing may reach it that the previous
eight have not agreed to.

The client is a required argument. There is no module-level default and no
lazily constructed one, so a caller who forgot to decide what transport this
execution uses gets a `TypeError` at the call site rather than a connection.

A simulated action skips the phase gate, and only a simulated action can: the
executor checks the *registry's* entry, not the prepared action's claim about
itself, and the registry will only agree for an entry whose origin is
`testnet.simulation.invalid` -- a name RFC 6761 guarantees cannot resolve. A
prepared action that lies about being a simulation is refused at stage three.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any

from lineageauth.approval import SpentReceiptStore, check_execution
from lineageauth.authority import check_permission
from lineageauth.bundle import EventBundle
from lineageauth.canonical import jcs
from lineageauth.didkey import is_did_key
from lineageauth.errors import LineageAuthError, ReasonCode
from lineageauth.flop.model import SIMULATION_BANNER, TestnetFailure, TestnetRefusal
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.sources import SourceSnapshotSet
from lineageauth.flop.testnet.approve import (
    ApprovedTestnetAction,
    approval_request,
    decision_to_refusal,
    freshness_refusal,
)
from lineageauth.flop.testnet.audit import InMemoryAuditLog
from lineageauth.flop.testnet.client import ClientResult, RestrictedClient
from lineageauth.flop.testnet.endpoints import (
    SIMULATION_ORIGIN,
    FlopEndpoint,
    FlopEndpointRegistry,
)
from lineageauth.flop.testnet.evidence import FlopEvidenceDraft, draft_evidence
from lineageauth.flop.testnet.phase import PhaseGate
from lineageauth.flop.testnet.ports import AuditSink
from lineageauth.flop.testnet.receipts import (
    FlopTestnetExecutionReceipt,
    receipt_from_response,
)
from lineageauth.flop.testnet.spend import SpendLedger, TestnetSpendPolicy, format_amount
from lineageauth.jsonio import loads
from lineageauth.lineage import resolve_lineage
from lineageauth.timeutil import format_instant

STAGES: tuple[str, ...] = (
    "phase",
    "official-source",
    "endpoint",
    "request-validation",
    "active-did",
    "authority",
    "spend",
    "exact-approval",
    "network",
)

REPEAT_WARNING = "This activity may be difficult to distinguish from low-value or wash activity."


@dataclass(slots=True)
class ExecutorContext:
    """Everything the executor is allowed to consult, injected rather than imported.

    The audit sink and the ledger are mutable and the rest is not. That split is
    deliberate: an execution may record what it did, and may not change the
    rules it was judged by.
    """

    gate: PhaseGate
    registry: FlopEndpointRegistry
    policy: TestnetSpendPolicy
    client: RestrictedClient
    snapshot: SourceSnapshotSet
    rules: FlopRuleRegistry
    store: SpentReceiptStore
    ledger: SpendLedger = field(default_factory=SpendLedger)
    audit: AuditSink = field(default_factory=InMemoryAuditLog)
    seen_request_hashes: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """What happened, at which stage, and what evidence it produced."""

    ok: bool
    stage: str
    detail: str
    refusal: TestnetRefusal | None = None
    receipt: FlopTestnetExecutionReceipt | None = None
    evidence: FlopEvidenceDraft | None = None
    client_result: ClientResult | None = None
    audit_hash: str | None = None
    warnings: tuple[str, ...] = ()
    network_attempts: int = 0

    @property
    def failure(self) -> TestnetFailure | None:
        return None if self.refusal is None else self.refusal.failure

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "stage": self.stage,
            "stages": list(STAGES),
            "detail": self.detail,
            "failure": None if self.failure is None else str(self.failure),
            "refusal": None if self.refusal is None else self.refusal.to_dict(),
            "receipt": None if self.receipt is None else self.receipt.to_dict(),
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
            "clientResult": None if self.client_result is None else self.client_result.to_dict(),
            "auditHash": self.audit_hash,
            "warnings": list(self.warnings),
            "networkAttempts": self.network_attempts,
        }


def execute(
    approved: ApprovedTestnetAction,
    *,
    context: ExecutorContext,
    bundle: EventBundle,
    at: datetime,
) -> ExecutionOutcome:
    """Run the nine checks and, if every one passes, perform exactly one attempt."""
    prepared = approved.prepared
    plan = prepared.plan
    warnings: list[str] = list(approved.warnings)

    def record(kind: str, entry: dict[str, Any]) -> str:
        entry["at"] = at
        entry["actionId"] = prepared.action_id
        entry["requestHash"] = prepared.request_hash
        return context.audit.append(kind, entry)

    def refuse(refusal: TestnetRefusal) -> ExecutionOutcome:
        audit_hash = record(
            "execution-refused",
            {"stage": refusal.stage, "failure": str(refusal.failure), "detail": refusal.detail},
        )
        return ExecutionOutcome(
            ok=False,
            stage=refusal.stage or "phase",
            detail=refusal.detail,
            refusal=refusal,
            audit_hash=audit_hash,
            warnings=tuple(warnings),
        )

    record(
        "execution-attempted",
        {
            "endpointId": plan.endpoint_id,
            "destination": plan.destination,
            "network": plan.network,
            "simulation": plan.simulation,
            "estimatedSpend": format_amount(prepared.estimated_spend),
            "maxAllowedSpend": format_amount(prepared.max_allowed_spend),
            "approver": approved.approver,
        },
    )

    # ---------------------------------------------------------------- 1. phase
    entry = context.registry.get(plan.endpoint_id)
    is_simulation = (
        entry is not None
        and entry.simulation
        and plan.simulation
        and entry.origin == SIMULATION_ORIGIN
    )
    if not is_simulation:
        phase_refusal = context.gate.refusal()
        if phase_refusal is not None:
            return refuse(phase_refusal)

    # ------------------------------------------------------ 2. official source
    stale = freshness_refusal(prepared, snapshot=context.snapshot, rules=context.rules, at=at)
    if stale is not None:
        return refuse(stale)

    # ------------------------------------------------------------- 3. endpoint
    resolved = context.registry.resolve(plan.endpoint_id, phase=context.gate.phase)
    if not isinstance(resolved, FlopEndpoint):
        return refuse(resolved)
    if resolved.simulation != plan.simulation:
        return refuse(
            TestnetRefusal(
                failure=TestnetFailure.REQUEST_INVALID,
                detail=(
                    f"the prepared action says simulation={plan.simulation} and endpoint "
                    f"{resolved.endpoint_id} says {resolved.simulation}; a claim about being "
                    "a simulation is not accepted from the action being executed"
                ),
                stage="endpoint",
            )
        )

    # --------------------------------------------------- 4. request validation
    body = jcs(dict(prepared.canonical_request))
    rebuilt = approval_request(prepared)
    if rebuilt.request_hash != prepared.request_hash:
        return refuse(
            TestnetRefusal(
                failure=TestnetFailure.APPROVAL_MISMATCH,
                detail=(
                    "the canonical request does not hash to the value recorded when it was "
                    "prepared; a single changed byte invalidates the approval"
                ),
                stage="request-validation",
            )
        )
    if plan.destination != resolved.url_for(plan.path):
        return refuse(
            TestnetRefusal(
                failure=TestnetFailure.REQUEST_INVALID,
                detail=(
                    f"the destination {plan.destination} is not the URL endpoint "
                    f"{resolved.endpoint_id} builds for {plan.path}"
                ),
                stage="request-validation",
            )
        )
    if prepared.expired(at):
        return refuse(
            TestnetRefusal(
                failure=TestnetFailure.REPREPARE_REQUIRED,
                detail=(f"the prepared action expired at {format_instant(prepared.expires_at)}"),
                stage="request-validation",
            )
        )

    # ------------------------------------------------------------ 5. active DID
    if not is_did_key(approved.agent) or approved.agent != plan.subject_did:
        return refuse(
            TestnetRefusal(
                failure=TestnetFailure.DID_NOT_ACTIVE,
                detail=(
                    f"the executing agent {approved.agent!r} is not the did:key this action "
                    f"was prepared for ({plan.subject_did!r})"
                ),
                stage="active-did",
            )
        )
    state = resolve_lineage(bundle, lineage=approved.lineage, at=at)
    if not state.resolved:
        return refuse(
            TestnetRefusal(
                failure=TestnetFailure.DID_NOT_ACTIVE,
                detail=f"lineage {approved.lineage} does not resolve: {state.detail}",
                stage="active-did",
            )
        )

    # ------------------------------------------------------------ 6. authority
    authority = check_permission(
        bundle,
        lineage=approved.lineage,
        agent=approved.agent,
        namespace=rebuilt.namespace,
        resource=rebuilt.resource,
        action=rebuilt.action,
        at=at,
        external=True,
    )
    if authority.reason not in (
        ReasonCode.VALID_AUTHORITY_CHAIN,
        ReasonCode.APPROVAL_REQUIRED,
    ):
        return refuse(
            TestnetRefusal(
                failure=TestnetFailure.AUTHORITY_DENIED,
                detail=f"authority check failed: {authority.detail}",
                stage="authority",
            )
        )
    warnings.extend(authority.warnings)

    # ---------------------------------------------------------------- 7. spend
    spend_decision = context.policy.check(
        prepared.estimated_spend,
        approved_max=prepared.max_allowed_spend,
        spent_today=context.ledger.spent_on(at.date()),
        spent_this_session=context.ledger.session_total,
    )
    if not spend_decision.allowed:
        assert spend_decision.refusal is not None
        return refuse(spend_decision.refusal)

    # -------------------------------------------------------- 8. exact approval
    if prepared.request_hash in context.seen_request_hashes:
        warnings.append(REPEAT_WARNING)
    decision = check_execution(
        bundle,
        lineage=approved.lineage,
        agent=approved.agent,
        request=rebuilt,
        at=at,
        store=context.store,
        external=True,
        reserve=True,
    )
    if not decision.may_execute:
        return refuse(decision_to_refusal(decision, stage="exact-approval"))
    if decision.receipt_id != approved.receipt_id:
        return refuse(
            TestnetRefusal(
                failure=TestnetFailure.APPROVAL_MISMATCH,
                detail=(
                    f"the receipt consumed at execution ({decision.receipt_id}) is not the one "
                    f"this action was approved with ({approved.receipt_id})"
                ),
                stage="exact-approval",
            )
        )

    # -------------------------------------------------------------- 9. network
    started = at
    result = context.client.send(endpoint=resolved, path=plan.path, body=body)
    context.seen_request_hashes.add(prepared.request_hash)
    if not result.ok:
        refusal = result.refusal or TestnetRefusal(
            failure=TestnetFailure.NETWORK_REFUSED,
            detail="the attempt did not succeed and gave no reason",
            stage="network",
        )
        audit_hash = record(
            "execution-failed",
            {"stage": "network", "failure": str(refusal.failure), "client": result.to_dict()},
        )
        return ExecutionOutcome(
            ok=False,
            stage="network",
            detail=refusal.detail,
            refusal=refusal,
            client_result=result,
            audit_hash=audit_hash,
            warnings=tuple(warnings),
            network_attempts=1,
        )

    payload = _payload_of(result)
    receipt = receipt_from_response(
        payload,
        action_id=prepared.action_id,
        subject_did=plan.subject_did,
        network=plan.network,
        action_type=plan.action_type,
        endpoint_id=resolved.endpoint_id,
        request_hash=result.request_sha256,
        response_hash=result.response_sha256 or _hash_of(result.body),
        started_at=started,
        completed_at=at,
        source_snapshot_id=plan.source_snapshot_id,
        quote_amount=prepared.quote.amount if prepared.quote is not None else None,
        model=plan.model,
        synthetic=plan.simulation,
        simulation=plan.simulation,
    )
    # The ledger is charged the greater of what was approved and what the far
    # side says it took. An endpoint that under-reports -- or reports zero --
    # would otherwise keep the daily and session caps empty forever, which turns
    # a spend limit into a courtesy the counterparty extends. The estimate was
    # checked against the policy before anything was sent, so charging it is
    # always defensible; charging only the report is not.
    charged = (
        prepared.estimated_spend
        if receipt.observed_spend is None
        else max(receipt.observed_spend, prepared.estimated_spend)
    )
    context.ledger.record(charged, at=at)
    evidence = draft_evidence(
        receipt,
        lineage=approved.lineage,
        issuer=approved.agent,
        issued_at=at,
        request_bytes=len(body),
        response_bytes=len(result.body),
    )
    audit_hash = record(
        "execution-completed",
        {
            "stage": "network",
            "verificationState": str(receipt.verification_state),
            "observedSpend": (
                None if receipt.observed_spend is None else format_amount(receipt.observed_spend)
            ),
            "chargedToLedger": format_amount(charged),
            "responseHash": receipt.response_hash,
            "receiptRef": receipt.transaction_ref,
            "simulation": receipt.simulation,
        },
    )
    detail = (
        f"{SIMULATION_BANNER}. " if receipt.simulation else ""
    ) + f"the attempt completed and is recorded as {receipt.verification_state}"
    return ExecutionOutcome(
        ok=True,
        stage="network",
        detail=detail,
        receipt=receipt,
        evidence=evidence,
        client_result=result,
        audit_hash=audit_hash,
        warnings=tuple(warnings),
        network_attempts=1,
    )


def _payload_of(result: ClientResult) -> dict[str, Any]:
    """Read a JSON response, or treat it as no answer at all.

    A body that will not parse is not an error to raise: it is a response with
    nothing verifiable in it, and `receipt_from_response` will mark the receipt
    partially verified for exactly the fields it could not find.
    """
    try:
        loaded = loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, LineageAuthError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _hash_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def observed_total(receipts: tuple[FlopTestnetExecutionReceipt, ...]) -> Decimal | None:
    """Sum of observed spend, or None when nothing was observed."""
    total: Decimal | None = None
    for receipt in receipts:
        if receipt.observed_spend is None:
            continue
        total = receipt.observed_spend if total is None else total + receipt.observed_spend
    return total


__all__ = [
    "REPEAT_WARNING",
    "STAGES",
    "ExecutionOutcome",
    "ExecutorContext",
    "execute",
    "observed_total",
]
