"""The whole flow, end to end, against a network that cannot exist.

Directive 28 wants the complete UX exercisable before launch: faucet, balance,
quote, authority, exact approval, execution, receipt, evidence, passport. All
nine happen here, through the same executor, the same approval check and the
same evidence drafts the real thing will use. Only the transport is different,
and the transport is the piece that would otherwise be the whole risk.

`SimulationTransport` computes an answer from the request bytes. It opens
nothing, reads no file and resolves no name -- and the URL it is handed points
at `testnet.simulation.invalid`, which RFC 6761 reserves precisely so that
software with a bug cannot accidentally reach a real host.

Every object this module produces carries `SIMULATION - NO FLOP NETWORK ACTION`
and `synthetic: true`. Not because a reader would otherwise be fooled, but
because a screenshot outlives its caption.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from lineageauth import jsonio
from lineageauth.approval import SpentReceiptStore
from lineageauth.authority import check_permission
from lineageauth.builders import build_approval_receipt
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.flop.model import (
    SIMULATION_BANNER,
    SYNTHETIC_BANNER,
    InferencePurpose,
    TestnetFailure,
    TestnetRefusal,
    TestnetRefusedError,
)
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.sources import SourceSnapshotSet
from lineageauth.flop.testnet.approve import ApprovedTestnetAction, approve
from lineageauth.flop.testnet.audit import InMemoryAuditLog
from lineageauth.flop.testnet.client import RestrictedClient
from lineageauth.flop.testnet.endpoints import (
    SIMULATION_ENDPOINT_ID,
    SIMULATION_FAUCET_ENDPOINT_ID,
    SIMULATION_NETWORK,
    FlopEndpointRegistry,
)
from lineageauth.flop.testnet.evidence import inference_summary
from lineageauth.flop.testnet.executor import ExecutionOutcome, ExecutorContext, execute
from lineageauth.flop.testnet.phase import PhaseGate
from lineageauth.flop.testnet.ports import AuditSink, RawResponse, TransportRequest
from lineageauth.flop.testnet.prepare import (
    ControlInput,
    InferenceQuote,
    InferenceWorkload,
    PreparedTestnetAction,
    Untrusted,
    assemble_request,
    build_plan,
)
from lineageauth.flop.testnet.spend import SpendLedger, TestnetSpendPolicy, format_amount
from lineageauth.timeutil import format_instant

SIMULATED_FAUCET_AMOUNT = Decimal("100")
SIMULATED_QUOTE_AMOUNT = Decimal("2.5")
SIMULATED_MODEL = "simulated-model-a"
DEFAULT_MAX_SPEND = Decimal("5")
QUOTE_TTL = timedelta(minutes=10)

SIMULATION_NOTE = (
    "Synthetic throughout. No faucet was claimed, no token moved, no inference was "
    "purchased, and no request left this process."
)


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SimulationTransport:
    """Answers the simulation endpoint by computing, never by connecting.

    `calls` counts attempts so a test can distinguish "refused before the
    transport" from "the transport declined", which are different bugs.
    """

    calls: list[TransportRequest] = field(default_factory=list)

    def send(self, request: TransportRequest) -> RawResponse:
        self.calls.append(request)
        if not request.url.startswith("https://testnet.simulation.invalid/"):
            raise TestnetRefusedError(
                TestnetRefusal(
                    failure=TestnetFailure.ENDPOINT_BLOCKED,
                    detail=(
                        "the simulation transport answers only the reserved simulation "
                        f"origin; it was handed {request.url}"
                    ),
                    stage="network",
                )
            )
        body = _simulated_body(request)
        return RawResponse(
            status=200,
            body=jsonio.dumps(body).encode("utf-8"),
            headers={"content-type": "application/json"},
            final_url=request.url,
            redirected=False,
        )


def _simulated_body(request: TransportRequest) -> dict[str, Any]:
    """A deterministic synthetic answer derived from the request bytes."""
    parsed: Mapping[str, Any] = {}
    try:
        loaded = jsonio.loads(request.body.decode("utf-8"))
        if isinstance(loaded, dict):
            parsed = loaded
    except (UnicodeDecodeError, ValueError):
        parsed = {}
    control = parsed.get("control")
    control_map: Mapping[str, Any] = control if isinstance(control, Mapping) else {}
    estimated = parsed.get("estimatedSpend")
    spend = estimated if isinstance(estimated, str) else format_amount(SIMULATED_QUOTE_AMOUNT)
    reference = _digest(request.url, str(control_map.get("planId", "")), spend)[:16]
    return {
        "simulation": True,
        "synthetic": True,
        "banner": SIMULATION_BANNER,
        "network": control_map.get("network", SIMULATION_NETWORK),
        "receiptRef": f"sim-receipt-{reference}",
        "observedSpend": spend,
        "model": control_map.get("model") or SIMULATED_MODEL,
        "miner": "simulated-miner",
        "result": (
            "Synthetic result. No inference was performed and this text is not an answer "
            "to anything."
        ),
    }


@dataclass(frozen=True, slots=True)
class SyntheticBalance:
    """A faucet grant and a balance that exist only in this process."""

    subject_did: str
    amount: Decimal
    at: datetime
    reference: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "subjectDid": self.subject_did,
            "amount": format_amount(self.amount),
            "unit": "test FLOP",
            "at": format_instant(self.at),
            "reference": self.reference,
            "synthetic": True,
            "simulation": True,
            "banner": SIMULATION_BANNER,
            "syntheticBanner": SYNTHETIC_BANNER,
            "officialFaucetAvailable": False,
        }


def simulate_faucet(*, subject_did: str, at: datetime) -> SyntheticBalance:
    """A synthetic faucet grant. No official faucet procedure is published."""
    return SyntheticBalance(
        subject_did=subject_did,
        amount=SIMULATED_FAUCET_AMOUNT,
        at=at,
        reference="sim-faucet-" + _digest(subject_did, format_instant(at))[:12],
    )


def simulate_balance(grant: SyntheticBalance, *, spent: Decimal = Decimal("0")) -> SyntheticBalance:
    """The balance after a synthetic spend. Still synthetic, still not a balance."""
    return SyntheticBalance(
        subject_did=grant.subject_did,
        amount=grant.amount - spent,
        at=grant.at,
        reference=grant.reference,
    )


def simulate_quote(
    *, subject_did: str, at: datetime, amount: Decimal = SIMULATED_QUOTE_AMOUNT
) -> InferenceQuote:
    """A synthetic price. `official` is False because no pricing method is published."""
    return InferenceQuote(
        quote_id="sim-quote-"
        + _digest(subject_did, format_instant(at), format_amount(amount))[:12],
        amount=amount,
        currency="test FLOP",
        expires_at=at + QUOTE_TTL,
        source_id="simulation",
        official=False,
        simulation=True,
    )


def default_workload(
    *, purpose: InferencePurpose = InferencePurpose.EVALUATION
) -> InferenceWorkload:
    """The workload the console's simulation uses when none is supplied."""
    return InferenceWorkload(
        purpose=purpose,
        prompt=(
            "Summarise the LineageAuth approval flow in three sentences for a reviewer "
            "who has not read the specification."
        ),
        requested_model=SIMULATED_MODEL,
        params={"maxTokens": 256},
        evidence_label="simulation-walkthrough",
    )


def prepare_simulation(
    *,
    subject_did: str,
    at: datetime,
    snapshot: SourceSnapshotSet,
    rules: FlopRuleRegistry,
    workload: InferenceWorkload | None = None,
    registry: FlopEndpointRegistry | None = None,
    policy: TestnetSpendPolicy | None = None,
    gate: PhaseGate | None = None,
    quote: InferenceQuote | None = None,
    max_spend: Decimal = DEFAULT_MAX_SPEND,
    endpoint_id: str = SIMULATION_ENDPOINT_ID,
    action_type: str = "inference",
) -> PreparedTestnetAction:
    """Build the exact action a person would approve. Deterministic given `at`.

    Determinism is what lets a test build the approval receipt for this action's
    hash and then run the whole flow again and have it match -- which is also
    exactly what a real operator does between preparing and approving.
    """
    body = workload if workload is not None else default_workload()
    quoted = quote if quote is not None else simulate_quote(subject_did=subject_did, at=at)
    plan = build_plan(
        ControlInput(
            endpoint_id=endpoint_id,
            subject_did=subject_did,
            action_type=action_type,
            purpose=body.purpose,
            max_spend=max_spend,
            model_id=SIMULATED_MODEL,
        ),
        registry=registry if registry is not None else FlopEndpointRegistry.default(),
        policy=policy if policy is not None else TestnetSpendPolicy(),
        gate=gate if gate is not None else PhaseGate(),
        snapshot=snapshot,
        rules=rules,
    )
    return assemble_request(plan, Untrusted(body), at=at, quote=quoted)


def prepare_faucet_simulation(
    *,
    subject_did: str,
    at: datetime,
    snapshot: SourceSnapshotSet,
    rules: FlopRuleRegistry,
    registry: FlopEndpointRegistry | None = None,
    policy: TestnetSpendPolicy | None = None,
    gate: PhaseGate | None = None,
) -> PreparedTestnetAction:
    """A synthetic faucet request. There is no official faucet procedure to follow."""
    workload = InferenceWorkload(
        purpose=InferencePurpose.OTHER,
        prompt="Request synthetic test FLOP from the simulation faucet.",
        requested_model=None,
        params={},
        evidence_label="simulation-faucet",
    )
    return prepare_simulation(
        subject_did=subject_did,
        at=at,
        snapshot=snapshot,
        rules=rules,
        workload=workload,
        registry=registry,
        policy=policy,
        gate=gate,
        quote=simulate_quote(subject_did=subject_did, at=at, amount=Decimal("0")),
        max_spend=Decimal("0"),
        endpoint_id=SIMULATION_FAUCET_ENDPOINT_ID,
        action_type="faucet",
    )


@dataclass(frozen=True, slots=True)
class SimulationStep:
    """One stage of the walkthrough, and whether it got there."""

    step_id: str
    label: str
    ok: bool
    detail: str
    data: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id,
            "label": self.label,
            "ok": self.ok,
            "detail": self.detail,
            "data": dict(self.data),
            "banner": SIMULATION_BANNER,
            "simulation": True,
        }


@dataclass(frozen=True, slots=True)
class SimulationRun:
    """The whole walkthrough: nine steps, one prepared action, one outcome."""

    steps: tuple[SimulationStep, ...]
    prepared: PreparedTestnetAction | None
    approved: ApprovedTestnetAction | None
    outcome: ExecutionOutcome | None
    transport_calls: int
    audit_head: str

    @property
    def ok(self) -> bool:
        return all(step.ok for step in self.steps)

    @property
    def network_writes_performed(self) -> int:
        """Attempts that reached a network, counted rather than asserted.

        The executor records how many attempts it made, and
        `SimulationTransport` counts how many of them it received. Every attempt
        in a simulation run should land on that transport, which resolves no
        name and opens no socket, so the difference is the number that went
        somewhere else. It is zero because it was measured as zero, which is a
        different statement from a literal zero in a response body -- and the
        difference is exactly `MEMORY.md`'s note that a setting existing is not
        a setting working.
        """
        attempts = 0 if self.outcome is None else self.outcome.network_attempts
        return max(attempts - self.transport_calls, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "banner": SIMULATION_BANNER,
            "syntheticBanner": SYNTHETIC_BANNER,
            "simulation": True,
            "synthetic": True,
            "ok": self.ok,
            "steps": [step.to_dict() for step in self.steps],
            "prepared": None if self.prepared is None else self.prepared.to_dict(),
            "approved": None if self.approved is None else self.approved.to_dict(),
            "outcome": None if self.outcome is None else self.outcome.to_dict(),
            "transportCalls": self.transport_calls,
            "auditHead": self.audit_head,
            "networkWritesPerformed": self.network_writes_performed,
            "simulatedAttempts": 0 if self.outcome is None else self.outcome.network_attempts,
            "note": SIMULATION_NOTE,
        }


def run_simulation(
    *,
    bundle: EventBundle,
    lineage: str,
    agent: str,
    at: datetime,
    snapshot: SourceSnapshotSet,
    rules: FlopRuleRegistry,
    store: SpentReceiptStore,
    workload: InferenceWorkload | None = None,
    registry: FlopEndpointRegistry | None = None,
    policy: TestnetSpendPolicy | None = None,
    gate: PhaseGate | None = None,
    transport: SimulationTransport | None = None,
    audit: AuditSink | None = None,
    max_spend: Decimal = DEFAULT_MAX_SPEND,
) -> SimulationRun:
    """Walk the whole flow and report each step, including the ones that refused.

    Nothing raises. A missing grant or a missing approval receipt is a step that
    says so, because the point of the walkthrough is to show an operator where
    their setup stops, and an exception would show them a stack trace instead.
    """
    endpoints = registry if registry is not None else FlopEndpointRegistry.default()
    spend_policy = policy if policy is not None else TestnetSpendPolicy()
    phase_gate = gate if gate is not None else PhaseGate()
    sim_transport = transport if transport is not None else SimulationTransport()
    sink: AuditSink = audit if audit is not None else InMemoryAuditLog()
    steps: list[SimulationStep] = []

    grant = simulate_faucet(subject_did=agent, at=at)
    steps.append(
        SimulationStep(
            step_id="faucet",
            label="Synthetic faucet",
            ok=True,
            detail="No official faucet procedure is published; this grant is invented locally.",
            data=grant.to_dict(),
        )
    )
    steps.append(
        SimulationStep(
            step_id="balance",
            label="Synthetic balance",
            ok=True,
            detail="A number this process made up. It is not a balance on any ledger.",
            data=grant.to_dict(),
        )
    )
    quote = simulate_quote(subject_did=agent, at=at)
    steps.append(
        SimulationStep(
            step_id="quote",
            label="Synthetic quote",
            ok=True,
            detail="No official pricing mechanism is published, so this price is not a price.",
            data=quote.to_dict(),
        )
    )

    try:
        prepared = prepare_simulation(
            max_spend=max_spend,
            subject_did=agent,
            at=at,
            snapshot=snapshot,
            rules=rules,
            workload=workload,
            registry=endpoints,
            policy=spend_policy,
            gate=phase_gate,
            quote=quote,
        )
    except TestnetRefusedError as exc:
        steps.append(
            SimulationStep(
                step_id="prepare",
                label="Prepared action",
                ok=False,
                detail=exc.refusal.detail,
                data=exc.refusal.to_dict(),
            )
        )
        return SimulationRun(
            steps=tuple(steps),
            prepared=None,
            approved=None,
            outcome=None,
            transport_calls=len(sim_transport.calls),
            audit_head=_head_of(sink),
        )
    steps.append(
        SimulationStep(
            step_id="prepare",
            label="Prepared action",
            ok=True,
            detail="The exact bytes a person is asked to approve. Nothing has been sent.",
            data=prepared.to_dict(),
        )
    )

    request = prepared.action_request()
    authority = check_permission(
        bundle,
        lineage=lineage,
        agent=agent,
        namespace=request.namespace,
        resource=request.resource,
        action=request.action,
        at=at,
        external=True,
    )
    steps.append(
        SimulationStep(
            step_id="authority",
            label="LineageAuth authority",
            ok=authority.reason.value in ("VALID_AUTHORITY_CHAIN", "APPROVAL_REQUIRED"),
            detail=authority.detail,
            data={
                "reason": str(authority.reason),
                "allowed": authority.allowed,
                "note": authority.note,
            },
        )
    )

    approved = approve(
        prepared,
        bundle=bundle,
        lineage=lineage,
        agent=agent,
        at=at,
        store=store,
        snapshot=snapshot,
        rules=rules,
        reserve=False,
    )
    if isinstance(approved, TestnetRefusal):
        steps.append(
            SimulationStep(
                step_id="approval",
                label="Exact-action approval",
                ok=False,
                detail=approved.detail,
                data=approved.to_dict(),
            )
        )
        return SimulationRun(
            steps=tuple(steps),
            prepared=prepared,
            approved=None,
            outcome=None,
            transport_calls=len(sim_transport.calls),
            audit_head=_head_of(sink),
        )
    steps.append(
        SimulationStep(
            step_id="approval",
            label="Exact-action approval",
            ok=True,
            detail=approved.detail,
            data=approved.to_dict(),
        )
    )

    context = ExecutorContext(
        gate=phase_gate,
        registry=endpoints,
        policy=spend_policy,
        client=RestrictedClient(registry=endpoints, transport=sim_transport),
        snapshot=snapshot,
        rules=rules,
        store=store,
        ledger=SpendLedger(),
        audit=sink,
    )
    outcome = execute(approved, context=context, bundle=bundle, at=at)
    steps.append(
        SimulationStep(
            step_id="execute",
            label="Simulated execution",
            ok=outcome.ok,
            detail=outcome.detail,
            data=outcome.to_dict(),
        )
    )
    steps.append(
        SimulationStep(
            step_id="receipt",
            label="Synthetic receipt",
            ok=outcome.receipt is not None,
            detail=("A receipt records that an answer arrived. It does not make the answer true."),
            data={} if outcome.receipt is None else outcome.receipt.to_dict(),
        )
    )
    steps.append(
        SimulationStep(
            step_id="evidence",
            label="LineageAuth evidence",
            ok=outcome.evidence is not None,
            detail=(
                "Unsigned drafts: one artifact per side of the exchange and one attestation "
                "under an unregistered predicate."
            ),
            data={} if outcome.evidence is None else outcome.evidence.to_dict(),
        )
    )
    receipts = () if outcome.receipt is None else (outcome.receipt,)
    steps.append(
        SimulationStep(
            step_id="passport",
            label="Activity passport",
            ok=True,
            detail="Observed counts only. There is no combined figure and no score.",
            data=inference_summary(receipts),
        )
    )
    return SimulationRun(
        steps=tuple(steps),
        prepared=prepared,
        approved=approved,
        outcome=outcome,
        transport_calls=len(sim_transport.calls),
        audit_head=_head_of(sink),
    )


def _head_of(sink: AuditSink) -> str:
    head = getattr(sink, "head", "")
    return head if isinstance(head, str) else ""


__all__ = [
    "DEFAULT_MAX_SPEND",
    "QUOTE_TTL",
    "SIMULATED_FAUCET_AMOUNT",
    "SIMULATED_MODEL",
    "SIMULATED_QUOTE_AMOUNT",
    "SIMULATION_NOTE",
    "SimulationRun",
    "SimulationStep",
    "SimulationTransport",
    "SyntheticBalance",
    "default_workload",
    "prepare_faucet_simulation",
    "prepare_simulation",
    "run_simulation",
    "simulate_balance",
    "simulate_faucet",
    "simulate_quote",
]


DEMO_RECEIPT_TTL = timedelta(minutes=30)

DEMO_RECEIPT_NOTE = (
    "signed by the demo approver's UNSAFE public test key so the walkthrough can reach "
    "execution; it is checked by the same verifier as a real receipt, is never written "
    "to the index, and proves nothing about any person"
)


ReceiptSigning = Callable[[dict[str, Any]], Envelope]
"""Turn an unsigned `approval.receipt` payload into a signed envelope.

The FLOP layer never imports a key-holding signer (a test walks its imports),
so the demo path takes a function instead. The process that owns the key --
`scripts/serve_flop_console.py`, with the unsafe public test key -- supplies
it. The layer holds a callable, not a key, and a production mount holds neither.
"""


def demo_approval_receipt(
    prepared: PreparedTestnetAction,
    *,
    lineage: str,
    agent: str,
    approver: str,
    at: datetime,
    sign: ReceiptSigning,
) -> Envelope:
    """Draft an approval receipt for exactly this prepared action and have it signed.

    The walkthrough is meant to show the whole flow before the network exists,
    and the flow has a human in the middle of it. A page holds no keys, so in a
    demo process the operator's click is stood in for by a signing callback the
    process was started with -- the unsafe, public test key
    `scripts/serve_flop_console.py` already uses for the demo bundle, and never
    anything else. Outside a demo, the receipt is pasted in as a signed envelope
    and this function is not called.

    Nothing about the receipt is weaker for having been made here: it binds the
    same request hash, nonce and expiry, and `approve` checks it through
    `check_execution` like any other. What it cannot be is evidence that anyone
    consented, which is why the API labels it and never ingests it.
    """
    payload = build_approval_receipt(
        lineage=lineage,
        approver=approver,
        agent=agent,
        request=prepared.action_request(),
        nonce=secrets.token_bytes(16),
        expires_at=at + DEMO_RECEIPT_TTL,
        issued_at=at,
    )
    return sign(payload)
