"""Shared UNSAFE fixtures for the FLOP testnet suites.

Not a test module. Every key here comes from `tests/testkeys.py`, is derived
from a public constant, and must never sign anything real.

The bundle these helpers build is the smallest one the executor will accept: a
root, a grant that names an approver (D-107), and an approval receipt bound to
one exact request hash. Building it in one place keeps every acceptance test
arguing about its own subject rather than about scaffolding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from lineageauth import jsonio
from lineageauth.actions import ActionRequest
from lineageauth.approval import InMemorySpentStore
from lineageauth.builders import (
    build_approval_receipt,
    build_delegation_grant,
    build_root_create,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from lineageauth.flop.model import SourceClass
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.sources import SourceSnapshotSet, load_snapshot
from lineageauth.flop.testnet.approve import ApprovedTestnetAction, approve
from lineageauth.flop.testnet.client import RestrictedClient
from lineageauth.flop.testnet.endpoints import (
    SIMULATION_ORIGIN,
    FlopEndpoint,
    FlopEndpointRegistry,
)
from lineageauth.flop.testnet.executor import ExecutionOutcome, ExecutorContext, execute
from lineageauth.flop.testnet.phase import PhaseGate
from lineageauth.flop.testnet.ports import RawResponse, TransportRequest
from lineageauth.flop.testnet.prepare import PreparedTestnetAction
from lineageauth.flop.testnet.simulation import SimulationTransport, prepare_simulation
from lineageauth.flop.testnet.spend import SpendLedger, TestnetSpendPolicy
from tests.testkeys import AGENT_1, OUTSIDER, RECOVERY_1, ROOT_A, unsafe_signer

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
FROM = AT - timedelta(days=1)
UNTIL = AT + timedelta(days=30)

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
OPERATOR = unsafe_signer(RECOVERY_1)
STRANGER = unsafe_signer(OUTSIDER)

LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

NONCE = b"\x22" * 16

SIMULATION_HOST = "testnet.simulation.invalid"

# An endpoint that would be executable if a testnet existed. Used only to prove
# that the phase gate refuses it: nothing in the shipped registry looks like it.
OFFICIAL_LIVE_ENDPOINT = FlopEndpoint(
    endpoint_id="official-inference",
    purpose="inference",
    origin="https://flop.finance",
    method="POST",
    path_pattern="/testnet/v1/inference",
    network="flop-testnet-hypothetical",
    source_url="https://flop.finance/teaser/",
    source_version="0.1-draft",
    verified_at="2026-09-03T00:00:00Z",
    mutates_state=True,
    auth_type="did",
    enabled=True,
    source_class=SourceClass.OFFICIAL,
    note="Fixture only. No such endpoint is published by any official FLOP source.",
)


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(
    *,
    host: str = SIMULATION_HOST,
    subject: LocalSigner = AGENT,
    approval: str = "required",
    approvers: tuple[LocalSigner, ...] = (ROOT,),
) -> Envelope:
    """A grant for `http` / `host:<host>` / post, naming who may approve (D-107)."""
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=subject.did,
            epoch=0,
            scopes=[{"namespace": "http", "resource": f"host:{host}", "actions": ["post"]}],
            not_before=FROM,
            expires_at=UNTIL,
            max_depth=0,
            approval=approval,
            approvers=[signer.did for signer in approvers],
            issued_at=AT,
        ),
        [ROOT],
    )


def receipt_for(
    request: ActionRequest,
    *,
    approver: LocalSigner = ROOT,
    agent: LocalSigner = AGENT,
    issued_at: datetime = AT - timedelta(minutes=1),
    expires_at: datetime = AT + timedelta(minutes=30),
    nonce: bytes = NONCE,
) -> Envelope:
    """One human approval bound to exactly this request hash."""
    return sign_payload(
        build_approval_receipt(
            lineage=LINEAGE,
            approver=approver.did,
            agent=agent.did,
            request=request,
            nonce=nonce,
            expires_at=expires_at,
            issued_at=issued_at,
        ),
        [approver],
    )


def bundle_of(*events: Envelope) -> EventBundle:
    return EventBundle.from_envelopes(list(events))


def approved_bundle(prepared: PreparedTestnetAction, *, host: str = SIMULATION_HOST) -> EventBundle:
    """Root, grant and a receipt bound to this prepared action's exact request."""
    return bundle_of(genesis(), grant(host=host), receipt_for(prepared.action_request()))


def snapshot() -> SourceSnapshotSet:
    return load_snapshot()


def rules() -> FlopRuleRegistry:
    return FlopRuleRegistry.load()


def simulation_registry() -> FlopEndpointRegistry:
    return FlopEndpointRegistry.default()


def registry_with_live_endpoint() -> FlopEndpointRegistry:
    """The shipped registry plus one hypothetical official entry."""
    return FlopEndpointRegistry.from_entries(
        (*FlopEndpointRegistry.default().entries, OFFICIAL_LIVE_ENDPOINT)
    )


DEFAULT_MAX_SPEND = Decimal("5")


@dataclass(slots=True)
class UnderReportingTransport:
    """A simulation transport whose answer says it charged nothing.

    Stands in for the endpoint the spend policy has to survive: one that
    under-reports, deliberately or through a bug, and would otherwise keep the
    daily and session caps empty forever.
    """

    calls: list[TransportRequest] = field(default_factory=list)

    def send(self, request: TransportRequest) -> RawResponse:
        inner = SimulationTransport()
        response = inner.send(request)
        self.calls.extend(inner.calls)
        payload = jsonio.loads(response.body.decode("utf-8"))
        assert isinstance(payload, dict)
        payload["observedSpend"] = "0"
        return RawResponse(
            status=response.status,
            body=jsonio.dumps(payload).encode("utf-8"),
            headers=response.headers,
            final_url=response.final_url,
            redirected=response.redirected,
        )


def zero_spend_execution() -> tuple[ExecutionOutcome, SpendLedger, Decimal]:
    """One completed simulated execution whose answer reports a spend of zero.

    Returns the outcome, the ledger it charged and the estimate it was approved
    for, so a test can say what the ledger should hold without rebuilding the
    executor's scaffolding.
    """
    prepared = prepare_simulation(subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules())
    bundle = approved_bundle(prepared)
    decided = approve(
        prepared,
        bundle=bundle,
        lineage=LINEAGE,
        agent=AGENT.did,
        at=AT,
        store=InMemorySpentStore(),
        snapshot=snapshot(),
        rules=rules(),
    )
    assert isinstance(decided, ApprovedTestnetAction)
    endpoints = simulation_registry()
    ledger = SpendLedger()
    context = ExecutorContext(
        gate=PhaseGate(),
        registry=endpoints,
        policy=TestnetSpendPolicy(),
        client=RestrictedClient(registry=endpoints, transport=UnderReportingTransport()),
        snapshot=snapshot(),
        rules=rules(),
        store=InMemorySpentStore(),
        ledger=ledger,
    )
    outcome = execute(decided, context=context, bundle=bundle, at=AT)
    return outcome, ledger, prepared.estimated_spend


__all__ = [
    "AGENT",
    "AT",
    "DEFAULT_MAX_SPEND",
    "LINEAGE",
    "OFFICIAL_LIVE_ENDPOINT",
    "OPERATOR",
    "ROOT",
    "SIMULATION_HOST",
    "SIMULATION_ORIGIN",
    "STRANGER",
    "UnderReportingTransport",
    "approved_bundle",
    "bundle_of",
    "genesis",
    "grant",
    "receipt_for",
    "registry_with_live_endpoint",
    "rules",
    "simulation_registry",
    "snapshot",
    "zero_spend_execution",
]
