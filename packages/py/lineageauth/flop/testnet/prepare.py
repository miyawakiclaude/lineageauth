"""The control plane and the workload, separated by type rather than by care.

Directive 22 says a requested inference prompt must never change the endpoint,
the spend limit, the signer or the source registry. "Must never" is a property
somebody has to keep true through every future edit, so it is arranged here as
something the type checker enforces instead:

    ControlInput  ->  build_plan(...)  ->  ExecutionPlan
                      no workload parameter exists

    ExecutionPlan +  assemble_request(plan, Untrusted[InferenceWorkload])
                      ->  PreparedTestnetAction

`build_plan` chooses the endpoint, the network, the cap and the signer, and its
signature has nowhere to put a prompt -- a test asserts that, so adding one is a
visible change rather than a quiet one. `assemble_request` then copies the
workload into one subtree of the request body, field by field from a fixed list.
Nothing in this module merges or unpacks a workload into the request, and a test
greps for the syntax that would, so a workload carrying `{"maxSpend": "999999"}`
produces a request whose *workload* says that and whose *control* does not.

`Untrusted[T]` exists to make the unwrap explicit. Under `mypy --strict` a
caller cannot pass a bare `InferenceWorkload` where the wrapper is expected, so
the moment a piece of external text enters the executor is a moment somebody
wrote down.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from lineageauth.actions import ActionRequest
from lineageauth.canonical import jcs
from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import (
    SIMULATION_BANNER,
    InferencePurpose,
    NetworkPhase,
    SafetyLevel,
    SourceClass,
    TestnetFailure,
    TestnetRefusal,
    TestnetRefusedError,
)
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.safety import overall_level, scan_text
from lineageauth.flop.sources import SourceSnapshotSet
from lineageauth.flop.testnet.endpoints import FlopEndpoint, FlopEndpointRegistry
from lineageauth.flop.testnet.phase import PhaseGate
from lineageauth.flop.testnet.spend import TestnetSpendPolicy, format_amount
from lineageauth.timeutil import format_instant

REQUEST_PROFILE = "flop.testnet.request/0.1"
"""This tool's own envelope version, not FLOP's. There is no official schema."""

DEFAULT_TTL = timedelta(minutes=15)

# The only keys a workload may contribute, and the subtree they go into. Adding
# one is an edit to this tuple, which is what a reviewer looks at.
WORKLOAD_FIELDS: tuple[str, ...] = (
    "purpose",
    "prompt",
    "requestedModel",
    "params",
    "evidenceLabel",
)


@dataclass(frozen=True)
class Untrusted[T]:
    """A value that came from outside. `.value` is the only way in."""

    value: T

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Untrusted({type(self.value).__name__})"


@dataclass(frozen=True, slots=True)
class InferenceWorkload:
    """What the agent wants computed. Never anything about how to reach a network.

    There is no endpoint field, no origin field, no spend field and no signer
    field, so a caller cannot even express the confusion. `requested_model` is
    named for what it is: a request, which `build_plan` may or may not have
    honoured, and which the executor reads from the control plane instead.
    """

    purpose: InferencePurpose
    prompt: str
    requested_model: str | None = None
    params: Mapping[str, str | int | float] = field(default_factory=dict)
    evidence_label: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.prompt, str) or not self.prompt.strip():
            raise MalformedEventError("an inference workload needs a non-empty prompt")
        if len(self.prompt) > 32_000:
            raise MalformedEventError("the workload prompt is limited to 32000 characters")
        for key, value in self.params.items():
            if not isinstance(key, str) or not key:
                raise MalformedEventError("every workload parameter needs a string name")
            if isinstance(value, bool) or not isinstance(value, str | int | float):
                raise MalformedEventError(
                    f"workload parameter {key!r} must be a string or a number"
                )

    def canonical(self) -> dict[str, Any]:
        """The workload subtree, built one allowlisted key at a time."""
        body: dict[str, Any] = {}
        body["purpose"] = str(self.purpose)
        body["prompt"] = self.prompt
        body["requestedModel"] = self.requested_model
        body["params"] = {str(key): self.params[key] for key in sorted(self.params)}
        body["evidenceLabel"] = self.evidence_label
        missing = [key for key in WORKLOAD_FIELDS if key not in body]
        if missing:  # pragma: no cover - guards the constant against drift
            raise MalformedEventError(f"workload subtree is missing {missing}")
        return body


@dataclass(frozen=True, slots=True)
class InferenceQuote:
    """What the network says an action will cost, and when that stops being true.

    `official` is false for every quote this tool can currently produce, because
    no official pricing mechanism is published. A simulated quote that claimed
    otherwise would be the first lie in the chain.
    """

    quote_id: str
    amount: Decimal
    currency: str
    expires_at: datetime
    source_id: str
    official: bool = False
    simulation: bool = True

    def expired(self, at: datetime) -> bool:
        return at >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "quoteId": self.quote_id,
            "amount": format_amount(self.amount),
            "currency": self.currency,
            "expiresAt": format_instant(self.expires_at),
            "sourceId": self.source_id,
            "official": self.official,
            "simulation": self.simulation,
            **({"banner": SIMULATION_BANNER} if self.simulation else {}),
        }


@dataclass(frozen=True, slots=True)
class ControlInput:
    """Everything the executor's control plane is allowed to be told.

    Every field is either an identifier chosen from a registry or a number. No
    free text reaches the plan, so there is nothing here for a prompt to be
    smuggled through.
    """

    endpoint_id: str
    subject_did: str
    action_type: str
    purpose: InferencePurpose
    max_spend: Decimal
    model_id: str | None = None
    path: str | None = None

    def __post_init__(self) -> None:
        if self.action_type not in ("inference", "faucet"):
            raise MalformedEventError(
                f"action type {self.action_type!r} is not one this executor knows"
            )
        if not isinstance(self.max_spend, Decimal) or self.max_spend < 0:
            raise MalformedEventError("max_spend must be a non-negative Decimal")


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """The resolved control plane: where, how, how much, under what evidence.

    Built only by `build_plan`, which has no way to receive a workload. Anything
    downstream that wants to know the destination reads it from here.
    """

    plan_id: str
    endpoint_id: str
    origin: str
    method: str
    path: str
    destination: str
    network: str
    action_type: str
    subject_did: str
    purpose: InferencePurpose
    model: str | None
    max_spend: Decimal
    signer_id: str
    source_snapshot_id: str
    rule_set_hash: str
    simulation: bool
    mutates_state: bool

    @property
    def host(self) -> str:
        return self.destination.split("://", 1)[1].split("/", 1)[0]

    def canonical(self) -> dict[str, Any]:
        """The control subtree. Assembled key by key, same discipline as the workload."""
        body: dict[str, Any] = {}
        body["planId"] = self.plan_id
        body["endpointId"] = self.endpoint_id
        body["origin"] = self.origin
        body["method"] = self.method
        body["path"] = self.path
        body["destination"] = self.destination
        body["network"] = self.network
        body["actionType"] = self.action_type
        body["subjectDid"] = self.subject_did
        body["purpose"] = str(self.purpose)
        body["model"] = self.model
        body["maxSpend"] = format_amount(self.max_spend)
        body["signerId"] = self.signer_id
        body["sourceSnapshotId"] = self.source_snapshot_id
        body["ruleSetHash"] = self.rule_set_hash
        body["simulation"] = self.simulation
        body["mutatesState"] = self.mutates_state
        return body

    def to_dict(self) -> dict[str, Any]:
        return self.canonical()


@dataclass(frozen=True, slots=True)
class PreparedTestnetAction:
    """One exact action, ready for a human to look at. Nothing has happened yet.

    `request_hash` is `ActionRequest`'s hash over the canonical request, which is
    what an approval receipt binds. Change one byte of the prompt and the hash
    moves, so a receipt obtained for one workload cannot be spent on another --
    that is acceptance E, and it is a property of the hash rather than of a
    comparison somebody remembered to write.
    """

    action_id: str
    plan: ExecutionPlan
    canonical_request: Mapping[str, Any]
    request_hash: str
    estimated_spend: Decimal
    max_allowed_spend: Decimal
    quote: InferenceQuote | None
    prepared_at: datetime
    expires_at: datetime
    safety_level: SafetyLevel
    safety_findings: tuple[Mapping[str, Any], ...] = ()

    @property
    def network(self) -> str:
        return self.plan.network

    @property
    def action_type(self) -> str:
        return self.plan.action_type

    @property
    def subject_did(self) -> str:
        return self.plan.subject_did

    @property
    def canonical_destination(self) -> str:
        return self.plan.destination

    @property
    def simulation(self) -> bool:
        return self.plan.simulation

    def expired(self, at: datetime) -> bool:
        return at >= self.expires_at

    def action_request(self) -> ActionRequest:
        """The `http` namespace request an approval receipt binds to.

        D-108(b): the FLOP executor borrows LineageAuth's existing `http`
        namespace rather than adding a `flop` one, because adding a namespace is
        a protocol change and the destination plus the exact bytes already say
        everything an approver needs to see. The bytes include the cap, so the
        approval binds the ceiling too.
        """
        return ActionRequest.over_bytes(
            namespace="http",
            resource=f"host:{self.plan.host}",
            action="post",
            destination=self.plan.destination,
            content=jcs(dict(self.canonical_request)),
        )

    def preview(self) -> str:
        """The exact-action panel from directive 7, in ASCII for a cp932 console."""
        lines = [
            "FLOP TESTNET INFERENCE",
            "",
            f"Agent DID:        {self.subject_did}",
            f"Network:          {self.network}",
            f"Action:           {self.action_type}",
            f"Purpose:          {self.plan.purpose}",
            f"Model:            {self.plan.model or 'not selected'}",
            f"Estimated cost:   {format_amount(self.estimated_spend)} test FLOP",
            f"Maximum approved: {format_amount(self.max_allowed_spend)} test FLOP",
            f"Destination:      {self.canonical_destination}",
            f"Request hash:     {self.request_hash}",
            f"Source snapshot:  {self.plan.source_snapshot_id}",
            f"Rule set:         {self.plan.rule_set_hash}",
            f"Expires:          {format_instant(self.expires_at)}",
            f"Safety:           {self.safety_level.display}",
            "",
            "Nothing has been sent. An approval receipt is required next.",
        ]
        if self.simulation:
            lines.insert(1, SIMULATION_BANNER)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.action_id,
            "network": self.network,
            "actionType": self.action_type,
            "subjectDid": self.subject_did,
            "endpointId": self.plan.endpoint_id,
            "method": self.plan.method,
            "canonicalDestination": self.canonical_destination,
            "canonicalRequest": dict(self.canonical_request),
            "requestHash": self.request_hash,
            "estimatedTestFlopSpend": format_amount(self.estimated_spend),
            "maxAllowedSpend": format_amount(self.max_allowed_spend),
            "model": self.plan.model,
            "purpose": str(self.plan.purpose),
            "sourceSnapshotId": self.plan.source_snapshot_id,
            "ruleSetHash": self.plan.rule_set_hash,
            "preparedAt": format_instant(self.prepared_at),
            "expiresAt": format_instant(self.expires_at),
            "quote": None if self.quote is None else self.quote.to_dict(),
            "safetyLevel": str(self.safety_level),
            "safetyFindings": [dict(finding) for finding in self.safety_findings],
            "simulation": self.simulation,
            "executed": False,
            "sent": False,
            **({"banner": SIMULATION_BANNER} if self.simulation else {}),
        }


def snapshot_fingerprint(snapshot: SourceSnapshotSet) -> str:
    """A stable id for one official-source snapshot set.

    Over the ids, hashes and statuses only. `fetchedAt` is excluded so that
    re-fetching unchanged documents does not invalidate every prepared action --
    the thing worth reacting to is the content moving, not the clock.
    """
    material = [
        {"id": entry.source_id, "sha256": entry.sha256, "status": entry.status}
        for entry in sorted(snapshot.snapshots, key=lambda item: item.source_id)
    ]
    return "sha256:" + hashlib.sha256(jcs(material)).hexdigest()


def rule_set_hash(registry: FlopRuleRegistry) -> str:
    """A stable id for the rule registry's economically meaningful content.

    `fetchedAt` is dropped for the same reason. A changed statement, status,
    formula or bound source hash moves this value, and a prepared action that
    quoted the old one is refused with `REPREPARE_REQUIRED` (acceptance N).
    """
    material = []
    for rule in sorted(registry.rules, key=lambda item: item.rule_id):
        entry = rule.to_dict()
        source = dict(entry["source"])
        source.pop("fetchedAt", None)
        entry["source"] = source
        material.append(entry)
    return "sha256:" + hashlib.sha256(jcs(material)).hexdigest()


def build_plan(
    control: ControlInput,
    *,
    registry: FlopEndpointRegistry,
    policy: TestnetSpendPolicy,
    gate: PhaseGate,
    snapshot: SourceSnapshotSet,
    rules: FlopRuleRegistry,
    signer_id: str = "none",
) -> ExecutionPlan:
    """Resolve the control plane. Has no parameter that could carry a prompt.

    That absence is the point, and `tests/test_flop_testnet_prepare_approve.py`
    asserts it by reading this function's signature: if a later change adds a
    `workload` argument here, the test fails and somebody has to argue for it.
    """
    resolved = registry.resolve(control.endpoint_id, phase=gate.phase)
    if not isinstance(resolved, FlopEndpoint):
        raise TestnetRefusedError(resolved)
    if control.max_spend > policy.per_action_max:
        raise TestnetRefusedError(
            TestnetRefusal(
                failure=TestnetFailure.SPEND_LIMIT_EXCEEDED,
                detail=(
                    f"the requested cap {format_amount(control.max_spend)} is above the "
                    f"per-action limit {format_amount(policy.per_action_max)}; raise the "
                    "policy explicitly if that is really intended"
                ),
                stage="spend",
            )
        )
    path = control.path if control.path is not None else resolved.path_pattern
    destination = resolved.url_for(path)
    plan_id = (
        "plan-"
        + hashlib.sha256(
            jcs(
                {
                    "endpoint": resolved.endpoint_id,
                    "did": control.subject_did,
                    "type": control.action_type,
                    "path": path,
                    "max": format_amount(control.max_spend),
                    "model": control.model_id,
                }
            )
        ).hexdigest()[:16]
    )
    return ExecutionPlan(
        plan_id=plan_id,
        endpoint_id=resolved.endpoint_id,
        origin=resolved.origin,
        method=resolved.method,
        path=path,
        destination=destination,
        network=resolved.network,
        action_type=control.action_type,
        subject_did=control.subject_did,
        purpose=control.purpose,
        model=control.model_id,
        max_spend=control.max_spend,
        signer_id=signer_id,
        source_snapshot_id=snapshot_fingerprint(snapshot),
        rule_set_hash=rule_set_hash(rules),
        simulation=resolved.simulation,
        mutates_state=resolved.mutates_state,
    )


def assemble_request(
    plan: ExecutionPlan,
    workload: Untrusted[InferenceWorkload],
    *,
    at: datetime,
    quote: InferenceQuote | None = None,
    estimated_spend: Decimal | None = None,
    ttl: timedelta = DEFAULT_TTL,
    network_phase: NetworkPhase = NetworkPhase.PRE_TESTNET,
) -> PreparedTestnetAction:
    """Put the workload in its subtree and hash the whole thing.

    The body is `{"control": ..., "workload": ...}`. Two separate subtrees, both
    built key by key; the workload's contribution to the request is bytes inside
    `workload`, and the executor reads `control`.

    The prompt is scanned first. A scan is not permission -- acceptance I turns
    on that -- but text that asks for a seed phrase or tries to redirect an
    executor has no business being prepared at all, so `HIGH_RISK` and `BLOCKED`
    refuse here with `SUSPICIOUS_CONTENT`.
    """
    body = workload.value
    findings = scan_text(body.prompt, source_class=SourceClass.UNKNOWN, network_phase=network_phase)
    level = overall_level(findings)
    if level.rank >= SafetyLevel.HIGH_RISK.rank:
        raise TestnetRefusedError(
            TestnetRefusal(
                failure=TestnetFailure.SUSPICIOUS_CONTENT,
                detail=(
                    f"the workload scans as {level.display}: "
                    + "; ".join(finding.reason for finding in findings[:3])
                ),
                stage="request-validation",
            )
        )
    if quote is not None and quote.expired(at):
        raise TestnetRefusedError(
            TestnetRefusal(
                failure=TestnetFailure.QUOTE_EXPIRED,
                detail=(
                    f"quote {quote.quote_id} expired at {format_instant(quote.expires_at)}; "
                    "prepare again rather than reusing a price nobody offered"
                ),
                stage="request-validation",
            )
        )
    amount = (
        estimated_spend
        if estimated_spend is not None
        else (quote.amount if quote is not None else Decimal("0"))
    )
    if amount > plan.max_spend:
        raise TestnetRefusedError(
            TestnetRefusal(
                failure=TestnetFailure.SPEND_LIMIT_EXCEEDED,
                detail=(
                    f"the estimate {format_amount(amount)} is above this plan's cap "
                    f"{format_amount(plan.max_spend)}"
                ),
                stage="request-validation",
            )
        )

    request: dict[str, Any] = {}
    request["profile"] = REQUEST_PROFILE
    request["control"] = plan.canonical()
    request["workload"] = body.canonical()
    request["estimatedSpend"] = format_amount(amount)
    request["quoteId"] = None if quote is None else quote.quote_id
    request["expiresAt"] = format_instant(at + ttl)

    action = ActionRequest.over_bytes(
        namespace="http",
        resource=f"host:{plan.host}",
        action="post",
        destination=plan.destination,
        content=jcs(request),
    )
    return PreparedTestnetAction(
        action_id="flop-" + action.request_hash.split(":", 1)[1][:16],
        plan=plan,
        canonical_request=request,
        request_hash=action.request_hash,
        estimated_spend=amount,
        max_allowed_spend=plan.max_spend,
        quote=quote,
        prepared_at=at,
        expires_at=at + ttl,
        safety_level=level,
        safety_findings=tuple(finding.to_dict() for finding in findings),
    )


__all__ = [
    "DEFAULT_TTL",
    "REQUEST_PROFILE",
    "WORKLOAD_FIELDS",
    "ControlInput",
    "ExecutionPlan",
    "InferenceQuote",
    "InferenceWorkload",
    "PreparedTestnetAction",
    "Untrusted",
    "assemble_request",
    "build_plan",
    "rule_set_hash",
    "snapshot_fingerprint",
]
