"""The FLOP Console's HTTP surface. Reads events, scans text, writes nothing.

Mounted onto the existing app rather than served as a second service, so it
inherits the security headers, the no-keys rule and the no-ingest rule that
`lineageauth.api` already enforces. The router adds no way to put an event into
the index, and its one `POST` computes a scan and stores nothing.

`POST` is used for the scanner because the text being scanned can be long and
does not belong in a URL -- a query string ends up in logs, and the whole point
of the text is that it is untrusted. That makes the endpoint a state-changing
shape as far as a browser is concerned, so it carries an `Origin` check: a
cross-origin `POST` is refused with 403 rather than answered. The page and the
API are the same origin by design, so the check costs the real client nothing.

Every response repeats what this service will not claim: no eligibility, no
score, no wallet, no network write. Repetition in an API response is cheap and
a client that renders the wrong thing is not.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from lineageauth.approval import InMemorySpentStore
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError
from lineageauth.flop.activity import (
    ActivitySourceAdapter,
    ActivitySubject,
    LocalEventsAdapter,
    MockAdapter,
    PublicEvidenceAdapter,
    collect_activities,
)
from lineageauth.flop.coverage import compute_coverage
from lineageauth.flop.model import (
    COVERAGE_LABEL,
    NOT_AFFILIATED_NOTICE,
    SEED_WARNING_NOTICE,
    SIMULATION_BANNER,
    SYNTHETIC_BANNER,
    InferencePurpose,
    NetworkPhase,
    SourceClass,
    TestnetFailure,
    TestnetRefusal,
    TestnetRefusedError,
)
from lineageauth.flop.passport import build_flop_passport
from lineageauth.flop.recommend import next_best_action, recommend
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.safety import scan_report
from lineageauth.flop.sources import classify_source, load_snapshot
from lineageauth.flop.testnet.approve import approve
from lineageauth.flop.testnet.endpoints import FlopEndpointRegistry
from lineageauth.flop.testnet.executor import STAGES
from lineageauth.flop.testnet.mainnet import NotYetAvailableMainnetAdapter
from lineageauth.flop.testnet.meter import NetworkWriteMeter
from lineageauth.flop.testnet.phase import PhaseGate
from lineageauth.flop.testnet.prepare import InferenceWorkload, PreparedTestnetAction
from lineageauth.flop.testnet.receipts import FlopTestnetExecutionReceipt
from lineageauth.flop.testnet.signer import NoSigner
from lineageauth.flop.testnet.simulation import (
    DEMO_RECEIPT_NOTE,
    ReceiptSigning,
    demo_approval_receipt,
    prepare_simulation,
    run_simulation,
    simulate_quote,
)
from lineageauth.flop.testnet.spend import TestnetSpendPolicy, to_amount
from lineageauth.flop.wash import detect_wash_signals
from lineageauth.index import EventIndex
from lineageauth.timeutil import parse_instant

FLOP_PREFIX = "/v1/flop"

MAX_SCAN_TEXT = 32_000

# The console is read-only against the network in every phase it can currently
# reach, and the switch that would change that is off and cannot be turned on
# from an HTTP request.
KILL_SWITCH_LOCKED_NOTE = (
    "Disable all FLOP network writes: ON (locked while the network phase is PRE_TESTNET)"
)


class ScanRequest(BaseModel):
    """Untrusted text to look at. It is never executed, and no URL is followed.

    There is no `networkPhase` field on purpose. The phase is what this service
    observed, not what a caller would like it to be, and both parameters that
    soften the scanner are reachable from a page: a request that could name its
    own phase could turn "the mainnet is live" from a contradiction into
    nothing. The same reasoning bars `sourceClass: official` -- official is an
    origin (`sources.classify_source`), never a word in a request body.
    """

    model_config = ConfigDict(extra="forbid")

    text: str = Field(max_length=MAX_SCAN_TEXT)
    source_class: str | None = Field(default=None, alias="sourceClass")


class TestnetSubjectRequest(BaseModel):
    """The subject a testnet question is about. No free text, no URL."""

    __test__ = False

    model_config = ConfigDict(extra="forbid")

    lineage: str = Field(max_length=256)
    did: str = Field(max_length=256)
    at: str | None = None


class InferencePrepareRequest(BaseModel):
    """A workload plus a cap. The endpoint is chosen here, never sent by a client."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    lineage: str = Field(max_length=256)
    did: str = Field(max_length=256)
    prompt: str = Field(max_length=MAX_SCAN_TEXT)
    purpose: str = "evaluation"
    max_spend: str = Field(default="5", alias="maxSpend", max_length=32)
    evidence_label: str | None = Field(default=None, alias="evidenceLabel", max_length=128)
    at: str | None = None


class SimulationRunRequest(InferencePrepareRequest):
    """The walkthrough's input: a workload, a cap, and optionally a signed receipt.

    `approvalReceipt` is a whole LAP envelope, signed wherever the approver's
    key lives. It is verified and used for this one run and never written to the
    index: the console ingests nothing over HTTP, and a receipt is no exception.
    """

    approval_receipt: dict[str, Any] | None = Field(default=None, alias="approvalReceipt")


class ActionIdRequest(BaseModel):
    """A reference to something already prepared. Never a raw action."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    lineage: str = Field(max_length=256)
    did: str = Field(max_length=256)
    action_id: str = Field(alias="actionId", max_length=128)
    at: str | None = None


# How many prepared actions and receipts one process keeps. A prepared action
# holds the whole canonical request, prompt included, and `action_id` changes
# with the prompt, so an unbounded map is a memory leak an unauthenticated local
# caller can drive. Forgetting the oldest is the honest behaviour: the typed
# refusal for a prepared action this process no longer holds already exists.
MAX_HELD_ACTIONS = 256


class _BoundedStore[Held]:
    """A small in-memory map that forgets the oldest rather than growing."""

    __slots__ = ("_items", "_limit")

    def __init__(self, limit: int = MAX_HELD_ACTIONS) -> None:
        self._items: OrderedDict[str, Held] = OrderedDict()
        self._limit = limit

    def put(self, key: str, value: Held) -> None:
        self._items[key] = value
        self._items.move_to_end(key)
        while len(self._items) > self._limit:
            self._items.popitem(last=False)

    def get(self, key: str) -> Held | None:
        return self._items.get(key)

    def drop_where(self, predicate: Callable[[Held], bool]) -> None:
        for key in [key for key, value in self._items.items() if predicate(value)]:
            del self._items[key]

    def __len__(self) -> int:
        return len(self._items)


def _moment(at: str | None) -> datetime:
    if at is None:
        return datetime.now(UTC)
    try:
        return parse_instant(at, field="at")
    except LineageAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset(
    {"localhost", "127.0.0.1", "::1", "[::1]", "testserver"}
)


def _require_known_host(request: Request, allowed_hosts: frozenset[str]) -> None:
    """Refuse a request whose `Host` is not one this service was started for.

    Without this the same-origin test below is self-referential: it builds the
    origin it expects out of `request.url`, which is built out of the `Host`
    header, which the attacker's page controls. DNS rebinding turns that into a
    bypass -- point `evil.example` at 127.0.0.1, and a page on `evil.example`
    sends `Origin: http://evil.example` with `Host: evil.example`, the two match,
    and a local console answers a remote page. Pinning the host set closes it:
    the browser cannot forge `Host`, and a name this service does not answer to
    is refused before anything is read.
    """
    host = request.url.hostname
    if host is not None and host.lower() in allowed_hosts:
        return
    raise HTTPException(
        status_code=421,
        detail=(
            f"host {host!r} is not one this console answers to "
            f"({', '.join(sorted(allowed_hosts))}); a request arriving under another name is "
            "either misrouted or a rebinding attempt"
        ),
    )


def _require_same_origin(request: Request) -> None:
    """Refuse a cross-origin POST.

    A browser attaches `Origin` to every POST it makes. A non-browser client
    attaches none, and refusing those would break the CLI without protecting
    anybody -- the attack this guards against is a page on another origin
    driving this one, and that page cannot suppress its own `Origin`.

    The expected origin is still read off the request, but `_require_known_host`
    has already refused every `Host` this service does not answer to, so what
    this compares against is one of a fixed set of names rather than whatever a
    remote page put in the header.
    """
    origin = request.headers.get("origin")
    if origin is None:
        return
    expected = f"{request.url.scheme}://{request.url.netloc}"
    if origin != expected:
        raise HTTPException(
            status_code=403,
            detail=(
                f"cross-origin request refused: this endpoint answers {expected} only, "
                "and no CORS header makes it answer anyone else"
            ),
        )


def build_flop_router(
    index: EventIndex,
    *,
    network_phase: NetworkPhase = NetworkPhase.PRE_TESTNET,
    include_mock: bool = False,
    allowed_hosts: Iterable[str] = DEFAULT_ALLOWED_HOSTS,
    demo_approver: str | None = None,
    demo_sign_receipt: ReceiptSigning | None = None,
) -> APIRouter:
    """Build the console's routes over an existing index.

    `include_mock` is off by default and, when on, every record it produces
    carries `synthetic: true` and the response carries the banner. A demo that
    cannot be told from real data is not a demo.

    `allowed_hosts` is the set of names this console answers to. It defaults to
    loopback because that is where a local console lives, and it is checked on
    every route rather than only the writes: after a rebinding a remote page can
    read `/passport` and `/activities` as easily as it can post.
    """
    hosts = frozenset(host.lower() for host in allowed_hosts)

    def _host_guard(request: Request) -> None:
        _require_known_host(request, hosts)

    router = APIRouter(prefix=FLOP_PREFIX, tags=["flop"], dependencies=[Depends(_host_guard)])

    snapshot = load_snapshot()
    registry = FlopRuleRegistry.load()
    public_evidence = PublicEvidenceAdapter()
    mock = MockAdapter() if include_mock else None

    def _adapters(lineage: str) -> tuple[ActivitySourceAdapter, ...]:
        adapters: list[ActivitySourceAdapter] = [
            LocalEventsAdapter(index.bundle(lineage=lineage)),
            public_evidence,
        ]
        if mock is not None:
            adapters.append(mock)
        return tuple(adapters)

    def _notices() -> dict[str, Any]:
        return {
            "affiliation": NOT_AFFILIATED_NOTICE,
            "seedPhrase": SEED_WARNING_NOTICE,
            "coverage": COVERAGE_LABEL,
            **({"synthetic": SYNTHETIC_BANNER} if include_mock else {}),
        }

    @router.get("/status")
    def status() -> dict[str, Any]:
        """What phase the network is in and what this tool will refuse to do."""
        stale = registry.stale_rules(snapshot)
        return {
            "networkPhase": str(network_phase),
            "networkPhaseBadge": network_phase.badge,
            "officialTestnetExecutable": False,
            "officialTestnetReason": (
                "No official FLOP testnet endpoint appears in any snapshotted official source, "
                "and no repository in the FLOP Labs organisation publishes one."
            ),
            "killSwitch": KILL_SWITCH_LOCKED_NOTE,
            "networkWritesPerformed": meter.performed,
            "networkWriteAccounting": meter.to_dict(),
            "walletCustody": signer.holds_private_keys,
            "holdsPrivateKeys": signer.holds_private_keys,
            "dataFreshness": snapshot.fetched_at,
            "sourceCount": len(snapshot.snapshots),
            "ruleCount": len(registry.rules),
            "unknownRuleCount": len(registry.unknown_rules),
            "staleRuleCount": len(stale),
            "syntheticDataEnabled": include_mock,
            "notices": _notices(),
        }

    @router.get("/sources")
    def sources() -> dict[str, Any]:
        """The official sources as snapshotted, each with its own classification."""
        return {
            **snapshot.to_dict(),
            "classification": [
                classify_source(entry.url).to_dict() for entry in snapshot.snapshots
            ],
            "note": (
                "Official is decided by origin. A nickname, a room name, a topic or a "
                "signature does not make a message official."
            ),
            "notices": _notices(),
        }

    @router.get("/rules")
    def rules() -> dict[str, Any]:
        """Every registered FLOP rule, its source, and whether it is still current."""
        return {**registry.to_dict(snapshot), "notices": _notices()}

    @router.get("/activities")
    def activities(lineage: str, did: str, at: str | None = None) -> dict[str, Any]:
        """Everything the read-only adapters found for this subject."""
        moment = _moment(at)
        try:
            collection = collect_activities(
                _adapters(lineage), ActivitySubject(did=did, lineage=lineage, at=moment)
            )
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {**collection.to_dict(), "notices": _notices()}

    @router.get("/coverage")
    def coverage(lineage: str, did: str, at: str | None = None) -> dict[str, Any]:
        """Ten categories, five states, and no total."""
        moment = _moment(at)
        try:
            collection = collect_activities(
                _adapters(lineage), ActivitySubject(did=did, lineage=lineage, at=moment)
            )
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        report = compute_coverage(collection.records, network_phase=network_phase)
        return {**report.to_dict(), "notices": _notices()}

    @router.get("/recommendations")
    def recommendations(lineage: str, did: str, at: str | None = None) -> dict[str, Any]:
        """Suggested next steps, each saying which rule produced it."""
        moment = _moment(at)
        try:
            collection = collect_activities(
                _adapters(lineage), ActivitySubject(did=did, lineage=lineage, at=moment)
            )
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        report = compute_coverage(collection.records, network_phase=network_phase)
        signals = detect_wash_signals(collection.records)
        items = recommend(
            report,
            records=collection.records,
            wash_signals=signals,
            registry=registry,
            network_phase=network_phase,
        )
        best = next_best_action(items)
        return {
            "recommendations": [item.to_dict() for item in items],
            "nextBestAction": best.to_dict() if best is not None else None,
            "washSignals": [signal.to_dict() for signal in signals],
            "isEligibilityAdvice": False,
            "containsSyntheticData": collection.contains_synthetic,
            **({"banner": SYNTHETIC_BANNER} if collection.contains_synthetic else {}),
            "notices": _notices(),
        }

    @router.get("/passport/{did}")
    def passport(did: str, lineage: str, at: str | None = None) -> dict[str, Any]:
        """The whole projection for one DID."""
        moment = _moment(at)
        try:
            built = build_flop_passport(
                index.bundle(lineage=lineage),
                lineage=lineage,
                did=did,
                at=moment,
                adapters=_adapters(lineage),
                registry=registry,
                snapshot=snapshot,
                network_phase=network_phase,
            )
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return built.to_dict()

    @router.post("/safety/scan")
    def safety_scan(request: Request, body: Annotated[ScanRequest, ...]) -> dict[str, Any]:
        """Scan untrusted text. Executes nothing and follows no URL it finds."""
        _require_same_origin(request)
        source_class = SourceClass.UNKNOWN
        if body.source_class is not None:
            if body.source_class not in tuple(SourceClass):
                raise HTTPException(
                    status_code=400,
                    detail=f"unknown sourceClass {body.source_class!r}",
                )
            if body.source_class == str(SourceClass.OFFICIAL):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "sourceClass 'official' cannot be asserted by a client: official is "
                        "decided by origin, and asserting it here would switch off the "
                        "impersonation check on text that claims to speak for FLOP Labs"
                    ),
                )
            source_class = SourceClass(body.source_class)
        return {
            **scan_report(body.text, source_class=source_class, network_phase=network_phase),
            "phaseIsThisService": True,
            "phaseNote": (
                "The phase used for this scan is the one this service observed. It cannot be "
                "set by a request."
            ),
            "notices": _notices(),
        }

    # ------------------------------------------------------------------ testnet
    #
    # Every route below refuses before it could reach a network, and only
    # `simulation/run` produces a receipt -- because the only network this tool
    # can currently reach is one that RFC 6761 guarantees does not resolve.
    gate = PhaseGate(phase=network_phase, kill_switch_engaged=True)
    endpoints = FlopEndpointRegistry.default()
    spend_policy = TestnetSpendPolicy()
    signer = NoSigner()
    mainnet = NotYetAvailableMainnetAdapter(registry=registry, network_phase=network_phase)
    spent_store = InMemorySpentStore()
    prepared_actions: _BoundedStore[PreparedTestnetAction] = _BoundedStore()
    receipts: _BoundedStore[FlopTestnetExecutionReceipt] = _BoundedStore()
    meter = NetworkWriteMeter()

    def _refuse(refusal: TestnetRefusal) -> HTTPException:
        return HTTPException(status_code=409, detail=refusal.to_dict())

    def _purpose(value: str) -> InferencePurpose:
        if value not in tuple(InferencePurpose):
            raise HTTPException(status_code=400, detail=f"unknown purpose {value!r}")
        return InferencePurpose(value)

    def _amount(value: str) -> Decimal:
        try:
            return to_amount(value, field_name="maxSpend")
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    def _workload(body: InferencePrepareRequest) -> InferenceWorkload:
        try:
            return InferenceWorkload(
                purpose=_purpose(body.purpose),
                prompt=body.prompt,
                evidence_label=body.evidence_label,
            )
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.get("/testnet/state")
    def testnet_state() -> dict[str, Any]:
        """The phase, the kill switch, the endpoint registry and the spend policy."""
        return {
            **gate.to_dict(),
            "endpoints": endpoints.to_dict(),
            "spendPolicy": spend_policy.to_dict(),
            "signer": signer.to_dict(),
            "mainnet": mainnet.to_dict("did:key:not-specified"),
            "executorStages": list(STAGES),
            "officialTestnetExecutable": bool(endpoints.executable_entries),
            "faucet": "INTERFACE_ONLY",
            "inference": "INTERFACE_ONLY",
            "networkWritesPerformed": meter.performed,
            "networkWriteAccounting": meter.to_dict(),
            "walletCustody": signer.holds_private_keys,
            "holdsPrivateKeys": signer.holds_private_keys,
            "heldPreparedActions": len(prepared_actions),
            "heldReceipts": len(receipts),
            "maxHeldActions": MAX_HELD_ACTIONS,
            "notices": _notices(),
        }

    @router.get("/testnet/receipts/{receipt_id}")
    def testnet_receipt(receipt_id: str) -> dict[str, Any]:
        """One execution receipt from this process. A simulated one says so."""
        receipt = receipts.get(receipt_id)
        if receipt is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"no receipt {receipt_id!r} in this process; receipts are held in memory "
                    "and a simulation run produces one"
                ),
            )
        return {**receipt.to_dict(), "notices": _notices()}

    @router.post("/testnet/inference/quote")
    def testnet_quote(
        request: Request, body: Annotated[TestnetSubjectRequest, ...]
    ) -> dict[str, Any]:
        """A synthetic price. No official pricing mechanism is published."""
        _require_same_origin(request)
        quote = simulate_quote(subject_did=body.did, at=_moment(body.at))
        return {
            "quote": quote.to_dict(),
            "officialPricingAvailable": False,
            "reason": (
                "No official FLOP pricing or quote mechanism appears in any snapshotted "
                "official source, so this figure is invented locally."
            ),
            "banner": SIMULATION_BANNER,
            "notices": _notices(),
        }

    @router.post("/testnet/inference/prepare")
    def testnet_prepare(
        request: Request, body: Annotated[InferencePrepareRequest, ...]
    ) -> dict[str, Any]:
        """Build the exact action a person would approve. Sends nothing."""
        _require_same_origin(request)
        moment = _moment(body.at)
        workload = _workload(body)
        try:
            # The same helper the simulation uses, so a prepared action from this
            # route and one from a run are the same bytes -- an approval receipt
            # obtained through the UI has to fit the action the executor sees.
            prepared = prepare_simulation(
                subject_did=body.did,
                at=moment,
                snapshot=snapshot,
                rules=registry,
                workload=workload,
                registry=endpoints,
                policy=spend_policy,
                gate=gate,
                max_spend=_amount(body.max_spend),
            )
        except TestnetRefusedError as exc:
            raise _refuse(exc.refusal) from exc
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # Expired actions go before the new one is held: a prepared action has a
        # 15-minute life, and keeping one past that is holding a prompt for no
        # reason anybody could act on.
        prepared_actions.drop_where(lambda held: held.expired(moment))
        prepared_actions.put(prepared.action_id, prepared)
        return {**prepared.to_dict(), "notices": _notices()}

    @router.post("/testnet/inference/approve")
    def testnet_approve(request: Request, body: Annotated[ActionIdRequest, ...]) -> dict[str, Any]:
        """Check that a receipt binds this exact action. Consumes no receipt."""
        _require_same_origin(request)
        prepared = prepared_actions.get(body.action_id)
        if prepared is None:
            raise _refuse(
                TestnetRefusal(
                    failure=TestnetFailure.REPREPARE_REQUIRED,
                    detail=(
                        f"no prepared action {body.action_id!r} in this process: prepared "
                        f"actions live in memory, expire after their window and are capped at "
                        f"{MAX_HELD_ACTIONS}, so prepare it again"
                    ),
                    stage="approval",
                )
            )
        try:
            decided = approve(
                prepared,
                bundle=index.bundle(lineage=body.lineage),
                lineage=body.lineage,
                agent=body.did,
                at=_moment(body.at),
                store=spent_store,
                snapshot=snapshot,
                rules=registry,
                reserve=False,
            )
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if isinstance(decided, TestnetRefusal):
            raise _refuse(decided)
        return {**decided.to_dict(), "notices": _notices()}

    @router.post("/testnet/inference/execute")
    def testnet_execute(request: Request, body: Annotated[ActionIdRequest, ...]) -> dict[str, Any]:
        """Refused while the phase is not TESTNET_ENABLED, before anything is read."""
        _require_same_origin(request)
        refusal = gate.refusal()
        if refusal is not None:
            raise _refuse(refusal)
        raise _refuse(  # pragma: no cover - no executable entry exists to reach this
            TestnetRefusal(
                failure=TestnetFailure.ENDPOINT_NOT_OFFICIAL,
                detail=(
                    "the phase permits execution, but the endpoint registry holds no "
                    "executable official entry"
                ),
                stage="endpoint",
            )
        )

    @router.post("/testnet/simulation/run")
    def testnet_simulation(
        request: Request, body: Annotated[SimulationRunRequest, ...]
    ) -> dict[str, Any]:
        """The whole flow against the reserved simulation origin. Nothing leaves this process.

        The approval in the middle of the flow comes from one of three places,
        and the response says which: a receipt the caller pasted (verified, used
        once, never indexed); the demo approver a demo process was started with;
        or nowhere, in which case the walkthrough stops at the approval step and
        says so. A receipt reaching the index would be ingestion, and this
        console has no ingest path.
        """
        _require_same_origin(request)
        workload = _workload(body)
        moment = _moment(body.at)
        max_spend = _amount(body.max_spend)
        receipt_source = "none"
        approver: str | None = None
        receipt: Envelope | None = None
        if body.approval_receipt is not None:
            try:
                receipt = Envelope.model_validate(body.approval_receipt)
            except Exception as exc:
                raise HTTPException(
                    status_code=400, detail=f"approvalReceipt is not an LAP envelope: {exc}"
                ) from exc
            receipt_source = "pasted"
        elif demo_approver is not None and demo_sign_receipt is not None:
            try:
                preview = prepare_simulation(
                    subject_did=body.did,
                    at=moment,
                    snapshot=snapshot,
                    rules=registry,
                    workload=workload,
                    registry=endpoints,
                    policy=spend_policy,
                    gate=gate,
                    max_spend=max_spend,
                )
            except LineageAuthError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            receipt = demo_approval_receipt(
                preview,
                lineage=body.lineage,
                agent=body.did,
                approver=demo_approver,
                at=moment,
                sign=demo_sign_receipt,
            )
            receipt_source = "demo-approver"
            approver = demo_approver
        if receipt is None:
            bundle = index.bundle(lineage=body.lineage)
        else:
            # Transient: the receipt lives in this bundle and nowhere else.
            bundle = EventBundle.from_envelopes([*index.envelopes(lineage=body.lineage), receipt])
            if approver is None:
                approver = str(receipt.payload.get("approver") or "")
        try:
            run = run_simulation(
                bundle=bundle,
                lineage=body.lineage,
                agent=body.did,
                at=moment,
                snapshot=snapshot,
                rules=registry,
                store=InMemorySpentStore(),
                workload=workload,
                registry=endpoints,
                policy=spend_policy,
                gate=gate,
                max_spend=max_spend,
            )
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if run.outcome is not None:
            meter.observe(run.outcome.network_attempts, simulation=True)
            if run.outcome.receipt is not None:
                receipts.put(run.outcome.receipt.action_id, run.outcome.receipt)
        if run.prepared is not None:
            prepared_actions.put(run.prepared.action_id, run.prepared)
        return {
            **run.to_dict(),
            "approvalReceipt": {
                "source": receipt_source,
                "approver": approver,
                "synthetic": receipt_source == "demo-approver",
                "ingested": False,
                "note": (
                    DEMO_RECEIPT_NOTE
                    if receipt_source == "demo-approver"
                    else "verified for this run only; the index was not written"
                    if receipt_source == "pasted"
                    else "no receipt was supplied and this process holds no signer, so the "
                    "walkthrough stops at the approval step; paste a signed approval receipt "
                    "for this exact request hash to continue"
                ),
            },
            "notices": _notices(),
        }

    return router


__all__ = [
    "DEFAULT_ALLOWED_HOSTS",
    "FLOP_PREFIX",
    "KILL_SWITCH_LOCKED_NOTE",
    "MAX_HELD_ACTIONS",
    "ActionIdRequest",
    "InferencePrepareRequest",
    "NetworkWriteMeter",
    "ScanRequest",
    "TestnetSubjectRequest",
    "build_flop_router",
]
