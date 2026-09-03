"""`la flop` -- read the FLOP layer from a terminal, and change nothing.

Every command here computes and prints. None of them fetches a source, signs an
event, claims a faucet, buys inference or writes a file. `inference execute` is
absent on purpose: directive 29 permits it only once the testnet is officially
enabled, and only against an already-approved prepared action, so shipping it
now would be shipping a command whose only possible behaviour is to refuse.

Output is ASCII. `tests/test_zero_cost.py` learned that the hard way -- one em
dash in a help string took the whole command down on a Japanese Windows console
under cp932 -- so the coverage label has an ASCII spelling and this file uses it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any

import typer

from lineageauth import jsonio
from lineageauth.approval import InMemorySpentStore
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError
from lineageauth.flop.model import (
    COVERAGE_LABEL_ASCII,
    NOT_AFFILIATED_NOTICE,
    SEED_WARNING_NOTICE,
    SIMULATION_BANNER,
    InferencePurpose,
    TestnetRefusal,
    TestnetRefusedError,
)
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.sources import classify_source, load_snapshot
from lineageauth.flop.testnet.meter import NetworkWriteMeter
from lineageauth.flop.testnet.signer import NoSigner
from lineageauth.timeutil import parse_instant

flop_app = typer.Typer(
    name="flop",
    help=(
        "Read the FLOP layer: official sources, registered rules, testnet state and a "
        "full local simulation. Nothing here fetches, signs, spends or sends."
    ),
    no_args_is_help=True,
)

testnet_app = typer.Typer(
    name="testnet", help="Testnet phase, gates and the local simulation.", no_args_is_help=True
)
faucet_app = typer.Typer(
    name="faucet",
    help="Faucet preparation. No official procedure is published.",
    no_args_is_help=True,
)
inference_app = typer.Typer(
    name="inference", help="Quote, prepare and inspect an inference action.", no_args_is_help=True
)
receipt_app = typer.Typer(
    name="receipt", help="Re-check an execution receipt this tool produced.", no_args_is_help=True
)
flop_app.add_typer(testnet_app)
flop_app.add_typer(faucet_app)
flop_app.add_typer(inference_app)
flop_app.add_typer(receipt_app)

STDIN_SENTINEL = "-"


def _moment(at: str | None) -> datetime:
    if at is None:
        return datetime.now(tz=UTC)
    try:
        return parse_instant(at, field="--at")
    except LineageAuthError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


def _read(path: str) -> str:
    if path == STDIN_SENTINEL:
        import sys

        return sys.stdin.read()
    source = Path(path)
    if not source.is_file():
        typer.secho(f"error: no such file: {path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    return source.read_text(encoding="utf-8-sig")


def _read_json(path: str) -> dict[str, Any]:
    try:
        loaded = jsonio.loads(_read(path))
    except LineageAuthError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    if not isinstance(loaded, dict):
        typer.secho("error: expected a JSON object", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    return loaded


def _bundle(path: str | None) -> EventBundle:
    """A bundle from a file, or an empty one so the flow can still be shown."""
    if path is None:
        return EventBundle.from_envelopes([])
    try:
        parsed = jsonio.loads(_read(path))
    except LineageAuthError:
        parsed = [jsonio.loads(line) for line in _read(path).splitlines() if line.strip()]
    if isinstance(parsed, dict):
        parsed = parsed["events"] if "events" in parsed else [parsed]
    if not isinstance(parsed, list):
        typer.secho("error: a bundle must be an array of envelopes", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    try:
        envelopes = [Envelope.model_validate(item) for item in parsed]
    except Exception as exc:
        typer.secho(f"error: not an LAP envelope bundle: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    return EventBundle.from_envelopes(envelopes)


def _emit(body: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        typer.echo(json.dumps(body, ensure_ascii=True, sort_keys=True))


def _print_refusal(refusal: TestnetRefusal) -> None:
    typer.secho(f"  refused: {refusal.failure}", fg=typer.colors.RED, err=True)
    typer.echo(f"    stage   {refusal.stage or 'unknown'}")
    typer.echo(f"    detail  {refusal.detail}")


@flop_app.command("status")
def flop_status(
    as_json: Annotated[bool, typer.Option("--json", help="Emit the status object.")] = False,
) -> None:
    """The network phase, the kill switch, and what this tool will not do."""
    from lineageauth.flop.testnet.endpoints import FlopEndpointRegistry
    from lineageauth.flop.testnet.phase import PhaseGate

    snapshot = load_snapshot()
    registry = FlopRuleRegistry.load()
    endpoints = FlopEndpointRegistry.default()
    gate = PhaseGate()
    meter = NetworkWriteMeter()
    body = {
        "networkPhase": str(gate.phase),
        "officialTestnetExecutable": bool(endpoints.executable_entries),
        "killSwitch": gate.to_dict()["killSwitch"],
        "sourceCount": len(snapshot.snapshots),
        "ruleCount": len(registry.rules),
        "unknownRuleCount": len(registry.unknown_rules),
        "staleRuleCount": len(registry.stale_rules(snapshot)),
        "dataFreshness": snapshot.fetched_at,
        # Counted in this process rather than asserted: a fresh meter that has
        # observed nothing reports nothing, and the CLI performs no execution.
        "networkWritesPerformed": meter.performed,
        "networkWriteAccounting": meter.to_dict(),
        "walletCustody": NoSigner().holds_private_keys,
        "coverageLabel": COVERAGE_LABEL_ASCII,
    }
    if as_json:
        _emit(body, as_json=True)
        return
    typer.secho("  FLOP status", bold=True)
    typer.echo(f"    network phase        {body['networkPhase']}")
    typer.echo(f"    testnet executable   {'yes' if body['officialTestnetExecutable'] else 'no'}")
    typer.echo(
        f"    network writes       {body['networkWritesPerformed']} "
        "(measured in this process; none possible in this phase)"
    )
    typer.echo("    wallet custody       none")
    typer.echo(f"    official sources     {body['sourceCount']} snapshotted")
    typer.echo(
        f"    rules                {body['ruleCount']} "
        f"({body['unknownRuleCount']} unknown, {body['staleRuleCount']} stale)"
    )
    typer.echo(f"    data freshness       {body['dataFreshness']}")
    typer.echo(f"    {COVERAGE_LABEL_ASCII}")
    typer.echo(f"    {NOT_AFFILIATED_NOTICE}")


@flop_app.command("sources")
def flop_sources(
    as_json: Annotated[bool, typer.Option("--json", help="Emit the source list.")] = False,
) -> None:
    """Every official source as it was snapshotted. Fetches nothing."""
    snapshot = load_snapshot()
    rows = [
        {**entry.to_dict(), "classification": classify_source(entry.url).to_dict()}
        for entry in snapshot.snapshots
    ]
    if as_json:
        _emit({"fetchedAt": snapshot.fetched_at, "sources": rows}, as_json=True)
        return
    typer.secho("  FLOP official sources", bold=True)
    typer.echo(f"    fetched at {snapshot.fetched_at}")
    for row in rows:
        badge = str(row["classification"]["sourceClass"]).upper()
        typer.echo(f"    [{badge}] {row['id']}")
        typer.echo(f"        {row['url']}")
        typer.echo(f"        sha256 {row['sha256'] or 'not recorded'}  status {row['status']}")
    typer.echo("    official is decided by origin, never by wording")


@flop_app.command("rules")
def flop_rules(
    as_json: Annotated[bool, typer.Option("--json", help="Emit the rule registry.")] = False,
) -> None:
    """Every registered rule, its status, and whether its source still matches."""
    snapshot = load_snapshot()
    registry = FlopRuleRegistry.load()
    if as_json:
        _emit(registry.to_dict(snapshot), as_json=True)
        return
    typer.secho("  FLOP rules", bold=True)
    freshness = {item.rule_id: item for item in registry.freshness(snapshot)}
    for rule in registry.rules:
        state = freshness.get(rule.rule_id)
        label = "" if state is None or state.label is None else f"  [{state.label}]"
        typer.echo(f"    {rule.rule_id}  ({rule.status}){label}")
        typer.echo(f"        {rule.statement[:88]}")
    typer.echo("    every figure above is data read from conformance/flop/rule-registry.json")


@testnet_app.command("simulate")
def testnet_simulate(
    did: Annotated[str, typer.Option("--did", help="The agent DID the simulation runs for.")],
    lineage: Annotated[str, typer.Option("--lineage", help="Lineage id for the bundle.")] = "",
    bundle_path: Annotated[
        str | None, typer.Option("--bundle", help="Envelope bundle, or '-' for stdin.")
    ] = None,
    at: Annotated[str | None, typer.Option("--at", help="RFC3339 instant to evaluate at.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the whole run.")] = False,
) -> None:
    """Walk the full flow against the reserved simulation origin. Nothing is sent."""
    from lineageauth.flop.testnet.simulation import run_simulation

    bundle = _bundle(bundle_path)
    target = lineage or (bundle.lineages()[0] if bundle.lineages() else "lineage-unset")
    run = run_simulation(
        bundle=bundle,
        lineage=target,
        agent=did,
        at=_moment(at),
        snapshot=load_snapshot(),
        rules=FlopRuleRegistry.load(),
        store=InMemorySpentStore(),
    )
    if as_json:
        _emit(run.to_dict(), as_json=True)
        raise typer.Exit(code=0 if run.ok else 1)
    typer.secho(f"  {SIMULATION_BANNER}", bold=True)
    for step in run.steps:
        mark = "ok  " if step.ok else "STOP"
        typer.echo(f"    [{mark}] {step.label}")
        typer.echo(f"           {step.detail}")
    typer.echo(f"    transport calls {run.transport_calls} (simulation only, no network)")
    typer.echo(f"    network writes performed: {run.network_writes_performed} (measured)")
    typer.echo(f"    {SEED_WARNING_NOTICE}")
    raise typer.Exit(code=0 if run.ok else 1)


@faucet_app.command("prepare")
def faucet_prepare(
    did: Annotated[str, typer.Option("--did", help="The agent DID the faucet would credit.")],
    at: Annotated[str | None, typer.Option("--at", help="RFC3339 instant to evaluate at.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the prepared action.")] = False,
) -> None:
    """Not yet available. Prints the simulated request instead, and claims nothing."""
    from lineageauth.flop.testnet.simulation import prepare_faucet_simulation

    prepared = prepare_faucet_simulation(
        subject_did=did,
        at=_moment(at),
        snapshot=load_snapshot(),
        rules=FlopRuleRegistry.load(),
    )
    if as_json:
        _emit(
            {
                "officialFaucetAvailable": False,
                "status": "not-yet-available",
                "prepared": prepared.to_dict(),
            },
            as_json=True,
        )
        return
    typer.secho("  FLOP faucet: NOT YET AVAILABLE", bold=True)
    typer.echo("    No official faucet procedure appears in any snapshotted official source.")
    typer.echo("    The request below is synthetic and was not sent.")
    typer.echo("")
    typer.echo(prepared.preview())


@inference_app.command("quote")
def inference_quote(
    did: Annotated[str, typer.Option("--did", help="The agent DID the quote is for.")],
    at: Annotated[str | None, typer.Option("--at", help="RFC3339 instant to evaluate at.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the quote.")] = False,
) -> None:
    """A synthetic price. No official pricing mechanism is published."""
    from lineageauth.flop.testnet.simulation import simulate_quote

    quote = simulate_quote(subject_did=did, at=_moment(at))
    if as_json:
        _emit({"quote": quote.to_dict(), "officialPricingAvailable": False}, as_json=True)
        return
    typer.secho(f"  {SIMULATION_BANNER}", bold=True)
    typer.echo(f"    quote id    {quote.quote_id}")
    typer.echo(f"    amount      {quote.to_dict()['amount']} {quote.currency}")
    typer.echo(f"    expires     {quote.to_dict()['expiresAt']}")
    typer.echo("    official pricing mechanism: none published")


@inference_app.command("prepare")
def inference_prepare(
    did: Annotated[str, typer.Option("--did", help="The agent DID the action is for.")],
    prompt: Annotated[str, typer.Option("--prompt", help="The workload text.")],
    purpose: Annotated[
        str, typer.Option("--purpose", help="Why this inference is wanted.")
    ] = "evaluation",
    max_spend: Annotated[
        str, typer.Option("--max-spend", help="The ceiling a human would approve.")
    ] = "5",
    at: Annotated[str | None, typer.Option("--at", help="RFC3339 instant to evaluate at.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the prepared action.")] = False,
) -> None:
    """Build the exact action a person would approve. Sends nothing, signs nothing."""
    from lineageauth.flop.testnet.prepare import InferenceWorkload
    from lineageauth.flop.testnet.simulation import prepare_simulation

    if purpose not in tuple(InferencePurpose):
        typer.secho(
            f"error: unknown purpose {purpose!r}; known: "
            f"{', '.join(str(item) for item in InferencePurpose)}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    try:
        workload = InferenceWorkload(purpose=InferencePurpose(purpose), prompt=prompt)
        prepared = prepare_simulation(
            subject_did=did,
            at=_moment(at),
            snapshot=load_snapshot(),
            rules=FlopRuleRegistry.load(),
            workload=workload,
            max_spend=Decimal(max_spend),
        )
    except TestnetRefusedError as exc:
        _print_refusal(exc.refusal)
        raise typer.Exit(code=1) from exc
    except LineageAuthError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    if as_json:
        _emit(prepared.to_dict(), as_json=True)
        return
    typer.echo(prepared.preview())


@inference_app.command("inspect")
def inference_inspect(
    action: Annotated[
        str, typer.Argument(metavar="ACTION", help="A prepared action JSON file, or '-'.")
    ],
    as_json: Annotated[bool, typer.Option("--json", help="Emit the inspection.")] = False,
) -> None:
    """Re-derive a prepared action's request hash and say whether it still matches.

    Exit code 1 means the recorded hash and the canonical bytes disagree, which
    is what a changed byte looks like from the outside.
    """
    from lineageauth.actions import ActionRequest
    from lineageauth.canonical import jcs

    body = _read_json(action)
    recorded = body.get("requestHash")
    canonical = body.get("canonicalRequest")
    destination = body.get("canonicalDestination")
    if not isinstance(canonical, dict) or not isinstance(destination, str):
        typer.secho(
            "error: that file has no canonicalRequest and canonicalDestination",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    host = destination.split("://", 1)[-1].split("/", 1)[0]
    try:
        rebuilt = ActionRequest.over_bytes(
            namespace="http",
            resource=f"host:{host}",
            action="post",
            destination=destination,
            content=jcs(canonical),
        )
    except LineageAuthError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    matches = rebuilt.request_hash == recorded
    if as_json:
        _emit(
            {
                "actionId": body.get("id"),
                "recordedRequestHash": recorded,
                "derivedRequestHash": rebuilt.request_hash,
                "matches": matches,
                "destination": destination,
                "authority": rebuilt.render(),
                "sent": False,
            },
            as_json=True,
        )
        raise typer.Exit(code=0 if matches else 1)
    typer.secho(
        f"  prepared action: {'MATCHES' if matches else 'DOES NOT MATCH'}",
        fg=typer.colors.GREEN if matches else typer.colors.RED,
        bold=True,
    )
    typer.echo(f"    recorded  {recorded}")
    typer.echo(f"    derived   {rebuilt.request_hash}")
    typer.echo(f"    authority {rebuilt.render()}")
    typer.echo("    nothing was sent and no approval was consumed")
    raise typer.Exit(code=0 if matches else 1)


@receipt_app.command("verify")
def receipt_verify(
    receipt_file: Annotated[
        str, typer.Argument(metavar="RECEIPT", help="An execution receipt JSON file, or '-'.")
    ],
    as_json: Annotated[bool, typer.Option("--json", help="Emit the verification.")] = False,
) -> None:
    """Say what a receipt does and does not establish. Exit 1 if it is not fully verified."""
    from lineageauth.flop.testnet.evidence import DOES_NOT_PROVE, PROVES
    from lineageauth.flop.testnet.receipts import NOT_PROOF_NOTE

    body = _read_json(receipt_file)
    state = str(body.get("verificationState", "unverified"))
    missing = body.get("unverifiedBecause")
    reasons = [str(item) for item in missing] if isinstance(missing, list) else []
    verified = state == "verified"
    if as_json:
        _emit(
            {
                "actionId": body.get("actionId"),
                "verificationState": state,
                "fullyVerified": verified,
                "unverifiedBecause": reasons,
                "synthetic": bool(body.get("synthetic")),
                "simulation": bool(body.get("simulation")),
                "proves": list(PROVES),
                "doesNotProve": list(DOES_NOT_PROVE),
            },
            as_json=True,
        )
        raise typer.Exit(code=0 if verified else 1)
    typer.secho(f"  receipt: {state}", bold=True)
    if body.get("simulation"):
        typer.echo(f"    {SIMULATION_BANNER}")
    typer.echo(f"    action      {body.get('actionId')}")
    typer.echo(f"    request     {body.get('requestHash')}")
    typer.echo(f"    response    {body.get('responseHash')}")
    typer.echo(f"    network ref {body.get('transactionOrReceiptRef')}")
    for reason in reasons:
        typer.echo(f"    not verified: {reason}")
    typer.echo(f"    {NOT_PROOF_NOTE}")
    raise typer.Exit(code=0 if verified else 1)


__all__ = ["flop_app"]
