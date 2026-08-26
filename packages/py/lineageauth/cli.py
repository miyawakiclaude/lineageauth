"""The `la` command line interface.

CLAUDE.md 9 names the first usable feature: `la verify <signed-event.json>`.
The ambition is not a pretty console -- it is to state, checkably, why a result
is what it is.

Safety rules this CLI follows:
  * it never accepts a raw private seed as an argument (docs/16_API_SDK_CLI.md);
  * it performs no network access;
  * a non-zero exit code means "did not verify", so CI can gate on it.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from lineageauth import __version__, catalog, jsonio
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError, ReasonCode
from lineageauth.lineage import LineageState, resolve_lineage
from lineageauth.timeutil import format_instant, parse_instant
from lineageauth.verify import EventVerification, verify_event_json

app = typer.Typer(
    name="la",
    help="LineageAuth (LAP) — verify agent authority and evidence offline.",
    no_args_is_help=True,
    add_completion=False,
)

lineage_app = typer.Typer(
    name="lineage",
    help="Resolve the current root and epoch of a lineage from a bundle of events.",
    no_args_is_help=True,
)
app.add_typer(lineage_app)

STDIN_SENTINEL = "-"


def _read_source(path: str) -> str:
    if path == STDIN_SENTINEL:
        return sys.stdin.read()
    source = Path(path)
    if not source.is_file():
        typer.secho(f"error: no such file: {path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    return source.read_text(encoding="utf-8")


def _result_as_dict(result: EventVerification) -> dict[str, object]:
    return {
        "integrityOk": result.integrity_ok,
        "reason": str(result.reason),
        "detail": result.detail,
        "eventId": result.event_id,
        "eventType": result.event_type,
        "eventFamily": result.event_family,
        "lineage": result.lineage,
        "verifiedSigners": list(result.verified_signers),
        "proofs": [
            {
                "index": proof.index,
                "signer": proof.signer,
                "alg": proof.alg,
                "verified": proof.verified,
                "reason": str(proof.reason),
                "detail": proof.detail,
            }
            for proof in result.proofs
        ],
        "warnings": list(result.warnings),
        "note": result.note,
    }


def _print_human(result: EventVerification) -> None:
    colour = typer.colors.GREEN if result.integrity_ok else typer.colors.RED
    typer.secho(f"{result.reason}", fg=colour, bold=True)
    typer.echo(f"  {result.detail}")
    typer.echo("")

    for label, value in (
        ("event id", result.event_id),
        ("type", result.event_type),
        ("family", result.event_family),
        ("lineage", result.lineage),
    ):
        if value is not None:
            typer.echo(f"  {label:<10} {value}")

    if result.proofs:
        typer.echo("")
        typer.echo("  proofs")
        for proof in result.proofs:
            mark = "ok  " if proof.verified else "FAIL"
            typer.echo(f"    [{proof.index}] {mark} {proof.alg}  {proof.signer}")
            if not proof.verified:
                typer.echo(f"           {proof.detail}")

    for warning in result.warnings:
        typer.echo("")
        typer.secho(f"  warning: {warning}", fg=typer.colors.YELLOW)

    if result.integrity_ok:
        typer.echo("")
        typer.secho(f"  note: {result.note}", fg=typer.colors.YELLOW)


@app.command()
def verify(
    event: Annotated[
        str,
        typer.Argument(help="Path to a signed event envelope, or '-' to read stdin."),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit the machine-readable result instead of prose."),
    ] = False,
) -> None:
    """Verify one signed event's structure and signatures.

    This checks integrity only. It does not decide whether an action is
    authorized -- that requires the full authority chain, and a verified
    signature on its own authorizes nothing.
    """
    result = verify_event_json(_read_source(event))

    if as_json:
        typer.echo(jsonio.dumps(_result_as_dict(result)))
    else:
        _print_human(result)

    raise typer.Exit(code=0 if result.integrity_ok else 1)


@app.command(name="event-id")
def event_id(
    event: Annotated[
        str,
        typer.Argument(help="Path to an event envelope or bare payload, or '-' for stdin."),
    ],
) -> None:
    """Print the canonical event id for a payload, without verifying signatures."""
    from lineageauth.canonical import compute_event_id
    from lineageauth.errors import LineageAuthError

    parsed = jsonio.loads(_read_source(event))
    payload = parsed.get("payload", parsed) if isinstance(parsed, dict) else parsed
    try:
        typer.echo(compute_event_id(payload))
    except LineageAuthError as exc:
        typer.secho(f"{ReasonCode.MALFORMED}: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc


class MalformedBundleError(LineageAuthError):
    """The bundle file itself could not be read. Distinct from a failed resolution."""


def _parse_envelopes(text: str) -> list[Envelope]:
    """Read a bundle of envelopes.

    Three spellings are accepted because all three occur in practice: a JSON
    array, an object with an `events` array, and JSON Lines. The resolver sorts
    by event id, so the spelling -- and the order within it -- cannot change the
    answer.
    """
    try:
        parsed = jsonio.loads(text)
    except LineageAuthError:
        parsed = [jsonio.loads(line) for line in text.splitlines() if line.strip()]

    if isinstance(parsed, dict):
        parsed = parsed["events"] if "events" in parsed else [parsed]
    if not isinstance(parsed, list):
        raise MalformedBundleError("a bundle must be an array of envelopes, or JSON Lines")

    envelopes: list[Envelope] = []
    for index, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise MalformedBundleError(f"entry {index} is not a JSON object")
        try:
            envelopes.append(Envelope.model_validate(item))
        except Exception as exc:
            raise MalformedBundleError(f"entry {index} is not an LAP envelope: {exc}") from exc
    return envelopes


def _state_as_dict(state: LineageState, bundle: EventBundle) -> dict[str, Any]:
    return {
        "lineage": state.lineage,
        "resolved": state.resolved,
        "reason": str(state.reason),
        "detail": state.detail,
        "evaluatedAt": format_instant(state.evaluated_at),
        "genesisRoot": state.genesis_root,
        # `root`/`epoch` are the last position the walk could justify, which is
        # not the same claim as "this is the current root". When `resolved` is
        # false they are how far it got, nothing more, and a consumer that reads
        # them without reading `resolved` would draw the wrong conclusion.
        "root": state.root if state.resolved else None,
        "epoch": state.epoch if state.resolved else None,
        "lastJustifiedRoot": state.root,
        "lastJustifiedEpoch": state.epoch,
        "supersededRoots": list(state.superseded_roots),
        "history": [
            {
                "fromEpoch": step.from_epoch,
                "toEpoch": step.to_epoch,
                "fromRoot": step.from_root,
                "toRoot": step.to_root,
                "mode": step.mode,
                "viaEventIds": list(step.via_event_ids),
            }
            for step in state.history
        ],
        "activeRecoveryPolicy": (
            None
            if state.active_recovery_policy is None
            else {
                "eventId": state.active_recovery_policy.event_id,
                "epoch": state.active_recovery_policy.epoch,
                "policySeq": state.active_recovery_policy.policy_seq,
                "members": list(state.active_recovery_policy.members),
                "threshold": state.active_recovery_policy.threshold,
            }
        ),
        "conflictingEventIds": list(state.conflicting_event_ids),
        "denied": [
            {
                "eventId": item.event_id,
                "eventType": item.event_type,
                "reason": str(item.reason),
                "detail": item.detail,
            }
            for item in state.denied
        ],
        # Integrity failures are dropped before the resolver ever sees them, so
        # this is the only place they surface. Omitting them turns "somebody
        # sent us a tampered event" into silence, which is the opposite of what
        # an audit trail is for.
        "rejected": [
            {
                "eventId": item.event_id,
                "eventType": item.event_type,
                "lineage": item.lineage,
                "reason": str(item.reason),
                "detail": item.detail,
            }
            for item in bundle.rejected
        ],
        "warnings": list(state.warnings),
        "note": state.note,
    }


def _print_lineage(state: LineageState, bundle: EventBundle) -> None:
    colour = typer.colors.GREEN if state.resolved else typer.colors.RED
    typer.secho(f"{state.reason}", fg=colour, bold=True)
    typer.echo(f"  {state.detail}")
    typer.echo("")
    typer.echo(f"  lineage      {state.lineage}")
    if state.resolved:
        typer.echo(f"  root         {state.root}")
        typer.echo(f"  epoch        {state.epoch}")
    else:
        typer.echo(f"  root         (unresolved; last justified: {state.root})")
        typer.echo(f"  epoch        (unresolved; last justified: {state.epoch})")
    typer.echo(f"  genesis      {state.genesis_root}")
    typer.echo(f"  evaluatedAt  {format_instant(state.evaluated_at)}")
    typer.echo(f"  admitted     {len(bundle.admitted)} event(s), {len(bundle.rejected)} rejected")

    if state.active_recovery_policy is not None:
        policy = state.active_recovery_policy
        typer.echo("")
        typer.echo(
            f"  recovery policy {policy.event_id} "
            f"(seq {policy.policy_seq}, {policy.threshold} of {len(policy.members)})"
        )
        for member in policy.members:
            typer.echo(f"    member  {member}")

    if state.history:
        typer.echo("")
        typer.echo("  history")
        for step in state.history:
            typer.echo(
                f"    epoch {step.from_epoch} -> {step.to_epoch}  {step.mode}  {step.to_root}"
            )
            for event_id in step.via_event_ids:
                typer.echo(f"      via {event_id}")

    if state.conflicting_event_ids:
        typer.echo("")
        typer.secho("  conflicting events", fg=typer.colors.RED)
        for event_id in state.conflicting_event_ids:
            typer.secho(f"    {event_id}", fg=typer.colors.RED)

    if state.denied:
        typer.echo("")
        typer.echo("  not counted")
        for item in state.denied:
            typer.echo(f"    {item.reason}  {item.event_id}")
            typer.echo(f"      {item.detail}")

    if bundle.rejected:
        typer.echo("")
        typer.secho("  rejected before resolution (integrity)", fg=typer.colors.RED)
        for rejection in bundle.rejected:
            typer.secho(f"    {rejection.reason}  {rejection.event_id}", fg=typer.colors.RED)
            typer.echo(f"      {rejection.detail}")

    for warning in state.warnings:
        typer.echo("")
        typer.secho(f"  warning: {warning}", fg=typer.colors.YELLOW)

    typer.echo("")
    typer.secho(f"  note: {state.note}", fg=typer.colors.YELLOW)


@lineage_app.command("show")
def lineage_show(
    bundle_path: Annotated[
        str,
        typer.Argument(
            metavar="BUNDLE",
            help="Path to a bundle of signed envelopes (JSON array, {events: [...]}, "
            "or JSON Lines), or '-' to read stdin.",
        ),
    ],
    lineage: Annotated[
        str | None,
        typer.Option(
            "--lineage",
            help="Which lineage to resolve. Required if the bundle carries more than one.",
        ),
    ] = None,
    at: Annotated[
        str | None,
        typer.Option(
            "--at",
            help="RFC3339 UTC evaluation time. Recorded in the result; "
            "it does not select or filter events (D-033).",
        ),
    ] = None,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit the machine-readable result instead of prose."),
    ] = False,
) -> None:
    """Resolve which key currently holds root authority for a lineage.

    Exit code 0 means resolved, 1 means the chain could not be resolved (a
    conflict, or a missing genesis), and 2 means the bundle could not be read.
    A resolved root is not an authorization decision for any specific action.
    """
    try:
        envelopes = _parse_envelopes(_read_source(bundle_path))
        moment = parse_instant(at, field="--at") if at is not None else datetime.now(tz=UTC)
    except LineageAuthError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    event_bundle = EventBundle.from_envelopes(envelopes)
    target = lineage
    if target is None:
        found = event_bundle.lineages()
        if len(found) != 1:
            # Anyone who can append one unrelated event to a bundle can make the
            # guess ambiguous, so name the candidates: the operator should be one
            # copy-paste away from proceeding, not left to go digging.
            typer.secho(
                f"error: the bundle carries {len(found)} lineages; name one with --lineage",
                fg=typer.colors.RED,
                err=True,
            )
            for candidate in found:
                typer.secho(f"  --lineage {candidate}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        target = found[0]

    state = resolve_lineage(event_bundle, lineage=target, at=moment)

    if as_json:
        typer.echo(jsonio.dumps(_state_as_dict(state, event_bundle)))
    else:
        _print_lineage(state, event_bundle)

    raise typer.Exit(code=0 if state.resolved else 1)


@app.command()
def version() -> None:
    """Print the implementation and protocol versions."""
    typer.echo(f"lineageauth {__version__}")
    typer.echo(f"protocol    {catalog.PROTOCOL} {catalog.CORE_VERSION}")
    typer.echo(f"supported   {', '.join(sorted(catalog.SUPPORTED_VERSIONS))}")


if __name__ == "__main__":  # pragma: no cover
    app()
