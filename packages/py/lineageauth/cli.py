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
from pathlib import Path
from typing import Annotated

import typer

from lineageauth import __version__, catalog, jsonio
from lineageauth.errors import ReasonCode
from lineageauth.verify import EventVerification, verify_event_json

app = typer.Typer(
    name="la",
    help="LineageAuth (LAP) — verify agent authority and evidence offline.",
    no_args_is_help=True,
    add_completion=False,
)

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


@app.command()
def version() -> None:
    """Print the implementation and protocol versions."""
    typer.echo(f"lineageauth {__version__}")
    typer.echo(f"protocol    {catalog.PROTOCOL} {catalog.CORE_VERSION}")
    typer.echo(f"supported   {', '.join(sorted(catalog.SUPPORTED_VERSIONS))}")


if __name__ == "__main__":  # pragma: no cover
    app()
