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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer

from lineageauth import __version__, catalog, jsonio
from lineageauth.actions import ActionRequest
from lineageauth.authority import AuthorityDecision, check_permission
from lineageauth.builders import build_approval_receipt, sign_payload
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError, ReasonCode
from lineageauth.lineage import LineageState, resolve_lineage
from lineageauth.timeutil import format_instant, parse_instant
from lineageauth.verify import EventVerification, verify_event_json

app = typer.Typer(
    name="la",
    help="LineageAuth (LAP) -- verify agent authority and evidence offline.",
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


# PowerShell writes UTF-16 with a BOM when output is redirected with `>`, which
# is how a Windows operator naturally saves a signed event. Read as UTF-8 that
# raises UnicodeDecodeError, and Typer prints a traceback -- on, of all days, the
# one where somebody is following docs/RECOVERY.md with a lost root key. The
# bytes are recognised here so the message can name the cause and the fix.
_BYTE_ORDER_MARKS = (
    (bytes([0xFF, 0xFE, 0x00, 0x00]), "UTF-32 (little endian)"),
    (bytes([0x00, 0x00, 0xFE, 0xFF]), "UTF-32 (big endian)"),
    (bytes([0xFF, 0xFE]), "UTF-16 (little endian) -- PowerShell writes this for `>`"),
    (bytes([0xFE, 0xFF]), "UTF-16 (big endian)"),
)


def _read_source(path: str) -> str:
    if path == STDIN_SENTINEL:
        return sys.stdin.read()
    source = Path(path)
    if not source.is_file():
        typer.secho(f"error: no such file: {path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    try:
        # utf-8-sig so a UTF-8 BOM, which several Windows editors add without
        # saying so, is consumed rather than left in front of the opening brace.
        return source.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        head = source.read_bytes()[:4]
        described = next((name for mark, name in _BYTE_ORDER_MARKS if head.startswith(mark)), None)
        typer.secho(f"error: {path} is not UTF-8 text.", fg=typer.colors.RED, err=True)
        if described:
            typer.secho(f"  it looks like {described}", fg=typer.colors.RED, err=True)
            typer.secho(
                "  re-save it as UTF-8. In PowerShell, write the file with "
                "`| Set-Content -Encoding utf8 FILE` rather than `> FILE`.",
                fg=typer.colors.YELLOW,
                err=True,
            )
        else:
            typer.secho(f"  {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


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


def _decision_as_dict(decision: AuthorityDecision, bundle: EventBundle) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "reason": str(decision.reason),
        "detail": decision.detail,
        "request": {
            "agent": decision.request.agent,
            "namespace": decision.request.namespace,
            "resource": decision.request.resource,
            "action": decision.request.action,
        },
        "lineage": decision.lineage,
        "evaluatedAt": format_instant(decision.evaluated_at),
        "root": decision.root,
        "epoch": decision.epoch,
        "path": list(decision.path),
        "approval": decision.approval.wire_name,
        "refusals": [
            {"eventId": item.event_id, "reason": str(item.reason), "detail": item.detail}
            for item in decision.refusals
        ],
        "rejected": [
            {
                "eventId": item.event_id,
                "eventType": item.event_type,
                "reason": str(item.reason),
                "detail": item.detail,
            }
            for item in bundle.rejected
        ],
        "warnings": list(decision.warnings),
        "note": decision.note,
    }


def _print_decision(decision: AuthorityDecision, bundle: EventBundle) -> None:
    colour = typer.colors.GREEN if decision.allowed else typer.colors.RED
    typer.secho(f"{decision.reason}", fg=colour, bold=True)
    typer.echo(f"  {decision.detail}")
    typer.echo("")
    typer.echo(f"  request      {decision.request.render()}")
    typer.echo(f"  lineage      {decision.lineage}")
    typer.echo(f"  root         {decision.root}")
    typer.echo(f"  epoch        {decision.epoch}")
    typer.echo(f"  approval     {decision.approval.wire_name}")
    typer.echo(f"  evaluatedAt  {format_instant(decision.evaluated_at)}")

    if decision.path:
        typer.echo("")
        typer.echo("  authority path (root -> agent)")
        for depth, event_id in enumerate(decision.path):
            typer.echo(f"    {'  ' * depth}{event_id}")

    if decision.refusals:
        typer.echo("")
        typer.echo("  grants considered and not used")
        for item in decision.refusals:
            typer.echo(f"    {item.reason}  {item.event_id}")
            typer.echo(f"      {item.detail}")

    if bundle.rejected:
        typer.echo("")
        typer.secho("  rejected before resolution (integrity)", fg=typer.colors.RED)
        for rejection in bundle.rejected:
            typer.secho(f"    {rejection.reason}  {rejection.event_id}", fg=typer.colors.RED)

    for warning in decision.warnings:
        typer.echo("")
        typer.secho(f"  warning: {warning}", fg=typer.colors.YELLOW)

    typer.echo("")
    typer.secho(f"  note: {decision.note}", fg=typer.colors.YELLOW)


@app.command("check")
def check(
    bundle_path: Annotated[
        str,
        typer.Argument(
            metavar="BUNDLE",
            help="Path to a bundle of signed envelopes, or '-' to read stdin.",
        ),
    ],
    agent: Annotated[str, typer.Option("--agent", help="The acting agent's did:key.")],
    namespace: Annotated[
        str, typer.Option("--namespace", help="Scope namespace, e.g. 'technocore'.")
    ],
    resource: Annotated[str, typer.Option("--resource", help="Resource, e.g. 'room:lobby'.")],
    action: Annotated[str, typer.Option("--action", help="Action, e.g. 'write'.")],
    lineage: Annotated[
        str | None,
        typer.Option("--lineage", help="Which lineage to resolve against."),
    ] = None,
    at: Annotated[
        str | None,
        typer.Option("--at", help="RFC3339 UTC evaluation time. Defaults to now."),
    ] = None,
    internal: Annotated[
        bool,
        typer.Option(
            "--internal",
            help="Assert the action has no effect outside the agent. Without it the "
            "action is assumed external, which is the assumption that fails safe.",
        ),
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit the machine-readable decision.")
    ] = False,
) -> None:
    """Decide whether an agent holds authority for one exact action.

    Exit code 0 means allowed, 1 means it is not (denied, revoked, expired,
    superseded, or awaiting human approval), and 2 means the bundle could not
    be read.

    A `0` here is provenance, not permission from the provider: OAuth, API
    keys, repository permissions, and MCP or A2A server policy all still apply.
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
            typer.secho(
                f"error: the bundle carries {len(found)} lineages; name one with --lineage",
                fg=typer.colors.RED,
                err=True,
            )
            for candidate in found:
                typer.secho(f"  --lineage {candidate}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        target = found[0]

    try:
        decision = check_permission(
            event_bundle,
            lineage=target,
            agent=agent,
            namespace=namespace,
            resource=resource,
            action=action,
            at=moment,
            external=not internal,
        )
    except LineageAuthError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    if as_json:
        typer.echo(jsonio.dumps(_decision_as_dict(decision, event_bundle)))
    else:
        _print_decision(decision, event_bundle)

    raise typer.Exit(code=0 if decision.allowed else 1)


index_app = typer.Typer(
    name="index",
    help="Build and inspect the derived index over an event store.",
    no_args_is_help=True,
)
app.add_typer(index_app)


@index_app.command("rebuild")
def index_rebuild(
    store_path: Annotated[
        str, typer.Argument(metavar="STORE", help="Directory holding the event store.")
    ],
    db: Annotated[
        str, typer.Option("--db", help="Path for the SQLite index. It is safe to delete.")
    ],
) -> None:
    """Discard every projection and rebuild it from the store.

    Always safe: the index is derived. If a rebuild ever changed an answer, the
    index was holding state that never came from a signed event.
    """
    from lineageauth.index import EventIndex
    from lineageauth.store import FileEventStore

    store = FileEventStore(store_path)
    with EventIndex(db) as index:
        indexed, rejected = index.rebuild(store)
        typer.echo(f"  store      {store_path} ({len(store)} event(s))")
        typer.echo(f"  index      {db}")
        typer.echo(f"  indexed    {indexed}")
        if rejected:
            typer.secho(f"  rejected   {rejected} (did not verify)", fg=typer.colors.RED)
        typer.echo(f"  checksum   {index.checksum()}")
    raise typer.Exit(code=1 if rejected else 0)


@index_app.command("stat")
def index_stat(
    db: Annotated[str, typer.Option("--db", help="Path to the SQLite index.")],
) -> None:
    """Summarise what an index holds."""
    from lineageauth.index import EventIndex

    with EventIndex(db) as index:
        typer.echo(f"  events     {len(index)}")
        typer.echo(f"  checksum   {index.checksum()}")
        lineages = index.lineages()
        typer.echo(f"  lineages   {len(lineages)}")
        for lineage in lineages:
            typer.echo(f"    {lineage}")
        counts = index.counts_by_type()
        if counts:
            typer.echo("  by type")
            for event_type, count in counts.items():
                typer.echo(f"    {event_type:24} {count}")


@index_app.command("add")
def index_add(
    store_path: Annotated[
        str, typer.Argument(metavar="STORE", help="Directory holding the event store.")
    ],
    events: Annotated[
        list[str],
        typer.Argument(help="Envelope or bundle files to add. Each is verified first."),
    ],
) -> None:
    """Add events to the store. Anything that does not verify is refused.

    The store is the authoritative side, so this is the only way events enter
    the system -- there is no HTTP path that can add one.
    """
    from lineageauth.store import FileEventStore, StoreError

    store = FileEventStore(store_path)
    added = 0
    failed = 0
    for path in events:
        try:
            for envelope in _parse_envelopes(_read_source(path)):
                try:
                    typer.echo(f"  + {store.put(envelope)}  ({path})")
                    added += 1
                except StoreError as exc:
                    typer.secho(f"  ! {path}: {exc}", fg=typer.colors.RED, err=True)
                    failed += 1
        except LineageAuthError as exc:
            typer.secho(f"  ! {path}: {exc}", fg=typer.colors.RED, err=True)
            failed += 1
    typer.echo(f"  added {added}, refused {failed}, store now holds {len(store)}")
    raise typer.Exit(code=1 if failed else 0)


@app.command("graph")
def graph(
    bundle_path: Annotated[
        str,
        typer.Argument(metavar="BUNDLE", help="Bundle of signed envelopes, or '-' for stdin."),
    ],
    lineage: Annotated[str | None, typer.Option("--lineage")] = None,
    at: Annotated[str | None, typer.Option("--at", help="RFC3339 UTC evaluation time.")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show a lineage as nodes and edges.

    Every status shown is read off the resolver rather than worked out here. A
    picture that disagrees with the verifier is worse than no picture.
    """
    from lineageauth.graph import build_graph

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
            typer.secho(
                f"error: the bundle carries {len(found)} lineages; name one with --lineage",
                fg=typer.colors.RED,
                err=True,
            )
            for candidate in found:
                typer.secho(f"  --lineage {candidate}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        target = found[0]

    projection = build_graph(event_bundle, lineage=target, at=moment)
    if as_json:
        typer.echo(jsonio.dumps(projection.to_dict()))
        raise typer.Exit(code=0 if projection.resolved else 1)

    colour = typer.colors.GREEN if projection.resolved else typer.colors.RED
    typer.secho(f"{projection.reason}", fg=colour, bold=True)
    typer.echo(f"  {projection.detail}")
    typer.echo("")
    typer.echo("  nodes")
    for node in projection.nodes:
        typer.echo(f"    {node.did}")
        typer.echo(f"      {', '.join(str(kind) for kind in node.kinds)}")
    typer.echo("")
    typer.echo("  edges")
    for edge in projection.edges:
        mark = "live" if edge.live else str(edge.reason)
        typer.secho(
            f"    [{mark}] {edge.kind}",
            fg=typer.colors.GREEN if edge.live else typer.colors.YELLOW,
        )
        typer.echo(f"      {edge.source}")
        typer.echo(f"        -> {edge.target}")
        if edge.label:
            typer.echo(f"      {edge.label}")
        typer.echo(f"      via {edge.event_id}")
    typer.echo("")
    typer.secho(f"  note: {projection.note}", fg=typer.colors.YELLOW)
    raise typer.Exit(code=0 if projection.resolved else 1)


@app.command("passport")
def passport(
    bundle_path: Annotated[
        str,
        typer.Argument(metavar="BUNDLE", help="Bundle of signed envelopes, or '-' for stdin."),
    ],
    did: Annotated[str, typer.Option("--did", help="The agent's did:key.")],
    lineage: Annotated[str | None, typer.Option("--lineage")] = None,
    at: Annotated[str | None, typer.Option("--at", help="RFC3339 UTC evaluation time.")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show what a bundle says about one agent, in separate categories.

    A passport is a projection of signed events -- not an identity, and not a
    score. The four sections are printed apart because a self-claimed skill and
    an independently attested one are different things.
    """
    from lineageauth.passport import build_passport

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
            typer.secho(
                f"error: the bundle carries {len(found)} lineages; name one with --lineage",
                fg=typer.colors.RED,
                err=True,
            )
            for candidate in found:
                typer.secho(f"  --lineage {candidate}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        target = found[0]

    try:
        projection = build_passport(event_bundle, lineage=target, did=did, at=moment)
    except LineageAuthError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    if as_json:
        typer.echo(jsonio.dumps(projection.to_dict()))
        raise typer.Exit(code=0)

    typer.secho(f"passport  {projection.did}", bold=True)
    typer.echo(f"  lineage      {projection.lineage}")
    typer.echo(f"  evaluatedAt  {format_instant(projection.evaluated_at)}")

    typer.echo("")
    typer.secho("  cryptographically linked", fg=typer.colors.CYAN)
    typer.echo(f"    lineage resolved  {projection.lineage_resolved} ({projection.lineage_reason})")
    typer.echo(f"    current root      {projection.current_root}")
    typer.echo(f"    epoch             {projection.epoch}")
    typer.echo(f"    holds authority   {projection.holds_live_authority}")
    for scope in projection.authority_scopes:
        typer.echo(f"      {scope}")

    typer.echo("")
    typer.secho("  self-claimed (this key's own word, nothing more)", fg=typer.colors.YELLOW)
    for claim in projection.self_claims:
        if claim.nickname:
            typer.echo(f"    nickname     {claim.nickname}")
        if claim.description:
            typer.echo(f"    description  {claim.description}")
    for claimed in projection.skill_claims:
        mark = "self" if claimed.self_claimed else "third party"
        typer.echo(f"    skill        {claimed.skill}  (claimed by {mark})")
    if not projection.self_claims and not projection.skill_claims:
        typer.echo("    (none)")

    typer.echo("")
    typer.secho("  evidence-supported", fg=typer.colors.GREEN)
    for made in projection.produced:
        mark = "authority ok" if made.authority_supported else str(made.authority_reason)
        typer.echo(f"    artifact  {made.artifact_id}  [{mark}]")
    for done in projection.tasks:
        marks = []
        if done.requester_is_worker:
            marks.append("self-created task")
        marks.append(f"{len(done.independent_verifiers)} independent verifier(s)")
        typer.echo(f"    task      {done.title}  [{done.status}]")
        typer.echo(f"      {', '.join(marks)}")
    for supported in projection.skills:
        typer.echo(
            f"    skill     {supported.skill}: "
            f"{len(supported.produced_artifacts)} produced, "
            f"{len(supported.independent_attesters)} independent attester(s) "
            f"-> supported={supported.is_evidence_supported}"
        )
    if not projection.produced and not projection.skills and not projection.tasks:
        typer.echo("    (none)")

    typer.echo("")
    typer.secho("  third-party attested (who said it, not that it is true)", fg=typer.colors.CYAN)
    for said in projection.attestations:
        known = "" if said.predicate_is_known else "  [unregistered predicate]"
        typer.echo(f"    {said.predicate}{known}")
        typer.echo(f"      by {said.issuer}")
    typer.echo(f"    independent counterparties: {len(projection.independent_counterparties)}")

    typer.echo("")
    typer.secho("  not included", fg=typer.colors.BRIGHT_BLACK)
    from lineageauth.passport import NOT_IMPLEMENTED

    for name, reason in NOT_IMPLEMENTED:
        typer.echo(f"    {name:16} {reason}")

    for warning in projection.warnings:
        typer.echo("")
        typer.secho(f"  warning: {warning}", fg=typer.colors.YELLOW)

    typer.echo("")
    typer.secho(f"  note: {projection.note}", fg=typer.colors.YELLOW)


approval_app = typer.Typer(
    name="approval",
    help="Draft and inspect human approvals for one exact action.",
    no_args_is_help=True,
)
app.add_typer(approval_app)


def _action_from_options(
    namespace: str, resource: str, action: str, destination: str, content_hash: str
) -> ActionRequest:
    return ActionRequest(
        namespace=namespace,
        resource=resource,
        action=action,
        destination=destination,
        content_hash=content_hash,
    )


def _print_preview(request: ActionRequest, *, agent: str, approver: str, expires: str) -> None:
    """What `docs/17` requires a human to see before consenting.

    Every field on that list, in one place, in the order that matters: who is
    acting, where the effect lands, what exactly is being done, the bytes it is
    fixed to, and when the permission dies. An approval UI that shows less than
    this is asking for consent to something the human cannot see.
    """
    typer.secho("  APPROVING ONE EXACT ACTION", bold=True)
    typer.echo(f"    agent          {agent}")
    typer.echo(f"    approver       {approver}")
    typer.echo(f"    namespace      {request.namespace}")
    typer.echo(f"    resource       {request.resource}")
    typer.echo(f"    action         {request.action}")
    typer.echo(f"    destination    {request.destination}")
    typer.echo(f"    content hash   {request.content_hash}")
    typer.echo(f"    request hash   {request.request_hash}")
    typer.echo(f"    expires        {expires}")


@approval_app.command("draft")
def approval_draft(
    lineage: Annotated[str, typer.Option("--lineage", help="Lineage identifier.")],
    approver: Annotated[str, typer.Option("--approver", help="The approving did:key.")],
    agent: Annotated[str, typer.Option("--agent", help="The acting agent's did:key.")],
    namespace: Annotated[str, typer.Option("--namespace", help="Scope namespace.")],
    resource: Annotated[str, typer.Option("--resource", help="Resource, e.g. 'room:lobby'.")],
    action: Annotated[str, typer.Option("--action", help="Action, e.g. 'write'.")],
    destination: Annotated[
        str, typer.Option("--destination", help="The concrete place the effect lands.")
    ],
    content_hash: Annotated[
        str, typer.Option("--content-hash", help="sha256:<64 hex> over the exact bytes.")
    ],
    expires_in: Annotated[
        int, typer.Option("--expires-in", help="Seconds until the approval expires.")
    ] = 300,
    at: Annotated[str | None, typer.Option("--at", help="Issue time (RFC3339 UTC).")] = None,
) -> None:
    """Draft an unsigned approval receipt, and show what it commits to.

    The draft is unsigned and this command holds no keys, so nothing here can
    approve anything. It prints the preview a human must read first, then the
    payload to sign wherever the approver's key actually lives.

    The nonce is generated with `secrets.token_bytes`. That is the one piece of
    randomness this tool does produce, because a nonce a caller could choose is
    a nonce an attacker could replay.
    """
    import secrets

    issued = parse_instant(at, field="at") if at else datetime.now(tz=UTC)
    if expires_in <= 0:
        typer.secho("  --expires-in must be positive", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    expires = issued + timedelta(seconds=expires_in)

    try:
        request = _action_from_options(namespace, resource, action, destination, content_hash)
        payload = build_approval_receipt(
            lineage=lineage,
            approver=approver,
            agent=agent,
            request=request,
            nonce=secrets.token_bytes(32),
            expires_at=expires,
            issued_at=issued,
        )
    except LineageAuthError as exc:
        typer.secho(f"  refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    _print_preview(request, agent=agent, approver=approver, expires=format_instant(expires))
    typer.echo("")
    typer.echo(jsonio.dumps(payload, indent=2))
    typer.echo("")
    typer.secho(
        "  This draft is UNSIGNED and grants nothing. Sign it where the approver's key lives.",
        fg=typer.colors.YELLOW,
    )


@app.command("execute")
def execute(
    bundle: Annotated[str, typer.Argument(metavar="BUNDLE", help="Bundle of signed events.")],
    lineage: Annotated[str, typer.Option("--lineage", help="Lineage identifier.")],
    agent: Annotated[str, typer.Option("--agent", help="The acting agent's did:key.")],
    namespace: Annotated[str, typer.Option("--namespace", help="Scope namespace.")],
    resource: Annotated[str, typer.Option("--resource", help="Resource, e.g. 'room:lobby'.")],
    action: Annotated[str, typer.Option("--action", help="Action, e.g. 'write'.")],
    destination: Annotated[
        str, typer.Option("--destination", help="The concrete place the effect lands.")
    ],
    content_hash: Annotated[
        str, typer.Option("--content-hash", help="sha256:<64 hex> over the exact bytes.")
    ],
    spent_db: Annotated[
        str | None,
        typer.Option("--spent-db", help="SQLite file recording which receipts are spent."),
    ] = None,
    reserve: Annotated[
        bool,
        typer.Option(
            "--reserve/--dry-run",
            help="Consume the receipt, or preview the decision without consuming it.",
        ),
    ] = False,
    internal: Annotated[
        bool,
        typer.Option("--internal", help="State that this action has no effect outside the agent."),
    ] = False,
    at: Annotated[str | None, typer.Option("--at", help="Evaluation time (RFC3339 UTC).")] = None,
) -> None:
    """Decide whether this exact action may be performed, right now.

    This never performs anything. It is the check an executor runs immediately
    before acting, and it answers only for the action described on the command
    line -- change the destination or a byte of the content and the answer is
    about a different action.

    `--dry-run` is the default. Consuming a receipt is a commit point: once it
    is reserved the approver would have to approve again, so a preview must not
    be able to burn one by accident.
    """
    from lineageauth.approval import InMemorySpentStore, SqliteSpentStore, check_execution

    moment = parse_instant(at, field="at") if at else datetime.now(tz=UTC)
    try:
        request = _action_from_options(namespace, resource, action, destination, content_hash)
        events = _parse_envelopes(_read_source(bundle))
    except LineageAuthError as exc:
        typer.secho(f"  refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    store = SqliteSpentStore(spent_db) if spent_db else InMemorySpentStore()
    if reserve and spent_db is None:
        typer.secho(
            "  --reserve without --spent-db records the reservation in memory, so it "
            "is forgotten when this process exits. That is not replay protection.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    try:
        decision = check_execution(
            EventBundle.from_envelopes(events),
            lineage=lineage,
            agent=agent,
            request=request,
            at=moment,
            store=store,
            external=not internal,
            reserve=reserve,
        )
    finally:
        close = getattr(store, "close", None)
        if callable(close):
            close()

    colour = typer.colors.GREEN if decision.may_execute else typer.colors.RED
    typer.secho(f"  {'MAY EXECUTE' if decision.may_execute else 'REFUSED'}", fg=colour, bold=True)
    typer.echo(f"    reason         {decision.reason}")
    typer.echo(f"    detail         {decision.detail}")
    typer.echo(f"    destination    {request.destination}")
    typer.echo(f"    content hash   {request.content_hash}")
    if decision.receipt_id:
        typer.echo(f"    receipt        {decision.receipt_id}")
        typer.echo(f"    approver       {decision.approver}")
    typer.echo(f"    receipt spent  {decision.reserved}")
    if not reserve:
        typer.echo("    (dry run: nothing was consumed)")
    for warning in decision.warnings:
        typer.secho(f"    warning        {warning}", fg=typer.colors.YELLOW)
    typer.echo("")
    typer.echo(f"  note: {decision.note}")
    raise typer.Exit(code=0 if decision.may_execute else 1)


@app.command("doctor")
def doctor(
    store_path: Annotated[
        str, typer.Argument(metavar="STORE", help="Directory holding the event store.")
    ],
    db: Annotated[str, typer.Option("--db", help="Path to the SQLite index.")],
    at: Annotated[str | None, typer.Option("--at", help="Evaluation time (RFC3339 UTC).")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit machine-readable output.")] = False,
) -> None:
    """Report the health of a store and its index, offline.

    This is the whole observability story and it is deliberately small
    (`docs/25`, `docs/31`): a local command, no agent, no endpoint, no service
    that could cost anything or become a place where events go.

    The question it answers is the one that actually matters for a derived
    index: **does the index still agree with the store?** The index is
    rebuildable by definition, so a disagreement is never a reason to trust the
    index -- it is a reason to rebuild it and find out what wrote to it.

    A non-zero exit means something disagreed, so this can gate a cron job
    without anything having to parse it.
    """
    from lineageauth.index import EventIndex
    from lineageauth.lineage import resolve_lineage
    from lineageauth.store import FileEventStore

    moment = parse_instant(at, field="at") if at else datetime.now(tz=UTC)
    store = FileEventStore(store_path)
    problems: list[str] = []
    report: dict[str, Any] = {
        "store": store_path,
        "index": db,
        "checkedAt": format_instant(moment),
    }

    with EventIndex(db) as index:
        store_ids = set(store.event_ids())
        index_ids = {envelope.event_id for envelope in index.envelopes()}

        report["storeEvents"] = len(store_ids)
        report["indexEvents"] = len(index_ids)
        report["checksum"] = index.checksum()

        missing = sorted(store_ids - index_ids)
        extra = sorted(index_ids - store_ids)
        report["missingFromIndex"] = missing
        report["notInStore"] = extra

        if missing:
            problems.append(
                f"{len(missing)} event(s) are in the store and not in the index; rebuild it"
            )
        if extra:
            # The dangerous direction. The store is authoritative, so an event
            # the index knows about and the store does not came from somewhere
            # that is not a signed event file.
            problems.append(
                f"{len(extra)} event(s) are in the index and not in the store. The store "
                "is authoritative, so this is not a stale index -- something wrote to "
                "the index that did not come from the store"
            )

        lineages = []
        for lineage in index.lineages():
            state = resolve_lineage(index.bundle(lineage=lineage), lineage=lineage, at=moment)
            lineages.append(
                {
                    "lineage": lineage,
                    "resolved": state.resolved,
                    "reason": str(state.reason),
                    "root": state.root,
                    "epoch": state.epoch,
                    "warnings": len(state.warnings),
                }
            )
            if not state.resolved:
                problems.append(f"{lineage} does not resolve: {state.reason}")
        report["lineages"] = lineages

    report["problems"] = problems

    if as_json:
        typer.echo(jsonio.dumps(report, indent=2))
    else:
        typer.echo(f"  store      {store_path} ({report['storeEvents']} event(s))")
        typer.echo(f"  index      {db} ({report['indexEvents']} event(s))")
        typer.echo(f"  checksum   {report['checksum']}")
        for entry in lineages:
            mark = "ok " if entry["resolved"] else "!! "
            typer.echo(f"  {mark}{entry['lineage']}")
            typer.echo(f"       epoch {entry['epoch']}  {entry['reason']}")
        if problems:
            typer.echo("")
            for problem in problems:
                typer.secho(f"  !! {problem}", fg=typer.colors.RED)
        else:
            typer.secho("\n  the index agrees with the store", fg=typer.colors.GREEN)
        typer.echo("")
        typer.echo(
            "  note: the index is derived and rebuildable. A disagreement is never a "
            "reason to trust it -- rebuild, and find out what wrote to it."
        )

    raise typer.Exit(code=1 if problems else 0)


key_app = typer.Typer(
    name="key",
    help="Create and inspect an encrypted signing key. This tool never holds one.",
    no_args_is_help=True,
)
app.add_typer(key_app)


def _read_secret(prompt: str) -> str:
    """One passphrase, from the terminal when there is one and stdin when not.

    `getpass` opens the console directly on Windows rather than reading stdin,
    so a piped passphrase hangs forever instead of failing. That makes the one
    procedure nobody can afford to get wrong -- recovering a lost root -- also
    the one procedure nobody can rehearse unattended.

    Falling back to stdin when stdin is not a terminal keeps it rehearsable.
    Piping is the operator choosing to; an argument would be visible to everyone
    on the machine whether they chose it or not, which is why that stays out.
    """
    import getpass

    if sys.stdin is not None and sys.stdin.isatty():
        return getpass.getpass(prompt)
    typer.echo(prompt, nl=False, err=True)
    line = sys.stdin.readline()
    if not line:
        typer.secho("  no passphrase on stdin", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    typer.echo("", err=True)
    return line.rstrip(chr(13) + chr(10))


def _ask_passphrase(*, confirm: bool) -> str:
    """Read a passphrase from a prompt, never from an argument.

    A command line is visible in the process table and lands in shell history.
    Nothing about a passphrase survives being put there.
    """
    first = _read_secret("passphrase: ")
    if not confirm:
        return first
    second = _read_secret("passphrase (again): ")
    if first != second:
        typer.secho("  the two passphrases differ", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    return first


@key_app.command("create")
def key_create(
    path: Annotated[str, typer.Argument(metavar="FILE", help="Where to write the encrypted key.")],
) -> None:
    """Generate a signing key and write it encrypted with a passphrase.

    The key is generated here, on this machine, and encrypted before it touches
    the disk. The seed is never printed, never logged and never returned -- the
    only thing this command puts on your screen is the DID, which is public by
    construction.

    Keep the file outside any repository. Losing the passphrase loses the
    identity: `did:key` has no revocation. Publish a `recovery.policy` while
    this key still works, so a quorum can move the lineage later.
    """
    from lineageauth import keyfile

    target = Path(path)
    if target.exists():
        typer.secho(
            f"  {target} already exists; refusing to overwrite", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(code=2)

    passphrase = _ask_passphrase(confirm=True)
    try:
        created = keyfile.create(target, passphrase)
    except LineageAuthError as exc:
        typer.secho(f"  refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.echo("")
    typer.secho("  KEY CREATED", bold=True)
    typer.echo(f"    did      {created.did}")
    typer.echo(f"    file     {created.path}")
    typer.echo("")
    typer.secho(
        "  The DID above is public: publish it freely. The file is not.",
        fg=typer.colors.YELLOW,
    )
    typer.secho(
        "  Back up the file and the passphrase separately, and publish a "
        "recovery.policy\n  before this key matters -- did:key cannot be revoked.",
        fg=typer.colors.YELLOW,
    )


@key_app.command("show")
def key_show(
    path: Annotated[str, typer.Argument(metavar="FILE", help="An encrypted key file.")],
) -> None:
    """Print the DID in a key file. Does not decrypt anything."""
    from lineageauth import keyfile

    try:
        typer.echo(keyfile.read_did(Path(path)))
    except LineageAuthError as exc:
        typer.secho(f"  {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


@app.command("sign")
def sign(
    payload_path: Annotated[
        str, typer.Argument(metavar="PAYLOAD", help="An unsigned event payload, or '-'.")
    ],
    key: Annotated[str, typer.Option("--key", help="Encrypted key file to sign with.")],
) -> None:
    """Sign an unsigned payload and print the envelope.

    The passphrase is prompted for. The seed is decrypted, used, and dropped
    inside one call -- it is never an argument, never printed, and never written
    anywhere by this command.

    Signing does not make a claim true. It makes it attributable, which is a
    smaller thing and the only thing a signature ever does.
    """
    from lineageauth import keyfile

    try:
        payload = jsonio.loads(_read_source(payload_path))
    except LineageAuthError as exc:
        typer.secho(f"  {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    if not isinstance(payload, dict):
        typer.secho("  a payload must be a JSON object", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    if "proofs" in payload:
        typer.secho(
            "  that looks like a whole envelope, not a payload. Sign the payload.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    passphrase = _ask_passphrase(confirm=False)
    try:
        signer = keyfile.unlock(Path(key), passphrase)
        envelope = sign_payload(payload, [signer])
    except LineageAuthError as exc:
        typer.secho(f"  refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(envelope.to_json())


# At the end, and it has to be. Sitting two-fifths of the way down the file, this
# block ran `app()` before the nine commands defined below it had been
# registered -- so `python -m lineageauth.cli` quietly offered a fraction of the
# CLI while `la` offered all of it. Nothing failed; the commands simply were not
# there. (D-096.)
# ---------------------------------------------------------------- tclk/1


tclk_app = typer.Typer(
    name="tclk",
    help=(
        "Read, simulate, authorize and prepare tclk/1 deal frames. Read-only: there "
        "is no send, publish, lock, claim, refund, reveal or pay here."
    ),
    no_args_is_help=True,
)
app.add_typer(tclk_app)


def _read_frame_line(path: str) -> str:
    """One frame line from a file or stdin. Surrounding whitespace only is trimmed."""
    text = _read_source(path).strip()
    if "\n" in text:
        typer.secho("error: expected exactly one frame line", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    return text


def _read_transcript(path: str) -> list[str]:
    """Frame lines from a JSON array of strings or newline-delimited text."""
    text = _read_source(path)
    stripped = text.strip()
    if stripped.startswith("["):
        try:
            loaded = jsonio.loads(stripped)
        except LineageAuthError as exc:
            typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from exc
        if not isinstance(loaded, list) or not all(isinstance(x, str) for x in loaded):
            typer.secho(
                "error: a JSON transcript must be an array of strings",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2)
        return [str(x) for x in loaded]
    return [line for line in text.splitlines() if line.strip()]


@tclk_app.command("inspect")
def tclk_inspect(
    frame: Annotated[
        str, typer.Argument(metavar="FRAME", help="File holding one frame line, or '-'.")
    ],
    as_json: Annotated[bool, typer.Option("--json", help="Emit the parsed frame.")] = False,
) -> None:
    """Decode one tclk/1 frame line. Parsed is not valid-in-context, and neither is authorized."""
    from lineageauth.adapters.tclk import FrameError, decode_frame, room_for_frame

    line = _read_frame_line(frame)
    try:
        parsed = decode_frame(line)
    except FrameError as exc:
        typer.secho(f"  refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    if as_json:
        typer.echo(
            jsonio.dumps(
                {
                    "type": parsed.kind,
                    "from": parsed.sender,
                    "contract": parsed.contract,
                    "room": room_for_frame(parsed),
                    "line": parsed.line,
                    "fields": parsed.as_dict(),
                }
            )
        )
        return
    typer.secho("  tclk/1 frame: PARSED", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"    type       {parsed.kind}")
    typer.echo(f"    from       {parsed.sender}")
    typer.echo(f"    contract   {parsed.contract or '-'}")
    typer.echo(f"    room       {room_for_frame(parsed)}")
    typer.echo(f"    canonical  yes ({len(parsed.line)} chars)")
    typer.echo("  note: parsed is not a valid transition, and not authority to post it")


@tclk_app.command("simulate")
def tclk_simulate(
    transcript: Annotated[
        str, typer.Argument(metavar="TRANSCRIPT", help="Frame lines: a JSON array or one per line.")
    ],
    now: Annotated[int, typer.Option("--now", help="The instant to evaluate at, unix ms.")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit the folded state.")] = False,
) -> None:
    """Fold a transcript into a contract state locally. Nothing is sent or settled."""
    from lineageauth.adapters.tclk import (
        FrameError,
        decode_frame,
        evidence_summary,
        fold,
        tclk_status_to_a2a,
        tclk_status_to_acp_phase,
    )

    lines = _read_transcript(transcript)
    if not lines:
        typer.secho("error: the transcript is empty", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    try:
        first = decode_frame(lines[0])
        if first.kind != "offer":
            raise FrameError("tclk: a transcript starts with an offer")
        rest = [decode_frame(line) for line in lines[1:]]
    except FrameError as exc:
        typer.secho(f"  refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    state, steps = fold(first, rest, now)
    if as_json:
        typer.echo(
            jsonio.dumps(
                {
                    "status": state.status,
                    "a2a": tclk_status_to_a2a(state.status),
                    "acp": tclk_status_to_acp_phase(state.status),
                    "steps": [
                        {"index": i + 1, "type": f.kind, "ok": s.ok, "reason": s.reason}
                        for i, (f, s) in enumerate(zip(rest, steps, strict=True))
                    ],
                    "evidence": evidence_summary(state, [first, *rest]),
                }
            )
        )
        return
    for index, (f, step) in enumerate(zip(rest, steps, strict=True), start=2):
        mark = "applied" if step.ok else "ignored"
        colour = typer.colors.GREEN if step.ok else typer.colors.YELLOW
        typer.secho(f"  {index:>3}  {f.kind:<8} {mark}  {step.reason or ''}", fg=colour)
    typer.echo("")
    typer.secho(f"  status       {state.status}", bold=True)
    typer.echo(f"  contract     {state.contract or '-'}")
    typer.echo(f"  payer        {state.payer_did or '-'}")
    typer.echo(f"  payee        {state.payee_did or '-'}")
    typer.echo(f"  rail         {state.rail or '-'}  ref {state.rail_ref or '-'}")
    typer.echo(f"  revealed     {state.secret_revealed}")
    a2a, acp = tclk_status_to_a2a(state.status), tclk_status_to_acp_phase(state.status)
    typer.echo(f"  a2a / acp    {a2a} / {acp}")
    typer.echo(
        "  note: a folded state proves what the frames say, not that money moved or work was done"
    )


@tclk_app.command("authorize")
def tclk_authorize(
    bundle: Annotated[str, typer.Argument(metavar="BUNDLE", help="Bundle of signed events.")],
    agent: Annotated[str, typer.Option("--agent", help="The DID that would post the frame.")],
    frame: Annotated[str, typer.Option("--frame", help="File holding one frame line, or '-'.")],
    lineage: Annotated[
        str | None, typer.Option("--lineage", help="Which lineage to resolve.")
    ] = None,
    at: Annotated[str | None, typer.Option("--at", help="RFC3339 UTC evaluation time.")] = None,
    room: Annotated[
        str | None, typer.Option("--room", help="Override the room SPEC 2 derives.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the decision.")] = False,
) -> None:
    """Does this agent hold LineageAuth authority to post this frame? Nothing is posted.

    Exit 0: allowed. Exit 1: not allowed (including approval required). Exit 2: input error.
    An allow is authority for the room write, not tclk validity, and not settlement.
    """
    from lineageauth.adapters.tclk import verify_tclk_authority

    line = _read_frame_line(frame)
    try:
        envelopes = _parse_envelopes(_read_source(bundle))
        moment = parse_instant(at, field="--at") if at is not None else datetime.now(tz=UTC)
    except LineageAuthError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    event_bundle = EventBundle.from_envelopes(envelopes)
    target = lineage
    if target is None:
        found = event_bundle.lineages()
        if len(found) != 1:
            typer.secho(
                f"error: the bundle carries {len(found)} lineages; name one with --lineage",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2)
        target = found[0]

    decision = verify_tclk_authority(
        event_bundle, lineage=target, agent=agent, frame_line=line, at=moment, room=room
    )
    if as_json:
        typer.echo(jsonio.dumps(decision.as_dict()))
    else:
        colour = typer.colors.GREEN if decision.allowed else typer.colors.RED
        typer.secho(f"  {'ALLOWED' if decision.allowed else 'NOT ALLOWED'}", fg=colour, bold=True)
        typer.echo(f"    reason      {decision.reason}")
        typer.echo(f"    detail      {decision.detail}")
        if decision.required is not None:
            typer.echo(f"    authority   {decision.required.render()}")
            typer.echo(
                f"    frame       {decision.required.frame_type} from {decision.required.sender}"
            )
        typer.echo(f"    unchecked   {', '.join(decision.unchecked)}")
        typer.echo("")
        typer.echo(f"  note: {decision.note}")
    raise typer.Exit(code=0 if decision.allowed else 1)


@tclk_app.command("prepare")
def tclk_prepare(
    frame: Annotated[
        str, typer.Argument(metavar="FRAME", help="File holding one frame line, or '-'.")
    ],
    nonce: Annotated[
        int | None, typer.Option("--nonce", help="Technocore nonce; adds the signing challenge.")
    ] = None,
    room: Annotated[
        str | None, typer.Option("--room", help="Override the room SPEC 2 derives.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the prepared action.")] = False,
) -> None:
    """The exact bytes, destination and ActionRequest a post would need. Sends nothing.

    No key is read. With --nonce the canonical signing challenge is printed for
    the DID's holder to sign wherever that key lives.
    """
    from lineageauth.adapters.tclk import FrameError, prepare_frame

    line = _read_frame_line(frame)
    try:
        prepared = prepare_frame(line, room=room, nonce=nonce)
    except (FrameError, LineageAuthError) as exc:
        typer.secho(f"  refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    if as_json:
        typer.echo(
            jsonio.dumps(
                {
                    "room": prepared.room,
                    "destination": prepared.destination,
                    "line": prepared.frame.line,
                    "contentHash": prepared.request.content_hash,
                    "requestHash": prepared.request.request_hash,
                    "authority": prepared.required.render(),
                    "signingChallenge": prepared.signing_challenge,
                    "sent": False,
                }
            )
        )
        return
    typer.echo(prepared.preview())


if __name__ == "__main__":  # pragma: no cover
    app()
