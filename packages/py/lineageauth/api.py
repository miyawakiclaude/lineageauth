"""A read-and-verify HTTP API over an event index.

`docs/16_API_SDK_CLI.md` lists these endpoints. What matters more than the list
is what the service is allowed to be: a way to *find* signed objects, never a
way to make one authoritative. Every response that asserts anything carries the
event ids behind it, so a client can fetch them and reach its own verdict
without taking this service's word for it (D-001).

Three constraints shape the whole module.

*No keys.* There is no signing endpoint and no key material anywhere in the
process. `docs/25` requires that a public indexer never hold a private key, and
the way to guarantee that is to have nowhere to put one.

*No writes to the protocol.* The API ingests nothing. Events arrive through the
store, and the index is rebuilt from it. An HTTP request cannot add an event,
so a request cannot manufacture authority.

*Deterministic answers.* Given the same events and the same `at`, every endpoint
returns the same result. `at` is a parameter rather than the wall clock wherever
a caller might need to reproduce an answer.

Optional dependency: this imports FastAPI, which the core deliberately does not.
`pip install lineageauth[api]`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from lineageauth import __version__, catalog
from lineageauth.authority import check_permission
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError
from lineageauth.index import EventIndex
from lineageauth.lineage import resolve_lineage
from lineageauth.timeutil import format_instant, parse_instant
from lineageauth.verify import verify_event

API_VERSION = "v1"

# A JSON API that renders no HTML still gets the headers, because a browser that
# is talked into treating a response as a document is the case they exist for.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}

STANDING_NOTE = (
    "This service helps you find signed events. It cannot make one authoritative. "
    "Verify the referenced events yourself."
)


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any]
    proofs: list[dict[str, Any]] = Field(default_factory=list)


class PermissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lineage: str
    agent: str
    namespace: str
    resource: str
    action: str
    at: str | None = None
    external: bool = True


def _moment(value: str | None) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    try:
        return parse_instant(value, field="at")
    except LineageAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def create_app(index: EventIndex, *, title: str = "LineageAuth") -> FastAPI:
    """Build the API over an existing index.

    The index is passed in rather than opened here so a caller decides what this
    process can see. A service handed a read-only projection cannot widen its own
    view by handling a request.
    """
    app = FastAPI(
        title=title,
        version=__version__,
        description=(
            "Read-and-verify access to LineageAuth events. Holds no keys, signs "
            "nothing, and accepts no events over HTTP."
        ),
    )

    @app.middleware("http")
    async def _headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "protocol": catalog.PROTOCOL, "version": catalog.CORE_VERSION}

    @app.get(f"/{API_VERSION}/meta")
    def meta() -> dict[str, Any]:
        """What this service is, and what it refuses to be."""
        return {
            "protocol": catalog.PROTOCOL,
            "coreVersion": catalog.CORE_VERSION,
            "supportedVersions": sorted(catalog.SUPPORTED_VERSIONS),
            "implementation": __version__,
            "indexedEvents": len(index),
            "holdsPrivateKeys": False,
            "acceptsEventsOverHttp": False,
            "note": STANDING_NOTE,
        }

    @app.post(f"/{API_VERSION}/verify/event")
    def verify_event_endpoint(body: VerifyRequest) -> dict[str, Any]:
        """Verify one envelope's integrity. Nothing is stored.

        A caller can check an event without publishing it, which matters for a
        draft they are not ready to share.
        """
        try:
            envelope = Envelope.model_validate(body.model_dump())
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"not an LAP envelope: {exc}") from exc
        result = verify_event(envelope)
        return {
            "integrityOk": result.integrity_ok,
            "reason": str(result.reason),
            "detail": result.detail,
            "eventId": result.event_id,
            "eventType": result.event_type,
            "lineage": result.lineage,
            "verifiedSigners": list(result.verified_signers),
            "warnings": list(result.warnings),
            "note": result.note,
        }

    @app.post(f"/{API_VERSION}/check-permission")
    def check_permission_endpoint(body: PermissionRequest) -> dict[str, Any]:
        """Decide one exact action against the indexed events."""
        at = _moment(body.at)
        try:
            decision = check_permission(
                index.bundle(lineage=body.lineage),
                lineage=body.lineage,
                agent=body.agent,
                namespace=body.namespace,
                resource=body.resource,
                action=body.action,
                at=at,
                external=body.external,
            )
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "allowed": decision.allowed,
            "reason": str(decision.reason),
            "detail": decision.detail,
            "lineage": decision.lineage,
            "root": decision.root,
            "epoch": decision.epoch,
            "approval": decision.approval.wire_name,
            "evaluatedAt": format_instant(decision.evaluated_at),
            # The grant ids that justified it. A client that wants to be sure
            # fetches these and re-walks the chain itself.
            "path": list(decision.path),
            "refusals": [
                {"eventId": r.event_id, "reason": str(r.reason), "detail": r.detail}
                for r in decision.refusals
            ],
            "warnings": list(decision.warnings),
            "note": decision.note,
        }

    @app.get(f"/{API_VERSION}/events/{{event_id}}")
    def get_event(event_id: str) -> dict[str, Any]:
        """Return one event exactly as stored, for the caller to verify."""
        envelope = index.get(event_id)
        if envelope is None:
            raise HTTPException(status_code=404, detail=f"no indexed event {event_id}")
        return {
            "eventId": envelope.event_id,
            "payload": envelope.payload,
            "proofs": [proof.model_dump() for proof in envelope.proofs],
            "note": STANDING_NOTE,
        }

    @app.get(f"/{API_VERSION}/lineages")
    def list_lineages() -> dict[str, Any]:
        return {"lineages": list(index.lineages())}

    @app.get(f"/{API_VERSION}/lineages/{{lineage}}")
    def get_lineage(lineage: str, at: str | None = None) -> dict[str, Any]:
        """Resolve a lineage's current root and epoch."""
        moment = _moment(at)
        try:
            state = resolve_lineage(index.bundle(lineage=lineage), lineage=lineage, at=moment)
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "lineage": state.lineage,
            "resolved": state.resolved,
            "reason": str(state.reason),
            "detail": state.detail,
            "evaluatedAt": format_instant(state.evaluated_at),
            "genesisRoot": state.genesis_root,
            # Only a resolved lineage reports a current root. Otherwise these
            # would read as an answer when the honest reply is that there is not
            # one yet.
            "root": state.root if state.resolved else None,
            "epoch": state.epoch if state.resolved else None,
            "supersededRoots": list(state.superseded_roots),
            "conflictingEventIds": list(state.conflicting_event_ids),
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
            "warnings": list(state.warnings),
            "note": state.note,
        }

    @app.get(f"/{API_VERSION}/dids/{{did}}")
    def get_did(did: str) -> dict[str, Any]:
        """What this DID has signed.

        Signing is not authority, and this endpoint says so in its own response:
        a key that signed a hundred events may hold no authority at all.
        """
        return {
            "did": did,
            "signedEventIds": list(index.signed_by(did)),
            "note": (
                "These are events this key produced a verifying signature on. That is "
                "key control, not authority, identity, or standing. Ask "
                f"/{API_VERSION}/check-permission for an authority decision."
            ),
        }

    return app


def create_app_from_paths(*, index_path: str, store_path: str | None = None) -> FastAPI:
    """Open an index (optionally rebuilding it from a store) and build the app."""
    index = EventIndex(index_path)
    if store_path is not None:
        from lineageauth.store import FileEventStore

        # The rebuild verifies every event on ingest, so nothing unverifiable
        # reaches the index regardless of how it got into the store.
        index.rebuild(FileEventStore(store_path))
    return create_app(index)
