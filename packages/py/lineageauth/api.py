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
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi import Query as FastQuery
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from lineageauth import __version__, catalog
from lineageauth.authority import check_permission
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError
from lineageauth.exchange import Moderation, browse
from lineageauth.graph import build_graph
from lineageauth.index import EventIndex
from lineageauth.jury import UnknownCaseError, resolve_dispute
from lineageauth.lineage import resolve_lineage
from lineageauth.passport import build_passport
from lineageauth.router import Query, Requirement, search
from lineageauth.scopes import ApprovalMode
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

EXPLORER_ROOT = Path(__file__).resolve().parents[3] / "apps" / "explorer"

# The Explorer's own policy, stricter than a default page would get and looser
# than the API's `default-src 'none'` in exactly two places: its stylesheet and
# its script, both same-origin files. There is no 'unsafe-inline' -- the page
# carries no inline script or style, which is why it does not need one
# (docs/17: strict CSP). `connect-src 'self'` lets it read this API and nothing
# else; `form-action 'none'` means no form on the page can post anywhere.
EXPLORER_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "connect-src 'self'; "
    "img-src 'none'; "
    "font-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

STANDING_NOTE = (
    "This service helps you find signed events. It cannot make one authoritative. "
    "Verify the referenced events yourself."
)


# Caps on anything a caller controls the size of.
#
# `scripts/benchmark.py` measured admission at roughly 0.5 ms per event, and the
# caller chooses how many to send: a 51-event bundle already exceeds the 10 ms a
# free Cloudflare Worker gets per request, and 201 events takes fourteen times
# it. That is a denial-of-service shape before it is a cost problem, and it does
# not go away on a paid plan -- it starts costing money instead of failing.
#
# These numbers are generous for real use and small enough that no unauthenticated
# request can buy meaningful CPU. The read-only API is public by design (D-092).
MAX_PROOFS = 16  # a recovery quorum is a handful of keys, not hundreds
MAX_SKILLS = 32
MAX_REQUIREMENTS = 8  # multiplied by the number of subjects, so it is the sharp one


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any]
    proofs: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_PROOFS)


class PermissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lineage: str
    agent: str
    namespace: str
    resource: str
    action: str
    at: str | None = None
    external: bool = True


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lineage: str
    skills: list[str] = Field(default_factory=list, max_length=MAX_SKILLS)
    requires: list[dict[str, str]] = Field(default_factory=list, max_length=MAX_REQUIREMENTS)
    approval_mode: str | None = None
    require_available: bool = False
    at: str | None = None
    limit: int = 20


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

    def _explorer_file(name: str, media_type: str) -> Response:
        path = EXPLORER_ROOT / name
        if not path.is_file():
            raise HTTPException(
                status_code=404,
                detail=(
                    "the Explorer is not present in this installation; it lives in "
                    "apps/explorer/ in the repository"
                ),
            )
        response: Response
        if media_type == "text/html":
            response = HTMLResponse(path.read_text(encoding="utf-8"))
        else:
            response = PlainTextResponse(path.read_text(encoding="utf-8"), media_type=media_type)
        response.headers["Content-Security-Policy"] = EXPLORER_CSP
        return response

    @app.get("/", response_class=HTMLResponse)
    def explorer() -> Response:
        """Serve the Explorer from this origin.

        Same origin on purpose. The page reads this API and nothing else, so it
        needs no cross-origin permission and this service needs no CORS header
        it would then have to be careful about.
        """
        return _explorer_file("index.html", "text/html")

    @app.get("/explorer/app.css")
    def explorer_css() -> Response:
        return _explorer_file("app.css", "text/css")

    @app.get("/explorer/app.js")
    def explorer_js() -> Response:
        return _explorer_file("app.js", "text/javascript")

    @app.get("/explorer/lineageauth.js")
    def explorer_verifier() -> Response:
        """The second implementation, so the local Explorer verifies too.

        Served from `packages/js/` rather than copied, because a copy would be
        a second thing to keep in step with the one the tests exercise.
        """
        path = Path(__file__).resolve().parents[3] / "packages" / "js" / "lineageauth.js"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="the JavaScript verifier is not present")
        response = PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/javascript")
        response.headers["Content-Security-Policy"] = EXPLORER_CSP
        return response

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

    @app.get(f"/{API_VERSION}/lineages/{{lineage}}/graph")
    def get_lineage_graph(lineage: str, at: str | None = None) -> dict[str, Any]:
        """Project a lineage into nodes and edges for rendering.

        Every status here comes from the resolver, not from the drawing. A
        picture that computed its own answers could disagree with the verifier,
        and people believe pictures.
        """
        moment = _moment(at)
        try:
            return build_graph(index.bundle(lineage=lineage), lineage=lineage, at=moment).to_dict()
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get(f"/{API_VERSION}/passports/{{did}}")
    def get_passport(did: str, lineage: str, at: str | None = None) -> dict[str, Any]:
        """Project what this bundle says about one DID, in separate categories.

        `docs/09`: never merge them into one unlabelled truth. There is no
        combined field, and the response says which sections are absent because
        nothing was found versus absent because the machinery is not built.
        """
        moment = _moment(at)
        try:
            return build_passport(
                index.bundle(lineage=lineage), lineage=lineage, did=did, at=moment
            ).to_dict()
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get(f"/{API_VERSION}/exchange")
    def get_exchange(
        lineage: str,
        at: str | None = None,
        status: Annotated[list[str] | None, FastQuery()] = None,
        requester: str | None = None,
        claimable_only: bool = False,
        blocked_did: Annotated[list[str] | None, FastQuery()] = None,
        blocked_task: Annotated[list[str] | None, FastQuery()] = None,
    ) -> dict[str, Any]:
        """List tasks, filtered the way the caller asked.

        `blocked_did` and `blocked_task` are the caller's own blocklist. They
        hide listings from this response and delete nothing: the events stay in
        the store, stay verifiable by anybody, and the response reports how many
        entries the filter removed.
        """
        moment = _moment(at)
        try:
            moderation = Moderation.of(dids=blocked_did or [], tasks=blocked_task or [])
            return browse(
                index.bundle(lineage=lineage),
                lineage=lineage,
                at=moment,
                status=status,
                requester=requester,
                claimable_only=claimable_only,
                moderation=moderation,
            ).to_dict()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get(f"/{API_VERSION}/disputes/{{case_id}}")
    def get_dispute(case_id: str, lineage: str, at: str | None = None) -> dict[str, Any]:
        """Resolve one dispute into its outcome, its tally and its caveats.

        The response carries the seats, every juror's disclosed and detected
        conflicts, and what the outcome would have been without the conflicted
        jurors -- so a reader can check the procedure rather than take the
        outcome on faith. It is a technical result, not arbitration.
        """
        moment = _moment(at)
        try:
            return resolve_dispute(
                index.bundle(lineage=lineage), lineage=lineage, case_id=case_id, at=moment
            ).to_dict()
        except UnknownCaseError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except LineageAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post(f"/{API_VERSION}/router/search")
    def router_search(body: SearchRequest) -> dict[str, Any]:
        """Rank agents by how well they fit a query.

        The response carries the weights and every contribution, so a caller can
        recompute the ranking. It is not authorization: `docs/10` is explicit
        that a search result does not permit an action, and a grant can be
        revoked between finding an agent and asking it to act.
        """
        moment = _moment(body.at)
        try:
            query = Query(
                skills=tuple(body.skills),
                requires=tuple(
                    Requirement(
                        namespace=item["namespace"],
                        resource=item["resource"],
                        action=item["action"],
                    )
                    for item in body.requires
                ),
                approval_mode=(
                    ApprovalMode.parse(body.approval_mode)
                    if body.approval_mode is not None
                    else None
                ),
                require_available=body.require_available,
            )
            return search(
                index.bundle(lineage=body.lineage),
                lineage=body.lineage,
                query=query,
                at=moment,
                limit=body.limit,
            ).to_dict()
        except (LineageAuthError, KeyError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

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
