"""LineageAuth as MCP tools, without depending on the MCP SDK.

`docs/19_MCP.md` names the tools. This module implements them as plain
functions over an index, and declares them in MCP's shape -- name, description,
input schema -- so a server binding is a thin layer rather than the substance.
That split is deliberate: the SDK went through a major rework for the
2026-07-28 specification (`FastMCP` became `MCPServer`), and protocol work
should not move every time a transport does.

Two rules from `docs/19` shape what is here.

*This server holds no keys.* There is no signing tool. `build_delegation` and
`build_approval` return **unsigned drafts** -- payloads a caller takes away and
signs somewhere that has a key, ideally offline for a root. A tool that could
sign would make every host that runs it a place a root key lives.

*LineageAuth does not replace MCP's authorization.* A `check_permission` result
is additional provenance about who delegated what. The MCP server's own
authorization still applies and is never bypassed by anything answered here.

One more, from MCP's own security guidance: tool descriptions and annotations
are untrusted unless the server is trusted. That cuts both ways, and it is why
`mcp_resource_for` exists -- an MCP server id and tool name arriving from
somewhere else are data, and they get validated against the scope grammar
before they are used as a resource.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from lineageauth import __version__, catalog
from lineageauth.actions import ActionRequest
from lineageauth.approval import check_execution
from lineageauth.authority import check_permission, describe_grants
from lineageauth.builders import build_approval_receipt, build_delegation_grant
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError, MalformedEventError
from lineageauth.graph import build_graph
from lineageauth.index import EventIndex
from lineageauth.lineage import resolve_lineage
from lineageauth.scopes import WILDCARD, parse_resource
from lineageauth.timeutil import format_instant, parse_instant
from lineageauth.verify import verify_event

# docs/19: an MCP server or tool maps onto the `mcp` namespace.
MCP_NAMESPACE = "mcp"
INVOKE = "invoke"
DISCOVER = "discover"

PROVENANCE_NOTE = (
    "This is provenance, not permission. The MCP server's own authorization still "
    "applies and is never bypassed by this answer."
)

UNSIGNED_NOTE = (
    "This is an UNSIGNED draft. It grants nothing until a key signs it, and this "
    "server holds no keys -- sign it where the key lives, offline for a root key."
)


def _moment(value: Any) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    return parse_instant(value, field="at")


def mcp_resource_for(server_id: str, tool_name: str | None = None) -> str:
    """Map an MCP server (and optionally a tool) onto a LineageAuth resource.

    Validated through the scope grammar rather than formatted by hand. A server
    id and tool name reach this from outside, and MCP's own guidance is that
    what a server says about itself is untrusted -- so a name carrying a slash
    or a control character is refused here rather than becoming a resource that
    matches more than it should.
    """
    for label, value in (("server id", server_id), ("tool name", tool_name)):
        if value is not None and WILDCARD in value:
            # A wildcard is legitimate in a *scope*, where it means "any tool on
            # this server". It is wrong here: this maps one concrete invocation
            # that is about to happen, and a resource meaning "any" would be
            # asked about -- and answered -- far more broadly than the caller
            # intended.
            raise MalformedEventError(
                f"{label} must name one concrete target; a wildcard belongs in a scope, "
                "not in the resource for a specific invocation"
            )
    resource = (
        f"server:{server_id}" if tool_name is None else f"server:{server_id}/tool:{tool_name}"
    )
    parse_resource(MCP_NAMESPACE, resource)
    return resource


@dataclass(frozen=True, slots=True)
class ToolDeclaration:
    """One tool, in the shape MCP declares them."""

    name: str
    description: str
    input_schema: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_STR = {"type": "string"}
_AT = {"type": "string", "description": "RFC3339 UTC evaluation time. Defaults to now."}


class LineageAuthTools:
    """The tool implementations, bound to one index.

    The index is supplied by whoever constructs this, so a host decides what the
    tools can see. Nothing here writes to the index or the store: an MCP client
    cannot add an event, and therefore cannot manufacture authority.
    """

    __slots__ = ("_index",)

    def __init__(self, index: EventIndex) -> None:
        self._index = index

    # ------------------------------------------------------------- verify

    def verify_event(
        self, *, payload: dict[str, Any], proofs: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Verify one signed envelope's integrity."""
        envelope = Envelope.model_validate({"payload": payload, "proofs": proofs})
        result = verify_event(envelope)
        return {
            "integrityOk": result.integrity_ok,
            "reason": str(result.reason),
            "detail": result.detail,
            "eventId": result.event_id,
            "eventType": result.event_type,
            "lineage": result.lineage,
            "verifiedSigners": list(result.verified_signers),
            "note": result.note,
        }

    def resolve_lineage(self, *, lineage: str, at: str | None = None) -> dict[str, Any]:
        """Resolve a lineage's current root and epoch."""
        state = resolve_lineage(
            self._index.bundle(lineage=lineage), lineage=lineage, at=_moment(at)
        )
        return {
            "lineage": state.lineage,
            "resolved": state.resolved,
            "reason": str(state.reason),
            "detail": state.detail,
            "root": state.root if state.resolved else None,
            "epoch": state.epoch if state.resolved else None,
            "genesisRoot": state.genesis_root,
            "supersededRoots": list(state.superseded_roots),
            "conflictingEventIds": list(state.conflicting_event_ids),
            "evaluatedAt": format_instant(state.evaluated_at),
            "note": state.note,
        }

    def resolve_did(self, *, did: str) -> dict[str, Any]:
        """What a key has signed. Not what it is allowed to do."""
        return {
            "did": did,
            "signedEventIds": list(self._index.signed_by(did)),
            "note": (
                "Signing is key control, not authority, identity, or standing. Use "
                "check_permission for an authority decision."
            ),
        }

    # ------------------------------------------------------------- authority

    def check_permission(
        self,
        *,
        lineage: str,
        agent: str,
        namespace: str,
        resource: str,
        action: str,
        at: str | None = None,
        external: bool = True,
    ) -> dict[str, Any]:
        """Decide whether an agent holds authority for one exact action."""
        decision = check_permission(
            self._index.bundle(lineage=lineage),
            lineage=lineage,
            agent=agent,
            namespace=namespace,
            resource=resource,
            action=action,
            at=_moment(at),
            external=external,
        )
        return {
            "allowed": decision.allowed,
            "reason": str(decision.reason),
            "detail": decision.detail,
            "root": decision.root,
            "epoch": decision.epoch,
            "approval": decision.approval.wire_name,
            "path": list(decision.path),
            "refusals": [
                {"eventId": r.event_id, "reason": str(r.reason), "detail": r.detail}
                for r in decision.refusals
            ],
            "evaluatedAt": format_instant(decision.evaluated_at),
            "note": f"{decision.note} {PROVENANCE_NOTE}",
        }

    def check_mcp_invocation(
        self,
        *,
        lineage: str,
        agent: str,
        server_id: str,
        tool_name: str,
        at: str | None = None,
    ) -> dict[str, Any]:
        """Ask whether an agent may invoke one MCP tool (docs/19 mapping)."""
        return self.check_permission(
            lineage=lineage,
            agent=agent,
            namespace=MCP_NAMESPACE,
            resource=mcp_resource_for(server_id, tool_name),
            action=INVOKE,
            at=at,
        )

    def list_grants(self, *, lineage: str, at: str | None = None) -> dict[str, Any]:
        """Report the standing of every delegation in a lineage."""
        standings = describe_grants(
            self._index.bundle(lineage=lineage), lineage=lineage, at=_moment(at)
        )
        return {
            "lineage": lineage,
            "grants": [
                {
                    "eventId": s.grant.event_id,
                    "issuer": s.grant.issuer,
                    "subject": s.grant.subject,
                    "epoch": s.grant.epoch,
                    "scopes": [scope.render() for scope in s.grant.scopes],
                    "approval": s.grant.approval.wire_name,
                    "usable": s.usable,
                    "reason": str(s.reason),
                    "detail": s.detail,
                    "revokedBy": s.revoked_by,
                }
                for s in standings
            ],
            "note": (
                "A usable grant means the grant itself is current. Whether the chain "
                "above it holds is a separate question."
            ),
        }

    def authority_graph(self, *, lineage: str, at: str | None = None) -> dict[str, Any]:
        """Project a lineage as nodes and edges."""
        return build_graph(
            self._index.bundle(lineage=lineage), lineage=lineage, at=_moment(at)
        ).to_dict()

    # ------------------------------------------------------------- approval

    def verify_approval(
        self,
        *,
        lineage: str,
        agent: str,
        namespace: str,
        resource: str,
        action: str,
        destination: str,
        content_hash: str,
        at: str | None = None,
        external: bool = True,
    ) -> dict[str, Any]:
        """Check whether an approved, unspent receipt covers one exact action.

        A preview: nothing is reserved, so asking does not consume a receipt.
        Consuming one is the executor's job at the moment it acts, because the
        answer can change in between.
        """
        request = ActionRequest(
            namespace=namespace,
            resource=resource,
            action=action,
            destination=destination,
            content_hash=content_hash,
        )
        decision = check_execution(
            self._index.bundle(lineage=lineage),
            lineage=lineage,
            agent=agent,
            request=request,
            at=_moment(at),
            store=None,
            external=external,
            reserve=False,
        )
        return {
            "mayExecute": decision.may_execute,
            "reason": str(decision.reason),
            "detail": decision.detail,
            "receiptId": decision.receipt_id,
            "approver": decision.approver,
            "requestHash": request.request_hash,
            "reserved": False,
            "warnings": list(decision.warnings),
            "note": (
                "A preview. Nothing was reserved, and the answer can change before you "
                f"act -- re-check at the moment of execution. {decision.note}"
            ),
        }

    # ------------------------------------------------------------- drafts

    def build_delegation(
        self,
        *,
        lineage: str,
        issuer: str,
        subject: str,
        epoch: int,
        scopes: list[dict[str, Any]],
        not_before: str,
        expires_at: str,
        max_depth: int = 0,
        approval: str = "none",
        parent: str | None = None,
        issued_at: str | None = None,
    ) -> dict[str, Any]:
        """Draft an UNSIGNED delegation grant."""
        payload = build_delegation_grant(
            lineage=lineage,
            issuer=issuer,
            subject=subject,
            epoch=epoch,
            scopes=scopes,
            not_before=parse_instant(not_before, field="notBefore"),
            expires_at=parse_instant(expires_at, field="expiresAt"),
            max_depth=max_depth,
            approval=approval,
            parent=parent,
            issued_at=_moment(issued_at),
        )
        return {"payload": payload, "signed": False, "note": UNSIGNED_NOTE}

    def build_approval(
        self,
        *,
        lineage: str,
        approver: str,
        agent: str,
        namespace: str,
        resource: str,
        action: str,
        destination: str,
        content_hash: str,
        nonce_b64u: str,
        expires_at: str,
        issued_at: str | None = None,
    ) -> dict[str, Any]:
        """Draft an UNSIGNED approval receipt for one exact action.

        The nonce is supplied by the caller. This server does not invent the
        randomness a human's consent depends on -- and it could not do so
        credibly anyway, since a caller cannot check where it came from.
        """
        from lineageauth.canonical import b64u_decode

        request = ActionRequest(
            namespace=namespace,
            resource=resource,
            action=action,
            destination=destination,
            content_hash=content_hash,
        )
        payload = build_approval_receipt(
            lineage=lineage,
            approver=approver,
            agent=agent,
            request=request,
            nonce=b64u_decode(nonce_b64u),
            expires_at=parse_instant(expires_at, field="expiresAt"),
            issued_at=_moment(issued_at),
        )
        return {
            "payload": payload,
            "signed": False,
            "requestHash": request.request_hash,
            "preview": request.render(),
            "note": UNSIGNED_NOTE,
        }

    def meta(self) -> dict[str, Any]:
        """What this server is and what it refuses to be."""
        return {
            "protocol": catalog.PROTOCOL,
            "coreVersion": catalog.CORE_VERSION,
            "implementation": __version__,
            "indexedEvents": len(self._index),
            "lineages": list(self._index.lineages()),
            "holdsPrivateKeys": False,
            "canSign": False,
            "acceptsEvents": False,
            "note": PROVENANCE_NOTE,
        }


DECLARATIONS: tuple[ToolDeclaration, ...] = (
    ToolDeclaration(
        "lineageauth_meta",
        "What this LineageAuth server holds, and what it cannot do. It holds no keys "
        "and cannot sign or accept events.",
        _schema({}, []),
    ),
    ToolDeclaration(
        "lineageauth_verify_event",
        "Verify one signed LineageAuth envelope's integrity. Reports whether the "
        "payload was signed unmodified by the DIDs its proofs name. This is not an "
        "authorization decision.",
        _schema(
            {
                "payload": {"type": "object", "description": "The event payload."},
                "proofs": {"type": "array", "items": {"type": "object"}},
            },
            ["payload", "proofs"],
        ),
    ),
    ToolDeclaration(
        "lineageauth_resolve_lineage",
        "Resolve which root currently holds a lineage, and at which epoch. Reports "
        "CONFLICTED and refuses to choose when competing successions cannot be ordered.",
        _schema({"lineage": _STR, "at": _AT}, ["lineage"]),
    ),
    ToolDeclaration(
        "lineageauth_resolve_did",
        "List the events a key has produced a verifying signature on. Signing is key "
        "control, not authority.",
        _schema({"did": _STR}, ["did"]),
    ),
    ToolDeclaration(
        "lineageauth_check_permission",
        "Decide whether an agent holds a valid authority chain for one exact action, "
        "and explain why. Provenance only -- the target system's own authorization "
        "still applies.",
        _schema(
            {
                "lineage": _STR,
                "agent": _STR,
                "namespace": _STR,
                "resource": _STR,
                "action": _STR,
                "at": _AT,
                "external": {
                    "type": "boolean",
                    "description": "Whether the action has an effect outside the agent. "
                    "Defaults to true, which is the assumption that fails safe.",
                },
            },
            ["lineage", "agent", "namespace", "resource", "action"],
        ),
    ),
    ToolDeclaration(
        "lineageauth_check_mcp_invocation",
        "Ask whether an agent holds authority to invoke one MCP tool, mapped onto the "
        "resource server:<id>/tool:<name>. Does not authorize the invocation -- the "
        "MCP server decides that for itself.",
        _schema(
            {
                "lineage": _STR,
                "agent": _STR,
                "server_id": _STR,
                "tool_name": _STR,
                "at": _AT,
            },
            ["lineage", "agent", "server_id", "tool_name"],
        ),
    ),
    ToolDeclaration(
        "lineageauth_list_grants",
        "Report every delegation in a lineage and whether it is currently live, "
        "revoked, expired, or superseded.",
        _schema({"lineage": _STR, "at": _AT}, ["lineage"]),
    ),
    ToolDeclaration(
        "lineageauth_authority_graph",
        "Project a lineage as nodes and edges for rendering. Statuses come from the "
        "verifier, so the picture cannot disagree with it.",
        _schema({"lineage": _STR, "at": _AT}, ["lineage"]),
    ),
    ToolDeclaration(
        "lineageauth_verify_approval",
        "Check whether an unspent human approval covers one exact action. A preview: "
        "nothing is reserved, and the answer can change before you act.",
        _schema(
            {
                "lineage": _STR,
                "agent": _STR,
                "namespace": _STR,
                "resource": _STR,
                "action": _STR,
                "destination": _STR,
                "content_hash": {"type": "string", "description": "sha256:<64 hex>"},
                "at": _AT,
                "external": {"type": "boolean"},
            },
            [
                "lineage",
                "agent",
                "namespace",
                "resource",
                "action",
                "destination",
                "content_hash",
            ],
        ),
    ),
    ToolDeclaration(
        "lineageauth_build_delegation",
        "Draft an UNSIGNED delegation grant. It grants nothing until signed, and this "
        "server cannot sign.",
        _schema(
            {
                "lineage": _STR,
                "issuer": _STR,
                "subject": _STR,
                "epoch": {"type": "integer"},
                "scopes": {"type": "array", "items": {"type": "object"}},
                "not_before": _STR,
                "expires_at": _STR,
                "max_depth": {"type": "integer"},
                "approval": {"type": "string", "enum": ["none", "external-only", "required"]},
                "parent": _STR,
                "issued_at": _AT,
            },
            ["lineage", "issuer", "subject", "epoch", "scopes", "not_before", "expires_at"],
        ),
    ),
    ToolDeclaration(
        "lineageauth_build_approval",
        "Draft an UNSIGNED approval receipt binding one exact action. The caller "
        "supplies the nonce; this server does not invent randomness a human's consent "
        "depends on.",
        _schema(
            {
                "lineage": _STR,
                "approver": _STR,
                "agent": _STR,
                "namespace": _STR,
                "resource": _STR,
                "action": _STR,
                "destination": _STR,
                "content_hash": _STR,
                "nonce_b64u": {
                    "type": "string",
                    "description": "At least 16 bytes, unpadded base64url.",
                },
                "expires_at": _STR,
                "issued_at": _AT,
            },
            [
                "lineage",
                "approver",
                "agent",
                "namespace",
                "resource",
                "action",
                "destination",
                "content_hash",
                "nonce_b64u",
                "expires_at",
            ],
        ),
    ),
)

_HANDLERS: dict[str, str] = {
    "lineageauth_meta": "meta",
    "lineageauth_verify_event": "verify_event",
    "lineageauth_resolve_lineage": "resolve_lineage",
    "lineageauth_resolve_did": "resolve_did",
    "lineageauth_check_permission": "check_permission",
    "lineageauth_check_mcp_invocation": "check_mcp_invocation",
    "lineageauth_list_grants": "list_grants",
    "lineageauth_authority_graph": "authority_graph",
    "lineageauth_verify_approval": "verify_approval",
    "lineageauth_build_delegation": "build_delegation",
    "lineageauth_build_approval": "build_approval",
}


def declarations() -> list[dict[str, Any]]:
    """Every tool, in MCP's declaration shape."""
    return [declaration.to_dict() for declaration in DECLARATIONS]


def call(tools: LineageAuthTools, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one tool call.

    A LineageAuth error becomes a structured refusal rather than an exception:
    a caller asking whether something is allowed deserves a reason code, and an
    unhandled traceback is not one.
    """
    handler_name = _HANDLERS.get(name)
    if handler_name is None:
        raise MalformedEventError(f"no such tool: {name!r}")
    handler = getattr(tools, handler_name)
    try:
        result: dict[str, Any] = handler(**arguments)
    except LineageAuthError as exc:
        return {"error": str(exc), "reason": str(exc.reason), "tool": name}
    except TypeError as exc:
        return {"error": f"bad arguments for {name}: {exc}", "reason": "MALFORMED", "tool": name}
    return result
