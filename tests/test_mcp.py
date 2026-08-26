"""The MCP adapter.

docs/19 sets two boundaries this file exists to hold: the server holds no keys
and returns unsigned drafts, and a LineageAuth answer never stands in for the
MCP server's own authorization.

The tool layer is tested without the SDK, which is also how it is written. The
SDK was reworked for the 2026-07-28 specification, and a test suite that could
only run with the current SDK version would stop testing the protocol the day
that changed.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.adapters.mcp import (
    DECLARATIONS,
    LineageAuthTools,
    call,
    declarations,
    mcp_resource_for,
)
from lineageauth.builders import (
    build_delegation_grant,
    build_delegation_revoke,
    build_root_create,
    sign_payload,
)
from lineageauth.canonical import b64u_encode
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError
from lineageauth.index import EventIndex
from tests.testkeys import AGENT_1, OUTSIDER, ROOT_A, unsafe_signer

AT = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
AT_TEXT = "2026-08-26T12:00:00Z"

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

MCP_SCOPE = {
    "namespace": "mcp",
    "resource": "server:files/tool:read",
    "actions": ["invoke"],
}


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, scope: dict | None = None) -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=AGENT.did,
            epoch=0,
            scopes=[scope or MCP_SCOPE],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            issued_at=AT,
        ),
        [ROOT],
    )


@pytest.fixture
def tools() -> LineageAuthTools:
    index = EventIndex()
    index.ingest_all([genesis(), grant()])
    return LineageAuthTools(index)


@pytest.fixture
def index() -> EventIndex:
    built = EventIndex()
    built.ingest_all([genesis(), grant()])
    return built


class TestDeclarations:
    def test_every_declared_tool_can_be_called(self) -> None:
        from lineageauth.adapters.mcp.tools import _HANDLERS

        assert {d.name for d in DECLARATIONS} == set(_HANDLERS)

    def test_declarations_are_in_mcp_shape(self) -> None:
        for declaration in declarations():
            assert set(declaration) == {"name", "description", "inputSchema"}
            assert declaration["inputSchema"]["type"] == "object"
            # Closed schemas: a field this server cannot interpret should be a
            # refusal, not something silently ignored.
            assert declaration["inputSchema"]["additionalProperties"] is False

    def test_descriptions_say_what_the_tool_does_not_do(self) -> None:
        by_name = {d.name: d.description for d in DECLARATIONS}
        assert "still applies" in by_name["lineageauth_check_permission"]
        assert "UNSIGNED" in by_name["lineageauth_build_delegation"]
        assert "cannot sign" in by_name["lineageauth_build_delegation"]
        assert "decides that for itself" in by_name["lineageauth_check_mcp_invocation"]

    def test_no_tool_offers_to_sign(self) -> None:
        # docs/19: the MCP server does not hold root private keys. The way to
        # guarantee that is to expose nothing that could use one.
        for declaration in DECLARATIONS:
            assert "sign" not in declaration.name
            assert "seed" not in str(declaration.input_schema).lower()
            assert "privateKey" not in str(declaration.input_schema)


class TestBoundaries:
    def test_meta_states_what_the_server_refuses_to_be(self, tools: LineageAuthTools) -> None:
        body = call(tools, "lineageauth_meta", {})
        assert body["holdsPrivateKeys"] is False
        assert body["canSign"] is False
        assert body["acceptsEvents"] is False

    def test_a_permission_answer_says_it_is_not_permission(self, tools: LineageAuthTools) -> None:
        body = call(
            tools,
            "lineageauth_check_mcp_invocation",
            {
                "lineage": LINEAGE,
                "agent": AGENT.did,
                "server_id": "files",
                "tool_name": "read",
                "at": AT_TEXT,
            },
        )
        assert body["allowed"] is True
        assert "never bypassed" in body["note"]

    def test_a_draft_comes_back_unsigned(self, tools: LineageAuthTools) -> None:
        body = call(
            tools,
            "lineageauth_build_delegation",
            {
                "lineage": LINEAGE,
                "issuer": ROOT.did,
                "subject": AGENT.did,
                "epoch": 0,
                "scopes": [MCP_SCOPE],
                "not_before": AT_TEXT,
                "expires_at": "2026-12-31T00:00:00Z",
                "issued_at": AT_TEXT,
            },
        )
        assert body["signed"] is False
        assert "UNSIGNED" in body["note"]
        # A payload with no proofs authorizes nothing, and the bundle agrees.
        from lineageauth.bundle import EventBundle

        bundle = EventBundle.from_envelopes([Envelope(payload=body["payload"], proofs=[])])
        assert bundle.admitted == ()

    def test_an_approval_draft_does_not_invent_the_nonce(self, tools: LineageAuthTools) -> None:
        # The caller supplies it. A nonce this server generated is one the
        # caller cannot check the provenance of.
        schema = next(
            d for d in DECLARATIONS if d.name == "lineageauth_build_approval"
        ).input_schema
        assert "nonce_b64u" in schema["required"]

    def test_an_approval_check_reserves_nothing(self, tools: LineageAuthTools) -> None:
        body = call(
            tools,
            "lineageauth_verify_approval",
            {
                "lineage": LINEAGE,
                "agent": AGENT.did,
                "namespace": "mcp",
                "resource": "server:files/tool:read",
                "action": "invoke",
                "destination": "mcp://files/read",
                "content_hash": "sha256:" + "0" * 64,
                "at": AT_TEXT,
            },
        )
        assert body["reserved"] is False
        assert "re-check at the moment of execution" in body["note"]


class TestAnswersMatchTheLibrary:
    def test_permission_agrees_with_check_permission(self, tools: LineageAuthTools) -> None:
        from lineageauth.authority import check_permission
        from lineageauth.bundle import EventBundle

        direct = check_permission(
            EventBundle.from_envelopes([genesis(), grant()]),
            lineage=LINEAGE,
            agent=AGENT.did,
            namespace="mcp",
            resource="server:files/tool:read",
            action="invoke",
            at=AT,
        )
        body = call(
            tools,
            "lineageauth_check_permission",
            {
                "lineage": LINEAGE,
                "agent": AGENT.did,
                "namespace": "mcp",
                "resource": "server:files/tool:read",
                "action": "invoke",
                "at": AT_TEXT,
            },
        )
        assert body["allowed"] == direct.allowed
        assert body["reason"] == str(direct.reason)

    def test_revocation_is_reflected(self) -> None:
        index = EventIndex()
        target = grant()
        index.ingest_all(
            [
                genesis(),
                target,
                sign_payload(
                    build_delegation_revoke(
                        lineage=LINEAGE, issuer=ROOT.did, grant=target.event_id, issued_at=AT
                    ),
                    [ROOT],
                ),
            ]
        )
        body = call(
            LineageAuthTools(index),
            "lineageauth_check_mcp_invocation",
            {
                "lineage": LINEAGE,
                "agent": AGENT.did,
                "server_id": "files",
                "tool_name": "read",
                "at": AT_TEXT,
            },
        )
        assert body["allowed"] is False
        assert body["reason"] == "REVOKED"

    def test_an_agent_without_a_grant_is_denied(self, tools: LineageAuthTools) -> None:
        body = call(
            tools,
            "lineageauth_check_mcp_invocation",
            {
                "lineage": LINEAGE,
                "agent": STRANGER.did,
                "server_id": "files",
                "tool_name": "read",
                "at": AT_TEXT,
            },
        )
        assert body["reason"] == "DENIED"

    def test_a_different_tool_is_not_covered(self, tools: LineageAuthTools) -> None:
        # The grant names server:files/tool:read. Invoking `write` is a
        # different resource, and deny-by-default applies.
        body = call(
            tools,
            "lineageauth_check_mcp_invocation",
            {
                "lineage": LINEAGE,
                "agent": AGENT.did,
                "server_id": "files",
                "tool_name": "write",
                "at": AT_TEXT,
            },
        )
        assert body["allowed"] is False


class TestResourceMapping:
    def test_it_maps_a_server_and_tool(self) -> None:
        assert mcp_resource_for("files") == "server:files"
        assert mcp_resource_for("files", "read") == "server:files/tool:read"

    @pytest.mark.parametrize(
        ("server_id", "tool_name"),
        [
            ("files/tool:write", "read"),
            ("files", "read/../write"),
            ("files", "read write"),
            ("..", "read"),
            ("files", "*"),
        ],
    )
    def test_a_name_that_could_widen_the_resource_is_refused(
        self, server_id: str, tool_name: str
    ) -> None:
        # MCP's own guidance is that what a server says about itself is
        # untrusted, so these arrive as data and are validated, not formatted.
        with pytest.raises(MalformedEventError):
            mcp_resource_for(server_id, tool_name)


class TestDispatch:
    def test_an_unknown_tool_is_refused(self, tools: LineageAuthTools) -> None:
        with pytest.raises(MalformedEventError, match="no such tool"):
            call(tools, "lineageauth_sign_everything", {})

    def test_a_protocol_error_becomes_a_structured_refusal(self, tools: LineageAuthTools) -> None:
        # A caller asking whether something is allowed deserves a reason code,
        # not an unhandled traceback.
        body = call(tools, "lineageauth_resolve_lineage", {"lineage": "not-a-lineage"})
        assert body["resolved"] is False
        assert body["reason"] == "MALFORMED"

    def test_bad_arguments_become_a_structured_refusal(self, tools: LineageAuthTools) -> None:
        body = call(tools, "lineageauth_resolve_did", {"wrong": "argument"})
        assert body["reason"] == "MALFORMED"
        assert "bad arguments" in body["error"]

    def test_verify_event_round_trips(self, tools: LineageAuthTools) -> None:
        event = genesis()
        body = call(
            tools,
            "lineageauth_verify_event",
            {
                "payload": event.payload,
                "proofs": [p.model_dump() for p in event.proofs],
            },
        )
        assert body["integrityOk"] is True
        assert "not an authorization decision" in body["note"]

    def test_list_grants_reports_standing(self, tools: LineageAuthTools) -> None:
        body = call(tools, "lineageauth_list_grants", {"lineage": LINEAGE, "at": AT_TEXT})
        assert len(body["grants"]) == 1
        assert body["grants"][0]["usable"] is True

    def test_the_graph_tool_returns_a_projection(self, tools: LineageAuthTools) -> None:
        body = call(tools, "lineageauth_authority_graph", {"lineage": LINEAGE, "at": AT_TEXT})
        assert body["resolved"] is True
        assert body["edges"][0]["kind"] == "delegated"


class TestApprovalDraft:
    def test_it_binds_the_exact_action(self, tools: LineageAuthTools) -> None:
        body = call(
            tools,
            "lineageauth_build_approval",
            {
                "lineage": LINEAGE,
                "approver": ROOT.did,
                "agent": AGENT.did,
                "namespace": "mcp",
                "resource": "server:files/tool:read",
                "action": "invoke",
                "destination": "mcp://files/read",
                "content_hash": "sha256:" + "0" * 64,
                "nonce_b64u": b64u_encode(b"\x11" * 16),
                "expires_at": "2026-08-26T12:10:00Z",
                "issued_at": AT_TEXT,
            },
        )
        assert body["signed"] is False
        assert body["payload"]["requestHash"] == body["requestHash"]
        assert "server:files/tool:read" in body["preview"]

    def test_a_short_nonce_is_refused(self, tools: LineageAuthTools) -> None:
        body = call(
            tools,
            "lineageauth_build_approval",
            {
                "lineage": LINEAGE,
                "approver": ROOT.did,
                "agent": AGENT.did,
                "namespace": "mcp",
                "resource": "server:files/tool:read",
                "action": "invoke",
                "destination": "mcp://files/read",
                "content_hash": "sha256:" + "0" * 64,
                "nonce_b64u": b64u_encode(b"\x11" * 8),
                "expires_at": "2026-08-26T12:10:00Z",
                "issued_at": AT_TEXT,
            },
        )
        assert body["reason"] == "MALFORMED"


# Scoped to the binding class, not the module. A module-level `importorskip`
# would take the SDK-independent tool tests with it -- and those are exactly the
# ones that must keep running when the SDK is absent, since being able to test
# the tool layer without it is the reason the split exists.
_HAS_MCP_SDK = importlib.util.find_spec("mcp") is not None


@pytest.mark.skipif(not _HAS_MCP_SDK, reason="the MCP SDK is an optional extra")
class TestSdkBinding:
    """The binding, checked against the real SDK rather than reasoned about.

    The SDK derives a tool's input schema from the registered function's
    signature and offers no hook for supplying one. A `**kwargs` closure
    therefore publishes a single required argument called `arguments`, and the
    declared schema never reaches the client -- which is exactly what the first
    version of this binding did. These tests exist because that bug was found by
    running it, not by reading it.
    """

    def _schemas(self, index: EventIndex) -> dict:
        from lineageauth.adapters.mcp.server import tool_schemas

        return tool_schemas(index)

    def test_every_declared_tool_is_registered(self, index: EventIndex) -> None:
        assert set(self._schemas(index)) == {d.name for d in DECLARATIONS}

    def test_the_published_schema_matches_the_declaration(self, index: EventIndex) -> None:
        published = self._schemas(index)
        for declaration in DECLARATIONS:
            schema = published[declaration.name]
            declared = declaration.input_schema
            assert set(schema.get("properties", {})) == set(declared["properties"]), (
                f"{declaration.name} publishes different parameters than it declares"
            )
            assert set(schema.get("required", [])) == set(declared["required"]), (
                f"{declaration.name} publishes different required fields than it declares"
            )

    def test_no_tool_publishes_a_catch_all_argument(self, index: EventIndex) -> None:
        # The specific regression: `**arguments` registering as one required
        # field named `arguments`.
        for name, schema in self._schemas(index).items():
            assert "arguments" not in schema.get("properties", {}), name

    def test_a_tool_call_returns_the_library_answer(self, index: EventIndex) -> None:
        import asyncio

        from lineageauth.adapters.mcp.server import create_server

        server = create_server(index)

        def result_of(name: str, args: dict) -> dict:
            raw = asyncio.run(server.call_tool(name, args))
            structured = getattr(raw, "structured_content", None)
            return structured if structured is not None else raw  # type: ignore[return-value]

        allowed = result_of(
            "lineageauth_check_mcp_invocation",
            {
                "lineage": LINEAGE,
                "agent": AGENT.did,
                "server_id": "files",
                "tool_name": "read",
                "at": AT_TEXT,
            },
        )
        assert allowed["allowed"] is True

        # A different tool is a different resource, and deny-by-default holds
        # through the SDK exactly as it does in the library.
        denied = result_of(
            "lineageauth_check_mcp_invocation",
            {
                "lineage": LINEAGE,
                "agent": AGENT.did,
                "server_id": "files",
                "tool_name": "write",
                "at": AT_TEXT,
            },
        )
        assert denied["allowed"] is False

    def test_an_omitted_optional_does_not_override_a_default(self, index: EventIndex) -> None:
        """Optionals arrive as None and are dropped before dispatch.

        Passing the None through would override each tool's own default -- and
        `external` defaulting to True is precisely the case where that would
        turn the cautious answer into the permissive one.
        """
        import asyncio

        from lineageauth.adapters.mcp.server import create_server

        server = create_server(index)
        raw = asyncio.run(server.call_tool("lineageauth_meta", {}))
        structured = getattr(raw, "structured_content", None)
        body = structured if structured is not None else raw
        assert body["canSign"] is False
