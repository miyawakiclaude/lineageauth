"""Binding the LineageAuth tools to the MCP Python SDK.

Deliberately thin. Everything of substance lives in `tools.py`, which does not
import the SDK at all -- the SDK was reworked for the 2026-07-28 specification
(`FastMCP` became `MCPServer`), and protocol work should not move every time a
transport does. Verified against `mcp` 2.1.1 on 2026-08-27.

The one subtlety is where a tool's input schema comes from. The SDK derives it
from the registered function's signature and offers no hook for supplying one,
so a naive `**kwargs` closure registers as a single required argument called
`arguments` -- the declared schema never reaches the client. Rather than
maintain a second, hand-written set of typed functions that could drift from
the declarations, this synthesises a real signature from each declaration. The
declaration stays the single source of truth, and what the client sees is what
`tools.py` says.

Optional dependency: `pip install lineageauth[mcp]`.
"""

from __future__ import annotations

import inspect
from typing import Any

from lineageauth.adapters.mcp.tools import DECLARATIONS, LineageAuthTools, ToolDeclaration, call
from lineageauth.index import EventIndex

SERVER_NAME = "lineageauth"
SERVER_INSTRUCTIONS = (
    "Verify agent authority and evidence offline. This server holds no private keys, "
    "cannot sign anything, and accepts no events -- `build_*` tools return unsigned "
    "drafts. An allowed result is provenance about who delegated what; the target "
    "system's own authorization still applies and is never bypassed."
)

# JSON Schema types this adapter declares, mapped to the annotations the SDK
# reads back. Anything outside this set would silently become `Any`, so it
# raises instead: a parameter the client cannot be told the type of is worse
# than a build error.
_TYPES: dict[str, Any] = {
    "string": str,
    "integer": int,
    "boolean": bool,
    "object": dict,
    "array": list,
}


def _signature_for(declaration: ToolDeclaration) -> tuple[inspect.Signature, dict[str, Any]]:
    """Build the signature the SDK should derive this tool's schema from."""
    schema = declaration.input_schema
    required = set(schema.get("required", []))
    parameters: list[inspect.Parameter] = []
    annotations: dict[str, Any] = {}

    # Required first: Python forbids a parameter without a default after one
    # with a default, and the SDK reads the signature as written.
    for name in sorted(schema.get("properties", {}), key=lambda n: (n not in required, n)):
        spec = schema["properties"][name]
        json_type = spec.get("type")
        base = _TYPES.get(json_type)
        if base is None:
            raise ValueError(
                f"tool {declaration.name!r} declares parameter {name!r} with unsupported "
                f"JSON type {json_type!r}; add it to the mapping rather than letting the "
                "client be told nothing about it"
            )
        if name in required:
            annotations[name] = base
            parameters.append(
                inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, annotation=base)
            )
        else:
            annotations[name] = base | None
            parameters.append(
                inspect.Parameter(
                    name, inspect.Parameter.KEYWORD_ONLY, annotation=base | None, default=None
                )
            )
    # `dict[str, Any]`, not a bare `dict`: the SDK builds a result schema from
    # this annotation and refuses an unparameterised one.
    annotations["return"] = dict[str, Any]
    return inspect.Signature(parameters, return_annotation=dict[str, Any]), annotations


def create_server(index: EventIndex, *, name: str = SERVER_NAME) -> Any:
    """Build an `MCPServer` exposing the LineageAuth tools over `index`."""
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(name=name, instructions=SERVER_INSTRUCTIONS)
    tools = LineageAuthTools(index)
    for declaration in DECLARATIONS:
        server.add_tool(
            _handler_for(tools, declaration),
            name=declaration.name,
            description=declaration.description,
            # Every tool answers with a structured result -- a reason code, the
            # events behind it, the standing caveat. Left off, the SDK returns
            # prose only, and a client would have to parse an answer back out of
            # a sentence to act on it.
            structured_output=True,
        )
    return server


def _handler_for(tools: LineageAuthTools, declaration: ToolDeclaration) -> Any:
    """Wrap one tool so the SDK sees the declared parameters."""
    signature, annotations = _signature_for(declaration)

    def handler(**arguments: Any) -> dict[str, Any]:
        # Omitted optionals arrive as None. Dropping them lets each tool's own
        # default apply rather than overriding it with a null the caller never
        # sent -- `external` defaulting to True is exactly the case where the
        # difference matters.
        supplied = {k: v for k, v in arguments.items() if v is not None}
        return call(tools, declaration.name, supplied)

    handler.__name__ = declaration.name
    handler.__doc__ = declaration.description
    handler.__signature__ = signature  # type: ignore[attr-defined]
    handler.__annotations__ = annotations
    return handler


def tool_schemas(index: EventIndex) -> dict[str, Any]:
    """The input schemas the SDK will actually publish. Used to check the binding."""
    import asyncio

    server = create_server(index)
    published = asyncio.run(server.list_tools())
    # `input_schema`, not `inputSchema`: mcp 2.x moved its model fields to
    # snake_case even though the wire format stays camelCase.
    return {tool.name: tool.input_schema for tool in published}


def run_stdio(index: EventIndex) -> None:  # pragma: no cover - process entry point
    """Serve over stdio. The usual way a host launches a local MCP server."""
    create_server(index).run()
