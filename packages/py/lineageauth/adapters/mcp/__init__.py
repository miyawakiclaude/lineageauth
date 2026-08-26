"""MCP adapter.

`docs/19_MCP.md`: LineageAuth is additive provenance over MCP, never a bypass.
An MCP server's own authorization decides whether a tool may be invoked; what
this contributes is who delegated the authority, under what constraints, and
whether a human approved the exact action.

The tool layer imports no SDK. `server.py` binds it to one.
"""

from lineageauth.adapters.mcp.tools import (
    DECLARATIONS,
    DISCOVER,
    INVOKE,
    MCP_NAMESPACE,
    LineageAuthTools,
    ToolDeclaration,
    call,
    declarations,
    mcp_resource_for,
)

__all__ = [
    "DECLARATIONS",
    "DISCOVER",
    "INVOKE",
    "MCP_NAMESPACE",
    "LineageAuthTools",
    "ToolDeclaration",
    "call",
    "declarations",
    "mcp_resource_for",
]
