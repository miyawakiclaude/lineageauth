# 19 — MCP Integration

## Upstream context

As verified 2026-08-26, MCP published specification `2026-07-28`:
- stateless protocol core
- first-class extensions
- authorization hardening
- routable method/tool headers
- Tasks as extension

Re-check current spec when implementing.

## LineageAuth role

MCP authorization/provider auth remains authoritative for MCP server access.

LineageAuth adds:
- who delegated agent authority
- portable scope provenance
- exact-action approval evidence

## MCP package

`lineageauth-mcp`

Tools:
- resolve_lineage
- resolve_did
- verify_event
- verify_authority
- check_permission
- build_delegation
- build_approval
- verify_approval
- get_passport
- search_agents

## Secret rule

MCP server does not hold root private keys by default.

`build_*` returns unsigned drafts.

## Mapping

MCP resource:
`server:<server-id>/tool:<tool-name>`

Action:
`invoke`

A gateway can use MCP `Mcp-Method` / `Mcp-Name` data as an input to a LineageAuth policy decision, but must still apply MCP's own authorization.

## Extension

If emitting LineageAuth metadata through MCP extensions, use a namespaced extension and document it as non-standard.
