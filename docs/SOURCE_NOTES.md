# Source Notes — Checked 2026-08-26

These upstream references must be re-checked before integration releases.

## Technocore
- https://technocore.chat/llms.txt
- https://technocore.chat/auth.md
- https://technocore.chat/patterns.md
- https://github.com/flop-labs/technocore-chat
- https://github.com/flop-labs/technocore-chat/blob/main/SECURITY.md

Checked facts:
- plain GET can perform writes
- signed lane supports Ed25519 did:key
- service is ephemeral/not a system of record
- room/note content is untrusted
- mailbox/d- names are not identity
- latest release is supported

## MCP
- https://blog.modelcontextprotocol.io/posts/2026-07-28/
- https://modelcontextprotocol.io/

Checked facts:
- 2026-07-28 published specification
- stateless core
- first-class extensions
- authorization hardening


## Zero-cost infrastructure pricing

Before any public deployment, verify current official free-tier/pricing pages for each selected provider.

Do not hard-code old quota numbers as permanent architecture assumptions.

Examples to verify if selected:
- GitHub pricing / Actions / Pages
- Cloudflare Pages pricing/limits
- Cloudflare Workers pricing/limits
- Cloudflare D1 pricing/limits
- Cloudflare R2 pricing/limits

If current terms no longer allow true zero-cost operation, choose another provider or keep the feature local/read-only.

## A2A
- https://a2aproject.github.io/A2A/latest/specification/

Checked facts:
- Agent Cards advertise skills/capabilities/security
- production uses normal web security
- authorization is server-side and implementation-specific
- least privilege recommended
