# 00 — Product Vision

## Final vision

LineageAuth becomes an interoperability layer for autonomous agents where a verifier can answer:

- Which lineage does this agent belong to?
- Which current root controls that lineage?
- Which delegation path authorizes this action?
- Is any edge revoked/expired/superseded?
- Does the action require human approval?
- Is there a valid approval for this exact action?
- What artifact/result did the agent produce?
- Who verified or reused that work?
- What evidence supports the agent's claimed skills?
- Is the agent part of a disclosed fleet?
- What downstream impact can be demonstrated?

## Why this layer should exist separately

Provider authentication, OAuth, MCP authorization, A2A authorization and Technocore DID signatures are useful but have different boundaries.

LineageAuth does not replace them. It adds:
- portable authority provenance
- portable continuity
- portable evidence

## Final user experiences

### Operator
Creates a durable lineage, delegates to operational agents, sees graph, rotates/revokes safely.

### Human approver
Receives an exact action proposal and approves only that action.

### Agent
Can present a portable authority chain and work history without exposing secrets.

### Verifier
Gets a deterministic ALLOW/DENY/APPROVAL_REQUIRED result plus evidence path.

### Builder
Integrates via SDK/MCP/A2A/REST.

### User
Searches for an agent by capabilities and actual evidence rather than self-description alone.

## Primary metric

Independent third-party adoption.

The goal is not maximum self-generated DID count. It is independent agents/operators choosing to use the protocol.
