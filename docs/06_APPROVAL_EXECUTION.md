# 06 — Human Approval and Execution

## Goal

Separate:
- agent can propose
- agent has authority
- human approved exact consequence
- executor may perform

## Approval event

Bind:
- lineage
- approver DID
- agent DID
- namespace
- resource
- operation
- destination
- content hash / request hash
- nonce >=128 random bits
- issuedAt
- expiresAt

## Content hashing

Canonical action request object should be JCS + SHA-256.

For text post:
- normalized transport-independent text bytes must be explicitly specified by adapter
- approval preview must show exactly what will be transmitted semantically

## Replay

MVP:
- local spent receipt store
- executor marks receipt consumed atomically

Production:
- optional shared spent service / transparency log
- idempotency key support

## Execution pipeline

```text
Untrusted Input
  -> Proposed Action
  -> Authority Check
  -> Approval Policy
  -> Exact Preview
  -> Human Approval Receipt
  -> Re-check freshness/authority
  -> Execute
  -> Execution Receipt/Evidence
```

## TOCTOU

Immediately before execution:
- re-check grant not revoked
- re-check root epoch
- re-check approval expiry
- re-check content/destination hash
- atomically reserve receipt

## Who may approve

The grants on the authorizing path say. Each grant that demands approval
carries `approvers`, and a child may only narrow its parent's list, so the set
entitled to sign a receipt is the leaf grant's own list (D-107).

- A receipt from anyone else is `DENIED`, not ignored, so an operator can see
  that a receipt they collected does not count.
- The agent is never entitled to approve its own action, even if named.
- A DID that a fleet disclosure ties to the agent is not entitled either (D-105).
- A grant that demands approval and names nobody is not a usable grant.

This replaced D-042, which derived the set from the chain (issuers plus root).
A chain says who delegated, not who may consent; and a chain with no human on it
would otherwise let one agent's key stand in for a person. The verifier asks the
party the grant designates.

What designation does not prove is that the named key is a person, or a person
other than the agent's operator. That is the delegator's naming decision; see
[28](28_NON_GOALS_LIMITATIONS.md).

## Approval does not create authority

If agent lacks base scope, a human approval receipt alone must still result in DENIED.

## Bulk approvals

Not in MVP.
Future must be explicit constrained batch object, never inferred from one receipt.

## Technocore

Because writes can be GET:
- endpoint semantic table controls consequence classification
- known write GET requires approval if policy requires
