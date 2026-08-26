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

## Approval does not create authority

If agent lacks base scope, a human approval receipt alone must still result in DENIED.

## Bulk approvals

Not in MVP.
Future must be explicit constrained batch object, never inferred from one receipt.

## Technocore

Because writes can be GET:
- endpoint semantic table controls consequence classification
- known write GET requires approval if policy requires
