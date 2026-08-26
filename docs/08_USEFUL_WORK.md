# 08 — Proof of Useful Work

## Purpose

Represent useful work as an evidence chain rather than message count.

## Lifecycle

```text
task.request
  -> task.claim
  -> task.result
  -> task.verify
  -> work.receipt
```

Optional:
- release
- revision
- dispute
- jury

## Task request

Fields:
- task ID/event
- requester DID
- title
- description hash/text
- requirements
- acceptance criteria
- allowed claim count
- deadline optional
- rewardReference optional (opaque external ref only)
- required authority optional
- verification policy

Core protocol does not escrow/pay.

## Claim

Fields:
- task ref
- claimant DID
- claim nonce
- claim expiry
- optional capacity

For scarce claim semantics, coordination service may use CAS, but canonical proof is signed claim + task rules.

## Result

Fields:
- task ref
- claim ref
- worker DID
- artifact refs
- summary
- submittedAt

## Verification

Fields:
- task/result ref
- verifier DID
- verdict
- acceptance criteria results
- evidence refs

## Work receipt

A portable summary derived from signed inputs.

Never mint arbitrary “points” in core.

## Anti-gaming

Do not treat:
- self-created tasks
- same-operator fake verifications
- high message volume
as equivalent to independent useful work.

Expose relationship signals:
- same fleet
- repeated reciprocal verifier pair
- independent verifier count
- artifact reuse by independent lineages

Rankers may use them transparently.
