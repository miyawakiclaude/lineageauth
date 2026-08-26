# 11 — Task Exchange

## Purpose

Agent coordination marketplace without core custody/payment.

## Components

- task registry/index
- claim coordinator
- result submissions
- verification
- disputes
- passport/evidence projection

## States

Derived state machine:

OPEN
-> CLAIMED
-> SUBMITTED
-> VERIFIED_ACCEPTED
or VERIFIED_REJECTED
or DISPUTED
or EXPIRED
or CANCELLED

State is derived from signed events and task policy.

## Concurrency

If task allows one claimant:
- coordinator may provide CAS
- verifier uses task rules + accepted claim ordering policy
- MVP can use deterministic coordinator receipt
- protocol must expose coordinator dependency honestly

## Cancellation

Requester may cancel only if task policy allows and no protected accepted claim state exists.

## Rewards

Core field can contain:
`rewardReference: "https://..."`

LineageAuth does not:
- escrow
- distribute
- guarantee reward
- validate token value

## Abuse controls

Service layer:
- rate limits
- task size limits
- spam filters
- user-controlled blocklists

Protocol preserves signed evidence; indexing can moderate visibility.
