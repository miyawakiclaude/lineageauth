# 21 — Database and Projection Model

## Principle

DB is derived, not authority.

## Core tables

- events
- proofs
- lineages
- roots
- recovery_policies
- recovery_members
- delegations
- revocations
- successions
- approvals
- spent_approvals

## Evidence tables

- artifacts
- artifact_receipts
- attestations
- tasks
- task_claims
- task_results
- task_verifications
- work_receipts

## Network tables

- profiles
- skill_claims
- availability
- fleets
- fleet_bindings
- disputes
- jury_votes
- verdicts
- impact_edges

## Search projections

- passport_projection
- skill_search
- authority_search
- task_search
- impact_summary

## Rebuild

Provide:
`la index rebuild <event-store>`

All projections must rebuild deterministically.

## PostgreSQL

Production:
- immutable event ingest table
- unique event_id
- JSONB raw envelope
- normalized projections
- migration version

## SQLite

Local/MVP supported.
