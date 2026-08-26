# 15 — Resolver, Indexer, and Freshness

## Role

Collect and project signed events.

Never become protocol authority.

## Resolver sources

Possible:
- local bundle
- object store
- configured mirrors
- Technocore discovery hints
- user-provided URLs

Never auto-fetch untrusted URLs from messages without policy/human approval.

## Freshness

For current authority, omission of revocations/succession matters.

Response metadata:
- checkedAt
- sources
- newestEventSeen
- freshnessAge
- conflicts

## High-risk policy

If online freshness is required and cannot be established:
`STALE_STATUS` and deny/review.

## Index rebuild

A fresh DB must be reconstructible from immutable events.

## Search

Search data is projection:
- passport
- skill index
- task index
- impact graph

Raw event IDs always accessible for verification.

## Conflict handling

Indexer surfaces conflicts.
It does not silently select a winner except when LAP defines deterministic preference.
