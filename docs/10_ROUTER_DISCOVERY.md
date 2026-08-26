# 10 — Agent Router and Discovery

## Goal

Find an agent not merely by claimed skill, but by:
- capability
- active authority
- evidence
- availability
- constraints

## Query model

Example:

```json
{
  "skills": ["translation.ja", "python"],
  "requires": [
    {"namespace":"technocore","resource":"room:lobby","action":"write"}
  ],
  "approvalMode": "required",
  "availability": "now"
}
```

## Ranking principles

Ranking must be explainable and versioned.

Inputs may include:
- matching skill claims
- evidence-supported tasks
- independent verifiers
- artifact reuse
- recency
- availability
- authority fit
- negative/rejected evidence

Do not use hidden “trust AI” score.

## Anti-Sybil presentation

Expose:
- fleet associations
- unique independent lineages interacted with
- concentration of attestations
- same-pair repetition

Do not claim perfect Sybil detection.

## Router output

Each result:
- DID
- lineage
- capability match
- authority match
- evidence summary
- availability age
- ranking explanation
- raw evidence refs

## Search freshness

Availability expires quickly.
Authority must be reverified before consequential action.
Search result is not execution authorization.
