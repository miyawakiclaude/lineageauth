"""The event type registry (docs/03_EVENT_CATALOG.md).

An unknown type is never assumed harmless. Types listed in
`AUTHORITY_EVENT_TYPES` decide what an agent may do, so anything unrecognised
among them fails closed (docs/24_VERSIONING_MIGRATION.md). Evidence types may
still be displayed raw under an UNKNOWN_VERSION status without being given
semantics.
"""

from __future__ import annotations

from types import MappingProxyType

PROTOCOL = "lineageauth"
CORE_VERSION = "0.1"
SUPPORTED_VERSIONS: frozenset[str] = frozenset({"0.1"})

AUTHORITY_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "root.create",
        "recovery.policy",
        "delegation.grant",
        "delegation.revoke",
        "root.succession",
        "approval.receipt",
    }
)

EVIDENCE_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "artifact.register",
        "artifact.receipt",
        "attestation.issue",
    }
)

WORK_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "task.request",
        "task.claim",
        "task.release",
        "task.result",
        "task.verify",
        "task.cancel",
        "claim.coordinate",
        "work.receipt",
    }
)

PASSPORT_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "profile.statement",
        "skill.claim",
        "availability.statement",
    }
)

FLEET_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "fleet.create",
        "fleet.bind",
        "fleet.unbind",
    }
)

# docs/03 sketches four jury types; three of them survived contact with docs/12
# (D-061). `jury.nominate` is gone because selection lives inside `dispute.open`:
# a separate nomination event lets the opener re-seat the jury after seeing how
# the votes are going, which is the one thing this layer must make impossible.
# `jury.verdict` is gone because docs/03 allows "a deterministic result from
# valid votes" and that is what `resolve_dispute` computes -- a signed verdict
# alongside it would be a second source of truth for the same question.
# `jury.disclose` is here because docs/12 requires conflict disclosure and
# docs/03 never named the event that carries it.
JURY_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "dispute.open",
        "jury.disclose",
        "jury.vote",
    }
)

IMPACT_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "artifact.reuse",
        "artifact.improve",
        "impact.attest",
    }
)

ALL_EVENT_TYPES: frozenset[str] = (
    AUTHORITY_EVENT_TYPES
    | EVIDENCE_EVENT_TYPES
    | WORK_EVENT_TYPES
    | PASSPORT_EVENT_TYPES
    | FLEET_EVENT_TYPES
    | JURY_EVENT_TYPES
    | IMPACT_EVENT_TYPES
)

EVENT_FAMILIES: MappingProxyType[str, frozenset[str]] = MappingProxyType(
    {
        "authority": AUTHORITY_EVENT_TYPES,
        "evidence": EVIDENCE_EVENT_TYPES,
        "work": WORK_EVENT_TYPES,
        "passport": PASSPORT_EVENT_TYPES,
        "fleet": FLEET_EVENT_TYPES,
        "jury": JURY_EVENT_TYPES,
        "impact": IMPACT_EVENT_TYPES,
    }
)


def family_of(event_type: str) -> str | None:
    """Return the family name for `event_type`, or None if unregistered."""
    for name, members in EVENT_FAMILIES.items():
        if event_type in members:
            return name
    return None


def is_authority_bearing(event_type: str) -> bool:
    """True when this type can grant, move, or restrict authority."""
    return event_type in AUTHORITY_EVENT_TYPES
