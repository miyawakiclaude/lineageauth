"""The provenance check, and where it sits in the sequence.

`docs/20` numbers the steps before a consequential A2A task:

    1. normal A2A authentication
    2. normal A2A server authorization
    3. optional LineageAuth provenance check
    4. optional exact human approval
    5. execute

Only step 3 lives here, and steps 1 and 2 are not this library's to perform,
skip, or vouch for. That ordering is returned with every answer, because a
provenance result that arrives without it looks exactly like an authorization
decision -- and a caller who mistakes it for one has removed their own server's
check and replaced it with a stranger's card.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from lineageauth.adapters.a2a.card import A2A_NAMESPACE, a2a_resource_for
from lineageauth.authority import check_permission
from lineageauth.bundle import EventBundle

INVOKE = "invoke"

VERIFICATION_ORDER = (
    "A2A authentication",
    "A2A server authorization",
    "LineageAuth provenance (this answer)",
    "exact human approval, where the action needs one",
    "execute",
)

NOT_AUTHORIZATION_NOTE = (
    "This is provenance, not permission, and it is step 3 of 5. The A2A server's "
    "own authentication and authorization come first and are never bypassed, "
    "weakened or stood in for by this answer. An ALLOW here means the agent holds "
    "the authority it claims inside its own lineage; it says nothing about whether "
    "the server should run anything."
)


def check_a2a_invocation(
    bundle: EventBundle,
    *,
    lineage: str,
    agent: str,
    skill_id: str,
    at: datetime,
    action: str = INVOKE,
) -> dict[str, Any]:
    """Ask whether an agent holds authority for one A2A skill, and say what that means.

    The skill id maps onto `a2a` / `skill:<id>` through the scope grammar
    (`docs/20`), so an id that would widen the resource is refused rather than
    formatted.
    """
    resource = a2a_resource_for(skill_id=skill_id)
    decision = check_permission(
        bundle,
        lineage=lineage,
        agent=agent,
        namespace=A2A_NAMESPACE,
        resource=resource,
        action=action,
        at=at,
    )
    return {
        "allowed": decision.allowed,
        "reason": str(decision.reason),
        "detail": decision.detail,
        "namespace": A2A_NAMESPACE,
        "resource": resource,
        "action": action,
        "root": decision.root,
        "epoch": decision.epoch,
        "approval": decision.approval.wire_name,
        "refusals": [
            {"eventId": r.event_id, "reason": str(r.reason), "detail": r.detail}
            for r in decision.refusals
        ],
        "verificationOrder": list(VERIFICATION_ORDER),
        "note": NOT_AUTHORIZATION_NOTE,
    }
