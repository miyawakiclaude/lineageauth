"""Binding a person's consent to one exact action, using the core's own semantics.

Nothing new is invented here. `approval.check_execution` already re-resolves
authority, finds a receipt that binds this exact `requestHash`, checks that its
approver is one the grant designates (D-107), checks the window, and reserves
the receipt so it cannot be spent twice. This module's whole job is to hand it
the right `ActionRequest` and to add the two checks the core cannot make,
because they are about FLOP rather than about authority:

* the prepared action has not expired -- an approval for a quote nobody offers
  any more is not consent to today's price;
* the official snapshot and rule set have not moved since preparation. If they
  have, the answer is `REPREPARE_REQUIRED` rather than a silent recalculation
  (acceptance N, directive 18).

Approval does not create authority. If the chain denies the action, a receipt
signed by anybody changes nothing, and the refusal names `AUTHORITY_DENIED`
rather than an approval problem, so the operator fixes the right thing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from lineageauth.actions import ActionRequest
from lineageauth.approval import ExecutionDecision, SpentReceiptStore, check_execution
from lineageauth.bundle import EventBundle
from lineageauth.errors import ReasonCode
from lineageauth.flop.model import SIMULATION_BANNER, TestnetFailure, TestnetRefusal
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.sources import SourceSnapshotSet
from lineageauth.flop.testnet.prepare import (
    PreparedTestnetAction,
    rule_set_hash,
    snapshot_fingerprint,
)
from lineageauth.timeutil import format_instant

# How a core refusal reads in FLOP's vocabulary. Kept as a table so a reader can
# see that nothing is being softened on the way through: a denial stays a
# denial, and only the word changes.
_REASON_TO_FAILURE: dict[ReasonCode, TestnetFailure] = {
    ReasonCode.APPROVAL_REQUIRED: TestnetFailure.APPROVAL_MISSING,
    ReasonCode.DENIED: TestnetFailure.AUTHORITY_DENIED,
    ReasonCode.SCOPE_VIOLATION: TestnetFailure.AUTHORITY_DENIED,
    ReasonCode.UNRESOLVED_PARENT: TestnetFailure.AUTHORITY_DENIED,
    ReasonCode.REVOKED: TestnetFailure.APPROVAL_MISMATCH,
    ReasonCode.EXPIRED: TestnetFailure.APPROVAL_EXPIRED,
    ReasonCode.NOT_YET_VALID: TestnetFailure.APPROVAL_MISMATCH,
    ReasonCode.SUPERSEDED: TestnetFailure.AUTHORITY_DENIED,
    ReasonCode.MALFORMED: TestnetFailure.REQUEST_INVALID,
    ReasonCode.INVALID_SIGNATURE: TestnetFailure.REQUEST_INVALID,
}


@dataclass(frozen=True, slots=True)
class ApprovedTestnetAction:
    """A prepared action plus the receipt that consented to exactly it.

    The executor accepts nothing else. There is no constructor path from a
    prepared action to this type that does not go through `check_execution`.
    """

    prepared: PreparedTestnetAction
    receipt_id: str
    approver: str
    agent: str
    lineage: str
    approved_at: datetime
    reserved: bool
    detail: str
    warnings: tuple[str, ...] = ()

    @property
    def request_hash(self) -> str:
        return self.prepared.request_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "actionId": self.prepared.action_id,
            "requestHash": self.request_hash,
            "receiptId": self.receipt_id,
            "approver": self.approver,
            "agent": self.agent,
            "lineage": self.lineage,
            "approvedAt": format_instant(self.approved_at),
            "receiptReserved": self.reserved,
            "detail": self.detail,
            "warnings": list(self.warnings),
            "executed": False,
            "simulation": self.prepared.simulation,
            **({"banner": SIMULATION_BANNER} if self.prepared.simulation else {}),
        }


def approval_request(prepared: PreparedTestnetAction) -> ActionRequest:
    """The exact `ActionRequest` a human approves. Shown before it is signed."""
    return prepared.action_request()


def freshness_refusal(
    prepared: PreparedTestnetAction,
    *,
    snapshot: SourceSnapshotSet,
    rules: FlopRuleRegistry,
    at: datetime,
) -> TestnetRefusal | None:
    """Whether the world this action was prepared against still holds.

    Three ways it may not: the action expired, the official sources moved, or a
    rule's registered content moved. All three give `REPREPARE_REQUIRED`,
    because the honest response to "the price list changed" is to show the new
    one and ask again, never to proceed on the old one.
    """
    if prepared.expired(at):
        return TestnetRefusal(
            failure=TestnetFailure.REPREPARE_REQUIRED,
            detail=(
                f"the prepared action expired at {format_instant(prepared.expires_at)}; "
                "prepare it again so the person approving sees current numbers"
            ),
            stage="request-validation",
        )
    current_snapshot = snapshot_fingerprint(snapshot)
    if current_snapshot != prepared.plan.source_snapshot_id:
        return TestnetRefusal(
            failure=TestnetFailure.REPREPARE_REQUIRED,
            detail=(
                "RULE UPDATED - the official source snapshot changed since this action was "
                f"prepared ({prepared.plan.source_snapshot_id} -> {current_snapshot}); "
                "the earlier snapshot is kept and no past evidence is rewritten"
            ),
            stage="official-source",
        )
    current_rules = rule_set_hash(rules)
    if current_rules != prepared.plan.rule_set_hash:
        return TestnetRefusal(
            failure=TestnetFailure.REPREPARE_REQUIRED,
            detail=(
                "RULE UPDATED - the rule registry changed since this action was prepared "
                f"({prepared.plan.rule_set_hash} -> {current_rules})"
            ),
            stage="official-source",
        )
    return None


def decision_to_refusal(decision: ExecutionDecision, *, stage: str) -> TestnetRefusal:
    """Translate a core refusal without weakening it."""
    failure = _REASON_TO_FAILURE.get(decision.reason, TestnetFailure.AUTHORITY_DENIED)
    return TestnetRefusal(failure=failure, detail=decision.detail, stage=stage)


def approve(
    prepared: PreparedTestnetAction,
    *,
    bundle: EventBundle,
    lineage: str,
    agent: str,
    at: datetime,
    store: SpentReceiptStore,
    snapshot: SourceSnapshotSet,
    rules: FlopRuleRegistry,
    reserve: bool = False,
) -> ApprovedTestnetAction | TestnetRefusal:
    """Check that a human approved exactly this, and return the approval or the reason.

    `reserve` defaults to False. Approving is a preview: it tells the operator
    whether a receipt is in place, and burning the receipt at that moment would
    mean a failed execution needs a fresh human approval for no reason. The
    executor calls `check_execution` again with `reserve=True` immediately
    before acting, which is where the core says the commit point belongs.
    """
    stale = freshness_refusal(prepared, snapshot=snapshot, rules=rules, at=at)
    if stale is not None:
        return stale
    if prepared.subject_did != agent:
        return TestnetRefusal(
            failure=TestnetFailure.DID_NOT_ACTIVE,
            detail=(
                f"this action was prepared for {prepared.subject_did} and is being approved "
                f"for {agent}; an approval is bound to one subject"
            ),
            stage="active-did",
        )
    decision = check_execution(
        bundle,
        lineage=lineage,
        agent=agent,
        request=approval_request(prepared),
        at=at,
        store=store,
        external=True,
        reserve=reserve,
    )
    if not decision.may_execute:
        return decision_to_refusal(decision, stage="exact-approval")
    if decision.receipt_id is None or decision.approver is None:
        # The chain permitted the action outright. For a spend this tool will
        # not accept that: directive 9 requires a person on every testnet
        # action, and a grant that waived approval does not waive it here.
        return TestnetRefusal(
            failure=TestnetFailure.APPROVAL_MISSING,
            detail=(
                "the authority chain allows this action without human approval, but a FLOP "
                "testnet spend always requires an approval receipt bound to the exact request"
            ),
            stage="exact-approval",
        )
    return ApprovedTestnetAction(
        prepared=prepared,
        receipt_id=decision.receipt_id,
        approver=decision.approver,
        agent=agent,
        lineage=lineage,
        approved_at=at,
        reserved=decision.reserved,
        detail=decision.detail,
        warnings=decision.warnings,
    )


__all__ = [
    "ApprovedTestnetAction",
    "approval_request",
    "approve",
    "decision_to_refusal",
    "freshness_refusal",
]
