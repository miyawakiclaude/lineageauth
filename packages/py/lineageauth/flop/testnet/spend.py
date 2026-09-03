"""How much test FLOP may be spent, and the fact that a policy is not a promise.

D-108's consequence, written down where it can be seen: LineageAuth's `http`
namespace has no spend condition, so the core cannot enforce a cap. That makes
this module a local guard, and a local guard is not evidence. The cap is
therefore also written into the canonical request that the approval hash binds
-- `prepare.assemble_request` puts `maxSpend` in the control subtree -- so a
receipt approves a ceiling as well as a destination. A policy that only lived
here would let an approval bind the endpoint and leave the amount open.

Decimal, not float. `0.1 + 0.2` is the wrong number in any currency, and a
comparison against a limit is exactly where that matters.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import TestnetFailure, TestnetRefusal

TESTNET_VALUE_NOTICE = "Testnet tokens have no assumed monetary value."


def to_amount(value: object, *, field_name: str = "amount") -> Decimal:
    """Parse an amount without ever going through float.

    A JSON number arrives as a Python float, and `Decimal(0.1)` is not
    `Decimal("0.1")`. Numbers are accepted as strings and integers only, which
    forces the caller to have kept the exact text.
    """
    if isinstance(value, Decimal):
        candidate = value
    elif isinstance(value, bool):
        raise MalformedEventError(f"{field_name} must be a number, not a boolean")
    elif isinstance(value, int):
        candidate = Decimal(value)
    elif isinstance(value, str):
        try:
            candidate = Decimal(value)
        except InvalidOperation as exc:
            raise MalformedEventError(f"{field_name} {value!r} is not a decimal number") from exc
    else:
        raise MalformedEventError(
            f"{field_name} must be a string or an integer; a float cannot represent an "
            "exact amount and is refused rather than rounded"
        )
    if not candidate.is_finite() or candidate < 0:
        raise MalformedEventError(f"{field_name} must be a finite non-negative amount")
    return candidate


def format_amount(value: Decimal) -> str:
    """The canonical text for an amount. Used in hashes, so it is fixed here."""
    normalised = value.normalize()
    text = format(normalised, "f")
    return text


@dataclass(frozen=True, slots=True)
class SpendDecision:
    """Whether an amount is within policy, and which limit decided it."""

    allowed: bool
    limit_id: str
    detail: str
    refusal: TestnetRefusal | None = None
    approval_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "limitId": self.limit_id,
            "detail": self.detail,
            "approvalRequired": self.approval_required,
            "refusal": None if self.refusal is None else self.refusal.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class TestnetSpendPolicy:
    """Conservative caps. Raising one is an explicit, logged act.

    `approval_required_above` defaults to zero, which means every spend needs a
    human. That is not a placeholder: this tool exists to make a person look at
    an exact action, and a threshold above which it stops asking would be the
    first step towards the farming loop directive 27 forbids.
    """

    __test__ = False

    per_action_max: Decimal = Decimal("10")
    daily_max: Decimal = Decimal("50")
    session_max: Decimal = Decimal("25")
    approval_required_above: Decimal = Decimal("0")

    def __post_init__(self) -> None:
        for name in ("per_action_max", "daily_max", "session_max", "approval_required_above"):
            amount = getattr(self, name)
            if not isinstance(amount, Decimal) or not amount.is_finite() or amount < 0:
                raise MalformedEventError(f"{name} must be a finite non-negative Decimal")
        if self.per_action_max > self.session_max or self.session_max > self.daily_max:
            raise MalformedEventError(
                "spend limits must nest: per action <= session <= daily, otherwise the "
                "narrower limit is decorative"
            )

    def requires_approval(self, amount: Decimal) -> bool:
        return amount > self.approval_required_above

    def check(
        self,
        amount: Decimal,
        *,
        approved_max: Decimal | None = None,
        spent_today: Decimal = Decimal("0"),
        spent_this_session: Decimal = Decimal("0"),
    ) -> SpendDecision:
        """Every limit, in the order that produces the most useful message.

        The approved maximum is checked first because it is the one a person
        actually consented to; being told the local policy would have allowed it
        is no comfort when the approval said otherwise.
        """
        approval_required = self.requires_approval(amount)
        if approved_max is not None and amount > approved_max:
            return SpendDecision(
                allowed=False,
                limit_id="approved-max",
                detail=(
                    f"the quote is {format_amount(amount)} and the approved maximum is "
                    f"{format_amount(approved_max)}; an approval binds a ceiling, not a wish"
                ),
                refusal=TestnetRefusal(
                    failure=TestnetFailure.SPEND_LIMIT_EXCEEDED,
                    detail=(
                        f"quote {format_amount(amount)} exceeds the approved maximum "
                        f"{format_amount(approved_max)}"
                    ),
                    stage="spend",
                ),
                approval_required=approval_required,
            )
        checks: tuple[tuple[str, Decimal, Decimal], ...] = (
            ("per-action-max", amount, self.per_action_max),
            ("session-max", spent_this_session + amount, self.session_max),
            ("daily-max", spent_today + amount, self.daily_max),
        )
        for limit_id, proposed, limit in checks:
            if proposed > limit:
                return SpendDecision(
                    allowed=False,
                    limit_id=limit_id,
                    detail=(
                        f"{limit_id} would be exceeded: {format_amount(proposed)} against a "
                        f"limit of {format_amount(limit)}"
                    ),
                    refusal=TestnetRefusal(
                        failure=TestnetFailure.SPEND_LIMIT_EXCEEDED,
                        detail=(
                            f"{limit_id} exceeded: {format_amount(proposed)} > "
                            f"{format_amount(limit)}"
                        ),
                        stage="spend",
                    ),
                    approval_required=approval_required,
                )
        return SpendDecision(
            allowed=True,
            limit_id="within-policy",
            detail=(f"{format_amount(amount)} is within every limit. {TESTNET_VALUE_NOTICE}"),
            approval_required=approval_required,
        )

    def raised(
        self,
        *,
        reason: str,
        per_action_max: Decimal | None = None,
        daily_max: Decimal | None = None,
        session_max: Decimal | None = None,
    ) -> tuple[TestnetSpendPolicy, dict[str, Any]]:
        """A new policy plus the audit line the change must be recorded with.

        Returning the record alongside the policy is how "do not silently raise
        limits" becomes structural: a caller who wants the higher limit is
        holding the log entry in the same tuple and has to discard it
        deliberately.
        """
        if not reason.strip():
            raise MalformedEventError("raising a spend limit requires a stated reason")
        updated = TestnetSpendPolicy(
            per_action_max=per_action_max if per_action_max is not None else self.per_action_max,
            daily_max=daily_max if daily_max is not None else self.daily_max,
            session_max=session_max if session_max is not None else self.session_max,
            approval_required_above=self.approval_required_above,
        )
        return updated, {
            "kind": "spend-policy-raised",
            "reason": reason,
            "before": self.to_dict(),
            "after": updated.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "perActionMax": format_amount(self.per_action_max),
            "dailyMax": format_amount(self.daily_max),
            "sessionMax": format_amount(self.session_max),
            "approvalRequiredAbove": format_amount(self.approval_required_above),
            "unit": "test FLOP",
            "notice": TESTNET_VALUE_NOTICE,
        }


@dataclass(slots=True)
class SpendLedger:
    """Observed spend, by day and by session. Never an estimate.

    Only `record` moves these numbers, and only the executor calls it, and only
    after a receipt says an amount was actually observed. A ledger that counted
    quotes would report spending that never happened.
    """

    session_total: Decimal = Decimal("0")
    by_day: dict[str, Decimal] = field(default_factory=dict)

    def record(self, amount: Decimal, *, at: datetime) -> None:
        if amount < 0:
            raise MalformedEventError("an observed spend cannot be negative")
        key = at.date().isoformat()
        self.by_day[key] = self.by_day.get(key, Decimal("0")) + amount
        self.session_total += amount

    def spent_on(self, day: date) -> Decimal:
        return self.by_day.get(day.isoformat(), Decimal("0"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "sessionTotal": format_amount(self.session_total),
            "byDay": {key: format_amount(value) for key, value in sorted(self.by_day.items())},
            "unit": "test FLOP",
            "observedOnly": True,
        }


def policy_from_mapping(entry: Mapping[str, Any]) -> TestnetSpendPolicy:
    """Build a policy from configuration, refusing floats and negatives."""
    return TestnetSpendPolicy(
        per_action_max=to_amount(entry.get("perActionMax", "10"), field_name="perActionMax"),
        daily_max=to_amount(entry.get("dailyMax", "50"), field_name="dailyMax"),
        session_max=to_amount(entry.get("sessionMax", "25"), field_name="sessionMax"),
        approval_required_above=to_amount(
            entry.get("approvalRequiredAbove", "0"), field_name="approvalRequiredAbove"
        ),
    )


__all__ = [
    "TESTNET_VALUE_NOTICE",
    "SpendDecision",
    "SpendLedger",
    "TestnetSpendPolicy",
    "format_amount",
    "policy_from_mapping",
    "to_amount",
]
