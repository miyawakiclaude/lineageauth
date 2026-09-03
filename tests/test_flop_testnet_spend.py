"""Spend limits, including acceptance F: a quote over the maximum is refused."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import TestnetFailure
from lineageauth.flop.testnet.spend import (
    TESTNET_VALUE_NOTICE,
    SpendLedger,
    TestnetSpendPolicy,
    format_amount,
    policy_from_mapping,
    to_amount,
)

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)


class TestAmounts:
    def test_a_float_is_refused_rather_than_rounded(self) -> None:
        with pytest.raises(MalformedEventError, match="a float cannot represent"):
            to_amount(0.1)

    def test_a_boolean_is_not_a_number(self) -> None:
        with pytest.raises(MalformedEventError, match="not a boolean"):
            to_amount(True)

    def test_a_string_keeps_its_exact_value(self) -> None:
        assert to_amount("0.1") + to_amount("0.2") == Decimal("0.3")

    def test_a_negative_amount_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="non-negative"):
            to_amount("-1")

    def test_formatting_is_stable_for_hashing(self) -> None:
        assert format_amount(Decimal("2.50")) == "2.5"
        assert format_amount(Decimal("10")) == "10"


class TestDefaults:
    def test_the_defaults_are_conservative_and_always_ask_a_human(self) -> None:
        policy = TestnetSpendPolicy()
        assert policy.per_action_max == Decimal("10")
        assert policy.approval_required_above == Decimal("0")
        assert policy.requires_approval(Decimal("0.000001")) is True

    def test_limits_must_nest(self) -> None:
        with pytest.raises(MalformedEventError, match="must nest"):
            TestnetSpendPolicy(
                per_action_max=Decimal("100"),
                session_max=Decimal("10"),
                daily_max=Decimal("1000"),
            )

    def test_the_rendered_policy_carries_the_value_notice(self) -> None:
        assert TestnetSpendPolicy().to_dict()["notice"] == TESTNET_VALUE_NOTICE


class TestAcceptanceF:
    def test_acceptance_f_a_quote_above_the_approved_maximum_is_refused(self) -> None:
        decision = TestnetSpendPolicy().check(Decimal("9"), approved_max=Decimal("5"))
        assert decision.allowed is False
        assert decision.limit_id == "approved-max"
        assert decision.refusal is not None
        assert decision.refusal.failure is TestnetFailure.SPEND_LIMIT_EXCEEDED
        assert decision.refusal.stage == "spend"

    def test_acceptance_f_the_approved_maximum_is_checked_before_local_policy(self) -> None:
        # Within every local limit, and still refused, because a person said 1.
        decision = TestnetSpendPolicy().check(Decimal("2"), approved_max=Decimal("1"))
        assert decision.limit_id == "approved-max"

    def test_acceptance_f_the_per_action_limit_refuses_on_its_own(self) -> None:
        decision = TestnetSpendPolicy().check(Decimal("11"))
        assert decision.allowed is False
        assert decision.limit_id == "per-action-max"

    def test_acceptance_f_the_session_limit_counts_what_was_already_spent(self) -> None:
        decision = TestnetSpendPolicy().check(Decimal("10"), spent_this_session=Decimal("20"))
        assert decision.allowed is False
        assert decision.limit_id == "session-max"

    def test_acceptance_f_the_daily_limit_counts_what_was_already_spent(self) -> None:
        policy = TestnetSpendPolicy(
            per_action_max=Decimal("10"), session_max=Decimal("50"), daily_max=Decimal("50")
        )
        decision = policy.check(Decimal("10"), spent_today=Decimal("45"))
        assert decision.allowed is False
        assert decision.limit_id == "daily-max"

    def test_a_spend_within_every_limit_is_allowed_and_still_needs_approval(self) -> None:
        decision = TestnetSpendPolicy().check(Decimal("2.5"), approved_max=Decimal("5"))
        assert decision.allowed is True
        assert decision.approval_required is True
        assert TESTNET_VALUE_NOTICE in decision.detail


class TestRaisingLimits:
    def test_raising_a_limit_requires_a_reason(self) -> None:
        with pytest.raises(MalformedEventError, match="stated reason"):
            TestnetSpendPolicy().raised(reason="")

    def test_raising_hands_back_the_audit_record_with_the_policy(self) -> None:
        policy, record = TestnetSpendPolicy().raised(
            reason="a longer evaluation run, watched", per_action_max=Decimal("20")
        )
        assert policy.per_action_max == Decimal("20")
        assert record["kind"] == "spend-policy-raised"
        assert record["before"]["perActionMax"] == "10"
        assert record["after"]["perActionMax"] == "20"


class TestLedger:
    def test_only_observed_amounts_move_it(self) -> None:
        ledger = SpendLedger()
        assert ledger.session_total == Decimal("0")
        ledger.record(Decimal("2.5"), at=AT)
        ledger.record(Decimal("1"), at=AT)
        assert ledger.session_total == Decimal("3.5")
        assert ledger.spent_on(AT.date()) == Decimal("3.5")
        assert ledger.to_dict()["observedOnly"] is True

    def test_a_negative_observation_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="cannot be negative"):
            SpendLedger().record(Decimal("-1"), at=AT)


class TestConfiguration:
    def test_a_policy_can_be_read_from_data(self) -> None:
        policy = policy_from_mapping(
            {"perActionMax": "1", "sessionMax": "2", "dailyMax": "3", "approvalRequiredAbove": "0"}
        )
        assert policy.per_action_max == Decimal("1")
        assert policy.daily_max == Decimal("3")
