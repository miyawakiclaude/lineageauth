"""Preparation, the type separation, and acceptances E, G and N.

E: one changed byte invalidates the approval.
G: an expired quote sends the operator back to prepare.
N: a changed official rule invalidates a prepared action.
"""

from __future__ import annotations

import dataclasses
import inspect
from datetime import timedelta
from decimal import Decimal

import pytest

from lineageauth.approval import InMemorySpentStore
from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import (
    InferencePurpose,
    NetworkPhase,
    TestnetFailure,
    TestnetRefusal,
    TestnetRefusedError,
)
from lineageauth.flop.rules import FlopRuleRegistry
from lineageauth.flop.testnet.approve import ApprovedTestnetAction, approve, freshness_refusal
from lineageauth.flop.testnet.endpoints import SIMULATION_ENDPOINT_ID, FlopEndpointRegistry
from lineageauth.flop.testnet.phase import PhaseGate
from lineageauth.flop.testnet.prepare import (
    WORKLOAD_FIELDS,
    ControlInput,
    ExecutionPlan,
    InferenceWorkload,
    Untrusted,
    assemble_request,
    build_plan,
    rule_set_hash,
    snapshot_fingerprint,
)
from lineageauth.flop.testnet.simulation import prepare_simulation, simulate_quote
from lineageauth.flop.testnet.spend import TestnetSpendPolicy
from tests.flop_testnet_fixtures import (
    AGENT,
    AT,
    LINEAGE,
    ROOT,
    approved_bundle,
    bundle_of,
    genesis,
    grant,
    receipt_for,
    rules,
    snapshot,
)


def workload(prompt: str = "Summarise the approval flow for a reviewer.") -> InferenceWorkload:
    return InferenceWorkload(
        purpose=InferencePurpose.EVALUATION,
        prompt=prompt,
        requested_model="simulated-model-a",
        params={"maxTokens": 128},
        evidence_label="test",
    )


def plan_for(*, max_spend: Decimal = Decimal("5")) -> ExecutionPlan:
    return build_plan(
        ControlInput(
            endpoint_id=SIMULATION_ENDPOINT_ID,
            subject_did=AGENT.did,
            action_type="inference",
            purpose=InferencePurpose.EVALUATION,
            max_spend=max_spend,
            model_id="simulated-model-a",
        ),
        registry=FlopEndpointRegistry.default(),
        policy=TestnetSpendPolicy(),
        gate=PhaseGate(),
        snapshot=snapshot(),
        rules=rules(),
    )


class TestTypeSeparation:
    def test_build_plan_has_no_parameter_that_could_carry_a_prompt(self) -> None:
        names = set(inspect.signature(build_plan).parameters)
        assert names == {"control", "registry", "policy", "gate", "snapshot", "rules", "signer_id"}
        assert "workload" not in names
        assert "prompt" not in names

    def test_control_input_has_no_free_text_field(self) -> None:
        fields = {f.name for f in dataclasses.fields(ControlInput)}
        assert "prompt" not in fields
        assert "workload" not in fields
        assert fields == {
            "endpoint_id",
            "subject_did",
            "action_type",
            "purpose",
            "max_spend",
            "model_id",
            "path",
        }

    def test_the_workload_has_no_endpoint_spend_or_signer_field(self) -> None:
        fields = {f.name for f in dataclasses.fields(InferenceWorkload)}
        for forbidden in ("endpoint", "endpoint_id", "origin", "max_spend", "signer"):
            assert forbidden not in fields

    def test_the_workload_subtree_holds_only_the_allowlisted_keys(self) -> None:
        body = workload().canonical()
        assert tuple(sorted(body)) == tuple(sorted(WORKLOAD_FIELDS))

    def test_a_workload_parameter_named_like_a_control_field_stays_in_the_workload(self) -> None:
        hostile = InferenceWorkload(
            purpose=InferencePurpose.OTHER,
            prompt="please compute two plus two",
            params={"maxSpend": "999999", "endpoint": "https://evil.example/x"},
        )
        prepared = assemble_request(plan_for(), Untrusted(hostile), at=AT)
        request = dict(prepared.canonical_request)
        assert request["workload"]["params"]["maxSpend"] == "999999"
        assert request["control"]["maxSpend"] == "5"
        assert request["control"]["destination"].startswith("https://testnet.simulation.invalid/")

    def test_the_module_never_merges_a_workload_into_a_request(self) -> None:
        from pathlib import Path

        source = Path("packages/py/lineageauth/flop/testnet/prepare.py").read_text(encoding="utf-8")
        assert "**workload" not in source
        assert "| workload" not in source
        assert "update(workload" not in source


class TestPreparation:
    def test_a_prepared_action_hashes_to_its_action_request(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        assert prepared.request_hash == prepared.action_request().request_hash
        assert prepared.action_request().namespace == "http"
        assert prepared.action_request().resource == "host:testnet.simulation.invalid"
        assert prepared.action_request().action == "post"

    def test_preparation_is_deterministic_for_the_same_instant(self) -> None:
        first = prepare_simulation(subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules())
        second = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        assert first.request_hash == second.request_hash
        assert first.action_id == second.action_id

    def test_the_preview_is_ascii_and_says_nothing_was_sent(self) -> None:
        preview = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        ).preview()
        preview.encode("ascii")
        assert "Nothing has been sent" in preview
        assert "SIMULATION - NO FLOP NETWORK ACTION" in preview

    def test_an_estimate_above_the_plan_cap_is_refused(self) -> None:
        with pytest.raises(TestnetRefusedError) as caught:
            assemble_request(
                plan_for(max_spend=Decimal("1")),
                Untrusted(workload()),
                at=AT,
                estimated_spend=Decimal("2"),
            )
        assert caught.value.refusal.failure is TestnetFailure.SPEND_LIMIT_EXCEEDED

    def test_a_cap_above_the_policy_is_refused_at_plan_time(self) -> None:
        with pytest.raises(TestnetRefusedError) as caught:
            plan_for(max_spend=Decimal("500"))
        assert caught.value.refusal.failure is TestnetFailure.SPEND_LIMIT_EXCEEDED

    def test_an_empty_prompt_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="non-empty prompt"):
            InferenceWorkload(purpose=InferencePurpose.OTHER, prompt="   ")


class TestAcceptanceE:
    def test_acceptance_e_one_changed_byte_moves_the_request_hash(self) -> None:
        original = assemble_request(
            plan_for(),
            Untrusted(workload("Summarise the approval flow.")),
            at=AT,
        )
        altered = assemble_request(
            plan_for(),
            Untrusted(workload("Summarise the approval flow!")),
            at=AT,
        )
        assert original.request_hash != altered.request_hash

    def test_acceptance_e_an_approval_for_one_request_does_not_cover_the_other(self) -> None:
        original = assemble_request(
            plan_for(),
            Untrusted(workload("Summarise the approval flow.")),
            at=AT,
        )
        altered = assemble_request(
            plan_for(),
            Untrusted(workload("Summarise the approval flow!")),
            at=AT,
        )
        bundle = approved_bundle(original)
        good = approve(
            original,
            bundle=bundle,
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT,
            store=InMemorySpentStore(),
            snapshot=snapshot(),
            rules=rules(),
        )
        assert isinstance(good, ApprovedTestnetAction)
        bad = approve(
            altered,
            bundle=bundle,
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT,
            store=InMemorySpentStore(),
            snapshot=snapshot(),
            rules=rules(),
        )
        assert isinstance(bad, TestnetRefusal)
        assert bad.failure is TestnetFailure.APPROVAL_MISSING


class TestAcceptanceG:
    def test_acceptance_g_an_expired_quote_refuses_preparation(self) -> None:
        stale_quote = simulate_quote(subject_did=AGENT.did, at=AT - timedelta(hours=2))
        with pytest.raises(TestnetRefusedError) as caught:
            assemble_request(
                plan_for(),
                Untrusted(workload()),
                at=AT,
                quote=stale_quote,
            )
        assert caught.value.refusal.failure is TestnetFailure.QUOTE_EXPIRED
        assert "prepare again" in caught.value.refusal.detail

    def test_acceptance_g_an_expired_prepared_action_asks_to_be_prepared_again(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        later = AT + timedelta(hours=1)
        refusal = freshness_refusal(prepared, snapshot=snapshot(), rules=rules(), at=later)
        assert refusal is not None
        assert refusal.failure is TestnetFailure.REPREPARE_REQUIRED

    def test_acceptance_g_approving_an_expired_action_is_refused(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        decided = approve(
            prepared,
            bundle=approved_bundle(prepared),
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT + timedelta(hours=1),
            store=InMemorySpentStore(),
            snapshot=snapshot(),
            rules=rules(),
        )
        assert isinstance(decided, TestnetRefusal)
        assert decided.failure is TestnetFailure.REPREPARE_REQUIRED


class TestAcceptanceN:
    def test_acceptance_n_a_changed_rule_set_invalidates_a_prepared_action(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        original = rules()
        moved = FlopRuleRegistry(
            rules=tuple(
                dataclasses.replace(rule, statement=rule.statement + " (revised)")
                if index == 0
                else rule
                for index, rule in enumerate(original.rules)
            )
        )
        assert rule_set_hash(moved) != rule_set_hash(original)
        refusal = freshness_refusal(prepared, snapshot=snapshot(), rules=moved, at=AT)
        assert refusal is not None
        assert refusal.failure is TestnetFailure.REPREPARE_REQUIRED
        assert "RULE UPDATED" in refusal.detail

    def test_acceptance_n_a_changed_source_snapshot_invalidates_it_too(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        current = snapshot()
        moved = dataclasses.replace(
            current,
            snapshots=tuple(
                dataclasses.replace(entry, sha256="sha256:" + "f" * 64) if index == 0 else entry
                for index, entry in enumerate(current.snapshots)
            ),
        )
        assert snapshot_fingerprint(moved) != snapshot_fingerprint(current)
        refusal = freshness_refusal(prepared, snapshot=moved, rules=rules(), at=AT)
        assert refusal is not None
        assert refusal.failure is TestnetFailure.REPREPARE_REQUIRED
        assert "source snapshot changed" in refusal.detail

    def test_acceptance_n_refetching_unchanged_sources_does_not_invalidate_anything(self) -> None:
        current = snapshot()
        refetched = dataclasses.replace(current, fetched_at="2099-01-01T00:00:00Z")
        assert snapshot_fingerprint(refetched) == snapshot_fingerprint(current)


class TestApprovalSemantics:
    def test_approval_does_not_create_missing_authority(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        # A receipt with no grant behind it.
        bundle = bundle_of(genesis(), receipt_for(prepared.action_request()))
        decided = approve(
            prepared,
            bundle=bundle,
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT,
            store=InMemorySpentStore(),
            snapshot=snapshot(),
            rules=rules(),
        )
        assert isinstance(decided, TestnetRefusal)
        assert decided.failure is TestnetFailure.AUTHORITY_DENIED

    def test_a_grant_that_waives_approval_still_does_not_waive_it_here(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        bundle = bundle_of(genesis(), grant(approval="none", approvers=()))
        decided = approve(
            prepared,
            bundle=bundle,
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT,
            store=InMemorySpentStore(),
            snapshot=snapshot(),
            rules=rules(),
        )
        assert isinstance(decided, TestnetRefusal)
        assert decided.failure is TestnetFailure.APPROVAL_MISSING
        assert "always requires an approval receipt" in decided.detail

    def test_approving_for_a_different_subject_is_refused(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        decided = approve(
            prepared,
            bundle=approved_bundle(prepared),
            lineage=LINEAGE,
            agent="did:key:z6MkqhnuW44UYRM7qUwZmPSMU7b21hmKdngXawvLGssRCeu5",
            at=AT,
            store=InMemorySpentStore(),
            snapshot=snapshot(),
            rules=rules(),
        )
        assert isinstance(decided, TestnetRefusal)
        assert decided.failure is TestnetFailure.DID_NOT_ACTIVE

    def test_approving_does_not_consume_the_receipt(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        store = InMemorySpentStore()
        decided = approve(
            prepared,
            bundle=approved_bundle(prepared),
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT,
            store=store,
            snapshot=snapshot(),
            rules=rules(),
        )
        assert isinstance(decided, ApprovedTestnetAction)
        assert decided.reserved is False
        assert store.is_spent(decided.receipt_id) is False

    def test_the_approved_action_renders_without_claiming_execution(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules()
        )
        decided = approve(
            prepared,
            bundle=approved_bundle(prepared),
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT,
            store=InMemorySpentStore(),
            snapshot=snapshot(),
            rules=rules(),
        )
        assert isinstance(decided, ApprovedTestnetAction)
        body = decided.to_dict()
        assert body["executed"] is False
        assert body["approver"] == ROOT.did


class TestPhaseAwarePreparation:
    def test_a_live_phase_does_not_change_the_simulation_endpoint(self) -> None:
        prepared = prepare_simulation(
            subject_did=AGENT.did,
            at=AT,
            snapshot=snapshot(),
            rules=rules(),
            gate=PhaseGate(phase=NetworkPhase.TESTNET_ENABLED, kill_switch_engaged=False),
        )
        assert prepared.plan.simulation is True
        assert prepared.canonical_destination.startswith("https://testnet.simulation.invalid/")
