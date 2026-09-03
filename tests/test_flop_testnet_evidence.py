"""Receipts and evidence, including acceptances L and M.

L: a response with no network receipt is partially verified, never fully.
M: a simulated spend is marked synthetic wherever it is recorded.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from lineageauth import catalog
from lineageauth.flop.model import SIMULATION_BANNER, SYNTHETIC_BANNER, VerificationState
from lineageauth.flop.testnet.evidence import (
    DOES_NOT_PROVE,
    INFERENCE_PREDICATE,
    PROVES,
    SYNTHETIC_REASON_CODE,
    draft_evidence,
    inference_summary,
)
from lineageauth.flop.testnet.receipts import (
    NOT_PROOF_NOTE,
    SELF_REPORTED_REASON,
    FlopTestnetExecutionReceipt,
    receipt_from_response,
    render_receipt,
)
from tests.flop_testnet_fixtures import AGENT, AT, LINEAGE

REQUEST_HASH = "sha256:" + "1" * 64
RESPONSE_HASH = "sha256:" + "2" * 64

LATER = datetime(2026, 9, 3, 12, 0, 5, tzinfo=UTC)


def receipt_for(
    payload: dict[str, object], *, synthetic: bool = False
) -> FlopTestnetExecutionReceipt:
    return receipt_from_response(
        payload,
        action_id="flop-abc",
        subject_did=AGENT.did,
        network="flop-simulation-local",
        action_type="inference",
        endpoint_id="simulation-inference",
        request_hash=REQUEST_HASH,
        response_hash=RESPONSE_HASH,
        started_at=AT,
        completed_at=LATER,
        source_snapshot_id="sha256:" + "3" * 64,
        quote_amount=Decimal("2.5"),
        model="simulated-model-a",
        synthetic=synthetic,
        simulation=synthetic,
    )


COMPLETE = {
    "receiptRef": "sim-receipt-0001",
    "observedSpend": "2.5",
    "result": "a synthetic answer",
    "miner": "simulated-miner",
}


class TestAcceptanceL:
    def test_acceptance_l_a_response_without_a_receipt_reference_is_partially_verified(
        self,
    ) -> None:
        receipt = receipt_for({"observedSpend": "2.5", "result": "an answer"})
        assert receipt.verification_state is VerificationState.PARTIALLY_VERIFIED
        assert receipt.fully_verified is False
        assert any("no network receipt reference" in why for why in receipt.unverified_because)

    def test_acceptance_l_a_response_without_a_spend_is_partially_verified(self) -> None:
        receipt = receipt_for({"receiptRef": "r1", "result": "an answer"})
        assert receipt.verification_state is VerificationState.PARTIALLY_VERIFIED
        assert receipt.observed_spend is None

    def test_acceptance_l_a_response_without_a_result_is_partially_verified(self) -> None:
        receipt = receipt_for({"receiptRef": "r1", "observedSpend": "2.5"})
        assert receipt.verification_state is VerificationState.PARTIALLY_VERIFIED
        assert receipt.result_available is False

    def test_acceptance_l_even_a_complete_response_stops_at_partially_verified(self) -> None:
        """Acceptance test L, at its limit: nothing a counterparty says is `verified`.

        A complete response fills in every field, and every one of those fields
        is the endpoint describing its own behaviour -- `observedSpend` included,
        which is the party being billed against stating what it charged. This
        codebase reserves `verified` for a check against somebody other than the
        party being checked, which is why `PublicEvidenceAdapter` will not say it
        for a URL it did not re-fetch. A receipt gets the same rule.
        """
        receipt = receipt_for(COMPLETE)
        assert receipt.verification_state is VerificationState.PARTIALLY_VERIFIED
        assert receipt.fully_verified is False
        assert receipt.unverified_because == (SELF_REPORTED_REASON,)

    def test_acceptance_l_an_empty_response_is_partially_verified_with_every_reason(self) -> None:
        receipt = receipt_for({})
        assert receipt.verification_state is VerificationState.PARTIALLY_VERIFIED
        # Three missing fields, plus the reason that holds even when none are.
        assert len(receipt.unverified_because) == 4
        assert receipt.unverified_because[-1] == SELF_REPORTED_REASON

    def test_acceptance_l_no_response_at_all_can_produce_a_verified_receipt(self) -> None:
        """The property, rather than an example: there is no payload that verifies."""
        payloads = (
            COMPLETE,
            {"receiptRef": "r1", "observedSpend": "2.5"},
            {"receiptRef": "r1", "result": "an answer", "observedSpend": "0"},
            {"verificationState": "verified", **COMPLETE},
        )
        for payload in payloads:
            assert receipt_for(payload).verification_state is not VerificationState.VERIFIED

    def test_acceptance_l_the_rendered_receipt_lists_what_was_not_verified(self) -> None:
        rendered = render_receipt(receipt_for({"observedSpend": "2.5"}))
        rendered.encode("ascii")
        assert "Not verified:" in rendered
        assert NOT_PROOF_NOTE in rendered


class TestAcceptanceM:
    def test_acceptance_m_a_simulated_receipt_carries_both_banners(self) -> None:
        body = receipt_for(COMPLETE, synthetic=True).to_dict()
        assert body["synthetic"] is True
        assert body["simulation"] is True
        assert body["banner"] == SYNTHETIC_BANNER
        assert body["simulationBanner"] == SIMULATION_BANNER

    def test_acceptance_m_the_evidence_wrapper_repeats_the_markers(self) -> None:
        draft = draft_evidence(
            receipt_for(COMPLETE, synthetic=True),
            lineage=LINEAGE,
            issuer=AGENT.did,
            issued_at=LATER,
        )
        body = draft.to_dict()
        assert body["synthetic"] is True
        assert body["banner"] == SYNTHETIC_BANNER
        assert body["simulationBanner"] == SIMULATION_BANNER

    def test_acceptance_m_the_marker_survives_into_the_signed_attestation(self) -> None:
        draft = draft_evidence(
            receipt_for(COMPLETE, synthetic=True),
            lineage=LINEAGE,
            issuer=AGENT.did,
            issued_at=LATER,
        )
        assert draft.attestation["reasonCode"] == SYNTHETIC_REASON_CODE

    def test_acceptance_m_a_non_synthetic_receipt_carries_no_synthetic_reason_code(self) -> None:
        draft = draft_evidence(
            receipt_for(COMPLETE), lineage=LINEAGE, issuer=AGENT.did, issued_at=LATER
        )
        assert "reasonCode" not in draft.attestation

    def test_acceptance_m_a_simulated_spend_is_never_reported_as_real(self) -> None:
        summary = inference_summary((receipt_for(COMPLETE, synthetic=True),))
        assert summary["containsSynthetic"] is True
        assert summary["isAirdropScore"] is False


class TestEvidenceShape:
    def test_the_predicate_is_not_registered(self) -> None:
        assert INFERENCE_PREDICATE == "flop.testnet.inference"
        assert INFERENCE_PREDICATE not in getattr(catalog, "KNOWN_PREDICATES", frozenset())

    def test_two_artifacts_are_drafted_when_there_is_an_answer(self) -> None:
        draft = draft_evidence(
            receipt_for(COMPLETE), lineage=LINEAGE, issuer=AGENT.did, issued_at=LATER
        )
        assert [payload["type"] for payload in draft.artifacts] == [
            "artifact.register",
            "artifact.register",
        ]
        assert draft.artifacts[0]["artifactId"] == REQUEST_HASH
        assert draft.artifacts[1]["artifactId"] == RESPONSE_HASH

    def test_the_response_artifact_does_not_claim_an_author(self) -> None:
        draft = draft_evidence(
            receipt_for(COMPLETE), lineage=LINEAGE, issuer=AGENT.did, issued_at=LATER
        )
        assert "createdBy" not in draft.artifacts[1]
        assert draft.artifacts[0]["createdBy"] == AGENT.did

    def test_the_attestation_states_the_verification_level_rather_than_success(self) -> None:
        partial = draft_evidence(
            receipt_for({"observedSpend": "2.5"}),
            lineage=LINEAGE,
            issuer=AGENT.did,
            issued_at=LATER,
        )
        assert partial.attestation["value"] == "partially-verified"

    def test_the_draft_says_what_it_does_not_prove(self) -> None:
        body = draft_evidence(
            receipt_for(COMPLETE), lineage=LINEAGE, issuer=AGENT.did, issued_at=LATER
        ).to_dict()
        assert body["proves"] == list(PROVES)
        assert body["doesNotProve"] == list(DOES_NOT_PROVE)
        assert any("was actually performed" in line for line in body["doesNotProve"])


class TestSummary:
    def test_no_receipts_reports_no_spend_rather_than_zero(self) -> None:
        summary = inference_summary(())
        assert summary["observedRequests"] == 0
        assert summary["observedSpend"] is None
        assert summary["lastActivity"] is None

    def test_spend_is_summed_from_observations_only(self) -> None:
        summary = inference_summary((receipt_for(COMPLETE), receipt_for({"receiptRef": "r"})))
        assert summary["observedSpend"] == "2.5"
        assert summary["observedRequests"] == 2
        # No receipt read off a response is fully verified, so the count of
        # evidence-supported executions is zero however complete the answers were.
        assert summary["evidenceSupported"] == 0
