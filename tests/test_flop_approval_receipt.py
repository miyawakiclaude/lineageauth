"""Where the approval in the simulation walkthrough comes from, and where it never goes.

Found by driving the console in a browser after the pipeline had finished: the
walkthrough stopped at "Exact-action approval -- refused" because the page holds
no keys and the demo bundle held no receipt for the request it had just built.
The directive (§28) wants the whole flow demonstrable before the network exists,
so the run now takes a receipt from one of three places and says which. None of
them writes to the index.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from lineageauth.api import create_app
from lineageauth.approval import InMemorySpentStore
from lineageauth.builders import sign_payload
from lineageauth.flop.api import FLOP_PREFIX
from lineageauth.flop.model import InferencePurpose
from lineageauth.flop.testnet.prepare import InferenceWorkload
from lineageauth.flop.testnet.simulation import (
    DEMO_RECEIPT_NOTE,
    demo_approval_receipt,
    prepare_simulation,
    run_simulation,
)
from lineageauth.index import EventIndex
from tests.flop_testnet_fixtures import (
    AGENT,
    AT,
    LINEAGE,
    ROOT,
    STRANGER,
    bundle_of,
    genesis,
    grant,
    receipt_for,
    rules,
    snapshot,
)

AT_TEXT = "2026-09-03T12:00:00Z"
PROMPT = "Summarise the LineageAuth approval flow for a reviewer."
WORKLOAD = InferenceWorkload(purpose=InferencePurpose.EVALUATION, prompt=PROMPT)
RUN = f"{FLOP_PREFIX}/testnet/simulation/run"
BODY: dict[str, Any] = {
    "lineage": LINEAGE,
    "did": AGENT.did,
    "prompt": PROMPT,
    "purpose": "evaluation",
    "maxSpend": "5",
    "at": AT_TEXT,
}


def prepared():  # type: ignore[no-untyped-def]
    return prepare_simulation(
        subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules(), workload=WORKLOAD
    )


def signed_by(signer):  # type: ignore[no-untyped-def]
    return lambda payload: sign_payload(payload, [signer])


def envelope_json(envelope) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    return {"payload": envelope.payload, "proofs": [p.model_dump() for p in envelope.proofs]}


def index_without_receipt() -> EventIndex:
    index = EventIndex()
    index.ingest_all([genesis(), grant()])
    return index


class TestTheDemoReceiptInCode:
    def test_a_demo_signed_receipt_lets_the_walkthrough_reach_execution(self) -> None:
        action = prepared()
        receipt = demo_approval_receipt(
            action,
            lineage=LINEAGE,
            agent=AGENT.did,
            approver=ROOT.did,
            at=AT,
            sign=signed_by(ROOT),
        )
        run = run_simulation(
            bundle=bundle_of(genesis(), grant(), receipt),
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT,
            snapshot=snapshot(),
            rules=rules(),
            store=InMemorySpentStore(),
            workload=WORKLOAD,
        )
        assert run.ok is True
        assert run.outcome is not None and run.outcome.ok is True

    def test_the_demo_receipt_is_a_real_receipt_checked_by_the_real_verifier(self) -> None:
        """Signed by a key the grant does not name, it is refused like any other."""
        action = prepared()
        stranger = demo_approval_receipt(
            action,
            lineage=LINEAGE,
            agent=AGENT.did,
            approver=STRANGER.did,
            at=AT,
            sign=signed_by(STRANGER),
        )
        run = run_simulation(
            bundle=bundle_of(genesis(), grant(), stranger),
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT,
            snapshot=snapshot(),
            rules=rules(),
            store=InMemorySpentStore(),
            workload=WORKLOAD,
        )
        assert run.ok is False
        approval = next(step for step in run.steps if step.step_id == "approval")
        assert approval.ok is False

    def test_the_receipt_binds_this_request_and_not_another(self) -> None:
        other = prepare_simulation(
            subject_did=AGENT.did,
            at=AT,
            snapshot=snapshot(),
            rules=rules(),
            workload=InferenceWorkload(purpose=InferencePurpose.EVALUATION, prompt=PROMPT + "!"),
        )
        receipt = demo_approval_receipt(
            other,
            lineage=LINEAGE,
            agent=AGENT.did,
            approver=ROOT.did,
            at=AT,
            sign=signed_by(ROOT),
        )
        run = run_simulation(
            bundle=bundle_of(genesis(), grant(), receipt),
            lineage=LINEAGE,
            agent=AGENT.did,
            at=AT,
            snapshot=snapshot(),
            rules=rules(),
            store=InMemorySpentStore(),
            workload=WORKLOAD,
        )
        assert run.ok is False


class TestTheThreeSourcesOverTheApi:
    def test_without_a_receipt_or_a_demo_signer_the_run_stops_and_says_so(self) -> None:
        client = TestClient(create_app(index_without_receipt()))
        body = client.post(RUN, json=BODY).json()
        assert body["ok"] is False
        assert body["approvalReceipt"]["source"] == "none"
        assert body["approvalReceipt"]["ingested"] is False
        assert "paste a signed approval receipt" in body["approvalReceipt"]["note"]

    def test_a_demo_process_signs_one_and_labels_it(self) -> None:
        index = index_without_receipt()
        before = index.envelopes(lineage=LINEAGE)
        client = TestClient(
            create_app(
                index,
                flop_demo_mode=True,
                flop_demo_approver=ROOT.did,
                flop_demo_sign_receipt=signed_by(ROOT),
            )
        )
        body = client.post(RUN, json=BODY).json()
        assert body["ok"] is True
        assert body["approvalReceipt"] == {
            "source": "demo-approver",
            "approver": ROOT.did,
            "synthetic": True,
            "ingested": False,
            "note": DEMO_RECEIPT_NOTE,
        }
        # Never indexed: the console ingests nothing over HTTP.
        assert index.envelopes(lineage=LINEAGE) == before

    def test_the_demo_signer_is_ignored_outside_demo_mode(self) -> None:
        """A production mount handed a signer by mistake still holds nothing that signs."""
        client = TestClient(
            create_app(
                index_without_receipt(),
                flop_demo_mode=False,
                flop_demo_approver=ROOT.did,
                flop_demo_sign_receipt=signed_by(ROOT),
            )
        )
        body = client.post(RUN, json=BODY).json()
        assert body["ok"] is False
        assert body["approvalReceipt"]["source"] == "none"

    def test_a_pasted_receipt_is_verified_used_once_and_not_indexed(self) -> None:
        index = index_without_receipt()
        before = index.envelopes(lineage=LINEAGE)
        client = TestClient(create_app(index))
        receipt = receipt_for(prepared().action_request())
        body = client.post(RUN, json=BODY | {"approvalReceipt": envelope_json(receipt)}).json()
        assert body["ok"] is True
        assert body["approvalReceipt"]["source"] == "pasted"
        assert body["approvalReceipt"]["approver"] == ROOT.did
        assert body["approvalReceipt"]["synthetic"] is False
        assert index.envelopes(lineage=LINEAGE) == before
        assert client.get("/v1/meta").json()["indexedEvents"] == len(before)

    def test_a_pasted_receipt_from_an_undesignated_key_is_refused(self) -> None:
        client = TestClient(create_app(index_without_receipt()))
        forged = receipt_for(prepared().action_request(), approver=STRANGER)
        body = client.post(RUN, json=BODY | {"approvalReceipt": envelope_json(forged)}).json()
        assert body["ok"] is False
        approval = next(step for step in body["steps"] if step["id"] == "approval")
        assert approval["ok"] is False

    @pytest.mark.parametrize("junk", [{"nope": 1}, {"payload": "x", "proofs": []}, 7])
    def test_something_that_is_not_an_envelope_is_a_400(self, junk: Any) -> None:
        client = TestClient(create_app(index_without_receipt()))
        response = client.post(RUN, json=BODY | {"approvalReceipt": junk})
        assert response.status_code in (400, 422)

    def test_the_cap_the_page_sends_is_the_cap_the_receipt_binds(self) -> None:
        """maxSpend reaches the run; a receipt for the default cap does not fit a raised one."""
        client = TestClient(create_app(index_without_receipt()))
        receipt = receipt_for(prepared().action_request())  # bound to the default cap of 5
        body = client.post(
            RUN, json=BODY | {"maxSpend": "7", "approvalReceipt": envelope_json(receipt)}
        ).json()
        assert body["ok"] is False


class TestThePage:
    def test_the_inference_form_offers_a_place_to_paste_a_receipt(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1] / "apps" / "flop"
        html = (root / "index.html").read_text(encoding="utf-8")
        js = (root / "app.js").read_text(encoding="utf-8")
        assert 'id="inference-receipt"' in html
        assert "approvalReceipt" in js
        assert "JSON.parse(pasted)" in js


class TestTheLayerHoldsAFunctionNotAKey:
    def test_the_flop_layer_still_imports_no_key_holding_signer(self) -> None:
        """The demo path is a callback the key's owner supplies; the guard test stays green."""
        import ast
        from pathlib import Path

        package = Path(__file__).resolve().parents[1] / "packages" / "py" / "lineageauth" / "flop"
        for path in package.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    assert node.module != "lineageauth.crypto", path
                    assert "LocalSigner" not in {a.name for a in node.names}, path
