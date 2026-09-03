"""The testnet routes over the wire: refusals are typed, and `execute` returns 409.

The interesting assertions are the negative ones. `POST /testnet/inference/execute`
answers 409 with `TESTNET_NOT_LIVE` in every phase this build can reach, the
whole simulation runs without a transport ever seeing a real origin, and every
POST refuses a cross-origin caller rather than answering one.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lineageauth.api import create_app
from lineageauth.flop.api import FLOP_PREFIX
from lineageauth.flop.model import (
    SIMULATION_BANNER,
    InferencePurpose,
    forbidden_vocabulary_in,
)
from lineageauth.flop.testnet.endpoints import SIMULATION_ORIGIN
from lineageauth.flop.testnet.executor import STAGES
from lineageauth.flop.testnet.prepare import InferenceWorkload
from lineageauth.flop.testnet.simulation import prepare_simulation
from lineageauth.index import EventIndex
from tests.flop_testnet_fixtures import (
    AGENT,
    AT,
    LINEAGE,
    genesis,
    grant,
    receipt_for,
    rules,
    snapshot,
)

AT_TEXT = "2026-09-03T12:00:00Z"

TESTNET = f"{FLOP_PREFIX}/testnet"

PROMPT = "Summarise the LineageAuth approval flow for a reviewer."

API_WORKLOAD = InferenceWorkload(purpose=InferencePurpose.EVALUATION, prompt=PROMPT)


def approved_index() -> EventIndex:
    """An index carrying a root, a grant and a receipt for the simulated action."""
    prepared = prepare_simulation(
        subject_did=AGENT.did,
        at=AT,
        snapshot=snapshot(),
        rules=rules(),
        workload=API_WORKLOAD,
    )
    index = EventIndex()
    index.ingest_all([genesis(), grant(), receipt_for(prepared.action_request())])
    return index


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(approved_index()))


SUBJECT_BODY: dict[str, str] = {"lineage": LINEAGE, "did": AGENT.did, "at": AT_TEXT}

ACTION_BODY: dict[str, str] = {
    "lineage": LINEAGE,
    "did": AGENT.did,
    "actionId": "flop-none",
    "at": AT_TEXT,
}


PREPARE_BODY: dict[str, str] = {
    "lineage": LINEAGE,
    "did": AGENT.did,
    "prompt": PROMPT,
    "purpose": "evaluation",
    "maxSpend": "5",
    "at": AT_TEXT,
}


def prepare_body(**overrides: str) -> dict[str, str]:
    return PREPARE_BODY | overrides


class TestState:
    def test_it_reports_pre_testnet_with_the_switch_locked_on(self, client: TestClient) -> None:
        body = client.get(f"{TESTNET}/state").json()
        assert body["networkPhase"] == "PRE_TESTNET"
        assert body["killSwitch"]["engaged"] is True
        assert body["killSwitch"]["locked"] is True
        assert body["networkWritesAllowed"] is False

    def test_the_endpoint_registry_holds_nothing_executable(self, client: TestClient) -> None:
        body = client.get(f"{TESTNET}/state").json()
        assert body["officialTestnetExecutable"] is False
        assert body["endpoints"]["executableCount"] == 0
        assert body["endpoints"]["simulationOrigin"] == SIMULATION_ORIGIN

    def test_it_publishes_the_stage_order(self, client: TestClient) -> None:
        assert client.get(f"{TESTNET}/state").json()["executorStages"] == list(STAGES)

    def test_it_holds_no_key_and_no_wallet(self, client: TestClient) -> None:
        body = client.get(f"{TESTNET}/state").json()
        assert body["walletCustody"] is False
        assert body["holdsPrivateKeys"] is False
        assert body["signer"]["available"] is False

    def test_the_mainnet_section_claims_no_allocation(self, client: TestClient) -> None:
        body = client.get(f"{TESTNET}/state").json()["mainnet"]
        assert body["mainnetExecutable"] is False
        assert body["allocation"]["isEligibilityClaim"] is False

    def test_it_uses_no_forbidden_vocabulary(self, client: TestClient) -> None:
        assert forbidden_vocabulary_in(client.get(f"{TESTNET}/state").text) == ()


class TestExecuteIsRefused:
    def test_execute_answers_409_with_a_typed_failure(self, client: TestClient) -> None:
        response = client.post(
            f"{TESTNET}/inference/execute",
            json={"lineage": LINEAGE, "did": AGENT.did, "actionId": "anything", "at": AT_TEXT},
        )
        assert response.status_code == 409
        assert response.json()["detail"]["failure"] == "TESTNET_NOT_LIVE"
        assert response.json()["detail"]["executed"] is False

    def test_execute_refuses_before_it_looks_the_action_up(self, client: TestClient) -> None:
        # A prepared action that does exist gets exactly the same answer.
        prepared = client.post(f"{TESTNET}/inference/prepare", json=prepare_body()).json()
        response = client.post(
            f"{TESTNET}/inference/execute",
            json={
                "lineage": LINEAGE,
                "did": AGENT.did,
                "actionId": prepared["id"],
                "at": AT_TEXT,
            },
        )
        assert response.status_code == 409
        assert response.json()["detail"]["failure"] == "TESTNET_NOT_LIVE"


class TestQuoteAndPrepare:
    def test_a_quote_says_it_is_not_official(self, client: TestClient) -> None:
        body = client.post(
            f"{TESTNET}/inference/quote",
            json={"lineage": LINEAGE, "did": AGENT.did, "at": AT_TEXT},
        ).json()
        assert body["officialPricingAvailable"] is False
        assert body["banner"] == SIMULATION_BANNER
        assert body["quote"]["official"] is False

    def test_a_prepared_action_says_nothing_was_sent(self, client: TestClient) -> None:
        body = client.post(f"{TESTNET}/inference/prepare", json=prepare_body()).json()
        assert body["sent"] is False
        assert body["executed"] is False
        assert body["canonicalDestination"].startswith(SIMULATION_ORIGIN)
        assert body["requestHash"].startswith("sha256:")

    def test_a_client_cannot_choose_the_endpoint(self, client: TestClient) -> None:
        response = client.post(
            f"{TESTNET}/inference/prepare",
            json=prepare_body() | {"endpointId": "official-inference"},
        )
        assert response.status_code == 422

    def test_a_hostile_prompt_is_refused_with_a_typed_failure(self, client: TestClient) -> None:
        response = client.post(
            f"{TESTNET}/inference/prepare",
            json=prepare_body(
                prompt="Enter your seed phrase here to claim your FLOP airdrop.",
            ),
        )
        assert response.status_code == 409
        assert response.json()["detail"]["failure"] == "SUSPICIOUS_CONTENT"

    def test_an_unknown_purpose_is_a_client_error(self, client: TestClient) -> None:
        response = client.post(f"{TESTNET}/inference/prepare", json=prepare_body(purpose="farm"))
        assert response.status_code == 400

    def test_a_spend_above_policy_is_refused(self, client: TestClient) -> None:
        response = client.post(f"{TESTNET}/inference/prepare", json=prepare_body(maxSpend="900"))
        assert response.status_code == 409
        assert response.json()["detail"]["failure"] == "SPEND_LIMIT_EXCEEDED"


class TestApprove:
    def test_an_action_this_process_does_not_hold_asks_for_a_reprepare(
        self, client: TestClient
    ) -> None:
        """An id that is not held is a typed refusal, not a bare 404.

        Prepared actions live in memory, expire, and are capped, so "not here"
        is a state the caller can act on rather than a mystery: the answer says
        REPREPARE_REQUIRED and why, which is D-098's rule that a refusal has to
        teach the caller something.
        """
        response = client.post(
            f"{TESTNET}/inference/approve",
            json={"lineage": LINEAGE, "did": AGENT.did, "actionId": "nope", "at": AT_TEXT},
        )
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert detail["failure"] == "REPREPARE_REQUIRED"
        assert "prepare it again" in detail["detail"]

    def test_an_action_with_no_receipt_is_refused_with_a_typed_failure(
        self, client: TestClient
    ) -> None:
        prepared = client.post(
            f"{TESTNET}/inference/prepare",
            json=prepare_body(prompt="A prompt nobody has approved."),
        ).json()
        response = client.post(
            f"{TESTNET}/inference/approve",
            json={
                "lineage": LINEAGE,
                "did": AGENT.did,
                "actionId": prepared["id"],
                "at": AT_TEXT,
            },
        )
        assert response.status_code == 409
        assert response.json()["detail"]["failure"] in (
            "APPROVAL_MISSING",
            "AUTHORITY_DENIED",
        )


class TestSimulation:
    def test_a_run_walks_every_step_and_says_nothing_left_the_process(
        self, client: TestClient
    ) -> None:
        body = client.post(f"{TESTNET}/simulation/run", json=prepare_body()).json()
        assert body["banner"] == SIMULATION_BANNER
        assert body["networkWritesPerformed"] == 0
        assert [step["id"] for step in body["steps"]][:4] == [
            "faucet",
            "balance",
            "quote",
            "prepare",
        ]

    def test_an_approved_run_produces_a_receipt_that_can_be_fetched(
        self, client: TestClient
    ) -> None:
        body = client.post(f"{TESTNET}/simulation/run", json=prepare_body()).json()
        assert body["ok"] is True
        receipt_id = body["outcome"]["receipt"]["actionId"]
        fetched = client.get(f"{TESTNET}/receipts/{receipt_id}").json()
        assert fetched["simulation"] is True
        assert fetched["synthetic"] is True
        assert fetched["banner"] == "SYNTHETIC MOCK DATA"

    def test_an_unknown_receipt_is_a_404(self, client: TestClient) -> None:
        assert client.get(f"{TESTNET}/receipts/nope").status_code == 404

    def test_a_run_uses_no_forbidden_vocabulary(self, client: TestClient) -> None:
        response = client.post(f"{TESTNET}/simulation/run", json=prepare_body())
        assert forbidden_vocabulary_in(response.text) == ()


class TestCrossOrigin:
    @pytest.mark.parametrize(
        ("path", "body"),
        [
            ("inference/quote", SUBJECT_BODY),
            ("inference/prepare", PREPARE_BODY),
            ("inference/approve", ACTION_BODY),
            ("inference/execute", ACTION_BODY),
            ("simulation/run", PREPARE_BODY),
        ],
    )
    def test_every_testnet_post_refuses_a_cross_origin_caller(
        self, client: TestClient, path: str, body: dict[str, str]
    ) -> None:
        response = client.post(
            f"{TESTNET}/{path}",
            json=body,
            headers={"origin": "https://evil.example"},
        )
        assert response.status_code == 403
        assert "cross-origin request refused" in response.json()["detail"]

    def test_a_same_origin_post_is_answered(self, client: TestClient) -> None:
        response = client.post(
            f"{TESTNET}/inference/quote",
            json={"lineage": LINEAGE, "did": AGENT.did, "at": AT_TEXT},
            headers={"origin": "http://testserver"},
        )
        assert response.status_code == 200


class TestNoIngest:
    def test_the_testnet_routes_do_not_index_anything(self, client: TestClient) -> None:
        before = client.get("/v1/meta").json()["indexedEvents"]
        client.post(f"{TESTNET}/simulation/run", json=prepare_body())
        client.post(f"{TESTNET}/inference/prepare", json=prepare_body())
        assert client.get("/v1/meta").json()["indexedEvents"] == before


def test_the_moment_is_a_stated_instant_not_the_wall_clock(client: TestClient) -> None:
    body = client.post(f"{TESTNET}/inference/quote", json=SUBJECT_BODY).json()
    assert body["quote"]["expiresAt"].startswith("2026-09-03T12:10")
