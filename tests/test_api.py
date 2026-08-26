"""The read-and-verify HTTP API.

The endpoints are from docs/16. What these tests are really defending is the
boundary around them: the service can help you find a signed object, and it can
never make one authoritative. So the interesting assertions are about what it
refuses to do -- accept an event, hold a key, or answer differently from the
library it wraps.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from lineageauth.api import SECURITY_HEADERS, create_app
from lineageauth.builders import (
    build_delegation_grant,
    build_delegation_revoke,
    build_root_create,
    sign_payload,
)
from lineageauth.envelope import Envelope
from lineageauth.index import EventIndex
from tests.testkeys import AGENT_1, OUTSIDER, ROOT_A, unsafe_signer

AT = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
AT_TEXT = "2026-08-26T12:00:00Z"

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

SCOPE = {"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "write"]}


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, approval: str = "none") -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=AGENT.did,
            epoch=0,
            scopes=[SCOPE],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            approval=approval,
            issued_at=AT,
        ),
        [ROOT],
    )


@pytest.fixture
def client() -> TestClient:
    index = EventIndex()
    index.ingest_all([genesis(), grant()])
    return TestClient(create_app(index))


def permission_body(**overrides: object) -> dict[str, object]:
    return {
        "lineage": LINEAGE,
        "agent": AGENT.did,
        "namespace": "technocore",
        "resource": "room:lobby",
        "action": "write",
        "at": AT_TEXT,
    } | overrides


class TestServiceShape:
    def test_health(self, client: TestClient) -> None:
        assert client.get("/healthz").json()["status"] == "ok"

    def test_meta_states_what_the_service_refuses_to_be(self, client: TestClient) -> None:
        body = client.get("/v1/meta").json()
        assert body["holdsPrivateKeys"] is False
        assert body["acceptsEventsOverHttp"] is False
        assert "cannot make one authoritative" in body["note"]

    def test_security_headers_are_present_on_every_response(self, client: TestClient) -> None:
        # A JSON API still gets them: the case they exist for is a browser being
        # talked into treating a response as a document.
        for path in ("/healthz", "/v1/meta", "/v1/lineages"):
            headers = client.get(path).headers
            for name, value in SECURITY_HEADERS.items():
                assert headers[name] == value

    def test_there_is_no_endpoint_that_ingests_an_event(self, client: TestClient) -> None:
        """Events enter through the store. An HTTP request must not add one."""
        routes = {
            (route.path, method)
            for route in client.app.routes  # type: ignore[attr-defined]
            for method in getattr(route, "methods", set())
        }
        writes = {
            (path, method)
            for path, method in routes
            if method in {"POST", "PUT", "PATCH", "DELETE"}
        }
        # The only POSTs are the two that compute an answer and store nothing.
        assert writes == {("/v1/verify/event", "POST"), ("/v1/check-permission", "POST")}

    def test_verifying_an_event_does_not_index_it(self, client: TestClient) -> None:
        before = client.get("/v1/meta").json()["indexedEvents"]
        other = sign_payload(build_root_create(root_did=STRANGER.did, issued_at=AT), [STRANGER])
        client.post(
            "/v1/verify/event",
            json={"payload": other.payload, "proofs": [p.model_dump() for p in other.proofs]},
        )
        assert client.get("/v1/meta").json()["indexedEvents"] == before


class TestVerifyEndpoint:
    def test_a_valid_event_verifies(self, client: TestClient) -> None:
        event = genesis()
        body = client.post(
            "/v1/verify/event",
            json={"payload": event.payload, "proofs": [p.model_dump() for p in event.proofs]},
        ).json()
        assert body["integrityOk"] is True
        assert body["verifiedSigners"] == [ROOT.did]
        assert "not an authorization decision" in body["note"]

    def test_a_tampered_event_does_not(self, client: TestClient) -> None:
        event = genesis()
        body = client.post(
            "/v1/verify/event",
            json={
                "payload": dict(event.payload) | {"epoch": 9},
                "proofs": [p.model_dump() for p in event.proofs],
            },
        ).json()
        assert body["integrityOk"] is False
        assert body["reason"] == "INVALID_SIGNATURE"

    def test_a_non_envelope_is_a_client_error(self, client: TestClient) -> None:
        assert client.post("/v1/verify/event", json={"nope": 1}).status_code == 422


class TestPermissionEndpoint:
    def test_a_valid_chain_is_allowed(self, client: TestClient) -> None:
        body = client.post("/v1/check-permission", json=permission_body()).json()
        assert body["allowed"] is True
        assert body["reason"] == "VALID_AUTHORITY_CHAIN"
        assert body["root"] == ROOT.did

    def test_the_response_names_the_grants_that_justified_it(self, client: TestClient) -> None:
        # A client that wants certainty refetches these and re-walks the chain.
        body = client.post("/v1/check-permission", json=permission_body()).json()
        assert body["path"] == [grant().event_id]
        assert client.get(f"/v1/events/{body['path'][0]}").status_code == 200

    def test_an_agent_without_a_grant_is_denied(self, client: TestClient) -> None:
        body = client.post("/v1/check-permission", json=permission_body(agent=STRANGER.did)).json()
        assert body["allowed"] is False
        assert body["reason"] == "DENIED"

    def test_a_scope_outside_the_grant_is_refused(self, client: TestClient) -> None:
        body = client.post("/v1/check-permission", json=permission_body(resource="room:ops")).json()
        assert body["reason"] == "SCOPE_VIOLATION"

    def test_revocation_changes_the_answer(self) -> None:
        index = EventIndex()
        target = grant()
        index.ingest_all(
            [
                genesis(),
                target,
                sign_payload(
                    build_delegation_revoke(
                        lineage=LINEAGE, issuer=ROOT.did, grant=target.event_id, issued_at=AT
                    ),
                    [ROOT],
                ),
            ]
        )
        client = TestClient(create_app(index))
        body = client.post("/v1/check-permission", json=permission_body()).json()
        assert body["reason"] == "REVOKED"

    def test_the_answer_is_reproducible_for_a_stated_time(self, client: TestClient) -> None:
        first = client.post("/v1/check-permission", json=permission_body()).json()
        second = client.post("/v1/check-permission", json=permission_body()).json()
        assert first == second

    def test_an_unparseable_time_is_a_client_error(self, client: TestClient) -> None:
        response = client.post("/v1/check-permission", json=permission_body(at="yesterday"))
        assert response.status_code == 400

    def test_an_unknown_field_is_refused(self, client: TestClient) -> None:
        # A field this service cannot interpret may be a constraint it would be
        # silently dropping.
        response = client.post("/v1/check-permission", json=permission_body(ignoreRevocations=True))
        assert response.status_code == 422


class TestReadEndpoints:
    def test_an_event_comes_back_exactly_as_stored(self, client: TestClient) -> None:
        event = genesis()
        body = client.get(f"/v1/events/{event.event_id}").json()
        assert body["payload"] == event.payload
        # Round-trips through verification, so a client need not trust the service.
        rebuilt = Envelope.model_validate({"payload": body["payload"], "proofs": body["proofs"]})
        assert rebuilt.event_id == event.event_id

    def test_a_missing_event_is_404(self, client: TestClient) -> None:
        assert client.get(f"/v1/events/sha256:{'a' * 64}").status_code == 404

    def test_lineages_are_listed_and_resolvable(self, client: TestClient) -> None:
        assert client.get("/v1/lineages").json()["lineages"] == [LINEAGE]
        body = client.get(f"/v1/lineages/{LINEAGE}", params={"at": AT_TEXT}).json()
        assert body["resolved"] is True
        assert body["root"] == ROOT.did
        assert body["epoch"] == 0

    def test_an_unresolved_lineage_reports_no_current_root(self) -> None:
        # Reporting the last position it could justify would read as an answer
        # when the honest reply is that there is not one.
        index = EventIndex()
        index.ingest(grant())  # a grant with no genesis
        client = TestClient(create_app(index))
        body = client.get(f"/v1/lineages/{LINEAGE}", params={"at": AT_TEXT}).json()
        assert body["resolved"] is False
        assert body["root"] is None
        assert body["epoch"] is None

    def test_a_did_lookup_says_that_signing_is_not_authority(self, client: TestClient) -> None:
        body = client.get(f"/v1/dids/{ROOT.did}").json()
        assert len(body["signedEventIds"]) == 2
        assert "not authority" in body["note"]

    def test_an_unknown_did_returns_an_empty_list_not_an_error(self, client: TestClient) -> None:
        assert client.get(f"/v1/dids/{STRANGER.did}").json()["signedEventIds"] == []


class TestApiMatchesTheLibrary:
    def test_the_endpoint_and_the_function_agree(self, client: TestClient) -> None:
        """The API is a wrapper. If it ever disagrees, the wrapper is wrong."""
        from lineageauth.authority import check_permission
        from lineageauth.bundle import EventBundle

        direct = check_permission(
            EventBundle.from_envelopes([genesis(), grant()]),
            lineage=LINEAGE,
            agent=AGENT.did,
            namespace="technocore",
            resource="room:lobby",
            action="write",
            at=AT,
        )
        body = client.post("/v1/check-permission", json=permission_body()).json()
        assert body["allowed"] == direct.allowed
        assert body["reason"] == str(direct.reason)
        assert body["path"] == list(direct.path)


class TestGraphEndpoint:
    def test_it_projects_the_lineage(self, client: TestClient) -> None:
        body = client.get(f"/v1/lineages/{LINEAGE}/graph", params={"at": AT_TEXT}).json()
        assert body["resolved"] is True
        assert {n["did"] for n in body["nodes"]} == {ROOT.did, AGENT.did}
        assert [e["kind"] for e in body["edges"]] == ["delegated"]
        assert body["edges"][0]["live"] is True

    def test_the_drawing_agrees_with_the_permission_endpoint(self, client: TestClient) -> None:
        """A picture that disagrees with the verifier is worse than no picture."""
        index = EventIndex()
        target = grant()
        index.ingest_all(
            [
                genesis(),
                target,
                sign_payload(
                    build_delegation_revoke(
                        lineage=LINEAGE, issuer=ROOT.did, grant=target.event_id, issued_at=AT
                    ),
                    [ROOT],
                ),
            ]
        )
        revoked_client = TestClient(create_app(index))
        decision = revoked_client.post("/v1/check-permission", json=permission_body()).json()
        drawing = revoked_client.get(f"/v1/lineages/{LINEAGE}/graph", params={"at": AT_TEXT}).json()
        edge = next(e for e in drawing["edges"] if e["eventId"] == target.event_id)
        assert decision["reason"] == "REVOKED"
        assert edge["live"] is False
        assert edge["reason"] == "REVOKED"

    def test_the_response_refuses_to_imply_trustworthiness(self, client: TestClient) -> None:
        body = client.get(f"/v1/lineages/{LINEAGE}/graph", params={"at": AT_TEXT}).json()
        assert "trustworthy" in body["note"]
