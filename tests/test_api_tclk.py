"""`POST /v1/tclk/{inspect,simulate,authorize}`.

Three compute-only endpoints over the tclk/1 adapter. What these defend: the
service never posts a frame, never touches a rail, never consumes a receipt
(the approval half is a dry run), and never invents a clock -- a transcript is
judged at the instant the caller states, which is the deterministic-answers rule
the rest of the API keeps and the reference MCP tool's issue #23 is about.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from lineageauth.actions import ActionRequest
from lineageauth.adapters import tclk
from lineageauth.api import SECURITY_HEADERS, create_app
from lineageauth.builders import (
    build_approval_receipt,
    build_delegation_grant,
    build_root_create,
    sign_payload,
)
from lineageauth.envelope import Envelope
from lineageauth.index import EventIndex
from tests.testkeys import AGENT_1, RECOVERY_1, ROOT_A, unsafe_signer

AT = datetime(2026, 9, 2, 12, 0, 0, tzinfo=UTC)
AT_TEXT = "2026-09-02T12:00:00Z"
T0 = 1_756_700_000_000
REFUND_AFTER = T0 + 7_200_000

ROOT = unsafe_signer(ROOT_A)
PAYER = unsafe_signer(AGENT_1)
PAYEE = unsafe_signer(RECOVERY_1)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

PREIMAGE = "0x" + "11" * 32
STATEMENT = "0x" + hashlib.sha256(bytes.fromhex("11" * 32)).hexdigest()


def offer_line() -> str:
    fields = {
        "type": "offer",
        "from": PAYER.did,
        "role": "payer",
        "amount": "1000000",
        "asset": "FLOP",
        "lock": "hash",
        "rails": ["flop-htlc", "x402"],
        "claimByMs": T0 + 3_600_000,
        "refundAfterMs": REFUND_AFTER,
        "expiresMs": T0 + 600_000,
        "nonce": "9f2c81d04c9e1f7a",
    }
    fields["id"] = tclk.offer_id(fields)
    return tclk.encode_frame(fields)


def transcript() -> list[str]:
    of = tclk.decode_frame(offer_line())
    core = {
        "from": PAYEE.did,
        "ref": of.fields["id"],
        "statement": STATEMENT,
        "nonce": "0011223344556677",
    }
    accept = tclk.encode_frame(
        {"type": "accept", **core, "contract": tclk.contract_id(of.fields, core)}
    )
    contract = tclk.decode_frame(accept).contract
    assert contract is not None
    lock = tclk.encode_frame(
        {"type": "lock", "from": PAYER.did, "contract": contract, "rail": "x402", "ref": "escrow-1"}
    )
    reveal = tclk.encode_frame(
        {"type": "reveal", "from": PAYEE.did, "contract": contract, "secret": PREIMAGE}
    )
    return [of.line, accept, lock, reveal]


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, approval: str = "none") -> Envelope:
    return sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=PAYER.did,
            epoch=0,
            scopes=[
                {"namespace": "technocore", "resource": "room:tclk-offers", "actions": ["write"]}
            ],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            approval=approval,
            approvers=[ROOT.did] if approval != "none" else None,
            issued_at=AT,
        ),
        [ROOT],
    )


def receipt_for(line: str) -> Envelope:
    request = ActionRequest.over_bytes(
        namespace="technocore",
        resource="room:tclk-offers",
        action="write",
        destination="https://technocore.chat/r/tclk-offers",
        content=line.encode(),
    )
    return sign_payload(
        build_approval_receipt(
            lineage=LINEAGE,
            approver=ROOT.did,
            agent=PAYER.did,
            request=request,
            nonce=b"\x11" * 16,
            expires_at=AT + timedelta(minutes=10),
            issued_at=AT - timedelta(minutes=1),
        ),
        [ROOT],
    )


def client_with(*events: Envelope) -> TestClient:
    index = EventIndex()
    index.ingest_all(list(events))
    return TestClient(create_app(index))


@pytest.fixture
def client() -> TestClient:
    return client_with(genesis(), grant())


class TestInspect:
    def test_a_frame_parses_and_is_labelled(self, client: TestClient) -> None:
        response = client.post("/v1/tclk/inspect", json={"line": offer_line()})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["type"] == "offer" and body["room"] == tclk.OFFER_ROOM
        assert body["artifactId"].startswith("sha256:")
        assert "never this service's" in body["note"]
        for header, value in SECURITY_HEADERS.items():
            assert response.headers[header] == value

    def test_a_malformed_frame_is_400_with_the_reason(self, client: TestClient) -> None:
        response = client.post("/v1/tclk/inspect", json={"line": 'tclk1 {"type":"offer"}'})
        assert response.status_code == 400
        assert "missing field" in response.json()["detail"]

    def test_an_oversized_line_is_refused_before_parsing(self, client: TestClient) -> None:
        response = client.post("/v1/tclk/inspect", json={"line": "tclk1 " + "x" * 5000})
        assert response.status_code == 422


class TestSimulate:
    def test_per_frame_instants_reach_claimed(self, client: TestClient) -> None:
        lines = transcript()
        response = client.post(
            "/v1/tclk/simulate",
            json={"lines": lines, "timestamps": [T0, T0 + 1, T0 + 2]},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "claimed" and body["secretRevealed"] is True
        assert body["a2a"] == "completed" and body["version"] == "tclk/1"
        assert [s["ok"] for s in body["steps"]] == [True, True, True]
        assert body["deadlines"]["refundAfterMs"] == REFUND_AFTER
        assert any("money" in s for s in body["evidence"]["doesNotProve"])

    def test_one_late_instant_lands_on_proposed(self, client: TestClient) -> None:
        """The #23 shape, measured: the accept expires before any reveal is reached."""
        response = client.post(
            "/v1/tclk/simulate", json={"lines": transcript(), "nowMs": REFUND_AFTER + 1}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "proposed"
        assert "expired" in body["steps"][0]["reason"]

    def test_there_is_no_default_clock(self, client: TestClient) -> None:
        response = client.post("/v1/tclk/simulate", json={"lines": transcript()})
        assert response.status_code == 400
        assert "nowMs" in response.json()["detail"]

    def test_timestamps_must_match_the_frames(self, client: TestClient) -> None:
        response = client.post(
            "/v1/tclk/simulate", json={"lines": transcript(), "timestamps": [T0]}
        )
        assert response.status_code == 400

    def test_a_transcript_must_start_with_an_offer(self, client: TestClient) -> None:
        lines = transcript()
        response = client.post("/v1/tclk/simulate", json={"lines": lines[1:], "nowMs": T0})
        assert response.status_code == 400
        assert "starts with an offer" in response.json()["detail"]

    def test_too_many_lines_are_refused(self, client: TestClient) -> None:
        response = client.post(
            "/v1/tclk/simulate", json={"lines": [offer_line()] * 65, "nowMs": T0}
        )
        assert response.status_code == 422


class TestAuthorize:
    def _body(self, line: str, **overrides: object) -> dict[str, object]:
        return {"lineage": LINEAGE, "agent": PAYER.did, "line": line, "at": AT_TEXT} | overrides

    def test_allowed_with_a_room_grant(self, client: TestClient) -> None:
        response = client.post("/v1/tclk/authorize", json=self._body(offer_line()))
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["allowed"] is True and body["reason"] == "VALID_AUTHORITY_CHAIN"
        assert "spend-limit" in body["unchecked"]
        assert body["prepared"]["destination"] == "https://technocore.chat/r/tclk-offers"
        assert body["approval"] == {"required": False, "mayExecute": True, "dryRun": True}

    def test_denied_without_one(self) -> None:
        client = client_with(genesis())
        response = client.post("/v1/tclk/authorize", json=self._body(offer_line()))
        assert response.status_code == 200
        body = response.json()
        assert body["allowed"] is False and body["reason"] == "DENIED"
        assert body["approval"] is None

    def test_a_malformed_frame_never_reaches_the_bundle(self, client: TestClient) -> None:
        response = client.post("/v1/tclk/authorize", json=self._body("tclk2 {}"))
        assert response.status_code == 200
        body = response.json()
        assert body["reason"] == "UNKNOWN_VERSION" and body["path"] == []

    def test_approval_required_reports_the_dry_run(self) -> None:
        line = offer_line()
        without = client_with(genesis(), grant(approval="required"))
        body = without.post("/v1/tclk/authorize", json=self._body(line)).json()
        assert body["reason"] == "APPROVAL_REQUIRED"
        assert body["approval"]["required"] is True
        assert body["approval"]["mayExecute"] is False
        assert body["approval"]["dryRun"] is True

        with_receipt = client_with(genesis(), grant(approval="required"), receipt_for(line))
        body = with_receipt.post("/v1/tclk/authorize", json=self._body(line)).json()
        assert body["approval"]["mayExecute"] is True
        assert body["approval"]["approver"] == ROOT.did
        # A dry run: asking twice finds the receipt twice.
        again = with_receipt.post("/v1/tclk/authorize", json=self._body(line)).json()
        assert again["approval"]["mayExecute"] is True

    def test_the_agent_must_be_the_frame_sender(self, client: TestClient) -> None:
        body = client.post(
            "/v1/tclk/authorize", json=self._body(offer_line(), agent=PAYEE.did)
        ).json()
        assert body["allowed"] is False and "not the agent asking" in body["detail"]

    def test_no_endpoint_posts_or_settles(self, client: TestClient) -> None:
        """The route table is the promise: nothing under /v1/tclk/ is a verb that moves."""
        paths = [route.path for route in client.app.routes]  # type: ignore[attr-defined]
        tclk_paths = [p for p in paths if "/tclk/" in p]
        assert sorted(tclk_paths) == [
            "/v1/tclk/authorize",
            "/v1/tclk/inspect",
            "/v1/tclk/simulate",
        ]
        for forbidden in ("post", "publish", "lock", "claim", "refund", "reveal", "pay", "send"):
            assert not any(p.endswith("/" + forbidden) for p in tclk_paths)
