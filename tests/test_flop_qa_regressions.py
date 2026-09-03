"""One test per defect the adversarial QA pass found, named after the defect.

These are regressions rather than features: each one failed before the fix that
sits next to it and would fail again if that fix were reverted. They are kept in
one file so the next reviewer can read the list of things this console got wrong
and see, in the same place, what now stops each of them.

The ordering follows the QA report: provenance that could be asserted rather
than derived, a scanner two request fields could quieten, synthetic records
counted without a label, a same-origin check built on a header the attacker
controls, memory an unauthenticated caller could grow, and four smaller ones --
a path that lands somewhere other than where it reads, a counterparty's word
recorded as verification, an import guard that stopped seeing one import form,
and a zero on the header nobody had measured.
"""

from __future__ import annotations

import ast
import dataclasses
import threading
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from lineageauth.api import create_app
from lineageauth.approval import InMemorySpentStore
from lineageauth.builders import build_root_create, sign_payload
from lineageauth.envelope import Envelope
from lineageauth.flop.activity import (
    ActivitySubject,
    MockAdapter,
    _record_from_mapping,
)
from lineageauth.flop.api import (
    DEFAULT_ALLOWED_HOSTS,
    FLOP_PREFIX,
    MAX_HELD_ACTIONS,
    _BoundedStore,
    build_flop_router,
)
from lineageauth.flop.coverage import compute_coverage
from lineageauth.flop.model import (
    SYNTHETIC_BANNER,
    NetworkPhase,
    SafetyLevel,
    SourceClass,
)
from lineageauth.flop.safety import (
    SUPPRESSED_BY_PHASE_PATTERN,
    SUPPRESSED_BY_PROVENANCE_PATTERN,
    overall_level,
    scan_report,
    scan_text,
)
from lineageauth.flop.sources import classify_source
from lineageauth.flop.testnet.audit import JsonlAuditLog
from lineageauth.flop.testnet.endpoints import FlopEndpoint
from lineageauth.flop.testnet.meter import NetworkWriteMeter
from lineageauth.flop.testnet.receipts import SELF_REPORTED_REASON, receipt_from_response
from lineageauth.flop.testnet.signer import NoSigner
from lineageauth.flop.testnet.simulation import prepare_simulation
from lineageauth.index import EventIndex
from tests.testkeys import AGENT_1, ROOT_A, unsafe_signer

AT = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
AT_TEXT = "2026-09-03T12:00:00Z"

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
LINEAGE: str = build_root_create(root_did=ROOT.did, issued_at=AT)["lineage"]

APPS = Path("apps/flop")

SCAM = (
    "Claim your airdrop now! The mainnet is live. Buy $FLOP. "
    "This is an official FLOP Labs announcement."
)


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def index_with_genesis() -> EventIndex:
    index = EventIndex()
    index.ingest_all([genesis()])
    return index


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(index_with_genesis()))


@pytest.fixture
def mock_client() -> TestClient:
    app = FastAPI()
    app.include_router(build_flop_router(index_with_genesis(), include_mock=True))
    return TestClient(app)


def subject(did: str = AGENT.did) -> ActivitySubject:
    return ActivitySubject(did=did, lineage=LINEAGE, at=AT)


def completed_simulation():  # type: ignore[no-untyped-def]
    """One simulation run that actually reaches the transport.

    The console's demo index holds a genesis event and no grant, so a run driven
    through HTTP stops at the authority stage. These tests are about what the
    network counter reports after an execution, so the run is built on the
    approved bundle the executor suite already uses.
    """
    from lineageauth.flop.testnet.simulation import run_simulation
    from tests.flop_testnet_fixtures import approved_bundle, rules, snapshot

    prepared = prepare_simulation(subject_did=AGENT.did, at=AT, snapshot=snapshot(), rules=rules())
    return run_simulation(
        bundle=approved_bundle(prepared),
        lineage=LINEAGE,
        agent=AGENT.did,
        at=AT,
        snapshot=snapshot(),
        rules=rules(),
        store=InMemorySpentStore(),
    )


class TestAPathThatDoesNotLandWhereItReads:
    """`https://github.com/flop-labs/../evil-org/payout` used to be official.

    A browser removes the dot segment before sending, so the request goes to
    `github.com/evil-org/payout` while the string still reads as FLOP Labs. The
    prefix test believed the string. Worse, the scanner said nothing at all
    about it: an official URL is neither suspicious nor unknown, so it produced
    no finding and the whole scan came back "SAFE TO REVIEW".
    """

    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/flop-labs/../evil-org/payout",
            "https://api.github.com/repos/flop-labs/%2e%2e/evil-org",
            "https://flop.finance/./../elsewhere",
            "https://technocore.chat/.well-known/../kv/anything",
        ],
    )
    def test_a_relative_segment_makes_a_url_suspicious_rather_than_official(self, url: str) -> None:
        decision = classify_source(url)
        assert decision.source_class is SourceClass.SUSPICIOUS
        assert decision.rule_id == "dot-segment-path"
        assert decision.may_carry_official_badge is False

    def test_an_encoded_separator_is_suspicious_too(self) -> None:
        decision = classify_source("https://github.com/flop-labs%2f..%2fevil")
        assert decision.source_class is SourceClass.SUSPICIOUS
        assert decision.rule_id == "encoded-separator-path"

    def test_the_ordinary_official_urls_still_classify_as_official(self) -> None:
        for url in (
            "https://github.com/flop-labs/tclk",
            "https://api.github.com/repos/flop-labs/tclk",
            "https://flop.finance/design.md",
            "https://technocore.chat/llms.txt",
        ):
            assert classify_source(url).source_class is SourceClass.OFFICIAL

    def test_the_scanner_no_longer_calls_that_link_safe_to_review(self, client: TestClient) -> None:
        response = client.post(
            f"{FLOP_PREFIX}/safety/scan",
            json={"text": "Task board: https://github.com/flop-labs/../evil-org/payout"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["level"] == str(SafetyLevel.HIGH_RISK)
        assert body["display"] != "SAFE TO REVIEW"
        assert [finding["patternId"] for finding in body["findings"]] == ["url.lookalike"]


class TestTheScannerCannotBeQuietenedByARequest:
    """`networkPhase` and `sourceClass` used to come off the request body.

    Sending `networkPhase: TESTNET_ENABLED` skipped the whole network-claim
    family; sending `sourceClass: official` skipped the impersonation family. A
    page could therefore ask the scanner not to notice, and the UI offered the
    second one in a dropdown.
    """

    def test_a_request_may_not_name_its_own_phase(self, client: TestClient) -> None:
        response = client.post(
            f"{FLOP_PREFIX}/safety/scan",
            json={"text": SCAM, "networkPhase": "TESTNET_ENABLED"},
        )
        assert response.status_code == 422
        assert any(error["type"] == "extra_forbidden" for error in response.json()["detail"])

    def test_a_request_may_not_call_itself_official(self, client: TestClient) -> None:
        response = client.post(
            f"{FLOP_PREFIX}/safety/scan", json={"text": SCAM, "sourceClass": "official"}
        )
        assert response.status_code == 400
        assert "decided by origin" in response.json()["detail"]

    def test_the_scam_text_is_still_high_risk_over_the_wire(self, client: TestClient) -> None:
        body = client.post(f"{FLOP_PREFIX}/safety/scan", json={"text": SCAM}).json()
        assert body["level"] == str(SafetyLevel.HIGH_RISK)
        assert body["phaseIsThisService"] is True
        patterns = {finding["patternId"] for finding in body["findings"]}
        assert {"network.buy-or-mint", "network.claim", "network.live"} <= patterns

    def test_a_live_phase_reports_the_suppression_instead_of_going_silent(self) -> None:
        findings = scan_text(SCAM, network_phase=NetworkPhase.TESTNET_ENABLED)
        patterns = {finding.pattern_id for finding in findings}
        assert SUPPRESSED_BY_PHASE_PATTERN in patterns
        assert overall_level(findings).rank >= SafetyLevel.CAUTION.rank

    def test_an_official_source_class_reports_the_suppression_too(self) -> None:
        findings = scan_text(SCAM, source_class=SourceClass.OFFICIAL)
        suppressed = [
            finding
            for finding in findings
            if finding.pattern_id == SUPPRESSED_BY_PROVENANCE_PATTERN
        ]
        assert len(suppressed) == 1
        assert "asserted by the caller" in suppressed[0].reason
        assert suppressed[0].level.rank >= SafetyLevel.CAUTION.rank

    def test_neither_parameter_can_empty_a_scan_of_this_text(self) -> None:
        report = scan_report(
            SCAM,
            source_class=SourceClass.OFFICIAL,
            network_phase=NetworkPhase.TESTNET_ENABLED,
        )
        assert report["findings"] != []
        assert report["display"] != "SAFE TO REVIEW"

    def test_the_page_no_longer_offers_official_as_a_provenance_to_pick(self) -> None:
        markup = (APPS / "index.html").read_text(encoding="utf-8")
        assert '<option value="official">' not in markup
        assert '<option value="community">' in markup
        assert "the network phase is the one this service observed" in markup


class TestSyntheticRecordsAreLabelledWhereverTheyAreCounted:
    """Activity and Passport labelled their records; Overview did not.

    Overview is the first screen anybody sees, and it drew coverage counts and a
    "Useful work" number computed partly from mock records with no banner
    anywhere on it, because `CoverageReport.to_dict` carried no synthetic flag
    and `app.js` never read `syntheticDataEnabled`.
    """

    def test_a_coverage_report_says_when_a_synthetic_record_went_into_it(self) -> None:
        records = MockAdapter().fetch(subject())
        assert records
        body = compute_coverage(records).to_dict()
        assert body["containsSyntheticData"] is True
        assert body["banner"] == SYNTHETIC_BANNER

    def test_a_coverage_report_over_real_records_carries_no_banner(self) -> None:
        body = compute_coverage(()).to_dict()
        assert body["containsSyntheticData"] is False
        assert "banner" not in body

    def test_the_coverage_endpoint_carries_the_flag(self, mock_client: TestClient) -> None:
        body = mock_client.get(
            f"{FLOP_PREFIX}/coverage",
            params={"lineage": LINEAGE, "did": AGENT.did, "at": AT_TEXT},
        ).json()
        assert body["containsSyntheticData"] is True
        assert body["banner"] == SYNTHETIC_BANNER

    def test_the_recommendations_endpoint_carries_the_flag(self, mock_client: TestClient) -> None:
        body = mock_client.get(
            f"{FLOP_PREFIX}/recommendations",
            params={"lineage": LINEAGE, "did": AGENT.did, "at": AT_TEXT},
        ).json()
        assert body["containsSyntheticData"] is True
        assert body["banner"] == SYNTHETIC_BANNER

    def test_the_header_carries_a_label_that_no_screen_change_removes(self) -> None:
        markup = (APPS / "index.html").read_text(encoding="utf-8")
        script = (APPS / "app.js").read_text(encoding="utf-8")
        assert 'id="notice-synthetic"' in markup
        assert "status.syntheticDataEnabled" in script
        assert "coverage.containsSyntheticData" in script


class TestARecordCannotHandItselfABadge:
    """`"sourceClass": "official"` in a data file used to be believed.

    `classify_source` exists because official is an origin, and the record path
    never called it -- so anyone who could edit `public-evidence.json` or
    `mock-activity.json` could raise a record to OFFICIAL. `MockAdapter` also
    returned the same records for any DID at all, which put a synthetic
    "verified-third-party" history under whatever key was asked about.
    """

    def test_a_forged_official_record_is_clamped_to_the_adapter(self) -> None:
        record = _record_from_mapping(
            {"id": "forged", "title": "forged official record", "sourceClass": "official"},
            subject=subject(),
            source_id="forged-source",
            default_source_class=SourceClass.COMMUNITY,
            synthetic=False,
        )
        assert record is not None
        assert record.source_class is SourceClass.COMMUNITY
        assert "declared sourceClass official" in record.detail

    def test_an_official_url_still_does_not_outrank_the_adapter(self) -> None:
        record = _record_from_mapping(
            {
                "id": "real",
                "title": "a FLOP Labs repository",
                "sourceClass": "official",
                "url": "https://github.com/flop-labs/tclk",
            },
            subject=subject(),
            source_id="public-evidence",
            default_source_class=SourceClass.VERIFIED_THIRD_PARTY,
            synthetic=False,
        )
        assert record is not None
        assert record.source_class is SourceClass.VERIFIED_THIRD_PARTY

    def test_a_record_claiming_less_than_its_adapter_is_taken_at_its_word(self) -> None:
        record = _record_from_mapping(
            {"id": "modest", "title": "a community note", "sourceClass": "community"},
            subject=subject(),
            source_id="public-evidence",
            default_source_class=SourceClass.VERIFIED_THIRD_PARTY,
            synthetic=False,
        )
        assert record is not None
        assert record.source_class is SourceClass.COMMUNITY
        assert record.detail == ""

    def test_mock_records_are_unknown_and_say_whose_they_are_not(self) -> None:
        records = MockAdapter().fetch(subject("did:key:z6MkNOBODYHASTHISKEY"))
        assert records
        for record in records:
            assert record.source_class is SourceClass.UNKNOWN
            assert record.synthetic is True
            assert "is not an observation about did:key:z6MkNOBODYHASTHISKEY" in record.detail

    def test_the_activities_endpoint_shows_the_disclaimer(self, mock_client: TestClient) -> None:
        body = mock_client.get(
            f"{FLOP_PREFIX}/activities",
            params={"lineage": LINEAGE, "did": AGENT.did, "at": AT_TEXT},
        ).json()
        mocked = [record for record in body["records"] if record["synthetic"]]
        assert mocked
        for record in mocked:
            assert record["sourceClass"] == str(SourceClass.UNKNOWN)
            assert "is not an observation about" in record["detail"]


class TestTheConsoleAnswersOnlyToNamesItWasStartedFor:
    """The same-origin check compared `Origin` against a header the page sets.

    Under DNS rebinding a page on `evil.example` resolves that name to 127.0.0.1
    and then sends `Origin: http://evil.example` with `Host: evil.example`. The
    two matched, so the CSRF check passed and the local console answered a
    remote page -- reads included.
    """

    def test_a_rebound_post_is_refused(self, client: TestClient) -> None:
        response = client.post(
            f"{FLOP_PREFIX}/safety/scan",
            json={"text": "hi"},
            headers={"Host": "evil.example.com", "Origin": "http://evil.example.com"},
        )
        assert response.status_code == 421
        assert "not one this console answers to" in response.json()["detail"]

    def test_a_rebound_read_is_refused_as_well(self, client: TestClient) -> None:
        response = client.get(f"{FLOP_PREFIX}/status", headers={"Host": "evil.example.com"})
        assert response.status_code == 421

    def test_every_flop_route_carries_the_guard(self, client: TestClient) -> None:
        for path, params in (
            (f"{FLOP_PREFIX}/sources", None),
            (f"{FLOP_PREFIX}/rules", None),
            (f"{FLOP_PREFIX}/testnet/state", None),
            (
                f"{FLOP_PREFIX}/activities",
                {"lineage": LINEAGE, "did": AGENT.did, "at": AT_TEXT},
            ),
            (
                f"{FLOP_PREFIX}/passport/{AGENT.did}",
                {"lineage": LINEAGE, "at": AT_TEXT},
            ),
        ):
            response = client.get(path, params=params, headers={"Host": "evil.example.com"})
            assert response.status_code == 421, path

    def test_the_ordinary_loopback_names_are_answered(self) -> None:
        assert {"localhost", "127.0.0.1", "testserver"} <= DEFAULT_ALLOWED_HOSTS
        app = FastAPI()
        app.include_router(build_flop_router(index_with_genesis()))
        for base in ("http://localhost:8792", "http://127.0.0.1:8792"):
            with TestClient(app, base_url=base) as loopback:
                assert loopback.get(f"{FLOP_PREFIX}/status").status_code == 200

    def test_a_deployment_may_name_its_own_host(self) -> None:
        app = FastAPI()
        app.include_router(
            build_flop_router(index_with_genesis(), allowed_hosts=["console.internal"])
        )
        with TestClient(app, base_url="http://console.internal") as named:
            assert named.get(f"{FLOP_PREFIX}/status").status_code == 200
        with TestClient(app, base_url="http://localhost") as other:
            assert other.get(f"{FLOP_PREFIX}/status").status_code == 421


class TestHeldActionsDoNotGrowWithoutBound:
    """`prepared_actions` and `receipts` were plain dicts with no limit.

    Every `prepare` holds a whole canonical request, prompt and all, and the
    action id changes with the prompt, so an unauthenticated local caller could
    add an entry per request until the process ran out of memory.
    """

    def test_the_store_forgets_the_oldest_rather_than_growing(self) -> None:
        store: _BoundedStore[str] = _BoundedStore(limit=2)
        store.put("a", "first")
        store.put("b", "second")
        store.put("c", "third")
        assert len(store) == 2
        assert store.get("a") is None
        assert store.get("c") == "third"

    def test_reading_an_entry_does_not_save_it_from_eviction(self) -> None:
        store: _BoundedStore[str] = _BoundedStore(limit=2)
        store.put("a", "first")
        store.put("b", "second")
        assert store.get("a") == "first"
        store.put("c", "third")
        assert store.get("a") is None

    def test_the_store_can_drop_what_has_expired(self) -> None:
        store: _BoundedStore[int] = _BoundedStore(limit=8)
        for key in range(6):
            store.put(str(key), key)
        store.drop_where(lambda held: held % 2 == 0)
        assert len(store) == 3
        assert store.get("0") is None
        assert store.get("1") == 1

    def test_the_api_reports_what_it_is_holding_and_its_ceiling(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/testnet/state").json()
        assert body["heldPreparedActions"] == 0
        assert body["heldReceipts"] == 0
        assert body["maxHeldActions"] == MAX_HELD_ACTIONS

    def test_preparing_repeatedly_does_not_pass_the_ceiling(self, client: TestClient) -> None:
        held = 0
        for attempt in range(5):
            response = client.post(
                f"{FLOP_PREFIX}/testnet/inference/prepare",
                json={
                    "lineage": LINEAGE,
                    "did": AGENT.did,
                    "prompt": f"prompt number {attempt}",
                    "at": AT_TEXT,
                },
            )
            assert response.status_code == 200
            held = client.get(f"{FLOP_PREFIX}/testnet/state").json()["heldPreparedActions"]
        assert held == 5
        assert held <= MAX_HELD_ACTIONS

    def test_an_expired_prepared_action_is_dropped_on_the_next_prepare(
        self, client: TestClient
    ) -> None:
        """A prepared action outlives neither its window nor the next request."""
        first = client.post(
            f"{FLOP_PREFIX}/testnet/inference/prepare",
            json={
                "lineage": LINEAGE,
                "did": AGENT.did,
                "prompt": "the first one",
                "at": AT_TEXT,
            },
        ).json()
        assert client.get(f"{FLOP_PREFIX}/testnet/state").json()["heldPreparedActions"] == 1
        later = (AT + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        second = client.post(
            f"{FLOP_PREFIX}/testnet/inference/prepare",
            json={
                "lineage": LINEAGE,
                "did": AGENT.did,
                "prompt": "much later",
                "at": later,
            },
        )
        assert second.status_code == 200
        state = client.get(f"{FLOP_PREFIX}/testnet/state").json()
        assert state["heldPreparedActions"] == 1
        refused = client.post(
            f"{FLOP_PREFIX}/testnet/inference/approve",
            json={
                "lineage": LINEAGE,
                "did": AGENT.did,
                "actionId": first["id"],
                "at": later,
            },
        )
        assert refused.status_code == 409
        assert refused.json()["detail"]["failure"] == "REPREPARE_REQUIRED"


class TestAConcretePathIsCheckedLikeAPattern:
    """`matches_path` checked the character set of the pattern, not of the path.

    A placeholder segment accepted anything without a slash, so a query, a
    fragment, a userinfo `@` or a percent-encoded traversal could ride into the
    destination that `url_for` builds -- the destination that goes into the
    request hash and onto the approval screen.
    """

    def endpoint(self) -> FlopEndpoint:
        return FlopEndpoint(
            endpoint_id="hypothetical",
            purpose="inference",
            origin="https://flop.finance",
            method="POST",
            path_pattern="/v1/{model}",
            network="hypothetical",
            source_url="https://flop.finance/design.md",
            source_version="alpha",
        )

    @pytest.mark.parametrize(
        "path",
        [
            "/v1/abc?admin=1",
            "/v1/abc#fragment",
            "/v1/%2e%2e%2fadmin",
            "/v1/user@host",
            "/v1/../admin",
            "/v1/",
            "/v1/{model}",
        ],
    )
    def test_a_path_that_hides_something_does_not_match(self, path: str) -> None:
        assert self.endpoint().matches_path(path) is False

    def test_url_for_refuses_the_same_paths(self) -> None:
        from lineageauth.errors import MalformedEventError

        with pytest.raises(MalformedEventError):
            self.endpoint().url_for("/v1/abc?admin=1")

    def test_an_ordinary_segment_still_matches(self) -> None:
        assert self.endpoint().matches_path("/v1/some-model.v2") is True
        assert (
            self.endpoint().url_for("/v1/some-model.v2") == "https://flop.finance/v1/some-model.v2"
        )


class TestNothingACounterpartySaysIsVerification:
    """A response that filled in three fields used to be recorded as VERIFIED.

    Those fields are the endpoint describing its own behaviour, `observedSpend`
    included -- the party being billed against stating what it charged. The
    ledger then recorded that number, so an endpoint reporting zero could keep
    the daily and session caps empty forever.
    """

    def payload(self, **overrides: object) -> dict[str, object]:
        base: dict[str, object] = {
            "receiptRef": "r1",
            "observedSpend": "2.5",
            "result": "an answer",
        }
        base.update(overrides)
        return base

    def receipt(self, payload: dict[str, object]):  # type: ignore[no-untyped-def]
        return receipt_from_response(
            payload,
            action_id="flop-test",
            subject_did=AGENT.did,
            network="simulation",
            action_type="inference",
            endpoint_id="simulation-inference",
            request_hash="sha256:" + "a" * 64,
            response_hash="sha256:" + "b" * 64,
            started_at=AT,
            completed_at=AT,
            source_snapshot_id="snapshot",
        )

    def test_a_complete_response_stops_at_partially_verified(self) -> None:
        receipt = self.receipt(self.payload())
        assert receipt.verification_state.value == "partially-verified"
        assert SELF_REPORTED_REASON in receipt.unverified_because

    def test_a_response_cannot_declare_its_own_verification_state(self) -> None:
        receipt = self.receipt(self.payload(verificationState="verified"))
        assert receipt.verification_state.value == "partially-verified"

    def test_the_ledger_charges_the_greater_of_the_estimate_and_the_report(self) -> None:
        """An endpoint reporting nothing does not get a free execution."""
        from lineageauth.flop.testnet.spend import SpendLedger

        ledger = SpendLedger()
        for reported, estimated in ((Decimal("0"), Decimal("2.5")), (Decimal("9"), Decimal("2"))):
            charged = max(reported, estimated)
            ledger.record(charged, at=AT)
        assert ledger.session_total == Decimal("11.5")

    def test_an_execution_charges_the_estimate_when_the_answer_reports_zero(self) -> None:
        from tests.flop_testnet_fixtures import zero_spend_execution

        outcome, ledger, estimated = zero_spend_execution()
        assert outcome.ok is True
        assert outcome.receipt is not None
        assert outcome.receipt.observed_spend == Decimal("0")
        assert ledger.session_total == estimated
        assert estimated > Decimal("0")


class TestTheImportGuardSeesEveryImportForm:
    """`NETWORK_MODULES` was narrowed and the detector was not.

    Narrowing `urllib` to `urllib.request` let `urllib.parse` be used at the
    URL-classifying boundary, which was right. But the detector only looked at
    `node.module` for a `from` import, so `from urllib import request` stopped
    being seen -- and so did `from http import client`.
    """

    def names_for(self, source: str) -> list[str]:
        from tests.test_zero_cost import NETWORK_MODULES

        found: list[str] = []
        for node in ast.walk(ast.parse(source)):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{alias.name}" for alias in node.names]
            found.extend(
                name
                for name in names
                if any(name == m or name.startswith(f"{m}.") for m in NETWORK_MODULES)
            )
        return found

    @pytest.mark.parametrize(
        "source",
        [
            "import socket",
            "import urllib.request",
            "from urllib.request import urlopen",
            "from urllib import request",
            "from http import client",
            "import httpx",
        ],
    )
    def test_every_way_of_reaching_the_network_is_seen(self, source: str) -> None:
        assert self.names_for(source) != []

    @pytest.mark.parametrize(
        "source",
        ["from urllib.parse import urlsplit", "from urllib import parse", "import json"],
    )
    def test_the_url_parser_is_still_allowed(self, source: str) -> None:
        assert self.names_for(source) == []


class TestTheAuditLogSurvivesTwoWriters:
    """`JsonlAuditLog.append` read the whole file, then wrote without a lock.

    Two writers computed the same `seq` and the same `prev` from the same tail,
    and the chain they left behind did not verify. Reading the whole file also
    made every append cost more than the last.
    """

    def test_concurrent_appends_leave_a_chain_that_verifies(self, tmp_path: Path) -> None:
        log = JsonlAuditLog(tmp_path / "audit.jsonl")

        def write(worker: int) -> None:
            for line in range(10):
                log.append("execution-completed", {"at": AT, "worker": worker, "line": line})

        workers = [threading.Thread(target=write, args=(index,)) for index in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        lines = log.entries()
        assert len(lines) == 40
        assert [line.seq for line in lines] == list(range(1, 41))
        ok, detail = log.verify_chain()
        assert ok, detail

    def test_the_head_is_read_without_loading_the_whole_file(self, tmp_path: Path) -> None:
        log = JsonlAuditLog(tmp_path / "audit.jsonl")
        for line in range(5):
            log.append("k", {"at": AT, "line": line})
        assert log.head == log.entries()[-1].hash

    def test_no_lock_file_is_left_behind(self, tmp_path: Path) -> None:
        log = JsonlAuditLog(tmp_path / "audit.jsonl")
        log.append("k", {"at": AT})
        assert list(tmp_path.glob("*.lock")) == []


class TestTheZeroOnTheHeaderIsMeasured:
    """`networkWritesPerformed: 0` and `walletCustody: false` were literals.

    `ExecutionOutcome.network_attempts` and `NoSigner` both knew the answer, and
    neither was consulted. A hardcoded zero keeps saying zero on the day it
    stops being true, which is the failure `MEMORY.md` records five times over.
    """

    def test_the_meter_counts_what_it_is_told_about(self) -> None:
        meter = NetworkWriteMeter()
        assert meter.performed == 0
        meter.observe(2, simulation=True)
        meter.observe(0, simulation=False)
        assert meter.performed == 0
        assert meter.simulated == 2
        assert meter.to_dict()["measured"] is True

    def test_the_status_number_comes_from_the_meter(self, client: TestClient) -> None:
        body = client.get(f"{FLOP_PREFIX}/status").json()
        assert body["networkWritesPerformed"] == 0
        assert body["networkWriteAccounting"]["measured"] is True
        assert body["walletCustody"] is NoSigner().holds_private_keys

    def test_a_simulation_run_reports_a_measured_zero(self) -> None:
        """Zero, computed as attempts minus the calls the simulation transport took.

        The subtraction is the measurement: if an attempt ever went somewhere
        other than the transport that opens no socket, this stops being zero
        without anybody remembering to change a literal.
        """
        run = completed_simulation()
        assert run.outcome is not None
        assert run.outcome.network_attempts >= 1
        assert run.transport_calls == run.outcome.network_attempts
        body = run.to_dict()
        assert body["networkWritesPerformed"] == 0
        assert body["simulatedAttempts"] == run.outcome.network_attempts

    def test_an_attempt_that_missed_the_simulation_transport_would_show(self) -> None:
        """The measurement can be non-zero, which is what makes the zero worth reading."""
        run = completed_simulation()
        assert run.outcome is not None
        drifted = dataclasses.replace(run, transport_calls=0)
        assert drifted.network_writes_performed == run.outcome.network_attempts


class TestTheSpentStoreIsStillNotShared:
    """A guard on the change above: the bounded store holds actions, not receipts of spend."""

    def test_a_fresh_router_holds_nothing(self) -> None:
        app = FastAPI()
        app.include_router(build_flop_router(index_with_genesis()))
        with TestClient(app) as fresh:
            body = fresh.get(f"{FLOP_PREFIX}/testnet/state").json()
        assert body["heldPreparedActions"] == 0
        assert isinstance(InMemorySpentStore(), InMemorySpentStore)


class TestTheNetworkMarkerIsExcludedRatherThanMerelyDeclared:
    """`markers` listed `network` and nothing acted on it.

    The QA pass could not find a test that used the marker, so the claim "network
    tests are excluded by default" was true only because nobody had written one.
    A marker with no filter behind it is documentation, and the first test that
    uses it would have gone straight out to the internet inside `gate.py`.
    """

    def test_the_default_options_deselect_it(self) -> None:
        import tomllib

        config = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        options = config["tool"]["pytest"]["ini_options"]
        assert "network" in " ".join(options["markers"])
        assert "not network" in options["addopts"]

    def test_this_very_session_ran_with_that_filter(self, pytestconfig) -> None:  # type: ignore[no-untyped-def]
        assert "not network" in (pytestconfig.getoption("-m") or "")
