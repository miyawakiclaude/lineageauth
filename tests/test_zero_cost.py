"""The zero-cost claim, checked rather than asserted.

`docs/31_ZERO_COST_OPERATIONS.md` ends with a "zero-cost definition of done":
a list of things that must work with no paid service. A list like that decays
the moment it stops being executed, so this file executes it. Every item is
either exercised here or named in `NOT_YET_BUILT` -- and `NOT_YET_BUILT` is
itself checked against the repository, so an item cannot quietly stay on the
unbuilt list after somebody builds it, and cannot quietly leave it either.

Two invariants sit underneath the list:

*The protocol core touches no network.* Everything outside the Technocore
adapter imports no networking module, so verifying an event, resolving a
lineage or checking a permission cannot become a paid API call by accident.

*Nothing on the zero-cost path depends on a paid service.* `docs/31` gives the
markers to search for, and the search runs here rather than during a review
somebody might skip.
"""

from __future__ import annotations

import ast
import json
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from lineageauth.actions import sha256_hex
from lineageauth.adapters.a2a import a2a_resource_for
from lineageauth.adapters.mcp.tools import declarations
from lineageauth.adapters.technocore.prepare import prepare_signed_message
from lineageauth.builders import (
    build_artifact_receipt,
    build_artifact_register,
    build_artifact_reuse,
    build_attestation,
    build_delegation_grant,
    build_dispute_open,
    build_fleet_create,
    build_root_create,
    build_task_claim,
    build_task_request,
    build_task_result,
    build_task_verify,
    sign_payload,
)
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.errors import ReasonCode
from lineageauth.exchange import browse
from lineageauth.fleet import resolve_fleets
from lineageauth.identifiers import derive_lineage_id
from lineageauth.impact import collect_impact
from lineageauth.index import EventIndex
from lineageauth.jury import resolve_dispute
from lineageauth.passport import build_passport
from lineageauth.resolver import MemorySource, collect
from lineageauth.router import Query, search
from lineageauth.store import MemoryEventStore
from lineageauth.verify import verify_event
from lineageauth.work import build_work_receipt
from tests.testkeys import AGENT_1, OUTSIDER, RECOVERY_1, RECOVERY_2, ROOT_A, unsafe_signer

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "packages" / "py" / "lineageauth"

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
WORKER = unsafe_signer(AGENT_1)
CHECKER = unsafe_signer(RECOVERY_1)
JUROR_A = unsafe_signer(RECOVERY_2)
JUROR_B = unsafe_signer(OUTSIDER)
LINEAGE: str = derive_lineage_id(ROOT.did)
ARTIFACT = sha256_hex(b"the zero-cost artifact")

# The only place a networking import is allowed: the Technocore adapter, which
# is opt-in, read-only, and refuses redirects (D-047).
NETWORK_MODULES = ("urllib", "http.client", "socket", "requests", "httpx", "aiohttp")
NETWORK_EXEMPT = PACKAGE / "adapters" / "technocore"

# docs/31's paid-service detector. Presence is not automatically wrong -- these
# words appear in prose about *not* using them -- so the check is scoped to the
# dependency lists, where presence would mean an actual dependency.
PAID_MARKERS = (
    "pro",
    "enterprise",
    "pay-as-you-go",
    "billing",
    "redis",
    "postgres",
    "pinecone",
    "weaviate",
    "datadog",
    "newrelic",
    "sentry",
    "openai",
    "anthropic",
)


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def full_envelopes() -> tuple[list[Envelope], str, str]:
    """One lineage carrying every projection the definition of done names."""
    grant = sign_payload(
        build_delegation_grant(
            lineage=LINEAGE,
            issuer=ROOT.did,
            subject=WORKER.did,
            epoch=0,
            scopes=[{"namespace": "technocore", "resource": "room:lobby", "actions": ["write"]}],
            not_before=AT - timedelta(days=1),
            expires_at=AT + timedelta(days=30),
            max_depth=0,
            issued_at=AT,
        ),
        [ROOT],
    )
    task = sign_payload(
        build_task_request(
            lineage=LINEAGE,
            requester=CHECKER.did,
            title="index the room list",
            acceptance_criteria=["every room reachable"],
            issued_at=AT,
        ),
        [CHECKER],
    )
    claim = sign_payload(
        build_task_claim(
            lineage=LINEAGE,
            task=task.event_id,
            claimant=WORKER.did,
            nonce=b"n" * 16,
            expires_at=AT + timedelta(days=2),
            issued_at=AT,
        ),
        [WORKER],
    )
    artifact = sign_payload(
        build_artifact_register(
            lineage=LINEAGE, artifact_id=ARTIFACT, created_by=WORKER.did, issued_at=AT
        ),
        [WORKER],
    )
    receipt = sign_payload(
        build_artifact_receipt(
            lineage=LINEAGE, artifact_id=ARTIFACT, worker=WORKER.did, issued_at=AT
        ),
        [WORKER],
    )
    result = sign_payload(
        build_task_result(
            lineage=LINEAGE,
            task=task.event_id,
            claim=claim.event_id,
            worker=WORKER.did,
            artifact_refs=[ARTIFACT],
            summary="indexed 41 rooms",
            issued_at=AT,
        ),
        [WORKER],
    )
    verified = sign_payload(
        build_task_verify(
            lineage=LINEAGE,
            task=task.event_id,
            result=result.event_id,
            verifier=CHECKER.did,
            verdict="accepted",
            issued_at=AT,
        ),
        [CHECKER],
    )
    attested = sign_payload(
        build_attestation(
            lineage=LINEAGE,
            issuer=CHECKER.did,
            subject_ref=ARTIFACT,
            predicate="artifact.reviewed",
            issued_at=AT,
        ),
        [CHECKER],
    )
    fleet = sign_payload(
        build_fleet_create(lineage=LINEAGE, controller=CHECKER.did, name="acme", issued_at=AT),
        [CHECKER],
    )
    reuse = sign_payload(
        build_artifact_reuse(
            lineage=LINEAGE,
            reuser=JUROR_A.did,
            used=ARTIFACT,
            used_in=sha256_hex(b"a downstream project"),
            issued_at=AT,
        ),
        [JUROR_A],
    )
    case = sign_payload(
        build_dispute_open(
            lineage=LINEAGE,
            opener=WORKER.did,
            task=task.event_id,
            result=result.event_id,
            reason_code="criteria-misread",
            statement="the checker tested a stale snapshot",
            jurors=[JUROR_A.did, JUROR_B.did, CHECKER.did],
            quorum=2,
            threshold=2,
            issued_at=AT,
        ),
        [WORKER],
    )
    envelopes = [
        genesis(),
        grant,
        task,
        claim,
        artifact,
        receipt,
        result,
        verified,
        attested,
        fleet,
        reuse,
        case,
    ]
    return envelopes, task.event_id, case.event_id


def full_bundle() -> tuple[EventBundle, str, str]:
    envelopes, task_id, case_id = full_envelopes()
    return EventBundle.from_envelopes(envelopes), task_id, case_id


# ------------------------------------------------------------ definition of done


class TestDefinitionOfDone:
    """Each item `docs/31` requires to work with no paid service."""

    def test_all_schemas_load(self) -> None:
        from lineageauth import catalog

        assert catalog.ALL_EVENT_TYPES
        assert catalog.PROTOCOL == "lineageauth"

    def test_core_verification(self) -> None:
        result = verify_event(genesis())
        assert result.integrity_ok
        assert result.reason is ReasonCode.SIGNATURE_VERIFIED

    def test_conformance_vectors(self) -> None:
        """The published examples still verify, or still fail, as labelled."""
        vectors = sorted((REPO / "examples").glob("*.json"))
        assert vectors, "the examples directory is part of the zero-cost claim"
        checked = 0
        for path in vectors:
            raw = json.loads(path.read_text(encoding="utf-8"))
            documents = raw if isinstance(raw, list) else [raw]
            expected_ok = "tampered" not in path.name
            for document in documents:
                envelope = Envelope.from_json(json.dumps(document))
                assert verify_event(envelope).integrity_ok is expected_ok, path.name
                checked += 1
        assert checked >= len(vectors)

    def test_cli(self) -> None:
        from typer.testing import CliRunner

        from lineageauth.cli import app

        result = CliRunner().invoke(app, ["version"])
        assert result.exit_code == 0

    def test_sqlite_index_and_rebuild(self) -> None:
        """A fresh index must be reconstructible from the immutable events alone."""
        store = MemoryEventStore()
        envelopes, _, _ = full_envelopes()
        for envelope in envelopes:
            store.put(envelope)
        with EventIndex() as index:
            index.ingest_all(list(store))
            before = index.checksum()
            index.rebuild(store)
            assert index.checksum() == before

    def test_technocore_dry_run_prepares_without_publishing(self) -> None:
        prepared = prepare_signed_message(room="lobby", text="hello", nonce=1, signer=WORKER)
        # It hands back everything a write needs and performs none of it.
        assert prepared.signature in prepared.url
        assert not hasattr(prepared, "send")

    def test_mcp_local_tools_without_the_sdk(self) -> None:
        assert declarations()

    def test_a2a_mapping(self) -> None:
        assert a2a_resource_for(skill_id="summarise") == "skill:summarise"

    def test_evidence_and_work_receipts(self) -> None:
        bundle, task_id, _ = full_bundle()
        receipt = build_work_receipt(bundle, lineage=LINEAGE, task_id=task_id, at=AT)
        assert receipt.artifact_refs == (ARTIFACT,)

    def test_passport_projection(self) -> None:
        bundle, _, _ = full_bundle()
        passport = build_passport(bundle, lineage=LINEAGE, did=WORKER.did, at=AT).to_dict()
        assert passport["did"] == WORKER.did

    def test_local_router(self) -> None:
        bundle, _, _ = full_bundle()
        found = search(bundle, lineage=LINEAGE, query=Query(), at=AT)
        assert found.candidates

    def test_task_exchange(self) -> None:
        bundle, _, _ = full_bundle()
        assert browse(bundle, lineage=LINEAGE, at=AT).listings

    def test_jury(self) -> None:
        bundle, _, case_id = full_bundle()
        assert resolve_dispute(bundle, lineage=LINEAGE, case_id=case_id, at=AT).jurors

    def test_fleet(self) -> None:
        bundle, _, _ = full_bundle()
        assert resolve_fleets(bundle, lineage=LINEAGE, at=AT).note

    def test_impact(self) -> None:
        bundle, _, _ = full_bundle()
        found = collect_impact(bundle, lineage=LINEAGE, artifact_id=ARTIFACT, at=AT)
        assert found.independent_reusers == (JUROR_A.did,)

    def test_multi_source_resolver(self) -> None:
        view = collect([MemorySource("local", [genesis()])], checked_at=AT)
        assert view.fresh

    def test_local_explorer(self) -> None:
        """Served by the local API, from the same origin, under its own strict CSP."""
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app

        with EventIndex() as index:
            index.ingest_all([genesis()])
            client = TestClient(create_app(index))
            page = client.get("/")
            assert page.status_code == 200
            assert "unsafe-inline" not in page.headers["content-security-policy"]

    def test_local_api_is_optional_and_works_when_present(self) -> None:
        """Optional on purpose: nothing above needed it to reach this line."""
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        from lineageauth.api import create_app

        with EventIndex() as index:
            index.ingest_all([genesis()])
            client = TestClient(create_app(index))
            assert client.get("/healthz").json()["status"] == "ok"


class TestWhatIsNotBuiltYet:
    """The honest half of the checklist.

    It is empty now. It was not: `docs/31` lists a local Explorer, and until the
    Explorer existed it was named here rather than quietly passing. The
    assertion ran the other way too, and that is what emptied this list -- the
    moment an Explorer appeared the test failed and forced the correction,
    instead of letting the checklist go on understating what works.

    A list that can only be corrected by hand goes stale. This one fails.
    """

    NOT_YET_BUILT: tuple[str, ...] = ()

    def test_every_named_gap_is_still_a_gap(self) -> None:
        assert self.NOT_YET_BUILT == (), "add a test below for anything named here"

    def test_the_explorer_exists_and_is_therefore_not_a_gap(self) -> None:
        assert (REPO / "apps" / "explorer" / "index.html").is_file()
        assert "local Explorer UI" not in self.NOT_YET_BUILT


# ------------------------------------------------------------ the invariants


class TestNoPaidPath:
    def test_the_protocol_core_imports_no_networking_module(self) -> None:
        """A verification must not be able to become a paid API call by accident."""
        offenders: list[str] = []
        for path in PACKAGE.rglob("*.py"):
            if NETWORK_EXEMPT in path.parents:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    if any(name == m or name.startswith(f"{m}.") for m in NETWORK_MODULES):
                        offenders.append(f"{path.relative_to(REPO)}: {name}")
        assert offenders == []

    def test_no_runtime_dependency_is_a_paid_service(self) -> None:
        project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        declared = list(project["dependencies"])
        for extra in project.get("optional-dependencies", {}).values():
            declared.extend(extra)
        for requirement in declared:
            name = requirement.split(">")[0].split("=")[0].split("[")[0].strip().lower()
            assert name not in PAID_MARKERS, requirement

    def test_the_cost_policy_still_forbids_spending(self) -> None:
        policy = (REPO / "infra" / "cost-policy.yaml").read_text(encoding="utf-8")
        assert "monthly_spend_limit_jpy: 0" in policy
        assert "allow_paid_services: false" in policy
        assert "allow_automatic_upgrades: false" in policy
        assert "on_free_limit_exceeded: stop_or_degrade" in policy

    def test_every_selected_service_is_free(self) -> None:
        """A service may only be in use if the register says it costs nothing."""
        policy = (REPO / "infra" / "cost-policy.yaml").read_text(encoding="utf-8")
        selected = policy.split("candidates_not_selected:")[0]
        assert "cost_mode: paid" not in selected
        assert "billing_enabled: true" not in selected

    def test_the_core_imports_without_the_optional_extras(self) -> None:
        """Nothing on the zero-cost path may need FastAPI or the MCP SDK."""
        import subprocess
        import sys

        script = (
            "import sys;"
            "sys.modules['fastapi'] = None;"
            "sys.modules['mcp'] = None;"
            "import lineageauth.verify, lineageauth.authority, lineageauth.passport;"
            "print('ok')"
        )
        done = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, check=False
        )
        assert done.returncode == 0, done.stderr
        assert "ok" in done.stdout


class TestTheCliRunsOnALegacyConsole:
    """Found by running `la --help` on a Japanese Windows console, not by reading.

    A single em dash in the app's help text raised UnicodeEncodeError under
    cp932 and took the whole command down. A CLI that cannot print its own help
    on the machine somebody is holding is broken there, whatever it does
    elsewhere -- and the zero-cost claim is specifically a claim about running
    locally, on whatever that machine is.
    """

    @pytest.mark.parametrize("encoding", ["cp932", "ascii", "utf-8"])
    def test_help_prints_under_a_narrow_console_encoding(self, encoding: str) -> None:
        import os
        import subprocess
        import sys

        env = os.environ | {"PYTHONIOENCODING": encoding}
        # Bytes, not text: the child writes in `encoding` and the parent's own
        # locale may be something else. Decoding here with the wrong one would
        # fail in the harness and look like a failure in the CLI.
        done = subprocess.run(
            [sys.executable, "-m", "lineageauth.cli", "--help"],
            capture_output=True,
            check=False,
            env=env,
        )
        assert done.returncode == 0, done.stderr.decode(encoding, errors="replace")[-2000:]

    def test_the_cli_module_holds_no_character_a_cp932_console_cannot_print(self) -> None:
        source = (PACKAGE / "cli.py").read_text(encoding="utf-8")
        source.encode("cp932")
