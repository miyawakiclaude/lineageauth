"""The emitted JSON Schemas, checked against real events.

A schema nobody validates against is decoration. These are validated with a
real validator rather than a hand-rolled one -- the same rule that keeps JCS
delegated to a library, for the same reason: a checker that disagrees with the
specification is worse than no checker, because it looks like one.

The tests that matter most are the ones about what the schemas *do not* prove.
A validator is exactly the sort of thing somebody wires into a pipeline and
then treats as approval, so every schema carries a sentence saying that a
document can validate and still be worthless, and this file makes sure that
sentence is there and true: a tampered event validates, and a verifier rejects
it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from lineageauth import catalog  # noqa: E402
from lineageauth.builders import (  # noqa: E402
    build_delegation_grant,
    build_root_create,
    sign_payload,
)
from lineageauth.envelope import Envelope  # noqa: E402
from lineageauth.identifiers import derive_lineage_id  # noqa: E402
from lineageauth.verify import verify_event  # noqa: E402
from tests.testkeys import AGENT_1, ROOT_A, unsafe_signer  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
SCHEMAS = REPO / "schemas"
EVENTS = SCHEMAS / "events"

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
LINEAGE: str = derive_lineage_id(ROOT.did)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant() -> Envelope:
    payload = build_delegation_grant(
        lineage=LINEAGE,
        issuer=ROOT.did,
        subject=AGENT.did,
        epoch=0,
        scopes=[{"namespace": "technocore", "resource": "room:lobby", "actions": ["write"]}],
        not_before=AT - timedelta(days=1),
        expires_at=AT + timedelta(days=30),
        max_depth=0,
        issued_at=AT,
    )
    return sign_payload(payload, [ROOT])


class TestTheSchemasExistForEveryRegisteredType:
    def test_one_file_per_registered_event_type(self) -> None:
        emitted = {p.name.removesuffix(".schema.json") for p in EVENTS.glob("*.schema.json")}
        assert emitted == set(catalog.ALL_EVENT_TYPES)

    def test_no_schema_exists_for_an_unregistered_type(self) -> None:
        """Otherwise the schema directory would claim types the verifier refuses."""
        emitted = {p.name.removesuffix(".schema.json") for p in EVENTS.glob("*.schema.json")}
        assert emitted - set(catalog.ALL_EVENT_TYPES) == set()

    def test_every_schema_is_itself_a_valid_json_schema(self) -> None:
        for path in [*SCHEMAS.glob("*.schema.json"), *EVENTS.glob("*.schema.json")]:
            document = load(path)
            jsonschema.Draft202012Validator.check_schema(document)

    def test_the_generator_is_deterministic(self) -> None:
        before = {
            p.relative_to(REPO).as_posix(): p.read_bytes() for p in sorted(SCHEMAS.rglob("*.json"))
        }
        done = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "generate_schemas.py")],
            capture_output=True,
            check=False,
            cwd=str(REPO),
        )
        assert done.returncode == 0, done.stderr.decode("utf-8", errors="replace")
        after = {
            p.relative_to(REPO).as_posix(): p.read_bytes() for p in sorted(SCHEMAS.rglob("*.json"))
        }
        assert before == after


class TestRealEventsValidate:
    def test_the_envelope_schema_accepts_a_real_envelope(self) -> None:
        schema = load(SCHEMAS / "envelope.schema.json")
        jsonschema.validate(json.loads(genesis().to_json()), schema)

    def test_every_published_example_validates(self) -> None:
        schema = load(SCHEMAS / "envelope.schema.json")
        for path in sorted((REPO / "examples").glob("*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            for document in raw if isinstance(raw, list) else [raw]:
                jsonschema.validate(document, schema)

    def test_a_payload_validates_against_its_own_type_schema(self) -> None:
        for envelope in (genesis(), grant()):
            payload = json.loads(envelope.to_json())["payload"]
            schema = load(EVENTS / f"{payload['type']}.schema.json")
            jsonschema.validate(payload, schema)

    def test_the_wrong_type_schema_rejects_it(self) -> None:
        payload = json.loads(genesis().to_json())["payload"]
        schema = load(EVENTS / "delegation.grant.schema.json")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(payload, schema)

    def test_an_unknown_field_is_allowed_through(self) -> None:
        """docs/24: a verifier displays unknown fields, it does not reject them.

        A closed schema would turn a forward-compatible event into a validation
        failure, which is the opposite of what the versioning rule asks for.
        """
        payload = json.loads(genesis().to_json())["payload"]
        payload["somethingFromAFutureVersion"] = {"any": "shape"}
        jsonschema.validate(payload, load(EVENTS / "root.create.schema.json"))

    def test_a_missing_common_field_is_rejected(self) -> None:
        payload = json.loads(genesis().to_json())["payload"]
        del payload["issuedAt"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(payload, load(EVENTS / "root.create.schema.json"))


class TestWhatValidationDoesNotEstablish:
    def test_a_tampered_event_still_validates(self) -> None:
        """The single most important test in this file.

        Shape is the least interesting property of a signed event. A pipeline
        that validates and proceeds has checked nothing that matters.
        """
        document = json.loads(grant().to_json())
        document["payload"]["subject"] = ROOT.did  # signature no longer covers this

        jsonschema.validate(document, load(SCHEMAS / "envelope.schema.json"))
        assert not verify_event(Envelope.model_validate(document)).integrity_ok

    def test_every_schema_says_validation_is_not_verification(self) -> None:
        for path in [*SCHEMAS.glob("*.schema.json"), *EVENTS.glob("*.schema.json")]:
            description = str(load(path).get("description", ""))
            assert "Validation here is not verification" in description, path.name

    def test_the_did_pattern_admits_that_it_checks_only_the_alphabet(self) -> None:
        schema = load(EVENTS / "root.create.schema.json")
        description = schema["$defs"]["didKey"]["description"]
        assert "not the multicodec prefix" in description

    def test_a_syntactically_valid_did_with_the_wrong_codec_is_not_caught_here(self) -> None:
        """Stated rather than fixed: a regex cannot decode multibase."""
        import re

        schema = load(EVENTS / "root.create.schema.json")
        pattern = schema["$defs"]["didKey"]["pattern"]
        # An X25519 did:key -- correct alphabet, wrong key type entirely.
        x25519 = "did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
        assert re.match(pattern, x25519)

        from lineageauth.didkey import DidKeyError, public_key_from_did_key

        with pytest.raises(DidKeyError):
            public_key_from_did_key(x25519)
