"""The hand-kept route table, held to the served contract (technocore-chat#430)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from lineageauth.adapters.technocore.routes import (
    Consequence,
    NamespacePolicy,
    classify,
    note_namespace_policy,
)

CONTRACT = (
    Path(__file__).resolve().parents[1] / "conformance" / "technocore" / "route-contract.json"
)
ORIGIN = "https://technocore.chat"
SAMPLE = {
    "room": "lobby",
    "nick": "bob",
    "text": "hello",
    "did": "did:key:z6Mkabc",
    "sig": "sig",
    "nonce": "7",
    "ns": "contrib",
    "key": "k1",
    "value": "v",
}


def operations() -> list[dict[str, object]]:
    return list(json.loads(CONTRACT.read_text(encoding="utf-8"))["operations"])


def render(path: str) -> str:
    return ORIGIN + re.sub(r"\{(\w+)\}", lambda m: SAMPLE[m.group(1)], path)


class TestTheContractIsPinned:
    def test_the_document_hash_and_version_are_recorded(self) -> None:
        meta = json.loads(CONTRACT.read_text(encoding="utf-8"))["_meta"]
        assert meta["sha256"].startswith("sha256:")
        assert meta["serviceVersion"] == "0.14.3"
        # D-118: re-derived at 0.14.3 with the operation set unchanged from 0.13.0.
        assert meta["previous"]["serviceVersion"] == "0.13.0"
        assert meta["previous"]["sha256"] != meta["sha256"]
        assert meta["previous"]["operationsChanged"] is False
        assert meta["sourceUrl"] == "https://technocore.chat/openapi.json"

    def test_exactly_seven_operations_mutate(self) -> None:
        assert sum(1 for op in operations() if op["mutating"]) == 7


class TestTheTableAgreesWithTheContract:
    @pytest.mark.parametrize(
        "op", [o for o in operations() if o["mutating"]], ids=lambda o: str(o["operationId"])
    )
    def test_every_mutating_operation_is_a_write_or_a_documented_refusal(
        self, op: dict[str, object]
    ) -> None:
        verdict = classify(render(str(op["path"])), method=str(op["method"])).consequence
        if op["serverRefuses"]:
            assert verdict is Consequence.UNKNOWN
        else:
            assert verdict is Consequence.WRITE, op

    @pytest.mark.parametrize(
        "op", [o for o in operations() if not o["mutating"]], ids=lambda o: str(o["operationId"])
    )
    def test_every_other_operation_is_a_read(self, op: dict[str, object]) -> None:
        verdict = classify(render(str(op["path"])), method=str(op["method"])).consequence
        assert verdict is Consequence.READ, op

    def test_a_route_the_contract_does_not_list_stays_unknown(self) -> None:
        assert classify(f"{ORIGIN}/r/lobby/erase").consequence is Consequence.UNKNOWN
        assert classify(f"{ORIGIN}/kv/ns/key/set-later/v").consequence is Consequence.UNKNOWN


class TestNoteNamespaces:
    def test_the_three_exceptions_and_the_default(self) -> None:
        assert note_namespace_policy("room-nonce") is NamespacePolicy.SERVER_ONLY
        assert note_namespace_policy("room-owners") is NamespacePolicy.OWNER_SIGNED
        assert note_namespace_policy("room-allow") is NamespacePolicy.OWNER_SIGNED
        assert note_namespace_policy("topic") is NamespacePolicy.WORLD_WRITABLE
        assert note_namespace_policy("contrib") is NamespacePolicy.WORLD_WRITABLE
