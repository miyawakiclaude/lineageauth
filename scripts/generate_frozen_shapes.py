"""Capture the payload keys every builder produces, as the frozen contract.

    py -3 -m uv run python scripts/generate_frozen_shapes.py

`RELEASE.md` asks for wire formats to be "frozen with a stated compatibility
promise". A promise in prose is not one: it needs something that fails when the
promise is broken, and this is the thing it fails against.

**Why not the JSON Schemas.** They describe the envelope -- protocol, version,
type, lineage, issuedAt -- and say so in their own description (D-068). The
per-event field names are not in them, so they cannot be the contract.

**Why not the decision log.** It lists the fields, and cross-checking it against
these builders on 2026-08-28 found three places where it was wrong: `parent`,
`reason` and `previousPolicy` were optional in code and unmarked in prose. Those
were fixed. But a regex over hand-written prose is a parser for a format nobody
designed, and getting it from 23 of 24 to 24 of 24 meant it started reading
`normal` and `recovery` -- values of a `mode` field -- as field names. Freezing
should be an explicit act, so the contract is an explicit file.

**Held versus frozen.** The `authority` family -- delegation, approval, root
succession, recovery policy -- is *held*, not frozen, because `docs/PRIOR_ART.md`
finds that layer overlaps UCAN substantially. If the answer is to become a
profile of an existing standard, those shapes change, and freezing them first
would only mean unfreezing them later. Everything else is outside those
standards' scope and is frozen now.

Every builder is driven with its required arguments only, so what lands in the
file is the set of keys that are *always* present. Optional keys are deliberately
not in the contract: adding one is a compatible change, and a contract that
forbids compatible changes gets edited out of the way.
"""

from __future__ import annotations

import inspect
import itertools
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "packages" / "py"))

from tests.testkeys import (  # noqa: E402
    AGENT_1,
    OUTSIDER,
    RECOVERY_1,
    RECOVERY_2,
    RECOVERY_3,
    ROOT_A,
    ROOT_B,
    unsafe_signer,
)

from lineageauth import builders, catalog  # noqa: E402
from lineageauth.actions import ActionRequest  # noqa: E402
from lineageauth.identifiers import derive_lineage_id  # noqa: E402

OUT = REPO / "conformance" / "frozen-shapes.json"

AT = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
DIDS = [
    unsafe_signer(k).did
    for k in (ROOT_A, ROOT_B, AGENT_1, OUTSIDER, RECOVERY_1, RECOVERY_2, RECOVERY_3)
]
LINEAGE = derive_lineage_id(DIDS[0])
IDS = ["sha256:" + f"{i:02x}" * 32 for i in range(1, 9)]
REQUEST = ActionRequest(
    namespace="technocore",
    resource="room:lobby",
    action="write",
    destination="room:lobby",
    content_hash=IDS[0],
)
SCOPES = [{"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "write"]}]

# Held rather than frozen: see the module docstring.
HELD_FAMILIES = frozenset({"authority"})

_DID_WORDS = (
    "did",
    "root",
    "issuer",
    "subject",
    "worker",
    "approver",
    "agent",
    "requester",
    "claimant",
    "opener",
    "juror",
    "verifier",
    "controller",
    "member",
    "coordinator",
    "author",
    "reuser",
    "attester",
)
_ID_WORDS = (
    "hash",
    "task",
    "result",
    "claim",
    "case",
    "artifact",
    "used",
    "improves",
    "parent",
    "policy",
    "bind",
    "fleet",
    "verification",
)


def _argument(name: str, dids: Any, ids: Any) -> Any:
    """A plausible value, chosen by parameter name.

    `_ref` is tested before the DID words on purpose: `subject_ref` contains
    "subject" and was being handed a DID, which is the same substring-precedence
    mistake that put a CSS token in the wire-format pile earlier the same day.
    """
    n = name.lower()
    if "issued_at" in n:
        return AT
    if "not_before" in n:
        return AT - timedelta(days=1)
    if "expires" in n or "deadline" in n:
        return AT + timedelta(days=1)
    if n == "request":
        return REQUEST
    if "lineage" in n:
        return LINEAGE
    if "scopes" in n:
        return SCOPES
    if "nonce" in n:
        return bytes(range(16))
    if any(k in n for k in ("members", "pool", "jurors")):
        return DIDS[4:7]
    if "criteria_results" in n:
        return [("it works", True)]
    if "criteria" in n:
        return ["it works"]
    if "conflicts" in n:
        return ["same-fleet"]
    if n.endswith("refs") or "sources" in n:
        return [next(ids)]
    if n.endswith("ref"):
        return next(ids)
    if any(
        k in n
        for k in (
            "epoch",
            "seq",
            "depth",
            "threshold",
            "seats",
            "quorum",
            "claims",
            "count",
            "length",
        )
    ):
        return 1
    if any(k in n for k in _DID_WORDS):
        return next(dids)
    if any(k in n for k in _ID_WORDS):
        return next(ids)
    if "available" in n:
        return True
    if "mode" in n:
        return "normal"
    if "verdict" in n:
        return "accepted"
    if "finding" in n:
        return "result-meets-criteria"
    if "selection" in n:
        return "named"
    if "approval" in n:
        return "none"
    return "a statement with words in it"


# Builders whose validation rules a name-based guess cannot satisfy.
OVERRIDES: dict[str, dict[str, Any]] = {
    "build_dispute_open": {
        "pool": None,
        "jurors": DIDS[4:7],
        "seats": 3,
        "quorum": 3,
        "threshold": 2,
    },
    "build_profile_statement": {
        "nickname": "fantasypolka",
        "description": "I verify Ed25519 signatures offline.",
    },
}


def shapes() -> dict[str, list[str]]:
    """`{event type: sorted required keys}` for every builder that produces one."""
    out: dict[str, list[str]] = {}
    for name in sorted(n for n in dir(builders) if n.startswith("build_")):
        fn = getattr(builders, name)
        dids, ids = itertools.cycle(DIDS), itertools.cycle(IDS)
        kwargs = {
            pname: _argument(pname, dids, ids)
            for pname, p in inspect.signature(fn).parameters.items()
            if p.kind is not inspect.Parameter.VAR_KEYWORD and p.default is inspect.Parameter.empty
        }
        for key, value in OVERRIDES.get(name, {}).items():
            if value is None:
                kwargs.pop(key, None)
            else:
                kwargs[key] = value
        payload = fn(**kwargs)
        if isinstance(payload, dict) and "type" in payload:
            out[str(payload["type"])] = sorted(payload)
    return out


def document() -> dict[str, Any]:
    family_of = {
        event: family.lower()
        for family in ("AUTHORITY", "EVIDENCE", "WORK", "FLEET", "IMPACT", "JURY", "PASSPORT")
        for event in getattr(catalog, f"{family}_EVENT_TYPES", frozenset())
    }
    built = shapes()
    doc: dict[str, Any] = {
        "note": (
            "The payload keys every registered event type always carries, captured "
            "from the builders by scripts/generate_frozen_shapes.py. A family marked "
            "frozen will not gain, lose or rename a required key without a decision "
            "entry saying so. A family marked held is waiting on the prior-art "
            "question in docs/PRIOR_ART.md: if that layer becomes a profile of an "
            "existing standard, its shapes change. Optional keys are not listed -- "
            "adding one is a compatible change."
        ),
        "generated_by": "scripts/generate_frozen_shapes.py",
        "protocol": catalog.PROTOCOL,
        "version": sorted(catalog.SUPPORTED_VERSIONS)[0],
        "families": {},
    }
    for event in sorted(built):
        family = family_of.get(event, "other")
        block = doc["families"].setdefault(
            family,
            {"status": "held" if family in HELD_FAMILIES else "frozen", "events": {}},
        )
        block["events"][event] = {"required": built[event]}
    return doc


def main() -> int:
    doc = document()
    OUT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    covered = {e for block in doc["families"].values() for e in block["events"]}
    missing = sorted(set(catalog.ALL_EVENT_TYPES) - covered)

    print(f"wrote {OUT.relative_to(REPO)}")
    for family, block in sorted(doc["families"].items()):
        print(f"  {block['status']:7} {family:10} {len(block['events'])} event type(s)")
    if missing:
        # `work.receipt` is derived from other events and has no builder, so it
        # has no payload of its own to freeze. Named rather than omitted.
        print(f"\n  no builder, nothing to freeze: {', '.join(missing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
