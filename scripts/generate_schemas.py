"""Emit JSON Schema for the envelope and for every registered event type.

Run: `uv run python scripts/generate_schemas.py`

Deterministic, like the example generator: same input, byte-identical output,
so a diff in `schemas/` is a protocol change and never a formatting one.

What these schemas are and are not
----------------------------------

They describe **shape**, and shape is the least interesting thing about a
LineageAuth event. Passing one of these says a document has the right fields
with the right primitive types. It says nothing about whether a signature
verifies, whether the signer holds the authority it claims, whether the event
id matches the payload, or whether the chain above it is intact -- and every
one of those is where the actual security lives.

So each schema carries that sentence in its own description. A validator is
exactly the sort of tool somebody wires up and then treats as approval, and a
schema that does not say what it leaves unchecked invites that.

The event-type schemas are generated from `catalog.py` and are deliberately
open (`additionalProperties: true`): `docs/24` requires a verifier to reject an
*unknown type* while still displaying unknown *fields* under an
UNKNOWN_VERSION status, and a closed schema would turn a forward-compatible
event into a validation failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "packages" / "py"))

from lineageauth import catalog  # noqa: E402
from lineageauth.envelope import Envelope  # noqa: E402

SCHEMA_DIR = REPO_ROOT / "schemas"
SCHEMA_VERSION = "https://json-schema.org/draft/2020-12/schema"
BASE_URI = "https://github.com/miyawakiclaude/lineageauth/blob/main/schemas"

SHAPE_ONLY = (
    "This schema describes shape only. A document that validates against it may "
    "still carry an invalid signature, a signer with no authority, an event id "
    "that does not match its payload, or a broken chain above it -- none of which "
    "a JSON Schema can express. Validation here is not verification; run a "
    "LineageAuth verifier."
)

EVENT_ID = {
    "type": "string",
    "pattern": "^sha256:[0-9a-f]{64}$",
    "description": "A LineageAuth event id: sha256 over the signing preimage.",
}

DID_KEY = {
    "type": "string",
    "pattern": "^did:key:z[1-9A-HJ-NP-Za-km-z]+$",
    "description": (
        "An Ed25519 did:key in canonical multibase base58btc. The pattern checks "
        "the alphabet, not the multicodec prefix or the key length -- a verifier "
        "checks those."
    ),
}

INSTANT = {
    "type": "string",
    "description": "RFC3339 UTC, e.g. 2026-08-27T12:00:00Z. Self-asserted by the signer.",
}


def envelope_schema() -> dict[str, object]:
    schema = Envelope.model_json_schema()
    schema["$schema"] = SCHEMA_VERSION
    schema["$id"] = f"{BASE_URI}/envelope.schema.json"
    schema["title"] = "LineageAuth envelope"
    schema["description"] = (
        "A payload and the proofs over it. Proofs sit outside the payload so one "
        "payload can carry many signatures -- which is what makes a recovery "
        "quorum expressible. " + SHAPE_ONLY
    )
    return schema


def event_schema(event_type: str, family: str) -> dict[str, object]:
    return {
        "$schema": SCHEMA_VERSION,
        "$id": f"{BASE_URI}/events/{event_type}.schema.json",
        "title": event_type,
        "description": (
            f"The common shape of a `{event_type}` payload ({family} family). "
            "Type-specific fields are intentionally not constrained here: they "
            "are validated by the reader for that type, which can express rules a "
            "schema cannot -- that a receipt is signed by the worker it names, "
            "that a threshold is a strict majority of the seats. " + SHAPE_ONLY
        ),
        "type": "object",
        "required": ["protocol", "version", "type", "lineage", "issuedAt"],
        # Open on purpose: docs/24 wants unknown fields displayable under an
        # UNKNOWN_VERSION status, not rejected outright.
        "additionalProperties": True,
        "properties": {
            "protocol": {"const": catalog.PROTOCOL},
            "version": {
                "type": "string",
                "enum": sorted(catalog.SUPPORTED_VERSIONS),
            },
            "type": {"const": event_type},
            "lineage": {
                "type": "string",
                "pattern": "^lineage:la:z[1-9A-HJ-NP-Za-km-z]+$",
            },
            "issuedAt": INSTANT,
        },
        "$defs": {"eventId": EVENT_ID, "didKey": DID_KEY, "instant": INSTANT},
    }


def catalog_schema() -> dict[str, object]:
    return {
        "$schema": SCHEMA_VERSION,
        "$id": f"{BASE_URI}/catalog.schema.json",
        "title": "LineageAuth event catalog",
        "description": (
            "Every registered event type, by family. An unregistered type is not "
            "assumed harmless: docs/24 fails closed on an unknown authority type "
            "and admits an unknown evidence type only as undisplayed raw data. " + SHAPE_ONLY
        ),
        "type": "object",
        "properties": {
            "protocol": {"const": catalog.PROTOCOL},
            "coreVersion": {"const": catalog.CORE_VERSION},
            "families": {
                "type": "object",
                "properties": {
                    family: {
                        "type": "array",
                        "items": {"type": "string", "enum": sorted(members)},
                    }
                    for family, members in sorted(catalog.EVENT_FAMILIES.items())
                },
            },
        },
    }


def write(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" so the output is identical on every platform, and the
    # determinism check means the same thing everywhere (D-029).
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    write(SCHEMA_DIR / "envelope.schema.json", envelope_schema())
    write(SCHEMA_DIR / "catalog.schema.json", catalog_schema())
    for event_type in sorted(catalog.ALL_EVENT_TYPES):
        family = catalog.family_of(event_type) or "unknown"
        write(SCHEMA_DIR / "events" / f"{event_type}.schema.json", event_schema(event_type, family))
    written = 2 + len(catalog.ALL_EVENT_TYPES)
    print(f"wrote {written} schema(s) to {SCHEMA_DIR}")


if __name__ == "__main__":
    main()
