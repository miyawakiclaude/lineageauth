"""Build the conformance vector package in `conformance/`.

Run: `uv run python scripts/generate_conformance.py`

`CONTRIBUTING.md` asks for one thing above all others: an independent
implementation that *disagrees* with this one. A disagreement is only useful if
both sides are answering the same question, so this package fixes the
questions.

Each vector states the verdict a conforming implementation must reach and, more
importantly, **why** -- so a failure names the rule that was broken instead of
just a mismatch. The negative vectors are the point of the package. Anyone can
accept a valid event; the value is in refusing the right things for the right
reasons, and most of these were bugs in this implementation before they were
vectors.

Deterministic: fixed UNSAFE test keys, fixed times, sorted output. Regenerating
produces byte-identical files, so a diff is a protocol change.

!! The keys behind these signatures are public and reproducible. Nothing here
!! is safe key material and none of these DIDs may be used for anything real.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "packages" / "py"))

from tests.testkeys import AGENT_1, OUTSIDER, ROOT_A, unsafe_signer  # noqa: E402

from lineageauth.actions import sha256_hex  # noqa: E402
from lineageauth.builders import (  # noqa: E402
    build_artifact_receipt,
    build_artifact_register,
    build_delegation_grant,
    build_delegation_revoke,
    build_root_create,
    sign_payload,
)
from lineageauth.envelope import Envelope  # noqa: E402
from lineageauth.identifiers import derive_lineage_id  # noqa: E402

OUT = REPO_ROOT / "conformance"
AT = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE = derive_lineage_id(ROOT.did)
ARTIFACT = sha256_hex(b"a conformance artifact")

VALID = "must-verify"
INVALID = "must-refuse"


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, subject: str | None = None) -> Envelope:
    payload = build_delegation_grant(
        lineage=LINEAGE,
        issuer=ROOT.did,
        subject=subject or AGENT.did,
        epoch=0,
        scopes=[{"namespace": "technocore", "resource": "room:lobby", "actions": ["write"]}],
        not_before=AT - timedelta(days=1),
        expires_at=AT + timedelta(days=365),
        max_depth=0,
        issued_at=AT,
    )
    return sign_payload(payload, [ROOT])


def as_document(envelope: Envelope) -> Any:
    return json.loads(envelope.to_json())


def vectors() -> list[dict[str, Any]]:
    """Every vector, with the rule it pins.

    Ordered by what they teach rather than by phase: the shape of a valid event
    first, then each way a document can look right and be wrong.
    """
    held = grant()
    revoked = sign_payload(
        build_delegation_revoke(
            lineage=LINEAGE,
            issuer=ROOT.did,
            grant=held.event_id,
            reason="key rotated",
            issued_at=AT + timedelta(days=1),
        ),
        [ROOT],
    )

    # A receipt naming a worker who did not sign it. It is well-formed, it
    # verifies as an envelope, and the authorship claim inside it is worth
    # nothing -- which is a different verdict from "refuse the event".
    unsigned_authorship = sign_payload(
        build_artifact_receipt(
            lineage=LINEAGE, artifact_id=ARTIFACT, worker=AGENT.did, issued_at=AT
        ),
        [STRANGER],
    )

    tampered = as_document(held)
    tampered["payload"]["subject"] = ROOT.did

    padded = as_document(genesis())
    padded["proofs"][0]["sig"] = padded["proofs"][0]["sig"] + "="

    wrong_type = as_document(genesis())
    wrong_type["payload"]["type"] = "root.summon"

    return [
        {
            "name": "root-create-valid",
            "expect": VALID,
            "rule": "A genesis event signed by the root it names verifies.",
            "documents": [as_document(genesis())],
        },
        {
            "name": "delegation-grant-valid",
            "expect": VALID,
            "rule": "A grant signed by the issuer it names verifies.",
            "documents": [as_document(genesis()), as_document(held)],
        },
        {
            "name": "delegation-revoked",
            "expect": VALID,
            "rule": (
                "Every event here verifies. A conforming implementation must "
                "additionally resolve the grant as REVOKED -- integrity and "
                "authority are separate questions and a vector can require both."
            ),
            "documents": [as_document(genesis()), as_document(held), as_document(revoked)],
            "authority": {
                "agent": AGENT.did,
                "namespace": "technocore",
                "resource": "room:lobby",
                "action": "write",
                "at": "2026-01-03T00:00:00Z",
                "expect": "deny",
                "reason": "REVOKED",
            },
        },
        {
            "name": "receipt-not-signed-by-its-worker",
            "expect": VALID,
            "rule": (
                "Three verdicts on one bundle, and they are not the same verdict. "
                "The envelopes VERIFY -- integrity is about signatures over "
                "payloads, and these are intact. The registration is ADMITTED with "
                "its createdBy reported as a claim nobody with that key signed "
                "(D-051). The receipt's authorship claim does NOT STAND at all: a "
                "receipt is the worker's own assertion, so one naming a worker who "
                "did not sign it must not borrow their name, and it is dropped with "
                "a warning rather than collected (D-052). An implementation that "
                "fails the envelope is wrong; one that credits the worker is wrong."
            ),
            "documents": [
                as_document(genesis()),
                as_document(
                    sign_payload(
                        build_artifact_register(
                            lineage=LINEAGE,
                            artifact_id=ARTIFACT,
                            created_by=AGENT.did,
                            issued_at=AT,
                        ),
                        [STRANGER],
                    )
                ),
                as_document(unsigned_authorship),
            ],
        },
        {
            "name": "tampered-payload",
            "expect": INVALID,
            "rule": (
                "One byte of the payload changed after signing. The signature "
                "covers the canonical payload, so this must fail integrity."
            ),
            "documents": [tampered],
        },
        {
            "name": "padded-base64url",
            "expect": INVALID,
            "rule": (
                "A padded signature must be refused. base64url here is "
                "unpadded and canonical; accepting '=' would admit two encodings "
                "of one signature and break the one-event-one-id property."
            ),
            "documents": [padded],
        },
        {
            "name": "unregistered-event-type",
            "expect": INVALID,
            "rule": (
                "An unregistered type must not be given semantics. docs/24 fails "
                "closed here: an admitted event reads as a counted one."
            ),
            "documents": [wrong_type],
        },
        {
            "name": "wrong-multicodec-did",
            "expect": INVALID,
            "rule": (
                "An X25519 did:key is syntactically a did:key and is not a "
                "signing key. Only the Ed25519 multicodec (0xed 0x01) is accepted."
            ),
            "documents": [
                {
                    "payload": {
                        "protocol": "lineageauth",
                        "version": "0.1",
                        "type": "root.create",
                        "lineage": "lineage:la:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                        "issuedAt": "2026-01-01T00:00:00Z",
                        "root": "did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                        "epoch": 0,
                    },
                    "proofs": [],
                }
            ],
        },
        {
            "name": "no-proofs",
            "expect": INVALID,
            "rule": "An envelope with no proof asserts nothing and must not be admitted.",
            "documents": [{"payload": as_document(genesis())["payload"], "proofs": []}],
        },
    ]


def write(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    cases = vectors()
    manifest = {
        "protocol": "lineageauth",
        "version": "0.1",
        "note": (
            "Each vector states the verdict a conforming implementation must reach "
            "and the rule behind it. The negative vectors are the point: anyone can "
            "accept a valid event, and the value is in refusing the right things for "
            "the right reasons. A disagreement with this package is worth an issue -- "
            "it may well be this implementation that is wrong."
        ),
        "vectors": [
            {
                "name": case["name"],
                "file": f"vectors/{case['name']}.json",
                "expect": case["expect"],
                "rule": case["rule"],
                **({"authority": case["authority"]} if "authority" in case else {}),
            }
            for case in cases
        ],
    }
    for case in cases:
        write(OUT / "vectors" / f"{case['name']}.json", case["documents"])
    write(OUT / "manifest.json", manifest)
    print(f"wrote {len(cases)} vector(s) and a manifest to {OUT}")


if __name__ == "__main__":
    main()
