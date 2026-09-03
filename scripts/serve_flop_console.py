"""Run the API with a demo bundle loaded, so the FLOP Console has something to show.

Development only, exactly like `scripts/serve_explorer.py`: it builds its
events with the public, deterministic, unsafe test keys, and those keys must
never hold real authority. `flop_demo_mode=True` turns on the synthetic
activity adapter, so every mock record still carries `synthetic: true` and
the `SYNTHETIC MOCK DATA` banner -- this script decides whether the mock
source is consulted, never whether its output is labelled.

The bundle carries one delegation whose scope is the shape a FLOP testnet
inference call would take under this project's design: `http` /
`host:testnet.simulation.invalid` / `post`, approval mode `required`, with
`ROOT` as the sole designated approver (D-107). No new authority namespace is
introduced -- `docs/FLOP_TESTNET_EXECUTOR.md` records why.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402
from tests.testkeys import (  # noqa: E402
    AGENT_1,
    RECOVERY_1,
    ROOT_A,
    unsafe_signer,
)

from lineageauth.actions import sha256_hex  # noqa: E402
from lineageauth.api import create_app  # noqa: E402
from lineageauth.builders import (  # noqa: E402
    build_artifact_receipt,
    build_artifact_register,
    build_attestation,
    build_delegation_grant,
    build_profile_statement,
    build_root_create,
    build_skill_claim,
    build_task_claim,
    build_task_request,
    build_task_result,
    build_task_verify,
    sign_payload,
)
from lineageauth.identifiers import derive_lineage_id  # noqa: E402
from lineageauth.index import EventIndex  # noqa: E402

# Comfortably in the past. `at` is a parameter everywhere this bundle is read,
# never the wall clock, so a demo dated ahead of the reader's own clock is not
# the failure mode this needs to avoid (D-033) -- it is dated behind it purely
# so every screen opens without a "this happened in the future" caveat.
AT = datetime.now(tz=UTC) - timedelta(days=3)

ROOT_SIGNER = unsafe_signer(ROOT_A)
WORKER = unsafe_signer(AGENT_1)
VERIFIER = unsafe_signer(RECOVERY_1)
LINEAGE = derive_lineage_id(ROOT_SIGNER.did)
ARTIFACT_A = sha256_hex(b"flop console demo artifact one")
ARTIFACT_B = sha256_hex(b"flop console demo artifact two")

# `testnet.simulation.invalid` is `FlopEndpointRegistry.SIMULATION_ORIGIN`'s
# host -- reserved by RFC 6761 and guaranteed not to resolve. Granting a scope
# over it demonstrates the exact-action pattern without naming a host that
# could ever be reached.
FLOP_INFERENCE_HOST = "testnet.simulation.invalid"


def demo() -> list[Any]:
    events = [
        sign_payload(build_root_create(root_did=ROOT_SIGNER.did, issued_at=AT), [ROOT_SIGNER])
    ]

    events.append(
        sign_payload(
            build_delegation_grant(
                lineage=LINEAGE,
                issuer=ROOT_SIGNER.did,
                subject=WORKER.did,
                epoch=0,
                scopes=[
                    {
                        "namespace": "http",
                        "resource": f"host:{FLOP_INFERENCE_HOST}",
                        "actions": ["post"],
                    },
                    {
                        "namespace": "technocore",
                        "resource": "room:lobby",
                        "actions": ["write"],
                    },
                ],
                not_before=AT - timedelta(days=1),
                expires_at=AT + timedelta(days=30),
                max_depth=0,
                approval="required",
                approvers=[ROOT_SIGNER.did],
                issued_at=AT,
            ),
            [ROOT_SIGNER],
        )
    )

    events.append(
        sign_payload(
            build_profile_statement(
                lineage=LINEAGE,
                subject=WORKER.did,
                nickname="flop-console-demo-worker",
                description="reviews FLOP official sources for the console demo",
                issued_at=AT,
            ),
            [WORKER],
        )
    )
    events.append(
        sign_payload(
            build_skill_claim(
                lineage=LINEAGE,
                subject=WORKER.did,
                skill="protocol-review",
                evidence_refs=[ARTIFACT_A],
                issued_at=AT,
            ),
            [WORKER],
        )
    )

    artifacts = (
        (ARTIFACT_A, "urn:demo:flop-console-notes"),
        (ARTIFACT_B, "urn:demo:flop-safety-scan-rules"),
    )
    for artifact_id, uri in artifacts:
        events.append(
            sign_payload(
                build_artifact_register(
                    lineage=LINEAGE,
                    artifact_id=artifact_id,
                    created_by=WORKER.did,
                    uri=uri,
                    issued_at=AT,
                ),
                [WORKER],
            )
        )
        events.append(
            sign_payload(
                build_artifact_receipt(
                    lineage=LINEAGE, artifact_id=artifact_id, worker=WORKER.did, issued_at=AT
                ),
                [WORKER],
            )
        )

    events.append(
        sign_payload(
            build_attestation(
                lineage=LINEAGE,
                issuer=VERIFIER.did,
                subject_ref=ARTIFACT_A,
                predicate="artifact.reviewed",
                issued_at=AT,
            ),
            [VERIFIER],
        )
    )

    task = sign_payload(
        build_task_request(
            lineage=LINEAGE,
            requester=VERIFIER.did,
            title="summarise the FLOP teaser draft",
            acceptance_criteria=["every provisional figure marked provisional"],
            issued_at=AT,
        ),
        [VERIFIER],
    )
    claim = sign_payload(
        build_task_claim(
            lineage=LINEAGE,
            task=task.event_id,
            claimant=WORKER.did,
            nonce=b"flop-demo-nonce1",
            expires_at=AT + timedelta(days=2),
            issued_at=AT,
        ),
        [WORKER],
    )
    result = sign_payload(
        build_task_result(
            lineage=LINEAGE,
            task=task.event_id,
            claim=claim.event_id,
            worker=WORKER.did,
            artifact_refs=[ARTIFACT_A],
            summary="summarised, every figure marked provisional",
            issued_at=AT,
        ),
        [WORKER],
    )
    verify = sign_payload(
        build_task_verify(
            lineage=LINEAGE,
            task=task.event_id,
            result=result.event_id,
            verifier=VERIFIER.did,
            verdict="accepted",
            issued_at=AT,
        ),
        [VERIFIER],
    )
    events.extend([task, claim, result, verify])
    return events


def main() -> None:
    index = EventIndex()
    index.ingest_all(demo())
    print(f"lineage  {LINEAGE}")
    print(f"worker   {WORKER.did}")
    port = int(os.environ.get("PORT", "8792"))
    print(f"flop console http://127.0.0.1:{port}/flop")
    uvicorn.run(
        create_app(
            index,
            flop_demo_mode=True,
            flop_demo_approver=ROOT_SIGNER.did,
            # The key stays in this script. The app receives a function.
            flop_demo_sign_receipt=lambda payload: sign_payload(payload, [ROOT_SIGNER]),
        ),
        host="127.0.0.1",
        port=port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
