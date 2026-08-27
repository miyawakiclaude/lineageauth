"""Run the API with a demo bundle loaded, so the Explorer has something to show.

Development only. It builds its events with the unsafe test keys, which is the
whole reason it is a script in `scripts/` and not a documented entry point:
those keys are public, deterministic, and must never hold real authority.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402
from tests.testkeys import (  # noqa: E402
    AGENT_1,
    OUTSIDER,
    RECOVERY_1,
    RECOVERY_2,
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
    build_dispute_open,
    build_jury_vote,
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

# Comfortably in the past. Events dated ahead of the reader's clock still count
# -- issuedAt is not a validity window (D-033) -- but the resolver says so on
# every screen, and a demo whose every panel opens with that warning teaches the
# wrong lesson about which warnings matter.
AT = datetime.now(tz=UTC) - timedelta(days=2)

ROOT = unsafe_signer(ROOT_A)
WORKER = unsafe_signer(AGENT_1)
CHECKER = unsafe_signer(RECOVERY_1)
JUROR = unsafe_signer(RECOVERY_2)
OTHER = unsafe_signer(OUTSIDER)
LINEAGE = derive_lineage_id(ROOT.did)
ARTIFACT = sha256_hex(b"the demo artifact")


def demo() -> list:
    events = [sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])]
    events.append(
        sign_payload(
            build_delegation_grant(
                lineage=LINEAGE,
                issuer=ROOT.did,
                subject=WORKER.did,
                epoch=0,
                scopes=[
                    {"namespace": "technocore", "resource": "room:lobby", "actions": ["write"]}
                ],
                not_before=AT - timedelta(days=1),
                expires_at=AT + timedelta(days=30),
                max_depth=0,
                issued_at=AT,
            ),
            [ROOT],
        )
    )
    events.append(
        sign_payload(
            build_skill_claim(
                lineage=LINEAGE,
                subject=WORKER.did,
                skill="summarise",
                evidence_refs=[ARTIFACT],
                issued_at=AT,
            ),
            [WORKER],
        )
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
            nonce=b"demo-nonce-16byt",
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
    rejected = sign_payload(
        build_task_verify(
            lineage=LINEAGE,
            task=task.event_id,
            result=result.event_id,
            verifier=CHECKER.did,
            verdict="rejected",
            issued_at=AT,
        ),
        [CHECKER],
    )
    attested = sign_payload(
        build_attestation(
            lineage=LINEAGE,
            issuer=OTHER.did,
            subject_ref=ARTIFACT,
            predicate="artifact.reviewed",
            issued_at=AT,
        ),
        [OTHER],
    )
    case = sign_payload(
        build_dispute_open(
            lineage=LINEAGE,
            opener=WORKER.did,
            task=task.event_id,
            result=result.event_id,
            reason_code="criteria-misread",
            statement="the checker tested a stale snapshot",
            jurors=[JUROR.did, OTHER.did, CHECKER.did],
            quorum=2,
            threshold=2,
            issued_at=AT,
        ),
        [WORKER],
    )
    vote = sign_payload(
        build_jury_vote(
            lineage=LINEAGE,
            case=case.event_id,
            juror=JUROR.did,
            finding="result-meets-criteria",
            reason_code="reviewed-evidence",
            issued_at=AT,
        ),
        [JUROR],
    )
    events.extend([task, claim, artifact, receipt, result, rejected, attested, case, vote])
    return events


def main() -> None:
    index = EventIndex()
    index.ingest_all(demo())
    print(f"lineage  {LINEAGE}")
    print(f"worker   {WORKER.did}")
    port = int(os.environ.get("PORT", "8765"))
    print(f"explorer http://127.0.0.1:{port}/")
    uvicorn.run(create_app(index), host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
