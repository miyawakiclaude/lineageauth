"""What a tclk/1 transcript becomes in LineageAuth's evidence model, and what it does not.

Frames are content, so each one is an artifact: `artifactId = sha256:<hex>` over
the frame line's bytes, registered with `artifact.register` (`docs/07`). A
contract's outcome is one party's signed opinion about the accept frame that
opened it: an `attestation.issue` whose `subjectRef` is that artifact and whose
predicate is `tclk.contract.outcome`.

That predicate is **not registered** in `KNOWN_PREDICATES`, on purpose.
Registering one is a protocol vocabulary change, which this integration does
not make (`docs/TCLK_GAP_ANALYSIS.md`, SPEC CHANGE REQUIRED). An unregistered
predicate stays displayable and cannot silently affect a ranking, which is the
right status for a claim whose truth this layer cannot check.

Everything here drafts unsigned payloads. Signing is the holder's act; nothing
is submitted anywhere. And the claims are small: an artifact proves these bytes
existed and were signed by a key; the attestation proves one DID said the
contract ended this way. Neither proves work was delivered, money moved, or the
deal was fair. Invariant 8: a deal result is evidence, not proof of truth.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from lineageauth.actions import sha256_hex
from lineageauth.adapters.tclk.frames import Frame
from lineageauth.adapters.tclk.machine import ContractState
from lineageauth.builders import build_artifact_register, build_attestation

TCLK_MEDIA_TYPE = "text/plain; profile=tclk/1"
OUTCOME_PREDICATE = "tclk.contract.outcome"
"""Unregistered by design; see the module docstring."""


def frame_artifact_id(frame: Frame | str) -> str:
    """`sha256:<hex>` over the frame line's UTF-8 bytes."""
    line = frame.line if isinstance(frame, Frame) else frame
    return sha256_hex(line.encode())


def draft_frame_artifact(
    frame: Frame, *, lineage: str, issued_at: datetime, created_by: str | None = None
) -> dict[str, Any]:
    """An `artifact.register` payload for one frame. Unsigned."""
    return build_artifact_register(
        lineage=lineage,
        artifact_id=frame_artifact_id(frame),
        media_type=TCLK_MEDIA_TYPE,
        byte_length=len(frame.line.encode()),
        created_by=created_by if created_by is not None else frame.sender,
        issued_at=issued_at,
    )


def draft_outcome_attestation(
    state: ContractState,
    *,
    accept_frame: Frame,
    lineage: str,
    issuer: str,
    issued_at: datetime,
    evidence_frames: Iterable[Frame] = (),
) -> dict[str, Any]:
    """An `attestation.issue` that `issuer` observed this contract reach `state.status`.

    Refuses a non-terminal state -- there is no outcome to attest to -- and
    refuses an accept frame that does not name the contract in `state`, so a
    verdict cannot be attached to the wrong deal.
    """
    if not state.terminal:
        raise ValueError(f"tclk: contract is not terminal (status {state.status})")
    if accept_frame.kind != "accept" or accept_frame.contract != state.contract:
        raise ValueError("tclk: accept frame does not open the contract in this state")
    return build_attestation(
        lineage=lineage,
        issuer=issuer,
        subject_ref=frame_artifact_id(accept_frame),
        predicate=OUTCOME_PREDICATE,
        value=state.status,
        evidence_refs=[frame_artifact_id(f) for f in evidence_frames] or None,
        issued_at=issued_at,
    )


def evidence_summary(state: ContractState, frames: Iterable[Frame]) -> dict[str, Any]:
    """The facts a consumer may read off a transcript, labelled for what they are."""
    return {
        "contract": state.contract,
        "status": state.status,
        "terminal": state.terminal,
        "payer": state.payer_did,
        "payee": state.payee_did,
        "rail": state.rail,
        "railRef": state.rail_ref,
        "secretRevealed": state.secret_revealed,
        "frameArtifacts": [
            {"type": f.kind, "from": f.sender, "artifactId": frame_artifact_id(f)} for f in frames
        ],
        "proves": [
            "these frame bytes existed and name these DIDs",
            "the transitions above applied under tclk/1 guards at the stated instant",
        ],
        "doesNotProve": [
            "that any work was delivered or was any good",
            "that money was locked, moved or refunded on any rail",
            "that a rail reference points at anything",
            "that the parties are distinct people",
        ],
    }


__all__ = [
    "OUTCOME_PREDICATE",
    "TCLK_MEDIA_TYPE",
    "draft_frame_artifact",
    "draft_outcome_attestation",
    "evidence_summary",
    "frame_artifact_id",
]
