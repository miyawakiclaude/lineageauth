"""Event integrity verification.

This layer answers exactly one question:

    Was this payload signed, unmodified, by the DIDs the proofs name?

It deliberately does NOT answer whether an action is allowed. Authority
resolution -- root epoch, delegation chain, attenuation, revocation, human
approval -- is a separate layer over the same events. CLAUDE.md 2.6 is blunt
about the difference: a valid signature proves control of a key and nothing
about identity, affiliation, or safety.

Verification is offline: no network, no database, no private keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lineageauth import catalog
from lineageauth.canonical import assert_canonical_payload, compute_event_id
from lineageauth.crypto import verify_by_did
from lineageauth.didkey import UnsupportedDidMethodError
from lineageauth.envelope import ALG_ED25519, Envelope, Proof
from lineageauth.errors import LineageAuthError, MalformedEventError, ReasonCode
from lineageauth.identifiers import is_lineage_id
from lineageauth.timeutil import parse_instant

REQUIRED_COMMON_FIELDS = ("protocol", "version", "type", "lineage", "issuedAt")

NOT_AUTHORIZATION_NOTE = (
    "Signature validity proves key control only. It is not an authorization "
    "decision and does not establish identity, affiliation, or safety."
)


@dataclass(frozen=True, slots=True)
class ProofResult:
    """Outcome for a single proof on an envelope."""

    index: int
    signer: str
    alg: str
    verified: bool
    reason: ReasonCode
    detail: str


@dataclass(frozen=True, slots=True)
class EventVerification:
    """Structured integrity result. Callers must not reduce this to a boolean."""

    integrity_ok: bool
    reason: ReasonCode
    detail: str
    event_id: str | None = None
    event_type: str | None = None
    event_family: str | None = None
    lineage: str | None = None
    proofs: tuple[ProofResult, ...] = ()
    verified_signers: tuple[str, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        """The standing caveat that accompanies every positive result."""
        return NOT_AUTHORIZATION_NOTE


def _fail(reason: ReasonCode, detail: str, **extra: object) -> EventVerification:
    return EventVerification(integrity_ok=False, reason=reason, detail=detail, **extra)  # type: ignore[arg-type]


def _verify_proof(index: int, proof: Proof, signing_bytes: bytes) -> ProofResult:
    if proof.alg != ALG_ED25519:
        return ProofResult(
            index=index,
            signer=proof.signer,
            alg=proof.alg,
            verified=False,
            reason=ReasonCode.UNKNOWN_VERSION,
            detail=f"unsupported proof algorithm {proof.alg!r}; protocol 0.1 supports Ed25519",
        )
    try:
        verified = verify_by_did(proof.signer, signing_bytes, proof.sig)
    except UnsupportedDidMethodError as exc:
        return ProofResult(
            index, proof.signer, proof.alg, False, ReasonCode.UNKNOWN_VERSION, str(exc)
        )
    except LineageAuthError as exc:
        return ProofResult(index, proof.signer, proof.alg, False, ReasonCode.MALFORMED, str(exc))

    if not verified:
        return ProofResult(
            index=index,
            signer=proof.signer,
            alg=proof.alg,
            verified=False,
            reason=ReasonCode.INVALID_SIGNATURE,
            detail="signature does not verify against this signer over the canonical preimage",
        )
    return ProofResult(
        index=index,
        signer=proof.signer,
        alg=proof.alg,
        verified=True,
        reason=ReasonCode.SIGNATURE_VERIFIED,
        detail="signature verifies over the canonical preimage",
    )


def verify_event(envelope: Envelope) -> EventVerification:
    """Verify one signed envelope's structure and every proof it carries.

    **At least one** proof must verify, and only the proofs that do become
    signers. A proof that does not verify is discarded with a warning rather
    than condemning the envelope (D-087, revising D-027).

    That revision is not leniency. Proofs sit outside the payload and do not
    affect the event id, so anybody holding no key can append one to a copy of a
    signed event. While a single bad proof was fatal, appending was a way of
    *deleting*: a mirror serving only the spoiled copy made the event disappear,
    which is the omission attack D-036 exists to prevent, executed at the door
    before merging was ever reached.

    Nothing is gained by appending. A forged proof names a signer who is absent
    from `verified_signers`, and `signed_by`, `distinct_signers` and every
    quorum count read that. The only thing that changes is that the event
    survives to be merged.
    """
    payload = envelope.payload

    try:
        event_id = compute_event_id(payload)
        # Before anything reads a field out of this payload: the bytes that were
        # signed must decode back to the document in hand. Otherwise a keyless
        # third party can respell a number, keep the signature and the id valid,
        # and change what a reader sees.
        assert_canonical_payload(payload)
    except MalformedEventError as exc:
        return _fail(ReasonCode.MALFORMED, str(exc))

    missing = [name for name in REQUIRED_COMMON_FIELDS if name not in payload]
    if missing:
        return _fail(
            ReasonCode.MALFORMED,
            f"payload is missing required common field(s): {', '.join(missing)}",
            event_id=event_id,
        )

    if payload["protocol"] != catalog.PROTOCOL:
        return _fail(
            ReasonCode.MALFORMED,
            f"protocol must be {catalog.PROTOCOL!r}, got {payload['protocol']!r}",
            event_id=event_id,
        )

    version = payload["version"]
    if not isinstance(version, str) or version not in catalog.SUPPORTED_VERSIONS:
        return _fail(
            ReasonCode.UNKNOWN_VERSION,
            f"unsupported protocol version {version!r}; "
            f"this verifier implements {sorted(catalog.SUPPORTED_VERSIONS)}",
            event_id=event_id,
        )

    event_type = payload["type"]
    if not isinstance(event_type, str):
        return _fail(ReasonCode.MALFORMED, "type must be a string", event_id=event_id)
    family = catalog.family_of(event_type)
    if family is None:
        return _fail(
            ReasonCode.UNKNOWN_VERSION,
            f"unregistered event type {event_type!r}; it cannot be given semantics "
            "by this verifier and must not be treated as authorizing anything",
            event_id=event_id,
            event_type=event_type,
        )

    lineage = payload["lineage"]
    if not is_lineage_id(lineage):
        return _fail(
            ReasonCode.MALFORMED,
            f"lineage must be a well-formed identifier (lineage:la:z...), got {lineage!r}",
            event_id=event_id,
            event_type=event_type,
            event_family=family,
        )

    try:
        parse_instant(payload["issuedAt"], field="issuedAt")
    except MalformedEventError as exc:
        return _fail(
            ReasonCode.MALFORMED,
            str(exc),
            event_id=event_id,
            event_type=event_type,
            event_family=family,
            lineage=lineage,
        )

    common: dict[str, object] = {
        "event_id": event_id,
        "event_type": event_type,
        "event_family": family,
        "lineage": lineage,
    }

    if not envelope.proofs:
        return _fail(ReasonCode.INVALID_SIGNATURE, "envelope carries no proofs", **common)

    results = tuple(
        _verify_proof(index, proof, envelope.signing_bytes)
        for index, proof in enumerate(envelope.proofs)
    )
    failed = [r for r in results if not r.verified]
    verified = [r for r in results if r.verified]
    if not verified:
        first = failed[0]
        return EventVerification(
            integrity_ok=False,
            reason=first.reason,
            detail=f"proof[{first.index}] ({first.signer}): {first.detail}",
            proofs=results,
            verified_signers=(),
            **common,  # type: ignore[arg-type]
        )

    warnings: list[str] = []
    if failed:
        # Refusing the whole envelope for one bad proof turned *adding* into
        # *deleting*: proofs sit outside the payload and do not touch the event
        # id, so anybody -- holding no key at all -- could append a nonsense
        # proof to a copy of a signed event and have that copy thrown away
        # whole. A mirror serving only that copy makes the event vanish, which
        # is precisely the omission attack D-036 exists to prevent. The union
        # guarantee was being broken at the door, before merging was reached.
        #
        # So a bad proof is discarded rather than fatal, and only the proofs
        # that verified become signers. Nothing is gained by appending one: a
        # forged proof names a signer who does not appear in `verified_signers`,
        # and `signed_by` and every quorum count read that. What changes is only
        # that the event survives. (D-087, revising D-027.)
        warnings.append(
            f"{len(failed)} proof(s) on this event did not verify and were discarded; "
            "they confer nothing. Anyone can append a proof without a key, so their "
            "presence is not evidence about the signers who did verify"
        )
    signers = [r.signer for r in verified]
    if len(set(signers)) != len(signers):
        warnings.append(
            "envelope repeats a signer DID across proofs; quorum layers must "
            "count distinct signers only (docs/05_RECOVERY_SUCCESSION.md)"
        )

    return EventVerification(
        integrity_ok=True,
        reason=ReasonCode.SIGNATURE_VERIFIED,
        detail=(
            f"{len(verified)} of {len(results)} proof(s) verified over the canonical "
            f"preimage. {NOT_AUTHORIZATION_NOTE}"
        ),
        proofs=results,
        verified_signers=tuple(signers),
        warnings=tuple(warnings),
        **common,  # type: ignore[arg-type]
    )


def verify_event_json(text: str | bytes) -> EventVerification:
    """Parse and verify an envelope given as JSON text."""
    try:
        envelope = Envelope.from_json(text)
    except LineageAuthError as exc:
        return _fail(exc.reason, str(exc))
    return verify_event(envelope)
