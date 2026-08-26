"""Artifacts, receipts, and attestations.

`docs/07_EVIDENCE_ARTIFACTS.md` opens with the sentence this whole layer has to
keep faith with:

    Evidence proves provenance of statements and content hashes.
    It does not prove semantic truth automatically.

So nothing here decides whether a thing is *good*. `artifact.register` says some
bytes exist and who claims to have made them. `artifact.receipt` says a worker
produced them under a named authority. `attestation.issue` says a DID holds an
opinion. All three are checkable claims about who said what; none is a finding
that the claim is true.

Three consequences the code has to carry, not just the prose:

*A creator field is a claim.* An artifact naming a creator proves nothing until
a receipt signed by that DID backs it, and a receipt proves control of a key,
not that the work is any good. `ArtifactEvidence` reports the two separately --
`self_asserted_creators` and `signed_producers` -- and never merges them.

*A hash is not availability.* A receipt can bind bytes nobody hosts. `uri` is
non-authoritative and may be absent, wrong, or gone; the hash is the identity.
Inferring "this is fetchable" from an artifact id would be inventing a fact.

*An attestation is one signer's opinion.* Ten attestations from one key are one
opinion repeated. `independent_attesters` exists so a caller counts distinct
signers rather than rows, and even that is a count -- not agreement, and not
truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from lineageauth.authority import DELEGATION_GRANT, describe_grants
from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError, ReasonCode
from lineageauth.timeutil import parse_instant

ARTIFACT_REGISTER = "artifact.register"
ARTIFACT_RECEIPT = "artifact.receipt"
ATTESTATION_ISSUE = "attestation.issue"

# docs/07. Unknown predicates stay displayable -- a reader may want to see what
# somebody asserted -- but they carry no meaning here, so nothing may act on
# one. A registry that silently accepted new predicates would let an issuer
# invent a claim type and have it counted.
KNOWN_PREDICATES: frozenset[str] = frozenset(
    {
        "result.accepted",
        "result.rejected",
        "artifact.reproduced",
        "artifact.reviewed",
        "artifact.reused",
        "translation.checked",
        "security.finding.confirmed",
    }
)

MAX_MEDIA_TYPE = 255
MAX_URI = 2048


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _as_did(value: Any) -> str | None:
    text = _as_str(value)
    if text is None:
        return None
    try:
        public_key_from_did_key(text)
    except LineageAuthError:
        return None
    return text


@dataclass(frozen=True, slots=True)
class Artifact:
    """Content-addressed metadata about some bytes.

    `artifact_id` is the identity: `sha256:` over the content. Everything else,
    `creator` included, is metadata somebody asserted.
    """

    event_id: str
    artifact_id: str
    media_type: str | None
    byte_length: int | None
    uri: str | None
    creator_claim: str | None
    source_refs: tuple[str, ...]
    registered_by: tuple[str, ...]

    @property
    def creator_is_self_asserted(self) -> bool:
        """True when the registration was not signed by the creator it names.

        Anyone may register an artifact and name anyone as its creator. Only a
        signature from that DID makes the claim theirs rather than someone
        else's assertion about them.
        """
        return self.creator_claim is not None and self.creator_claim not in self.registered_by


def read_artifact(event: AdmittedEvent) -> Artifact | str:
    """Validate an `artifact.register` payload, returning it or a complaint."""
    artifact_id = event.get("artifactId")
    if not is_event_id(artifact_id):
        return "artifactId must be a content hash of the form sha256:<64 lowercase hex>"

    media_type = event.get("mediaType")
    if media_type is not None:
        if not isinstance(media_type, str) or len(media_type) > MAX_MEDIA_TYPE:
            return f"mediaType must be a string of at most {MAX_MEDIA_TYPE} characters"

    byte_length = event.get("byteLength")
    if byte_length is not None and (
        isinstance(byte_length, bool) or not isinstance(byte_length, int)
    ):
        return "byteLength must be an integer"
    if isinstance(byte_length, int) and not isinstance(byte_length, bool) and byte_length < 0:
        return "byteLength must not be negative"

    uri = event.get("uri")
    if uri is not None:
        if not isinstance(uri, str) or len(uri) > MAX_URI:
            return f"uri must be a string of at most {MAX_URI} characters"
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in uri):
            # A uri is displayed to a human deciding whether to fetch it.
            return "uri must not contain control characters"

    creator = event.get("createdBy")
    if creator is not None and _as_did(creator) is None:
        return "createdBy must be a usable Ed25519 did:key when present"

    raw_sources = event.get("sourceRefs")
    sources: list[str] = []
    if raw_sources is not None:
        if not isinstance(raw_sources, list):
            return "sourceRefs must be an array of content or event ids"
        for ref in raw_sources:
            if not is_event_id(ref):
                return "every sourceRef must be a sha256:<64 lowercase hex> reference"
            sources.append(str(ref))

    return Artifact(
        event_id=event.event_id,
        artifact_id=str(artifact_id),
        media_type=media_type,
        byte_length=byte_length if isinstance(byte_length, int) else None,
        uri=uri,
        creator_claim=_as_str(creator),
        source_refs=tuple(sorted(set(sources))),
        registered_by=event.verified_signers,
    )


@dataclass(frozen=True, slots=True)
class ArtifactReceipt:
    """A signed statement that a worker produced an artifact under an authority."""

    event_id: str
    artifact_id: str
    worker: str
    authority_refs: tuple[str, ...]
    approval_ref: str | None
    issued_at: datetime


def read_receipt(event: AdmittedEvent) -> ArtifactReceipt | str:
    """Validate an `artifact.receipt` payload, returning it or a complaint."""
    artifact_id = event.get("artifactId")
    if not is_event_id(artifact_id):
        return "artifactId must be a content hash of the form sha256:<64 lowercase hex>"

    worker = _as_did(event.get("worker"))
    if worker is None:
        return "worker must be a usable Ed25519 did:key"
    if not event.signed_by(worker):
        # The point of a receipt is that the worker asserts authorship. A
        # payload naming a worker who did not sign it is somebody else's claim
        # about them, and should not be able to borrow their name.
        return f"not signed by the worker it names ({worker})"

    raw_authority = event.get("authorityRefs")
    authority: list[str] = []
    if raw_authority is not None:
        if not isinstance(raw_authority, list):
            return "authorityRefs must be an array of event ids"
        for ref in raw_authority:
            if not is_event_id(ref):
                return "every authorityRef must be an event id"
            authority.append(str(ref))

    approval = event.get("approvalRef")
    if approval is not None and not is_event_id(approval):
        return "approvalRef must be an event id when present"

    return ArtifactReceipt(
        event_id=event.event_id,
        artifact_id=str(artifact_id),
        worker=worker,
        authority_refs=tuple(sorted(set(authority))),
        approval_ref=_as_str(approval),
        issued_at=event.issued_at,
    )


@dataclass(frozen=True, slots=True)
class Attestation:
    """One DID's signed opinion about something.

    Not a verdict. `issuer` controls a key and said this; whether it is correct
    is outside what any signature can establish.
    """

    event_id: str
    issuer: str
    subject_ref: str
    predicate: str
    value: str | None
    reason_code: str | None
    evidence_refs: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime | None

    @property
    def predicate_is_known(self) -> bool:
        """False for a predicate this version has no meaning for."""
        return self.predicate in KNOWN_PREDICATES

    def is_current(self, at: datetime) -> bool:
        return self.expires_at is None or at < self.expires_at


def read_attestation(event: AdmittedEvent) -> Attestation | str:
    """Validate an `attestation.issue` payload, returning it or a complaint."""
    issuer = _as_did(event.get("issuer"))
    if issuer is None:
        return "issuer must be a usable Ed25519 did:key"
    if not event.signed_by(issuer):
        return f"not signed by its declared issuer ({issuer})"

    subject = event.get("subjectRef")
    if not is_event_id(subject):
        return "subjectRef must be an event or content id of the form sha256:<64 hex>"

    predicate = _as_str(event.get("predicate"))
    if predicate is None or not predicate:
        return "predicate must be a non-empty string"

    value = event.get("value")
    if value is not None and not isinstance(value, str):
        return "value must be a string when present"
    reason_code = event.get("reasonCode")
    if reason_code is not None and not isinstance(reason_code, str):
        return "reasonCode must be a string when present"

    raw_evidence = event.get("evidenceRefs")
    evidence: list[str] = []
    if raw_evidence is not None:
        if not isinstance(raw_evidence, list):
            return "evidenceRefs must be an array of ids"
        for ref in raw_evidence:
            if not is_event_id(ref):
                return "every evidenceRef must be a sha256:<64 lowercase hex> reference"
            evidence.append(str(ref))

    expires_at: datetime | None = None
    if event.get("expiresAt") is not None:
        try:
            expires_at = parse_instant(event.get("expiresAt"), field="expiresAt")
        except MalformedEventError as exc:
            return str(exc)
        if expires_at <= event.issued_at:
            return "expiresAt must be after issuedAt"

    return Attestation(
        event_id=event.event_id,
        issuer=issuer,
        subject_ref=str(subject),
        predicate=predicate,
        value=value,
        reason_code=reason_code,
        evidence_refs=tuple(sorted(set(evidence))),
        issued_at=event.issued_at,
        expires_at=expires_at,
    )


# ------------------------------------------------------------------ projection


@dataclass(frozen=True, slots=True)
class ArtifactEvidence:
    """Everything a bundle says about one artifact, with the claims kept apart.

    `docs/09_AGENT_PASSPORT.md` insists the categories never merge into one
    unlabelled truth. That starts here, because a passport can only present
    what this hands it.
    """

    artifact_id: str
    registrations: tuple[Artifact, ...] = ()
    receipts: tuple[ArtifactReceipt, ...] = ()
    attestations: tuple[Attestation, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def self_asserted_creators(self) -> tuple[str, ...]:
        """Creators named by a registration nobody with that key signed."""
        return tuple(
            sorted(
                {
                    a.creator_claim
                    for a in self.registrations
                    if a.creator_claim is not None and a.creator_is_self_asserted
                }
            )
        )

    @property
    def signed_producers(self) -> tuple[str, ...]:
        """Workers who signed a receipt claiming to have produced this.

        Stronger than a creator field -- somebody with that key said it -- and
        still only a claim of authorship, not evidence the work is any good.
        """
        return tuple(sorted({receipt.worker for receipt in self.receipts}))

    def independent_attesters(
        self, *, at: datetime, exclude: frozenset[str] = frozenset()
    ) -> tuple[str, ...]:
        """Distinct current attesters, optionally excluding some DIDs.

        Counting rows would let one key manufacture a consensus by attesting
        repeatedly. `exclude` is how a caller drops the artifact's own producers,
        since an author attesting to their own work is not independent -- the
        caller decides, because this layer does not rank anything.
        """
        return tuple(
            sorted(
                {
                    attestation.issuer
                    for attestation in self.attestations
                    if attestation.is_current(at) and attestation.issuer not in exclude
                }
            )
        )

    @property
    def has_unknown_predicates(self) -> bool:
        return any(not a.predicate_is_known for a in self.attestations)

    @property
    def note(self) -> str:
        return (
            "Evidence records who said what about these bytes. A signature proves "
            "key control, not that the artifact is correct, useful, or safe. A hash "
            "is not a promise that anyone hosts the content."
        )


def collect_evidence(bundle: EventBundle, *, lineage: str, artifact_id: str) -> ArtifactEvidence:
    """Gather every claim in a bundle about one artifact.

    Ordered by event id throughout, so two callers with the same events get the
    same answer.
    """
    if not is_event_id(artifact_id):
        raise MalformedEventError(
            f"artifactId must be sha256:<64 lowercase hex>, got {artifact_id!r}"
        )

    warnings: list[str] = []
    registrations: list[Artifact] = []
    receipts: list[ArtifactReceipt] = []
    attestations: list[Attestation] = []

    for event in bundle.of_type(ARTIFACT_REGISTER, lineage=lineage):
        parsed = read_artifact(event)
        if isinstance(parsed, str):
            warnings.append(f"artifact.register {event.event_id} ignored: {parsed}")
            continue
        if parsed.artifact_id == artifact_id:
            registrations.append(parsed)

    for event in bundle.of_type(ARTIFACT_RECEIPT, lineage=lineage):
        parsed_receipt = read_receipt(event)
        if isinstance(parsed_receipt, str):
            warnings.append(f"artifact.receipt {event.event_id} ignored: {parsed_receipt}")
            continue
        if parsed_receipt.artifact_id == artifact_id:
            receipts.append(parsed_receipt)

    subjects = {artifact_id} | {r.event_id for r in registrations} | {r.event_id for r in receipts}
    for event in bundle.of_type(ATTESTATION_ISSUE, lineage=lineage):
        parsed_attestation = read_attestation(event)
        if isinstance(parsed_attestation, str):
            warnings.append(f"attestation.issue {event.event_id} ignored: {parsed_attestation}")
            continue
        if parsed_attestation.subject_ref in subjects:
            attestations.append(parsed_attestation)

    if not registrations and (receipts or attestations):
        warnings.append(
            f"no artifact.register in this bundle declares {artifact_id}; the metadata "
            "for these bytes is missing, though the claims about them still stand"
        )

    return ArtifactEvidence(
        artifact_id=artifact_id,
        registrations=tuple(sorted(registrations, key=lambda a: a.event_id)),
        receipts=tuple(sorted(receipts, key=lambda r: r.event_id)),
        attestations=tuple(sorted(attestations, key=lambda a: a.event_id)),
        warnings=tuple(warnings),
    )


@dataclass(frozen=True, slots=True)
class ReceiptAuthority:
    """Whether the authority a receipt cites actually stands."""

    receipt: ArtifactReceipt
    supported: bool
    reason: ReasonCode
    detail: str


def check_receipt_authority(
    bundle: EventBundle, *, lineage: str, receipt: ArtifactReceipt, at: datetime
) -> ReceiptAuthority:
    """Check the grants a receipt cites, at a stated time.

    A receipt citing authority it never held is still a signed statement -- the
    worker really did say it -- so this reports rather than discards. What it
    refuses to do is let an unsupported citation read as a supported one.
    """
    if not receipt.authority_refs:
        return ReceiptAuthority(
            receipt=receipt,
            supported=False,
            reason=ReasonCode.UNRESOLVED_PARENT,
            detail=(
                "the receipt cites no authority, so there is nothing to check. It "
                "remains a signed claim of authorship."
            ),
        )

    standings = {s.grant.event_id: s for s in describe_grants(bundle, lineage=lineage, at=at)}
    missing = [ref for ref in receipt.authority_refs if ref not in standings]
    if missing:
        return ReceiptAuthority(
            receipt=receipt,
            supported=False,
            reason=ReasonCode.UNRESOLVED_PARENT,
            detail=(
                f"cites {len(missing)} grant(s) this bundle does not carry: "
                f"{', '.join(sorted(missing))}"
            ),
        )

    unusable = [standings[ref] for ref in receipt.authority_refs if not standings[ref].usable]
    if unusable:
        first = unusable[0]
        return ReceiptAuthority(
            receipt=receipt,
            supported=False,
            reason=first.reason,
            detail=f"grant {first.grant.event_id} is not currently usable: {first.detail}",
        )

    wrong_subject = [
        standings[ref].grant
        for ref in receipt.authority_refs
        if standings[ref].grant.subject != receipt.worker
    ]
    if wrong_subject:
        return ReceiptAuthority(
            receipt=receipt,
            supported=False,
            reason=ReasonCode.DENIED,
            detail=(
                f"grant {wrong_subject[0].event_id} delegates to "
                f"{wrong_subject[0].subject}, not to the worker {receipt.worker}"
            ),
        )

    return ReceiptAuthority(
        receipt=receipt,
        supported=True,
        reason=ReasonCode.VALID_AUTHORITY_CHAIN,
        detail=(
            f"all {len(receipt.authority_refs)} cited grant(s) are held by the worker "
            "and currently usable. This supports the claim that the work was done "
            "under delegated authority -- not that the work is correct."
        ),
    )


__all__ = [
    "ARTIFACT_RECEIPT",
    "ARTIFACT_REGISTER",
    "ATTESTATION_ISSUE",
    "DELEGATION_GRANT",
    "KNOWN_PREDICATES",
    "Artifact",
    "ArtifactEvidence",
    "ArtifactReceipt",
    "Attestation",
    "ReceiptAuthority",
    "check_receipt_authority",
    "collect_evidence",
    "read_artifact",
    "read_attestation",
    "read_receipt",
]
