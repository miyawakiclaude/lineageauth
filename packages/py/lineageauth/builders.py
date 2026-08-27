"""Unsigned draft builders for the Phase 1 lineage events.

Drafting and signing are separate on purpose (docs/16_API_SDK_CLI.md): a
`build_*` call returns an unsigned payload, and a signer -- local, ideally
offline for root and recovery keys -- turns it into an envelope. Nothing here
touches the network.

Field names for `root.create`, `recovery.policy`, and `root.succession` are
fixed by decision D-026 in docs/29_DECISIONS.md; docs/03_EVENT_CATALOG.md names
the events but leaves their exact payload shape open.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from lineageauth import catalog
from lineageauth.actions import ActionRequest
from lineageauth.canonical import b64u_encode, is_event_id, preimage
from lineageauth.crypto import LocalSigner
from lineageauth.didkey import public_key_from_did_key
from lineageauth.envelope import ALG_ED25519, Envelope, Proof
from lineageauth.errors import MalformedEventError
from lineageauth.identifiers import derive_lineage_id
from lineageauth.scopes import ApprovalMode, parse_scopes
from lineageauth.timeutil import format_instant

MIN_NONCE_BYTES = 16

SuccessionMode = str  # "normal" | "recovery"
NORMAL_SUCCESSION = "normal"
RECOVERY_SUCCESSION = "recovery"


def _common(event_type: str, lineage: str, issued_at: datetime) -> dict[str, Any]:
    return {
        "protocol": catalog.PROTOCOL,
        "version": catalog.CORE_VERSION,
        "type": event_type,
        "lineage": lineage,
        "issuedAt": format_instant(issued_at),
    }


def build_root_create(*, root_did: str, issued_at: datetime) -> dict[str, Any]:
    """Draft the genesis event that opens a lineage at epoch 0.

    The lineage identifier is derived from `root_did`, so a verifier can
    recompute it and confirm the two agree without consulting any registry.
    """
    public_key_from_did_key(root_did)
    lineage = derive_lineage_id(root_did)
    return _common("root.create", lineage, issued_at) | {"root": root_did, "epoch": 0}


def build_recovery_policy(
    *,
    lineage: str,
    epoch: int,
    policy_seq: int,
    members: list[str],
    threshold: int,
    previous_policy: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a recovery policy: which DIDs may authorize a recovery succession.

    docs/05_RECOVERY_SUCCESSION.md requires unique members and an ordering
    signal, so `policySeq` must increase and `previousPolicy` must reference the
    policy being replaced. Unordered competing policies fail closed later rather
    than being resolved by timestamp.
    """
    if epoch < 0:
        raise MalformedEventError("epoch must be a non-negative integer")
    if policy_seq < 1:
        raise MalformedEventError("policySeq must start at 1 and increase")
    if len(set(members)) != len(members):
        raise MalformedEventError("recovery members must be distinct DIDs")
    if not members:
        raise MalformedEventError("recovery policy requires at least one member")
    for member in members:
        public_key_from_did_key(member)
    if not 1 <= threshold <= len(members):
        raise MalformedEventError(
            f"threshold must be between 1 and the member count ({len(members)}), got {threshold}"
        )
    if policy_seq > 1 and previous_policy is None:
        raise MalformedEventError(
            "a replacement policy (policySeq > 1) must reference the policy it replaces"
        )

    payload = _common("recovery.policy", lineage, issued_at) | {
        "epoch": epoch,
        "policySeq": policy_seq,
        "members": sorted(members),
        "threshold": threshold,
    }
    if previous_policy is not None:
        payload["previousPolicy"] = previous_policy
    return payload


def build_root_succession(
    *,
    lineage: str,
    from_root: str,
    to_root: str,
    from_epoch: int,
    mode: SuccessionMode,
    recovery_policy_ref: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a root succession moving the lineage from one epoch to the next.

    `normal` mode is signed by the outgoing root. `recovery` mode is signed by a
    threshold of the members named in `recoveryPolicyRef`; that reference is
    mandatory so a verifier knows which policy the quorum must satisfy rather
    than guessing at the newest one it happens to hold.
    """
    if mode not in (NORMAL_SUCCESSION, RECOVERY_SUCCESSION):
        raise MalformedEventError(
            f"mode must be {NORMAL_SUCCESSION!r} or {RECOVERY_SUCCESSION!r}, got {mode!r}"
        )
    if from_epoch < 0:
        raise MalformedEventError("fromEpoch must be a non-negative integer")
    if from_root == to_root:
        raise MalformedEventError("succession must move the root to a different DID")
    public_key_from_did_key(from_root)
    public_key_from_did_key(to_root)
    if mode == RECOVERY_SUCCESSION and not recovery_policy_ref:
        raise MalformedEventError("recovery succession must reference the recovery policy it uses")

    payload = _common("root.succession", lineage, issued_at) | {
        "fromRoot": from_root,
        "toRoot": to_root,
        "fromEpoch": from_epoch,
        "toEpoch": from_epoch + 1,
        "mode": mode,
    }
    if recovery_policy_ref is not None:
        payload["recoveryPolicyRef"] = recovery_policy_ref
    return payload


def sign_payload(payload: dict[str, Any], signers: list[LocalSigner]) -> Envelope:
    """Attach one Ed25519 proof per signer to an unsigned payload."""
    if not signers:
        raise MalformedEventError("at least one signer is required to produce an envelope")
    message = preimage(payload)
    proofs = [
        Proof(alg=ALG_ED25519, signer=signer.did, sig=signer.sign_b64u(message))
        for signer in signers
    ]
    return Envelope(payload=payload, proofs=proofs)


def build_delegation_grant(
    *,
    lineage: str,
    issuer: str,
    subject: str,
    epoch: int,
    scopes: list[dict[str, Any]],
    not_before: datetime,
    expires_at: datetime,
    max_depth: int = 0,
    approval: str = "none",
    parent: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a delegation of attenuated scopes (D-039).

    `epoch` binds the grant to the root epoch under which it was issued. A
    succession moves the lineage past that epoch and the grant stops being
    current -- which is the whole point of recovery: authority a compromised
    root handed out must not survive its replacement.

    `maxDepth` is how many *further* delegations this grant permits, so a leaf
    grant is depth 0. `approval` may only be strengthened by a child.
    """
    if epoch < 0:
        raise MalformedEventError("epoch must be a non-negative integer")
    if max_depth < 0:
        raise MalformedEventError("maxDepth must be a non-negative integer")
    if issuer == subject:
        raise MalformedEventError("a grant must delegate to a different DID than its issuer")
    public_key_from_did_key(issuer)
    public_key_from_did_key(subject)
    if not scopes:
        raise MalformedEventError("a grant must carry at least one scope")
    if expires_at <= not_before:
        raise MalformedEventError("expiresAt must be after notBefore")

    # Validate and normalise the scopes through the same grammar the verifier
    # uses, so a draft that would be refused fails here rather than after it has
    # been signed.
    normalised = [
        {
            "namespace": parsed.namespace,
            "resource": parsed.resource.render(),
            "actions": sorted(parsed.actions),
        }
        for parsed in parse_scopes(scopes)
    ]
    ApprovalMode.parse(approval)

    payload = _common("delegation.grant", lineage, issued_at) | {
        "issuer": issuer,
        "subject": subject,
        "epoch": epoch,
        "scopes": normalised,
        "notBefore": format_instant(not_before),
        "expiresAt": format_instant(expires_at),
        "maxDepth": max_depth,
        "approval": approval,
    }
    if parent is not None:
        payload["parent"] = parent
    return payload


def build_delegation_revoke(
    *,
    lineage: str,
    issuer: str,
    grant: str,
    reason: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a revocation of one grant.

    Revocation only ever removes authority, so it is deliberately easier to
    issue than a grant: the grant's own issuer, any ancestor that delegated to
    that issuer, or the current root may all revoke it (D-041).
    """
    public_key_from_did_key(issuer)
    payload = _common("delegation.revoke", lineage, issued_at) | {
        "issuer": issuer,
        "grant": grant,
    }
    if reason is not None:
        payload["reason"] = reason
    return payload


def build_approval_receipt(
    *,
    lineage: str,
    approver: str,
    agent: str,
    request: ActionRequest,
    nonce: bytes,
    expires_at: datetime,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a human approval for one exact action (D-043).

    The action's fields are carried in full *and* as `requestHash`. The hash is
    derivable from the fields, so carrying both lets a verifier confirm the
    receipt binds the same action it displays -- a receipt that shows one
    destination and commits to another is precisely what an approval preview
    exists to prevent.

    `nonce` must be at least 16 bytes from a cryptographic source. Generating it
    is the caller's job because this module never invents randomness that a
    human's consent depends on.
    """
    public_key_from_did_key(approver)
    public_key_from_did_key(agent)
    if approver == agent:
        raise MalformedEventError(
            "an agent may not approve its own action; the point of an approval is "
            "that a second party consented"
        )
    if len(nonce) < MIN_NONCE_BYTES:
        raise MalformedEventError(
            f"nonce must carry at least {MIN_NONCE_BYTES} bytes of randomness, got {len(nonce)}"
        )
    if expires_at <= issued_at:
        raise MalformedEventError("expiresAt must be after issuedAt")

    return _common("approval.receipt", lineage, issued_at) | {
        "approver": approver,
        "agent": agent,
        "namespace": request.namespace,
        "resource": request.resource,
        "action": request.action,
        "destination": request.destination,
        "contentHash": request.content_hash,
        "requestHash": request.request_hash,
        "nonce": b64u_encode(nonce),
        "expiresAt": format_instant(expires_at),
    }


def build_artifact_register(
    *,
    lineage: str,
    artifact_id: str,
    media_type: str | None = None,
    byte_length: int | None = None,
    uri: str | None = None,
    created_by: str | None = None,
    source_refs: list[str] | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft an `artifact.register` (D-051).

    `artifact_id` is the content hash and is the artifact's identity. Everything
    else is metadata somebody asserts -- including `created_by`, which is a claim
    until a receipt signed by that DID backs it.

    `uri` is deliberately optional and non-authoritative. An artifact may be
    private: the hash binds the bytes without anyone hosting them, and nothing
    should read a hash as a promise that the content is fetchable.
    """
    if not is_event_id(artifact_id):
        raise MalformedEventError(
            "artifactId must be a content hash of the form sha256:<64 lowercase hex>"
        )
    if byte_length is not None and byte_length < 0:
        raise MalformedEventError("byteLength must not be negative")
    if created_by is not None:
        public_key_from_did_key(created_by)
    for ref in source_refs or []:
        if not is_event_id(ref):
            raise MalformedEventError("every sourceRef must be a sha256:<64 hex> reference")

    payload = _common("artifact.register", lineage, issued_at) | {"artifactId": artifact_id}
    if media_type is not None:
        payload["mediaType"] = media_type
    if byte_length is not None:
        payload["byteLength"] = byte_length
    if uri is not None:
        payload["uri"] = uri
    if created_by is not None:
        payload["createdBy"] = created_by
    if source_refs:
        payload["sourceRefs"] = sorted(set(source_refs))
    return payload


def build_artifact_receipt(
    *,
    lineage: str,
    artifact_id: str,
    worker: str,
    authority_refs: list[str] | None = None,
    approval_ref: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft an `artifact.receipt`: the worker's own claim of authorship.

    It must be signed by `worker`, or it is somebody else's assertion borrowing
    their name. `authority_refs` name the grants the work was done under, so a
    verifier can check them rather than take the citation on trust.
    """
    if not is_event_id(artifact_id):
        raise MalformedEventError("artifactId must be a sha256:<64 hex> content hash")
    public_key_from_did_key(worker)
    for ref in authority_refs or []:
        if not is_event_id(ref):
            raise MalformedEventError("every authorityRef must be an event id")
    if approval_ref is not None and not is_event_id(approval_ref):
        raise MalformedEventError("approvalRef must be an event id")

    payload = _common("artifact.receipt", lineage, issued_at) | {
        "artifactId": artifact_id,
        "worker": worker,
    }
    if authority_refs:
        payload["authorityRefs"] = sorted(set(authority_refs))
    if approval_ref is not None:
        payload["approvalRef"] = approval_ref
    return payload


def build_attestation(
    *,
    lineage: str,
    issuer: str,
    subject_ref: str,
    predicate: str,
    value: str | None = None,
    reason_code: str | None = None,
    evidence_refs: list[str] | None = None,
    expires_at: datetime | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft an `attestation.issue`: one DID's signed opinion.

    An unregistered predicate is accepted here and stays displayable, because
    refusing to let anyone express a new kind of claim would be the wrong
    failure. What it must never do is take effect -- the verifier marks it
    unknown, and nothing may act on it (docs/07).
    """
    public_key_from_did_key(issuer)
    if not is_event_id(subject_ref):
        raise MalformedEventError("subjectRef must be a sha256:<64 hex> event or content id")
    if not predicate:
        raise MalformedEventError("predicate must be a non-empty string")
    for ref in evidence_refs or []:
        if not is_event_id(ref):
            raise MalformedEventError("every evidenceRef must be a sha256:<64 hex> reference")
    if expires_at is not None and expires_at <= issued_at:
        raise MalformedEventError("expiresAt must be after issuedAt")

    payload = _common("attestation.issue", lineage, issued_at) | {
        "issuer": issuer,
        "subjectRef": subject_ref,
        "predicate": predicate,
    }
    if value is not None:
        payload["value"] = value
    if reason_code is not None:
        payload["reasonCode"] = reason_code
    if evidence_refs:
        payload["evidenceRefs"] = sorted(set(evidence_refs))
    if expires_at is not None:
        payload["expiresAt"] = format_instant(expires_at)
    return payload


MAX_NICKNAME = 64
MAX_DESCRIPTION = 1024


def build_profile_statement(
    *,
    lineage: str,
    subject: str,
    nickname: str | None = None,
    description: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `profile.statement`: what a DID says about itself (D-053).

    Everything in here is self-claimed and stays labelled that way for the whole
    life of the event. A nickname is not a name, a description is not a
    credential, and the passport that renders them says so.

    Control characters are refused because these strings are displayed next to
    cryptographically-backed facts, and a description able to redraw its
    surroundings could borrow their authority.
    """
    public_key_from_did_key(subject)
    for label, value, limit in (
        ("nickname", nickname, MAX_NICKNAME),
        ("description", description, MAX_DESCRIPTION),
    ):
        if value is None:
            continue
        if not value.strip():
            raise MalformedEventError(f"{label} must not be blank when present")
        if len(value) > limit:
            raise MalformedEventError(f"{label} is limited to {limit} characters")
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            raise MalformedEventError(
                f"{label} must not contain control characters; it is shown beside "
                "facts that are cryptographically backed and must not be able to "
                "dress itself up as one"
            )
    if nickname is None and description is None:
        raise MalformedEventError("a profile statement must say something")

    payload = _common("profile.statement", lineage, issued_at) | {"subject": subject}
    if nickname is not None:
        payload["nickname"] = nickname
    if description is not None:
        payload["description"] = description
    return payload


def build_skill_claim(
    *,
    lineage: str,
    subject: str,
    skill: str,
    evidence_refs: list[str] | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `skill.claim`.

    A claim, whoever signs it. When the subject signs it, it is self-claimed;
    when somebody else does, it is a third party's opinion about them. Neither
    is evidence -- that comes from artifacts the subject actually produced, and
    `evidence_refs` is how a claim points at them so a reader can check rather
    than believe.
    """
    public_key_from_did_key(subject)
    if not skill or not skill.strip():
        raise MalformedEventError("skill must be a non-empty identifier")
    if len(skill) > 128:
        raise MalformedEventError("skill is limited to 128 characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in skill):
        raise MalformedEventError("skill must not contain control characters")
    for ref in evidence_refs or []:
        if not is_event_id(ref):
            raise MalformedEventError("every evidenceRef must be a sha256:<64 hex> reference")

    payload = _common("skill.claim", lineage, issued_at) | {
        "subject": subject,
        "skill": skill,
    }
    if evidence_refs:
        payload["evidenceRefs"] = sorted(set(evidence_refs))
    return payload


TASK_REQUEST = "task.request"
TASK_CLAIM = "task.claim"
TASK_RELEASE = "task.release"
TASK_RESULT = "task.result"
TASK_VERIFY = "task.verify"

ACCEPTED = "accepted"
REJECTED = "rejected"
VERDICTS = (ACCEPTED, REJECTED)

MAX_TITLE = 200
MAX_SUMMARY = 4096


def _check_display_text(label: str, value: str, limit: int) -> None:
    if not value.strip():
        raise MalformedEventError(f"{label} must not be blank")
    if len(value) > limit:
        raise MalformedEventError(f"{label} is limited to {limit} characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise MalformedEventError(
            f"{label} must not contain control characters; it is displayed to whoever "
            "decides whether to take the work on"
        )


def build_task_request(
    *,
    lineage: str,
    requester: str,
    title: str,
    acceptance_criteria: list[str],
    allowed_claims: int = 1,
    deadline: datetime | None = None,
    reward_reference: str | None = None,
    required_authority: list[dict[str, Any]] | None = None,
    cancellable: bool = True,
    coordinator: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `task.request` (D-055).

    `rewardReference` is an opaque string and nothing else. The core protocol
    escrows nothing, pays nothing, and validates no token value -- whatever a
    reward reference points at is somebody else's system, and treating it as a
    promise here would be the protocol claiming something it cannot deliver.

    `cancellable=False` binds the requester: a task published that way can never
    be withdrawn, which is worth something to whoever is deciding whether to
    start work. `coordinator` names in advance the one key whose
    `claim.coordinate` settles competing claims -- naming it afterwards would
    let the requester pick whoever awards the claim they prefer.
    """
    public_key_from_did_key(requester)
    _check_display_text("title", title, MAX_TITLE)
    if not acceptance_criteria:
        raise MalformedEventError(
            "a task must state its acceptance criteria; without them a verification "
            "is an opinion about nothing in particular"
        )
    for criterion in acceptance_criteria:
        _check_display_text("acceptance criterion", criterion, MAX_TITLE)
    if allowed_claims < 1:
        raise MalformedEventError("allowedClaims must be at least 1")
    if deadline is not None and deadline <= issued_at:
        raise MalformedEventError("deadline must be after issuedAt")
    if reward_reference is not None:
        _check_display_text("rewardReference", reward_reference, MAX_TITLE)

    payload = _common(TASK_REQUEST, lineage, issued_at) | {
        "requester": requester,
        "title": title,
        "acceptanceCriteria": list(acceptance_criteria),
        "allowedClaims": allowed_claims,
    }
    if not cancellable:
        payload["cancellable"] = False
    if coordinator is not None:
        public_key_from_did_key(coordinator)
        payload["coordinator"] = coordinator
    if deadline is not None:
        payload["deadline"] = format_instant(deadline)
    if reward_reference is not None:
        payload["rewardReference"] = reward_reference
    if required_authority:
        payload["requiredAuthority"] = [
            {
                "namespace": scope.namespace,
                "resource": scope.resource.render(),
                "actions": sorted(scope.actions),
            }
            for scope in parse_scopes(required_authority)
        ]
    return payload


def build_task_claim(
    *,
    lineage: str,
    task: str,
    claimant: str,
    nonce: bytes,
    expires_at: datetime,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `task.claim`.

    The nonce makes two claims by one key on one task distinguishable, so a
    replayed claim cannot masquerade as a fresh one.
    """
    if not is_event_id(task):
        raise MalformedEventError("task must be the event id of a task.request")
    public_key_from_did_key(claimant)
    if len(nonce) < MIN_NONCE_BYTES:
        raise MalformedEventError(
            f"nonce must carry at least {MIN_NONCE_BYTES} bytes of randomness"
        )
    if expires_at <= issued_at:
        raise MalformedEventError("expiresAt must be after issuedAt")

    return _common(TASK_CLAIM, lineage, issued_at) | {
        "task": task,
        "claimant": claimant,
        "nonce": b64u_encode(nonce),
        "expiresAt": format_instant(expires_at),
    }


def build_task_release(
    *, lineage: str, claim: str, claimant: str, issued_at: datetime
) -> dict[str, Any]:
    """Draft a `task.release`: the claimant giving the task back."""
    if not is_event_id(claim):
        raise MalformedEventError("claim must be the event id of a task.claim")
    public_key_from_did_key(claimant)
    return _common(TASK_RELEASE, lineage, issued_at) | {
        "claim": claim,
        "claimant": claimant,
    }


def build_task_result(
    *,
    lineage: str,
    task: str,
    claim: str,
    worker: str,
    artifact_refs: list[str],
    summary: str,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `task.result`: the work, pointing at what was produced."""
    for label, ref in (("task", task), ("claim", claim)):
        if not is_event_id(ref):
            raise MalformedEventError(f"{label} must be an event id")
    public_key_from_did_key(worker)
    if not artifact_refs:
        raise MalformedEventError(
            "a result must reference at least one artifact; a claim of work with "
            "nothing attached is not evidence of any"
        )
    for ref in artifact_refs:
        if not is_event_id(ref):
            raise MalformedEventError("every artifactRef must be a sha256:<64 hex> id")
    _check_display_text("summary", summary, MAX_SUMMARY)

    return _common(TASK_RESULT, lineage, issued_at) | {
        "task": task,
        "claim": claim,
        "worker": worker,
        "artifactRefs": sorted(set(artifact_refs)),
        "summary": summary,
    }


def build_task_verify(
    *,
    lineage: str,
    task: str,
    result: str,
    verifier: str,
    verdict: str,
    criteria_results: dict[str, bool] | None = None,
    evidence_refs: list[str] | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `task.verify`: one verifier's signed assessment.

    A verdict is that verifier's opinion, and the work receipt derived from it
    reports who held it rather than treating it as settled.
    """
    for label, ref in (("task", task), ("result", result)):
        if not is_event_id(ref):
            raise MalformedEventError(f"{label} must be an event id")
    public_key_from_did_key(verifier)
    if verdict not in VERDICTS:
        raise MalformedEventError(f"verdict must be one of {list(VERDICTS)}, got {verdict!r}")
    for ref in evidence_refs or []:
        if not is_event_id(ref):
            raise MalformedEventError("every evidenceRef must be a sha256:<64 hex> id")

    payload = _common(TASK_VERIFY, lineage, issued_at) | {
        "task": task,
        "result": result,
        "verifier": verifier,
        "verdict": verdict,
    }
    if criteria_results:
        payload["criteriaResults"] = {k: bool(v) for k, v in sorted(criteria_results.items())}
    if evidence_refs:
        payload["evidenceRefs"] = sorted(set(evidence_refs))
    return payload



TASK_CANCEL = "task.cancel"
CLAIM_COORDINATE = "claim.coordinate"


def build_task_cancel(
    *, lineage: str, task: str, requester: str, reason: str, issued_at: datetime
) -> dict[str, Any]:
    """Draft a `task.cancel`: the requester withdrawing a task.

    Drafting one is always allowed; whether it *takes effect* is decided by
    `resolve_task` against the bundle, not here. `docs/11` permits cancellation
    only while no protected state exists, and a resolver that checked timestamps
    instead would let a requester backdate a cancellation over work already
    done.
    """
    if not is_event_id(task):
        raise MalformedEventError("task must be the event id of a task.request")
    public_key_from_did_key(requester)
    _check_display_text("reason", reason, MAX_SUMMARY)
    return _common(TASK_CANCEL, lineage, issued_at) | {
        "task": task,
        "requester": requester,
        "reason": reason,
    }


def build_claim_coordinate(
    *, lineage: str, task: str, coordinator: str, claim: str, issued_at: datetime
) -> dict[str, Any]:
    """Draft a `claim.coordinate`: the named coordinator awarding one claim.

    `docs/11` allows a coordinator receipt to settle which claim wins on a
    single-claimant task, and asks that the dependency be exposed honestly. So
    the coordinator is named by the requester inside `task.request` before any
    claim exists, and everything downstream reports that the award rests on that
    key's say-so rather than on anything cryptography establishes about who was
    first.
    """
    for label, ref in (("task", task), ("claim", claim)):
        if not is_event_id(ref):
            raise MalformedEventError(f"{label} must be an event id")
    public_key_from_did_key(coordinator)
    return _common(CLAIM_COORDINATE, lineage, issued_at) | {
        "task": task,
        "coordinator": coordinator,
        "claim": claim,
    }


AVAILABILITY_STATEMENT = "availability.statement"

# docs/10: "Availability expires quickly." A statement that outlived its
# usefulness is worse than none, because a stale one still looks like an answer.
MAX_AVAILABILITY_WINDOW = timedelta(days=7)


def build_availability_statement(
    *,
    lineage: str,
    subject: str,
    available: bool,
    expires_at: datetime,
    capacity: int | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft an `availability.statement`: a short-lived offer to take work.

    Deliberately short-lived. `docs/10` has availability expiring quickly and
    being flagged when stale, because an agent that said it was free a week ago
    has told you nothing about now -- and a stale statement still reads like an
    answer unless something forces it to expire.
    """
    public_key_from_did_key(subject)
    if expires_at <= issued_at:
        raise MalformedEventError("expiresAt must be after issuedAt")
    if expires_at - issued_at > MAX_AVAILABILITY_WINDOW:
        raise MalformedEventError(
            f"an availability statement may not claim more than "
            f"{MAX_AVAILABILITY_WINDOW.days} days; availability that far out is a "
            "guess, and a guess that does not expire is treated as a fact"
        )
    if capacity is not None and capacity < 0:
        raise MalformedEventError("capacity must not be negative")

    payload = _common(AVAILABILITY_STATEMENT, lineage, issued_at) | {
        "subject": subject,
        "available": available,
        "expiresAt": format_instant(expires_at),
    }
    if capacity is not None:
        payload["capacity"] = capacity
    return payload


FLEET_CREATE = "fleet.create"
FLEET_BIND = "fleet.bind"
FLEET_UNBIND = "fleet.unbind"

MAX_FLEET_NAME = 128


def build_fleet_create(
    *, lineage: str, controller: str, name: str, issued_at: datetime
) -> dict[str, Any]:
    """Draft a `fleet.create`: an operator disclosing that it runs a group (D-059).

    Disclosure is voluntary and one-directional. Creating a fleet says "these
    DIDs are mine"; it can never say "and I have no others", so nothing built on
    this may treat an absent fleet as evidence of independence.
    """
    public_key_from_did_key(controller)
    _check_display_text("name", name, MAX_FLEET_NAME)
    return _common(FLEET_CREATE, lineage, issued_at) | {
        "controller": controller,
        "name": name,
    }


def build_fleet_bind(
    *,
    lineage: str,
    fleet: str,
    controller: str,
    member: str,
    role: str | None = None,
    expires_at: datetime | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `fleet.bind`: the controller declaring a DID part of its fleet.

    Signed by the controller, not the member. The claim being made is "I operate
    this", which is the controller's to make -- and it stays a claim: a binding
    proves the signer asserted a relationship, not that one legal person holds
    both keys.
    """
    if not is_event_id(fleet):
        raise MalformedEventError("fleet must be the event id of a fleet.create")
    public_key_from_did_key(controller)
    public_key_from_did_key(member)
    if role is not None:
        _check_display_text("role", role, MAX_FLEET_NAME)
    if expires_at is not None and expires_at <= issued_at:
        raise MalformedEventError("expiresAt must be after issuedAt")

    payload = _common(FLEET_BIND, lineage, issued_at) | {
        "fleet": fleet,
        "controller": controller,
        "member": member,
    }
    if role is not None:
        payload["role"] = role
    if expires_at is not None:
        payload["expiresAt"] = format_instant(expires_at)
    return payload


def build_fleet_unbind(
    *, lineage: str, bind: str, controller: str, issued_at: datetime
) -> dict[str, Any]:
    """Draft a `fleet.unbind`: ending a binding going forward.

    Forward-only. The binding happened and the events that relied on it stay as
    they were; unbinding says the relationship no longer holds, not that it
    never did.
    """
    if not is_event_id(bind):
        raise MalformedEventError("bind must be the event id of a fleet.bind")
    public_key_from_did_key(controller)
    return _common(FLEET_UNBIND, lineage, issued_at) | {
        "bind": bind,
        "controller": controller,
    }


ARTIFACT_REUSE = "artifact.reuse"
ARTIFACT_IMPROVE = "artifact.improve"
IMPACT_ATTEST = "impact.attest"


def build_artifact_reuse(
    *,
    lineage: str,
    reuser: str,
    used: str,
    used_in: str,
    note: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft an `artifact.reuse`: B used A (D-060).

    Signed by the reuser, because the claim is "I used this". A reuse anyone
    could mint would let an author manufacture their own downstream adoption,
    which is exactly the vanity metric `docs/14` sets out to avoid.
    """
    public_key_from_did_key(reuser)
    for label, ref in (("used", used), ("usedIn", used_in)):
        if not is_event_id(ref):
            raise MalformedEventError(f"{label} must be a sha256:<64 hex> reference")
    if used == used_in:
        raise MalformedEventError("an artifact cannot be reused in itself")
    if note is not None:
        _check_display_text("note", note, MAX_TITLE)

    payload = _common(ARTIFACT_REUSE, lineage, issued_at) | {
        "reuser": reuser,
        "used": used,
        "usedIn": used_in,
    }
    if note is not None:
        payload["note"] = note
    return payload


def build_artifact_improve(
    *,
    lineage: str,
    author: str,
    improves: str,
    artifact: str,
    note: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft an `artifact.improve`: this artifact derives from and improves another.

    "Improves" is the author's claim, not a finding. Whether the newer artifact
    is actually better is exactly the kind of judgement a signature cannot make.
    """
    public_key_from_did_key(author)
    for label, ref in (("improves", improves), ("artifact", artifact)):
        if not is_event_id(ref):
            raise MalformedEventError(f"{label} must be a sha256:<64 hex> reference")
    if improves == artifact:
        raise MalformedEventError("an artifact cannot improve on itself")
    if note is not None:
        _check_display_text("note", note, MAX_TITLE)

    payload = _common(ARTIFACT_IMPROVE, lineage, issued_at) | {
        "author": author,
        "improves": improves,
        "artifact": artifact,
    }
    if note is not None:
        payload["note"] = note
    return payload


def build_impact_attest(
    *,
    lineage: str,
    issuer: str,
    subject_ref: str,
    observed: str,
    evidence_refs: list[str] | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft an `impact.attest`: a third party reporting downstream use.

    Distinct from `artifact.reuse` in who is speaking. A reuse is the user's own
    statement; this is somebody else observing that use happened, which is
    weaker evidence about the fact and stronger evidence about independence.
    """
    public_key_from_did_key(issuer)
    if not is_event_id(subject_ref):
        raise MalformedEventError("subjectRef must be a sha256:<64 hex> reference")
    _check_display_text("observed", observed, MAX_SUMMARY)
    for ref in evidence_refs or []:
        if not is_event_id(ref):
            raise MalformedEventError("every evidenceRef must be a sha256:<64 hex> reference")

    payload = _common(IMPACT_ATTEST, lineage, issued_at) | {
        "issuer": issuer,
        "subjectRef": subject_ref,
        "observed": observed,
    }
    if evidence_refs:
        payload["evidenceRefs"] = sorted(set(evidence_refs))
    return payload


DISPUTE_OPEN = "dispute.open"
JURY_DISCLOSE = "jury.disclose"
JURY_VOTE = "jury.vote"

MAX_JURORS = 32

# docs/12 leaves selection open and names two MVP modes. Both are here, and the
# second is labelled honestly rather than described as random (D-061).
NAMED_SELECTION = "named"
DECLARED_POOL_SELECTION = "declared-pool"

# The juror's finding is about the *result*, never about who is disputing it.
# "Upholds" or "overturns" would only make sense relative to a prior verdict,
# which inverts every time somebody disputes a rejection.
MEETS_CRITERIA = "result-meets-criteria"
FAILS_CRITERIA = "result-fails-criteria"
ABSTAIN = "abstain"
FINDINGS = (MEETS_CRITERIA, FAILS_CRITERIA, ABSTAIN)

CONFLICT_CODES = (
    "same-fleet",
    "prior-role-in-task",
    "repeat-counterparty",
    "other",
)


def _check_policy(*, seats: int, quorum: int, threshold: int) -> None:
    """Refuse a policy that could declare both sides winners, at draft time.

    A threshold at or below half the seats lets a 5-seat jury split 2/2 and
    satisfy a threshold of 2 on both sides at once. Rather than resolve that at
    tally time -- where the tie-break would be somebody deciding -- the builder
    refuses to draft it.
    """
    if seats < 1:
        raise MalformedEventError("a jury needs at least one seat")
    if seats > MAX_JURORS:
        raise MalformedEventError(f"a jury is limited to {MAX_JURORS} seats")
    if threshold < 1:
        raise MalformedEventError("threshold must be at least 1")
    if threshold <= seats // 2:
        raise MalformedEventError(
            f"threshold must be a strict majority of the {seats} seats "
            f"(more than {seats // 2}); anything less can be met by both sides at once"
        )
    if threshold > seats:
        raise MalformedEventError("threshold must not exceed the number of seats")
    if quorum < threshold:
        raise MalformedEventError(
            "quorum must be at least the threshold, or a verdict could be reached "
            "by fewer jurors than the policy says are needed to reach it"
        )
    if quorum > seats:
        raise MalformedEventError("quorum must not exceed the number of seats")


def _check_juror_dids(label: str, dids: list[str]) -> tuple[str, ...]:
    if not dids:
        raise MalformedEventError(f"{label} must not be empty")
    for did in dids:
        public_key_from_did_key(did)
    unique = tuple(sorted(set(dids)))
    if len(unique) != len(dids):
        raise MalformedEventError(f"{label} must not repeat a DID")
    return unique


def build_dispute_open(
    *,
    lineage: str,
    opener: str,
    task: str,
    result: str,
    reason_code: str,
    statement: str,
    quorum: int,
    threshold: int,
    jurors: list[str] | None = None,
    pool: list[str] | None = None,
    seats: int | None = None,
    seed: str | None = None,
    disputed_verification: str | None = None,
    evidence_refs: list[str] | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `dispute.open`: a signed objection carrying its own decision policy.

    The policy travels with the case on purpose. Deciding the quorum after the
    votes are in is the oldest way to arrange an outcome, so `docs/12` has
    seats, quorum and threshold fixed before anyone votes -- and this builder
    refuses a policy that both sides could satisfy at once (`_check_policy`).

    Two selection modes, both from `docs/12`. `jurors=` names them outright.
    `pool=` with `seats=` and `seed=` records a deterministic draw anybody can
    recompute. Neither is claimed to be unbiased: the opener chooses the seed,
    so the draw is reproducible rather than fair, and every reader of the
    resolved case is told exactly that.
    """
    public_key_from_did_key(opener)
    for label, ref in (("task", task), ("result", result)):
        if not is_event_id(ref):
            raise MalformedEventError(f"{label} must be an event id")
    if disputed_verification is not None and not is_event_id(disputed_verification):
        raise MalformedEventError("disputedVerification must be an event id")
    _check_display_text("reasonCode", reason_code, 64)
    _check_display_text("statement", statement, MAX_SUMMARY)
    for ref in evidence_refs or []:
        if not is_event_id(ref):
            raise MalformedEventError("every evidenceRef must be a sha256:<64 hex> reference")

    if (jurors is None) == (pool is None):
        raise MalformedEventError("give either jurors= (named) or pool= (declared draw), not both")

    selection: dict[str, Any]
    if jurors is not None:
        seated = _check_juror_dids("jurors", jurors)
        if seats is not None and seats != len(seated):
            raise MalformedEventError("seats must match the number of named jurors")
        seat_count = len(seated)
        selection = {"mode": NAMED_SELECTION, "jurors": list(seated)}
    else:
        candidates = _check_juror_dids("pool", pool or [])
        if seats is None:
            raise MalformedEventError("a declared draw needs seats=")
        if not seed:
            raise MalformedEventError("a declared draw needs a recorded seed")
        _check_display_text("seed", seed, 128)
        if seats > len(candidates):
            raise MalformedEventError("seats must not exceed the size of the pool")
        seat_count = seats
        selection = {
            "mode": DECLARED_POOL_SELECTION,
            "pool": list(candidates),
            "seats": seats,
            "seed": seed,
        }

    _check_policy(seats=seat_count, quorum=quorum, threshold=threshold)

    payload = _common(DISPUTE_OPEN, lineage, issued_at) | {
        "opener": opener,
        "task": task,
        "result": result,
        "reasonCode": reason_code,
        "statement": statement,
        "selection": selection,
        "policy": {"seats": seat_count, "quorum": quorum, "threshold": threshold},
    }
    if disputed_verification is not None:
        payload["disputedVerification"] = disputed_verification
    if evidence_refs:
        payload["evidenceRefs"] = sorted(set(evidence_refs))
    return payload


def build_jury_disclose(
    *,
    lineage: str,
    case: str,
    juror: str,
    conflicts: list[str],
    note: str | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `jury.disclose`: a juror naming their own conflicts before voting.

    Disclosure is evidence, not identity truth (`docs/12`). It never voids the
    vote -- a disclosed conflict is reported beside the tally, and the resolved
    case states whether the outcome would survive without the conflicted votes.
    """
    public_key_from_did_key(juror)
    if not is_event_id(case):
        raise MalformedEventError("case must be the event id of a dispute.open")
    if not conflicts:
        raise MalformedEventError(
            "disclose at least one conflict code; a juror with nothing to declare "
            "simply does not publish a jury.disclose"
        )
    for code in conflicts:
        if code not in CONFLICT_CODES:
            raise MalformedEventError(
                f"conflict must be one of {list(CONFLICT_CODES)}, got {code!r}"
            )
    payload = _common(JURY_DISCLOSE, lineage, issued_at) | {
        "case": case,
        "juror": juror,
        "conflicts": sorted(set(conflicts)),
    }
    if note is not None:
        _check_display_text("note", note, MAX_SUMMARY)
        payload["note"] = note
    return payload


def build_jury_vote(
    *,
    lineage: str,
    case: str,
    juror: str,
    finding: str,
    reason_code: str,
    evidence_refs: list[str] | None = None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Draft a `jury.vote`: one seated juror's signed finding on the result."""
    public_key_from_did_key(juror)
    if not is_event_id(case):
        raise MalformedEventError("case must be the event id of a dispute.open")
    if finding not in FINDINGS:
        raise MalformedEventError(f"finding must be one of {list(FINDINGS)}, got {finding!r}")
    _check_display_text("reasonCode", reason_code, 64)
    for ref in evidence_refs or []:
        if not is_event_id(ref):
            raise MalformedEventError("every evidenceRef must be a sha256:<64 hex> reference")

    payload = _common(JURY_VOTE, lineage, issued_at) | {
        "case": case,
        "juror": juror,
        "finding": finding,
        "reasonCode": reason_code,
    }
    if evidence_refs:
        payload["evidenceRefs"] = sorted(set(evidence_refs))
    return payload
