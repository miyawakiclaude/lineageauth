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

from datetime import datetime
from typing import Any

from lineageauth import catalog
from lineageauth.canonical import preimage
from lineageauth.crypto import LocalSigner
from lineageauth.didkey import public_key_from_did_key
from lineageauth.envelope import ALG_ED25519, Envelope, Proof
from lineageauth.errors import MalformedEventError
from lineageauth.identifiers import derive_lineage_id
from lineageauth.scopes import ApprovalMode, parse_scopes
from lineageauth.timeutil import format_instant

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
