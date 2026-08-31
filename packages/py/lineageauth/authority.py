"""Delegation chains: does this agent hold authority for this exact action?

This is the layer `la verify` was always pointing at. Everything below it --
canonicalization, signatures, epoch resolution, the scope grammar -- exists so
that this question can be answered offline and the answer can be explained.

The shape of the answer matters as much as the answer. `docs/04` requires a
decision to carry the current root and epoch, the grant path that justified it,
the approval requirement, and a reason code. A bare boolean would be a
regression even when it is correct.

Rules this enforces, each from `docs/04_SCOPE_AUTHORIZATION.md`:

  * Deny by default. No matching active chain means deny.
  * Authority only attenuates. A child never broadens resource or actions,
    never starts earlier or ends later, never consumes less depth, and never
    weakens the approval requirement.
  * A chain terminates at the *current* root of the lineage. A grant issued
    under an earlier epoch is superseded, not merely old (D-040).
  * Revocation removes authority from the whole subtree beneath the revoked
    grant, not just from the grant itself.

And the standing caveat: holding authority here is not permission from the
provider. LineageAuth never substitutes for OAuth, an API key, a repository
permission, or an MCP or A2A server's own policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError, ReasonCode
from lineageauth.lineage import LineageState, resolve_lineage
from lineageauth.scopes import ApprovalMode, Scope, parse_scopes
from lineageauth.timeutil import parse_instant

DELEGATION_GRANT = "delegation.grant"
DELEGATION_REVOKE = "delegation.revoke"

PROVIDER_AUTH_NOTE = (
    "A valid authority chain is provenance, not permission from the provider. "
    "OAuth, API keys, repository permissions, and MCP or A2A server policy all "
    "still apply and are never bypassed by this result."
)

# A chain cannot be longer than the number of grants in the bundle; this bound
# only makes non-termination impossible to write by accident.
_MAX_CHAIN = 64


@dataclass(frozen=True, slots=True)
class Grant:
    """A parsed `delegation.grant`."""

    event_id: str
    issuer: str
    subject: str
    epoch: int
    scopes: tuple[Scope, ...]
    not_before: datetime
    expires_at: datetime
    max_depth: int
    approval: ApprovalMode
    parent: str | None

    @property
    def is_root_grant(self) -> bool:
        """True when this grant claims to come straight from the lineage root."""
        return self.parent is None

    def covers(self, *, namespace: str, resource: str, action: str) -> bool:
        return any(
            scope.covers(namespace=namespace, resource=resource, action=action)
            for scope in self.scopes
        )


@dataclass(frozen=True, slots=True)
class Request:
    """The exact thing being asked about."""

    agent: str
    namespace: str
    resource: str
    action: str

    def render(self) -> str:
        return f"{self.agent} -> {self.namespace}:{self.resource} [{self.action}]"


@dataclass(frozen=True, slots=True)
class Refusal:
    """One grant that was considered and not used, and why."""

    event_id: str
    reason: ReasonCode
    detail: str


@dataclass(frozen=True, slots=True)
class AuthorityDecision:
    """The explained outcome. Never reduce this to its `allowed` field alone."""

    allowed: bool
    reason: ReasonCode
    detail: str
    request: Request
    lineage: str
    evaluated_at: datetime
    root: str | None = None
    epoch: int | None = None
    path: tuple[str, ...] = ()
    approval: ApprovalMode = ApprovalMode.NONE
    refusals: tuple[Refusal, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        return PROVIDER_AUTH_NOTE


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


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def read_grant(event: AdmittedEvent) -> Grant | str:
    """Validate a `delegation.grant` payload, returning it or a complaint."""
    issuer = _as_did(event.get("issuer"))
    subject = _as_did(event.get("subject"))
    if issuer is None or subject is None:
        return "issuer and subject must both be usable Ed25519 did:key values"
    if issuer == subject:
        return "a grant must delegate to a different DID than its issuer"
    if not event.signed_by(issuer):
        # Without this, anyone could mint a payload naming someone else as
        # issuer and have it treated as that party's delegation.
        return f"not signed by its declared issuer {issuer}"

    epoch = _as_int(event.get("epoch"))
    if epoch is None or epoch < 0:
        return "epoch must be a non-negative integer"
    max_depth = _as_int(event.get("maxDepth"))
    if max_depth is None or max_depth < 0:
        return "maxDepth must be a non-negative integer"

    try:
        scopes = parse_scopes(event.get("scopes"))
        approval = ApprovalMode.parse(event.get("approval"))
        not_before = parse_instant(event.get("notBefore"), field="notBefore")
        expires_at = parse_instant(event.get("expiresAt"), field="expiresAt")
    except MalformedEventError as exc:
        return str(exc)
    if expires_at <= not_before:
        return "expiresAt must be after notBefore"

    raw_parent = event.get("parent")
    parent = None
    if raw_parent is not None:
        if not is_event_id(raw_parent):
            return "parent must be an event id of the form sha256:<64 hex>"
        parent = str(raw_parent)
        if parent == event.event_id:
            return "a grant cannot be its own parent"

    return Grant(
        event_id=event.event_id,
        issuer=issuer,
        subject=subject,
        epoch=epoch,
        scopes=scopes,
        not_before=not_before,
        expires_at=expires_at,
        max_depth=max_depth,
        approval=approval,
        parent=parent,
    )


def _collect_grants(
    bundle: EventBundle, *, lineage: str, refusals: list[Refusal]
) -> dict[str, Grant]:
    grants: dict[str, Grant] = {}
    for event in bundle.of_type(DELEGATION_GRANT, lineage=lineage):
        parsed = read_grant(event)
        if isinstance(parsed, str):
            refusals.append(Refusal(event.event_id, ReasonCode.MALFORMED, parsed))
            continue
        grants[parsed.event_id] = parsed
    return grants


def _collect_revocations(
    bundle: EventBundle,
    *,
    lineage: str,
    grants: dict[str, Grant],
    root: str,
    refusals: list[Refusal],
) -> dict[str, str]:
    """Return grant id -> revoking event id.

    A revocation counts when it is signed by its declared issuer and that issuer
    is entitled to revoke: the grant's own issuer, any ancestor that delegated
    to it, or the current root (D-041). Revocation only ever subtracts
    authority, so a slightly wider revoker set is the safe direction -- but not
    an unbounded one, or any stranger could switch off a lineage.
    """
    revoked: dict[str, str] = {}
    for event in bundle.of_type(DELEGATION_REVOKE, lineage=lineage):
        issuer = _as_did(event.get("issuer"))
        target = event.get("grant")
        if issuer is None or not is_event_id(target):
            refusals.append(
                Refusal(
                    event.event_id,
                    ReasonCode.MALFORMED,
                    "a revocation needs a did:key issuer and an event id to revoke",
                )
            )
            continue
        if not event.signed_by(issuer):
            refusals.append(
                Refusal(
                    event.event_id,
                    ReasonCode.DENIED,
                    f"not signed by its declared issuer {issuer}",
                )
            )
            continue
        grant = grants.get(str(target))
        if grant is None:
            # Revoking something absent is not an error -- a bundle need not
            # carry the grant to carry its revocation -- but it cannot be
            # applied either, and staying quiet about that would hide a
            # revocation that is not taking effect.
            refusals.append(
                Refusal(
                    event.event_id,
                    ReasonCode.UNRESOLVED_PARENT,
                    f"revokes {target}, which this bundle does not carry as a valid grant",
                )
            )
            continue
        if issuer != root and not _is_ancestor_issuer(issuer, grant, grants):
            refusals.append(
                Refusal(
                    event.event_id,
                    ReasonCode.DENIED,
                    f"{issuer} is neither the current root nor an issuer on the chain "
                    f"above {grant.event_id}",
                )
            )
            continue
        revoked.setdefault(grant.event_id, event.event_id)
    return revoked


def _is_ancestor_issuer(did: str, grant: Grant, grants: dict[str, Grant]) -> bool:
    """True when `did` issued this grant or anything above it."""
    seen: set[str] = set()
    cursor: Grant | None = grant
    for _ in range(_MAX_CHAIN):
        if cursor is None or cursor.event_id in seen:
            return False
        seen.add(cursor.event_id)
        if cursor.issuer == did:
            return True
        cursor = grants.get(cursor.parent) if cursor.parent else None
    return False


def _edge_failure(child: Grant, parent: Grant) -> str | None:
    """Return why `child` is not a valid attenuation of `parent`, or None."""
    from lineageauth.scopes import attenuation_failure

    if child.issuer != parent.subject:
        return (
            f"issued by {child.issuer}, but its parent delegates to {parent.subject}; "
            "only the holder of a grant may delegate from it"
        )
    scope_failure = attenuation_failure(parent.scopes, child.scopes)
    if scope_failure is not None:
        return scope_failure
    if child.not_before < parent.not_before:
        return "starts before the grant it derives from"
    if child.expires_at > parent.expires_at:
        return "outlives the grant it derives from"
    if parent.max_depth < 1:
        return "its parent permits no further delegation (maxDepth 0)"
    if child.max_depth > parent.max_depth - 1:
        return (
            f"claims maxDepth {child.max_depth}, but delegating from a parent of "
            f"maxDepth {parent.max_depth} permits at most {parent.max_depth - 1}"
        )
    if child.approval < parent.approval:
        return (
            f"weakens the approval requirement from {parent.approval.wire_name} to "
            f"{child.approval.wire_name}; a child may only strengthen it"
        )
    if child.epoch != parent.epoch:
        return f"anchored to epoch {child.epoch} while its parent is anchored to {parent.epoch}"
    return None


def _grant_standing(
    grant: Grant,
    *,
    at: datetime,
    epoch: int,
    revoked: dict[str, str],
) -> tuple[ReasonCode, str] | None:
    """Return why this grant is not currently usable, or None when it is."""
    if grant.event_id in revoked:
        return (ReasonCode.REVOKED, f"revoked by {revoked[grant.event_id]}")
    if grant.epoch < epoch:
        return (
            ReasonCode.SUPERSEDED,
            f"issued under epoch {grant.epoch}; the lineage is now at epoch {epoch}, and "
            "authority granted under a replaced root does not survive the replacement "
            "(D-040)",
        )
    if grant.epoch > epoch:
        return (
            ReasonCode.UNRESOLVED_PARENT,
            f"claims epoch {grant.epoch}, which this lineage has not reached (now {epoch})",
        )
    if at < grant.not_before:
        return (ReasonCode.NOT_YET_VALID, f"not valid until {grant.not_before.isoformat()}")
    if at >= grant.expires_at:
        return (ReasonCode.EXPIRED, f"expired at {grant.expires_at.isoformat()}")
    return None


@dataclass(frozen=True, slots=True)
class _Chain:
    path: tuple[str, ...]
    approval: ApprovalMode


def _walk_to_root(
    leaf: Grant,
    *,
    grants: dict[str, Grant],
    revoked: dict[str, str],
    state: LineageState,
    at: datetime,
    request: Request | None,
) -> _Chain | tuple[ReasonCode, str]:
    """Validate the chain from `leaf` up to the lineage root.

    `request` is the one request-specific part: with it, every hop must cover the
    action being asked for. Passing None asks the request-independent half --
    "does this chain hold at all" -- which is what `describe_grants` needs. The
    walk is deliberately not duplicated for that caller. An earlier version had
    `describe_grants` judge each grant on its own, and the two answers drifted:
    revoking a parent left the child reporting VALID_AUTHORITY_CHAIN while
    `check_permission` on the same bundle said REVOKED (D-103).
    """
    root, epoch = state.root, state.epoch
    if root is None or epoch is None:  # pragma: no cover - guarded by the caller
        return (ReasonCode.UNRESOLVED_PARENT, "the lineage has no resolved root")

    path: list[str] = []
    approval = ApprovalMode.NONE
    seen: set[str] = set()
    # Subjects, not event ids. Refusing a repeated event id stops a grant naming
    # itself as its own parent and nothing else: an agent holding a throwaway key
    # can publish A->B and then B->A, attenuating properly at every edge, and so
    # appear on its own authorizing path as an issuer -- which is exactly the set
    # `approval._approvers_entitled` reads to decide who may consent (D-042).
    # A real chain R->A->B->C has distinct subjects; a loop has to repeat one.
    # Purely a restriction: it can refuse a chain, never widen one.
    subjects: set[str] = set()
    cursor = leaf

    for _ in range(_MAX_CHAIN):
        if cursor.event_id in seen:
            return (ReasonCode.MALFORMED, f"the delegation chain revisits {cursor.event_id}")
        seen.add(cursor.event_id)

        if cursor.subject in subjects:
            return (
                ReasonCode.MALFORMED,
                f"the delegation chain delegates to {cursor.subject} twice; a loop adds no "
                "authority but launders who appears to have granted it",
            )
        subjects.add(cursor.subject)

        standing = _grant_standing(cursor, at=at, epoch=epoch, revoked=revoked)
        if standing is not None:
            return standing

        # Defence in depth: attenuation is checked edge by edge, so every
        # ancestor should already cover anything the leaf covers. Checking it
        # here too means a bug in attenuation cannot quietly become an
        # escalation -- it becomes a denial.
        if request is not None and not cursor.covers(
            namespace=request.namespace, resource=request.resource, action=request.action
        ):
            return (
                ReasonCode.SCOPE_VIOLATION,
                f"grant {cursor.event_id} on the chain does not cover {request.render()}",
            )

        path.append(cursor.event_id)
        approval = max(approval, cursor.approval)

        if cursor.is_root_grant:
            if cursor.issuer != root:
                return (
                    ReasonCode.DENIED,
                    f"the chain terminates at {cursor.issuer}, which is not the current "
                    f"root of this lineage ({root})",
                )
            return _Chain(path=tuple(reversed(path)), approval=approval)

        parent = grants.get(str(cursor.parent))
        if parent is None:
            return (
                ReasonCode.UNRESOLVED_PARENT,
                f"grant {cursor.event_id} names parent {cursor.parent}, which this bundle "
                "does not carry as a valid grant",
            )
        failure = _edge_failure(cursor, parent)
        if failure is not None:
            return (ReasonCode.SCOPE_VIOLATION, f"grant {cursor.event_id} {failure}")
        cursor = parent

    return (ReasonCode.MALFORMED, "the delegation chain is longer than this verifier will walk")


def check_permission(
    bundle: EventBundle,
    *,
    lineage: str,
    agent: str,
    namespace: str,
    resource: str,
    action: str,
    at: datetime,
    external: bool = True,
) -> AuthorityDecision:
    """Decide whether `agent` holds authority for one exact action.

    `external` says whether performing this action would have an effect outside
    the agent -- a message sent, a repository written, an HTTP request that
    changes something. It defaults to True because that is the assumption that
    fails safe: a scope marked `external-only` then demands human approval
    unless the caller positively states the action is internal.

    Offline: no network, no database, no private keys.
    """
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")

    request = Request(agent=agent, namespace=namespace, resource=resource, action=action)
    refusals: list[Refusal] = []
    warnings = list(bundle.warnings)

    def deny(
        reason: ReasonCode,
        detail: str,
        *,
        state: LineageState | None = None,
        approval: ApprovalMode = ApprovalMode.NONE,
    ) -> AuthorityDecision:
        return AuthorityDecision(
            allowed=False,
            reason=reason,
            detail=detail,
            request=request,
            lineage=lineage,
            evaluated_at=at,
            root=state.root if state is not None and state.resolved else None,
            epoch=state.epoch if state is not None and state.resolved else None,
            approval=approval,
            refusals=tuple(refusals),
            warnings=tuple(warnings),
        )

    if _as_did(agent) is None:
        return deny(
            ReasonCode.MALFORMED, f"the agent must be a usable Ed25519 did:key, got {agent!r}"
        )

    state = resolve_lineage(bundle, lineage=lineage, at=at)
    warnings.extend(state.warnings)
    if not state.resolved or state.root is None or state.epoch is None:
        # A chain must terminate at a current root. If the lineage itself cannot
        # be resolved -- conflicted, missing genesis -- there is nothing for a
        # chain to terminate at, and the lineage's own reason code is the honest
        # answer rather than a generic denial.
        return deny(state.reason, f"the lineage does not resolve: {state.detail}", state=state)

    grants = _collect_grants(bundle, lineage=lineage, refusals=refusals)
    revoked = _collect_revocations(
        bundle, lineage=lineage, grants=grants, root=state.root, refusals=refusals
    )

    held = sorted(
        (g for g in grants.values() if g.subject == agent),
        key=lambda g: g.event_id,
    )
    if not held:
        return deny(
            ReasonCode.DENIED,
            f"no grant in this bundle delegates to {agent}",
            state=state,
        )

    candidates = [
        g for g in held if g.covers(namespace=namespace, resource=resource, action=action)
    ]
    if not candidates:
        for grant in held:
            refusals.append(
                Refusal(
                    grant.event_id,
                    ReasonCode.SCOPE_VIOLATION,
                    f"does not cover {namespace}:{resource} [{action}]",
                )
            )
        return deny(
            ReasonCode.SCOPE_VIOLATION,
            f"{agent} holds {len(held)} grant(s), none covering {request.render()}",
            state=state,
        )

    best: _Chain | None = None
    for grant in candidates:
        outcome = _walk_to_root(
            grant, grants=grants, revoked=revoked, state=state, at=at, request=request
        )
        if isinstance(outcome, tuple):
            refusals.append(Refusal(grant.event_id, outcome[0], outcome[1]))
            continue
        # Several chains may authorize the same action. Prefer the one demanding
        # the least approval: refusing it because a *different*, stricter path
        # also exists would deny authority the holder genuinely has.
        if best is None or outcome.approval < best.approval:
            best = outcome

    if best is None:
        # Report the most specific refusal rather than a bare DENIED. Ordering is
        # by how much it tells the holder about what to fix.
        priority = [
            ReasonCode.REVOKED,
            ReasonCode.SUPERSEDED,
            ReasonCode.EXPIRED,
            ReasonCode.NOT_YET_VALID,
            ReasonCode.SCOPE_VIOLATION,
            ReasonCode.UNRESOLVED_PARENT,
            ReasonCode.DENIED,
            ReasonCode.MALFORMED,
        ]
        for reason in priority:
            match = next((r for r in refusals if r.reason is reason), None)
            if match is not None:
                return deny(reason, f"grant {match.event_id}: {match.detail}", state=state)
        return deny(ReasonCode.DENIED, "no valid authority chain", state=state)

    needs_approval = best.approval is ApprovalMode.REQUIRED or (
        best.approval is ApprovalMode.EXTERNAL_ONLY and external
    )
    common: dict[str, Any] = {
        "request": request,
        "lineage": lineage,
        "evaluated_at": at,
        "root": state.root,
        "epoch": state.epoch,
        "path": best.path,
        "approval": best.approval,
        "refusals": tuple(refusals),
        "warnings": tuple(warnings),
    }
    if needs_approval:
        # The chain is sound; what is missing is a human's signature on this
        # exact action. That is a receipt (docs/06), and Phase 3 supplies it --
        # so this is emphatically not a denial of authority.
        return AuthorityDecision(
            allowed=False,
            reason=ReasonCode.APPROVAL_REQUIRED,
            detail=(
                f"authority is valid, but the chain requires "
                f"{best.approval.wire_name} human approval for this action"
            ),
            **common,
        )
    return AuthorityDecision(
        allowed=True,
        reason=ReasonCode.VALID_AUTHORITY_CHAIN,
        detail=(
            f"authorized by a chain of {len(best.path)} grant(s) terminating at the "
            f"current root of epoch {state.epoch}. {PROVIDER_AUTH_NOTE}"
        ),
        **common,
    )


@dataclass(frozen=True, slots=True)
class GrantStanding:
    """Where one grant stands right now, and why.

    Separate from `check_permission` on purpose. That answers "may this agent do
    this exact thing", which is a question about one request. This answers "is
    this grant live", which is what an operator looking at a lineage wants and
    what a graph needs in order to draw an edge honestly.

    `usable` means this grant *and every grant above it* on the chain to the root
    are current -- none revoked, all inside their windows, all anchored to the
    current epoch. It is still not permission: it says nothing about whether the
    scopes cover any particular action, so it is never on its own a reason to
    permit anything.

    It used to mean only that the grant itself was current. That was true, and it
    was a trap: every caller read it as a statement about the chain, because the
    honest picture a graph or a passport needs *is* the chain. Revoking a parent
    left the child drawn as a live edge hanging off a revoked one, and left a
    receipt citing that child reading as supported by a valid authority chain
    (D-103).
    """

    grant: Grant
    usable: bool
    reason: ReasonCode
    detail: str
    revoked_by: str | None = None


def describe_grants(
    bundle: EventBundle, *, lineage: str, at: datetime
) -> tuple[GrantStanding, ...]:
    """Report the standing of every delegation grant in a lineage.

    Ordered by event id, so two callers with the same events get the same list.
    """
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")

    state = resolve_lineage(bundle, lineage=lineage, at=at)
    refusals: list[Refusal] = []
    grants = _collect_grants(bundle, lineage=lineage, refusals=refusals)
    revoked: dict[str, str] = {}
    if state.resolved and state.root is not None:
        revoked = _collect_revocations(
            bundle, lineage=lineage, grants=grants, root=state.root, refusals=refusals
        )

    out: list[GrantStanding] = []
    for event_id in sorted(grants):
        grant = grants[event_id]
        if not state.resolved or state.epoch is None:
            out.append(
                GrantStanding(
                    grant=grant,
                    usable=False,
                    reason=state.reason,
                    detail=f"the lineage does not resolve: {state.detail}",
                )
            )
            continue
        outcome = _walk_to_root(
            grant, grants=grants, revoked=revoked, state=state, at=at, request=None
        )
        if isinstance(outcome, _Chain):
            out.append(
                GrantStanding(
                    grant=grant,
                    usable=True,
                    reason=ReasonCode.VALID_AUTHORITY_CHAIN,
                    detail=(
                        f"the grant is current, and so is every one of the {len(outcome.path)} "
                        "grant(s) on the chain from it to the root. This is not permission for "
                        "any particular action -- ask check_permission for that."
                    ),
                )
            )
            continue
        out.append(
            GrantStanding(
                grant=grant,
                usable=False,
                reason=outcome[0],
                detail=outcome[1],
                revoked_by=revoked.get(grant.event_id),
            )
        )
    return tuple(out)
