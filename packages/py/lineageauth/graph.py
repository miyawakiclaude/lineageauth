"""The authority graph: a projection, not a decision.

`docs/17_UI_UX.md` asks for a picture of a lineage -- roots, agents, recovery
members, and the edges between them. This builds it, and it decides nothing:
every status here is read off the resolver and the authority layer rather than
worked out again. A drawing that computed its own answers could disagree with
the verifier, and a picture that disagrees with the verifier is worse than no
picture, because people believe pictures.

`docs/17` also pins the vocabulary. Nodes and edges carry statuses like
`revoked`, `superseded`, `expired`, and never anything that reads as *trusted*,
*official*, or *safe*. A key that signed a thousand events and holds no
authority must not be drawn as though it does.

Determinism matters here too. Same events, same `at`, same graph -- nodes and
edges come out sorted, so a diff between two renderings means the events
changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from lineageauth.approval import APPROVAL_RECEIPT, read_receipt
from lineageauth.authority import describe_grants
from lineageauth.bundle import EventBundle
from lineageauth.errors import ReasonCode
from lineageauth.lineage import RECOVERY_POLICY, resolve_lineage
from lineageauth.timeutil import format_instant


class NodeKind(StrEnum):
    """What a node is. Roles, not verdicts about the people behind them."""

    CURRENT_ROOT = "current-root"
    GENESIS_ROOT = "genesis-root"
    SUPERSEDED_ROOT = "superseded-root"
    AGENT = "agent"
    RECOVERY_MEMBER = "recovery-member"
    APPROVER = "approver"


class EdgeKind(StrEnum):
    """What one node did to another, according to a signed event."""

    DELEGATED = "delegated"
    SUCCEEDED = "succeeded"
    RECOVERED = "recovered"
    APPROVED = "approved"
    RECOVERY_MEMBER_OF = "recovery-member-of"


@dataclass(frozen=True, slots=True)
class Node:
    """One DID in the graph, with the roles it holds."""

    did: str
    kinds: tuple[NodeKind, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"did": self.did, "kinds": [str(kind) for kind in self.kinds]}


@dataclass(frozen=True, slots=True)
class Edge:
    """One relationship, and the event that asserts it."""

    source: str
    target: str
    kind: EdgeKind
    event_id: str
    live: bool
    reason: ReasonCode
    detail: str
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": str(self.kind),
            "eventId": self.event_id,
            # `live` is the only boolean, and it is deliberately not called
            # "valid" or "trusted": it means this edge is in force right now.
            "live": self.live,
            "reason": str(self.reason),
            "detail": self.detail,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class AuthorityGraph:
    """A rendering-ready projection of one lineage."""

    lineage: str
    resolved: bool
    reason: ReasonCode
    detail: str
    evaluated_at: datetime
    root: str | None
    epoch: int | None
    nodes: tuple[Node, ...] = ()
    edges: tuple[Edge, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        return (
            "A node in this graph is a key with a role, not a person, an organisation, "
            "or a guarantee. An edge means a signed event asserts that relationship. "
            "Neither implies the holder is trustworthy."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "lineage": self.lineage,
            "resolved": self.resolved,
            "reason": str(self.reason),
            "detail": self.detail,
            "evaluatedAt": format_instant(self.evaluated_at),
            "root": self.root if self.resolved else None,
            "epoch": self.epoch if self.resolved else None,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "warnings": list(self.warnings),
            "note": self.note,
        }


def build_graph(bundle: EventBundle, *, lineage: str, at: datetime) -> AuthorityGraph:
    """Project one lineage into nodes and edges."""
    state = resolve_lineage(bundle, lineage=lineage, at=at)
    roles: dict[str, set[NodeKind]] = {}
    edges: list[Edge] = []

    def role(did: str, kind: NodeKind) -> None:
        roles.setdefault(did, set()).add(kind)

    if state.genesis_root is not None:
        role(state.genesis_root, NodeKind.GENESIS_ROOT)
    if state.resolved and state.root is not None:
        role(state.root, NodeKind.CURRENT_ROOT)
    for did in state.superseded_roots:
        role(did, NodeKind.SUPERSEDED_ROOT)

    # ---- succession edges, straight off the resolved history ----
    for step in state.history:
        role(step.from_root, NodeKind.SUPERSEDED_ROOT)
        kind = EdgeKind.RECOVERED if step.mode == "recovery" else EdgeKind.SUCCEEDED
        for event_id in step.via_event_ids:
            edges.append(
                Edge(
                    source=step.from_root,
                    target=step.to_root,
                    kind=kind,
                    event_id=event_id,
                    live=True,
                    reason=ReasonCode.VALID_AUTHORITY_CHAIN,
                    detail=f"epoch {step.from_epoch} -> {step.to_epoch} ({step.mode})",
                    label=f"epoch {step.to_epoch}",
                )
            )

    # ---- recovery membership ----
    for event in bundle.of_type(RECOVERY_POLICY, lineage=lineage):
        members = event.get("members")
        if not isinstance(members, list):
            continue
        active = state.active_recovery_policy
        live = active is not None and active.event_id == event.event_id
        for member in members:
            if not isinstance(member, str):
                continue
            role(member, NodeKind.RECOVERY_MEMBER)
            edges.append(
                Edge(
                    source=member,
                    target=lineage,
                    kind=EdgeKind.RECOVERY_MEMBER_OF,
                    event_id=event.event_id,
                    live=live,
                    reason=(ReasonCode.VALID_AUTHORITY_CHAIN if live else ReasonCode.SUPERSEDED),
                    detail=(
                        "named by the active recovery policy"
                        if live
                        else "named by a policy that is not the active one"
                    ),
                    label=f"{event.get('threshold')} of {len(members)}",
                )
            )

    # ---- delegation edges, with standing from the authority layer ----
    for standing in describe_grants(bundle, lineage=lineage, at=at):
        grant = standing.grant
        role(grant.subject, NodeKind.AGENT)
        detail = standing.detail
        if standing.revoked_by is not None:
            detail = f"{detail} (revoked by {standing.revoked_by})"
        edges.append(
            Edge(
                source=grant.issuer,
                target=grant.subject,
                kind=EdgeKind.DELEGATED,
                event_id=grant.event_id,
                live=standing.usable,
                reason=standing.reason,
                detail=detail,
                label=", ".join(sorted(scope.render() for scope in grant.scopes)),
            )
        )

    # ---- approvals ----
    for event in bundle.of_type(APPROVAL_RECEIPT, lineage=lineage):
        receipt = read_receipt(event)
        if isinstance(receipt, str):
            continue
        role(receipt.approver, NodeKind.APPROVER)
        role(receipt.agent, NodeKind.AGENT)
        expired = at >= receipt.expires_at
        edges.append(
            Edge(
                source=receipt.approver,
                target=receipt.agent,
                kind=EdgeKind.APPROVED,
                event_id=event.event_id,
                live=not expired,
                reason=ReasonCode.EXPIRED if expired else ReasonCode.VALID_AUTHORITY_CHAIN,
                detail=(
                    f"approved {receipt.request.render()}"
                    + (f"; expired at {receipt.expires_at.isoformat()}" if expired else "")
                ),
                label=receipt.request.action,
            )
        )

    nodes = tuple(Node(did=did, kinds=tuple(sorted(kinds))) for did, kinds in sorted(roles.items()))
    ordered_edges = tuple(
        sorted(edges, key=lambda e: (e.event_id, str(e.kind), e.source, e.target))
    )
    return AuthorityGraph(
        lineage=lineage,
        resolved=state.resolved,
        reason=state.reason,
        detail=state.detail,
        evaluated_at=at,
        root=state.root,
        epoch=state.epoch,
        nodes=nodes,
        edges=ordered_edges,
        warnings=state.warnings,
    )
