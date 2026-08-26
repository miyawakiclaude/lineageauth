"""The impact graph: demonstrable downstream use, not vanity activity.

`docs/14_IMPACT_GRAPH.md` opens with that distinction and never lets go of it.
An artifact that exists is not an artifact that was used; an artifact reused by
its own author is not adoption; ten reuses by one key are one adopter.

This is also the piece a directory structurally cannot supply. A list can say a
tool exists. Only signed downstream use can say anyone picked it up -- which is
why `independent_reusers` is the number that matters here and raw edge count is
the one that does not.

Independence has three tiers, and `docs/14` names them:

    same key         the author reusing their own work
    same fleet       a disclosed sibling (docs/13)
    independent      everything else

The third tier is the weakest claim, not the strongest: "no disclosure ties
these two" is not "these two are unrelated". Undisclosed fleets remain possible,
so a high independent count means the evidence *looks* independent.

*No magic score.* `docs/14` allows a product to compute one only if the formula
is versioned, the inputs disclosed, and an explanation provided -- and forbids
calling it objective trust. So this module computes features and stops. The
router already knows how to turn features into an explainable relevance number;
duplicating that here would give two rankings to reconcile.

*Flags are heuristics.* Reciprocal loops, reuse concentrated in one key,
duplicate content hashes: all reported, none proof of wrongdoing. The document
says so and so does every flag this emits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError
from lineageauth.evidence import ARTIFACT_RECEIPT
from lineageauth.evidence import read_receipt as read_artifact_receipt
from lineageauth.fleet import FleetView, resolve_fleets

ARTIFACT_REUSE = "artifact.reuse"
ARTIFACT_IMPROVE = "artifact.improve"
IMPACT_ATTEST = "impact.attest"

IMPACT_NOTE = (
    "Impact counts downstream use that somebody signed for. It is not a measure "
    "of quality, and it is not a score. Reuse by the author is not adoption; ten "
    "reuses by one key are one adopter; and 'independent' here means no "
    "disclosure ties the parties together, which is weaker than knowing they are "
    "unrelated. The flags are heuristics, never proof of wrongdoing."
)


class Independence(StrEnum):
    """How far a downstream user is from the artifact's producer."""

    SAME_KEY = "same-key"
    SAME_FLEET = "same-fleet"
    INDEPENDENT = "independent"


class EdgeKind(StrEnum):
    REUSED = "reused"
    IMPROVED = "improved"
    OBSERVED = "observed"


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
class ImpactEdge:
    """One signed statement that an artifact was used downstream."""

    event_id: str
    kind: EdgeKind
    actor: str
    subject: str
    """The artifact whose impact this is."""

    downstream: str | None
    """The artifact it was used in or improved into, when there is one."""

    independence: Independence
    note: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "eventId": self.event_id,
            "kind": str(self.kind),
            "actor": self.actor,
            "subject": self.subject,
            "downstream": self.downstream,
            "independence": str(self.independence),
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class ImpactFlag:
    """A shape worth a second look. Never a finding."""

    name: str
    detail: str


@dataclass(frozen=True, slots=True)
class ArtifactImpact:
    """What a bundle can demonstrate about one artifact's downstream use."""

    artifact_id: str
    producers: tuple[str, ...]
    edges: tuple[ImpactEdge, ...] = ()
    flags: tuple[ImpactFlag, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        return IMPACT_NOTE

    @property
    def independent_reusers(self) -> tuple[str, ...]:
        """Distinct keys, not tied by disclosure to a producer, that used this.

        The number that means something. Edge count does not: one key can emit
        as many reuse events as it likes.
        """
        return tuple(
            sorted(
                {edge.actor for edge in self.edges if edge.independence is Independence.INDEPENDENT}
            )
        )

    @property
    def same_fleet_reusers(self) -> tuple[str, ...]:
        return tuple(
            sorted({e.actor for e in self.edges if e.independence is Independence.SAME_FLEET})
        )

    @property
    def self_reuses(self) -> int:
        return sum(1 for e in self.edges if e.independence is Independence.SAME_KEY)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifactId": self.artifact_id,
            "producers": list(self.producers),
            # Counts of *keys*, alongside the raw edges, so a reader can see the
            # difference between adoption and one enthusiastic author.
            "independentReusers": list(self.independent_reusers),
            "sameFleetReusers": list(self.same_fleet_reusers),
            "selfReuses": self.self_reuses,
            "edges": [edge.to_dict() for edge in self.edges],
            "flags": [{"name": f.name, "detail": f.detail} for f in self.flags],
            "warnings": list(self.warnings),
            "note": self.note,
        }


def _producers_of(bundle: EventBundle, *, lineage: str, artifact_id: str) -> tuple[str, ...]:
    """Workers who signed a receipt claiming to have produced this artifact."""
    found: set[str] = set()
    for event in bundle.of_type(ARTIFACT_RECEIPT, lineage=lineage):
        parsed = read_artifact_receipt(event)
        if not isinstance(parsed, str) and parsed.artifact_id == artifact_id:
            found.add(parsed.worker)
    return tuple(sorted(found))


def _independence_of(actor: str, producers: tuple[str, ...], fleets: FleetView) -> Independence:
    if actor in producers:
        return Independence.SAME_KEY
    if any(fleets.same_fleet(actor, producer) for producer in producers):
        return Independence.SAME_FLEET
    return Independence.INDEPENDENT


def _read_reuse(event: AdmittedEvent) -> tuple[str, str, str, str | None] | str:
    reuser = _as_did(event.get("reuser"))
    if reuser is None:
        return "reuser must be a usable Ed25519 did:key"
    if not event.signed_by(reuser):
        # Signed by whoever used it. A reuse anyone could mint would let an
        # author manufacture their own downstream adoption.
        return f"not signed by the reuser it names ({reuser})"
    used, used_in = event.get("used"), event.get("usedIn")
    if not is_event_id(used) or not is_event_id(used_in):
        return "used and usedIn must both be sha256:<64 hex> references"
    return (reuser, str(used), str(used_in), _as_str(event.get("note")))


def _read_improve(event: AdmittedEvent) -> tuple[str, str, str, str | None] | str:
    author = _as_did(event.get("author"))
    if author is None:
        return "author must be a usable Ed25519 did:key"
    if not event.signed_by(author):
        return f"not signed by the author it names ({author})"
    improves, artifact = event.get("improves"), event.get("artifact")
    if not is_event_id(improves) or not is_event_id(artifact):
        return "improves and artifact must both be sha256:<64 hex> references"
    return (author, str(improves), str(artifact), _as_str(event.get("note")))


def collect_impact(
    bundle: EventBundle, *, lineage: str, artifact_id: str, at: datetime
) -> ArtifactImpact:
    """Gather every signed statement of downstream use for one artifact."""
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")
    if not is_event_id(artifact_id):
        raise MalformedEventError(
            f"artifactId must be sha256:<64 lowercase hex>, got {artifact_id!r}"
        )

    warnings: list[str] = []
    fleets = resolve_fleets(bundle, lineage=lineage, at=at)
    warnings.extend(fleets.warnings)
    producers = _producers_of(bundle, lineage=lineage, artifact_id=artifact_id)
    edges: list[ImpactEdge] = []

    for event in bundle.of_type(ARTIFACT_REUSE, lineage=lineage):
        parsed = _read_reuse(event)
        if isinstance(parsed, str):
            warnings.append(f"artifact.reuse {event.event_id} ignored: {parsed}")
            continue
        reuser, used, used_in, note = parsed
        if used != artifact_id:
            continue
        edges.append(
            ImpactEdge(
                event_id=event.event_id,
                kind=EdgeKind.REUSED,
                actor=reuser,
                subject=used,
                downstream=used_in,
                independence=_independence_of(reuser, producers, fleets),
                note=note,
            )
        )

    for event in bundle.of_type(ARTIFACT_IMPROVE, lineage=lineage):
        parsed_improve = _read_improve(event)
        if isinstance(parsed_improve, str):
            warnings.append(f"artifact.improve {event.event_id} ignored: {parsed_improve}")
            continue
        author, improves, artifact, note = parsed_improve
        if improves != artifact_id:
            continue
        edges.append(
            ImpactEdge(
                event_id=event.event_id,
                kind=EdgeKind.IMPROVED,
                actor=author,
                subject=improves,
                downstream=artifact,
                independence=_independence_of(author, producers, fleets),
                note=note,
            )
        )

    for event in bundle.of_type(IMPACT_ATTEST, lineage=lineage):
        issuer = _as_did(event.get("issuer"))
        subject = event.get("subjectRef")
        observed = _as_str(event.get("observed"))
        if issuer is None or not event.signed_by(issuer) or not is_event_id(subject):
            warnings.append(f"impact.attest {event.event_id} ignored: malformed or unsigned")
            continue
        if subject != artifact_id:
            continue
        edges.append(
            ImpactEdge(
                event_id=event.event_id,
                kind=EdgeKind.OBSERVED,
                actor=issuer,
                subject=str(subject),
                downstream=None,
                independence=_independence_of(issuer, producers, fleets),
                note=observed,
            )
        )

    ordered = tuple(sorted(edges, key=lambda e: (e.event_id, str(e.kind))))
    return ArtifactImpact(
        artifact_id=artifact_id,
        producers=producers,
        edges=ordered,
        flags=_flags_for(ordered, producers),
        warnings=tuple(warnings),
    )


def _flags_for(edges: tuple[ImpactEdge, ...], producers: tuple[str, ...]) -> tuple[ImpactFlag, ...]:
    """Shapes worth a second look. Heuristics, never findings.

    `docs/14` lists these and says plainly that a flag is not proof of
    wrongdoing, so each one describes what was observed rather than what it
    means.
    """
    flags: list[ImpactFlag] = []
    if not edges:
        return ()

    actors: dict[str, int] = {}
    for edge in edges:
        actors[edge.actor] = actors.get(edge.actor, 0) + 1

    top = max(actors.values())
    if len(edges) >= 3 and top / len(edges) > 0.5:
        loudest = sorted(a for a, n in actors.items() if n == top)[0]
        flags.append(
            ImpactFlag(
                name="reuse_concentration",
                detail=(
                    f"{top} of {len(edges)} downstream statements come from {loudest}. "
                    "One enthusiastic user is not broad adoption -- which may be "
                    "entirely innocent, and is worth seeing either way."
                ),
            )
        )

    self_edges = [e for e in edges if e.independence is Independence.SAME_KEY]
    if self_edges and len(self_edges) == len(edges):
        flags.append(
            ImpactFlag(
                name="only_self_reuse",
                detail=(
                    "every downstream statement is by a producer of this artifact. "
                    "Using your own work is normal; it is not evidence anyone else did."
                ),
            )
        )

    fleet_edges = [e for e in edges if e.independence is Independence.SAME_FLEET]
    if fleet_edges and not any(e.independence is Independence.INDEPENDENT for e in edges):
        flags.append(
            ImpactFlag(
                name="only_disclosed_siblings",
                detail=(
                    "every downstream statement is from a disclosed fleet sibling of a "
                    "producer. Visible only because somebody disclosed it -- an "
                    "undisclosed equivalent would look independent."
                ),
            )
        )

    if not producers:
        flags.append(
            ImpactFlag(
                name="no_signed_producer",
                detail=(
                    "no artifact.receipt in this bundle ties a key to producing this "
                    "artifact, so independence is measured against nobody."
                ),
            )
        )
    return tuple(flags)


__all__ = [
    "ARTIFACT_IMPROVE",
    "ARTIFACT_REUSE",
    "IMPACT_ATTEST",
    "IMPACT_NOTE",
    "ArtifactImpact",
    "EdgeKind",
    "ImpactEdge",
    "ImpactFlag",
    "Independence",
    "collect_impact",
]
