"""Fleet transparency: voluntary disclosure that several DIDs share an operator.

`docs/13_FLEET_TRANSPARENCY.md` describes a positive act. A network of many DIDs
can look like a crowd when it is one operator, and this gives that operator a way
to say so. What it emphatically does not do is detect the operators who stay
quiet.

Two sentences from that document drive the whole design.

    Binding proves: the signing controller asserted a relationship.
    It does NOT prove ... all hidden DIDs disclosed.

So an absent fleet is not evidence of independence. Anything that treated "no
disclosed fleet" as "independent" would reward silence, which is the opposite of
what disclosure is for.

    Never penalize disclosure in a hidden way; ranking policy must be documented.

This is the sharper constraint, and it is easy to violate by accident. The
obvious move is to subtract points when a verifier turns out to be a fleet
sibling -- and that would make disclosure cost the honest operator exactly what
it saves the quiet one. `same_fleet` therefore stops a relationship *counting as
independent*; it never subtracts. "Disclosure costs you" and "what you disclosed
is not double-counted" are different rules, and only the second is safe to
publish.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError
from lineageauth.timeutil import format_instant, parse_instant

FLEET_CREATE = "fleet.create"
FLEET_BIND = "fleet.bind"
FLEET_UNBIND = "fleet.unbind"

FLEET_NOTE = (
    "A fleet is a voluntary disclosure. A binding proves that the signing "
    "controller asserted a relationship -- not that one legal person holds both "
    "keys, and never that every DID an operator runs has been disclosed. An "
    "agent with no fleet is not thereby independent; it has only said nothing."
)


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
class Fleet:
    """A disclosed group and who says they run it."""

    event_id: str
    controller: str
    name: str


@dataclass(frozen=True, slots=True)
class Binding:
    """One DID declared part of a fleet, by that fleet's controller."""

    event_id: str
    fleet: str
    controller: str
    member: str
    role: str | None
    expires_at: datetime | None
    issued_at: datetime

    def is_current(self, at: datetime, *, unbound: frozenset[str]) -> bool:
        if self.event_id in unbound:
            return False
        return self.expires_at is None or at < self.expires_at


def read_fleet(event: AdmittedEvent) -> Fleet | str:
    """Validate a `fleet.create` payload, returning it or a complaint."""
    controller = _as_did(event.get("controller"))
    if controller is None:
        return "controller must be a usable Ed25519 did:key"
    if not event.signed_by(controller):
        return f"not signed by the controller it names ({controller})"
    name = _as_str(event.get("name"))
    if not name:
        return "name must be a non-empty string"
    return Fleet(event_id=event.event_id, controller=controller, name=name)


def read_binding(event: AdmittedEvent) -> Binding | str:
    """Validate a `fleet.bind` payload, returning it or a complaint."""
    fleet = event.get("fleet")
    if not is_event_id(fleet):
        return "fleet must be the event id of a fleet.create"
    controller = _as_did(event.get("controller"))
    member = _as_did(event.get("member"))
    if controller is None or member is None:
        return "controller and member must both be usable Ed25519 did:key values"
    if not event.signed_by(controller):
        # Signed by the controller, not the member: the claim is "I operate
        # this", which is the controller's to make. A binding anyone could mint
        # would let a stranger tar an unrelated agent as part of their fleet.
        return f"not signed by the controller it names ({controller})"

    expires_at: datetime | None = None
    if event.get("expiresAt") is not None:
        try:
            expires_at = parse_instant(event.get("expiresAt"), field="expiresAt")
        except MalformedEventError as exc:
            return str(exc)

    return Binding(
        event_id=event.event_id,
        fleet=str(fleet),
        controller=controller,
        member=member,
        role=_as_str(event.get("role")),
        expires_at=expires_at,
        issued_at=event.issued_at,
    )


@dataclass(frozen=True, slots=True)
class FleetView:
    """Every disclosed fleet in a bundle, and who is currently in one."""

    fleets: tuple[Fleet, ...] = ()
    bindings: tuple[Binding, ...] = ()
    evaluated_at: datetime | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        return FLEET_NOTE

    def fleets_of(self, did: str) -> tuple[str, ...]:
        """The fleets this DID is currently disclosed as part of."""
        return tuple(sorted({b.fleet for b in self.bindings if b.member == did}))

    def members_of(self, fleet_id: str) -> tuple[str, ...]:
        """Currently bound members, plus the controller that runs them."""
        members = {b.member for b in self.bindings if b.fleet == fleet_id}
        for fleet in self.fleets:
            if fleet.event_id == fleet_id:
                members.add(fleet.controller)
        return tuple(sorted(members))

    def same_fleet(self, one: str, other: str) -> bool:
        """True when a disclosure ties these two DIDs together.

        False means no disclosure ties them -- not that they are unrelated.
        """
        if one == other:
            return True
        shared = set(self.fleets_of(one)) & set(self.fleets_of(other))
        if shared:
            return True
        # A controller and its own members are the same operator by assertion,
        # even though the controller is not bound to its own fleet.
        for fleet in self.fleets:
            members = set(self.members_of(fleet.event_id))
            if {one, other} <= members:
                return True
        return False

    def related_to(self, did: str) -> frozenset[str]:
        """Every DID a disclosure ties to this one, including itself."""
        related = {did}
        for fleet_id in self.fleets_of(did):
            related |= set(self.members_of(fleet_id))
        for fleet in self.fleets:
            if fleet.controller == did:
                related |= set(self.members_of(fleet.event_id))
        return frozenset(related)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fleets": [
                {
                    "eventId": f.event_id,
                    "controller": f.controller,
                    "name": f.name,
                    "members": list(self.members_of(f.event_id)),
                }
                for f in self.fleets
            ],
            "bindings": [
                {
                    "eventId": b.event_id,
                    "fleet": b.fleet,
                    "controller": b.controller,
                    "member": b.member,
                    "role": b.role,
                    "expiresAt": format_instant(b.expires_at) if b.expires_at else None,
                }
                for b in self.bindings
            ],
            "warnings": list(self.warnings),
            "note": self.note,
        }


def resolve_fleets(bundle: EventBundle, *, lineage: str, at: datetime) -> FleetView:
    """Read the disclosed fleets from a bundle, at a stated time."""
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")

    warnings: list[str] = []
    fleets: dict[str, Fleet] = {}
    for event in bundle.of_type(FLEET_CREATE, lineage=lineage):
        parsed = read_fleet(event)
        if isinstance(parsed, str):
            warnings.append(f"fleet.create {event.event_id} ignored: {parsed}")
            continue
        fleets[parsed.event_id] = parsed

    candidates: dict[str, Binding] = {}
    for event in bundle.of_type(FLEET_BIND, lineage=lineage):
        parsed_binding = read_binding(event)
        if isinstance(parsed_binding, str):
            warnings.append(f"fleet.bind {event.event_id} ignored: {parsed_binding}")
            continue
        fleet = fleets.get(parsed_binding.fleet)
        if fleet is None:
            warnings.append(
                f"fleet.bind {parsed_binding.event_id} ignored: this bundle carries no "
                f"fleet.create with id {parsed_binding.fleet}"
            )
            continue
        if fleet.controller != parsed_binding.controller:
            # Only the fleet's own controller may add to it.
            warnings.append(
                f"fleet.bind {parsed_binding.event_id} ignored: signed by "
                f"{parsed_binding.controller}, but the fleet is controlled by "
                f"{fleet.controller}"
            )
            continue
        candidates[parsed_binding.event_id] = parsed_binding

    unbound: set[str] = set()
    for event in bundle.of_type(FLEET_UNBIND, lineage=lineage):
        target = event.get("bind")
        controller = _as_did(event.get("controller"))
        if not is_event_id(target) or controller is None or not event.signed_by(controller):
            warnings.append(f"fleet.unbind {event.event_id} ignored: malformed or unsigned")
            continue
        binding = candidates.get(str(target))
        if binding is None:
            continue
        if binding.controller != controller:
            warnings.append(
                f"fleet.unbind {event.event_id} ignored: only the controller that made "
                "a binding may end it"
            )
            continue
        unbound.add(str(target))

    current = tuple(
        sorted(
            (b for b in candidates.values() if b.is_current(at, unbound=frozenset(unbound))),
            key=lambda b: b.event_id,
        )
    )
    return FleetView(
        fleets=tuple(sorted(fleets.values(), key=lambda f: f.event_id)),
        bindings=current,
        evaluated_at=at,
        warnings=tuple(warnings),
    )


__all__ = [
    "FLEET_BIND",
    "FLEET_CREATE",
    "FLEET_NOTE",
    "FLEET_UNBIND",
    "Binding",
    "Fleet",
    "FleetView",
    "read_binding",
    "read_fleet",
    "resolve_fleets",
]
