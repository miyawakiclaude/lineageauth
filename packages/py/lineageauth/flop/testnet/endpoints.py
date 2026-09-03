"""Where a request is allowed to go, and the fact that today the answer is nowhere.

An endpoint becomes executable only by being derived from an official snapshot
and carrying a `verifiedAt`. That is checked in the constructor, so an
executable entry that nobody verified cannot be built at all -- not built and
then rejected downstream, where a later refactor could route around the check.

The registry currently holds one entry: the simulation's. Its origin is
`https://testnet.simulation.invalid`, and RFC 6761 reserves `.invalid` as a name
that is guaranteed not to resolve. If every other guard in this package failed
at once, the packet would still have nowhere to go.

Community endpoints are `READABLE_IF_SAFE` and never executable. Unknown ones
are `BLOCKED`. A faucet URL posted in a room is a community endpoint no matter
how official the message sounds -- `sources.classify_source` decides that from
the origin, and this module does not get a second opinion.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import NetworkPhase, SourceClass, TestnetFailure, TestnetRefusal
from lineageauth.flop.sources import classify_source

SIMULATION_ORIGIN = "https://testnet.simulation.invalid"
"""RFC 6761 reserves `.invalid`: this name is guaranteed never to resolve."""

SIMULATION_NETWORK = "flop-simulation-local"

SIMULATION_ENDPOINT_ID = "simulation-inference"
SIMULATION_FAUCET_ENDPOINT_ID = "simulation-faucet"

# A path pattern is a literal path with `{name}` segments. Deliberately not a
# regular expression supplied by data: a registry entry is configuration, and
# configuration that can express catastrophic backtracking is a denial of
# service waiting for the day somebody edits the JSON.
_SEGMENT = re.compile(r"\{[a-z][a-z0-9_]*\}")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~\-/{}]*$")
# A concrete segment carries no braces: those belong to a pattern, not a value.
_SAFE_SEGMENT = re.compile(r"[A-Za-z0-9._~\-]+")


class EndpointDisposition(StrEnum):
    """What this tool may do with an endpoint. Four answers, no default."""

    EXECUTABLE = "EXECUTABLE"
    READABLE_IF_SAFE = "READABLE_IF_SAFE"
    SIMULATION = "SIMULATION"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class FlopEndpoint:
    """One place a request could be sent, and the provenance that decides it.

    `mutates_state` is recorded rather than inferred from the method, because a
    GET that changes something is exactly the trap `adapters/technocore/routes`
    exists to catch, and the FLOP network's eventual API is not this project's
    to assume.
    """

    endpoint_id: str
    purpose: str
    origin: str
    method: str
    path_pattern: str
    network: str
    source_url: str
    source_version: str
    verified_at: str | None = None
    mutates_state: bool = True
    auth_type: str = "unknown"
    enabled: bool = False
    source_class: SourceClass = SourceClass.UNKNOWN
    simulation: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        if not self.endpoint_id:
            raise MalformedEventError("an endpoint needs an id")
        scheme, netloc = urlsplit(self.origin).scheme, urlsplit(self.origin).netloc
        if scheme != "https":
            raise MalformedEventError(
                f"endpoint {self.endpoint_id} has origin {self.origin!r}: https is required, "
                "because an executor that will accept http will accept a downgrade"
            )
        if not netloc or urlsplit(self.origin).path not in ("", "/"):
            raise MalformedEventError(
                f"endpoint {self.endpoint_id} origin must be scheme://host with no path"
            )
        if self.method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise MalformedEventError(f"endpoint {self.endpoint_id} has method {self.method!r}")
        if not _SAFE_PATH.match(self.path_pattern):
            raise MalformedEventError(
                f"endpoint {self.endpoint_id} path {self.path_pattern!r} is not a literal path "
                "with {placeholder} segments"
            )
        if self.simulation and self.origin != SIMULATION_ORIGIN:
            raise MalformedEventError(
                f"a simulation endpoint must use {SIMULATION_ORIGIN}, which cannot resolve"
            )
        if not self.simulation and self.origin == SIMULATION_ORIGIN:
            raise MalformedEventError(
                f"{SIMULATION_ORIGIN} is the simulation's origin and may not be marked live"
            )

    @property
    def host(self) -> str:
        return urlsplit(self.origin).netloc

    @property
    def executable(self) -> bool:
        """Executable is derived, never stored.

        Three facts have to hold at once and none of them is a flag somebody can
        set on its own: the entry came from an official origin, a human
        verification is recorded against it, and it is enabled. A simulation
        entry is never executable however it is configured.
        """
        return (
            not self.simulation
            and self.enabled
            and self.verified_at is not None
            and self.source_class is SourceClass.OFFICIAL
        )

    @property
    def disposition(self) -> EndpointDisposition:
        if self.simulation:
            return EndpointDisposition.SIMULATION
        if self.executable:
            return EndpointDisposition.EXECUTABLE
        if self.source_class in (SourceClass.COMMUNITY, SourceClass.VERIFIED_THIRD_PARTY):
            return EndpointDisposition.READABLE_IF_SAFE
        if self.source_class is SourceClass.OFFICIAL:
            return EndpointDisposition.READABLE_IF_SAFE
        return EndpointDisposition.BLOCKED

    def url_for(self, path: str) -> str:
        """The full URL for a concrete path, refusing one the pattern does not cover."""
        if not self.matches_path(path):
            raise MalformedEventError(
                f"path {path!r} does not match endpoint {self.endpoint_id} "
                f"pattern {self.path_pattern!r}"
            )
        return f"{self.origin.rstrip('/')}{path}"

    def matches_path(self, path: str) -> bool:
        """Whether a concrete path fits the pattern, segment by segment.

        The character set is checked on the concrete path too, not only on the
        pattern in the registry. `url_for` concatenates origin and path, so a
        placeholder segment that accepted anything without a slash would let a
        query (`?admin=1`), a fragment, a userinfo `@` or a percent-encoded
        traversal (`%2e%2e%2f`) into the destination -- the destination that
        goes into the request hash and onto the approval screen. No official
        endpoint with a placeholder exists yet, which is exactly why this is
        worth fixing now rather than on the day one is registered.
        """
        if not isinstance(path, str) or not path.startswith("/") or ".." in path:
            return False
        if not _SAFE_PATH.match(path):
            return False
        wanted = self.path_pattern.split("/")
        given = path.split("/")
        if len(wanted) != len(given):
            return False
        for expected, actual in zip(wanted, given, strict=True):
            if _SEGMENT.fullmatch(expected):
                if not _SAFE_SEGMENT.fullmatch(actual):
                    return False
                continue
            if expected != actual:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.endpoint_id,
            "purpose": self.purpose,
            "origin": self.origin,
            "host": self.host,
            "method": self.method,
            "pathPattern": self.path_pattern,
            "network": self.network,
            "sourceUrl": self.source_url,
            "sourceVersion": self.source_version,
            "verifiedAt": self.verified_at,
            "mutatesState": self.mutates_state,
            "authType": self.auth_type,
            "enabled": self.enabled,
            "sourceClass": str(self.source_class),
            "simulation": self.simulation,
            "executable": self.executable,
            "disposition": str(self.disposition),
            "note": self.note,
        }


def _simulation_entries() -> tuple[FlopEndpoint, ...]:
    return (
        FlopEndpoint(
            endpoint_id=SIMULATION_FAUCET_ENDPOINT_ID,
            purpose="faucet",
            origin=SIMULATION_ORIGIN,
            method="POST",
            path_pattern="/simulation/faucet",
            network=SIMULATION_NETWORK,
            source_url="local://simulation",
            source_version="simulation-1",
            mutates_state=False,
            auth_type="none",
            enabled=True,
            source_class=SourceClass.UNKNOWN,
            simulation=True,
            note="Synthetic. No FLOP network action. The origin cannot resolve (RFC 6761).",
        ),
        FlopEndpoint(
            endpoint_id=SIMULATION_ENDPOINT_ID,
            purpose="inference",
            origin=SIMULATION_ORIGIN,
            method="POST",
            path_pattern="/simulation/inference",
            network=SIMULATION_NETWORK,
            source_url="local://simulation",
            source_version="simulation-1",
            mutates_state=False,
            auth_type="none",
            enabled=True,
            source_class=SourceClass.UNKNOWN,
            simulation=True,
            note="Synthetic. No FLOP network action. The origin cannot resolve (RFC 6761).",
        ),
    )


@dataclass(frozen=True, slots=True)
class FlopEndpointRegistry:
    """The allowlist. Nothing outside it is reachable, by construction."""

    entries: tuple[FlopEndpoint, ...]

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for entry in self.entries:
            if entry.endpoint_id in seen:
                raise MalformedEventError(f"duplicate endpoint id {entry.endpoint_id!r}")
            seen.add(entry.endpoint_id)
            if not entry.executable:
                continue
            decision = classify_source(entry.source_url)
            if decision.source_class is not SourceClass.OFFICIAL:
                raise MalformedEventError(
                    f"endpoint {entry.endpoint_id} claims to be executable, but its source "
                    f"{entry.source_url!r} classifies as {decision.source_class} "
                    f"({decision.reason}); only an official source makes an endpoint executable"
                )
            origin_decision = classify_source(entry.origin)
            if origin_decision.source_class is not SourceClass.OFFICIAL:
                raise MalformedEventError(
                    f"endpoint {entry.endpoint_id} claims to be executable, but its origin "
                    f"{entry.origin!r} classifies as {origin_decision.source_class}"
                )

    @classmethod
    def default(cls) -> FlopEndpointRegistry:
        """The registry as it stands today: simulation only, zero executable."""
        return cls(entries=_simulation_entries())

    @classmethod
    def from_entries(cls, entries: Iterable[FlopEndpoint]) -> FlopEndpointRegistry:
        return cls(entries=tuple(entries))

    @property
    def executable_entries(self) -> tuple[FlopEndpoint, ...]:
        return tuple(entry for entry in self.entries if entry.executable)

    @property
    def allowed_origins(self) -> frozenset[str]:
        return frozenset(entry.origin for entry in self.entries)

    def get(self, endpoint_id: str) -> FlopEndpoint | None:
        for entry in self.entries:
            if entry.endpoint_id == endpoint_id:
                return entry
        return None

    def resolve(self, endpoint_id: str, *, phase: NetworkPhase) -> FlopEndpoint | TestnetRefusal:
        """The endpoint to use, or the typed reason there is none.

        A simulation entry resolves in any phase -- it is the thing that works
        when nothing else does. A live entry resolves only when it is executable
        *and* the phase says the testnet is on.
        """
        entry = self.get(endpoint_id)
        if entry is None:
            return TestnetRefusal(
                failure=TestnetFailure.ENDPOINT_BLOCKED,
                detail=(
                    f"no endpoint {endpoint_id!r} is registered; an endpoint that is not in "
                    "the allowlist is blocked rather than attempted"
                ),
                stage="endpoint",
            )
        if entry.simulation:
            return entry
        if not entry.executable:
            return TestnetRefusal(
                failure=TestnetFailure.ENDPOINT_NOT_OFFICIAL,
                detail=(
                    f"endpoint {endpoint_id!r} is {entry.disposition}: it is not derived from a "
                    "verified official source, so it may be read about but never executed"
                ),
                stage="endpoint",
            )
        if not phase.testnet_is_live:
            return TestnetRefusal(
                failure=TestnetFailure.TESTNET_NOT_LIVE,
                detail=f"endpoint {endpoint_id!r} exists but the phase is {phase}",
                stage="endpoint",
            )
        return entry

    def classify_candidate(self, url: object) -> dict[str, Any]:
        """What this tool would do with a URL somebody found. It fetches nothing.

        The answer for a faucet URL posted by a community source is
        `READABLE_IF_SAFE`, which reads as "you may look at where it came from",
        not "you may call it".
        """
        decision = classify_source(url)
        registered = None
        if isinstance(url, str):
            split = urlsplit(url)
            origin = f"{split.scheme}://{split.netloc}"
            for entry in self.entries:
                if entry.origin == origin and entry.matches_path(split.path or "/"):
                    registered = entry
                    break
        if registered is not None:
            disposition = registered.disposition
        elif decision.source_class in (SourceClass.COMMUNITY, SourceClass.VERIFIED_THIRD_PARTY):
            disposition = EndpointDisposition.READABLE_IF_SAFE
        else:
            disposition = EndpointDisposition.BLOCKED
        return {
            "url": decision.url,
            "sourceClass": str(decision.source_class),
            "reason": decision.reason,
            "disposition": str(disposition),
            "executable": registered is not None and registered.executable,
            "registeredEndpointId": None if registered is None else registered.endpoint_id,
            "fetched": False,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "executableCount": len(self.executable_entries),
            "officialTestnetExecutable": bool(self.executable_entries),
            "simulationOrigin": SIMULATION_ORIGIN,
            "note": (
                "An endpoint is executable only when it comes from a verified official "
                "source. The simulation's origin is reserved by RFC 6761 and cannot resolve."
            ),
        }


def endpoint_from_mapping(entry: Mapping[str, Any]) -> FlopEndpoint:
    """Build one entry from a registry file, refusing anything under-specified."""
    required = ("id", "purpose", "origin", "method", "pathPattern", "network", "sourceUrl")
    for key in required:
        if not isinstance(entry.get(key), str) or not entry[key]:
            raise MalformedEventError(f"an endpoint entry needs a non-empty {key!r}")
    raw_class = entry.get("sourceClass", "unknown")
    source_class = (
        SourceClass(raw_class) if raw_class in tuple(SourceClass) else SourceClass.UNKNOWN
    )
    verified = entry.get("verifiedAt")
    return FlopEndpoint(
        endpoint_id=str(entry["id"]),
        purpose=str(entry["purpose"]),
        origin=str(entry["origin"]),
        method=str(entry["method"]),
        path_pattern=str(entry["pathPattern"]),
        network=str(entry["network"]),
        source_url=str(entry["sourceUrl"]),
        source_version=str(entry.get("sourceVersion", "")),
        verified_at=verified if isinstance(verified, str) else None,
        mutates_state=bool(entry.get("mutatesState", True)),
        auth_type=str(entry.get("authType", "unknown")),
        enabled=bool(entry.get("enabled", False)),
        source_class=source_class,
        simulation=bool(entry.get("simulation", False)),
        note=str(entry.get("note", "")),
    )


__all__ = [
    "SIMULATION_ENDPOINT_ID",
    "SIMULATION_FAUCET_ENDPOINT_ID",
    "SIMULATION_NETWORK",
    "SIMULATION_ORIGIN",
    "EndpointDisposition",
    "FlopEndpoint",
    "FlopEndpointRegistry",
    "endpoint_from_mapping",
]
