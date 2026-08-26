"""Semantic classification of Technocore routes.

Technocore performs writes through plain `GET`. That is a deliberate design
choice upstream -- it lets an agent whose sandbox only allows `webfetch` be a
full peer -- and it means the HTTP verb carries no information about
consequence. `CLAUDE.md` 2.4 and D-016 both say the same thing: classify by
what a route *does*, never by how it is spelled.

So this module is an allowlist, and the default is refusal. A route this table
does not recognise is `UNKNOWN`, and `UNKNOWN` is not "probably a read" -- it is
"do not call this automatically". Upstream can add routes at any time, and the
one that gets added while nobody is looking should fail closed.

Classification checked against the official specification on 2026-08-26. It is
a snapshot of someone else's service and must be re-checked before shipping any
integration that acts on it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from lineageauth.errors import MalformedEventError

SERVICE_ORIGIN = "https://technocore.chat"
SERVICE_HOST = "technocore.chat"


class Consequence(StrEnum):
    """What calling a route does."""

    READ = "read"
    WRITE = "write"
    UNKNOWN = "unknown"

    @property
    def safe_to_call_automatically(self) -> bool:
        """Only reads. UNKNOWN is treated as unsafe, not as unclassified."""
        return self is Consequence.READ


@dataclass(frozen=True, slots=True)
class Route:
    """One recognised route pattern and what it does."""

    pattern: re.Pattern[str]
    consequence: Consequence
    description: str
    signed: bool = False


def _route(
    pattern: str, consequence: Consequence, description: str, *, signed: bool = False
) -> Route:
    return Route(re.compile(pattern), consequence, description, signed=signed)


# Order matters: the first match wins, so write patterns are listed before the
# broader read patterns they would otherwise be swallowed by. `/r/<room>/say/x`
# must never fall through to "reading a room".
ROUTES: tuple[Route, ...] = (
    # ---- writes, all reachable by GET ----
    _route(
        r"^/r/[^/]+/say-signed/[^/]+/[^/]+/[^/]+/.*$",
        Consequence.WRITE,
        "post a signed message to a room",
        signed=True,
    ),
    _route(r"^/r/[^/]+/say/[^/]+/.*$", Consequence.WRITE, "post an unsigned message to a room"),
    _route(
        r"^/kv/[^/]+/[^/]+/set-signed/[^/]+/[^/]+/[^/]+/.*$",
        Consequence.WRITE,
        "write a signed note (room ownership and allow-lists use this)",
        signed=True,
    ),
    _route(r"^/kv/[^/]+/[^/]+/set/.*$", Consequence.WRITE, "write an unsigned note"),
    # ---- reads ----
    _route(r"^/r/events$", Consequence.READ, "discovery stream of new public rooms"),
    _route(r"^/r/[^/]+$", Consequence.READ, "read recent messages in a room"),
    _route(r"^/kv/[^/]+/[^/]+$", Consequence.READ, "read one note"),
    _route(r"^/kv/[^/]+$", Consequence.READ, "list the keys in a namespace"),
    _route(r"^/rooms$", Consequence.READ, "enumerate rooms"),
    _route(r"^/openapi\.json$", Consequence.READ, "OpenAPI description"),
    _route(r"^/\.well-known/[^/]*$", Consequence.READ, "service metadata and limits"),
    _route(r"^/healthz$", Consequence.READ, "health probe"),
    _route(
        r"^/(llms\.txt|skill\.md|patterns\.md|interop\.md|auth\.md)$",
        Consequence.READ,
        "service documentation",
    ),
    _route(r"^/$", Consequence.READ, "service front page"),
)


@dataclass(frozen=True, slots=True)
class Classification:
    """What a URL would do, and whether an adapter may call it unattended."""

    url: str
    consequence: Consequence
    description: str
    signed: bool
    detail: str

    @property
    def safe_to_call_automatically(self) -> bool:
        return self.consequence.safe_to_call_automatically


def classify(url: str, *, method: str = "GET") -> Classification:
    """Classify a Technocore URL by what it does.

    `method` is accepted and reported, but it does not decide anything. A `GET`
    to a say route is a write; a `POST` to a room is the same write by another
    spelling. Any method other than GET or POST is `UNKNOWN` -- upstream defines
    no others, and inventing a meaning for one would be exactly the guess this
    module exists to avoid.
    """
    if not isinstance(url, str) or not url:
        raise MalformedEventError("a URL to classify must be a non-empty string")

    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != SERVICE_HOST:
        # Refusing anything off-origin here is what stops a URL that arrived
        # inside a message -- untrusted data, never an instruction -- from being
        # classified as a safe Technocore read and then fetched.
        return Classification(
            url=url,
            consequence=Consequence.UNKNOWN,
            description="not a Technocore URL",
            signed=False,
            detail=(
                f"expected https://{SERVICE_HOST}, got scheme {parts.scheme!r} host "
                f"{parts.hostname!r}; this classifier speaks only for Technocore"
            ),
        )
    if parts.port not in (None, 443):
        return Classification(
            url=url,
            consequence=Consequence.UNKNOWN,
            description="non-standard port",
            signed=False,
            detail=f"port {parts.port} is not the service's",
        )
    if method not in ("GET", "POST"):
        return Classification(
            url=url,
            consequence=Consequence.UNKNOWN,
            description="unrecognised method",
            signed=False,
            detail=f"upstream documents GET and POST only, got {method!r}",
        )

    path = parts.path or "/"

    # Dot segments never reach the route table. `urlsplit` does not normalise
    # them, but proxies, caches, and the server itself may, so `/kv/../x` can be
    # classified as one route here and resolved as another there. Percent-
    # encoding does not help: `quote` leaves `.` alone, so a caller escaping its
    # inputs correctly still produces them.
    if any(segment in (".", "..") for segment in path.split("/")):
        return Classification(
            url=url,
            consequence=Consequence.UNKNOWN,
            description="path contains a relative segment",
            signed=False,
            detail=(
                f"path {path!r} contains a '.' or '..' segment; what this classifier "
                "matches and what the server resolves could differ"
            ),
        )

    for route in ROUTES:
        if route.pattern.match(path):
            consequence = route.consequence
            if method == "POST" and consequence is Consequence.READ:
                # Upstream's POST routes are the body-carrying spellings of
                # writes. A POST to something this table calls a read is a shape
                # it does not describe.
                return Classification(
                    url=url,
                    consequence=Consequence.UNKNOWN,
                    description=route.description,
                    signed=route.signed,
                    detail="POST to a route documented only as a read",
                )
            return Classification(
                url=url,
                consequence=consequence,
                description=route.description,
                signed=route.signed,
                detail=f"matched the {consequence} route for {route.description}",
            )

    return Classification(
        url=url,
        consequence=Consequence.UNKNOWN,
        description="unrecognised route",
        signed=False,
        detail=(
            f"path {path!r} matches no route in the table checked on 2026-08-26; "
            "an unrecognised Technocore route is treated as unsafe to call, because "
            "writes here are reachable by GET and a new one would look like a read"
        ),
    )


def is_write(url: str, *, method: str = "GET") -> bool:
    """True when calling this URL would change state."""
    return classify(url, method=method).consequence is Consequence.WRITE


def assert_safe_to_read(url: str, *, method: str = "GET") -> Classification:
    """Return the classification, or raise if the URL must not be fetched."""
    result = classify(url, method=method)
    if not result.safe_to_call_automatically:
        raise MalformedEventError(
            f"refusing to fetch {url}: classified {result.consequence} -- {result.detail}"
        )
    return result
