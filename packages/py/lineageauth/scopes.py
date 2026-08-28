"""Scope grammar, namespace registry, and attenuation.

`docs/04_SCOPE_AUTHORIZATION.md` defines a scope as a namespace, a resource,
and a set of actions. This module decides two questions and nothing else:

    does this scope cover this request?
    is this child scope a subset of that parent scope?

Everything here fails closed. An unknown namespace, an unregistered action, or
a resource this grammar cannot parse is refused rather than passed through --
`docs/24_VERSIONING_MIGRATION.md` is explicit that an unknown namespace must
never silently authorize.

A scope grants nothing on its own. It says what a delegation *would* permit if
the chain above it is valid, current, and unrevoked; that is decided elsewhere.
And none of it substitutes for the provider's own authorization: LineageAuth
never bypasses OAuth, an API key, a repository permission, an MCP server's
policy, or an A2A server's policy. It is provenance layered on top.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType
from typing import Any

from lineageauth.errors import MalformedEventError

WILDCARD = "*"

# A resource is a sequence of segments split on ':' and '/'. Segment characters
# are deliberately narrow: no whitespace, no control characters, no regex
# metacharacters. Untrusted events supply these strings, and they end up in
# comparisons and in messages a human reads.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SPLIT_RE = re.compile(r"[:/]")


class ApprovalMode(IntEnum):
    """How much human involvement a scope demands.

    Ordered, because `docs/04` requires monotonicity: a child may strengthen the
    requirement and may never weaken it. `IntEnum` makes `child >= parent` the
    literal check rather than a lookup table someone can get backwards.
    """

    NONE = 0
    EXTERNAL_ONLY = 1
    REQUIRED = 2

    @classmethod
    def parse(cls, value: Any) -> ApprovalMode:
        """Read the wire spelling (`none`, `external-only`, `required`)."""
        if not isinstance(value, str) or value not in _APPROVAL_BY_NAME:
            raise MalformedEventError(
                f"approval mode must be one of {sorted(_APPROVAL_BY_NAME)}, got {value!r}"
            )
        return _APPROVAL_BY_NAME[value]

    @property
    def wire_name(self) -> str:
        """The spelling used inside a signed payload."""
        return _APPROVAL_TO_NAME[self]


_APPROVAL_BY_NAME: MappingProxyType[str, ApprovalMode] = MappingProxyType(
    {
        "none": ApprovalMode.NONE,
        "external-only": ApprovalMode.EXTERNAL_ONLY,
        "required": ApprovalMode.REQUIRED,
    }
)
_APPROVAL_TO_NAME: MappingProxyType[ApprovalMode, str] = MappingProxyType(
    {mode: name for name, mode in _APPROVAL_BY_NAME.items()}
)


@dataclass(frozen=True, slots=True)
class Namespace:
    """One transport's resource shapes and action vocabulary."""

    name: str
    actions: frozenset[str]
    # Each prefix maps to the number of segments that follow it. `None` means
    # the shape is open-ended, which currently nothing uses -- future
    # subresources (GitHub issues, HTTP paths) will need their own decision.
    resource_shapes: MappingProxyType[str, int]

    def describes(self, prefix: str) -> bool:
        return prefix in self.resource_shapes


def _ns(name: str, actions: set[str], shapes: dict[str, int]) -> Namespace:
    return Namespace(
        name=name, actions=frozenset(actions), resource_shapes=MappingProxyType(shapes)
    )


# docs/04_SCOPE_AUTHORIZATION.md. Adding a namespace or an action is a protocol
# change: an unregistered one is refused, never guessed at.
NAMESPACES: MappingProxyType[str, Namespace] = MappingProxyType(
    {
        "technocore": _ns(
            "technocore",
            {"read", "write", "create", "claim", "allow"},
            {"room": 1, "owned-room": 1, "note": 2},
        ),
        "mcp": _ns(
            "mcp",
            {"discover", "invoke"},
            {"server": 1, "server/tool": 2},
        ),
        "a2a": _ns(
            "a2a",
            {"discover", "message", "invoke", "task"},
            {"agent": 1, "skill": 1},
        ),
        "github": _ns(
            "github",
            {
                "read",
                "issue.create",
                "issue.comment",
                "pr.create",
                "pr.comment",
                "commit",
                "merge",
            },
            {"repo": 2},
        ),
        "http": _ns("http", {"get", "post", "put", "patch", "delete"}, {"host": 1}),
    }
)


@dataclass(frozen=True, slots=True)
class Resource:
    """A parsed resource: a prefix plus its segments, one of which may be `*`."""

    namespace: str
    prefix: str
    segments: tuple[str, ...]

    @property
    def has_wildcard(self) -> bool:
        return WILDCARD in self.segments

    def render(self) -> str:
        return f"{self.prefix}:{'/'.join(self.segments)}"

    def covers(self, other: Resource) -> bool:
        """True when this resource contains `other`.

        Containment is by segment. A trailing `*` stands for exactly one
        segment, never for an arbitrary depth of them: `repo:owner/*` covers
        `repo:owner/api` but not `repo:owner/api/issues`. The narrow reading is
        the safe one -- a wildcard that silently reached into subresources would
        grant authority nobody wrote down, and deny-by-default means an
        unmatched request is refused rather than guessed at. Widening this later
        is a compatible change; narrowing it would not be.
        """
        if (self.namespace, self.prefix) != (other.namespace, other.prefix):
            return False
        if len(self.segments) != len(other.segments):
            return False
        return all(
            mine == WILDCARD or mine == theirs
            for mine, theirs in zip(self.segments, other.segments, strict=True)
        )


def parse_resource(namespace: str, resource: Any) -> Resource:
    """Parse and validate a resource string against its namespace's grammar."""
    space = NAMESPACES.get(namespace)
    if space is None:
        raise MalformedEventError(
            f"unregistered scope namespace {namespace!r}; protocol 0.1 knows {sorted(NAMESPACES)}"
        )
    if not isinstance(resource, str) or not resource:
        raise MalformedEventError("resource must be a non-empty string")
    if ":" not in resource:
        raise MalformedEventError(
            f"resource must start with a type prefix, e.g. 'room:lobby', got {resource!r}"
        )

    prefix, _, remainder = resource.partition(":")
    # `server:<id>/tool:<tool>` is the one shape whose tail carries its own
    # prefix; normalise it to a two-segment `server/tool` shape.
    if namespace == "mcp" and "/tool:" in remainder:
        # The prefix has to be checked, not merely replaced. Overwriting it
        # unconditionally made `server:s/tool:t`, `tool:s/tool:t` and even
        # `zzz:s/tool:t` parse to one Resource. No authority is widened -- they
        # name the same thing -- but a signed grant then has several spellings,
        # and "one meaning, one encoding" is the rule everything else here keeps
        # (canonical did:key, sorted actions, re-encoded base64url).
        if prefix != "server":
            raise MalformedEventError(
                f"an mcp server/tool resource must begin with 'server:', got {prefix!r}"
            )
        server, _, tool = remainder.partition("/tool:")
        prefix, segments = "server/tool", [server, tool]
    else:
        segments = _SPLIT_RE.split(remainder) if remainder else []

    expected = space.resource_shapes.get(prefix)
    if expected is None:
        raise MalformedEventError(
            f"namespace {namespace!r} has no resource type {prefix!r}; "
            f"it defines {sorted(space.resource_shapes)}"
        )
    if len(segments) != expected:
        raise MalformedEventError(
            f"{namespace}:{prefix} takes {expected} segment(s), got {len(segments)} in {resource!r}"
        )
    for index, segment in enumerate(segments):
        if segment == WILDCARD:
            if index != len(segments) - 1:
                raise MalformedEventError(
                    "a wildcard is only allowed as the final segment of a resource; "
                    f"got {resource!r}"
                )
            continue
        if segment in (".", ".."):
            # `.` and `..` are legal under the segment alphabet but mean
            # "somewhere else" to almost every consumer that later joins a
            # resource into a path or a URL. Comparison here is exact, so they
            # would never traverse anything -- but a resource that reads as
            # traversal should not be storable in a signed grant at all.
            raise MalformedEventError(
                f"resource segment {segment!r} is a relative path element and is not "
                "a usable resource name"
            )
        if _SEGMENT_RE.fullmatch(segment) is None:
            raise MalformedEventError(
                f"resource segment {segment!r} contains characters outside "
                "[A-Za-z0-9._-]; untrusted events must not carry pattern syntax"
            )
    return Resource(namespace=namespace, prefix=prefix, segments=tuple(segments))


@dataclass(frozen=True, slots=True)
class Scope:
    """A namespace, a resource, and the actions permitted on it."""

    namespace: str
    resource: Resource
    actions: frozenset[str]

    @classmethod
    def parse(cls, value: Any) -> Scope:
        """Read a scope object out of a signed payload."""
        if not isinstance(value, dict):
            raise MalformedEventError("a scope must be a JSON object")
        unexpected = set(value) - {"namespace", "resource", "actions"}
        if unexpected:
            raise MalformedEventError(
                f"scope carries unrecognised field(s) {sorted(unexpected)}; a field this "
                "verifier cannot interpret may be a constraint it would be ignoring"
            )

        namespace = value.get("namespace")
        if not isinstance(namespace, str) or namespace not in NAMESPACES:
            raise MalformedEventError(
                f"unregistered scope namespace {namespace!r}; "
                f"protocol 0.1 knows {sorted(NAMESPACES)}"
            )
        resource = parse_resource(namespace, value.get("resource"))

        raw_actions = value.get("actions")
        if not isinstance(raw_actions, list) or not raw_actions:
            raise MalformedEventError("scope actions must be a non-empty array")
        known = NAMESPACES[namespace].actions
        actions: set[str] = set()
        for action in raw_actions:
            if not isinstance(action, str) or action not in known:
                raise MalformedEventError(
                    f"namespace {namespace!r} has no action {action!r}; it defines {sorted(known)}"
                )
            actions.add(action)
        if len(actions) != len(raw_actions):
            raise MalformedEventError("scope actions must be distinct")
        if sorted(raw_actions) != list(raw_actions):
            raise MalformedEventError(
                "scope actions must be in ascending order so one action set has one encoding"
            )
        return cls(namespace=namespace, resource=resource, actions=frozenset(actions))

    def covers(self, *, namespace: str, resource: str, action: str) -> bool:
        """True when this scope permits `action` on `resource`.

        A malformed request is not covered. It is not an exception either: a
        caller asking about nonsense gets a refusal, which is the same answer
        deny-by-default gives to anything it cannot match.
        """
        if namespace != self.namespace or action not in self.actions:
            return False
        try:
            target = parse_resource(namespace, resource)
        except MalformedEventError:
            return False
        return self.resource.covers(target)

    def contains(self, child: Scope) -> bool:
        """True when every permission `child` describes is one this scope holds."""
        return (
            self.namespace == child.namespace
            and child.actions <= self.actions
            and self.resource.covers(child.resource)
        )

    def render(self) -> str:
        return f"{self.namespace}:{self.resource.render()} [{','.join(sorted(self.actions))}]"


def parse_scopes(value: Any) -> tuple[Scope, ...]:
    """Read a scope array out of a signed payload."""
    if not isinstance(value, list) or not value:
        raise MalformedEventError("scopes must be a non-empty array")
    return tuple(Scope.parse(item) for item in value)


def attenuation_failure(parent: tuple[Scope, ...], child: tuple[Scope, ...]) -> str | None:
    """Return why `child` exceeds `parent`, or None when it does not.

    Every child scope must be contained by *some single* parent scope. Allowing
    a child to be assembled from parts of several parent scopes would let two
    narrow grants combine into one broader one -- read on repo A plus merge on
    repo B becoming merge on repo A.
    """
    for scope in child:
        if not any(candidate.contains(scope) for candidate in parent):
            return (
                f"scope {scope.render()} is not contained by any parent scope "
                f"({', '.join(p.render() for p in parent)})"
            )
    return None
