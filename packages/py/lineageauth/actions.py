"""The canonical description of one exact action.

`docs/06_APPROVAL_EXECUTION.md` separates four things that are easy to conflate:

    the agent can propose        the agent has authority
    a human approved *this*      the executor may perform

This module is about the third. An approval is worthless if it approves "post
to Technocore" in general; it has to bind the destination and the exact content,
so that a receipt obtained for one message cannot be spent on another.

The binding is a hash over a canonical object:

    requestHash = sha256( JCS(action request) )

Note what `contentHash` does and does not promise. It fixes the bytes an
executor may transmit. It says nothing about how a *transport* will frame them,
so every adapter must state which bytes it hashes -- `docs/06` requires exactly
that, and Technocore's signed lane is a live example: it signs
`<room>|<nonce>|<text>`, not the URL that carries it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from lineageauth import catalog
from lineageauth.canonical import is_event_id, jcs
from lineageauth.errors import MalformedEventError
from lineageauth.scopes import NAMESPACES, parse_resource

# A destination is shown to a human and then transmitted. Control characters in
# it could dress one destination up as another in the approval preview, which is
# precisely the decision the human is being asked to make.
_FORBIDDEN_IN_DESTINATION = frozenset(chr(code) for code in [*range(0x00, 0x20), 0x7F])

MAX_DESTINATION_LENGTH = 2048


def sha256_hex(data: bytes) -> str:
    """Content address for a byte string."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """Exactly what is about to happen, in the form an approval binds to.

    `destination` is the concrete place the effect lands -- a Technocore room, a
    repository, a host. `content_hash` fixes the bytes. Both are part of the
    hash, so a receipt for one destination cannot be replayed against another
    even when the content is identical.
    """

    namespace: str
    resource: str
    action: str
    destination: str
    content_hash: str

    def __post_init__(self) -> None:
        # Validated on construction: an ActionRequest that cannot be trusted to
        # describe one specific effect should not exist at all.
        parse_resource(self.namespace, self.resource)
        known = NAMESPACES[self.namespace].actions
        if self.action not in known:
            raise MalformedEventError(
                f"namespace {self.namespace!r} has no action {self.action!r}; "
                f"it defines {sorted(known)}"
            )
        if not isinstance(self.destination, str) or not self.destination:
            raise MalformedEventError("destination must be a non-empty string")
        if len(self.destination) > MAX_DESTINATION_LENGTH:
            raise MalformedEventError(f"destination exceeds {MAX_DESTINATION_LENGTH} characters")
        if _FORBIDDEN_IN_DESTINATION & set(self.destination):
            raise MalformedEventError(
                "destination contains control characters; it is shown to a human "
                "before they approve, and must not be able to disguise itself"
            )
        if not is_event_id(self.content_hash):
            raise MalformedEventError(
                f"contentHash must be sha256:<64 lowercase hex>, got {self.content_hash!r}"
            )

    @classmethod
    def over_bytes(
        cls, *, namespace: str, resource: str, action: str, destination: str, content: bytes
    ) -> ActionRequest:
        """Build a request that binds the exact bytes to be transmitted."""
        return cls(
            namespace=namespace,
            resource=resource,
            action=action,
            destination=destination,
            content_hash=sha256_hex(content),
        )

    def canonical(self) -> dict[str, Any]:
        """The object whose canonical bytes are hashed."""
        return {
            "protocol": catalog.PROTOCOL,
            "version": catalog.CORE_VERSION,
            "namespace": self.namespace,
            "resource": self.resource,
            "action": self.action,
            "destination": self.destination,
            "contentHash": self.content_hash,
        }

    @property
    def request_hash(self) -> str:
        """`sha256:<hex>` over the canonical request object (JCS + SHA-256)."""
        return "sha256:" + hashlib.sha256(jcs(self.canonical())).hexdigest()

    def render(self) -> str:
        return (
            f"{self.namespace}:{self.resource} [{self.action}] -> {self.destination} "
            f"content {self.content_hash}"
        )

    def matches(self, other: ActionRequest) -> bool:
        """True when both describe the same effect."""
        return self.request_hash == other.request_hash


def request_hash_of(value: Any) -> str:
    """Hash an already-canonical request object. Used to re-derive from a payload."""
    if not isinstance(value, dict):
        raise MalformedEventError("an action request must be a JSON object")
    return "sha256:" + hashlib.sha256(jcs(value)).hexdigest()


__all__ = [
    "MAX_DESTINATION_LENGTH",
    "ActionRequest",
    "request_hash_of",
    "sha256_hex",
]
