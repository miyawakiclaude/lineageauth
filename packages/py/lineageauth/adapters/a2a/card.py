"""Reading and writing the LineageAuth block inside an A2A Agent Card.

An Agent Card is a public document published by whoever runs the agent. That
makes every field in it a claim by a stranger, and this module treats it that
way: a DID that does not decode is refused, an evidence reference that is not
an event id is refused, and the `resolver` URL is carried through as data that
is *never fetched here*. `docs/20` and `docs/18` agree on this -- a URL in a
document is data, not an instruction.

The card also never carries a secret. `docs/20`: "Never include plaintext
secrets." A LineageAuth reference is a public, signed evidence id, which is the
whole reason it is safe to publish one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from lineageauth import catalog
from lineageauth.canonical import is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError
from lineageauth.scopes import WILDCARD, parse_resource

A2A_NAMESPACE = "a2a"
EXTENSION_VERSION = catalog.CORE_VERSION

# A repository URL rather than a domain, deliberately. The project runs on a
# zero-yen budget and buying a domain is a spend decision, not an engineering
# one -- so the identifier points at the document that defines the extension
# and resolves today. If this is ever standardised upstream the URI changes,
# and that is a breaking change by design: an extension URI is an identity, and
# quietly reusing it for different semantics is how interop rots.
EXTENSION_URI = "https://github.com/miyawakiclaude/lineageauth/blob/main/docs/20_A2A.md"

EXTENSION_DESCRIPTION = (
    "LineageAuth provenance: a lineage, a DID, and references to signed evidence. "
    "Data only. It does not authorize anything and does not replace this agent's "
    "own authorization."
)

RESOLVER_NOTE = (
    "The resolver URL comes from the agent card, which is written by whoever runs "
    "the agent. It is carried here as data and is never fetched by this library. "
    "Anything it returns would still have to verify on its own signatures before "
    "it meant anything."
)

CARD_NOTE = (
    "Everything in an agent card is a claim by its publisher. A DID here means "
    "the publisher wrote that DID down, not that they hold its key -- only a "
    "signature over an event establishes that."
)

# Same alphabet the scope grammar accepts for one segment, checked before the
# id is ever formatted into a resource.
_SKILL_ID = re.compile(r"[A-Za-z0-9._-]+")


def a2a_resource_for(*, agent_id: str | None = None, skill_id: str | None = None) -> str:
    """Map an A2A agent or skill onto a LineageAuth resource (`docs/20`).

    Built through the scope grammar rather than by hand. Skill ids arrive from a
    published card, so one carrying a slash, a dot segment or a wildcard is
    refused here rather than becoming a resource that matches more than the
    caller meant to ask about.
    """
    if agent_id is not None and skill_id is None:
        label, prefix, value = "agent id", "agent", agent_id
    elif skill_id is not None and agent_id is None:
        label, prefix, value = "skill id", "skill", skill_id
    else:
        raise MalformedEventError("give exactly one of agent_id= or skill_id=")

    if WILDCARD in value:
        raise MalformedEventError(
            f"{label} must name one concrete target; a wildcard belongs in a scope, "
            "not in the resource for a specific invocation"
        )
    if _SKILL_ID.fullmatch(value) is None or value in (".", ".."):
        raise MalformedEventError(
            f"{label} must be one segment of [A-Za-z0-9._-] and not a dot segment"
        )

    resource = f"{prefix}:{value}"
    parse_resource(A2A_NAMESPACE, resource)
    return resource


def build_extension(
    *,
    lineage: str,
    did: str,
    resolver: str | None = None,
    evidence: list[str] | None = None,
) -> dict[str, Any]:
    """Build the `AgentExtension` object to place in `capabilities.extensions`.

    `required` is hard-coded false and there is no parameter to change it.
    Upstream says data-only extensions should not be marked required, and this
    one is data only; an agent that rejected clients for not activating it
    would be using LineageAuth to gate access, which `docs/20` forbids in its
    first sentence.
    """
    public_key_from_did_key(did)
    if not lineage.startswith("lineage:"):
        raise MalformedEventError("lineage must be a LineageAuth lineage identifier")
    for ref in evidence or []:
        if not is_event_id(ref):
            raise MalformedEventError("every evidence reference must be a sha256:<64 hex> id")
    if resolver is not None and not resolver.startswith("https://"):
        # Not a security control on its own -- the URL is never fetched here --
        # but publishing an http:// resolver invites somebody else to fetch it.
        raise MalformedEventError("a resolver URL must be https")

    params: dict[str, Any] = {
        "version": EXTENSION_VERSION,
        "lineage": lineage,
        "did": did,
    }
    if resolver is not None:
        params["resolver"] = resolver
    if evidence:
        params["evidence"] = sorted(set(evidence))

    return {
        "uri": EXTENSION_URI,
        "description": EXTENSION_DESCRIPTION,
        "required": False,
        "params": params,
    }


@dataclass(frozen=True, slots=True)
class A2AProvenance:
    """What a card claims about its LineageAuth identity, and what it does not."""

    lineage: str
    did: str
    resolver: str | None
    evidence: tuple[str, ...]
    declared_required: bool
    warnings: tuple[str, ...] = ()

    @property
    def note(self) -> str:
        text = f"{CARD_NOTE} {RESOLVER_NOTE}" if self.resolver else CARD_NOTE
        return text

    def to_dict(self) -> dict[str, Any]:
        return {
            "lineage": self.lineage,
            "did": self.did,
            "resolver": self.resolver,
            "evidence": list(self.evidence),
            "declaredRequired": self.declared_required,
            "warnings": list(self.warnings),
            "note": self.note,
        }


def read_extension(card: Any) -> A2AProvenance | None:
    """Find and validate the LineageAuth extension in an agent card.

    Returns None when the card carries no such extension -- which is not a
    complaint about the agent. Most agents will not publish one, and a missing
    extension says nothing at all about them.

    Raises `MalformedEventError` when the extension is present but unusable.
    Half-reading a broken provenance block would be worse than refusing it: a
    partially parsed DID is exactly the kind of thing a reader treats as
    identity.
    """
    if not isinstance(card, dict):
        raise MalformedEventError("an agent card must be a JSON object")
    capabilities = card.get("capabilities")
    if not isinstance(capabilities, dict):
        return None
    extensions = capabilities.get("extensions")
    if not isinstance(extensions, list):
        return None

    found = [
        entry
        for entry in extensions
        if isinstance(entry, dict) and entry.get("uri") == EXTENSION_URI
    ]
    if not found:
        return None
    if len(found) > 1:
        # Two blocks under one URI, and nothing says which is current. Picking
        # either would be this module choosing an identity for the reader.
        raise MalformedEventError(
            f"this card declares the {EXTENSION_URI} extension more than once; "
            "which one is meant is not something a reader can determine"
        )

    entry = found[0]
    params = entry.get("params")
    if not isinstance(params, dict):
        raise MalformedEventError("the LineageAuth extension carries no params object")

    lineage = params.get("lineage")
    if not isinstance(lineage, str) or not lineage.startswith("lineage:"):
        raise MalformedEventError("params.lineage must be a LineageAuth lineage identifier")

    did = params.get("did")
    if not isinstance(did, str):
        raise MalformedEventError("params.did must be a string")
    try:
        public_key_from_did_key(did)
    except LineageAuthError as exc:
        raise MalformedEventError(f"params.did is not a usable Ed25519 did:key: {exc}") from exc

    warnings: list[str] = []

    resolver = params.get("resolver")
    if resolver is not None:
        if not isinstance(resolver, str):
            raise MalformedEventError("params.resolver must be a string when present")
        if not resolver.startswith("https://"):
            warnings.append(
                "the declared resolver is not https; it is carried as data and is not "
                "fetched here, but nothing else should fetch it either"
            )

    raw_evidence = params.get("evidence") or []
    if not isinstance(raw_evidence, list):
        raise MalformedEventError("params.evidence must be a list when present")
    evidence: list[str] = []
    for ref in raw_evidence:
        if not isinstance(ref, str) or not is_event_id(ref):
            warnings.append(f"ignored an evidence reference that is not an event id: {ref!r}")
            continue
        evidence.append(ref)

    declared_required = bool(entry.get("required"))
    if declared_required:
        # Upstream: data-only extensions should not be marked required, and a
        # required extension means the agent should reject clients that did not
        # activate it. An agent doing that with LineageAuth is gating access on
        # provenance, which docs/20 forbids. Reported, not silently normalised:
        # what the card says is a fact about the card.
        warnings.append(
            "this card marks the LineageAuth extension required:true. It is a "
            "data-only extension, upstream says data-only extensions should not be "
            "marked required, and an agent that rejects clients for not activating "
            "it is using provenance to gate access -- which this integration exists "
            "not to do"
        )

    return A2AProvenance(
        lineage=lineage,
        did=did,
        resolver=resolver if isinstance(resolver, str) else None,
        evidence=tuple(evidence),
        declared_required=declared_required,
        warnings=tuple(warnings),
    )
