"""A2A integration: a namespaced extension that adds evidence and takes nothing.

`docs/20_A2A.md` opens with the constraint that governs the whole adapter:

    LineageAuth must not replace/bypass server authorization.

So nothing here answers "may this run". It answers "what has this agent signed
for", which is a different question that arrives at a different point in the
sequence -- `docs/20` numbers it step 3 of 5, after A2A's own authentication and
after the server's own authorization, and every decision this module returns
says so in its own text.

Upstream facts checked 2026-08-27 against the A2A specification (latest
released 1.0.x, extensions mechanism introduced in 1.0.1, May 2026):

    extensions live at   AgentCard.capabilities.extensions
    an AgentExtension is {uri, description, required, params}
    a client activates   the A2A-Extensions request header, comma-separated
    required: true       means the agent should reject a client that did not
                         activate it, and upstream says data-only extensions
                         should not be marked required

That last line is not advice we get to weigh. This extension is data-only --
provenance a reader may consult -- so `required` is always false and
`build_extension` refuses to emit anything else. An agent card that made
LineageAuth mandatory would be doing exactly what `docs/20` forbids: standing
between a client and a server that had already authorized it.
"""

from lineageauth.adapters.a2a.card import (
    EXTENSION_URI,
    EXTENSION_VERSION,
    A2AProvenance,
    a2a_resource_for,
    build_extension,
    read_extension,
)
from lineageauth.adapters.a2a.checks import VERIFICATION_ORDER, check_a2a_invocation

__all__ = [
    "EXTENSION_URI",
    "EXTENSION_VERSION",
    "VERIFICATION_ORDER",
    "A2AProvenance",
    "a2a_resource_for",
    "build_extension",
    "check_a2a_invocation",
    "read_extension",
]
