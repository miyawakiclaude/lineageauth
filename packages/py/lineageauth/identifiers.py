"""Lineage identifiers.

docs/02_LAP_CORE.md names the field but leaves its construction open, and
CLAUDE.md 8 forbids inventing protocol rules silently -- so this is recorded as
decision D-025 in docs/29_DECISIONS.md.

    lineage:la:<method-specific id of the epoch-0 root did:key>

The identifier is anchored to the genesis root key and never changes, so root
succession (docs/05) moves the root DID while the lineage keeps its name. It is
also self-certifying: given a `root.create` event, a verifier recomputes the
identifier from the declared root DID offline, with no registry to consult.

A lineage identifier is a *name*, not an authority. Being able to derive one
proves nothing; only the signed `root.create` event establishes the genesis
root, and only the highest valid epoch establishes the current one.
"""

from __future__ import annotations

import re

from lineageauth.didkey import DID_KEY_PREFIX, public_key_from_did_key
from lineageauth.errors import MalformedEventError

LINEAGE_PREFIX = "lineage:la:"
LINEAGE_ID_RE = re.compile(r"^lineage:la:z[1-9A-HJ-NP-Za-km-z]{40,}$")


def derive_lineage_id(genesis_root_did: str) -> str:
    """Derive the lineage identifier anchored to an epoch-0 root `did:key`."""
    public_key_from_did_key(genesis_root_did)  # rejects unsupported/non-canonical DIDs
    return LINEAGE_PREFIX + genesis_root_did[len(DID_KEY_PREFIX) :]


def genesis_did_from_lineage_id(lineage_id: object) -> str:
    """Recover the genesis root `did:key` a lineage identifier is anchored to."""
    if not isinstance(lineage_id, str):
        raise MalformedEventError("lineage identifier must be a string")
    if not lineage_id.startswith(LINEAGE_PREFIX):
        raise MalformedEventError(
            f"lineage identifier must start with '{LINEAGE_PREFIX}', got '{lineage_id[:24]}'"
        )
    did = DID_KEY_PREFIX + lineage_id[len(LINEAGE_PREFIX) :]
    public_key_from_did_key(did)
    return did


def is_lineage_id(value: object) -> bool:
    """True if `value` is a well-formed lineage identifier."""
    if not isinstance(value, str) or LINEAGE_ID_RE.fullmatch(value) is None:
        return False
    try:
        genesis_did_from_lineage_id(value)
    except MalformedEventError:
        return False
    return True
