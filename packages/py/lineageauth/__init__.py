"""LineageAuth — Lineage Authority Protocol (LAP) reference implementation.

Core verification is offline by design: no network, no database, no private keys.
See CLAUDE.md section 5 ("Separation") for the trust boundary this package enforces.
"""

from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import EVENT_PREIMAGE_PREFIX, compute_event_id, jcs, preimage
from lineageauth.didkey import DidKeyError, did_key_from_public_key, public_key_from_did_key
from lineageauth.envelope import Envelope, Proof
from lineageauth.errors import ReasonCode
from lineageauth.lineage import EpochStep, LineageState, resolve_lineage
from lineageauth.verify import EventVerification, verify_event

__version__ = "0.1.0"
PROTOCOL = "lineageauth"
CORE_VERSION = "0.1"

__all__ = [
    "CORE_VERSION",
    "EVENT_PREIMAGE_PREFIX",
    "PROTOCOL",
    "AdmittedEvent",
    "DidKeyError",
    "Envelope",
    "EpochStep",
    "EventBundle",
    "EventVerification",
    "LineageState",
    "Proof",
    "ReasonCode",
    "__version__",
    "compute_event_id",
    "did_key_from_public_key",
    "jcs",
    "preimage",
    "public_key_from_did_key",
    "resolve_lineage",
    "verify_event",
]
