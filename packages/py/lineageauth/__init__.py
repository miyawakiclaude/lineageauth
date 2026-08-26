"""LineageAuth — Lineage Authority Protocol (LAP) reference implementation.

Core verification is offline by design: no network, no database, no private keys.
See CLAUDE.md section 5 ("Separation") for the trust boundary this package enforces.
"""

from lineageauth.actions import ActionRequest
from lineageauth.approval import (
    ApprovalReceipt,
    ExecutionDecision,
    InMemorySpentStore,
    SpentReceiptStore,
    SqliteSpentStore,
    check_execution,
)
from lineageauth.authority import AuthorityDecision, Grant, Request, check_permission
from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import EVENT_PREIMAGE_PREFIX, compute_event_id, jcs, preimage
from lineageauth.didkey import DidKeyError, did_key_from_public_key, public_key_from_did_key
from lineageauth.envelope import Envelope, Proof
from lineageauth.errors import ReasonCode
from lineageauth.lineage import EpochStep, LineageState, resolve_lineage
from lineageauth.scopes import ApprovalMode, Scope
from lineageauth.verify import EventVerification, verify_event

__version__ = "0.1.0"
PROTOCOL = "lineageauth"
CORE_VERSION = "0.1"

__all__ = [
    "CORE_VERSION",
    "EVENT_PREIMAGE_PREFIX",
    "PROTOCOL",
    "ActionRequest",
    "AdmittedEvent",
    "ApprovalMode",
    "ApprovalReceipt",
    "AuthorityDecision",
    "DidKeyError",
    "Envelope",
    "EpochStep",
    "EventBundle",
    "EventVerification",
    "ExecutionDecision",
    "Grant",
    "InMemorySpentStore",
    "LineageState",
    "Proof",
    "ReasonCode",
    "Request",
    "Scope",
    "SpentReceiptStore",
    "SqliteSpentStore",
    "__version__",
    "check_execution",
    "check_permission",
    "compute_event_id",
    "did_key_from_public_key",
    "jcs",
    "preimage",
    "public_key_from_did_key",
    "resolve_lineage",
    "verify_event",
]
