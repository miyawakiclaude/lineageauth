"""Technocore adapter: read classification and dry-run write preparation.

Technocore is transport and discovery. It is not a source of truth, it holds no
keys, and everything that comes out of it -- messages, notes, room topics,
nicknames, URLs -- is untrusted data rather than instruction. The signed
LineageAuth event remains authoritative regardless of what any room says
(D-001, `CLAUDE.md` 2.4).

This package deliberately cannot write. `prepare_signed_message` builds the
exact URL, the exact bytes, and the signature, and returns them. Sending is a
separate act that belongs behind `lineageauth.approval`.
"""

from lineageauth.adapters.technocore.client import (
    DEFAULT_MAX_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    HttpsTransport,
    MockTransport,
    Response,
    TechnocoreReader,
    Transport,
    TransportError,
    UntrustedMessage,
    parse_messages,
    verify_message_signature,
)
from lineageauth.adapters.technocore.delegation import (
    CheckedDelegation,
    DelegationRecord,
    DelegationVerdict,
    check_delegations,
    delegation_scopes,
    live_delegations,
    note_path,
    parse_delegations,
    permitting_record,
)
from lineageauth.adapters.technocore.prepare import (
    ANNOUNCE_PREFIX,
    MAX_URL_BYTES,
    PreparedWrite,
    format_announcement,
    prepare_signed_message,
)
from lineageauth.adapters.technocore.routes import (
    SERVICE_HOST,
    SERVICE_ORIGIN,
    Classification,
    Consequence,
    assert_safe_to_read,
    classify,
    is_write,
)
from lineageauth.adapters.technocore.text import (
    MAX_MESSAGE_CHARS,
    MAX_NOTE_CHARS,
    SignedMessage,
    build_signed_message,
    note_signing_bytes,
    sweep,
)

__all__ = [
    "ANNOUNCE_PREFIX",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_MESSAGE_CHARS",
    "MAX_NOTE_CHARS",
    "MAX_URL_BYTES",
    "SERVICE_HOST",
    "SERVICE_ORIGIN",
    "CheckedDelegation",
    "Classification",
    "Consequence",
    "DelegationRecord",
    "DelegationVerdict",
    "HttpsTransport",
    "MockTransport",
    "PreparedWrite",
    "Response",
    "SignedMessage",
    "TechnocoreReader",
    "Transport",
    "TransportError",
    "UntrustedMessage",
    "assert_safe_to_read",
    "build_signed_message",
    "check_delegations",
    "classify",
    "delegation_scopes",
    "format_announcement",
    "is_write",
    "live_delegations",
    "note_path",
    "note_signing_bytes",
    "parse_delegations",
    "parse_messages",
    "permitting_record",
    "prepare_signed_message",
    "sweep",
    "verify_message_signature",
]
