"""Machine-readable reason codes.

CLAUDE.md 2.6 fixes this vocabulary. A verifier never returns a bare boolean
(docs/16_API_SDK_CLI.md, "Error model"), and never labels a DID "trusted"
merely because a signature validated.
"""

from __future__ import annotations

from enum import StrEnum


class ReasonCode(StrEnum):
    """Statuses a verifier may report. Additions require a protocol version bump."""

    # Positive
    VALID_AUTHORITY_CHAIN = "VALID_AUTHORITY_CHAIN"
    SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"

    # Authority outcomes
    DENIED = "DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    UNRESOLVED_PARENT = "UNRESOLVED_PARENT"

    # Lifecycle
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    SUPERSEDED = "SUPERSEDED"

    # Integrity
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    MALFORMED = "MALFORMED"
    UNKNOWN_VERSION = "UNKNOWN_VERSION"

    # Resolution
    STALE_STATUS = "STALE_STATUS"
    CONFLICTED = "CONFLICTED"
    INSUFFICIENT_RECOVERY_PROOFS = "INSUFFICIENT_RECOVERY_PROOFS"


class LineageAuthError(Exception):
    """Base error. Carries a ReasonCode so callers never have to parse messages."""

    reason: ReasonCode = ReasonCode.MALFORMED

    def __init__(self, message: str, reason: ReasonCode | None = None) -> None:
        super().__init__(message)
        if reason is not None:
            self.reason = reason


class MalformedEventError(LineageAuthError):
    reason = ReasonCode.MALFORMED


class UnknownVersionError(LineageAuthError):
    reason = ReasonCode.UNKNOWN_VERSION
