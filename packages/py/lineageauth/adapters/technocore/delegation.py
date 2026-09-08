"""Technocore's native delegation records, read and verified. Never issued here.

`llms.txt` (served 2026-09-08) added DELEGATION: a root key writes, into its
own DID note, one or more records of the form

    delegate: <agent-did> <scope> <expires> <nonce> <sig>

where `sig` is the root's Ed25519 signature over
`delegate|<root-did>|<agent-did>|<scope>|<expires>|<nonce>`, base64url without
padding. Scope is `*`, `r:<room>` or `kv:<ns>`; `expires` is unix seconds; the
server neither checks nor stores any of it -- the note is world-writable, and
a forged record is meant to be visibly inert rather than fatal.

This module is the reader's half only. It parses a note body the way the
reference (`scripts/sign.py` in flop-labs/technocore-chat) does -- by scanning
for the token, never by line, because the server sweeps every newline into a
space -- verifies each record against the root DID, applies the expiry, and
then decides which record is current for each agent by highest nonce.

One deliberate difference from the reference at the pinned commit: the nonce
ranking here runs over records whose signature verified, not over every
record. Ranking first lets a forged record with a large nonce, which anyone
can append to a world-writable note, report a real grant as SUPERSEDED
(flop-labs/technocore-chat#782). Nothing about the record format changes; only
the order of the checks.

What a record proves, and what it does not, is the same as for every other
Technocore artefact: a key signed these bytes. It is not a LineageAuth grant
and it creates no LAP authority. `delegation_scopes` says which LAP scopes the
record's scope would correspond to, so a caller can compare the two views; it
does not manufacture a `delegation.grant`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from lineageauth.crypto import verify_by_did
from lineageauth.didkey import is_did_key
from lineageauth.errors import LineageAuthError

DELEGATE_MARKER = "delegate:"
DELEGATE_FIELDS = 5  # agent, scope, expires, nonce, sig

# The reference's grammar, verbatim: the room/namespace halves are the server's
# NAME_RE, so a scope names something that can exist.
NAME = r"[a-z0-9][a-z0-9_-]{0,47}"
SCOPE_RE = re.compile(rf"\*|r:{NAME}|kv:{NAME}")
# ASCII decimal only. str.isdigit() accepts Unicode digits that int() also
# accepts and no JavaScript /[0-9]/ matches, and expiry is the only revocation
# this format has, so the two verifiers of one record must agree on it.
DIGITS_RE = re.compile(r"[0-9]{1,19}")
SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{86}")

SCOPE_ANY = "*"
SCOPE_ROOM = "r:"
SCOPE_NOTES = "kv:"


class DelegationVerdict(StrEnum):
    """What a reader may conclude about one record. Only OK confers anything."""

    OK = "OK"
    FORGED = "FORGED"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"
    MALFORMED = "MALFORMED"


@dataclass(frozen=True, slots=True)
class DelegationRecord:
    """The five fields after one `delegate:` token, exactly as found."""

    agent: str
    scope: str
    expires: str
    nonce: str
    signature: str
    position: int

    def signing_message(self, root: str) -> str:
        return signing_message(root, self.agent, self.scope, self.expires, self.nonce)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "scope": self.scope,
            "expires": self.expires,
            "nonce": self.nonce,
            "signature": self.signature,
            "position": self.position,
        }


@dataclass(frozen=True, slots=True)
class CheckedDelegation:
    """One record with its verdict and the reason, never a bare boolean."""

    record: DelegationRecord
    verdict: DelegationVerdict
    detail: str
    expires_at: datetime | None = None

    @property
    def live(self) -> bool:
        return self.verdict is DelegationVerdict.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "record": self.record.to_dict(),
            "verdict": str(self.verdict),
            "detail": self.detail,
            "expiresAt": None if self.expires_at is None else self.expires_at.isoformat(),
            "live": self.live,
        }


def signing_message(root: str, agent: str, scope: str, expires: str, nonce: str) -> str:
    """The string a delegation signature covers.

    The root DID is inside the signed string even though the note it lives in
    is already addressed by the root's fingerprint: a record lifted out of one
    root's note and pasted into another's must not verify against the second.
    """
    return f"delegate|{root}|{agent}|{scope}|{expires}|{nonce}"


def note_path(root: str) -> str:
    """Where a DID's identity note lives: `/kv/did-XX/<14 hex>`.

    The fingerprint is over the did:key *string*, as the reference computes it,
    so a reader holding only a DID printed in a message can find the note.
    """
    if not is_did_key(root):
        raise LineageAuthError(f"not an Ed25519 did:key: {root!r}")
    fingerprint = hashlib.sha256(root.encode()).hexdigest()[:16]
    return f"/kv/did-{fingerprint[:2]}/{fingerprint[2:]}"


def parse_delegations(body: str) -> tuple[DelegationRecord, ...]:
    """Every record in a note body, found by token rather than by line.

    A note is one line however it was written -- the server replaces every
    control character with a space -- so records are the five whitespace-
    separated fields after each `delegate:` token. A token with fewer than
    five fields after it is not a record and is skipped, as the reference does.
    The body is untrusted text; nothing here follows or executes any of it.
    """
    fields = body.split()
    out: list[DelegationRecord] = []
    for index, token in enumerate(fields):
        if token != DELEGATE_MARKER:
            continue
        record = fields[index + 1 : index + 1 + DELEGATE_FIELDS]
        if len(record) == DELEGATE_FIELDS:
            out.append(
                DelegationRecord(
                    agent=record[0],
                    scope=record[1],
                    expires=record[2],
                    nonce=record[3],
                    signature=record[4],
                    position=len(out),
                )
            )
    return tuple(out)


def _shape_failure(record: DelegationRecord) -> str | None:
    if not is_did_key(record.agent):
        return "agent is not an Ed25519 did:key"
    if not SCOPE_RE.fullmatch(record.scope):
        return "scope is not '*', 'r:<room>' or 'kv:<ns>'"
    if not DIGITS_RE.fullmatch(record.expires):
        return "expires is not ASCII decimal unix seconds"
    if not DIGITS_RE.fullmatch(record.nonce):
        return "nonce is not ASCII decimal"
    if not SIGNATURE_RE.fullmatch(record.signature):
        return "signature is not 86 unpadded base64url characters"
    return None


def check_delegations(root: str, body: str, *, at: datetime) -> tuple[CheckedDelegation, ...]:
    """Report every delegation in `body` against `root`, in note order.

    The checks, in order: shape, signature, expiry, then supersession among
    the records that verified. Garbage in a world-writable note is expected,
    so nothing raises on a bad record; the verdict says what it is.
    """
    if not is_did_key(root):
        raise LineageAuthError(f"not an Ed25519 did:key: {root!r}")
    if at.tzinfo is None:
        raise LineageAuthError("`at` must be timezone-aware")
    now = int(at.timestamp())
    records = parse_delegations(body)

    verified: list[int] = []
    provisional: dict[int, tuple[DelegationVerdict, str, datetime | None]] = {}
    for record in records:
        failure = _shape_failure(record)
        if failure is not None:
            provisional[record.position] = (DelegationVerdict.MALFORMED, failure, None)
            continue
        if not verify_by_did(root, record.signing_message(root).encode("utf-8"), record.signature):
            provisional[record.position] = (
                DelegationVerdict.FORGED,
                f"not signed by {root[:20]}...; forged, or written for a different root",
                None,
            )
            continue
        verified.append(record.position)
        expires_at = datetime.fromtimestamp(int(record.expires), tz=UTC)
        if int(record.expires) <= now:
            provisional[record.position] = (
                DelegationVerdict.EXPIRED,
                f"expired at {expires_at.isoformat()}",
                expires_at,
            )
            continue
        provisional[record.position] = (DelegationVerdict.OK, "", expires_at)

    # Highest nonce wins per agent, ties to the last record -- but only among
    # records the root actually signed. See the module docstring and #782.
    current = _newest(records, verified)
    out: list[CheckedDelegation] = []
    for record in records:
        verdict, detail, expiry = provisional[record.position]
        if verdict is DelegationVerdict.OK and record.position not in current:
            verdict = DelegationVerdict.SUPERSEDED
            detail = f"a higher nonce than {record.nonce} names this agent"
        elif verdict is DelegationVerdict.OK:
            days_left = -((now - int(record.expires)) // 86400)
            detail = f"{days_left}d left, nonce {record.nonce}"
        out.append(
            CheckedDelegation(record=record, verdict=verdict, detail=detail, expires_at=expiry)
        )
    return tuple(out)


def _newest(records: tuple[DelegationRecord, ...], eligible: list[int]) -> set[int]:
    best: dict[str, tuple[int, int]] = {}
    for record in records:
        if record.position not in eligible:
            continue
        rank = int(record.nonce)
        if record.agent not in best or rank >= best[record.agent][0]:
            best[record.agent] = (rank, record.position)
    return {position for _rank, position in best.values()}


def live_delegations(checked: tuple[CheckedDelegation, ...]) -> tuple[CheckedDelegation, ...]:
    return tuple(entry for entry in checked if entry.live)


def scope_covers(scope: str, target: str) -> bool:
    """Whether a record's scope reaches `target` (`r:<room>` or `kv:<ns>`).

    `*` reaches everything; anything else must match exactly. There is no
    prefix or glob form in the format, and none is invented here.
    """
    return scope == SCOPE_ANY or scope == target


def permitting_record(
    checked: tuple[CheckedDelegation, ...], *, agent: str, target: str
) -> CheckedDelegation | None:
    """The live record, if any, under which `agent` may act on `target`."""
    for entry in checked:
        if entry.live and entry.record.agent == agent and scope_covers(entry.record.scope, target):
            return entry
    return None


def delegation_scopes(scope: str) -> list[dict[str, Any]]:
    """The LAP `technocore` scopes a record's scope corresponds to.

    A comparison aid, not a conversion: the record grants Technocore-side
    standing that Technocore itself never checks, and LAP authority comes only
    from a signed `delegation.grant`. Technocore's format has no action
    granularity, so the correspondence is read and write on the named thing.
    """
    if scope == SCOPE_ANY:
        return [
            {"namespace": "technocore", "resource": "room:*", "actions": ["read", "write"]},
        ]
    if scope.startswith(SCOPE_ROOM):
        return [
            {
                "namespace": "technocore",
                "resource": f"room:{scope[len(SCOPE_ROOM) :]}",
                "actions": ["read", "write"],
            }
        ]
    if scope.startswith(SCOPE_NOTES):
        return [
            {
                "namespace": "technocore",
                "resource": f"note:{scope[len(SCOPE_NOTES) :]}/*",
                "actions": ["read", "write"],
            }
        ]
    raise LineageAuthError(f"not a delegation scope: {scope!r}")


__all__ = [
    "DELEGATE_FIELDS",
    "DELEGATE_MARKER",
    "DIGITS_RE",
    "SCOPE_RE",
    "CheckedDelegation",
    "DelegationRecord",
    "DelegationVerdict",
    "check_delegations",
    "delegation_scopes",
    "live_delegations",
    "note_path",
    "parse_delegations",
    "permitting_record",
    "scope_covers",
    "signing_message",
]
