"""Exact-action human approval, replay protection, and the execution gate.

`docs/06_APPROVAL_EXECUTION.md` describes a pipeline, and the ordering in it is
the security property:

    proposed action -> authority check -> approval policy -> exact preview
      -> human approval receipt -> re-check freshness/authority -> execute

Two things this layer must never do.

*It must never create authority.* An approval receipt says a human consented to
a consequence. It says nothing about whether the agent was entitled to cause it.
An agent without a base grant is DENIED no matter how many receipts it holds --
`docs/06` states this outright and `check_execution` enforces it by running the
authority check first and refusing before a receipt is even looked at.

*It must never let one receipt be spent twice.* A receipt binds one destination
and one content hash, but nothing in a signature stops it being replayed. The
spent store is what stops that, and reservation has to be atomic -- two
executors racing on the same receipt must not both win.

The gap between checking and executing is the other half of the problem. A grant
can be revoked, a root can be superseded, and a receipt can expire in the
milliseconds after a decision is computed, so `check_execution` re-checks
everything immediately before reserving, rather than trusting an earlier answer.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from lineageauth.actions import ActionRequest
from lineageauth.authority import AuthorityDecision, Grant, check_permission, read_grant
from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import b64u_decode, is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError, ReasonCode
from lineageauth.scopes import ApprovalMode
from lineageauth.timeutil import parse_instant

APPROVAL_RECEIPT = "approval.receipt"

# docs/06: "nonce >=128 random bits". Anything shorter is guessable enough that
# a receipt could be pre-computed for a request an approver has not seen.
MIN_NONCE_BYTES = 16


@dataclass(frozen=True, slots=True)
class ApprovalReceipt:
    """A parsed `approval.receipt`: one human, consenting to one exact effect."""

    event_id: str
    approver: str
    agent: str
    request: ActionRequest
    request_hash: str
    nonce: str
    issued_at: datetime
    expires_at: datetime


def read_receipt(event: AdmittedEvent) -> ApprovalReceipt | str:
    """Validate an `approval.receipt` payload, returning it or a complaint."""
    approver = event.get("approver")
    agent = event.get("agent")
    for label, did in (("approver", approver), ("agent", agent)):
        if not isinstance(did, str):
            return f"{label} must be a did:key string"
        try:
            public_key_from_did_key(did)
        except LineageAuthError as exc:
            return f"{label} is not a usable did:key: {exc}"
    approver, agent = str(approver), str(agent)

    if not event.signed_by(approver):
        # Otherwise anyone could mint a receipt naming a human as the approver.
        return f"not signed by its declared approver {approver}"

    try:
        request = ActionRequest(
            namespace=str(event.get("namespace")),
            resource=str(event.get("resource")),
            action=str(event.get("action")),
            destination=str(event.get("destination")),
            content_hash=str(event.get("contentHash")),
        )
    except (MalformedEventError, KeyError) as exc:
        return f"the approved action is not well-formed: {exc}"

    declared = event.get("requestHash")
    if not is_event_id(declared):
        return "requestHash must be sha256:<64 lowercase hex>"
    if declared != request.request_hash:
        # The hash is derivable from the fields, so a mismatch means the receipt
        # displays one action and binds another -- exactly the substitution an
        # approval preview exists to prevent.
        return (
            "requestHash does not match the action this receipt describes; the "
            "receipt binds something other than what it displays"
        )

    nonce = event.get("nonce")
    if not isinstance(nonce, str):
        return "nonce must be a base64url string"
    try:
        nonce_bytes = b64u_decode(nonce)
    except MalformedEventError as exc:
        return f"nonce is not canonical unpadded base64url: {exc}"
    if len(nonce_bytes) < MIN_NONCE_BYTES:
        return f"nonce must carry at least {MIN_NONCE_BYTES} bytes of randomness"

    try:
        expires_at = parse_instant(event.get("expiresAt"), field="expiresAt")
    except MalformedEventError as exc:
        return str(exc)
    if expires_at <= event.issued_at:
        return "expiresAt must be after issuedAt"

    return ApprovalReceipt(
        event_id=event.event_id,
        approver=approver,
        agent=agent,
        request=request,
        request_hash=str(declared),
        nonce=nonce,
        issued_at=event.issued_at,
        expires_at=expires_at,
    )


# --------------------------------------------------------------------- replay


class SpentReceiptStore(Protocol):
    """Records which receipts have been consumed.

    `reserve` must be atomic: given two callers racing on one receipt id,
    exactly one may receive True. A store that can return True twice turns every
    approval into an unlimited licence.
    """

    def reserve(self, receipt_id: str) -> bool:
        """Claim `receipt_id`. True if this call claimed it, False if already spent."""
        ...

    def is_spent(self, receipt_id: str) -> bool:
        """True when `receipt_id` has already been consumed."""
        ...


class InMemorySpentStore:
    """A spent store for tests and single-process use.

    Lost on restart, which is the wrong failure direction -- a restart would
    make every past receipt replayable. Use `SqliteSpentStore` for anything that
    executes real actions.
    """

    __slots__ = ("_lock", "_spent")

    def __init__(self) -> None:
        self._spent: set[str] = set()
        self._lock = threading.Lock()

    def reserve(self, receipt_id: str) -> bool:
        with self._lock:
            if receipt_id in self._spent:
                return False
            self._spent.add(receipt_id)
            return True

    def is_spent(self, receipt_id: str) -> bool:
        with self._lock:
            return receipt_id in self._spent


class SqliteSpentStore:
    """A durable spent store.

    Atomicity comes from the primary key: two concurrent inserts of one receipt
    id cannot both succeed, and the loser raises `IntegrityError`. That is the
    whole mechanism -- no read-then-write, because a read-then-write is exactly
    the race this has to survive.

    SQLite because `CLAUDE.md` 2.7.7 makes it the default database and it costs
    nothing to run.
    """

    __slots__ = ("_path", "_timeout")

    def __init__(self, path: str | Path, *, timeout_seconds: float = 5.0) -> None:
        self._path = str(path)
        # Stated rather than left to the library default. Under contention
        # `BEGIN IMMEDIATE` waits for the write lock, and how long it waits is a
        # security-relevant choice: too short and a busy executor sees spurious
        # errors on a gate that must not be flaky.
        self._timeout = timeout_seconds
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS spent_approvals ("
                "  receipt_id TEXT PRIMARY KEY,"
                "  spent_at   TEXT NOT NULL"
                ")"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, isolation_level="IMMEDIATE", timeout=self._timeout)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def reserve(self, receipt_id: str, *, at: datetime | None = None) -> bool:
        """Claim a receipt. False means it was already spent.

        A lock timeout or a disk error propagates rather than returning False.
        Returning False would say "already spent", and a caller told that would
        reasonably stop; but the truthful answer is "unknown", and the one thing
        this must never do is report a definite outcome it did not establish.
        """
        stamp = at.isoformat() if at is not None else ""
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO spent_approvals (receipt_id, spent_at) VALUES (?, ?)",
                    (receipt_id, stamp),
                )
        except sqlite3.IntegrityError:
            return False
        return True

    def is_spent(self, receipt_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM spent_approvals WHERE receipt_id = ?", (receipt_id,)
            ).fetchone()
        return row is not None


# ------------------------------------------------------------------- decision


@dataclass(frozen=True, slots=True)
class ExecutionDecision:
    """Whether an executor may perform this action, right now, and why."""

    may_execute: bool
    reason: ReasonCode
    detail: str
    request: ActionRequest
    authority: AuthorityDecision
    receipt_id: str | None = None
    approver: str | None = None
    reserved: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        return self.authority.note


def _approvers_entitled(decision: AuthorityDecision, grants: dict[str, Grant]) -> set[str]:
    """Who may approve an exercise of this authority.

    The party that delegated authority is the party entitled to consent to its
    use, so the set is the issuers along the path that authorized the action,
    plus the current root (D-042). Anyone else signing a receipt is a stranger
    consenting on someone else's behalf.
    """
    entitled: set[str] = set()
    if decision.root is not None:
        entitled.add(decision.root)
    for event_id in decision.path:
        grant = grants.get(event_id)
        if grant is not None:
            entitled.add(grant.issuer)
    return entitled


def check_execution(
    bundle: EventBundle,
    *,
    lineage: str,
    agent: str,
    request: ActionRequest,
    at: datetime,
    store: SpentReceiptStore | None = None,
    external: bool = True,
    reserve: bool = True,
) -> ExecutionDecision:
    """Decide whether an executor may perform `request` on behalf of `agent`.

    This is the TOCTOU re-check from `docs/06`, and it is meant to be called
    immediately before the action, not once at the start of a session: authority
    is re-resolved, the receipt is re-validated against the exact request, and
    only then is the receipt reserved.

    Reservation is last on purpose. A receipt burnt by a check that was going to
    fail anyway would be a denial-of-service on the approver, who would have to
    approve again. Once every check passes, the reservation is the commit point
    -- after it returns True the caller may act, and if the action then fails
    the receipt stays spent, because replaying it is the worse outcome.

    Pass `reserve=False` to preview a decision without consuming anything.
    """
    authority = check_permission(
        bundle,
        lineage=lineage,
        agent=agent,
        namespace=request.namespace,
        resource=request.resource,
        action=request.action,
        at=at,
        external=external,
    )
    warnings = list(authority.warnings)

    def refuse(reason: ReasonCode, detail: str, **extra: Any) -> ExecutionDecision:
        return ExecutionDecision(
            may_execute=False,
            reason=reason,
            detail=detail,
            request=request,
            authority=authority,
            warnings=tuple(warnings),
            **extra,
        )

    # Authority first, always. A receipt cannot supply a grant that never
    # existed, so an agent without one is refused before any receipt is read.
    if authority.reason not in (ReasonCode.VALID_AUTHORITY_CHAIN, ReasonCode.APPROVAL_REQUIRED):
        return refuse(authority.reason, f"authority check failed: {authority.detail}")

    if authority.allowed and authority.approval is ApprovalMode.NONE:
        return ExecutionDecision(
            may_execute=True,
            reason=ReasonCode.VALID_AUTHORITY_CHAIN,
            detail=(
                f"the authority chain permits this action without human approval. {authority.note}"
            ),
            request=request,
            authority=authority,
            warnings=tuple(warnings),
        )
    if authority.allowed:
        # external-only, and the caller stated the action is internal.
        return ExecutionDecision(
            may_execute=True,
            reason=ReasonCode.VALID_AUTHORITY_CHAIN,
            detail=(
                f"the chain requires {authority.approval.wire_name} approval, and this "
                f"action was declared internal. {authority.note}"
            ),
            request=request,
            authority=authority,
            warnings=tuple(warnings),
        )

    grants = {
        parsed.event_id: parsed
        for parsed in (
            read_grant(event) for event in bundle.of_type("delegation.grant", lineage=lineage)
        )
        if not isinstance(parsed, str)
    }
    entitled = _approvers_entitled(authority, grants)

    matching: list[ApprovalReceipt] = []
    for event in bundle.of_type(APPROVAL_RECEIPT, lineage=lineage):
        parsed = read_receipt(event)
        if isinstance(parsed, str):
            warnings.append(f"approval receipt {event.event_id} ignored: {parsed}")
            continue
        if parsed.agent != agent or parsed.request_hash != request.request_hash:
            continue
        matching.append(parsed)

    if not matching:
        return refuse(
            ReasonCode.APPROVAL_REQUIRED,
            "authority is valid, but no approval receipt in this bundle binds this "
            f"exact action ({request.render()})",
        )

    problems: list[tuple[ReasonCode, str]] = []
    for receipt in sorted(matching, key=lambda r: r.event_id):
        if receipt.approver not in entitled:
            problems.append(
                (
                    ReasonCode.DENIED,
                    f"receipt {receipt.event_id} is signed by {receipt.approver}, who is "
                    "neither the current root nor an issuer on the authority path (D-042)",
                )
            )
            continue
        if at < receipt.issued_at:
            problems.append(
                (ReasonCode.NOT_YET_VALID, f"receipt {receipt.event_id} is issued in the future")
            )
            continue
        if at >= receipt.expires_at:
            problems.append(
                (
                    ReasonCode.EXPIRED,
                    f"receipt {receipt.event_id} expired at {receipt.expires_at.isoformat()}",
                )
            )
            continue
        if store is not None and store.is_spent(receipt.event_id):
            problems.append(
                (ReasonCode.REVOKED, f"receipt {receipt.event_id} has already been used")
            )
            continue

        if store is not None and reserve:
            if not store.reserve(receipt.event_id):
                # Lost the race. Another executor holds this receipt, and two
                # executors acting on one approval is the thing being prevented.
                problems.append(
                    (
                        ReasonCode.REVOKED,
                        f"receipt {receipt.event_id} was consumed concurrently",
                    )
                )
                continue

        return ExecutionDecision(
            may_execute=True,
            reason=ReasonCode.VALID_AUTHORITY_CHAIN,
            detail=(
                f"authorized by the chain and approved by {receipt.approver} for this "
                f"exact action. {authority.note}"
            ),
            request=request,
            authority=authority,
            receipt_id=receipt.event_id,
            approver=receipt.approver,
            reserved=store is not None and reserve,
            warnings=tuple(warnings),
        )

    reason, detail = problems[0]
    return refuse(reason, detail)
