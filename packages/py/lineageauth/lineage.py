"""Resolving the current root and epoch of a lineage from a set of events.

`docs/05_RECOVERY_SUCCESSION.md`: current authority is the highest *validly
resolved* epoch. This module walks that chain -- genesis, then one epoch at a
time -- and stops the moment it can no longer justify a step.

Three design commitments are worth reading before the code, because each of them
is a place where an obvious shortcut would be a vulnerability.

*Nothing is decided by a timestamp.* `issuedAt` is a claim about when a
signature was made, not a validity window; no Phase 1 payload has `notBefore` or
`expiresAt` (D-026). So `at` is recorded and used to warn about future-dated
events, and takes no part in any decision (D-033). Deciding a contested
succession by time would hand the lineage to whoever signs last, which is
exactly the attacker holding a stolen key. When two incompatible successions
leave the same epoch, both are surfaced and the resolver stops (CONFLICTED).

*Fail closed, but only where a stranger cannot reach the switch.* Anyone can
mint a well-formed, correctly signed event naming someone else's lineage. If
such an event could halt resolution, the halt itself becomes the attack (D-034).
So lineage-wide halts are reserved for conditions that required the current
root's signature; everything else is denied as an individual candidate, which is
equally fail-closed -- a denied candidate never moves authority -- without
letting an outsider freeze anything.

*A superseded key is not a broken key.* `did:key` has no revocation, so an old
root signs valid signatures forever. SUPERSEDED is a statement about this
protocol's semantics, never about the mathematics. `LineageState.note` carries
that caveat on every result so an interface cannot forget to show it.

Offline: no network, no database, no private keys. The same events, the same
`at`, and the same protocol version always give the same result, regardless of
the order the events arrived in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from lineageauth.bundle import AdmittedEvent, EventBundle
from lineageauth.canonical import is_event_id
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError, ReasonCode
from lineageauth.identifiers import derive_lineage_id, is_lineage_id

ROOT_CREATE = "root.create"
RECOVERY_POLICY = "recovery.policy"
ROOT_SUCCESSION = "root.succession"
NORMAL_SUCCESSION = "normal"
RECOVERY_SUCCESSION = "recovery"

SUPERSEDED_KEY_NOTE = (
    "A superseded root key keeps producing mathematically valid signatures "
    "forever -- did:key has no revocation. SUPERSEDED means this protocol no "
    "longer treats that key as the lineage's current root; it does not mean the "
    "key's signatures stop verifying. Interfaces must state this explicitly "
    "(docs/05_RECOVERY_SUCCESSION.md)."
)

RESOLUTION_SCOPE_NOTE = (
    "This resolves which key currently holds root authority for a lineage. It "
    "is not an authorization decision for any particular action, and says "
    "nothing about the identity, affiliation, or safety of the holder."
)


@dataclass(frozen=True, slots=True)
class EpochStep:
    """One accepted move from `from_epoch` to `to_epoch`.

    `via_event_ids` holds *every* authorized succession that produced this step,
    ascending. When several successions agree on the same `to_root` there is no
    conflict and therefore no winner to pick -- picking one would discard audit
    evidence, and any rule for picking would be a tiebreak the protocol has
    deliberately refused to define.
    """

    from_epoch: int
    to_epoch: int
    from_root: str
    to_root: str
    mode: str
    via_event_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ActivePolicy:
    """The recovery policy currently governing recovery successions."""

    event_id: str
    epoch: int
    policy_seq: int
    members: tuple[str, ...]
    threshold: int
    previous_policy: str | None = None


@dataclass(frozen=True, slots=True)
class DeniedCandidate:
    """An event that could have moved authority and was refused, with the reason."""

    event_id: str
    event_type: str
    reason: ReasonCode
    detail: str


@dataclass(frozen=True, slots=True)
class LineageState:
    """The resolved standing of one lineage. Never reduce this to a boolean.

    On failure `root` and `epoch` keep the last position the resolver could
    justify, so an operator can see *where* the chain stopped -- but `resolved`
    is False and `standing_of` refuses to call anyone current (D-035).
    """

    lineage: str
    resolved: bool
    reason: ReasonCode
    detail: str
    evaluated_at: datetime
    genesis_root: str | None = None
    root: str | None = None
    epoch: int | None = None
    history: tuple[EpochStep, ...] = ()
    superseded_roots: tuple[str, ...] = ()
    active_recovery_policy: ActivePolicy | None = None
    conflicting_event_ids: tuple[str, ...] = ()
    denied: tuple[DeniedCandidate, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def note(self) -> str:
        """The caveats that accompany every result, positive or not."""
        return f"{RESOLUTION_SCOPE_NOTE} {SUPERSEDED_KEY_NOTE}"

    def standing_of(self, did: str) -> ReasonCode:
        """How this lineage regards `did` right now.

        An unresolved lineage answers with its own failure code rather than
        DENIED or SUPERSEDED: those read as settled answers, and nothing is
        settled here (D-035).
        """
        if not self.resolved:
            return self.reason
        if did == self.root:
            return ReasonCode.VALID_AUTHORITY_CHAIN
        if did in self.superseded_roots:
            return ReasonCode.SUPERSEDED
        return ReasonCode.DENIED


class _Halt(Exception):
    """Internal: a condition that stops resolution for the whole lineage.

    Reserved for states only an authorized signer can create (D-034).
    """

    def __init__(self, reason: ReasonCode, detail: str, event_ids: tuple[str, ...] = ()) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.event_ids = event_ids


def _as_int(value: Any) -> int | None:
    """Read a JSON integer. `bool` is an `int` in Python and is not one here."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _as_did(value: Any) -> str | None:
    """Read a payload field that must be a usable Ed25519 `did:key`.

    Checking the shape here rather than at the point of comparison matters
    twice over. A root the verifier cannot parse could otherwise be reported as
    the current root -- a resolved state nobody can subsequently verify against
    -- and an unparsed field is raw attacker-controlled text that goes on to be
    interpolated into human-readable reasons. `did:key` has a strict alphabet,
    so validating it here is also what keeps terminal escape sequences out of
    the CLI's output.

    Genesis already held itself to this standard through `derive_lineage_id`;
    successions did not, and the asymmetry was the bug.
    """
    text = _as_str(value)
    if text is None:
        return None
    try:
        public_key_from_did_key(text)
    except LineageAuthError:
        return None
    return text


def _as_event_ref(value: Any) -> str | None:
    """Read a payload field that must be an `sha256:<64 hex>` event reference."""
    text = _as_str(value)
    if text is None or not is_event_id(text):
        return None
    return text


def _read_policy(event: AdmittedEvent) -> ActivePolicy | str:
    """Validate a `recovery.policy` payload, returning the policy or a complaint.

    Members must arrive already sorted and distinct: `builders.py` emits them
    that way, and accepting other spellings would let one membership set have
    several canonical forms and therefore several event ids.
    """
    epoch = _as_int(event.get("epoch"))
    if epoch is None or epoch < 0:
        return "epoch must be a non-negative integer"
    policy_seq = _as_int(event.get("policySeq"))
    if policy_seq is None or policy_seq < 1:
        return "policySeq must be an integer >= 1"

    raw_members = event.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        return "members must be a non-empty array of DIDs"
    members: list[str] = []
    for candidate in raw_members:
        member = _as_did(candidate)
        if member is None:
            return "every recovery member must be a usable Ed25519 did:key"
        members.append(member)
    if len(set(members)) != len(members):
        return "recovery members must be distinct DIDs"
    if members != sorted(members):
        return "members must be in ascending order so one membership set has one encoding"

    threshold = _as_int(event.get("threshold"))
    if threshold is None or not 1 <= threshold <= len(members):
        return f"threshold must be between 1 and the member count ({len(members)})"

    raw_previous = event.get("previousPolicy")
    previous = _as_event_ref(raw_previous)
    if raw_previous is not None and previous is None:
        return "previousPolicy must be an event id of the form sha256:<64 hex>"
    if policy_seq > 1 and previous is None:
        return "a replacement policy (policySeq > 1) must reference the policy it replaces"
    if policy_seq == 1 and previous is not None:
        # The first policy in a chain has nothing to replace. Accepting a
        # reference here would let a payload claim a lineage of policies that
        # the sequence number says does not exist.
        return "the first policy (policySeq 1) must not claim to replace another"

    return ActivePolicy(
        event_id=event.event_id,
        epoch=epoch,
        policy_seq=policy_seq,
        members=tuple(members),
        threshold=threshold,
        previous_policy=previous,
    )


def _advance_policy(
    bundle: EventBundle,
    *,
    lineage: str,
    epoch: int,
    current_root: str,
    active: ActivePolicy | None,
    denied: list[DeniedCandidate],
    considered: set[str],
) -> ActivePolicy | None:
    """Apply the recovery policies installed at `epoch`.

    A policy stays active across later epochs until another replaces it (D-031),
    so this only ever looks at policies stamped with the epoch just entered.

    Only the current root may install one (`docs/05_RECOVERY_SUCCESSION.md`), so
    everything that reaches the halting paths below is root-signed -- which is
    what makes halting safe rather than a stranger's off switch (D-034).
    """
    candidates: list[ActivePolicy] = []
    for event in bundle.of_type(RECOVERY_POLICY, lineage=lineage):
        parsed = _read_policy(event)
        if isinstance(parsed, str):
            considered.add(event.event_id)
            denied.append(
                DeniedCandidate(event.event_id, RECOVERY_POLICY, ReasonCode.MALFORMED, parsed)
            )
            continue
        if parsed.epoch != epoch:
            continue
        considered.add(event.event_id)
        if not event.signed_by(current_root):
            denied.append(
                DeniedCandidate(
                    event.event_id,
                    RECOVERY_POLICY,
                    ReasonCode.DENIED,
                    f"not signed by the root holding epoch {epoch} ({current_root}); "
                    "only the current root may install a recovery policy",
                )
            )
            continue
        candidates.append(parsed)

    _reject_unorderable(candidates)

    for candidate in sorted(candidates, key=lambda policy: policy.policy_seq):
        if active is not None and candidate.policy_seq <= active.policy_seq:
            denied.append(
                DeniedCandidate(
                    candidate.event_id,
                    RECOVERY_POLICY,
                    ReasonCode.SUPERSEDED,
                    f"policySeq {candidate.policy_seq} does not advance past the active "
                    f"policy's {active.policy_seq}",
                )
            )
            continue
        if candidate.policy_seq > 1:
            if active is None:
                # Nothing is being kept alive by this refusal, so deny the candidate
                # rather than the lineage.
                denied.append(
                    DeniedCandidate(
                        candidate.event_id,
                        RECOVERY_POLICY,
                        ReasonCode.UNRESOLVED_PARENT,
                        "the policy it replaces is not active in this bundle, so the "
                        "policy chain cannot be established",
                    )
                )
                continue
            _check_policy_chain(bundle, lineage=lineage, candidate=candidate, active=active)
        active = candidate
    return active


def _reject_unorderable(candidates: list[ActivePolicy]) -> None:
    """Halt when two distinct policies claim one `policySeq`.

    `docs/05_RECOVERY_SUCCESSION.md` asks for exactly this: policies that cannot
    be ordered fail closed. The alternative -- ordering them by `issuedAt` -- is
    the timestamp tiebreak the protocol refuses (D-033).
    """
    by_seq: dict[int, list[str]] = {}
    for candidate in candidates:
        by_seq.setdefault(candidate.policy_seq, []).append(candidate.event_id)
    for seq in sorted(by_seq):
        event_ids = sorted(set(by_seq[seq]))
        if len(event_ids) > 1:
            raise _Halt(
                ReasonCode.CONFLICTED,
                f"{len(event_ids)} distinct recovery policies claim policySeq {seq}; "
                "they cannot be ordered by the protocol and are not ordered by time",
                tuple(event_ids),
            )


def _check_policy_chain(
    bundle: EventBundle,
    *,
    lineage: str,
    candidate: ActivePolicy,
    active: ActivePolicy,
) -> None:
    """Halt when a replacement policy does not attach to the active one.

    Denying the replacement instead would silently leave the *previous* policy
    active. That is the dangerous outcome: rotation exists to drop a compromised
    member, and quietly keeping the set that still names them is worse than
    refusing to answer. Only the current root can reach this state, so halting
    is not something an outsider can trigger (D-034).
    """
    referenced = candidate.previous_policy
    target = bundle.by_id(referenced)
    if target is None or target.event_type != RECOVERY_POLICY or target.lineage != lineage:
        raise _Halt(
            ReasonCode.UNRESOLVED_PARENT,
            f"recovery policy {candidate.event_id} replaces {referenced!r}, which this "
            "bundle does not contain as a verified recovery policy for this lineage",
            (candidate.event_id,),
        )
    if target.event_id != active.event_id:
        raise _Halt(
            ReasonCode.CONFLICTED,
            f"recovery policy {candidate.event_id} replaces {target.event_id}, but the "
            f"active policy is {active.event_id}; the policy chain forks",
            tuple(sorted({candidate.event_id, target.event_id, active.event_id})),
        )


@dataclass(frozen=True, slots=True)
class _Succession:
    event_id: str
    from_root: str
    to_root: str
    from_epoch: int
    mode: str


def _read_succession(event: AdmittedEvent) -> _Succession | str:
    """Validate a `root.succession` payload, returning it or a complaint."""
    from_epoch = _as_int(event.get("fromEpoch"))
    if from_epoch is None or from_epoch < 0:
        return "fromEpoch must be a non-negative integer"
    to_epoch = _as_int(event.get("toEpoch"))
    if to_epoch != from_epoch + 1:
        return f"toEpoch must be fromEpoch + 1 ({from_epoch + 1}), got {to_epoch!r}"
    from_root = _as_did(event.get("fromRoot"))
    to_root = _as_did(event.get("toRoot"))
    if from_root is None or to_root is None:
        return "fromRoot and toRoot must both be usable Ed25519 did:key values"
    if from_root == to_root:
        return "a succession must move the root to a different DID"
    mode = _as_str(event.get("mode"))
    if mode not in (NORMAL_SUCCESSION, RECOVERY_SUCCESSION):
        return f"mode must be {NORMAL_SUCCESSION!r} or {RECOVERY_SUCCESSION!r}, got {mode!r}"
    return _Succession(event.event_id, from_root, to_root, from_epoch, mode)


def _authorize_succession(
    event: AdmittedEvent,
    succession: _Succession,
    *,
    bundle: EventBundle,
    current_root: str,
    active: ActivePolicy | None,
) -> DeniedCandidate | None:
    """Return None when the succession is authorized, else why it is not.

    Both refusals here are candidate-level rather than lineage-level: a stranger
    can author either one, and a halt they can trigger is a denial of service
    (D-034). A denied candidate still cannot move authority, so this is not a
    weakening.
    """
    if succession.mode == NORMAL_SUCCESSION:
        if not event.signed_by(current_root):
            return DeniedCandidate(
                event.event_id,
                ROOT_SUCCESSION,
                ReasonCode.DENIED,
                f"a normal succession must be signed by the outgoing root {current_root}",
            )
        return None

    referenced = _as_event_ref(event.get("recoveryPolicyRef"))
    if referenced is None:
        return DeniedCandidate(
            event.event_id,
            ROOT_SUCCESSION,
            ReasonCode.MALFORMED,
            "a recovery succession must reference the recovery policy it uses, "
            "as an event id of the form sha256:<64 hex>",
        )
    if active is None:
        return DeniedCandidate(
            event.event_id,
            ROOT_SUCCESSION,
            ReasonCode.DENIED,
            "no recovery policy is active for this lineage, so no quorum can authorize "
            "a recovery succession",
        )
    if referenced != active.event_id:
        resolvable = bundle.by_id(referenced) is not None
        return DeniedCandidate(
            event.event_id,
            ROOT_SUCCESSION,
            ReasonCode.SUPERSEDED if resolvable else ReasonCode.UNRESOLVED_PARENT,
            f"cites recovery policy {referenced}, but the policy active at epoch "
            f"{succession.from_epoch} is {active.event_id} (D-030)",
        )

    # One key, one vote: duplicate proofs collapse and non-members count zero.
    qualifying = event.distinct_signers() & set(active.members)
    if len(qualifying) < active.threshold:
        return DeniedCandidate(
            event.event_id,
            ROOT_SUCCESSION,
            ReasonCode.INSUFFICIENT_RECOVERY_PROOFS,
            f"{len(qualifying)} distinct policy member(s) signed; policy "
            f"{active.event_id} requires {active.threshold} of {len(active.members)}",
        )
    return None


def _resolve_genesis(bundle: EventBundle, *, lineage: str, denied: list[DeniedCandidate]) -> str:
    """Establish the epoch-0 root, or halt.

    The genesis event must be signed by the root it installs (D-029), and the
    lineage identifier must recompute from that root (D-025) -- so a lineage is
    self-certifying and no registry is consulted.
    """
    valid: list[AdmittedEvent] = []
    for event in bundle.of_type(ROOT_CREATE, lineage=lineage):
        complaint = _genesis_complaint(event, lineage=lineage)
        if complaint is not None:
            denied.append(DeniedCandidate(event.event_id, ROOT_CREATE, complaint[0], complaint[1]))
            continue
        valid.append(event)

    if not valid:
        raise _Halt(
            ReasonCode.UNRESOLVED_PARENT,
            f"no verified root.create establishes {lineage}; without a genesis event "
            "there is no authority to resolve",
        )
    if len(valid) > 1:
        event_ids = tuple(sorted(event.event_id for event in valid))
        raise _Halt(
            ReasonCode.CONFLICTED,
            f"{len(event_ids)} genesis events claim {lineage}; a lineage opens exactly once",
            event_ids,
        )
    root = _as_str(valid[0].get("root"))
    assert root is not None  # _genesis_complaint already established this
    return root


def _genesis_complaint(event: AdmittedEvent, *, lineage: str) -> tuple[ReasonCode, str] | None:
    epoch = _as_int(event.get("epoch"))
    if epoch != 0:
        return (ReasonCode.MALFORMED, f"root.create must declare epoch 0, got {epoch!r}")
    root = _as_str(event.get("root"))
    if root is None:
        return (ReasonCode.MALFORMED, "root must be a DID string")
    try:
        derived = derive_lineage_id(root)
    except MalformedEventError as exc:
        return (ReasonCode.MALFORMED, f"root is not a usable did:key: {exc}")
    if derived != lineage:
        return (
            ReasonCode.MALFORMED,
            f"lineage {lineage} does not derive from the declared root {root} (D-025)",
        )
    if not event.signed_by(root):
        return (
            ReasonCode.DENIED,
            f"genesis is not signed by the root it installs ({root}); "
            "opening a lineage requires proof of control of that key (D-029)",
        )
    return None


def resolve_lineage(bundle: EventBundle, *, lineage: str, at: datetime) -> LineageState:
    """Resolve the current root and epoch of `lineage` from `bundle`.

    `at` is recorded as `evaluated_at` and used only to warn about events dated
    after it. It is deliberately not a filter: dropping a future-dated event
    would let a clock decide a contested succession, which is the timestamp
    tiebreak `docs/05_RECOVERY_SUCCESSION.md` forbids (D-033). The parameter
    stays in the signature for the Phase 2 events that will carry real validity
    windows.
    """
    if at.tzinfo is None:
        raise MalformedEventError("the evaluation time must be timezone-aware (RFC3339 UTC)")

    warnings: list[str] = list(bundle.warnings)
    denied: list[DeniedCandidate] = []

    if not is_lineage_id(lineage):
        return LineageState(
            lineage=lineage,
            resolved=False,
            reason=ReasonCode.MALFORMED,
            detail=f"{lineage!r} is not a well-formed lineage identifier",
            evaluated_at=at,
            warnings=tuple(warnings),
        )

    future = tuple(
        sorted(
            event.event_id
            for event in bundle.admitted
            if event.lineage == lineage and event.issued_at > at
        )
    )
    if future:
        warnings.append(
            f"{len(future)} event(s) claim an issuedAt after the evaluation time: "
            f"{', '.join(future)}. They still count -- issuedAt is not a validity "
            "window and is never used to prefer one event over another (D-033)."
        )

    genesis_root: str | None = None
    root: str | None = None
    epoch: int | None = None
    history: list[EpochStep] = []
    superseded: list[str] = []
    active: ActivePolicy | None = None
    considered_policies: set[str] = set()

    def unreached_policy_warning() -> list[str]:
        """Name recovery policies the walk never evaluated.

        The chain is only walked from epoch 0 to the last epoch it could
        resolve, so a policy stamped with any other epoch is never looked at.
        Dropping it silently is the dangerous part: rotating a policy to remove
        a compromised member is exactly the operation where a mistyped epoch
        leaves the old membership active, and the operator sees a clean result
        with the replacement nowhere in it.
        """
        unreached = sorted(
            event.event_id
            for event in bundle.of_type(RECOVERY_POLICY, lineage=lineage)
            if event.event_id not in considered_policies
        )
        if not unreached:
            return []
        return [
            f"{len(unreached)} recovery policy event(s) were never evaluated because their "
            f"epoch lies outside the resolved range: {', '.join(unreached)}. They are not "
            "in force; check their epoch field."
        ]

    def superseded_view() -> tuple[str, ...]:
        """Roots that have been stepped away from and are not held right now.

        A lineage may hand the root back to a key it used before (A -> B -> A).
        Listing that key as superseded while it is the current root invites a
        reader -- or a downstream projection that trusts the field on its own --
        to treat the live root as retired.

        Order follows the succession chain rather than sorting: the walk is
        already deterministic, and the sequence a lineage actually moved through
        says more than an alphabet does.
        """
        seen: set[str] = set()
        ordered: list[str] = []
        for did in superseded:
            if did != root and did not in seen:
                seen.add(did)
                ordered.append(did)
        return tuple(ordered)

    try:
        genesis_root = _resolve_genesis(bundle, lineage=lineage, denied=denied)
        root, epoch = genesis_root, 0
        successions = bundle.of_type(ROOT_SUCCESSION, lineage=lineage)

        # Every succession advances the epoch by exactly one, so the chain cannot
        # revisit an epoch; this bound just makes termination obvious.
        for _ in range(len(successions) + 1):
            active = _advance_policy(
                bundle,
                lineage=lineage,
                epoch=epoch,
                current_root=root,
                active=active,
                denied=denied,
                considered=considered_policies,
            )
            step = _next_step(
                bundle,
                successions,
                current_root=root,
                current_epoch=epoch,
                active=active,
                denied=denied,
            )
            if step is None:
                break
            history.append(step)
            superseded.append(root)
            root, epoch = step.to_root, step.to_epoch
    except _Halt as halt:
        return LineageState(
            lineage=lineage,
            resolved=False,
            reason=halt.reason,
            detail=halt.detail,
            evaluated_at=at,
            genesis_root=genesis_root,
            root=root,
            epoch=epoch,
            history=tuple(history),
            superseded_roots=superseded_view(),
            active_recovery_policy=active,
            conflicting_event_ids=halt.event_ids,
            denied=tuple(denied),
            warnings=tuple(warnings + unreached_policy_warning()),
        )

    return LineageState(
        lineage=lineage,
        resolved=True,
        reason=ReasonCode.VALID_AUTHORITY_CHAIN,
        detail=(
            f"resolved to epoch {epoch} after {len(history)} succession(s); current root {root}"
        ),
        evaluated_at=at,
        genesis_root=genesis_root,
        root=root,
        epoch=epoch,
        history=tuple(history),
        superseded_roots=superseded_view(),
        active_recovery_policy=active,
        denied=tuple(denied),
        warnings=tuple(warnings + unreached_policy_warning()),
    )


def _next_step(
    bundle: EventBundle,
    successions: tuple[AdmittedEvent, ...],
    *,
    current_root: str,
    current_epoch: int,
    active: ActivePolicy | None,
    denied: list[DeniedCandidate],
) -> EpochStep | None:
    """Find the one authorized move out of `current_epoch`, or halt on a conflict."""
    authorized: list[_Succession] = []
    for event in successions:
        parsed = _read_succession(event)
        if isinstance(parsed, str):
            denied.append(
                DeniedCandidate(event.event_id, ROOT_SUCCESSION, ReasonCode.MALFORMED, parsed)
            )
            continue
        if parsed.from_epoch != current_epoch:
            continue
        if parsed.from_root != current_root:
            # D-032: an event naming the right epoch but the wrong outgoing root is
            # not a candidate at all, so it cannot manufacture a conflict either.
            denied.append(
                DeniedCandidate(
                    event.event_id,
                    ROOT_SUCCESSION,
                    ReasonCode.DENIED,
                    f"leaves {parsed.from_root}, but epoch {current_epoch} is held by "
                    f"{current_root}",
                )
            )
            continue
        refusal = _authorize_succession(
            event, parsed, bundle=bundle, current_root=current_root, active=active
        )
        if refusal is not None:
            denied.append(refusal)
            continue
        authorized.append(parsed)

    if not authorized:
        return None

    destinations = sorted({candidate.to_root for candidate in authorized})
    event_ids = tuple(sorted(candidate.event_id for candidate in authorized))
    if len(destinations) > 1:
        raise _Halt(
            ReasonCode.CONFLICTED,
            f"{len(event_ids)} incompatible successions are authorized out of epoch "
            f"{current_epoch}, naming {len(destinations)} different roots. The protocol "
            "cannot prefer one and refuses to prefer the later timestamp, so new "
            "authority fails closed (docs/05_RECOVERY_SUCCESSION.md)",
            event_ids,
        )

    modes = sorted({candidate.mode for candidate in authorized})
    return EpochStep(
        from_epoch=current_epoch,
        to_epoch=current_epoch + 1,
        from_root=current_root,
        to_root=destinations[0],
        mode="+".join(modes),
        via_event_ids=event_ids,
    )
