# 29 — Architecture Decision Log

## D-001 Signed event is source of truth
DB/Technocore are projections/discovery.

## D-002 RFC8785 JCS
No custom canonicalization.

## D-003 Ed25519 did:key first
Other DID methods are extensions.

## D-004 SHA-256 event IDs
`sha256:<lower hex>` MVP.

## D-005 Deny by default
No implicit authority.

## D-006 Attenuation monotonic
Child cannot broaden.

## D-007 Epoch-based root succession
Highest valid resolved epoch is current authority.

## D-008 Conflict fail-closed
Ambiguous competing current root => CONFLICTED.

## D-009 Exact-action human approval
Agent + action + destination + hash + nonce + expiry.

## D-010 Approval does not create authority
Base grant required.

## D-011 No wallet integration
Separate keys and no payments core.

## D-012 Evidence is not truth
Attestation proves issuer's signed statement.

## D-013 Passport is projection
No centralized truth score.

## D-014 Router rank must be explainable
No opaque trust score.

## D-015 Fleet disclosure is voluntary
Not Sybil-proofing.

## D-016 Technocore endpoint semantics over HTTP verb
GET may be write.

## D-017 MCP/A2A adapters do not bypass native authorization
LineageAuth is additive provenance.

## D-018 Immutable history
Corrections are new events.

## D-019 DB rebuildable
Projection stores are disposable.

## D-020 Protocol decisions must be logged
Claude Code appends new decisions before implementing ambiguous semantics.

## D-021 Personal project isolation
LineageAuth is developed outside the company RPO account/environment.

## D-022 Personal Git/GitHub identity
Expected personal account/owner is `miyawakiclaude`.

## D-023 No company resource dependency
Company source code, secrets, cloud, billing, repositories, SSO and deployment environments are not dependencies of LineageAuth.

## D-024 Remote writes verify identity
Git/GitHub writes require confirmation of active account + repository owner + remote + branch before execution.


## D-025 Lineage identifier is derived from the genesis root DID

- **Date:** 2026-08-26
- **Problem:** `docs/02_LAP_CORE.md` requires a `lineage` field on every event
  but does not say how the identifier is constructed. Hashing the `root.create`
  event is circular, because `lineage` is inside the payload being hashed.
- **Options:** (a) random UUID; (b) hash of the genesis event; (c) derive from
  the epoch-0 root DID.
- **Decision:** (c). `lineage:la:<method-specific id of the epoch-0 root did:key>`.
- **Security impact:** Self-certifying. A verifier recomputes the identifier
  from the declared root DID offline, so no registry can be substituted and no
  lookup can be omitted. Two distinct genesis keys cannot collide on one
  identifier. Deriving an identifier confers nothing: only the signed
  `root.create` establishes the genesis root.
- **Interop impact:** None outside this protocol. The identifier is opaque to
  Technocore, MCP, and A2A.
- **Migration:** A future DID method would need its own derivation rule under a
  versioned extension profile.

## D-026 Phase 1 payload field names are fixed here

- **Date:** 2026-08-26
- **Problem:** `docs/03_EVENT_CATALOG.md` names the lineage events but leaves
  their payload shapes open. Implementation cannot proceed without them.
- **Decision:**
  - `root.create` — `root`, `epoch` (always 0)
  - `recovery.policy` — `epoch`, `policySeq`, `members` (sorted, distinct),
    `threshold`, `previousPolicy` (required when `policySeq > 1`)
  - `root.succession` — `fromRoot`, `toRoot`, `fromEpoch`, `toEpoch`, `mode`
    (`normal` | `recovery`), `recoveryPolicyRef` (required in `recovery` mode)
- **Security impact:** `previousPolicy` and `policySeq` give recovery policies
  an explicit order, so competing policies fail closed rather than being
  resolved by timestamp (`docs/05_RECOVERY_SUCCESSION.md`).
  `recoveryPolicyRef` is mandatory so a verifier checks a quorum against the
  policy the succession names, instead of whichever policy it happens to hold.
- **Interop impact:** Any change is a protocol version bump; unknown fields are
  already rejected for authority-bearing events.
- **Migration:** Pre-1.0. These shapes may still change before the vectors are
  published as stable.

## D-027 Every proof on an envelope must verify

- **Date:** 2026-08-26
- **Problem:** An envelope may carry several proofs (a recovery quorum needs
  that). If one of them fails to verify, is the event invalid, or is that proof
  simply not counted?
- **Options:** (a) require every proof to verify; (b) pass if any proof
  verifies, and let higher layers count qualifying signers.
- **Decision:** (a). A cryptographically invalid proof is evidence of tampering
  or corruption, not a neutral fact, and integrity fails closed.
- **Security impact:** Prevents an attacker appending junk proofs that a lenient
  reader would ignore. This is distinct from *membership* rules in
  `docs/05_RECOVERY_SUCCESSION.md`: duplicate signers and non-members are valid
  signatures that do not count toward a threshold. Quorum layers therefore read
  the per-proof results rather than relying on the top-level pass.
- **Interop impact:** An independent implementation that passes on "any valid
  proof" would accept envelopes this one rejects. Covered by conformance
  vectors.
- **Migration:** None.

## D-028 Duplicate copies of one event are not merged in Phase 1  — **SUPERSEDED by D-036**

> Withdrawn 2026-08-26. The security impact recorded below is wrong: it treats
> "can only ever deny" as conservative, but denial *is* the attack when the
> thing denied is a legitimate root recovery. See D-036.

- **Date:** 2026-08-26
- **Problem:** A bundle may contain the same `event_id` twice with different
  proof sets (one envelope holding recovery signer 1, another holding signer
  2). Should a quorum count the union of their verified signers?
- **Options:** (a) union the verified signers across copies; (b) treat one
  envelope as the unit of quorum and admit a single copy.
- **Decision:** (b) for Phase 1. `docs/02_LAP_CORE.md` and
  `packages/py/lineageauth/envelope.py` describe the intended shape as *one*
  envelope carrying several proofs, which is exactly what a recovery quorum
  needs. Merging split copies is a distribution concern, not a protocol one,
  and is deferred to its own decision.
- **Security impact:** Conservative. Unioning signers across copies can only
  ever raise a signer count, so declining to union can only ever deny -- never
  admit -- a succession. Duplicate copies are admitted deterministically (the
  copy that sorts first by `(event_id, sorted verified signers)`) and a warning
  names them, so a caller is never silently short a quorum.
- **Interop impact:** An implementation that unions would accept bundles this
  one denies. Bundles should carry one envelope per event.
- **Migration:** A later decision may add unioning; it is a strict relaxation.

## D-029 `root.create` must be signed by the root it declares

- **Date:** 2026-08-26
- **Problem:** `root.create` names the epoch-0 root DID. Nothing in
  `docs/03_EVENT_CATALOG.md` says who must sign it.
- **Options:** (a) accept any signer; (b) require the declared `root`.
- **Decision:** (b). The genesis event must carry a proof from the DID it
  installs as root.
- **Security impact:** Without this, anyone could open a lineage naming a key
  they do not control. `lineage` is derived from that DID (D-025), so the
  attacker could not steal an existing lineage -- but they could publish a
  plausible-looking genesis for someone else's key and seed confusion. Proof of
  control at genesis costs nothing and removes the ambiguity.
- **Interop impact:** Genesis events signed only by a third party are rejected.
- **Migration:** None; no vectors are published yet.

## D-030 A recovery succession must name the policy active at its `fromEpoch`

- **Date:** 2026-08-26
- **Problem:** `recoveryPolicyRef` is mandatory (D-026), but a succession could
  name a superseded policy whose membership has since been rotated.
- **Options:** (a) accept any policy the bundle contains; (b) require the
  reference to equal the policy active at `fromEpoch`.
- **Decision:** (b). A reference to a resolvable but non-active policy is
  denied with `SUPERSEDED`; a reference that resolves to nothing in the bundle
  is denied with `UNRESOLVED_PARENT`; a recovery succession with no active
  policy at all is denied with `DENIED`.
- **Security impact:** This is the whole point of policy rotation. If an old
  policy still authorized successions, removing a compromised recovery member
  would be cosmetic -- the attacker would simply cite the policy that still
  names them.
- **Interop impact:** Bundles must include the policy chain, not just the
  policy a succession happens to cite.
- **Migration:** None.

## D-031 A recovery policy stays active across epochs until replaced

- **Date:** 2026-08-26
- **Problem:** `recovery.policy` carries an `epoch` (D-026). Does a policy stop
  applying the moment a succession moves the lineage to `epoch + 1`?
- **Options:** (a) a policy applies only to its own epoch; (b) a policy stays
  active until a later policy replaces it.
- **Decision:** (b). `epoch` records when the policy was installed, not a
  window in which it applies.
- **Security impact:** Under (a) a normal succession would silently destroy the
  lineage's recovery capability: between the succession and the new root
  publishing a fresh policy, losing the root key would be unrecoverable. That
  is an availability hole, not a safety margin -- and
  `docs/05_RECOVERY_SUCCESSION.md` exists precisely to prevent unrecoverable
  key loss. Rotation stays explicit and ordered (`policySeq`,
  `previousPolicy`), so a stale policy is replaceable at any time.
- **Interop impact:** An implementation applying (a) would deny recovery
  successions this one admits.
- **Migration:** None.

## D-032 A succession is bound to the root it claims to leave

- **Date:** 2026-08-26
- **Problem:** `fromEpoch` alone identifies a position in the chain, but not
  which root occupied it.
- **Decision:** A `root.succession` is a candidate only when its `fromRoot`
  equals the resolved root at `fromEpoch`, and only when
  `toEpoch == fromEpoch + 1`.
- **Security impact:** Prevents a stale or fabricated succession that names the
  right epoch number but the wrong outgoing root from being considered at all
  -- including as a manufactured conflict.
- **Interop impact:** None beyond stricter candidate selection.
- **Migration:** None.

## D-033 The evaluation time `at` takes no part in Phase 1 epoch resolution

- **Date:** 2026-08-26
- **Problem:** `resolve_lineage` takes an explicit evaluation time so results
  are reproducible (`docs/02_LAP_CORE.md`). The tempting next step is to drop
  events whose `issuedAt` lies in the future of `at` as `NOT_YET_VALID`.
- **Options:** (a) filter events by `issuedAt` against `at`; (b) use `at` only
  for reporting, and record a warning for future-dated events.
- **Decision:** (b). No Phase 1 payload has a `notBefore` or `expiresAt` field
  (D-026), so `issuedAt` is a claim about when a signature was made, not a
  protocol validity window. `at` stays in the signature for the Phase 2 events
  that will carry real validity windows.
- **Security impact:** This is the load-bearing part of
  `docs/05_RECOVERY_SUCCESSION.md`'s "do not choose based only on timestamp".
  Filtering by `issuedAt` is that same timestamp tiebreak wearing a disguise:
  given two incompatible successions from one `fromEpoch`, a filter that
  removes one of them lets the survivor advance alone, with no CONFLICTED
  status -- so an attacker who back-dates, or a victim whose clock skews,
  decides the winner. Refusing to filter means both candidates always meet, and
  the conflict is seen. `tests/test_lineage.py::test_issued_at_never_breaks_ties`
  is the regression guard.
- **Interop impact:** An implementation that filters would resolve a current
  root where this one reports CONFLICTED. That divergence is fail-open on their
  side, so this is the safe direction.
- **Migration:** When Phase 2 adds explicit validity windows, `at` gains meaning
  against those fields only, never against `issuedAt`.

## D-034 Lineage-wide fail-closed states require an authorized signature

- **Date:** 2026-08-26
- **Problem:** Fail-closed is correct, but a status anyone can trigger from
  outside is a denial-of-service switch. A stranger can always mint a
  syntactically valid, correctly signed event naming someone else's lineage.
- **Decision:** A condition halts resolution for the whole lineage only when
  producing it required a signature the protocol already trusts -- the current
  root, or a satisfied recovery quorum. Everything an outsider can author is
  evaluated as a candidate and denied individually, with its reason code
  recorded, without stopping the resolver.
- **Security impact:** Competing root-signed successions still yield
  `CONFLICTED` (`docs/05_RECOVERY_SUCCESSION.md`), and competing root-signed
  policies sharing one `policySeq` still fail closed. But a succession citing a
  dangling `recoveryPolicyRef`, which any stranger can sign, is merely denied,
  so no third party can freeze a lineage by publishing junk. Denying a
  candidate is itself fail-closed: a denied candidate never moves authority.
- **Interop impact:** Implementations must not escalate outsider-authored
  defects to a lineage-level status.
- **Migration:** None.

## D-035 An unresolved lineage reports its reason code, never a standing

- **Date:** 2026-08-26
- **Problem:** `LineageState.standing_of(did)` answers "is this DID the current
  root?". When resolution failed (CONFLICTED, or no genesis), what does it say?
- **Options:** (a) add an `UNDETERMINED` reason code; (b) return the state's own
  failure reason.
- **Decision:** (b). `errors.py` fixes the reason vocabulary and states that
  additions require a protocol version bump, and `CONFLICTED` /
  `UNRESOLVED_PARENT` already say precisely why nothing is determined.
- **Security impact:** The important property is that an unresolved lineage
  never returns `DENIED` or `SUPERSEDED` for any DID -- those read as settled
  answers. It returns the failure instead, so a caller that treats any
  non-`VALID_AUTHORITY_CHAIN` result as "do not proceed" is correct by default
  (CLAUDE.md 2.6: never a bare boolean).
- **Interop impact:** None; the code set is unchanged.
- **Migration:** None.

## D-036 Duplicate copies of one event id merge by union of verified signers

- **Date:** 2026-08-26
- **Supersedes:** D-028
- **Problem:** D-028 admitted a single copy per `event_id`, choosing the one
  that sorted first by `(event_id, sorted verified signers)`. An adversarial
  review of the resolver found this exploitable **with no private key at all**.
- **How it failed:** One `event_id` is one payload, so anyone can take a
  published envelope and republish a copy with proofs removed. A shorter tuple
  that shares a prefix with a longer one sorts first in Python, so the stripped
  copy deterministically won the selection. An observer could therefore reduce a
  genuine 2-of-3 recovery succession to one signature, and the resolver denied
  it with `INSUFFICIENT_RECOVERY_PROOFS` -- freezing the lineage at an epoch it
  had already left. Republishing a copy signed only by the attacker's own key
  had the same effect. D-028's reasoning that "declining to union can only ever
  deny" mistook denial for safety; against recovery, denial is the objective.
- **Options:** (a) union the verified signers across copies; (b) keep selecting
  one copy under a different total order; (c) treat differing copies as
  ambiguous and fail closed.
- **Decision:** (a). Options (b) and (c) both leave a keyless third party in
  control of the outcome -- (c) merely converts suppression into a lineage-wide
  denial that anyone can trigger by injecting one copy.
- **Security impact:** Union is the only merge rule that is simultaneously
  order-independent and monotone: nothing an attacker adds can subtract. It
  cannot inflate authority either, because a forged copy can only carry
  signatures the forger can actually produce, and a signer who is neither the
  current root nor a member of the referenced recovery policy contributes
  nothing to any decision the resolver makes.
- **Interop impact:** A strict relaxation of D-028 -- every bundle D-028
  resolved, D-036 resolves identically. Regression vectors:
  `tests/test_bundle.py::test_a_keyless_attacker_cannot_strip_proofs_from_a_published_event`.
- **Migration:** None.

## D-037 Payload fields that name a key or an event are validated at the parse boundary

- **Date:** 2026-08-26
- **Problem:** The resolver read `fromRoot`, `toRoot`, `recoveryPolicyRef`,
  `previousPolicy`, and recovery `members` with an `isinstance(value, str)`
  check only. Genesis, by contrast, ran its `root` through
  `derive_lineage_id`, which validates the `did:key` strictly. The asymmetry was
  not deliberate.
- **Consequences of the gap:** A succession could install a `toRoot` that is not
  a parseable `did:key`, so a lineage could resolve to a "current root" no
  verifier can ever check a signature against. Separately, those unvalidated
  strings were interpolated into human-readable reasons and printed by the CLI,
  which let arbitrary payload bytes -- including terminal escape sequences --
  reach a terminal and dress up a denial as an approval.
- **Decision:** Validate at the point of parsing. A field that names a key must
  be a canonical Ed25519 `did:key`; a field that names an event must match
  `sha256:<64 lowercase hex>`. Anything else makes the event `MALFORMED`.
- **Security impact:** Fixes both problems at the source rather than escaping at
  each output site, which would have to be repeated correctly forever. `did:key`
  and event ids have strict alphabets, so a validated field is also a safe one
  to display.
- **Interop impact:** Events that were previously parsed and then denied on
  other grounds are now rejected earlier, with a clearer reason code.
- **Migration:** None. `builders.py` has always emitted valid values.

## D-038 Events the resolver never evaluated must be reported, not dropped

- **Date:** 2026-08-26
- **Problem:** The walk visits epoch 0 through the last epoch it can resolve, so
  a `recovery.policy` stamped with any other epoch was skipped with no entry in
  `denied` and no warning. Integrity-rejected envelopes were likewise absent
  from the CLI's output entirely.
- **Why it matters:** Rotating a recovery policy to drop a compromised member is
  exactly the operation where a mistyped `epoch` is plausible, and the result
  was a clean-looking resolution in which the old membership -- still naming the
  compromised key -- remained active, with the replacement nowhere in the
  output. Silence read as success. Equally, "somebody sent us a tampered event"
  is the single most important thing a bundle can tell an operator, and it was
  being discarded before display.
- **Decision:** Report both. Policies outside the resolved epoch range produce a
  warning naming them; `EventBundle.rejected` appears in the CLI's JSON and
  human output.
- **Security impact:** Failing closed is necessary but not sufficient -- an
  operator who cannot see *what* was excluded cannot tell a typo from an attack.
- **Interop impact:** Additive output only; no verdict changes.
- **Migration:** None.

## D-039 `delegation.grant` and `delegation.revoke` payload shapes

- **Date:** 2026-08-26
- **Problem:** `docs/03_EVENT_CATALOG.md` names both events; neither payload is
  specified.
- **Decision:**
  - `delegation.grant` — `issuer`, `subject`, `epoch`, `scopes[]`, `notBefore`,
    `expiresAt`, `maxDepth`, `approval`, and `parent` (absent on a grant issued
    directly by the root).
  - `delegation.revoke` — `issuer`, `grant`, optional `reason`.
- **Security impact:** `maxDepth` counts *further* delegations, so a leaf grant
  is depth 0 and delegating from a parent of depth N yields at most N-1;
  otherwise depth would be unbounded in practice. A grant must be signed by its
  declared `issuer`, or anyone could mint a payload naming the root and have it
  treated as the root's delegation.
- **Interop impact:** Any change is a protocol version bump.
- **Migration:** Pre-1.0; shapes may still change.

## D-040 A grant is anchored to a root epoch and does not survive a succession

- **Date:** 2026-08-26
- **Problem:** When a lineage moves from epoch N to N+1, what happens to grants
  issued under epoch N?
- **Options:** (a) they continue until their own expiry; (b) they are superseded
  the moment the lineage advances.
- **Decision:** (b). A grant declares its `epoch` and is current only while the
  lineage is at that epoch.
- **Security impact:** This is what makes recovery mean anything. Recovery
  exists because a root key was lost or compromised; if that root's outstanding
  delegations kept working afterwards, recovery would have changed who can sign
  *new* grants and nothing else, leaving every agent the attacker had already
  provisioned in place. `MASTER_PLAN.md` invariant 4 -- a higher valid epoch
  supersedes lower current authority -- is not satisfied by any weaker reading.
- **Operational cost:** Real, and deliberate. A voluntary succession also
  invalidates outstanding grants, so re-issuing them is part of rotating a root.
  Making the cheap path the safe one is the trade being taken.
- **Interop impact:** An implementation honouring old-epoch grants would allow
  actions this one refuses. Covered by conformance vectors.
- **Migration:** None.

## D-041 Who may revoke a grant

- **Date:** 2026-08-26
- **Problem:** Revocation only ever subtracts authority, which argues for a wide
  revoker set. But an unbounded one lets any stranger switch off a lineage.
- **Decision:** A revocation counts when signed by its declared issuer and that
  issuer is the grant's own issuer, any ancestor that delegated (transitively)
  to it, or the current root.
- **Security impact:** Revoking a grant removes the whole subtree beneath it,
  because every chain through that subtree passes through the revoked grant --
  so revocation cannot be escaped by delegating onward. A revocation from
  outside the set is recorded as a refusal rather than silently dropped, so an
  operator can see that a revocation they issued is not taking effect.
- **Interop impact:** None beyond the rule itself.
- **Migration:** None.

## D-042 Who may approve an exercise of authority

- **Date:** 2026-08-26
- **Problem:** `docs/06` fixes what an approval binds but not who may sign one.
  Any DID would mean a stranger's consent counts; only the root would make
  delegated operation impractical, since the operator who delegated to an agent
  is exactly the party who should be able to consent to its actions.
- **Decision:** The approver must be the current root of the lineage, or an
  issuer of a grant on the authority path that authorized this action.
- **Security impact:** Mirrors D-041 for revocation, and for the same reason:
  the party that conferred authority is the party entitled to speak about its
  use. A receipt from outside that set is refused with `DENIED` rather than
  ignored, so an operator can see that a receipt they collected does not count.
- **Interop impact:** An implementation accepting any signer would permit
  actions this one refuses.
- **Migration:** A future `approve` scope action could widen this deliberately.

## D-043 `approval.receipt` carries the action in full and as a hash

- **Date:** 2026-08-26
- **Problem:** `docs/06` requires an approval to bind lineage, approver, agent,
  namespace, resource, operation, destination, content hash, nonce, issuance and
  expiry. Should the receipt carry the fields, the hash, or both?
- **Decision:** Both. The fields are present verbatim, plus `requestHash` =
  SHA-256 over the JCS encoding of the canonical request object. A verifier
  recomputes the hash from the fields and refuses on mismatch.
- **Security impact:** The hash is derivable, so carrying it adds no secrecy --
  it adds a consistency check. A receipt that displays one destination and
  commits to another is exactly the substitution an approval preview exists to
  prevent, and the mismatch surfaces immediately rather than at execution time.
  The nonce must decode to at least 16 bytes, so a receipt cannot be
  precomputed for a request the approver has not seen. An agent may not approve
  its own action: the point of an approval is that a second party consented.
- **Limitation to state plainly:** `contentHash` fixes the bytes an executor may
  transmit. It says nothing about how a transport frames them, so every adapter
  must document which bytes it hashes. Technocore's signed lane is the live
  example -- it signs `<room>|<nonce>|<text>`, not the URL carrying it.
- **Migration:** Pre-1.0.

## D-044 Reservation is the last step, and a store never guesses

- **Date:** 2026-08-26
- **Problem:** Where in `check_execution` should a receipt be marked spent, and
  what should a spent store do when it cannot tell?
- **Decision:** Reserve after every other check has passed. A store that cannot
  establish an outcome raises rather than returning `False`.
- **Security impact:** Reserving early would let a check that was going to fail
  anyway burn the receipt, forcing the approver to consent again -- a denial of
  service on the human. Reserving last makes the reservation the commit point:
  once it returns True the caller may act, and if the action then fails the
  receipt stays spent, because replaying it is the worse outcome. On the store
  side, `False` means "already spent", and a caller told that will reasonably
  stop; returning it for a lock timeout would report a definite outcome that was
  never established. `reserve=False` exists so a caller can preview a decision
  without consuming anything.
- **Interop impact:** None; the store is local infrastructure, not protocol.
- **Migration:** `docs/06` anticipates a shared spent service or transparency
  log for production. The `SpentReceiptStore` protocol is the seam for it.

## D-045 The Technocore adapter hashes the swept text, not the caller's text

- **Date:** 2026-08-26
- **Problem:** Technocore applies a "single-line sweep" before storage -- every
  C0/C1 control, format character, zero-width joiner and bidi override becomes a
  space -- and its signed lane covers the text *after* that sweep. So the bytes
  a caller supplies and the bytes that end up stored and signed can differ.
- **Decision:** The adapter sweeps first, and everything downstream uses the
  swept text: the signing preimage, the `contentHash` inside the `ActionRequest`,
  and the approval preview shown to a human.
- **Security impact:** Hashing the caller's text would mean a human approves one
  string while a different one is stored -- the exact substitution
  `docs/06` requires every adapter to close by stating which bytes it hashes.
  The preview also flags when the sweep changed anything, because "what you
  typed is not what will be stored" is information the approver needs.
  Separately, text that is nothing but invisibles sweeps to a run of blanks; it
  is refused rather than signed, since signing it would attest to a message
  nobody can read.
- **Known weakness, stated deliberately:** the sweep here is reimplemented from
  upstream prose, not shared with the server. A divergence would silently weaken
  every approval built on it. Nothing in this package writes, so it cannot cause
  an unapproved effect on its own, but the equivalence must be checked against
  the running service before writing is enabled. That check is not automated.
- **Migration:** Re-verify against upstream before any release that writes.

## D-046 Technocore routes are classified by an allowlist, and unknown is unsafe

- **Date:** 2026-08-26
- **Problem:** Technocore performs writes through plain `GET` -- deliberately,
  so that an agent limited to `webfetch` can be a full peer. The HTTP verb
  therefore carries no information about consequence (D-016).
- **Decision:** A table of recognised route patterns maps each to `READ`,
  `WRITE`, or `UNKNOWN`. Only `READ` may be called automatically. `UNKNOWN` is
  not "unclassified, probably harmless" -- it is a refusal. Write patterns are
  matched before the broader read patterns that would otherwise swallow them,
  since `/r/<room>` would match `/r/<room>/say/...` under a looser rule and turn
  a write into a read.
- **Security impact:** Upstream can add routes at any time, and the one added
  while nobody is looking must fail closed. The classifier also refuses anything
  that is not `https://technocore.chat` on the default port, which is what stops
  a URL arriving inside a message -- untrusted data, never an instruction --
  from being classified as a safe read and then fetched.
- **Interop impact:** A snapshot of someone else's service, checked 2026-08-26.
  It must be re-checked before shipping any integration that acts on it.
- **Migration:** Adding a route is a table edit plus a fresh verification date.

## D-047 The read client refuses redirects and re-checks at the socket

- **Date:** 2026-08-26
- **Problem:** A read adapter is still an outbound request to an address, and
  the two ways that goes wrong are a redirect chosen by someone else and a guard
  that lives only at the call site.
- **Decision:** `HttpsTransport` refuses every redirect, caps the response size,
  sends no cookies or credentials, and calls `assert_safe_to_read` itself --
  even though every caller already did.
- **Security impact:** Following a redirect means fetching a URL the classifier
  never saw, which is the shape of an SSRF regardless of it being "only a read".
  Re-checking inside the transport puts the guard at the last point before a
  socket opens, so a future caller that forgets is refused rather than trusted.
  Dot segments (`.`, `..`) are rejected in `classify` before the route table is
  consulted: `urlsplit` does not normalise them but proxies and servers may, so
  a path could match one route here and resolve to another there -- and
  percent-encoding does not help, since `quote` leaves `.` alone.
- **Interop impact:** None; this is client-side conduct.
- **Migration:** None.

## D-048 A rebuild is one transaction, and the API is optional

- **Date:** 2026-08-26
- **Problem:** `EventIndex.rebuild` emptied its tables in one transaction and
  refilled them one event at a time. A concurrency test showed a reader
  observing counts of 1 and 2 during a rebuild of three events.
- **Why that is not merely untidy:** a permission check computed against a
  partially repopulated index can return ALLOW because the `delegation.revoke`
  had not been reinserted yet. The partial state is not a smaller truth, it is
  a different and more permissive one, and an index behind an HTTP API is read
  concurrently by definition.
- **Decision:** the delete and every insert happen under one lock and one
  commit. A reader sees the index before the rebuild or after it, never during.
- **Also decided:** the REST API is an optional extra (`lineageauth[api]`), not
  a core dependency. `CLAUDE.md` 2.7.2 requires the protocol core to stay fully
  useful locally, so nothing needed to verify an event, resolve a lineage, or
  check a permission may live behind FastAPI. The service ingests nothing over
  HTTP and holds no keys -- events enter only through the store, so a request
  cannot manufacture authority, and there is nowhere for a private key to go.
- **Related:** the same test run found that a single SQLite connection is bound
  to its creating thread, which a threaded server violates immediately. Fixed
  with `check_same_thread=False` plus a reentrant lock: serialising access is
  honest for indexed reads over a local file.
- **Interop impact:** none; this is implementation conduct.
- **Migration:** none.

## D-049 The MCP tool layer does not import the MCP SDK

- **Date:** 2026-08-27
- **Problem:** `docs/19_MCP.md` asks for an `lineageauth-mcp` package. The SDK
  was reworked for the 2026-07-28 specification -- `FastMCP` became
  `MCPServer`, model fields moved to snake_case -- so binding the protocol work
  directly to it means the protocol work moves whenever the transport does.
- **Decision:** `adapters/mcp/tools.py` implements and declares every tool
  without importing the SDK. `server.py` binds it, behind the optional
  `lineageauth[mcp]` extra. The tool tests run with no SDK installed; only the
  five binding tests skip.
- **Security impact:** No signing tool exists, so the server has nowhere to put
  a private key -- `build_delegation` and `build_approval` return unsigned
  drafts, and a test asserts no declared tool mentions a key or a seed. Nothing
  writes to the index, so an MCP client cannot add an event and therefore cannot
  manufacture authority. Every permission answer carries the note that the
  target system's own authorization still applies.
- **Verified rather than reasoned about:** the first binding used a `**kwargs`
  closure. The SDK derives a tool's input schema from the registered function's
  signature and offers no hook for supplying one, so every tool published a
  single required argument called `arguments` and the declared schema never
  reached the client. Running it found that; reading it had not. The binding now
  synthesises a real signature from each declaration, and a test compares what
  the SDK publishes against what the declaration says.
- **Interop impact:** A client sees the declared schemas. Adding a JSON type to
  the mapping is a deliberate edit, not an implicit `Any`.
- **Migration:** A future SDK rework touches `server.py` only.

## D-050 An MCP invocation resource must name one concrete tool

- **Date:** 2026-08-27
- **Problem:** `mcp_resource_for` formats `server:<id>/tool:<name>` from values
  that arrive from outside. MCP's own guidance is that what a server says about
  itself is untrusted.
- **Decision:** The result goes through the scope grammar, and a wildcard is
  refused outright.
- **Security impact:** A wildcard is legitimate in a *scope*, where `tool:*`
  means "any tool on this server". It is wrong when mapping an invocation that
  is about to happen: the question would be asked, and answered, about far more
  than the caller intended. Names carrying a slash, a space, a dot segment, or a
  control character are refused by the grammar for the same reason -- a resource
  that can be widened by its own name is not a resource.
- **Interop impact:** None.
- **Migration:** None.

## D-051 Evidence payload shapes, and the three claim categories

- **Date:** 2026-08-27
- **Problem:** `docs/03` names `artifact.register`, `artifact.receipt`, and
  `attestation.issue`; none of their payloads is specified.
- **Decision:**
  - `artifact.register` — `artifactId` (content hash, the identity),
    `mediaType?`, `byteLength?`, `uri?`, `createdBy?`, `sourceRefs?`
  - `artifact.receipt` — `artifactId`, `worker`, `authorityRefs?`,
    `approvalRef?`; must be signed by `worker`
  - `attestation.issue` — `issuer`, `subjectRef`, `predicate`, `value?`,
    `reasonCode?`, `evidenceRefs?`, `expiresAt?`; must be signed by `issuer`
- **Security impact:** The three categories `docs/09` requires kept apart start
  here, because a passport can only present what this layer hands it.
  `createdBy` on a registration is a *claim* -- anyone may register an artifact
  and name anyone as its creator -- so it is reported as self-asserted unless
  that DID signed the registration. A receipt is stronger, because the worker
  signed it, and is still only a claim of authorship rather than evidence the
  work is any good. An attestation is one signer's opinion, so
  `independent_attesters` counts distinct keys rather than rows: counting rows
  would let one key manufacture a consensus by attesting repeatedly.
- **Availability:** `uri` is optional and non-authoritative. A receipt can bind
  bytes nobody hosts, and there is no field claiming otherwise -- reading a hash
  as "this is fetchable" would be inventing a fact.
- **Unknown predicates:** accepted and kept displayable, but marked. Refusing to
  let anyone express a new kind of claim would be the wrong failure; letting an
  unrecognised one take effect would be the dangerous one.
- **Migration:** Pre-1.0.

## D-052 A cited authority is checked, never taken on trust

- **Date:** 2026-08-27
- **Problem:** An `artifact.receipt` may cite the grants the work was done
  under. A citation is just a field in a payload the worker signed.
- **Decision:** `check_receipt_authority` resolves each cited grant and reports
  whether it is currently usable *and* actually held by the worker who signed
  the receipt.
- **Security impact:** Citing a grant is not holding it. Without the subject
  check, a worker could cite any live grant in the lineage -- including one
  delegated to somebody else -- and have the citation read as support. An
  unsupported citation is reported rather than discarded, because the receipt
  is still a signed claim of authorship; what it must never do is read as
  supported.
- **Interop impact:** None.
- **Migration:** None.

## D-053 A passport is four sections with no combined field

- **Date:** 2026-08-27
- **Problem:** `docs/09_AGENT_PASSPORT.md` asks for an evidence-first profile
  and forbids a single trust score in the same breath. Any convenience field
  that summarised the sections would become that score in practice, whatever it
  was called.
- **Decision:** `Passport` exposes self-claimed, cryptographically linked,
  evidence-supported, and third-party attested as separate collections, and
  offers nothing that merges them. `profile.statement` and `skill.claim` carry
  the self-claimed half; both refuse control characters, because they are
  rendered beside cryptographically-backed facts and must not be able to dress
  themselves up as one.
- **Security impact:** A test walks every key in the rendered passport and
  fails on any name containing `score`, `rating`, `trust`, `reputation`, `rank`,
  or `level`. Keeping the categories apart is the whole value: a self-claimed
  skill and an independently attested one are different things, and a reader
  who cannot tell which is which has been given a number, not evidence.
- **Skill support requires both halves:** a skill counts as evidence-supported
  only when the subject signed a receipt for a cited artifact *and* a different
  key attested to it. Without the receipt the claim points at work nobody can
  tie to that key; without an independent attester the only support is the
  claimant's own word twice over. Support is reported as the parts -- which
  artifacts, which attesters -- rather than as a verdict, because `docs/10`
  requires ranking inputs to stay explainable.
- **Migration:** Pre-1.0.

## D-054 Unbuilt sections are named, not left empty

- **Date:** 2026-08-27
- **Problem:** `docs/09` lists completed tasks, fleet bindings, impact, and
  availability among a passport's contents. None of those phases is built.
- **Decision:** the passport carries a `notIncluded` section naming each and
  saying why.
- **Security impact:** An empty list reads as "this agent has none" when the
  truth is "this system does not look". The difference matters most for the
  sections a reader would weigh -- an agent with no completed tasks and an agent
  whose completed tasks are invisible look identical otherwise. Genuinely empty
  sections are still rendered empty, so the distinction stays legible.
- **Migration:** Entries are removed from `NOT_IMPLEMENTED` as their phases land.

## D-055 Task lifecycle payloads, and state that is derived rather than stored

- **Date:** 2026-08-27
- **Problem:** `docs/03` names the five task events; none of their payloads is
  specified, and nothing says where a task's status lives.
- **Decision:**
  - `task.request` — `requester`, `title`, `acceptanceCriteria` (required,
    non-empty), `allowedClaims`, `deadline?`, `rewardReference?`,
    `requiredAuthority?`
  - `task.claim` — `task`, `claimant`, `nonce`, `expiresAt`
  - `task.release` — `claim`, `claimant`
  - `task.result` — `task`, `claim`, `worker`, `artifactRefs` (non-empty),
    `summary`
  - `task.verify` — `task`, `result`, `verifier`, `verdict`,
    `criteriaResults?`, `evidenceRefs?`
  Status is **derived** by `resolve_task`. No event writes it.
- **Security impact:** Each event must be signed by the party it names, so a
  result cannot be submitted against somebody else's claim and only the holder
  may release one -- otherwise anyone could free a task out from under whoever
  is working on it. Acceptance criteria are mandatory because a verification
  against no criteria is an opinion about nothing in particular. Deriving status
  means removing a verification from a bundle un-accepts the task, which is what
  makes the chain checkable rather than a stored flag somebody set.
- **Disagreement is not resolved here:** an accepted and a rejected verdict on
  one result yields `CONTESTED`. Picking a side would be inventing an
  adjudication this protocol does not have; `docs/12` is where that belongs.
- **`rewardReference` is opaque.** The core escrows nothing, pays nothing, and
  validates no token value. Treating a reward reference as a promise would be
  the protocol claiming something it cannot deliver.
- **Migration:** Pre-1.0.

## D-056 A work receipt carries signals, never a score

- **Date:** 2026-08-27
- **Problem:** `docs/08` says never to mint points in the core, and then lists
  the shapes that make a naive count of completed work meaningless:
  self-created tasks, same-operator verification, and volume.
- **Decision:** `WorkReceipt` has no numeric field that could be summed. It
  reports `requesterIsWorker`, `selfVerified`, the distinct independent
  verifiers, the non-independent ones, and any reciprocal verifier pair -- and
  weights none of them. A test walks every key in the rendered receipt and fails
  on any name containing score, points, rating, rank, or reputation.
- **Security impact:** A reciprocal pair is the cheapest way to make review look
  independent: A verifies B's work and B verifies A's, and each passes the
  narrow "is the verifier the worker" test. Detecting it needs the whole bundle
  rather than the one task, which is why the signal is computed across every
  result and verification present.
- **Passport coupling:** the passport's completed-task section carries these
  signals with each task, so the count never appears without what qualifies it.
  `completedTasks` left `notIncluded` when this phase landed (D-054).
- **Interop impact:** Rankers may use the signals transparently, which means
  handing over the parts rather than an answer.
- **Migration:** None.

## D-057 Relevance is a published sum, not a score

- **Date:** 2026-08-27
- **Problem:** `docs/10` asks for ranked discovery and forbids a hidden trust
  score in the same breath. Ranking needs an order, so some number has to exist.
- **Decision:** the number is *relevance* -- fit for one query, not a rating of
  an agent. It arrives as a list of named `Contribution` values, each carrying
  its count, its weight, and the reason for it, and the weight table travels
  with every response. Adding the contributions reproduces the number exactly,
  and a test asserts that. `RANKING_VERSION` moves whenever the formula does.
- **Security impact:** "Explainable" is only meaningful if a caller can
  recompute the answer, so the weights are published rather than buried --
  buried weights are the hidden score under a different name. Negative evidence
  is weighted too: rejected tasks, self-created tasks, and reciprocal
  verification all subtract, because a ranking that only ever adds is one where
  a rejection costs nothing.
- **Not a Sybil verdict:** the relationship shape -- independent counterparties,
  attestation concentration, reciprocal pairs -- is reported so a caller can
  judge, not because it settles anything. `docs/13` is explicit that fleet
  disclosure is voluntary and undisclosed fleets remain possible.
- **Not authorization:** a result carries the standing reminder to re-check
  authority at the moment of action, since a grant can be revoked between
  finding an agent and asking it to act.
- **Migration:** Reweighting requires a version bump and nothing else.

## D-058 An availability statement expires, and a stale one says so

- **Date:** 2026-08-27
- **Problem:** `docs/10` has availability expiring quickly and being flagged
  when stale.
- **Decision:** `availability.statement` requires an `expiresAt` no more than
  seven days out. An expired statement is reported as `stale` rather than
  dropped, and `usable` is false for it.
- **Security impact:** An agent that said it was free last week has told you
  nothing about now, but a stale statement still *reads* like an answer unless
  something forces it to expire. Capping the window stops an agent declaring
  itself permanently available; keeping the stale record visible lets a caller
  see that a statement existed and lapsed, rather than confusing "said nothing"
  with "said yes a long time ago".
- **Migration:** None.

## D-059 Fleet payloads, and disclosure that costs nothing to make

- **Date:** 2026-08-27
- **Problem:** `docs/13` wants voluntary disclosure of shared operation, and
  adds a constraint that is easy to violate by accident: *never penalize
  disclosure in a hidden way*.
- **Decision:**
  - `fleet.create` — `controller`, `name`; signed by the controller
  - `fleet.bind` — `fleet`, `controller`, `member`, `role?`, `expiresAt?`;
    signed by the controller, not the member
  - `fleet.unbind` — `bind`, `controller`; forward-only
  A disclosed sibling is **excluded from the independent count** and **never
  subtracted from the relevance**.
- **Why that distinction is the whole design:** the obvious implementation
  subtracts points when a verifier turns out to be a fleet sibling. That makes
  disclosure cost the honest operator exactly what silence saves the quiet one,
  and nobody discloses again. "Disclosure costs you" and "what you disclosed is
  not double-counted" are different rules, and only the second can be published
  without destroying the behaviour it is meant to encourage. A test pins it:
  disclosing lowers the relevance by exactly the uncounted counterparty's weight
  and not a point more.
- **What a binding proves:** that the signing controller asserted a
  relationship. Not one legal person, not employment, and never that every DID
  an operator runs has been disclosed. So an absent fleet is not evidence of
  independence -- an agent with no fleet has said nothing, and both the router
  and the passport say so in their own output.
- **Signed by the controller:** the claim is "I operate this", which is the
  controller's to make. A binding anyone could mint would let a stranger tar an
  unrelated agent as part of their group.
- **Migration:** Pre-1.0.

## D-060: impact is features, not a score, and independence has three tiers

- **Date:** 2026-08-27
- **Problem:** `docs/14` asks for demonstrable downstream use and immediately
  lists the ways a use count lies: the author reusing their own work, one
  enthusiast reusing it ten times, a disclosed sibling vouching.
- **Decision:**
  - `artifact.reuse` -- `reuser`, `used`, `usedIn`; signed by the reuser
  - `artifact.improve` -- `author`, `improves`, `artifact`, `note?`; signed by
    the author
  - `impact.attest` -- `issuer`, `subjectRef`, `observed`; a third party
    reporting use they saw, kept as its own edge kind because who is speaking
    differs from a first-person reuse
  `collect_impact` returns features -- edges, `independent_reusers`,
  `self_reuses`, `same_fleet_reusers`, flags -- and **no number**.
- **Why no score here:** `docs/14` permits a product to compute one only if the
  formula is versioned, the inputs disclosed and an explanation attached. The
  router already does exactly that (`explainable-v1`). A second number computed
  in this module would be a second ranking to reconcile, and the one without an
  explanation would win by being shorter.
- **Three tiers, and the third is the weakest:** same key / same fleet (D-059) /
  independent. "Independent" means *no disclosure ties these two* -- an
  undisclosed fleet is indistinguishable from a stranger, so a high count means
  the evidence looks independent, not that it is. The note says so in every
  response.
- **Distinct keys, not edge count:** ten reuses by one key are one adopter.
  `edges` is kept because the detail is real, but `independent_reusers` is the
  number a reader should quote, and a test pins the gap between them.
- **Signature binding:** a reuse must be signed by the `reuser` and an
  improvement by its `author`. Without it an author could mint their own
  adoption, which is the cheapest possible attack on this whole layer.
- **Flags are heuristics:** `reuse_concentration`, `only_self_reuse`,
  `only_disclosed_siblings`, `no_signed_producer`. Each is reported with its
  reason and none is proof of wrongdoing -- `only_disclosed_siblings` in
  particular fires on the *honest* operator who disclosed, so it must read as an
  observation and never as an accusation (D-059).
- **Migration:** Pre-1.0.

## D-061: a jury outcome is a procedure's output, and a split jury is an answer

- **Date:** 2026-08-27
- **Problem:** `docs/12` wants technical dispute resolution and spends most of
  its length on what that must not become: not legal arbitration, not a claim
  of unbiased random selection, not a rule that turns disclosure into grounds
  for voiding a vote.
- **Decision:**
  - `dispute.open` -- `opener`, `task`, `result`, `reasonCode`, `statement`,
    `selection`, `policy`, `disputedVerification?`; signed by the opener
  - `jury.disclose` -- `case`, `juror`, `conflicts`, `note?`; signed by the juror
  - `jury.vote` -- `case`, `juror`, `finding`, `reasonCode`; signed by the juror
  The verdict is **derived** by `resolve_dispute`, never signed as an event.
- **The policy travels inside `dispute.open`.** Seats, quorum and threshold are
  fixed before any vote exists. Choosing the quorum once the tally is visible is
  the oldest way to arrange an outcome, and no amount of signing fixes it after
  the fact.
- **A threshold must be a strict majority of the seats**, refused at draft time
  by the builder and again at parse time by the reader. A threshold of 2 on 4
  seats lets a 2/2 split satisfy *both* sides, and the alternative -- resolving
  that at tally time -- is a tie-break by somebody's judgement.
- **A split jury is `UNDECIDED`, not a verdict.** Nothing breaks the tie, and in
  particular nothing breaks it by `issuedAt` -- the same refusal the succession
  layer makes (D-034). Abstentions count toward quorum, because the juror did
  turn up, and toward neither side.
- **Conflicts are reported, never used to void a vote.** `docs/12` calls
  disclosure evidence rather than identity truth, so a conflicted juror still
  counts and the resolved case additionally reports
  `outcomeWithoutConflictedJurors`. A reader who cares can see whether the
  outcome needed those votes, instead of trusting this module to have excluded
  the right people silently.
- **Detection is deliberately narrow:** shared disclosed fleet membership, and a
  prior role in the disputed task. Those are the two a bundle can actually show.
  An empty detected list is stated to be no clean bill.
- **The draw is reproducible, not fair.** Declared-pool selection orders the pool
  by `sha256(seed || "
" || did)`. The opener picks the seed and could grind
  it, so every resolved case drawn this way says so -- `docs/12` forbids
  claiming unbiased selection that is not verifiably implemented, and
  "deterministic" reads as "unbiased" to most people unless contradicted.
- **The verdict does not overwrite the task status.** `resolve_task` still reads
  the status off the verifications; the jury outcome sits beside it. Merging
  them would let a jury rewrite work history, and would collapse two facts a
  reader should be able to compare.
- **Two catalog types from `docs/03` were dropped.** `jury.nominate` is gone
  because a separate nomination event lets the opener re-seat the jury after
  seeing the votes; selection lives in `dispute.open` instead, which `docs/03`
  permits ("selection evidence"). `jury.verdict` is gone because `docs/03`
  equally permits "a deterministic result from valid votes", and a signed
  verdict beside the derived one would be a second source of truth. Registering
  a type nothing gives semantics to is worse than rejecting it: an admitted
  event reads as a counted one. `jury.disclose` was added because `docs/12`
  requires conflict disclosure and `docs/03` never named its event.
- **Migration:** Pre-1.0.

## D-062: the exchange awards nothing it cannot justify, and hides nothing quietly

- **Date:** 2026-08-27
- **Problem:** `docs/11` wants a coordination marketplace and hands over two
  constraints that most implementations quietly break: *"protocol must expose
  coordinator dependency honestly"*, and *"protocol preserves signed evidence;
  indexing can moderate visibility"*.
- **Decision:**
  - `task.cancel` -- `task`, `requester`, `reason`; signed by the requester
  - `claim.coordinate` -- `task`, `coordinator`, `claim`; signed by the
    coordinator the requester named inside `task.request`
  - `task.request` gains optional `cancellable` (default true) and
    `coordinator`
  - `TaskStatus.CANCELLED`; `lineageauth.exchange` adds a listing view with
    `DISPUTED` layered over the task's own status
- **Competing claims stay competing.** When more claims are live than the task
  allows, every one is listed and none is awarded. `issuedAt` is self-asserted,
  so ordering by it hands the task to whoever backdates best -- the same reason
  the succession layer refuses timestamp tie-breaks (D-034).
- **A coordinator is named in advance or not at all.** Naming one afterwards
  would let the requester pick whoever awards the claim they wanted. Every
  award says out loud that it rests on that key's say-so and that this protocol
  cannot check whether the coordinator applied any rule at all. A coordinator
  who awards twice awards nothing: choosing between their two awards would be
  the ordering this layer just refused to invent.
- **Cancellation is checked against the bundle, never against timestamps.** A
  `task.cancel` takes effect only while no live claim and no result exist at
  the evaluation time. Checking `issuedAt` instead would let a requester who
  has seen the work publish a backdated cancellation and erase it.
  `cancellable: false` binds the requester permanently, which is worth
  something to whoever is deciding whether to start.
- **`DISPUTED` is a view, not a rewrite.** The listing shows `DISPUTED` while a
  case is open and undecided, and carries the task's own `taskStatus`
  unchanged beside it. `resolve_task` never learns about juries, which is what
  keeps D-061 true: a jury cannot rewrite what the verifications said.
- **Moderation belongs to the reader and is always counted.** Blocklists come
  from the caller, never from an event, and hide rather than delete: the events
  stay in the store and stay verifiable. The response reports every hidden
  listing, because a filter that silently shrank the results is
  indistinguishable from an empty exchange.
- **An unknown status filter is an error, not an empty page.** Returning
  nothing would read as "no such tasks".
- **Still not custody.** `rewardReference` remains an opaque string. Nothing
  escrows, distributes, guarantees or values anything, and the note says so on
  every response.
- **Migration:** Pre-1.0.

## D-063: the A2A extension is data-only, and can never be marked required

- **Date:** 2026-08-27
- **Upstream checked 2026-08-27** against the A2A specification (latest released
  1.0.x; the extension mechanism arrived in 1.0.1, May 2026):
  - extensions are declared at `AgentCard.capabilities.extensions`
  - an `AgentExtension` is `{uri, description, required, params}`
  - clients activate one through the `A2A-Extensions` request header, a
    comma-separated list of URIs, echoed back by the agent
  - `required: true` means the agent should reject a client that did not
    activate the extension, and upstream says data-only extensions should not
    be marked required
- **Problem:** `docs/20` opens with "LineageAuth must not replace/bypass server
  authorization", and an extension mechanism is exactly the place that rule
  gets broken by accident.
- **Decision:** `build_extension` hard-codes `required: false` and takes no
  parameter that could change it. This extension carries provenance and nothing
  else; an agent that rejected clients for failing to activate it would be
  gating access on provenance, which is the first thing `docs/20` forbids.
  A card that arrives marked `required: true` is **reported, not normalised** --
  what the card says is a fact about the card, and the warning explains why it
  is wrong.
- **Every provenance answer carries the five-step order** from `docs/20`
  (A2A authentication, A2A server authorization, this check, human approval,
  execute). A provenance result without it looks exactly like an authorization
  decision, and a caller who mistakes it for one has replaced their own server's
  check with a stranger's card.
- **A card is a stranger's document.** The DID must decode or the whole block is
  refused rather than half-read; evidence references that are not event ids are
  dropped and reported; and the `resolver` URL is carried as data and **never
  fetched** -- `docs/18` and `docs/20` agree that a URL in a document is data,
  never an instruction. Two blocks under one URI is a refusal, because choosing
  between them would be this library picking an identity for the reader.
- **Skill ids come off a published card**, so `a2a_resource_for` runs them
  through the scope grammar and refuses separators, dot segments and wildcards.
  A wildcard is legitimate in a *scope*; in the resource for one concrete
  invocation it would ask a far broader question than the caller intended
  (the same rule as `mcp_resource_for`, D-050).
- **The extension URI is a repository URL, not a domain.** The project runs on a
  ¥0 budget and a domain is a spend decision. The URI points at the document
  that defines the extension and resolves today; if this is ever standardised
  upstream the URI changes, and that is a breaking change on purpose.
- **Migration:** Pre-1.0.

## D-064: the resolver merges by union, and freshness is not completeness

- **Date:** 2026-08-27
- **Problem:** `docs/15` gives this layer one job -- collect and project signed
  events -- and one prohibition: never become protocol authority. Both are easy
  to break, in opposite directions.
- **Decision:** `lineageauth.resolver` reads any number of caller-supplied
  sources, merges them by **union**, reports `checkedAt`, `sources`,
  `newestEventSeen`, `freshnessAge` and `conflicts`, and decides nothing.
- **Union, never selection.** A hostile mirror can add events -- which then have
  to verify on their own signatures, so adding junk achieves nothing -- but it
  can never remove an event another source supplied. Selecting between copies
  would hand that mirror the power to suppress a revocation. This is the same
  reasoning as proof merging inside a bundle (D-036): **omission is the
  attack**, so the merge rule has to be the one that is monotone under adding
  sources.
- **Freshness measures recency, never completeness.** `freshnessAge` is the gap
  between `checkedAt` and the newest event anyone produced. A mirror that
  withholds a revocation makes that gap larger and the view fails closed -- but
  the same mirror forwarding one harmless recent event makes the gap small
  again while the revocation is still missing. Every response therefore says
  that a small age means "something recent arrived", not "nothing is missing".
  That caveat is the difference between a freshness field and a false one.
- **A quiet source is not an agreeing source.** A source that raises is recorded
  as unreachable, distinguishable from a source that answered with nothing, and
  `FreshnessPolicy(require_all_sources=True)` refuses the view: a silent mirror
  is indistinguishable from one that is withholding.
- **Conflicts name the source.** Any admitted event that some *answering*
  source did not supply is reported with `presentIn` and `absentFrom`. Missing
  `delegation.revoke`, `root.succession` or `recovery.policy` is flagged
  `authorityCritical` and sorted first, because omitting one of those leaves
  authority looking live. Nothing is resolved: the only preferences LAP defines
  are the union of proofs and the ordering of epochs.
- **A met policy has no affirmative status.** `status` is `STALE_STATUS` or
  `None`. Freshness being satisfied is the absence of a problem, and giving it a
  positive reason code would invite somebody to read it as a verdict about the
  events themselves.
- **Nothing here fetches a URL.** `docs/15` forbids auto-fetching untrusted URLs
  without policy or human approval, so no HTTP source ships in the core. A
  `Source` is a two-member protocol; an operator who wants a mirror writes one
  under their own policy, outside this module.
- **Migration:** Pre-1.0.

## D-065: the zero-cost claim is executed, not asserted

- **Date:** 2026-08-27
- **Problem:** `docs/31` ends with a "zero-cost definition of done" -- a list of
  things that must work with no paid service. A list like that stops being true
  the moment it stops being run, and nobody notices, because a checklist in a
  document cannot fail.
- **Decision:** `tests/test_zero_cost.py` executes the list. Every item is
  either exercised or named in `NOT_YET_BUILT`, and the unbuilt list is checked
  **against the repository in both directions**: the Explorer test fails if an
  Explorer appears, which forces the list to be corrected rather than letting it
  understate what works.
- **Two invariants underneath it:**
  - *The protocol core imports no networking module.* Enforced by walking the
    package's ASTs, with the Technocore adapter as the single, deliberate
    exemption (it is opt-in and read-only, D-047). Verified with a negative
    control, so the scanner is known to detect what it is looking for rather
    than merely passing.
  - *Nothing on the zero-cost path depends on a paid service.* `docs/31`'s
    detector runs over the declared dependencies, where a marker would mean an
    actual dependency rather than prose about avoiding one.
- **Found by running it:** `la --help` crashed on a Japanese Windows console.
  One em dash in the help text raised `UnicodeEncodeError` under `cp932` and
  took the whole command down. A CLI that cannot print its own help on the
  machine somebody is holding is broken there, whatever it does elsewhere --
  and the zero-cost claim is specifically a claim about running locally, on
  whatever that machine is. Fixed, and pinned by a test that runs the CLI under
  `PYTHONIOENCODING=cp932`, `ascii` and `utf-8`.
- **`RUNBOOK.md`** carries the local zero-yen path. Every command in it was run
  before it was written, including the negative controls: the tampered example
  must fail and the revoked delegation must be denied.
- **Migration:** Pre-1.0.

## D-066: the Explorer displays and verifies nothing, and says so

- **Date:** 2026-08-27
- **Problem:** every value this page shows -- room names, task titles, dispute
  statements, profile text, fleet names -- is written by somebody else. A
  viewer for a provenance protocol is exactly the wrong place to execute a
  string.
- **Decision:** `apps/explorer/` is one HTML file, one stylesheet and one
  script, served by the local API from the same origin.
  - **No string ever becomes markup.** Text reaches the page through
    `textContent` and nothing else. A test reads the source and fails on every
    construct that could turn a string into markup -- which is why none of them
    are spelled out even in a comment, since the first version of that comment
    failed its own test.
  - **Strict CSP with no `unsafe-inline`.** The page carries no inline script
    and no inline style, which is what earns it `script-src 'self'` instead.
    The API's own `default-src 'none'` still applies to every data endpoint;
    the Explorer's looser policy is set per-route and does not leak.
  - **Same origin, so no CORS.** Serving the page from the API means it needs
    no cross-origin permission, and the API needs no header it would then have
    to be careful about.
  - **It verifies nothing** and repeats that on the page. A viewer that looks
    like a verifier gets believed like one.
  - No storage, no `window.open`, no navigation, no key generation in the
    browser (`docs/17` excludes the last until it is separately
    threat-modelled). Each is pinned by a test.
- **Status language:** `docs/17` forbids "trusted human", "official" and
  "guaranteed safe". A test asserts all three appear nowhere in the UI files,
  and it caught two of my own comments before it caught anything else.
- **Visual design** follows the Technocore/Flop material this protocol plugs
  into -- dark gridded ground, cyan accent, monospace slugs, outlined section
  numerals -- with **no logo and no borrowed wordmark**. Looking like it belongs
  in that world is fine; passing for somebody else's product is not, and a page
  about provenance is a poor place to blur that. Dark only: a security surface
  that changes colour with the operating system also changes which warnings
  look urgent.
- **The zero-cost ratchet fired.** `tests/test_zero_cost.py` named the Explorer
  as not built and asserted the *absence* of one. Building it broke that test
  and forced the checklist to be corrected, which is the behaviour D-065 was
  designed for: a list that can only be corrected by hand goes stale, and this
  one fails instead.
- **Migration:** Pre-1.0.

## D-067: the release checklist is a test, and three boxes stay unticked

- **Date:** 2026-08-27
- **Problem:** `TASKS.md` ends with a release checklist. Every line is a claim
  about the repository, and a claim nobody re-checks stops being true quietly.
- **Decision:** `tests/test_final_gate.py` executes the checklist, and a box is
  ticked only where a test establishes it. Three stay unticked on purpose:
  - *free tiers re-verified before deployment* -- nothing is deployed, so
    ticking it would be ticking it on a technicality
  - *all protocol tests pass* -- a suite cannot assert its own totality without
    lying about it; CI establishes this on every push
  - *the account is personal* is ticked, but the test says what it actually
    checks: the remote URL. Whether that GitHub account is personal is a fact
    about GitHub, not about this checkout
- **The contamination scan runs on every test run**, not on request, because a
  scan somebody has to remember is not a control.
- **Its first version was wrong in both directions and both were caught:**
  - It fired on `TASKS.md` documenting the isolation rule. A scan that punishes
    writing the rule down teaches people to stop writing it down, so the
    company's *identity* (which may appear nowhere) is now separated from a
    *path into the company tree* (which is the actual contamination).
  - The path pattern matched only forward slashes, so it was blind to every
    Windows path -- the shape contamination would actually arrive in. **It
    passed the suite anyway.** A negative control caught it, and that control is
    now a test: a scanner that never fires is indistinguishable from a clean
    repository, and the only way to tell them apart is to feed it something it
    must catch.
- **Migration:** Pre-1.0.

## D-068: the schemas describe shape, and say so in their own description

- **Date:** 2026-08-27
- **Problem:** a JSON Schema is exactly the sort of artifact somebody wires into
  a pipeline and then treats as approval. Shape is the least interesting
  property of a signed event.
- **Decision:** `scripts/generate_schemas.py` emits `schemas/envelope.schema.json`,
  `schemas/catalog.schema.json` and one schema per registered event type, from
  `catalog.py` and the envelope model rather than by hand. Deterministic, so a
  diff there is a protocol change and never a formatting one.
- **Every schema carries the disclaimer in its `description`:** a document may
  validate and still carry an invalid signature, a signer with no authority, an
  event id that does not match its payload, or a broken chain above it. A test
  asserts the sentence is present in every file, and another proves it true --
  a tampered grant validates against the envelope schema and the verifier
  rejects it.
- **The event schemas are open** (`additionalProperties: true`). `docs/24`
  wants a verifier to reject an unknown *type* while still displaying unknown
  *fields*; a closed schema would turn a forward-compatible event into a
  validation failure.
- **Type-specific fields are deliberately unconstrained.** The rules that
  matter cannot be written in a schema -- that a receipt is signed by the worker
  it names, that a jury threshold is a strict majority of the seats -- so they
  stay in the readers that can express them, rather than being half-expressed
  in two places that could disagree.
- **The `did:key` pattern checks the alphabet, not the key type**, and says so.
  A test pins it with an X25519 `did:key` that matches the regex and that
  `public_key_from_did_key` refuses.
- **Validated with `jsonschema`, a test-only dependency.** Hand-rolling a
  validator would repeat the mistake JCS is delegated to a library to avoid: a
  checker that disagrees with the specification is worse than none, because it
  looks like one.
- **Migration:** Pre-1.0.

## D-069: the conformance package publishes the rules, not just the verdicts

- **Date:** 2026-08-27
- **Problem:** `CONTRIBUTING.md` asks for an independent implementation that
  *disagrees* with this one. A disagreement is only useful if both sides
  answered the same question, and a vector that says only "expect: invalid"
  fixes the answer without fixing the question.
- **Decision:** `conformance/` carries a manifest where every vector states the
  verdict **and the rule behind it**, so a failure names the rule that broke
  rather than reporting a mismatch. Generated by
  `scripts/generate_conformance.py`, deterministic, and a test proves this
  implementation actually reaches every verdict the package claims -- otherwise
  the vectors would describe what somebody hoped the code did.
- **The negative vectors are the package.** Anyone can accept a valid event.
  Most of these were bugs here before they were vectors: a padded signature
  (two encodings of one signature), an unregistered type (an admitted event
  reads as a counted one), an X25519 `did:key` (syntactically a `did:key`, not
  a signing key).
- **A raised error counts as a refusal.** An implementation that rejects at the
  DID layer before reaching a proof has refused, which is correct. What must not
  happen is a refusal-shaped document coming back admitted.
- **One vector carries three different verdicts on one bundle**, and confusing
  them is the mistake it exists to catch: the envelopes *verify*, the
  registration is *admitted* with its `createdBy` reported as an unsigned claim
  (D-051), and the receipt's authorship claim *does not stand at all* (D-052).
  Failing the envelope is wrong; crediting the worker is wrong. The first
  version of this vector's own rule text described behaviour the code does not
  have, and writing the test is what caught it.
- **`MIGRATION.md` is checked the same way.** Tests assert the preimage it
  quotes is the real one, that the refusals it promises actually happen, and
  that it does not promise stability. A migration document describing behaviour
  the code lacks is worse than none: it is read once, by somebody who then
  relies on it.
- **Migration:** Pre-1.0.

## D-070: operations are questions you can answer offline

- **Date:** 2026-08-27
- **Problem:** `docs/25` asks for observability, a backup drill and a dependency
  audit. `docs/31` caps all three at zero yen. That constraint turned out to be
  the useful one: it rules out the versions of these that are a subscription and
  leaves the versions that are a question answerable offline.
- **Observability is `la doctor`,** and it asks one question: *does the index
  still agree with the store?* Non-zero exit so a scheduled job can gate on it,
  `--json` for machines, no agent, no endpoint, nothing that could cost money or
  become a second place events live. The asymmetry is the interesting part --
  an event in the store and not the index is a stale index, while an event in
  the **index and not the store** means something wrote to the index that did
  not come from a signed event, and those get different messages.
- **The drill deletes the index for real.** A backup nobody has restored is a
  hope. The failure mode worth catching is an index that only looks
  reconstructible while the old file is still there, so the file is unlinked
  and the rebuild reads the store alone. The copy kept for diagnosis is never
  read back -- that would be the drill grading its own work. A changed checksum
  means the index was holding state that never came from a signed event, which
  is a bug in the index rather than a problem with the drill.
- **The dependency audit is offline, and says what it cannot see.** Five runtime
  packages, each with a stated reason a test enforces, so a dependency cannot
  arrive without somebody writing down why. Two of them exist specifically so
  nothing is hand-rolled: `rfc8785` and `cryptography`. **Known vulnerabilities
  are out of scope** and the RUNBOOK says so -- that needs a vulnerability
  database, which is a network service, and calling something an audit while it
  quietly checks nothing about CVEs is worse than having no audit.
- **Fuzzing asserts one property:** every parser returns, or raises a
  `LineageAuthError`. A verifier reads bytes an attacker chose, and a leaked
  `KeyError` in the safe path is a denial of service on the decision that was
  about to be made. `RecursionError` on deeply nested JSON is allowed through
  deliberately: that is the interpreter's stack limit, and catching it would
  hide the depth limit instead of documenting it.
- **Migration:** Pre-1.0.

## D-071: the stop sign goes where being wrong cannot be undone

- **Date:** 2026-08-27
- **Problem:** `CLAUDE.md` 2.8 keeps this project off every company resource.
  Everything before a push is local and recoverable. A push is not: a public
  repository that briefly held company material has published it, and deleting
  the commit afterwards does not unpublish it.
- **Decision:** `scripts/pre_push_check.py`, wired as a `pre-push` hook. It
  checks the remote is the personal account, the committer address is not a
  company address, and the tree carries no company identity, no path into the
  company tree, and no key material.
- **Tracked in `.githooks/` and enabled with a repo-local `core.hooksPath`.**
  Both halves matter: a hook living only in `.git/hooks` is invisible in review
  and gone on a fresh clone, and a global setting would reach every other
  repository on this machine when the rule belongs to this project alone.
- **`git push --no-verify` bypasses it, and the script says so.** A check that
  cannot be bypassed gets deleted the first time it is wrong; one that says out
  loud how to bypass it gets read instead.
- **Proved by making it fail.** A probe file containing a company path was
  staged, the check refused, and the probe was removed -- the same lesson as
  D-067: a scanner that never fires is indistinguishable from a clean tree.
- **`git` is resolved with `shutil.which` rather than left to PATH.** This runs
  as a hook in whatever environment the push had, and a check redirectable by a
  PATH entry is not much of a check. The linter flagged it and the linter was
  right.
- **Scale targets are designed, not provisioned** (`infra/scale-design.md`).
  `docs/31` says growth is a success signal and forbids prepaying for
  hypothetical scale, so the document is the shape of the answer for when there
  are real numbers. Two things in it are load-bearing: a scaled index **stays
  derived** or the restore drill stops meaning anything, and **`JSONB` reorders
  keys**, so it must never be the source for a signature check.
- **`RELEASE.md` says v1 is not close.** The item that cannot be done from
  inside this repository is first on the list: an independent implementation
  that has actually run the conformance vectors. Until then, "the specification
  is implementable" is an opinion held by whoever wrote both sides.
- **Migration:** Pre-1.0.

### Pending decision template

- ID:
- Date:
- Problem:
- Options:
- Security impact:
- Interop impact:
- Decision:
- Migration:
