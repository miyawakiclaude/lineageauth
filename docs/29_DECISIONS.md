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

### Pending decision template

- ID:
- Date:
- Problem:
- Options:
- Security impact:
- Interop impact:
- Decision:
- Migration:
