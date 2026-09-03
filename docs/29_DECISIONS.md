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
    `threshold`, `previousPolicy?` (required when `policySeq > 1`)
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
    `expiresAt`, `maxDepth`, `approval`, and `parent?` (absent on a grant issued
    directly by the root).
  - `delegation.revoke` — `issuer`, `grant`, `reason?`.
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
- **Migration:** **frozen, 2026-08-28.** The required keys of the evidence family are recorded in `conformance/frozen-shapes.json` and checked by `tests/test_frozen_shapes.py`; they will not be added to, removed or renamed without a new decision entry. Adding an optional key remains compatible and is not constrained.

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
- **Migration:** **frozen, 2026-08-28.** The required keys of the passport family are recorded in `conformance/frozen-shapes.json` and checked by `tests/test_frozen_shapes.py`; they will not be added to, removed or renamed without a new decision entry. Adding an optional key remains compatible and is not constrained.

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
- **Migration:** **frozen, 2026-08-28.** The required keys of the work family are recorded in `conformance/frozen-shapes.json` and checked by `tests/test_frozen_shapes.py`; they will not be added to, removed or renamed without a new decision entry. Adding an optional key remains compatible and is not constrained.

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
- **Migration:** **frozen, 2026-08-28.** The required keys of the fleet family are recorded in `conformance/frozen-shapes.json` and checked by `tests/test_frozen_shapes.py`; they will not be added to, removed or renamed without a new decision entry. Adding an optional key remains compatible and is not constrained.

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
- **Migration:** **frozen, 2026-08-28.** The required keys of the impact family are recorded in `conformance/frozen-shapes.json` and checked by `tests/test_frozen_shapes.py`; they will not be added to, removed or renamed without a new decision entry. Adding an optional key remains compatible and is not constrained.

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
- **Migration:** **frozen, 2026-08-28.** The required keys of the jury family are recorded in `conformance/frozen-shapes.json` and checked by `tests/test_frozen_shapes.py`; they will not be added to, removed or renamed without a new decision entry. Adding an optional key remains compatible and is not constrained.

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
- **Migration:** **frozen, 2026-08-28.** The required keys of the work family are recorded in `conformance/frozen-shapes.json` and checked by `tests/test_frozen_shapes.py`; they will not be added to, removed or renamed without a new decision entry. Adding an optional key remains compatible and is not constrained.

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
- **Migration:** **frozen, 2026-08-28.** `Resolution` reports `checkedAt`, `sources`, `newestEventSeen`, `conflicts` and `freshness`; those names are the contract now. Adding a field remains compatible.

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
- **Migration:** none. This is a test over this repository's own claims.

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
- **Migration:** none. The Explorer is an application over the API, not a format.

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
- **Migration:** none. The checklist is a test; nothing consumes it.

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
- **Migration:** **frozen, 2026-08-28.** The published schemas describe the envelope, and the envelope is the part that cannot move without breaking every event id. `scripts/generate_schemas.py` is deterministic and a diff in `schemas/` is a protocol change.

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
- **Migration:** **frozen, 2026-08-28.** The manifest's shape -- `name`, `file`, `expect`, `rule`, optional `authority` -- is what an outside implementation reads, and `tests/test_conformance.py` fails if a vector loses its rule.

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
- **Migration:** none. `la doctor` reports on a local store and has no consumers.

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
- **Migration:** none. A pre-push hook runs before this repository's own pushes.

## D-072: a scan that cannot see a new file has a blind spot where it matters most

- **Date:** 2026-08-27
- **Found by:** CI, on the commit that added the pre-push check.
- **What happened:** the contamination scan used `git ls-files`, which lists
  only what is committed or staged. `scripts/pre_push_check.py` names the
  company by necessity -- it is the scanner -- and when the local gate ran, the
  file was **not tracked yet**, so the scan could not see it. The gate said
  PASS. The commit landed. CI, working from a checkout where the file *was*
  tracked, failed immediately.
- **Two separate mistakes, and the second is the interesting one:**
  1. the scanner was not in the exemption list, alongside the test that has the
     same problem for the same reason. Fixed by adding it.
  2. **the scan had a blind spot exactly where contamination is easiest to
     catch** -- the moment after somebody creates a file and before they think
     about it. Both scans now use
     `ls-files --cached --others --exclude-standard`, and a control test proves
     a brand-new unstaged file is seen.
- **A related false positive, found the same way:** the pre-push check treated
  an unset `user.email` as a violation. It is not one -- an unset address is not
  a company address, and git will not commit without one anyway. It fired in CI,
  where nobody is committing. A check that cries wolf is a check somebody
  bypasses and then deletes.
- **Why the local gate could not have caught this:** the gate runs the same four
  commands CI runs, but not against the same file set, because untracked files
  are invisible to a `ls-files` scan and CI always works from a full checkout.
  Widening the scan closes that gap for this check specifically; the general
  lesson is that a check reading `git ls-files` is reading a different
  repository before and after `git add`.
- **Migration:** none. The scan reads this working tree.

## D-073: CI failures must be readable by whoever can fix them

- **Date:** 2026-08-27
- **Problem:** a test failed on CI and passed locally, and the log endpoint
  returns 403 without admin rights. Two rounds were spent guessing at
  platform differences that did not exist -- the failure had nothing to do with
  the platform, and the guessing happened only because the evidence was
  unreadable.
- **Decision:** the `Tests` step re-emits pytest failures as workflow
  `::error::` annotations, which appear on the job page **without signing in**.
  A failure that exists only in a log nobody can open is a failure the person
  most likely to fix it cannot read.
- **What the failure actually was:** D-072 was inserted *before* D-071, and
  `test_every_decision_id_is_unique_and_sequential` requires the log to be
  ordered. Trivial, and it cost two CI rounds purely because it was invisible.
- **The process failure underneath it:** that commit went out **without running
  the gate**. `scripts/gate.py` exists precisely so this cannot happen, and
  skipping it once was enough. Running the gate is not optional even for a
  documentation-only change, because "documentation-only" is a judgement about
  a diff and the tests are what check that judgement.
- **Migration:** none. CI annotations are read by people, not by code.

## D-074: an unparseable workflow looks exactly like a failing test

- **Date:** 2026-08-27
- **What happened:** the edit that added D-073's annotations broke the workflow
  YAML -- an escaped newline became a real one and split a `printf` across two
  lines, collapsing the block scalar. GitHub does not report that as a syntax
  error. It **renames the workflow to its own file path**, reports zero jobs,
  and marks the run failed. From the API that is indistinguishable from a test
  failure, and a round was spent looking for a failing test in a workflow that
  had never started.
- **Decision:** tests parse every workflow file, require a `name` (its absence
  is the tell that parsing failed), require every step to have a non-empty
  `run` or a `uses`, and assert the gate and CI run the same four checks -- if
  those drift, the gate stops predicting CI and stops being worth running.
  `pyyaml` joins the test-only dependencies for this.
- **`echo` rather than `printf`.** The bug was an escaping problem in a
  generator writing a shell line into YAML. `echo` needs no escape, and a
  construct that cannot be got wrong is better than one that was got wrong once.
- **The pattern across D-072, D-073 and this one:** each was invisible where it
  happened. A scan that could not see untracked files, a failure readable only
  with admin rights, a workflow that reports its own breakage as somebody
  else's. None was hard to fix; all three cost time purely because the evidence
  was somewhere nobody was looking.
- **Migration:** none. The workflow files are this repository's own.

## D-075: measured, and the answer changed -- no verify endpoint on a Worker

- **Date:** 2026-08-27
- **Why now:** a Cloudflare account was registered. Registering costs nothing and
  commits nothing, but it made the open caveat in `infra/scale-design.md`
  actionable, and a caveat that stays a caveat eventually gets treated as a
  detail.
- **Measured** (`scripts/benchmark.py`, native CPython, against the 10 ms CPU a
  free-plan Worker gets per request):

  | operation | cost | of budget |
  |---|---:|---:|
  | verify one event | 0.6 ms | 6% |
  | admit 11 events | 5.0 ms | 50% |
  | admit 51 events | 25.6 ms | **256%** |
  | one request (admit 51, then check) | 43.7 ms | **437%** |

- **Decision: no public verify endpoint on a free Worker.** Two independent
  grounds, either sufficient:
  1. **CPU.** Admission dominates and is linear in events, and *the caller
     chooses how many to send*. An endpoint admitting a caller-supplied bundle
     pays whatever it is asked to pay. That is a denial-of-service shape before
     it is a cost problem, and a paid plan does not fix it -- it converts
     failing into spending.
  2. **Runtime.** Python Workers run under Pyodide, which is WebAssembly, and
     `cryptography` is a native package that cannot be imported there. The
     verifier will not run at all, whatever the budget says.
- **What this does not rule out:** static hosting. A passport and an event
  bundle are static JSON, there is no CPU budget to exceed and no bundle a
  stranger can inflate. That was already the recommendation and the measurement
  strengthens it rather than changing it.
- **If a dynamic endpoint is ever genuinely needed,** the order is: cache
  verification by event id (an id is a hash of the signed payload, so a verified
  id stays verified and the key cannot be forged without forging the hash), cap
  the accepted bundle size, then look at cost. Not the other way round.
- **A JS or WASM verifier would be valuable for a different reason.** It is what
  `CONTRIBUTING.md` asks for and what `RELEASE.md` puts first for v1: an
  independent implementation that can disagree with this one. That is a project,
  not a deployment, and conflating the two is how it would get built badly.
- **Migration:** none. A deployment that was decided against has nothing to migrate.

## D-076: publishing a snapshot, and the bug only a static host can show

- **Date:** 2026-08-27
- **Approved by the project owner**, who chose GitHub Pages over Cloudflare.
  That matches D-075: the measured verdict ruled out a Worker verify endpoint,
  and static hosting was already the answer. Pages is free on a public
  repository and adds no service, no account and no billing surface.
- **What is published:** the Explorer as a static snapshot, plus the conformance
  vectors and the JSON Schemas -- so an independent implementation can fetch
  what it needs without cloning anything, which is the point of publishing them
  at all.
- **Three things the page says before it says anything else,** in order of how
  much damage getting them wrong would do:
  1. **the keys are public and reproducible.** The demo is signed with the
     project's test keys. No DID on the site belongs to anybody, and the
     *builder refuses to produce a page missing that sentence* -- a guard in the
     build, not only in review.
  2. **it verifies nothing.** It renders precomputed answers; `la verify` is
     where checking happens.
  3. **it is a snapshot,** stamped with its build time. A page serving stale
     answers as if they were current is doing precisely what this protocol's
     freshness rules exist to stop.
- **The gate runs before the deploy.** A site that went up while the tests were
  red would be publishing claims the repository does not stand behind.
- **The bug a live deployment could never have shown.** A server decodes the
  request path before routing, so `lineage%3Ala%3A...` and `lineage:la:...` are
  the same request. A static lookup matches the key **literally**, so they are
  not. The client encodes with `encodeURIComponent`; the first builder wrote raw
  keys; every screen past the first failed with "not precomputed". Fixed by
  encoding both sides the same way, and pinned by a test that derives the keys
  the way the client derives them and asserts the build produced them.
- **Relative paths throughout.** A project page lives under `/<repo>/`, and a
  leading slash reaches for the domain root instead. The Explorer test that used
  to require paths to *start* with `/` was asserting the wrong property; what
  matters is that no reference names another host.
- **Verified by serving it under a prefix and driving every screen** before
  anything was pushed, because that is the only configuration where these
  particular mistakes are visible.
- **Migration:** none. The published site is generated; regenerate it.

## D-077: a 404 from an endpoint that needs auth is not evidence of absence

- **Date:** 2026-08-27
- **What happened:** while diagnosing the failed Pages deploy I checked
  `GET /repos/{owner}/{repo}/pages` unauthenticated, got 404, and reported that
  Pages was not enabled. The conclusion was right; **the evidence was not**. The
  conclusive evidence was the workflow's own error, `Create Pages site failed:
  Resource not accessible by integration`.
- **Verified afterwards:** `pages-themes/cayman` serves a live Pages site and
  its `/pages` API returns 404 to an unauthenticated caller. The endpoint
  requires authentication and 404s either way, so **that check can never
  distinguish enabled from disabled**.
- **Why it matters beyond the incident:** the same 404 was then useless for
  confirming that enabling Pages had worked. A check that returns the same
  answer in both states is not a check, and reading it as one produces
  confident wrong statements -- which is worse than having no check, because a
  missing check gets replaced.
- **The rule:** before treating an absence as evidence, confirm the observation
  can distinguish the two cases. The cheap way is a positive control -- find
  something known to be in the state you are testing for and check that the
  probe reports it. That is the same discipline as D-067's contamination-scan
  control and D-072's untracked-file control, arriving for the third time from
  a different direction.
- **Pattern, now four deep** (D-072 through D-077): every recent mistake has
  been about *where the evidence is*, not about the code. A scan blind to new
  files, a log needing admin rights, a workflow reporting its own breakage as
  somebody else's, and now a probe that cannot tell the two answers apart.
- **Migration:** none. This records how to read an API response, not a format.

## D-078: the site went up before its free tier was in the register

- **Date:** 2026-08-27
- **What happened:** GitHub Pages was deployed and *then* its free tier was
  checked and written into `infra/cost-policy.yaml`. The rule in `docs/31` and
  in the register's own header is that a service is verified **before** it is
  used. The order was wrong by about twenty minutes.
- **Recorded rather than quietly fixed,** because the register exists to make
  spending decisions deliberate, and back-dating a check into it would make the
  register lie about when somebody looked.
- **Verified 2026-08-27:** free on public repositories, 1 GB published site,
  100 GB/month bandwidth (soft), 10 builds/hour (soft). Making this repository
  private would end that -- visibility is a budget decision for Pages as well as
  for Actions.
- **Nothing depends on the site being reachable.** Everything it serves is in
  the repository, `scripts/build_site.py` reproduces it, and `docs/31` already
  says a public URL is not required to prove correctness. So the shutdown
  behaviour is "turn the source off", with no fallback to design.

## D-079: a latest release number is not a tag that exists

- **Date:** 2026-08-27
- **What happened:** bumping the workflow actions, I read
  `astral-sh/setup-uv`'s latest *release* -- `v10.0.1` -- and pinned `@v10`.
  That tag does not exist: the moving major tags stop at `v7`. Every workflow
  would have failed at its first step.
- **Two probes failed to catch it, in the same way.** A `runs=` field came back
  empty and was read as "no inputs used" rather than "the fetch returned
  nothing", and a regex over the fetched file found no inputs, which looked like
  an answer instead of a parse failure. Both were 404 responses being read as
  data -- the same mistake as D-077, twice more, within an hour.
- **What made it visible:** asking `git/ref/tags/{tag}` directly, which
  distinguishes "exists" from "does not". That is a probe with two possible
  answers, which is the property D-077 says to check for first.
- **Decision:** `tests/test_final_gate.py` pins the set of action refs the
  workflows may use, with the date they were verified. Bumping one is then a
  deliberate act, and a typo'd or invented tag fails locally instead of on the
  first push. The test needs no network -- it compares the workflows against a
  list a person checked.
- **Also required:** every `uses` is pinned and none follows `@main`. Somebody
  else's default branch is not a version.
- **Migration:** none. A pinned action reference is CI configuration.

## D-080: a second implementation, written to disagree

- **Date:** 2026-08-27
- **Why:** `CONTRIBUTING.md` asks for an independent implementation and
  `RELEASE.md` puts it first for v1. Until a second verifier has run the
  vectors, "the specification is implementable" is an opinion held by whoever
  wrote the only one.
- **Decision:** `packages/js/lineageauth.js` -- dependency-free, no build step,
  runs unchanged in Node and in a browser.
- **Independence is the whole value, so the awkward parts are re-derived rather
  than ported:** RFC 8785 canonicalization, base58btc, the multicodec check, the
  signing preimage and the event id. The Python side delegates JCS to a library
  precisely so it cannot be got subtly wrong; this side writes it out precisely
  so a subtle mistake in **either** becomes visible. **Two implementations
  calling the same library agree by construction and prove nothing.**
- **SHA-256 and Ed25519 come from WebCrypto.** Those are primitives with
  published test vectors and nothing to disagree about, and hand-rolling a curve
  would add risk without adding evidence.
- **The differential test compares canonical output, not verdicts.** Vectors
  compare verify/refuse, which is coarse: two implementations can both say
  "verify" while disagreeing about the bytes they verified, and that surfaces
  much later as an event id nobody can resolve. Hypothesis generates payloads
  and both sides must produce identical JCS and identical event ids.
- **The discriminating test case took two attempts.** "z" against U+1F600 proves
  nothing -- 0x7A is below both 0xD83D and 0x1F600, so code-unit and code-point
  ordering agree and a wrong implementation passes. The pair that separates them
  is U+FFFD against U+1F600. The first version of that test used the useless
  pair *and* asserted the wrong direction.
- **A bug in the harness, found by the property test itself:** results crossed
  the process boundary as JSON lines split with Python's `splitlines()`, which
  also breaks on U+0085, U+2028 and U+2029 -- and `JSON.stringify` emits those
  raw because they are above U+001F. A payload with U+0085 in a key arrived cut
  in half. Fixed to `split("
")`.
- **The published Explorer now verifies.** It imports this implementation and
  checks every signature and every event id in the snapshot, in the reader's
  browser. The banner changed from "verifies no signature" to what it now does
  -- a claim that got *stronger*, so the guard had to move with it, because a
  banner understating the page is a different failure from one overstating it
  and just as wrong.
- **What it still does not establish,** and the page says so: a signature
  covering a payload is not the signer holding authority.
- **Half the v1 item, and the smaller half.** Both implementations were written
  by the same author in the same week, so they can share a misreading of the
  document without either being wrong about the other. `RELEASE.md` now says
  that rather than claiming the line is closed.
- **Migration:** none. A second implementation of an unchanged format.

## D-081: a key the tool creates and never holds

- **Date:** 2026-08-27
- **Problem:** every DID this project has published so far comes from the public
  test-key domain string, so none of them belong to anybody. The tool existed;
  the identity did not.
- **Decision:** `la key create` generates an Ed25519 key locally and writes it
  **encrypted at rest** -- scrypt over a passphrase, ChaCha20-Poly1305 over the
  seed, the DID bound in as associated data. `la sign` decrypts, signs, and
  drops it inside one call.
- **The constraints this is shaped by, and each one has a test:**
  - the seed is never printed, logged, returned or put in an argument
  - the **passphrase is never an argument either** -- a command line is visible
    in the process table and lands in shell history, so it comes from a prompt
  - `LocalSigner` still has no way to hand back a seed. The seed is generated
    inside `keyfile.create` rather than pulled out of a signer, because adding
    an accessor for one caller's convenience would put a seed-shaped hole in a
    class everything else shares
  - **one error message for a wrong passphrase and a tampered file.** Telling
    them apart tells an attacker which one they are making progress on
  - `create` refuses to overwrite: a key file replaceable by a typo will be, and
    the identity does not come back
- **scrypt at N=2^17**, deliberately slow. It is the only thing between a stolen
  file and an identity that cannot be revoked, and a fast KDF there is not a KDF.
- **`did:key` has no revocation**, so the tooling says so at creation and the key
  file says so in its own note. The mitigation is a `recovery.policy` published
  *while the key still works* -- `docs/05` only ever helps somebody who acted in
  advance.
- **Not custody.** The spec forbids the core holding keys; this writes a file the
  operator owns, reads it for one operation, and keeps nothing. The API cannot
  reach it and the verifier does not want it -- verification is a public-key
  operation.
- **`docs/INTRODUCTION_DRAFT.md` is a draft, not an action.** The Technocore
  adapter has no send path, by design and with a test. Publishing is the
  operator's decision.
- **Migration:** none for the protocol. The key file format is `lineageauth-keyfile-v1` and is local to an operator; `ALLOWED_KDF` (D-099) is what governs changing it.

## D-082: a shortcut into the specification, wired to fail when it drifts

- **Date:** 2026-08-27
- **Problem:** the first item on `RELEASE.md`'s v1 list is an implementation by
  somebody who is not this project, and the only thing this project can do about
  it is lower the cost of trying. That cost was 4,059 lines of specification. A
  stranger deciding whether to spend an afternoon does not read 4,059 lines
  first, so the ask was being made in a place nobody reached.
- **Decision:** `docs/IMPLEMENTERS_GUIDE.md` -- the verification rules on one
  page: the JCS behaviour that actually bites, the byte-exact preimage, the
  `did:key` decoding including the X25519 codec that looks correct, the refusal
  list, and how to run the published vectors. Linked from `README.md`,
  `CONTRIBUTING.md`, `conformance/README.md`, and the footer of the published
  page, because a door nobody walks past is not a door.
- **The cost of doing this, which is the part worth recording:** a summary of a
  normative document becomes a second normative document. A guide that drifts
  from the code is *worse than no guide*: it reads as authoritative while
  teaching an implementation that fails the vectors, and the person it misleads
  concludes the protocol is broken rather than the prose. Prose has no compiler,
  so nothing would catch it.
- **So the guide is tested against the thing it describes**
  (`tests/test_implementers_guide.py`): every constant is compared to the
  constant in the code, the UTF-16 ordering example is *executed* rather than
  asserted from memory, every claim about the vectors is read out of
  `manifest.json`, every relative link is resolved, and every published URL must
  exist in the repository. Changing the protocol without changing the page fails
  CI. Verified by breaking four of them and watching four tests fail.
- **The guide tells the reader not to read the implementations first.** An
  implementation written from another implementation inherits its misreadings,
  which is precisely the limitation `D-080` records about `packages/js/`. What
  is wanted is the reading that finds the specification unclear.
- **This does not make the v1 line true**, and `RELEASE.md` now says which part
  it does address. Removing the reasons a stranger stops before starting is the
  whole of what one project can do about being independently implemented.
- **Migration:** none. A document, tested against the code it summarises.

## D-083: a text colour is a token, and a token has to be legible

- **Date:** 2026-08-27
- **Problem:** `D-082` put the project's one request to strangers in the footer,
  and measuring it found the footer set at **2.45:1** against the page. Text at
  that ratio is readable only by someone who already knows what it says. The
  colour survived because it was a **literal in a rule rather than a token**, so
  nothing ever compared it to anything.
- **Decision:** two rules, both tested (`tests/test_explorer.py`):
  - a `color:` declaration must name a palette token, never a literal
  - every token used as text clears **WCAG AA (4.5:1)** against the lightest
    surface it can land on, so passing there passes everywhere
- **What that immediately caught:** `input::placeholder` at **2.16:1** -- the
  only instruction the event-id field gives, set as decoration -- and `--dim` at
  4.35:1, used for hints and section labels across eight screens. `--dim` moved
  to `#788393` (5.2:1 on the page, 4.8:1 on the lightest panel).
- **One exemption, and it is bounded:** `dd::before` is a decorative em dash
  standing in for a list marker. A test asserts the exemption still points at a
  rule whose `content` is at most a few characters, because an exemption list is
  where failures go to hide.
- **The measurement error worth recording.** A first pass in the browser
  reported seven failures in the notice block, including text at 1.00:1. All
  seven were wrong: the notice background is `rgba(217, 164, 65, 0.04)`, and the
  checker read the nearest non-transparent layer as if it were opaque -- turning
  a 4% tint into solid amber. **A contrast checker has to composite the stack
  the way the browser paints it.** Corrected, the rendered page reports zero
  failures across 278 text elements on all eight screens. Had the first number
  been believed, the fix would have been to change colours that were already
  correct.
- **Migration:** none. Presentation, in one page this project publishes.

## D-084: the prose has to keep up with the code, and a test says so

- **Date:** 2026-08-27
- **Problem:** `README.md` called the Explorer a snapshot that "verifies
  nothing". That was true when written and stopped being true at `D-080`.
  Fifteen lines below, the same file's checklist said the page verifies the
  signatures it shows using the second implementation. **A reader meets both
  claims on one screen and has to guess which one this project believes.** For
  a project whose entire pitch is "check it yourself in a minute", losing that
  reader at the contradiction costs more than the feature earned.
- **The third copy is the one that matters.** The page's own notice block was
  correct and precise -- demo keys, no live API, verified in your browser, three
  separate facts. But the offline branch, shown only when no API answers, said
  the Explorer "does not verify anything itself". Wrong, and hidden: nobody
  reviewing the page in its normal state ever sees that paragraph.
- **Second problem, same cause:** the status line read `pre-alpha` and
  "Phase 1 (lineage) is in progress" directly above a checklist of fifteen
  shipped layers. Understating is not the safe direction it looks like -- it
  reads as inattention, and it buries the fact that the remaining work is not
  code at all.
- **Decision:** the Explorer is described as *not an authority or a source of
  truth*, which is the real caveat, **and** as independently verifying in the
  browser the signatures it displays, which is the real capability. The status
  says the reference implementation is feature-complete for the pre-1.0 draft
  and that v1 is deliberately blocked on an outside implementation. The warning
  that matters -- do not put real authority behind it -- stays in both places.
- **Tested, and not as a banned phrase.** `TestTheClaimsMatchTheCapability`
  first asserts the capability from the source (the page imports the second
  implementation and calls it), and only then requires that no user-facing text
  deny it. If in-browser verification is ever removed, the honest sentence
  becomes legal again and it is the capability assertion that fails. A banned
  word list would have gone on failing for the wrong reason forever.
- **Migration:** none. Prose, with a test that keeps it true.

## D-085: a runbook is a thing somebody has executed

- **Date:** 2026-08-27
- **Problem:** `RELEASE.md` listed "recovery has been rehearsed, not only
  tested" as a v1 blocker, and it was right to. `tests/test_lineage.py` covers
  succession, quorums and `CONFLICTED` with payloads built in memory. **None of
  that can catch a procedure that cannot be followed** -- where the code is
  correct and the person holding three recovery files still cannot get back,
  because a required step was never written down.
- **Decision:** `scripts/recovery_drill.py` runs the disaster on files: real
  encrypted keys, the root **deleted**, and everything afterwards read out of
  the published bundle rather than out of the variables that produced it.
  `docs/RECOVERY.md` is the procedure, written from what the drill had to do.
  `tests/test_recovery_drill.py` runs it every suite and checks the runbook
  still describes what the drill still does.
- **It passed. That was the least useful thing about it.** Five findings no
  test would have produced:
  1. **`docs/05` is a specification, not a procedure** -- fields and rules, no
     steps, nothing about the day it is needed.
  2. **`recoveryPolicyRef` is mandatory and undocumented.** It is the policy
     event's id. Nothing said so and nothing prints it, so a survivor holding
     the right files still stalls.
  3. **No CLI issues anything.** `la` verifies and inspects. Opening a lineage
     or signing a succession is Python, and a runbook that implies otherwise
     strands its reader at the worst moment. Said plainly instead.
  4. **`getpass` on Windows opens the console rather than reading stdin**, so a
     piped passphrase *hangs* rather than failing. Every operator script in this
     repository had grown a stdin fallback for that reason; the shipped CLI had
     not. That made the one procedure nobody can afford to get wrong also the
     one procedure nobody could rehearse unattended. Fixed, with the argument
     form still refused -- piping is the operator choosing to, an argument is
     visible to everyone whether they chose it or not.
  5. **Five facts a survivor cannot reconstruct** afterwards. Four are readable
     out of the published bundle, which is now named as the artifact to back up.
- **The drill has a negative control**, because a drill that cannot fail proves
  nothing about the day it matters: weakening the policy to threshold 1 makes
  the first refusal stop refusing, and the drill exits non-zero. That is a test.
- **The refusals are the drill, not a footnote.** Below-threshold, a non-member,
  **the same member signing twice to look like two**, and a quorum pointing at a
  policy that does not exist -- all refused, and in each case the lineage holds
  at the old root rather than erroring, which is what fail-closed looks like
  from the operator's side.
- **Migration:** none. A drill and a runbook over an unchanged protocol.

## D-086: the file the operator actually produced

- **Date:** 2026-08-27
- **Found by:** verifying that the operator's real recovery keys open, which is
  the half of `D-085` a drill with throwaway keys cannot cover. Two signatures
  were produced with `la sign ... > proof.json` and neither would load.
- **Problem:** **PowerShell writes UTF-16 with a byte order mark when you
  redirect with `>`.** That is the natural way to save a file on Windows, the
  runbook tells people to save files, and reading the result as UTF-8 raised
  `UnicodeDecodeError` -- which Typer rendered as a traceback. On, of all days,
  the one where somebody has lost a root key and is following `docs/RECOVERY.md`
  line by line.
- **Decision:** `_read_source` recognises UTF-16 and UTF-32 byte order marks and
  reports what the file is and how to re-save it, naming
  `Set-Content -Encoding utf8`. It does **not** re-decode the file: silently
  accepting bytes the operator did not mean to produce is not a kindness here,
  and a runbook step that appears to work while writing the wrong encoding is
  worse than one that stops.
- **A UTF-8 BOM is different and is consumed.** Several Windows editors add one
  without saying so. That is a stray character in front of the opening brace,
  not an encoding the tool cannot read, and refusing the file for it would
  strand somebody whose only mistake was using Notepad.
- **The test for that was vacuous at first, and the negative control caught it.**
  It asserted `MALFORMED`, which both the fixed and the broken path reach --
  removing the BOM handling left all four tests green. What discriminates is
  whether the JSON parsed at all: `invalid JSON: Unexpected UTF-8 BOM` versus
  `envelope does not match the LAP envelope shape`. Asserting the reason rather
  than the verdict is what makes it a test.
- **The verification itself:** both recovery keys opened, both Ed25519
  signatures verified against the DIDs the published policy names, and the two
  are distinct members -- so the 2-of-3 threshold is reachable. Proven, from the
  signatures, rather than reported.
- **Migration:** none for the protocol. A file that used to raise a traceback now reports its encoding; nothing that worked before stops working.

## D-086b: an agent must not become entitled to approve itself

- **Date:** 2026-08-28 (audit)
- **Problem:** `D-042` says the parties who may consent to an exercise of
  authority are the issuers along the authorizing path, plus the root -- whoever
  delegated it is who may approve its use. The chain walk refused loops by
  **event id**, which stops a grant naming itself as its own parent and nothing
  more. An agent holding a throwaway key could publish `A->B` and then `B->A`,
  attenuating correctly at every edge, and thereby appear on its own authorizing
  path as an issuer. It then signed its own approval receipt.
- **Decision:** three locks, because one of them being wrong should not be
  enough. (1) `_walk_to_root` refuses a chain that delegates to the same DID
  twice -- a real chain `R->A->B->C` has distinct subjects, a loop must repeat
  one, and the rule can only ever refuse. (2) `_approvers_entitled` discards
  the requesting agent unconditionally. (3) `read_receipt` refuses
  `approver == agent`, which `build_approval_receipt` already refused --
  **a rule only the drafting side enforces is a rule an attacker skips by not
  using the drafting side.**
- **Verified end to end**, not just at unit level: the full loop plus a receipt
  signed by the throwaway key now returns `may_execute=False, DENIED`.
- **Migration:** **a delegation chain that revisits a subject is now refused**, and a receipt whose approver is its own agent is refused by the verifier as well as the builder. Any bundle relying on either was relying on a hole.

## D-087: a proof that does not verify is discarded, not fatal (revises D-027)

- **Date:** 2026-08-28 (audit)
- **Problem:** `D-027` treated any unverifiable proof as tampering and refused
  the whole envelope. `D-036` promises that merging copies of one event takes
  the **union** of their proofs, because a mirror that could drop a signature
  could suppress a recovery quorum. **The two were incompatible.** Proofs sit
  outside the payload and do not affect the event id, so anybody holding no key
  could append a nonsense proof to a copy of a signed event and have that copy
  discarded whole. A mirror serving only the spoiled copy made the event vanish.
  Adding worked as deleting, and the union guarantee was broken at the door,
  before merging was ever reached.
- **Decision:** at least one proof must verify; the ones that do become the
  signers; the ones that do not are discarded with a warning. Nothing is gained
  by appending -- a forged proof names a signer absent from `verified_signers`,
  and `signed_by`, `distinct_signers` and every quorum count read that list. The
  only thing that changes is that the event survives to be merged. An envelope
  where **every** proof fails is still refused.
- **Both implementations changed together.** `packages/js/lineageauth.js` does
  the same thing, and the conformance run still reports 9/9. Fixing one side
  only would have manufactured exactly the disagreement this project asks
  strangers to look for.
- **Migration:** **a consumer that treated `integrity_ok` as "every proof verified" must read `verified_signers` instead.** An envelope carrying one bad proof is now admitted with the bad proof discarded and a warning attached. Quorum counts were already reading `verified_signers` and are unaffected.

## D-088: a recovery quorum outranks a disagreeing normal succession

- **Date:** 2026-08-28 (audit)
- **Problem:** two authorized successions leaving one epoch for different roots
  halted the lineage as `CONFLICTED`. That reads as the safe answer and was the
  opposite. **Recovery exists for the case where the root key is the compromised
  one**, so the thief holding it could sign an ordinary succession, collide with
  the quorum on purpose, and freeze the lineage for good: the event is public,
  anybody can keep a copy in the bundle, and re-signing with every member
  changes nothing. Refusal was the attack -- the same shape as `D-034`, arrived
  at from the other direction.
- **Decision:** when successions out of one epoch **disagree** and both modes are
  present, the recovery ones win and the normal ones are denied as `SUPERSEDED`.
  Two recovery quorums disagreeing still halts: that means threshold-many
  members are split or colluding, and there is nothing left to prefer with.
- **This is not a timestamp tie-break.** `D-034` stands. `mode` is a field inside
  the signed payload, so the preference is fixed by what the issuers themselves
  declared. `issuedAt` is self-asserted and is exactly what a thief would forge.
- **Only when they disagree.** Successions naming the *same* next root are two
  parties agreeing, not a conflict, and both stay in the step's history. The
  first version of this fix dropped the normal one either way and an existing
  test caught it.
- **Migration:** **a lineage that halted as `CONFLICTED` because a normal and a recovery succession disagreed now resolves to the recovery one.** Any stored `CONFLICTED` verdict for that case should be re-derived. Recovery-versus-recovery still halts.

## D-089: the execution gate has no default that turns the guard off

- **Date:** 2026-08-28 (audit)
- **Problem:** `check_execution` took `store: SpentReceiptStore | None = None`,
  and with `None` it ran neither `is_spent` nor `reserve`. It returned
  `may_execute=True` with `reserved=False` and **no warning at all**, so one
  human approval became an unlimited licence for any caller who did not notice
  the second field. The module's own header calls "never let one receipt be
  spent twice" one of its two rules; the gate's default disabled it.
- **Decision:** `store` is required. Previewing without consuming is what
  `reserve=False` already expressed, so nothing needed the `None`.
- **The MCP adapter is where the cost lands, and it is paid honestly.**
  `LineageAuthTools` holds no spent store, so `verify_approval` now takes one
  optionally and reports `spentStateConsulted: false` with a warning when it has
  none. An empty store answers "nothing is spent", which is a guess; the flag is
  what stops a caller reading it as a fact.
- **Migration:** **`check_execution` requires `store`.** Callers passing nothing must pass a `SpentReceiptStore`; previewing without consuming is `reserve=False`. `LineageAuthTools` takes an optional store and reports `spentStateConsulted`. Callers passing no store must pass one.

## D-090: one meaning, one encoding, for mcp resources too

- **Date:** 2026-08-28 (audit)
- **Problem:** `parse_resource` overwrote the prefix of an `mcp` server/tool
  resource without checking it, so `server:s/tool:t`, `tool:s/tool:t` and
  `zzz:s/tool:t` all parsed to one `Resource`. No authority widened -- they name
  the same thing -- but a signed grant then had several spellings, which is the
  rule every neighbouring check keeps: canonical `did:key`, sorted actions,
  re-encoded base64url.
- **Decision:** the prefix must be `server:`; anything else is `MalformedEventError`.
- **Migration:** **an `mcp` server/tool resource must begin with `server:`.** A signed grant spelling it otherwise no longer parses; it never named a different resource, so re-issuing under the canonical spelling is the whole of the change.

## D-091: an unpaired surrogate has no preimage, in either implementation

- **Date:** 2026-08-28 (audit)
- **Problem:** the two implementations **disagreed**, which is the one outcome
  this project asks strangers to look for -- found here by an internal review
  first. A payload containing an unpaired UTF-16 surrogate cannot be encoded as
  UTF-8, and the preimage is UTF-8 bytes, so there is nothing to sign. Python
  refused it. JavaScript did not: `TextEncoder` substitutes U+FFFD instead of
  throwing, so `jcs`, `preimage` and `eventId` all completed and `verifyEvent`
  returned ok -- **for bytes that were not the document.**
- **Decision:** `canonicalString` throws on any surrogate that survives
  `for...of`, which by definition is unpaired since the iterator yields valid
  pairs as one character. Python was already right; JavaScript now matches.
- **Disagreeing in the permissive direction is the worse half.** A stricter
  implementation refuses something real and someone notices. A looser one
  admits an event whose id does not describe its content, and nobody does.
- **Migration:** **JavaScript now refuses an unpaired surrogate**, matching Python. Any event that verified there and nowhere else had no UTF-8 encoding and therefore no preimage.

## D-092: nothing a caller sizes is unbounded

- **Date:** 2026-08-28 (audit)
- **Problem:** `POST /v1/verify/event` accepted any number of proofs and
  verified every one, and `POST /v1/router/search` accepted any number of
  `requires`, which multiply against the subject count inside a double loop of
  `check_permission`. `limit` truncates the *results*, not the work.
- **Measured, not assumed:** `scripts/benchmark.py` puts admission near 0.5 ms
  an event, so 51 events already exceed the 10 ms a free Cloudflare Worker gets
  per request and 201 take fourteen times it. **The caller picks the size**, so
  an endpoint that admits whatever it is handed pays whatever it is asked to.
  That is a denial-of-service shape before it is a cost problem, and a paid plan
  converts it from failing into costing money.
- **Decision:** `MAX_PROOFS = 16`, `MAX_SKILLS = 32`, `MAX_REQUIREMENTS = 8`.
  Generous for real use -- a recovery quorum is a handful of keys -- and small
  enough that no unauthenticated request buys meaningful CPU.
- **Migration:** **`/v1/verify/event` accepts at most 16 proofs, and `/v1/router/search` at most 32 skills and 8 requirements.** A caller sending more gets a validation error rather than a slow answer.

## D-093: the policy has to reach the copy strangers load

- **Date:** 2026-08-28 (audit)
- **Problem:** the Explorer's strict CSP was sent as a header by `api.py`, and
  tested there. The published Explorer is on GitHub Pages, and **static hosting
  cannot set headers.** So the protection existed exactly where nobody is
  attacking, and was absent from the one copy that is reachable from the
  internet -- while the tests reported it present.
- **Decision:** the same policy is repeated as a `<meta http-equiv>` in
  `index.html`, so it travels with the file. `frame-ancestors` and `form-action`
  are header-only directives and are ignored in a meta tag; they stay in the
  header, and the test that compares the two knows to skip them rather than
  demanding a tag do what the specification says it cannot.
- **Verified in a browser on the built site**, not from the source: an inline
  script and a script from another origin were both refused, with the violations
  in the console, and the page still worked. Checking the file for a string
  would have proved only that a string was in a file -- the failure being fixed
  was precisely a policy that existed without applying.
- **Migration:** none. A meta tag added to a published page.

## D-094: a claim is a hold, and a hold can lapse

- **Date:** 2026-08-28 (audit)
- **Problem:** `resolve_task` accepted a `task.result` if the claim it cited
  existed and belonged to the worker. It never asked whether the claim was still
  *held*. So on a task allowing one claimant, somebody could claim it, release
  it or let it expire, watch a second worker pick it up -- and still submit a
  result days later that counted as legitimate work. `exchange._awarded_claim`
  had the same gap from the other end: it was handed every claim ever made, so a
  coordinator could award one that had already lapsed.
- **Decision:** a result is ignored, with a warning rather than an error, when
  the claim it cites was released or had expired at the moment the result was
  issued. The coordinator may only award among the live claims -- it settles a
  contest, it does not revive a hold.
- **Warnings rather than refusals**, because a late result is a fact about the
  bundle worth reporting, and derived state that silently omits things is harder
  to debug than derived state that says what it dropped.
- **Migration:** **a `task.result` citing a released or expired claim is ignored**, with a warning, and a coordinator may only award among live claims. Derived task state may change for bundles that contained one.

## D-095: a check that scans nothing must not report "clean"

- **Date:** 2026-08-28 (audit)
- **Problem:** `scripts/pre_push_check.py` is the last gate before the
  irreversible step, and it failed open in two ways. `git()` returned `""` for a
  failed command; `check_remote` read that as a problem, but `tracked_text`
  split it into an empty list and reported a clean tree. And a file that would
  not decode as UTF-8 was skipped silently -- which on this machine means the
  encoding PowerShell writes for `>`, the very thing `cli.py` warns about two
  files away. **The most likely encoding on the operator's own console was the
  blind spot in the scanner.**
- **Decision:** `git()` returns `None` on failure and the caller must decide;
  files are decoded as UTF-8, then UTF-16 either way, and anything still
  unreadable is reported as unscanned rather than skipped; scanning zero files
  is itself a refusal.
- **Verified by planting a real-shaped token in both a UTF-8 and a UTF-16 file.**
  Before, only the UTF-8 one was caught.
- **Migration:** none. A pre-push check over this working tree.

## D-096: the module entry point offered a fraction of the CLI

- **Date:** 2026-08-28 (audit)
- **Problem:** `if __name__ == "__main__": app()` sat two-fifths of the way down
  `cli.py`, so it ran before the commands defined below it were registered.
  `python -m lineageauth.cli` offered five commands where `la` offered fourteen
  -- **approval, check, doctor, execute, graph, index, key, passport and sign
  were simply absent.** Nothing failed. They were not there.
- **Decision:** the block moves to the end, and a test compares the two entry
  points command for command. 1,228 tests passing did not catch this, because
  every one of them used the installed entry point.
- **Migration:** none. `python -m lineageauth.cli` now offers the commands `la` always did.

## D-097: a gate that cannot count is a gate that cannot say "clean"

- **Date:** 2026-08-28 (audit)
- **Problem:** `scripts/gate.py` ran `pytest -q` while `pyproject.toml` already
  put `-q` in `addopts`. The two combined into `-qq`, which suppresses the
  "N passed" line entirely. For a full day of work the gate could only report
  that nothing objected -- **and a suite that collected zero tests reports
  exactly the same thing.**
- **Decision:** the `-q` is gone from the gate, the tests run captured, and the
  tally is echoed in the summary. It now reads `PASS tests -- 1228 passed`,
  which is a different claim from `PASS tests`.
- **Migration:** none; this is tooling.

## D-098: a limit the builder enforces is not a limit

- **Date:** 2026-08-28 (audit)
- **Problem:** two caps existed only on the drafting side. `MAX_AVAILABILITY_WINDOW`
  (seven days) and `MAX_JURORS` (32 seats) were refused by their builders and
  accepted by their readers. A payload written by hand skipped both -- so an
  agent could declare itself available for a decade, and a case could seat an
  unbounded jury that this resolver would then draw and count.
- **Decision:** both are checked where they are read. This is the third instance
  of one pattern today (`approval.read_receipt` was the first), and the pattern
  is worth stating plainly: **a builder is a convenience and a verifier is a
  rule.** An event that only the drafting side rejects is an event an attacker
  drafts by hand.
- **Migration:** **`availability.statement` windows over seven days and juries over 32 seats are now refused on read**, matching what the builders already refused to draft.

## D-099: three ways a tool destroyed what it was protecting

- **Date:** 2026-08-28 (audit)
- **`keyfile.unlock` ignored the file's own KDF block** and derived with today's
  constants. Raising `SCRYPT_N` in a future version would have made every
  existing key file report "the passphrase is wrong, or the file has been
  altered", sending somebody to hunt for a passphrase that was never wrong.
  It reads the block now, and accepts only `ALLOWED_KDF` -- honouring the file
  is not trusting it, and an altered file asking for `n=2**30` would otherwise
  turn unlocking into a memory-exhaustion switch. `restore_key.py` checks
  against the same set, so the recovery path cannot be stalled either.
- **`build_site.py` deleted whatever `--out` named.** It now requires the
  directory to look like a previous build (`.nojekyll` or `data/site.json`)
  before removing it, and exits saying so otherwise.
- **`recovery_drill.py` printed "files left for inspection" and then deleted
  them.** `finally` tested `sys.exc_info()`, which is already clear once the
  exception is handled, so the one run where somebody needed the evidence was
  the run that removed it. An explicit flag now, set only on success.
- **Also:** `pre_push_check.py` did not know what this project's own key
  material looks like -- an Ed25519 seed is 64 hex characters and no pattern
  described one, so the scanner knew every shape except the one it exists to
  protect. Added, with `(?<!sha256:)` so it does not fire on the event ids that
  fill this repository, because a scanner that cries wolf gets deleted. Names
  like `seed.txt` are refused before the text-suffix filter, which was where
  `.pem` and `.key` had been slipping past.
- **Migration:** none for the protocol. `keyfile.unlock` now reads the file's own KDF block and accepts only `ALLOWED_KDF`; every file this project has written qualifies.

## D-100: most of the pre-1.0 marks were never statements

- **Date:** 2026-08-28
- **Problem:** `RELEASE.md` listed "the pre-1.0 marks are gone from the decision
  log" as a v1 blocker covering 46 entries, and treated all 46 as shapes that
  might still change. Reading them found that **most of those marks meant
  nothing.** `Migration: Pre-1.0` is the pending-decision template's default, and
  it had been carried onto decisions with no consumer at all: a pre-push hook, a
  text colour, how CI renders an annotation, a document tested against the code.
  A decision about a CSS token has no migration path. Saying "this may still
  change" about it told a reader only that nobody had looked.
- **Why that is worse than it sounds.** A blocker list is read to decide what is
  safe to depend on. Forty-six entries saying "unsettled" when fourteen are
  unsettled does not fail safe -- it makes the list unreadable, and an unreadable
  list gets skimmed, and the fourteen that matter get skimmed with it.
- **Decision:** each of the 46 was read and given the note that is true of it.
  **Eighteen internal ones** say `none` with the reason. **Fourteen behaviour
  changes from this day's audit** state the migration they actually impose --
  `check_execution` requiring a store, `verified_signers` replacing "every proof
  verified", a `CONFLICTED` verdict that now resolves, results outside a live
  claim being ignored. **Fourteen remain `Pre-1.0`**, and every one of those
  defines a payload shape, a published schema, or an artifact somebody else's
  code reads.
- **Two blockers turned out to be one.** Those fourteen are not a separate task
  from "wire formats are frozen"; they are its content, and `RELEASE.md` now
  lists them by number.
- **The judgement was made by reading, not by matching.** A first pass classified
  them with keywords and put the pre-push hook and the text colour in the
  wire-format pile because their prose contains the words "field" and "schema".
  Forty-six is a readable number and the classifier was the wrong tool for it.
- **Migration:** none. This is a decision about the decision log.

## D-101: the wire formats that do not depend on the prior-art answer are frozen

- **Date:** 2026-08-28
- **Problem:** `RELEASE.md` asked for wire formats "frozen with a stated
  compatibility promise, and meaning it". Meaning it is the half a document
  cannot do, and there was nothing that failed when the promise was broken.
- **Decision:** `conformance/frozen-shapes.json` records the payload keys every
  event type always carries, generated by `scripts/generate_frozen_shapes.py`.
  **22 of 28 event types are frozen** -- evidence, work, fleet, impact, jury,
  passport, plus the resolver output, the published schemas and the conformance
  manifest. A frozen required key does not move without a decision entry.
- **The `authority` family is held, not frozen.** Delegation, approval, root
  succession and recovery policy are the layer `docs/PRIOR_ART.md` finds
  overlapping UCAN and Biscuit. If the answer to that question is to build on
  one of them, these shapes change; freezing first would only mean unfreezing
  later. Held means recorded and watched, not unwatched: the test still fails if
  they change without the file being regenerated.
- **Optional keys are deliberately outside the contract.** Adding one is a
  compatible change, and a promise that forbade compatible changes would be
  edited out of the way the first time it was inconvenient -- which is worse
  than not making it.
- **Three sources were considered and two rejected.** The JSON Schemas describe
  the envelope only, so they cannot carry per-event names. The decision log does
  list the fields, and cross-checking it against the builders was worth doing --
  it found `parent`, `reason` and `previousPolicy` marked required in prose and
  optional in code, all three now fixed. But a regex over hand-written prose is a
  parser for a format nobody designed: pushing it from 23 of 24 to 24 of 24 made
  it read `normal` and `recovery`, the *values* of a `mode` field, as field
  names. **Freezing is an explicit act, so the contract is an explicit file.**
- **Checked by breaking it:** renaming `artifactId` to `artifactID` in a builder
  fails the test with the family, the event and both sides of the difference.
- **Migration:** none. This records what will not change; nothing changed.

## D-102: the loop finding was put to another implementation

- **Date:** 2026-08-31
- **What happened:** `D-086b` -- an agent laundering its own standing by
  delegating through a key it also controls, so that it appears as an issuer on
  its own authorizing chain -- was described to the author of
  [ADTP](https://github.com/Zahanturel/adtp) on
  [ucan-wg/spec#206](https://github.com/ucan-wg/spec/discussions/206), a Go
  implementation of agent delegation over UCAN chains.
- **Why that project and not another.** ADTP tests RESTRICT against seven named
  escalation vectors -- scope widening, depth bypass, RESTRICT removal, caveat
  stripping, cross-org escalation, replay injection, malformed caveats -- and
  **the loop is in none of them.** Its `§8.6 Self-delegation` refuses `iss ==
  aud`, which closes the one-hop case; the two-hop A->B->A has `iss != aud` on
  every edge and the rule does not fire. The parenthetical in that section says
  "cycle ... hygiene", so cycles are on the author's mind: the gap is between
  what the section intends and what it says.
- **What was claimed, and what was not.** The message states plainly that only
  `docs/PROTOCOL.md` was read and not the Go, so an implementation-level check
  would make the finding noise. It also says the attack **only pays off where
  something reads the issuer list as a list of parties** -- and "approval" does
  not occur in ADTP's specification, so it may be harmless there today and
  become live the moment such a layer is added.
- **Nothing was asked for.** No link to this project, no mention of its name.
  The author had asked whether RESTRICT is worth proposing as a spec extension
  and that question is answered: the proposable part is not the narrowing, which
  UCAN already requires, but that it is enforced **at chain validation rather
  than policy evaluation** -- a claim about where the check lives, which is
  testable in isolation and cannot be switched off by configuration.
- **Whatever comes back is worth recording here.** If ADTP already closes this
  somewhere unread, that is a fact about a second implementation's design and
  belongs beside `D-086b`. Being told the finding is wrong is a better outcome
  than not being told.
- **Migration:** none. This records an exchange, not a change.

## D-103: grant standing walks the chain, because every caller read it as if it did

- **Date:** 2026-09-01
- **What prompted it.** A third party on
  [ucan-wg/spec#206](https://github.com/ucan-wg/spec/discussions/206) made a
  point about revocation that is not about revocation being weak: *"the chain
  that proves who was allowed cannot tell you what to go undo."* Revoking an
  ancestor answers the next call and says nothing about the writes that already
  landed. Checking whether this project actually did better found something
  worse than the gap being described.
- **What was wrong.** `describe_grants` judged each grant in isolation -- not
  revoked, inside its window, right epoch -- and returned
  `VALID_AUTHORITY_CHAIN` for a grant whose parent had been revoked. Measured on
  one bundle at one instant: `check_permission` said `REVOKED`, and standing said
  `usable=True`.
- **This was documented, and that did not save it.** `GrantStanding` said in
  its own docstring that `usable` "says nothing about whether the chain above it
  holds -- ask check_permission", and the success detail repeated it. Four
  callers read it as a chain answer anyway, because the honest thing each of them
  needs *is* the chain:
  - `graph.py` drew a live delegation edge hanging off a revoked one -- in a
    module whose docstring says a picture that disagrees with the verifier is
    worse than no picture;
  - `passport.py` reported the worker as holding live authority, with scopes;
  - `evidence.py` reported a receipt citing that child as supported by a valid
    authority chain -- turning the per-grant fact into exactly the retroactive
    claim #206 says a chain cannot make;
  - the MCP `list_grants` tool shipped `usable: true` to an agent over the wire.
- **Decision.** One walk, one answer. `_walk_to_root` takes `request: Request |
  None`; with `None` it performs the request-independent half, and
  `describe_grants` calls it instead of judging grants alone. `usable` now means
  this grant *and every grant above it* are current. It is still not permission:
  scope coverage remains a question only `check_permission` answers.
- **Why not fix the four callers instead.** That leaves the trap for the fifth.
  A per-grant standing has no consumer -- nothing in this repository wants to
  know that a grant is fine while its parent is dead, except to refuse it.
- **Security impact.** Strictly a refusal: the walk can deny a chain, never widen
  one, and the four surfaces now agree with the gate rather than overstating it.
  The negative controls matter as much -- revoking a child still leaves its
  parent usable, and an intact chain is unchanged.
- **Interop impact.** The MCP `list_grants` field `usable` narrows in meaning. No
  wire format moves: no payload shape, signing preimage or conformance vector is
  touched, and the JavaScript implementation has no authority layer to follow.
- **What this does not claim.** It closes a disagreement inside this
  implementation. It does not answer #206. Enumerating what to undo after a
  revocation still depends on receipts citing `authorityRefs`, which is an
  optional field -- work performed without citing its authority remains
  unattributable to the grant that permitted it. That is a real limit, now
  written down rather than assumed away.
- **How it was missed.** The full suite -- 1276 tests -- passed both before and
  after the change. Nothing covered a two-hop chain with a revoked parent.
  `tests/test_standing_agrees_with_gate.py` pins the invariant rather than the
  four symptoms; 7 of its 14 tests fail against the previous code, and the other
  7 are controls that must pass against both.
- **Migration:** none for stored events. A caller depending on `usable` meaning
  "this grant alone is current" would see a narrower answer, and there is no such
  caller in this repository.

## D-104: the exact-action approval claim was narrowed against prior art

- **Date:** 2026-09-01
- **What happened.** The same #206 comment that prompted `D-103` linked [an
  SQLite approval-audit
  schema](https://gist.github.com/renezander030/ad81c7a805a09a844983f881e2c487e5).
  It was read in full before anything was written about it.
- **What it says.** Freeze the full payload the human saw rather than a pointer
  to it, store its hash beside it, record the operator's identity rather than
  their role, and never `UPDATE` or `DELETE` the row. It is framed against GDPR
  Article 22 and drawn from a running Go tool,
  [draftcat](https://github.com/renezander030/draftcat).
- **Why it matters here.** `PRIOR_ART.md` listed exact-action human approval as
  one of two residual claims. Those four rules have exact counterparts in this
  project -- `contentHash`, `requestHash`, the approver's DID, and events that
  merge by union -- and they predate it. **The binding is not the residual.**
- **What survives, stated narrowly.** That the record is verifiable by someone
  who does not trust whoever holds the store, because it is signed rather than
  append-only by convention; plus a receipt spendable exactly once, and the
  re-check of authority between decision and execution.
- **What the schema does that this does not.** Its fourth query asks whether
  anything executed with no approval at all -- a left join from side effects to
  approvals. There is no equivalent here, because `authorityRefs` and
  `approvalRef` on `artifact.receipt` are both optional, so a receipt carrying
  neither joins to nothing. Recorded in `28_NON_GOALS_LIMITATIONS.md` rather than
  fixed, because making either field required is a wire change and belongs with
  the held `authority` family, not beside it.
- **Why record a retreat at all.** This is the page that exists to stop
  overclaiming. A claim quietly narrowed is the same failure as a claim never
  checked, so the citation is pinned in `tests/test_prior_art.py`: dropping the
  link fails the suite.
- **Migration:** none. Documentation and a test.

## D-105: the delegation-loop invariant is withdrawn; approval excludes disclosed siblings

- **Date:** 2026-09-02
- **Who found it.** Alan Karp, on
  [ucan-wg/spec#206](https://github.com/ucan-wg/spec/discussions/206), replying to
  the description of `D-086b` posted there. Both of his points were reproduced
  against this code before anything was changed.
- **The rule under review.** `D-086b` made `_walk_to_root` refuse a chain that
  delegated to the same DID twice, on the grounds that a loop `A->B->A` puts A on
  its own authorizing path as an issuer, and `_approvers_entitled` (D-042) reads
  that path to decide who may consent.
- **It refused something correct.** *"If B asks A to use the resource, then A MUST
  use B's permission to avoid a confused deputy vulnerability."* A chain in which A
  exercises authority delegated by B repeats A by construction. Measured: with the
  rule in place `check_permission` on `R->A->B->A` returned `MALFORMED`.
- **It did not close the hole.** *"B's delegation back to A can be issued to a
  different DID that A controls."* Measured: `R->A->B->A'` with `A'` a second key
  the same operator holds gives `may_execute=True, VALID_AUTHORITY_CHAIN` with A
  signing the approval for A'. Every subject on that chain is distinct.
- **Why no shape rule can work.** The suite already said it, in a comment on the
  test that encoded the old belief: *"Nothing in the bundle distinguishes it from a
  real second party -- which is the point, and why the fix cannot depend on telling
  them apart."* A DID costs nothing, and `28_NON_GOALS_LIMITATIONS.md` says counting
  them counts nothing. A rule about the shape of a chain counts DIDs.
- **Decision.** The repeated-subject refusal is removed; the repeated-`event_id`
  check stays, because that is a real cycle. `_approvers_entitled` now also
  excludes any DID a **disclosure** ties to the agent, via `FleetView.same_fleet` --
  the rule `jury._detect_conflicts` already applies to a juror who shares a fleet
  with a party. `check_execution` resolves fleets and passes them in.
- **What that buys, exactly.** It holds an operator to its own statement and
  nothing else. Undisclosed collusion stays undetectable, which is now asserted by
  a test (`test_an_undisclosed_key_the_agent_controls_is_not_detected`) so it cannot
  quietly stop being true, and stated in `28_NON_GOALS_LIMITATIONS.md`.
- **Not a penalty for disclosing.** `fleet.py` requires that disclosure never cost
  the honest operator what silence saves the quiet one. This does not subtract from
  anybody; it stops a relationship *counting as independent*, which is the safe half
  of that rule.
- **Security impact.** Mixed, and worth naming rather than smoothing over. Removing
  the invariant **widens** what verifies: `R->A->B->A'` was already permitted, but
  `R->A->B->A` now resolves instead of failing closed. The exclusion **narrows**
  approval wherever a fleet is disclosed. The net is that a rule which gave a false
  sense of two-person control is replaced by one that is true but smaller, plus an
  explicit limitation. Anyone who read the old rule as two-person control was
  relying on something that never held.
- **Interop impact.** None. No payload shape, preimage or conformance vector moves.
  `_approvers_entitled` is private and gains a parameter.
- **Migration:** none for stored events. Chains previously refused as loops now
  resolve, so a verifier upgrading may accept a chain it used to reject.
- **Owed.** Karp also asked what "approve" means here, having found no definition.
  That is a fair question about this project's vocabulary and is answered in the
  reply, not in code.

## D-106: a read-only tclk/1 adapter, with no change to LAP core

- **Date:** 2026-09-02
- **What tclk/1 is.** A convention published by FLOP Labs the same day
  (`flop-labs/tclk`, `v0.1.0`, commit `81a8346`): HTLC/PTLC deal-making
  between agents as signed single-line frames in a Technocore room, with money
  on a settlement rail elsewhere. Read from primary sources first; the report
  is `docs/TCLK_RESEARCH_REPORT.md`, with the unknowns marked.
- **The binding, stated once.** A tclk frame is a Technocore signed-lane
  message. Posting one is `technocore` / `room:<room>` / `write`, where the
  room is the one `SPEC.md` §2 assigns to the frame type. That is an authority
  LineageAuth already expresses, so **no namespace, action, reason code, event
  type, payload shape or predicate was added**. Everything the model cannot say
  -- spend limit, rail allowlist, counterparty, per-frame-type -- is named on
  every decision as `unchecked` and written up in `docs/TCLK_GAP_ANALYSIS.md`
  as `SPEC CHANGE REQUIRED`, awaiting a decision rather than taken.
- **Three modes, no fourth.** Read-only, simulate, prepare. `publish()` raises.
  The rail type is a `Protocol` with no member that moves value. Nothing mints,
  stores or echoes a secret; `ContractState` records `secret_revealed: bool`
  and has no field for the value, which is stricter than the reference library
  and the same rule as its MCP server.
- **Conformance.** The reference's golden vectors are copied verbatim into
  `conformance/tclk/` with commit and retrieval time, and reproduced byte for
  byte by `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
  -- no canonicaliser of this project's own. Synthetic transcripts are labelled
  synthetic; the reference publishes no byte-exact end-to-end example and says
  so.
- **Where this port is stricter than the reference, and why.** Non-canonical
  lines and duplicate JSON keys are refused (the reference accepts both). Every
  reference-emitted frame is canonical, so the difference bites only hand-built
  lines, and fail-closed is the rule on a path that describes money.
- **Where it deliberately matches the reference against instinct.** The DID is
  checked for shape and not decoded, because the golden vectors' DIDs are not
  real keys and parity with the vectors is the point. `claimByMs` is not
  enforced by the machine, because the reference leaves it to the rail.
- **Security impact.** Additive and read-only. A valid frame creates no
  authority; authority never rescues an invalid frame; approval binds the
  frame's bytes so a changed nonce is a different action; room content is data
  and the suite refuses the network. The residual is the one `SPEC.md` §8.5 and
  D-105 both name: two keys may be one operator, and only disclosure catches it.
- **Interop impact.** None to LAP. To tclk: this is a second implementation of
  its wire format and state machine, in another language, agreeing on its
  vectors -- the thing this project asks of others in `RELEASE.md`.
- **Not done, on purpose.** No PTLC adaptor port (unaudited upstream, and this
  signs nothing). No `MemoryRail`/`PaperRail` (a rehearsal of value movement).
  The Explorer page was deferred to a later commit the same day (a ninth
  screen over three compute-only endpoints, `POST /v1/tclk/{inspect,simulate,
  authorize}`; the approval half is a dry run and the API has no default
  clock). The adapter commit was made local-only and pushed afterwards at the
  user's direction, once the integration report had been read.
- **Migration:** none.

### Pending decision template

- ID:
- Date:
- Problem:
- Options:
- Security impact:
- Interop impact:
- Decision:
- Migration:

## D-107: who may approve is designated on the grant, not inferred from the chain

- **Date:** 2026-09-03
- **Problem:** D-042 said the parties entitled to approve an exercise of
  authority are the issuers along the authorizing path plus the current root:
  whoever delegated it may consent to its use. Alan Karp, replying on
  [ucan-wg/spec#206](https://github.com/ucan-wg/spec/discussions/206) after
  D-105, asked what the rule means when nobody on the chain is a human -- an
  agent that delegated to another agent would be "the human in the loop" -- and
  suggested the verifier should instead ask a *designated* party. D-086b and
  D-105 had already shown the derived rule was the wrong shape: an operator
  could put a key it controls on the path (D-086b), the loop rule that tried to
  stop it refused a legitimate confused-deputy chain and was bypassable
  (D-105), and what remained was a disclosure-only exclusion.
- **Decision:** a `delegation.grant` carries `approvers`, a list of did:key
  values. It is required whenever `approval` is not `none`; a grant that
  demands approval and names nobody is refused by the builder **and** by
  `read_grant`, so a hand-built payload cannot fall open to "anyone on the
  chain" (fail closed; the alternative of treating a missing list as "the root"
  was considered and rejected as a silent default). The list attenuates: a
  child may only name a subset of its parent's (`SCOPE_VIOLATION` otherwise);
  a parent naming nobody constrains nothing. `_approvers_entitled` is now the
  intersection of the lists along the path -- the leaf's own list by
  construction -- minus the agent, minus any DID a fleet disclosure ties to the
  agent (D-105). Nobody is entitled by position: neither the root nor an issuer
  on the path may approve unless named. The `DENIED` detail says so.
- **What it closes.** The laundering D-086b found is closed structurally, not
  by a rule about the chain's shape: a throwaway key on the path is entitled to
  nothing unless the party above named it, and `tests/test_approval.py`
  pins the bundle that used to execute and now does not.
- **What it does not close, said flatly.** A delegator that names a key it
  wrongly believes is a person -- including the agent operator's second key --
  is not caught; the receipt verifies as a second party's would. The question
  moved from the chain's shape to the delegator's decision, which is where it
  can be answered. `docs/28` says so, and the suite keeps a test asserting
  `may_execute` for exactly that case so the limitation cannot quietly stop
  being true.
- **Wire and conformance.** `approvers` is an optional key on the wire
  (present iff non-empty), so `conformance/frozen-shapes.json` is unchanged:
  no required key was added, and the `authority` family stays *held*. An
  implementation that ignores `approvers` and applies D-042 would permit
  receipts this one refuses -- a stricter-than-before divergence, in the safe
  direction. The JS package does not evaluate authority and is unaffected.
- **Security impact.** Strictly narrower. Every receipt that verified before
  and still verifies is signed by a party a grant names. The agent and
  disclosed-fleet exclusions are retained as defence in depth on top of
  designation, not replaced by it.
- **Migration.** Existing grants with `approval: none` are unaffected. A grant
  with `approval: external-only` or `required` and no `approvers` is no longer
  usable and must be reissued naming its approvers. No such grant exists in
  the conformance vectors, the examples, or the Explorer demo.
