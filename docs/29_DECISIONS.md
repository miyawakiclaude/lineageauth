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

### Pending decision template

- ID:
- Date:
- Problem:
- Options:
- Security impact:
- Interop impact:
- Decision:
- Migration:
