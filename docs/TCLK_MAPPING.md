# tclk/1 → LineageAuth mapping tables

Reference: `flop-labs/tclk` `81a8346` (`SPEC.md` §2–§8).

## 1. Frame → required LineageAuth authority

| frame | room (`SPEC` §2) | namespace / resource / action | who may post it (tclk) |
|---|---|---|---|
| `offer` | `tclk-offers` | `technocore` / `room:tclk-offers` / `write` | either side |
| `accept` | `tclk-offers` | same | the counterparty |
| `lock` | `mb-p-tclk-<16hex>` | `technocore` / `room:mb-p-tclk-<16hex>` / `write` | payer |
| `reveal` | deal room | same | payee |
| `refund` | deal room | same | payer, at/after `refundAfterMs` |
| `cancel` | deal room (or board before accept) | same | either party, pre-lock |
| `receipt` | deal room | same | either party, post-terminal |

LineageAuth checks the room write. The "who may post it" column is tclk's
state-machine guard, enforced by `apply_frame`, not by authority.

## 2. Frame fields → what the approval receipt binds

An `approval.receipt` binds `contentHash = sha256(frame line)` and
`destination = <origin>/r/<room>`. Because the line *is* the frame, every field
below is bound without being named in the receipt:

| directive asks for | where it lives | bound by |
|---|---|---|
| agent DID | `from` | contentHash (and `agent` on the receipt) |
| tclk action type | `type` | contentHash |
| contract id | `contract` (or `id` for an offer) | contentHash |
| counterparty | `offer.from` / `accept.from` | contentHash of the frame that names it |
| settlement rail | `rails` / `rail` | contentHash |
| amount / asset | `amount`, `asset` | contentHash |
| deadlines | `claimByMs`, `refundAfterMs`, `expiresMs` | contentHash |
| canonical frame hash | the line | contentHash |
| nonce, expiry of the *approval* | receipt fields | the receipt itself |

## 3. Contract status → other lifecycles (`SPEC` §6, `src/interop.ts`)

| tclk | A2A task state | Virtuals ACP phase |
|---|---|---|
| `proposed` | `submitted` | `request` |
| `accepted` | `submitted` | `negotiation` |
| `locked` | `working` | `transaction` |
| `claimed` | `completed` | `completed` |
| `refunded` | `failed` | `rejected` |
| `cancelled` | `canceled` | `rejected` |

Total mappings. None is execution proof.

## 4. Transcript → LineageAuth evidence

| tclk | LineageAuth | proves |
|---|---|---|
| any frame line | `artifact.register`, `artifactId = sha256:<line>` | these bytes existed |
| a party's authorship | `artifact.receipt` by that DID (optional `authorityRefs`) | that DID claims them |
| terminal status | `attestation.issue`, predicate `tclk.contract.outcome`, `subjectRef` = the accept frame's artifact | one DID says it ended this way |
| `lock.ref` | carried as data in `evidence_summary` | a string was posted; nothing about a rail |
| `reveal` | `secret_revealed: true` in the folded state | a secret opened the statement at that instant |
| `job` | `job_reference` — data | which external task the deal claims to pay for |

## 5. Arbitration: tclk §8 vs LineageAuth `docs/12`

| feature | tclk/1 | LineageAuth | overlap | difference | integration |
|---|---|---|---|---|---|
| arbiter selection | named in the offer, hashed into the contract id | explicitly named verifier DIDs, or deterministic selection with a recorded seed | both name jurors up front | tclk's are bound into the deal id; LAP's into a `dispute.open` | none needed; a tclk offer's arbiter list can be attested as evidence |
| voting | commit–reveal: `sha256(domain\|commit\|contract\|verdict\|salt)` in the room | `jury.disclose` then `jury.vote`, signed events | both are two-round and signed | tclk seals the verdict with a salt; LAP discloses conflicts first | `verify_vote_commitment` lets LAP re-check a tclk round from an export |
| commit / reveal | yes (§8.3) | no sealed commitment | — | LAP votes are visible when cast | not reimplemented |
| evidence submission | none in the frames | `evidenceRefs` on votes | — | — | tclk frames become LAP artifacts |
| verdict | who holds the secret releases it | a derived outcome with threshold/quorum/ties | — | tclk's verdict *is* custody; LAP's is a technical result | a tclk release can be attested |
| settlement effect | direct: the secret opens the rail | none | — | this is the whole difference | LAP never has one |
| authority effect | none | none (a verdict grants nothing) | same | — | — |
| conflicts | §8.5: same operator, different keys, "means nothing" | `CONFLICT_SAME_FLEET`, `CONFLICT_PRIOR_ROLE` (`docs/12`, D-105) | same conclusion reached independently | LAP has a disclosure mechanism; tclk names the problem and stops | LAP's fleet check applies to tclk jurors too |
| k-of-n | absent on purpose (§8.4) | threshold policy on votes, no secret sharing | — | different objects | — |

Nothing in §8 is re-implemented beyond `vote_commitment` /
`verify_vote_commitment` (verification only). Secret splitting (§8.2) is
custody of a payment secret and stays out.

## 6. FLOP-native authority vs LineageAuth

| | FLOP-native (as described in `SPEC` §5, §8.6) | LineageAuth |
|---|---|---|
| what it is | an on-chain typed escrow whose policy leaves (`Hash`, `Point`, `Before`, `Sig`, `Threshold`, and/or/k-of-n) release funds | portable, offline-verifiable authority provenance across MCP, A2A, Technocore, GitHub, HTTP, tclk |
| where it is enforced | by the network, in its own time domain | by any verifier holding the events |
| documentation | `UNKNOWN_FROM_OFFICIAL_SPEC` — no public repo, spec or deployment found | this repository |
| delegation / proxy / spend limits | unknown | delegation and attenuation yes; spend limits no (`TCLK_GAP_ANALYSIS.md`) |

**Principle: provider-native authorization remains authoritative. LineageAuth
is additive provenance and policy.** If the FLOP network ships account-level
delegation or spend conditions, they are not bypassed, duplicated or
second-guessed by anything here; a LineageAuth allow is step 4 of 7 in
`VERIFICATION_ORDER`, and "the settlement rail's own checks — never performed
here" is step 7.

## 7. Reason-code mapping

| directive | LineageAuth code | produced by |
|---|---|---|
| AUTHORIZED | `VALID_AUTHORITY_CHAIN` | `check_permission` |
| APPROVAL_REQUIRED | `APPROVAL_REQUIRED` | `check_permission` |
| NO_AUTHORITY | `DENIED` | `check_permission`; also sender ≠ agent; also unknown rail |
| SCOPE_VIOLATION | `SCOPE_VIOLATION` | `check_permission` |
| EXPIRED / REVOKED / SUPERSEDED / CONFLICTED | same | `check_permission` |
| UNSUPPORTED_TCLK_VERSION | `UNKNOWN_VERSION` | `verify_tclk_authority` on a `tclkN ` prefix, N ≠ 1 |
| (malformed frame) | `MALFORMED` | `verify_tclk_authority` |
| SPEND_LIMIT_EXCEEDED | — | not expressible; listed in `unchecked` |
