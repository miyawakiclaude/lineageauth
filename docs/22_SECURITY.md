# 22 — Final Security Threat Model

## Threats

- operational key theft
- root key theft/loss
- recovery key theft
- resolver omission
- stale status
- malicious indexer
- replay
- TOCTOU
- prompt injection
- confused deputy
- semantic GET write
- XSS
- SSRF
- URL auto-fetch
- scope escalation
- forged attestations
- fake adoption/Sybil
- jury collusion
- task spam
- dependency compromise
- log leakage
- secret leakage

## Required controls

### Keys
- local signer
- offline root/recovery recommendation
- wallet isolation
- no private keys in browser
- no private seeds as CLI args

### Authority
- deny-by-default
- attenuation
- revocation
- epoch
- conflict fail-closed

### Approval
- exact action
- short expiry
- random nonce
- replay store
- final re-check

### Network
- allowlist semantic endpoint classes
- SSRF prevention
- no untrusted URL auto-fetch
- TLS in production

### UI
- CSP
- escaping
- no raw HTML
- link safety

### Evidence
- distinguish self-claim / signed claim / independent attestation
- do not promote repeated collusive attestations invisibly

### Jury
- disclose conflicts
- quorum
- signed votes
- no legal claims

### Availability
- short TTL
- stale label

## Production security gates

- dependency scan
- SAST
- fuzz parsers
- property tests authorization
- secrets scan
- threat review before enabling any external write automation

---

## What attacking this actually found — 2026-08-28

The lists above name threat *classes*. This section names the ones that were
real in this code, because a class nobody has instantiated is a word, and a
reviewer deserves to know which words had something behind them.

Thirty findings came from a review of the whole tree. Each was reproduced before
it was fixed and each fix has a test that fails without it. What follows is not
the list of thirty; it is the four shapes they fell into, because the shapes are
what generalise.

### Refusal is the attack

The most common mistake here, and the least intuitive. Three instances:

**Appending a proof deleted an event.** Proofs sit outside the payload and do not
affect the event id, so anyone holding no key could append a nonsense proof to a
copy of a signed event. Admission refused any envelope carrying one bad proof, so
the copy was discarded whole — and a mirror serving only that copy made the event
vanish. `resolver omission` was on the threat list above; what was not seen is
that omission could be achieved *at the door*, before the union merge that exists
to prevent it. (D-087.)

**A stolen root key could veto its own replacement.** Two authorized successions
out of one epoch halted the lineage as `CONFLICTED`. Recovery exists for the case
where the root key is the compromised one — so the thief could sign an ordinary
succession, collide on purpose, and freeze the lineage permanently. The event is
public; anyone can keep a copy in the bundle; re-signing with every member
changed nothing. (D-088.)

**Respelling a number made a recovery policy unreadable.** RFC 8785 normalises
`2.0` to `2`, so both spellings share a preimage, a signature and an event id
while Python holds one as `int` and the other as `float`. One character, no key,
and a signed `recovery.policy` still verified but no longer parsed. (D-002 note,
fixed in the canonical-form check.)

**`conflict fail-closed` appears in the controls above as if it were a safety
property.** It is one only where a stranger cannot reach the switch. Where they
can, closing *is* the attack, and the line in that list does not distinguish the
two cases.

### A builder is a convenience; a verifier is a rule

Four instances, and the count is the point. A constraint enforced only where
events are *drafted* is skipped by anyone who writes the payload by hand:

- an approval receipt naming its own agent as approver
- an `availability.statement` with a window longer than seven days
- a `dispute.open` seating more than 32 jurors
- an `mcp` resource with a prefix other than `server:`

None granted authority that was not held. All of them let a hand-made event
reach a code path that had assumed the builder's guarantee.

### Standing, not authority

An agent could not widen its own scope. It could change *who appeared to have
granted* it: delegate to a throwaway key and back again, attenuating correctly at
every edge, and thereby appear among the issuers on its own authorizing path —
which is the set consulted to decide who may sign an approval. Every individual
check passed. `confused deputy` covers this in name; the chain walk refused loops
by event id, which stops only a grant naming itself as its own parent. (D-086b.)
The loop rule was later withdrawn as both over- and under-inclusive (D-105), and
the set consulted stopped being read off the chain at all: a grant now designates
its approvers, and a child may only narrow the list (D-107).

### The guard that is not on duty

`check_execution` took `store=None` and, with it, ran neither the spent check nor
the reservation — returning `may_execute=True`, `reserved=False`, and no warning.
One human approval became an unlimited licence for any caller who did not read
the second field. The module's own header calls "never let one receipt be spent
twice" one of its two rules. (D-089.)

Adjacent: the pre-push secret scanner reported "clean" when `git ls-files` failed
and skipped files it could not decode as UTF-8 — which on Windows is what
PowerShell's `>` writes. **The likeliest encoding on the operator's own console
was the blind spot in the check guarding the irreversible step.** (D-095.)

---

## What a second reader is for

This document has had one reader, and everything above was found by that reader
attacking their own work. That is worth exactly what it is worth: **the bug that
survives self-review is the one where the test and the code share an assumption**,
and only somebody else breaks that.

Specific places where a second opinion would be most useful:

1. **The `CONFLICTED` fail-closed design.** D-088 fixed one way a halt could be
   induced. The general question — *can a stranger cause a lineage to stop?* — is
   answered "no, halts are reserved for states only an authorized signer can
   create" (D-034), and that claim has never been attacked by anyone but its
   author.

2. **Omission, beyond the door.** Union merge and the D-087 change stop
   *addition* from working as *deletion*. Nothing stops a source from simply
   never handing you a revocation, and `resolver.py`'s freshness policy is
   explicitly not completeness. Whether the reason codes make that distinction
   legible enough to act on is a judgement, not a proof.

3. **The approval model against a real integrator.** Exact-action approval,
   spendable once, re-checked at the moment of execution. It has never been
   wired into anything that actually executes.

4. **Whether the two implementations agree for the right reasons.** They agree on
   nine conformance vectors and on canonical bytes under property testing. Both
   were written by one author in one week, so they can share a misreading; the
   unpaired-surrogate divergence (D-091) is what that looks like when it surfaces.

5. **The key file at rest.** scrypt N=2^17, ChaCha20-Poly1305, the DID bound in
   as associated data, one error message for a wrong passphrase and a tampered
   file. Reviewed by nobody.

Reporting: [SECURITY.md](../SECURITY.md). A finding that this document is wrong
about its own threats is as useful as a finding in the code.
