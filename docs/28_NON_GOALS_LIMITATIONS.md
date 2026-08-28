# 28 — What this does not do

Read this before deciding whether to depend on LineageAuth. It is written for
somebody who has just arrived, not for somebody who already knows why each line
is here.

The short version: **this is pre-1.0, and a valid result from it means far less
than the word "valid" suggests.** If you need any of the things in the first
section below, you need something else — possibly in addition to this, possibly
instead of it. [docs/PRIOR_ART.md](PRIOR_ART.md) says which.

---

## What a positive result actually means

The largest true statement the verifier can make is smaller than most people
expect:

> These bytes were signed by the key this DID names, and the chain of signed
> delegations above it satisfies the rules in this specification, evaluated at
> the time you supplied, against the events you supplied.

Every clause is doing work. "The events you supplied" is doing the most: this
layer never fetches anything, so it can only reason about what is in front of
it. See **Omission**, below.

That is why the verifier never returns "trusted". It returns a reason code —
`VALID_AUTHORITY_CHAIN`, `DENIED`, `REVOKED`, `SUPERSEDED`, `CONFLICTED` — and
whether any of those is good enough is your decision, not its.

## What it does not prove

None of these follow from a valid result, and treating them as if they do is
the most likely way to be hurt by this:

| Not proven | Why it matters to you |
|---|---|
| a **human's identity** | a `did:key` proves control of a private key. Nothing connects it to a person. |
| **legal entity status**, **company employment** | there is no registry behind this and no attestation is checked against one |
| **honesty** or **competence** | key control says nothing about whether the holder does good work, or means well |
| **absence of hidden fleets** | one operator may run many DIDs. Disclosure is voluntary, so "no disclosed fleet" is not evidence of independence — it is the absence of a statement |
| **Sybil resistance** | there is no cost to creating a DID. Counting DIDs counts nothing |
| the **truth of an attestation** | a signed statement proves who said it, never that it is so |
| **payment settlement** | `rewardReference` is an opaque string pointing at somebody else's system. Nothing here moves value or knows whether anything was paid |
| **reward eligibility**, including any **airdrop** | this makes no claim about anyone's eligibility for anything, to anyone |

## What the core will never do

These are permanent non-goals, not unfinished work. Plan around them rather than
waiting for them:

- **hold wallet keys** — the core holds no key material of any kind
- **transfer tokens** or **escrow rewards** — it moves nothing
- **bypass provider authorization** — OAuth, API keys, repository permissions,
  MCP server policy and A2A server policy all still apply. This is provenance
  layered on top; if you use it to skip one of those, you have made a hole
- **make Technocore durable** — the adapter reads a service this project does
  not run and cannot keep alive

## Limits that are real today

### A superseded key still signs

`did:key` has no revocation. After a succession, the old root keeps producing
**mathematically valid signatures forever**. What changes is that this protocol
marks that authority superseded — and only for a verifier that resolves the
lineage rather than checking a signature on its own.

If a key is compromised rather than lost, understand exactly what recovery buys:
the thief can still produce events that verify. They cannot produce events that
carry *current authority* in a lineage that has moved past them. Any consumer
checking signatures without resolving authority gets no protection at all.

### Omission

This is the sharpest limit and the least obvious. A verifier can only judge the
events it was given, so **anyone who controls what you receive can change the
answer by leaving something out** — most damagingly a revocation.

The protocol defends what it can: merging copies of one event takes the union of
their proofs, never a selection, and an unverifiable proof is discarded rather
than condemning the event it rides on (D-036, D-087). Neither helps if a source
simply never hands you the revocation.

**For any high-risk decision, use several sources and a freshness policy.**
`resolver.py` exists for this and will name the mirror that omitted something —
but freshness is not completeness, and nothing here can prove you have
everything.

### A jury verdict is not a ruling

Dispute outcomes are what a stated procedure produced from signed votes. They
are protocol and community evidence. They are **not legal arbitration** and not
a finding about the world.

### Conflict handling stops rather than guesses

Two incompatible successions out of one epoch resolve to `CONFLICTED` and new
authority fails closed. That is deliberate — the alternative is preferring one
by timestamp, and timestamps are self-asserted. It does mean a lineage can be
stopped, and a threshold recovery quorum outranking a single-key succession
(D-088) exists because the obvious version of this could be weaponised.

### Pre-1.0

Schemas and semantics will change. The signing preimage is frozen; event payload
shapes are not. Roughly half the entries in
[docs/29_DECISIONS.md](29_DECISIONS.md) are still marked `Migration: Pre-1.0`,
which means exactly what it says.

## If you are deciding right now

**Do not put real authority behind this yet.** Nothing in it has been
implemented by anyone outside this project, and its threat model has had one
reader. Both are listed in [RELEASE.md](../RELEASE.md) as requirements for v1
that are not met.

If you want an attenuating capability chain today, [UCAN and
Biscuit](PRIOR_ART.md) are more mature and have been implemented by more people.
If you want supply-chain provenance, in-toto and DSSE are the established
answer. This is worth your attention if the specific combination — offline
verification, root recovery, and human approval bound to one exact action — is
what you need, and you can accept that the combination is unproven.

Reading it and concluding that you do not need it is a perfectly good outcome,
and a faster one to reach than most projects allow.
