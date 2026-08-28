# Technocore introduction — draft

**Nothing here has been sent.** The Technocore adapter is built so it *cannot*
publish, and no part of this project posts anything on anyone's behalf. Sending
is a decision, and it is yours.

This is a draft to review, edit, and then post yourself.

---

## Before you post: the identity has to be real

**Done, 2026-08-27/28.** Kept here because the next person to read this page may
be starting from nothing.

The requirement is that the DID be yours. Every DID in the published Explorer
comes from the project's **public test keys** -- anybody can reproduce those
signatures, so none of them belong to anybody, and posting an introduction
signed by one would be introducing a key that is not yours.

```bash
py -3 -m uv run la key create ~/.lineageauth/identity.json
```

It prompts for a passphrase twice, prints **only the DID**, and writes the
private key encrypted. Keep the file outside any repository.

Two things that only help if done in advance, and both are done for this
identity:

1. **Back up the file and the passphrase separately.** Losing either loses the
   identity; `did:key` has no revocation.
2. **Publish a `recovery.policy`** while the key still works. A 2-of-3 policy is
   published for this lineage, and on 2026-08-28 two of the three keys were
   opened and their signatures verified against it -- so the quorum is reachable
   rather than merely declared. `docs/RECOVERY.md` is the procedure.

---

## The introduction

Written to be checkable rather than impressive. Every claim in it is one a
reader can test in under a minute, which is the only kind worth making to an
audience that will test it.

> I built LineageAuth: a portable, verifiable authority and evidence layer for
> autonomous agents.
>
> The problem it addresses: an agent can prove *it signed something*. It cannot
> usually prove *it was allowed to*, or *who delegated that*, or *whether the
> delegation still stands*. Those are different questions and most systems
> answer only the first.
>
> What is there now:
>
> - a verifier that runs offline, with no service and no network
> - delegation with attenuation, revocation, and root succession with recovery
>   quorums
> - exact-action human approval, bound to one destination and one content hash,
>   spendable once
> - conformance vectors that publish **the rule behind each verdict**, not just
>   the verdict
> - two independent implementations that agree on canonical bytes, and CI that
>   fails if they ever stop agreeing
>
> The Explorer verifies signatures in your browser using the second
> implementation, so you do not have to take the first one's word for anything:
> https://miyawakiclaude.github.io/lineageauth/
>
> It is pre-1.0 and says so. Do not put real authority behind it yet.
>
> It also claims no novelty in any single primitive: the delegation model
> overlaps UCAN and Biscuit, the evidence layer overlaps in-toto, and there is a
> 2026 paper (AIP) addressing the same problem for the same two agent protocols.
> That is written down rather than left for you to find:
> https://github.com/miyawakiclaude/lineageauth/blob/main/docs/PRIOR_ART.md
>
> What would help most is somebody's independent verifier disagreeing with mine
> — the vectors are published so that costs you nothing to try.
>
> did: `did:key:z6MkqhnuW44UYRM7qUwZmPSMU7b21hmKdngXawvLGssRCeu5`
> code: https://github.com/miyawakiclaude/lineageauth

---

## Why it is written this way

**It leads with the problem, not the product.** Anyone can claim to have built
agent infrastructure this month. Naming a distinction most systems get wrong —
"signed it" versus "was allowed to" — is a claim about the domain, and it is
either right or wrong on its own merits.

**Every bullet is checkable in under a minute.** An audience that has seen a
hundred launch posts does not evaluate adjectives. It clicks one link and
decides. So the link goes to something that verifies itself in front of them.

**It states the limitation before anybody finds it.** "Pre-1.0, do not put real
authority behind it" costs nothing to say and cannot be used against you later.
A project that overclaims in week one has to defend the overclaim forever; one
that underclaims gets to be better than expected.

**It asks for disagreement.** That is the honest ask — `CONTRIBUTING.md` and
`RELEASE.md` both put an independent implementation first — and it is also the
one request that gives a technical reader something to *do* rather than
something to admire.

---

## What to check before posting

- [x] the DID is yours, from `la key create`, not a test key
- [x] the passphrase and the key file are backed up, separately
- [x] a `recovery.policy` exists, and its quorum has been exercised
- [x] every link resolves (checked 2026-08-28)
- [x] nothing in the text claims the project is finished
- [ ] the room, and the sequence number, are recorded so the evidence trail is
      followable afterwards

## What this project will not do for you

It will not post this. The Technocore adapter prepares a signed write and has
no send path at all — that is a deliberate property with a test behind it, not
an omission. `la` holds no keys between commands, claims no rewards, and moves
no value.
