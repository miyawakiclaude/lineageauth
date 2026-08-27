# Recovering a lost root key

`did:key` has no revocation. If you lose the root key and its passphrase and
have published nothing else, the identity is gone permanently, along with the
standing of everything ever signed under it.

A `recovery.policy` is the way back, and it only helps somebody who published
one **while the root key still worked**. If you are reading this before anything
has gone wrong, that is the section to act on.

`docs/05_RECOVERY_SUCCESSION.md` specifies the rules. This is the procedure.
`scripts/recovery_drill.py` executes it end to end, and was written first — every
step below is a step that script actually had to take.

---

## Before you need it

Publish a recovery policy naming keys you can still reach after a fire:

```bash
py -3 -m uv run la key create recovery-1.json
```

Three keys, threshold two, each with **its own passphrase**, stored apart from
each other and from the root. Three key files in one folder is one key file.

The root must not be one of the members. A root that can vote to replace itself
is not a quorum, it is the same single point of failure with extra steps.

Then open the lineage and publish `root.create` and `recovery.policy` together
(see [Building the events](#building-the-events) — this has no CLI yet).

### Write these five things down, somewhere that is not this machine

The drill exists because it found out what a survivor cannot reconstruct:

| | Why you cannot recover it later |
|---|---|
| the **root DID** | it appears in your published bundle, so keep the bundle; without either, nothing tells you which lineage you are recovering |
| the **lineage id** | derived from the root DID, so it is lost with it |
| the **recovery policy's event id** | it is the mandatory `recoveryPolicyRef`, and it is a hash of the policy — recomputable **only if you still have the policy event** |
| **which files are the members**, and where they are | a recovery key you cannot find is not a recovery key |
| **where each passphrase is** | three distinct passphrases mean three chances to be locked out |

The single most important artifact is the **published bundle** — the JSON array
holding `root.create` and `recovery.policy`. It is entirely public: DIDs and a
threshold, nothing secret. Copy it somewhere it will survive you losing this
machine. Four of the five rows above can be read straight out of it.

---

## The day the root key is gone

You need: the published bundle, and enough recovery key files to meet the
threshold, with their passphrases.

### 1. Confirm what you are recovering

```bash
py -3 -m uv run la lineage show lineage.json
```

This prints the lineage, the current root and the epoch. If it does not resolve,
stop — the bundle is incomplete, and adding a succession to a bundle that does
not resolve will not fix it.

### 2. Create the new root

```bash
py -3 -m uv run la key create new-root.json
```

A fresh key, a new passphrase, stored apart from the recovery keys.

Do not promote one of the recovery keys to be the new root. Nothing stops you,
and the succession will verify, but that key then holds two roles at once: it is
both a member of the quorum and the thing the quorum exists to replace. If you
must, publish a fresh recovery policy immediately afterwards that no longer
names it.

### 3. Build and sign the succession

`mode` is `recovery`, and `recoveryPolicyRef` is **the event id of your
`recovery.policy` event** — not its `policySeq`, not the lineage. `docs/05`
lists the field without saying what goes in it; this is what goes in it.

It must be signed by a threshold of **distinct** members. Two proofs from one
key is one vote, and the resolver refuses it.

### 4. Check before you publish

```bash
py -3 -m uv run la lineage show recovered.json
```

Expect the new root, `epoch` one higher than before, and
`VALID_AUTHORITY_CHAIN`. Anything else means do not publish it yet.

`CONFLICTED` here means two incompatible successions claim the same epoch step.
That is not a bug to work around: it fails closed on purpose, and it will not be
resolved by publishing a third one or by adjusting a timestamp. Find out which
succession you did not make.

### 5. Afterwards

Publish a **new recovery policy** under the new root. The old policy belongs to
the old epoch, and you have now spent whatever secrecy the used members had.

---

## Building the events

There is **no CLI command that creates a lineage or a succession.** `la` verifies
and inspects; it does not issue. Until that changes, this step is Python:

```python
from lineageauth import keyfile
from lineageauth.builders import build_root_succession, sign_payload
from lineageauth.canonical import compute_event_id

policy_ref = compute_event_id(policy_payload)  # step 3's reference
quorum = [keyfile.unlock(path, passphrase) for path, passphrase in members]
envelope = sign_payload(
    build_root_succession(
        lineage=lineage,
        from_root=old_root,
        to_root=new_root_did,
        from_epoch=current_epoch,
        mode="recovery",
        recovery_policy_ref=policy_ref,
        issued_at=now,
    ),
    quorum,
)
```

Two things that cost the drill time:

- `keyfile.create` returns the **public half only** — a DID and a path, with no
  way to sign. To use a key you just made, unlock the file. This is deliberate:
  nothing in the library hands back something that can be copied.
- a published bundle is a JSON **array of documents**. Load it with
  `Envelope.from_json` per document, then `EventBundle.from_envelopes`.

`scripts/recovery_drill.py` is a worked example of all of it.

---

## What recovery refuses

Checked by the drill on every run, because a recovery that accepts anything is
not a recovery:

| | |
|---|---|
| fewer signatures than the threshold | refused |
| a signature from somebody the policy does not name | refused |
| the same member signing twice to look like two | refused |
| a real quorum pointing at a policy that does not exist | refused |

In each case the lineage **holds at the old root** rather than erroring. That is
the fail-closed behaviour: a rejected succession leaves you where you were.

---

## What recovery does not do

Succession moves *authority*. It does not and cannot invalidate mathematics:
**signatures made by the old key stay cryptographically valid forever.** What
changes is that the protocol marks that authority superseded, so a verifier
following the rules will not grant current authority from it.

If the old key was compromised rather than lost, understand what this does and
does not buy: anyone holding it can still produce events that verify. They
cannot produce events that *carry current authority* in a lineage that has moved
past them — provided the verifier resolves the lineage rather than checking the
signature alone.

---

## Rehearse it

```bash
py -3 -m uv run python scripts/recovery_drill.py
```

It creates throwaway keys, opens a lineage, **deletes the root key**, recovers
from the published bundle and a quorum, and checks the refusals. About four
seconds, no network, nothing of yours touched.

Run it after changing anything in this document. A runbook nobody has executed
is a design, and the day you need this one is the worst possible day to find out
which step was missing.
