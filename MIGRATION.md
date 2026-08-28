# Versioning and migration

`docs/24_VERSIONING_MIGRATION.md` sets the rules. This is what they mean in
practice for anyone holding events produced by an earlier version.

## The one thing that can never change quietly

**An event id is a hash over the canonical payload.** Change the
canonicalization, the preimage, or the id algorithm and every event ever signed
gets a different id — every reference between events breaks at once, and
nothing already signed can be re-signed, because the point of a signature is
that the signer is not around to redo it.

So the signing preimage is frozen:

```
b"lineageauth:event:v1\n" + JCS(payload)
```

The `v1` in that string is not the protocol version. It is the *preimage*
version, and changing it is a new protocol, not a new release of this one.

## What will not change across versions

The signing preimage above is one. The other is the set of payload keys every
event type always carries, recorded in
[`conformance/frozen-shapes.json`](conformance/frozen-shapes.json) and checked by
`tests/test_frozen_shapes.py`.

**Frozen** (22 event types -- evidence, work, fleet, impact, jury, passport): a
required key will not be added, removed or renamed without a decision entry in
`docs/29_DECISIONS.md` saying what changed and what a holder of older events
should do. Adding an *optional* key stays a compatible change and is not
constrained; a contract that forbade compatible changes would be edited out of
the way the first time it was inconvenient.

**Held** (6 event types -- the authority family: delegation, approval, root
succession, recovery policy): no promise yet. `docs/PRIOR_ART.md` finds that this
layer overlaps UCAN and Biscuit substantially, and if the right answer is to
become a profile of one of them these shapes change. Freezing them first would
mean unfreezing them later, so they are recorded and watched rather than
promised.

`work.receipt` is derived from other events and has no payload of its own, so
there is nothing there to freeze.

## What a version bump does and does not permit

`version` on every payload is the **core** version. `catalog.SUPPORTED_VERSIONS`
is what a verifier will admit.

Permitted inside a version:

- **adding an event type** — unknown types already fail closed for authority and
  are displayable-but-inert for evidence, so an old verifier meeting a new type
  behaves safely rather than guessing
- **adding an optional field** — the schemas are open on purpose
  (`additionalProperties: true`), and `docs/24` wants unknown fields displayed
  rather than rejected
- **adding a reason code** — but see below

Not permitted inside a version:

- changing what an existing field means
- making an optional field required
- changing a default in a way that weakens a check
- removing a reason code, or reusing one for a different situation

## Reason codes

Adding a `ReasonCode` requires a version bump. The enum's own docstring says so,
and it is not pedantry: callers switch on these, and a caller that has never
heard of a new code will fall into whatever its default branch is. If that
branch allows, a new refusal silently becomes a permission.

## Deny-by-default is the migration strategy

There is no upgrade script and there does not need to be one, because every
layer already fails closed on what it does not recognise:

| unknown thing | what happens |
|---|---|
| event type not in the catalog | `UNKNOWN_VERSION`; never given semantics |
| `version` not in `SUPPORTED_VERSIONS` | refused |
| namespace not in the registry | scope refused |
| action not in the namespace | refused |
| approval mode not recognised | refused, and it may only strengthen |
| DID method other than `did:key` | refused |
| multicodec other than Ed25519 | refused |

An old verifier reading new events is therefore conservative, not wrong. It
will refuse things it should have allowed, which is the safe direction and
visible immediately, rather than allowing things it should have refused.

## The index and the store

The **store** is authoritative and append-only. The **index** is derived and
may be deleted at any time:

```bash
py -3 -m uv run la index rebuild ./events --db ./index.sqlite3
```

That is the whole migration procedure for anything index-shaped. If a schema
change ever required a data migration in the index, it would mean the index was
holding state that never came from a signed event, which is a bug in the index
and not a migration problem.

`checksum()` before and after a rebuild must match. `tests/test_zero_cost.py`
runs that drill.

## Checking a change

Before publishing a change to anything on this page:

```bash
py -3 -m uv run python scripts/gate.py
```

```bash
py -3 -m uv run python scripts/generate_examples.py
```

```bash
py -3 -m uv run python scripts/generate_schemas.py
```

```bash
py -3 -m uv run python scripts/generate_conformance.py
```

All three generators are deterministic. If any of them produces a diff, the
change is a protocol change: record it in
[`docs/29_DECISIONS.md`](docs/29_DECISIONS.md) with the migration consequences
before merging, and expect the [conformance vectors](conformance/README.md) to
need new entries.

## What is not promised

Nothing here is 1.0 and none of it carries a stability guarantee yet. Every
decision in `docs/29_DECISIONS.md` currently ends with `Migration: Pre-1.0`,
which means exactly what it says: shapes may still change without a migration
path, because nobody should have real authority behind this yet. The README
says the same thing in fewer words.
