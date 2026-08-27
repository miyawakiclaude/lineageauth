# Scale targets — designed, not provisioned

`docs/31` is explicit about the order these things happen in:

> If adoption grows beyond free capacity, that is a success signal.
> Do not prepay for hypothetical scale.

So this document is not a migration plan. It is the shape of the answer for
when there are real numbers, written down now so that the thinking is not being
done under pressure later. **Nothing here is provisioned. Nothing here may be
provisioned without a human decision recorded in
[`docs/29_DECISIONS.md`](../docs/29_DECISIONS.md).**

The check that keeps that true is in `tests/test_zero_cost.py` and
`tests/test_final_gate.py`: no paid dependency, no billing flag, no cloud SDK.
If any of this were quietly wired up, those fail.

## What actually has to scale

Be precise about this, because the answer is smaller than it looks.

| thing | grows with | authoritative? |
|---|---|---|
| event store | events, forever (append-only) | **yes** |
| SQLite index | events | no — derived, deletable |
| passports, graphs, routers, exchange | nothing; computed per request | no |
| approval spent-store | approvals, and only until they expire | yes, and small |

Only the first is a durability problem. Everything else is a rebuild away, by
construction — that is what `la doctor` and the restore drill exist to keep
true.

## The bottleneck is CPU, not storage

Signed events are small. A `delegation.grant` is a few hundred bytes and a
million of them is a few hundred megabytes, which is not a problem anybody needs
a plan for.

What costs is **verification**: Ed25519 plus JCS canonicalization, per event,
per bundle, per request. A resolver that re-verifies a whole bundle to answer
one permission check does work proportional to the bundle, and an attacker only
has to pay for sending it. `bundle.py` already indexes by id and type for
exactly this reason (an O(N²) scan is a gift to whoever sends the largest
bundle).

So the first optimisation is never a bigger database. It is:

1. **cache verification by event id** — an id is a hash of the signed payload,
   so a verified id stays verified, and the cache key cannot be forged without
   forging the hash;
2. **answer from a precomputed static file** where the question is not
   per-caller — a passport and an event bundle are both static JSON.

Both are free. Neither needs a service.

## Threshold, and what to measure before spending

Do not migrate on a feeling. `docs/31` asks for numbers, so these are the ones
to have in hand:

- events in the store, and bytes
- p50 and p95 for `check_permission` on a real bundle
- requests per day, and the shape of the peak
- how much of the traffic is the same question repeated
- what fraction can be answered from a static file

If the last two are large, the answer is caching and static export, and it
remains ¥0.

## PostgreSQL — design only

Reach for this only when the **index** must be shared by more than one process
or machine, which is a coordination problem and not a size problem. SQLite
handles far more data than this project will have.

The schema is the SQLite one, unchanged in shape:

```
events(event_id TEXT PRIMARY KEY, event_type TEXT, lineage TEXT,
       issued_at TIMESTAMPTZ, payload JSONB, proofs JSONB)
index on (lineage, event_type)
index on (lineage, issued_at)
```

Notes that matter more than the DDL:

- **it stays derived.** A Postgres index that is treated as authoritative is a
  second source of truth, and the restore drill stops meaning anything. Same
  rule: deletable, rebuildable, `checksum()` must match.
- **`JSONB` reorders keys.** It must never be the source for a signature check —
  canonicalization is over the original bytes, and a payload that has been
  through `JSONB` is not those bytes. Store the canonical document verbatim
  (`TEXT`) if signature checks ever read from the database.
- **no `ON CONFLICT DO UPDATE` on `events`.** Events are immutable; the only
  correct conflict behaviour is to merge proofs (D-036), which the store layer
  already does and the database should not be reimplementing.

**Cost:** every managed Postgres worth using is paid. A free tier exists at
several providers with sleep-after-idle and a small row cap; those are fine for
a demo and are a bad idea for an index somebody depends on, because the failure
mode is silent slowness. Either way: not without approval.

## Object storage — design only

Only needed if **artifact bytes** must be served, and `docs/07` is deliberately
built so they usually do not: an artifact is identified by hash, `uri` is
optional and non-authoritative, and a hash-only receipt is a complete evidence
record.

Before provisioning anything, answer: *whose bytes are these, and does anyone
need them from us?* Usually the artifact already lives somewhere — a repository,
a document, a page — and what this protocol adds is the signed statement about
it, not a second copy.

If bytes really must be hosted:

- content-addressed keys (`sha256/<hex>`), so the store cannot serve something
  other than what was signed for
- immutable, no overwrite — a mutable object under a content hash is a lie
- public read only; anything private does not belong in this layer at all
- serve the hash next to the bytes so a reader can check rather than trust

**Cost:** free allowances exist and are metered by egress, which is the line
item that surprises people. Not without approval.

## Measured: a public verify endpoint does not fit a free Worker

This was carried as an open caveat and is now a number.
`scripts/benchmark.py`, native CPython, against the 10 ms CPU a Cloudflare
Worker gets per request on the free plan (checked 2026-08-27):

| operation | cost | of a 10 ms budget |
|---|---:|---:|
| verify one event | 0.6 ms | 6% |
| admit a bundle of 11 events | 5.0 ms | 50% |
| admit a bundle of 51 events | 25.6 ms | **256%** |
| admit a bundle of 201 events | 138.6 ms | **1386%** |
| one request: admit 51 events, then check | 43.7 ms | **437%** |

**Admission dominates and is linear in events**, because every event in a bundle
is verified and *the caller chooses how many to send*. An endpoint that admits a
caller-supplied bundle pays whatever the caller asks it to pay. That is a
denial-of-service shape before it is a cost problem, and it does not stop being
one on a paid plan — it just starts costing money instead of failing.

There is a second, independent blocker. Python Workers run under Pyodide, which
is WebAssembly, and **`cryptography` is a native package that cannot be imported
there**. So the verifier cannot run on Workers at all today, whatever the CPU
budget. Doing it would mean an Ed25519 and RFC 8785 implementation in JS or WASM
— which is a genuinely valuable thing to exist (`CONTRIBUTING.md` asks for an
independent implementation) but is a project, not a deployment.

**Conclusion: the ¥0 answer is precomputed static files, and that was already
the answer.** A passport and an event bundle are static JSON. Static hosting has
no CPU budget to exceed and no bundle a stranger can inflate.

If a dynamic endpoint is ever genuinely needed, the order is: cache verification
by event id (an id is a hash of the signed payload, so a verified id stays
verified and the key cannot be forged without forging the hash), cap the
accepted bundle size, and only then look at what it costs.

## Not selected, and why the register says so

[`cost-policy.yaml`](cost-policy.yaml) lists the candidates under
`candidates_not_selected` with the free tiers checked on 2026-08-27.

## The rule, once more

Growth is a success signal. Numbers first, then the smallest option, then a
human decision, then provisioning — and `on_free_limit_exceeded: stop_or_degrade`
means the service stops or degrades in the meantime rather than quietly
starting to cost money.
