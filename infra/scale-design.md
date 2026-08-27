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

## Not selected, and why the register says so

[`cost-policy.yaml`](cost-policy.yaml) lists the candidates under
`candidates_not_selected` with the free tiers checked on 2026-08-27 and one real
constraint recorded there: Cloudflare Workers allow 10 ms CPU per request on the
free plan, and Ed25519 verification over a whole bundle **has not been measured
against that**. If it does not fit, the ¥0 answer is precomputed static files,
not a paid plan.

## The rule, once more

Growth is a success signal. Numbers first, then the smallest option, then a
human decision, then provisioning — and `on_free_limit_exceeded: stop_or_degrade`
means the service stops or degrades in the meantime rather than quietly
starting to cost money.
