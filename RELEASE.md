# v1 release checklist

**v1 is not close, and this document exists to say why rather than to imply
otherwise.** Everything in `docs/29_DECISIONS.md` currently ends with
`Migration: Pre-1.0`, which means shapes may still change without a migration
path. The README says the same in fewer words: do not put real authority behind
this yet.

What follows is the list of things that would have to become true. It is
written now, while nothing is under pressure, because a release checklist
assembled the week of a release is a list of reasons to ship.

## Already true, and checked by a test

These are not aspirations. Each one has a test that fails if it stops holding —
see `tests/test_final_gate.py`, `tests/test_zero_cost.py`,
`tests/test_conformance.py`.

- [x] the whole system runs locally at ¥0, and that list is executed rather than asserted
- [x] no paid service, no billing, no automatic upgrade
- [x] no company resource, identity, or path — scanned on every test run, and the scan has a control
- [x] no secret in the tree
- [x] no unapproved external side effect: the API accepts no events, the Technocore adapter has no send path, no MCP tool can sign
- [x] the index is derived, and the restore drill proves it byte for byte
- [x] conformance vectors publish the rule behind each verdict, and this implementation reaches them
- [x] every parser returns or raises a `LineageAuthError`, under fuzzing
- [x] JSON Schema for every registered event type, each saying what it cannot check
- [x] the CLI runs on a legacy console encoding
- [x] `MIGRATION.md` describes behaviour the code actually has

## Required for v1, and not yet true

### An independent implementation, by somebody who is not this project

**Half done, and the half that is done is the smaller half.**

`packages/js/` is a second implementation. It re-derives RFC 8785
canonicalization, base58btc, the multicodec check, the signing preimage and the
event id from the specification rather than porting them, and it takes only
SHA-256 and Ed25519 from WebCrypto. It agrees with the first implementation on
all nine conformance vectors and on canonical output for every payload
hypothesis can generate, including the shapes that separate UTF-16 code-unit
ordering from code-point ordering. CI fails if they ever diverge.

That establishes the specification is implementable **twice**. It does not
establish that it is implementable **by somebody else**, and the second is what
this line is really asking for: both of these were written by the same author in
the same week, so they can share a misreading of the document without either
being wrong about the other.

Until an outside implementation has run `conformance/` and either agreed or
found this project wrong, "the specification is implementable" remains partly an
opinion held by whoever wrote both sides. `CONTRIBUTING.md` asks for that, and
the vectors are published so it costs a stranger nothing to try.

What has been done to make that ask answerable, rather than only stated:
`docs/IMPLEMENTERS_GUIDE.md` compresses the verification rules to one page, so
the entry cost is an afternoon rather than 4,000 lines of specification. The
guide is checked against the code by `tests/test_implementers_guide.py` —
every constant, every link, every claim about the vectors — because a
shortcut that drifts teaches an implementation that fails the vectors and
blames the protocol. None of that makes this line true. It removes the
reasons a stranger would stop before starting, which is the only part of it
this project can do by itself.

### ~~The pre-1.0 marks are gone from the decision log~~ — resolved into the line below, 2026-08-28

This asked for 46 of 100 entries to be gone through. Reading them found that
**most of those marks were never statements.** `Migration: Pre-1.0` is the
template's default, and it had been filled in by habit on decisions with nothing
to migrate: a pre-push hook, a text colour, how CI annotations are rendered, a
document. A decision about a CSS token has no consumers and no migration path,
and saying "this may still change" about it told a reader nothing except that
nobody had looked.

32 entries now say what is actually true of them -- `none`, with the reason, for
the internal ones, and the migration they genuinely impose for the behaviour
that changed on 2026-08-28. **Fourteen remain, and every one defines a payload
shape, a published schema, or an artifact somebody else's code reads.** Those
fourteen are not a separate problem from the next section; they are its content.

### Wire formats are frozen — 22 of 28 event types, 2026-08-28

`conformance/frozen-shapes.json` records the payload keys every event type
always carries, and `tests/test_frozen_shapes.py` fails when a builder stops
matching. The promise is that a **frozen** family will not gain, lose or rename
a required key without a decision entry saying what changed and what a holder of
older events should do. Adding an *optional* key stays compatible and is not
constrained -- a contract that forbade compatible changes would be edited out of
the way the first time it was inconvenient.

**Frozen:** evidence, work, fleet, impact, jury, passport — 22 event types,
covered by `D-051`, `D-053`, `D-055`, `D-059`, `D-060`, `D-061`, `D-062`, plus
the resolver output (`D-064`), the published schemas (`D-068`) and the
conformance manifest (`D-069`).

**Held, and the last thing on this list that is anyone's to decide:** the
`authority` family — `D-026`, `D-039`, `D-043`, `D-063`, six event types.
`docs/PRIOR_ART.md` finds this layer overlaps UCAN and Biscuit substantially. If
the right answer is to become a profile of one of them, these shapes change, so
freezing them first would only mean unfreezing them later. They are recorded and
watched rather than promised.

`work.receipt` is derived from other events and has no payload of its own.

Verified by renaming `artifactId` to `artifactID` in a builder and watching the
test name the family, the event and both sides of the difference. A contract
nobody has broken on purpose is a contract nobody has checked.

### The threat model has been reviewed by somebody else

**Still open, and it is a person rather than a task.** What changed on
2026-08-28 is that the document is now worth somebody's hour.

It was 84 lines of threat *names* — "resolver omission", "confused deputy",
"replay". A reviewer handed a checklist spends their first hour discovering
things the author already knows, and there is only going to be one reviewer.

It now also records what attacking this code actually found: the four shapes the
thirty findings fell into, the places where the controls list above is
misleading (`conflict fail-closed` is a safety property only where a stranger
cannot reach the switch), and five specific places a second opinion would help —
two of them marked as never exercised by anyone at all.

The requirement is unchanged: the class of bug that survives self-review is the
one where the test and the code share an assumption, and only a second person
breaks that. **This line becomes true when a reviewer says something, not when
somebody is asked.**

### ~~Recovery has been rehearsed, not only tested~~ — done, 2026-08-27

`scripts/recovery_drill.py` creates real encrypted key files, opens a lineage,
**deletes the root key**, and rebuilds authority from the published bundle and a
2-of-3 quorum -- reading everything after the deletion out of the bundle rather
than out of the variables that produced it. It also checks the four refusals,
and `tests/test_recovery_drill.py` runs the whole thing on every suite, so
"rehearsed" keeps meaning "still rehearsed".

The rehearsal was worth more than the result. It passed, but only after finding
five things no test could have:

- **`docs/05` is a specification, not a procedure.** It lists the fields and
  never says what to do on the day. `docs/RECOVERY.md` is the procedure, written
  from what the drill actually had to do, and tested against it.
- **`recoveryPolicyRef` is mandatory and undocumented.** It is the policy
  event's *id*. Nothing said so, and nothing prints it.
- **There is no CLI that issues anything.** `la` verifies and inspects; opening
  a lineage or signing a succession is Python. The runbook says so rather than
  implying a command exists.
- **`getpass` on Windows opens the console rather than reading stdin**, so a
  piped passphrase hung instead of failing. Every operator script here had
  grown a stdin fallback; the shipped CLI had not, which made the one procedure
  nobody can afford to get wrong also the one nobody could rehearse unattended.
- **A survivor needs five facts written down** that cannot be reconstructed
  afterwards. The runbook lists them, and four of the five are readable out of
  the published bundle -- which is now stated as the artifact to back up.

### ~~Performance is measured rather than assumed~~ — done, 2026-08-27

`scripts/benchmark.py` measures verification CPU, native CPython, against the
10 ms per-request budget of the Cloudflare Workers free plan. Verifying one
event fits comfortably (well under 1 ms). Admitting a caller-supplied bundle
does not scale the same way: a 51-event bundle already runs over the budget,
and a 201-event bundle runs several times over it. `infra/scale-design.md`
carries the measured table and is re-checked whenever the number matters.

This did not resolve a v1 blocker — it confirmed one, and closed the question
underneath it. The number was never "is admission fast enough"; it was
"whose bytes get verified, and who decides how many." The caller picks the
bundle size, so a public endpoint that admits whatever it is handed pays
whatever the caller asks it to pay — a denial-of-service shape before it is a
cost problem, and one that does not go away on a paid plan, it just starts
costing money instead of failing. Underneath that is a second, independent
blocker: Python Workers run under Pyodide (WebAssembly), and `cryptography` is
a native package that cannot be imported there, so the verifier does not run
on Workers at all today regardless of CPU budget.

So this is a **design decision, not a defect**: a public dynamic verify
endpoint on the free tier is not the shape to build. The ¥0 answer that was
already the plan — precomputed static files (a passport, an event bundle, both
static JSON) — has no CPU budget to exceed and no bundle a stranger can inflate,
and stays the answer. Nothing here blocks v1; it removes a guess `infra/scale-design.md`
was carrying and confirms the design already pointed the right way.

### ~~The limitations page is written from the outside~~ — done, 2026-08-28

`docs/28_NON_GOALS_LIMITATIONS.md` was a 28-line list for somebody who already
knew why each line was there. It now opens with the largest true statement a
positive result supports -- which is smaller than the word "valid" suggests --
then what is not proven and why that matters to a decision, then the permanent
non-goals so a reader can plan around them rather than wait for them, then the
limits that are real today: a superseded key that keeps signing, omission as the
standing risk, and pre-1.0 meaning what it says.

It ends by naming what to use instead. A limitations page that cannot point
elsewhere is a sales page, so it sends a reader who needs an attenuating
capability chain today to UCAN or Biscuit, and one who needs supply-chain
provenance to in-toto -- and says that reading it and deciding you do not need
this is a perfectly good outcome.

`tests/test_limitations.py` asserts every claim the old list made, one by one.
Rewriting a normative page is the edit where prose improves and a fact quietly
goes missing, and the missing fact is the one somebody needed.

## Explicitly not required for v1

- **a public deployment.** `docs/31`: "A public hosted URL is useful but not
  required to prove protocol correctness." The definition of done contains no
  hosted service, and adding one would be a spending decision needing approval
  recorded in `docs/29_DECISIONS.md`.
- **a paid tier of anything.** `monthly_spend_limit_jpy: 0` is an invariant with
  a test behind it, not a starting position.
- **key custody, token transfer, or reward distribution.** These are permanent
  non-goals, not unfinished work. The core holds no keys and moves no value, and
  `rewardReference` stays an opaque string that points at somebody else's system.

## Cutting a release

When the list above is honestly complete:

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

All three generators are deterministic; a diff from any of them means a
protocol change that needs a decision record before the tag. Then tag, and note
in `docs/29_DECISIONS.md` that `Migration: Pre-1.0` no longer applies.
