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

### The pre-1.0 marks are gone from the decision log

Every entry in `docs/29_DECISIONS.md` says `Migration: Pre-1.0`. Reaching v1
means going through them and, for each, either committing to the shape or
changing it while that is still free. A decision log where every entry says
"this may still change" is not a v1 contract.

### Wire formats are frozen with a stated compatibility promise

`MIGRATION.md` documents what may change inside a version. v1 additionally
requires saying what will **not** change across versions, and meaning it. The
signing preimage is already frozen; event payload shapes are not.

### The threat model has been reviewed by somebody else

`docs/22_SECURITY.md` is the working threat model and it has had exactly one
reader. Several real defects in this repository were found by writing a test
that disagreed with the code — the class of bug that survives is the one where
the test and the code share an assumption, and only a second person breaks that.

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

### Performance is measured rather than assumed

`infra/scale-design.md` names the bottleneck as verification CPU and says the
Cloudflare Workers free-tier limit of 10 ms per request has **not been measured
against** a bundle verification. A v1 should not be guessing about the cost of
its own core operation.

### The limitations page is written from the outside

`docs/28_NON_GOALS_LIMITATIONS.md` lists what this deliberately does not do.
Before v1 it needs rewriting for somebody who has just arrived and is deciding
whether to depend on it, rather than for somebody who already knows why each
line is there.

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
