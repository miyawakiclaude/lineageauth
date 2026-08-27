# Contributing

Contributions are welcome, including ones that tell us the design is wrong.

The most valuable contribution right now is an **independent implementation**
that disagrees with this one. If your verifier and ours reach different verdicts
on the same event bundle, that is a finding — open an issue with both results.

You do not need this repository, this language, or the specification to do it.
[**docs/IMPLEMENTERS_GUIDE.md**](docs/IMPLEMENTERS_GUIDE.md) is the whole
verification rule set on one page, and the
[vectors](https://miyawakiclaude.github.io/lineageauth/conformance/manifest.json)
are served over HTTP so nothing needs cloning.

## Setup

Python 3.12+. No paid service, no account, no network after install.

```bash
uv sync --extra dev
```

```bash
uv run pytest
```

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

CI runs exactly those commands, plus a check that regenerating `examples/`
produces byte-identical files and a scan for private key material.

## Ground rules

### Never commit key material

No private seeds, JWK `d` values, wallet keys, API secrets, or tokens — not in
code, tests, fixtures, docs, screenshots, or commit messages. Test keys are
derived at runtime from a public constant in `tests/testkeys.py` and are unsafe
by construction. Use those.

### Don't hand-roll crypto or canonical JSON

RFC 8785 canonicalization comes from the `rfc8785` library; Ed25519 comes from
`cryptography`. Patches that reimplement either will be declined regardless of
correctness.

### Fail closed

Deny by default. An unknown protocol version, unregistered event type,
unsupported DID method, or ambiguous current root must produce a refusal with a
reason code — never a permissive fallback, and never a bare boolean.

### Say what a result does not mean

A verified signature is not an authorization decision and not an identity claim.
Any new status, API field, or UI string that could be read as "trusted",
"official", or "safe" will be sent back.

### Protocol changes need a decision record

If a change affects canonicalization, signatures, authority resolution,
recovery, conflict handling, or interoperability, add an entry to
[docs/29_DECISIONS.md](docs/29_DECISIONS.md) using the template at the bottom:
problem, options, decision, security impact, interop impact, migration.

Do not invent protocol semantics in an implementation. If the spec is silent,
say so in the record and pick the conservative behaviour.

### Tests are not optional for protocol code

New event types, scope rules, or verification paths need vectors. Property tests
are preferred where an invariant can be stated — for example that a child
delegation never holds a permission its parent lacked.

## Zero-cost policy

The project runs at **¥0/month** and that is a product constraint, not a
preference. A patch that introduces a paid service, a paid API, a service that
can silently meter, or a custom domain will not be merged without a recorded
decision. Free tiers need a verification date in
[infra/cost-policy.yaml](infra/cost-policy.yaml).

The core protocol must stay fully usable with no hosted service at all.

## No external side effects in tests

Tests must not reach the network. Technocore integration is tested against a
mock transport; there are no live writes in the suite, ever.

## Commits

Explain *why*, not *what* — the diff already says what. Note any behavioural
change a downstream verifier would observe.

## Reporting security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree your contributions are licensed under Apache-2.0.
