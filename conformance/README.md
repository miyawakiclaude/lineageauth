# Conformance vectors

`CONTRIBUTING.md` asks for one thing above everything else: **an independent
implementation that disagrees with this one.** A disagreement is only useful if
both sides answered the same question, so this package fixes the questions.

## What is here

- `manifest.json` — every vector, the verdict a conforming implementation must
  reach, and the rule behind it
- `vectors/*.json` — each file is a JSON array of envelopes

Both are generated:

```bash
py -3 -m uv run python scripts/generate_conformance.py
```

Deterministically. Regenerating produces byte-identical files, so a diff here
is a protocol change and never a formatting one. A test enforces that.

## How to use it

For each entry in `manifest.json`:

1. Load `file` — an array of envelope documents.
2. Verify each one with your implementation.
3. `expect: "must-verify"` means **every** document verifies.
   `expect: "must-refuse"` means at least one does not.
4. Where an entry carries an `authority` block, additionally resolve the named
   action at the named time and check the decision and reason code.

A raised error counts as a refusal. An implementation that rejects an X25519
`did:key` before it ever reaches a proof has still refused, which is the
correct outcome; what must not happen is a refusal-shaped document coming back
admitted.

## The negative vectors are the point

Anyone can accept a valid event. The value is in refusing the right things for
the right reasons, and most of these were bugs in this implementation before
they were vectors:

| vector | the rule it pins |
|---|---|
| `tampered-payload` | the signature covers the canonical payload |
| `padded-base64url` | unpadded base64url only, or one signature has two encodings |
| `unregistered-event-type` | an admitted event reads as a counted one, so unknown types fail closed |
| `wrong-multicodec-did` | a `did:key` can be syntactically fine and not a signing key |
| `no-proofs` | an envelope with no proof asserts nothing |

## One vector deserves reading twice

`receipt-not-signed-by-its-worker` carries **three different verdicts on one
bundle**, and getting them confused is the mistake it exists to catch:

- the envelopes **verify** — integrity is about signatures over payloads, and
  these are intact;
- the registration is **admitted**, with `createdBy` reported as a claim nobody
  holding that key signed;
- the receipt's authorship claim **does not stand at all** — a receipt is the
  worker's own assertion, so one naming a worker who did not sign it must not
  borrow their name.

An implementation that fails the envelope is wrong. One that credits the worker
is wrong. "Verifies" and "is true" are different questions and this protocol
keeps them apart everywhere.

## If you disagree

Open an issue. **It may well be this implementation that is wrong** — that is
why the rules are written out rather than just the expected verdicts, so a
disagreement can be about the rule instead of about whose code it is.

## The keys

Every signature here comes from public, reproducible test keys derived from a
fixed domain string. Nothing in this directory is safe key material and none of
these DIDs may be used for anything real.
