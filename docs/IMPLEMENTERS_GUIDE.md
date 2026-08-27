# Write your own verifier

Everything you need to verify a LineageAuth event, on one page. The goal is
that you can disagree with the reference implementation by this afternoon.

There are already two implementations here — Python and JavaScript — and they
agree. That is worth less than it sounds: **the same person wrote both, in the
same week, and two implementations by one author can share a misreading of the
specification without either being wrong about the other.** A third, by
somebody who is not this project, is the only thing that settles it.

If yours disagrees, [open an issue](https://github.com/miyawakiclaude/lineageauth/issues).
It may well be this project that is wrong, which is why the vectors publish the
rule behind each verdict and not just the verdict.

---

## What an event is

```json
{
  "payload": { "protocol": "lineageauth", "version": "0.1", "type": "root.create", ... },
  "proofs":  [ { "alg": "Ed25519", "signer": "did:key:z6Mk...", "sig": "<base64url>" } ]
}
```

Proofs sit **outside** the payload. That is deliberate: one payload can carry
many signatures, which is what makes a recovery quorum expressible at all.

## Verifying one event

Four steps. Three of them are where implementations diverge.

### 1. Canonicalize the payload — RFC 8785 (JCS)

The three rules that actually bite:

- **Object keys sort by UTF-16 code unit**, not by code point. These differ for
  characters outside the BMP. `"�"` sorts *after* `"😀"` (U+1F600)
  because `0xD83D < 0xFFFD` — sorting by code point gives the opposite order and
  a different event id. If your language sorts strings by code point (Python,
  Go, Rust all do), you must convert.
- **Numbers** use ECMAScript `Number::toString`, with the one exception that
  `-0` serializes as `0`.
- **No whitespace anywhere.** Strings escape only what JSON requires; other
  control characters become `\u00xx`.

Use a library if one exists for your language. The reference implementation
delegates this to `rfc8785` precisely because it is easy to get subtly wrong.

### 2. Build the signing preimage

```
b"lineageauth:event:v1\n" + JCS(payload)
```

Byte for byte, including the trailing newline in the prefix. One character of
difference here and nothing you produce will interoperate with anything.

### 3. Decode the signer's `did:key`

```
did:key:z<base58btc>
```

- Reject DID URLs: anything containing `#`, `?`, `/` or `;`. `did:key:zAAA#zBBB`
  must never be treated as `did:key:zAAA`.
- Multibase prefix must be `z` (base58btc).
- Decode to **34 bytes**: a 2-byte multicodec followed by the 32-byte key.
- The multicodec must be `0xED 0x01` (Ed25519). **`0xEC 0x01` is X25519** — a
  syntactically perfect `did:key` that is a key-agreement key and not a signing
  key. Reject it.

### 4. Verify the signature

Ed25519 over the preimage from step 2. `alg` must be `"Ed25519"`.

The signature is **unpadded** base64url. Reject `=` padding, and reject
non-canonical trailing bits — re-encoding the decoded bytes must reproduce the
input exactly. Otherwise one signature has two encodings and one event has two
ids.

## The event id

```
"sha256:" + hex(SHA-256(preimage))
```

Lowercase hex. This is a hash of the signed bytes, so a verified id stays
verified — which is why it is safe to use as a cache key.

## What must be refused

Deny by default. Each of these was a bug here before it was a rule:

| | |
|---|---|
| an unregistered event `type` | never give it semantics; an admitted event reads as a counted one |
| a `version` outside the supported set | refuse |
| an envelope with **no proofs** | it asserts nothing |
| padded or non-canonical base64url | one signature, one encoding |
| a non-Ed25519 multicodec | see step 3 |
| a DID URL as a signer identity | see step 3 |

Unknown **fields** are a different matter: display them, do not reject them.
A closed schema turns a forward-compatible event into a validation failure.

## Test against the vectors

```
https://miyawakiclaude.github.io/lineageauth/conformance/manifest.json
```

Each entry gives a file, the verdict a conforming implementation must reach,
and **the rule behind it**. No cloning required.

```
expect: "must-verify"   every document in the file verifies
expect: "must-refuse"   at least one does not
```

A raised error counts as a refusal. Refusing an X25519 `did:key` before you ever
reach a proof is correct.

Some entries carry an `authority` block. Those additionally fix a permission
decision at a given time, because **integrity and authority are separate
questions** and a vector can pin both.

### The vector worth reading twice

`receipt-not-signed-by-its-worker` carries **three different verdicts on one
bundle**, and confusing them is the mistake it exists to catch:

- the envelopes **verify** — integrity is about signatures over payloads;
- the artifact registration is **admitted**, with its `createdBy` reported as a
  claim nobody holding that key signed;
- the receipt's authorship claim **does not stand at all** — a receipt is the
  worker's own assertion, so one naming a worker who did not sign it must not
  borrow their name.

Failing the envelope is wrong. Crediting the worker is wrong. "Verifies" and
"is true" are different questions.

## Beyond one event

Verification is where most of the divergence risk lives, so start there. If you
go further, the two rules that catch people:

- **Merging copies of one event id takes the union of the proofs.** Never select
  one copy over another by any total order over the content — selecting is
  exploitable *without a private key*, because it lets a hostile mirror suppress
  a signature from a recovery quorum. Omission is the attack.
- **Never break a tie by `issuedAt`.** Timestamps are self-asserted. Competing
  root successions at one epoch are `CONFLICTED`, which is a real answer and
  fails closed.

## The reference implementations

- Python: [`packages/py/lineageauth/`](../packages/py/lineageauth/) — the one with all the layers
- JavaScript: [`packages/js/lineageauth.js`](../packages/js/lineageauth.js) — dependency-free, ~350 lines, runs in Node and the browser

Read the second one if you want a short model of exactly this page. Read
neither first if you can help it: an implementation written from the
specification is worth more than one written from another implementation,
because the whole point is to find where the specification is unclear.
