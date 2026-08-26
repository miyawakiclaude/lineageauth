# Examples

> ## ⚠ UNSAFE TEST MATERIAL
>
> Every signature in this directory was produced by a **deterministic key
> derived from a public constant**. The private keys are trivially reproducible
> by anyone who reads [`tests/testkeys.py`](../tests/testkeys.py) — that is
> deliberate, so an independent implementation can regenerate these files
> byte-for-byte and check its own results against them.
>
> **None of these DIDs may be used for anything real.** They control nothing and
> prove nothing.

## Regenerating

```bash
uv run python scripts/generate_examples.py
```

Output is deterministic: fixed keys, fixed issuance times. If regenerating
produces a diff, the protocol changed — that is the point.

## The lineage these files describe

```text
lineage   lineage:la:z6Mkj3MFJwUVhEAMBQQ4oRsNJLrvtX3ZbKiLnnXuz8v9tfs2
root A    did:key:z6Mkj3MFJwUVhEAMBQQ4oRsNJLrvtX3ZbKiLnnXuz8v9tfs2   (epoch 0, genesis)
root B    did:key:z6MkhCQKL9KABp6NQ5suPTC5R1pn1j9MHr8jQaVVcZQwQc9z   (epoch 1, after recovery)
recovery  three keys, threshold 2
```

The lineage identifier is anchored to the *genesis* root and does not change
when the root does. That continuity across a key change is the thing this
protocol exists to provide.

| File | What it is |
|---|---|
| `root-create.json` | Opens the lineage at epoch 0. Signed by root A. |
| `recovery-policy.json` | Names three recovery members with threshold 2. Signed by root A. |
| `root-succession-normal.json` | Root A hands over to root B voluntarily. One proof. |
| `root-succession-recovery.json` | Root A is lost; two of three recovery keys install root B. Two proofs. |
| `tampered-root-create.json` | `root-create.json` with `epoch` edited to `1`. Must fail. |

## Try it

```bash
uv run la verify examples/root-create.json
```

```bash
uv run la verify examples/tampered-root-create.json
```

The second exits non-zero and reports `INVALID_SIGNATURE`, naming the proof that
failed and why.

## What a passing result does and does not mean

`SIGNATURE_VERIFIED` means: these bytes were signed by these DIDs, and nothing
has been altered since.

It does **not** mean the action is authorized, that the signer is the lineage
root, that the root is current, or that any human approved anything. Those are
authority questions, answered by a separate layer over the same events — and
that layer is not implemented yet.
