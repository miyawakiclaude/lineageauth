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
| `delegation-allowed.json` | Genesis + a root grant of `technocore:room:lobby [read,write]` to the agent. |
| `delegation-revoked.json` | The same, plus the root's revocation of that grant. |

The agent in the delegation bundles is
`did:key:z6MkqFRbThS1M62TP7pUYo8DGxizE5TD66mbf6vXh6kmyE6X`.

## Try it

```bash
uv run la verify examples/root-create.json
```

```bash
uv run la verify examples/tampered-root-create.json
```

The second exits non-zero and reports `INVALID_SIGNATURE`, naming the proof that
failed and why.

Resolve who currently holds the lineage:

```bash
uv run la lineage show examples/delegation-allowed.json
```

Then Demo A from [docs/26](../docs/26_LAUNCH_ADOPTION.md) — delegate, allow,
revoke, deny. The agent is authorized here:

```bash
uv run la check examples/delegation-allowed.json --agent did:key:z6MkqFRbThS1M62TP7pUYo8DGxizE5TD66mbf6vXh6kmyE6X --namespace technocore --resource room:lobby --action write
```

and refused here, naming the revocation that did it:

```bash
uv run la check examples/delegation-revoked.json --agent did:key:z6MkqFRbThS1M62TP7pUYo8DGxizE5TD66mbf6vXh6kmyE6X --namespace technocore --resource room:lobby --action write
```

## What a passing result does and does not mean

`SIGNATURE_VERIFIED` means: these bytes were signed by these DIDs, and nothing
has been altered since.

It does **not** mean the action is authorized, that the signer is the lineage
root, or that the root is current. Those are separate questions, answered by
`la lineage show` and `la check` over the same events.

`VALID_AUTHORITY_CHAIN` from `la check` means: a chain of grants, each a proper
attenuation of the one above it, runs from the current root of this lineage to
this agent and covers this exact action, and nothing on that chain is revoked,
expired, or superseded.

It still does **not** mean the provider will let the action through. OAuth, API
keys, repository permissions, and MCP or A2A server policy all apply
independently and are never bypassed. Nor does it mean a human approved
anything — that is an approval receipt, and it is not implemented yet. A chain
whose grants demand approval reports `APPROVAL_REQUIRED` rather than allowing
the action.
