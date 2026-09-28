# FLOP wire profile v1 — Appendix F, reproduced

`packages/py/lineageauth/flop/wire.py` implements the byte layouts the FLOP
Yellow Paper (v0.5.0 draft, mirror `flop-labs/yellowpaper`) makes normative in
Appendix F, and `tests/test_flop_wire.py` checks that implementation against
the paper's own public corpus, `evidence/wire-format-v1.json`, copied verbatim
into `conformance/flop/wire-format-v1.json` with its commit and hash in
`wire-format-v1.provenance.json`.

## Why this exists

The testnet executor (D-108) prepares an inference request and, once an
official network exists, will hold a receipt for it. A receipt this project
cannot re-derive is a receipt it cannot say anything about. Appendix F is the
part of the paper that says what those bytes are: the compute-channel id, the
per-turn transcript leaf, the Merkle path a settlement proves a turn against,
the receipt message an agent signs, and the attestation a validator signs.
Every one of those is reproducible offline from the standard library.

It was written from the appendix's tables, not ported from the reference
Python in the mirror, and then met the corpus. The corpus is what makes that
claim checkable: an implementation that reads the text differently produces
different bytes.

## What reproduces

Every positive vector in the corpus, byte for byte:

| Family | Vectors | Result |
|---|---|---|
| F.0 codec | `Compact<u32>` at every mode boundary (8), six malformed encodings, `bool` | reproduced; malformed refused |
| F.1 identity | `channel_id` v1, `task_hash` v1 (preimage and hash), `DecodePolicy` default SCALE and its `decode_policy_hash`, `report_data` v1 | reproduced |
| F.2 attestation | `ValidatorAttestation` SCALE (275 B) and its signable prefix (179 B) | reproduced |
| F.3 transcript | leaf preimages and hashes for V0–V3 (116/140/172/236 B), Merkle root and path, receipt message v1, legacy 96 B receipt preimage, `VerifiedTurn` SCALE round trip, FCC4 blob round trip | reproduced |
| F.4 data availability | `DataRef` v1 (34 B) | reproduced |
| negative cases | unknown enum tags, truncated / trailing / wrong-magic FCC4, duplicate turn index, V3 fields under a V2 tag, legacy leaf on a policy-pinned channel | refused as expected |

## What does not, and why

- **sr25519 signatures.** The corpus's receipt signature, V3 leaf signature and
  validator signature are sr25519 under the Substrate signing context. This
  project carries no sr25519 implementation and adds none for this; the three
  vectors are checked for shape (64 bytes) and stated as not verified.
- **`wrong_path_orientation`, resolved upstream.** The corpus this project
  first met (`cb3cbf97`) expected `reject LeafNotInRoot` for a `VerifiedTurn`
  whose flipped path item was the leaf's own duplicate — the odd last node of
  a three-leaf tree — so `blake2_256(left || right)` yielded the same node
  either way round and the vector could not be refused under F.3's stated
  rule. `flop-labs/yellowpaper#44` reported it; this project confirmed it from
  an independent implementation and pinned the fact in a test rather than
  inventing an orientation rule (D-116). The 2026-09-24 sync (`3c97bbc8`)
  regenerated the corpus so the case flips a sibling that is not the
  duplicate, and #44 was closed. The corpus here is that regenerated one
  (D-121); the vector now refuses as expected, and the test checks both that
  the flipped item is not the duplicate and that the recomputed root differs.
- **`wrong_genesis_network` / `wrong_session`.** The corpus gives the mutated
  hashes without the mutated inputs, so only "differs from the canonical id"
  can be checked.
- **The agent acknowledgement (`fcc4_transcript_with_ack`).** New in the
  regenerated corpus: an 84-byte ack preimage and a 64-byte agent signature
  over an FCC4 blob, plus a negative case `invalid_agent_ack_signature`. The
  blob decodes here as any FCC4 container does; the preimage layout is not in
  the published Appendix F text and the signature is sr25519, so both are
  checked for shape and stated as not reproduced (D-121).

## What the module is not

Not a client, not a signer, not a settlement verifier. It encodes and decodes
bytes and recomputes hashes. Whether a receipt is *accepted* depends on chain
state the paper describes and this project cannot see: pending tuples, active
validator sets, quorum, channel markers. `accepts_leaf_version` and
`verified_work_from_turns` implement the two pure checks F.3 states; the rest
is left to the consumer paths the corpus's `coverage` block names.
