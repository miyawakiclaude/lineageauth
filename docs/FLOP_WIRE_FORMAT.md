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
- **`wrong_path_orientation`.** The corpus expects `reject LeafNotInRoot` for a
  `VerifiedTurn` whose first path item has its `sibling_is_left` flipped. That
  item is the leaf's own duplicate — the odd last node of the corpus's
  three-leaf tree — so `blake2_256(left || right)` yields the same node either
  way round and the recomputed root equals the canonical root. Under F.3's
  stated rule the vector is indistinguishable from the positive one; rejecting
  it needs a rule the appendix does not state. `flop-labs/yellowpaper#44`
  reports the same. The test pins the fact instead of inventing an orientation
  rule, and a second test shows a genuinely wrong orientation (a non-duplicate
  sibling) is refused.
- **`wrong_genesis_network` / `wrong_session`.** The corpus gives the mutated
  hashes without the mutated inputs, so only "differs from the canonical id"
  can be checked.

## What the module is not

Not a client, not a signer, not a settlement verifier. It encodes and decodes
bytes and recomputes hashes. Whether a receipt is *accepted* depends on chain
state the paper describes and this project cannot see: pending tuples, active
validator sets, quorum, channel markers. `accepts_leaf_version` and
`verified_work_from_turns` implement the two pure checks F.3 states; the rest
is left to the consumer paths the corpus's `coverage` block names.
