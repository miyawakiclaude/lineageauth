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
| F.3 transcript | leaf preimages and hashes for V0–V3 (116/140/172/236 B), Merkle root and path, receipt message v1, legacy 96 B receipt preimage, `VerifiedTurn` SCALE round trip, FCC4 blob round trip, the per-turn agent ack preimage (84 B) | reproduced |
| F.3 `h_ids` v1 | the billed token ids a V3 leaf binds: `blake2_256(prompt_count:u32LE ‖ prompt_ids ‖ generated_count:u32LE ‖ generated_ids)`, counts fixed-width and not `Compact` (two vectors, one of them the `h_ids` the leaf fixture carries) | reproduced |
| F.4 data availability | `DataRef` v1 (34 B) | reproduced |
| negative cases | unknown enum tags, truncated / trailing / wrong-magic FCC4, duplicate turn index, V3 fields under a V2 tag, legacy leaf on a policy-pinned channel | refused as expected |

Every u64 and u128 input in the corpus (nonces, timings, `g_n`,
`aggregate_gn`, `payable`, `gn_weight`) is a canonical decimal string, the
schema's `decimal_u64` / `decimal_u128`, since the `b03378c0` sync; before it
some were JSON numbers. The test reads them in that canonical form only, and
fails if the corpus writes one any other way rather than coercing it. It also
lists the corpus's families, its compute-channel and direct-rail blocks, its
negative cases and its coverage block, so a re-sync that adds one fails until
the lists, and what reads each entry, are looked at again. The `b03378c0` sync
also rebuilt two negative cases, `duplicate_turn_index` and
`legacy_leaf_current_channel`, at turn index 0 with an empty Merkle path, the
duplicate's `g_n` at 10 rather than `u128::MAX`; both are refused here as
before.

## What does not, and why

- **sr25519 signatures.** The corpus's receipt signature, V3 leaf signature,
  validator signature and agent ack signature are sr25519 under the Substrate
  signing context. This project carries no sr25519 implementation and adds none
  for this; the four vectors are checked for shape (64 bytes) and stated as not
  verified.
- **`wrong_path_orientation`, resolved upstream.** The corpus this project
  first met (`cb3cbf97`) expected `reject LeafNotInRoot` for a `VerifiedTurn`
  whose flipped path item was the leaf's own duplicate — the odd last node of
  a three-leaf tree — so `blake2_256(left || right)` yielded the same node
  either way round and the vector could not be refused under F.3's stated
  rule. `flop-labs/yellowpaper#44` reported it; this project confirmed it from
  an independent implementation and pinned the fact in a test rather than
  inventing an orientation rule (D-116). The 2026-09-24 sync (`3c97bbc8`)
  regenerated the corpus so the case flips a sibling that is not the
  duplicate, and #44 was closed. The corpus here descends from that
  regeneration (D-121, then `b03378c0` in D-125); the vector refuses as
  expected, and the test checks both that the flipped item is not the
  duplicate and that the recomputed root differs.
- **`wrong_genesis_network` / `wrong_session`.** The corpus gives the mutated
  hashes without the mutated inputs, so only "differs from the canonical id"
  can be checked.
- **The agent acknowledgement's signature (`fcc4_transcript_with_ack`).** Added
  by the `3c97bbc8` corpus: an FCC4 blob whose turn carries an ack, its 84-byte
  preimage `channel_id ‖ turn_index:u32LE ‖ leaf_hash ‖ agent_send_ms:u64LE ‖
  agent_recv_ms:u64LE`, and the agent's 64-byte signature over it, plus a
  negative case `invalid_agent_ack_signature`. The preimage is reproduced from
  F.3's "per-turn agent ack" row by `turn_ack_message` (D-125). The signature
  is sr25519 and is checked for shape only. The negative case is that blob with
  a signature byte flipped; refusing it takes sr25519, so it is not decided
  here, and the test checks only that every differing byte lies inside the
  signature and that the ack preimage is unchanged. D-121
  had recorded the preimage layout as missing from the text. The mirror at
  `cb3cbf97`, the commit D-116 met, did lack it, but `3c97bbc8` had added the
  row, and D-121 did not re-read F.3 at that commit.

## What the module is not

Not a client, not a signer, not a settlement verifier. It encodes and decodes
bytes and recomputes hashes. Whether a receipt is *accepted* depends on chain
state the paper describes and this project cannot see: pending tuples, active
validator sets, quorum, channel markers. `accepts_leaf_version` and
`verified_work_from_turns` implement the two pure checks F.3 states; the rest
is left to the consumer paths the corpus's `coverage` block names.
