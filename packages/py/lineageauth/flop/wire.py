"""The FLOP wire profile v1 (Yellow Paper Appendix F), written from the text.

This module is a reader and encoder for the byte layouts Appendix F of the FLOP
Yellow Paper (v0.5.0 draft, mirror `flop-labs/yellowpaper`) declares
normative: the SCALE subset it uses, the identity preimages (F.1), the direct
rail attestation (F.2), the compute-channel transcript, Merkle path and receipt
(F.3), and the data-availability reference (F.4). It was written from the
appendix's own tables and checked afterwards against the paper's public
corpus, `evidence/wire-format-v1.json`, which `tests/test_flop_wire.py` loads
from `conformance/flop/` and reproduces byte for byte.

What it is for here: the testnet executor (D-108) will one day hold a receipt
from a FLOP compute channel, and a receipt it cannot re-derive is a receipt it
cannot say anything about. Every hash and preimage a settlement consumer
recomputes is reproducible offline from this file, with no dependency beyond
the standard library.

What it deliberately does not do: sign or verify sr25519. Appendix F signs
receipts, V3 leaves and validator attestations with sr25519 under the
Substrate signing context, and this project carries no sr25519
implementation. Signature bytes are carried through as opaque fields and the
tests say which vectors are therefore checked only for shape.

Fail closed throughout: negative or overflowing integers, non-minimal compact
encodings, unknown tags, truncated fields and trailing bytes are all refused
with `LineageAuthError`, as F.0 requires.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from hashlib import blake2b, sha256

from lineageauth.errors import LineageAuthError

H256_LEN = 32
SIGNATURE_LEN = 64

TASK_HASH_DOMAIN_V1 = b"FLOP/POUI/TASK"
CHANNEL_ID_DOMAIN_V1 = b"FLOP/COMPUTE_CHANNEL/ID"
RECEIPT_DOMAIN = b"FLOP/COMPUTE_CHANNEL/RECEIPT"
DECODE_POLICY_HASH_DOMAIN_V1 = b"FLOP_DECODE_POLICY_HASH_V1"
TRANSCRIPT_BLOB_MAGIC = b"FCC4"
WIRE_VERSION_V1 = b"\x01"

U32_MAX = (1 << 32) - 1
COMPACT_MODE_BOUNDS = (1 << 6, 1 << 14, 1 << 30)


class WireError(LineageAuthError):
    """A byte layout Appendix F says to reject."""


# ------------------------------------------------------------------ F.0 codec


def blake2_256(data: bytes) -> bytes:
    return blake2b(data, digest_size=32).digest()


def uint_le(value: int, width: int, name: str = "value") -> bytes:
    """A fixed unsigned little-endian integer. Negative or overflowing is refused."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise WireError(f"{name} must be an integer")
    if value < 0 or value >= 1 << (8 * width):
        raise WireError(f"{name} does not fit u{8 * width}")
    return value.to_bytes(width, "little")


def fixed(value: bytes, length: int, name: str) -> bytes:
    if not isinstance(value, bytes | bytearray) or len(value) != length:
        raise WireError(f"{name} must be exactly {length} bytes")
    return bytes(value)


def compact_u32(value: int) -> bytes:
    """Canonical SCALE Compact<u32>: the shortest mode that holds the value."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > U32_MAX:
        raise WireError("compact value must be an integer in [0, u32::MAX]")
    if value < COMPACT_MODE_BOUNDS[0]:
        return bytes([value << 2])
    if value < COMPACT_MODE_BOUNDS[1]:
        return ((value << 2) | 0b01).to_bytes(2, "little")
    if value < COMPACT_MODE_BOUNDS[2]:
        return ((value << 2) | 0b10).to_bytes(4, "little")
    return b"\x03" + value.to_bytes(4, "little")


def decode_compact_u32(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a Compact<u32> at `offset`; returns (value, next offset).

    Truncated encodings, non-minimal (overlong) encodings and values wider than
    u32 are refused, as F.0 requires and the corpus's `malformed_compact` pins.
    """
    if offset >= len(data):
        raise WireError("compact: truncated")
    first = data[offset]
    mode = first & 0b11
    if mode == 0:
        return first >> 2, offset + 1
    if mode == 1:
        if offset + 2 > len(data):
            raise WireError("compact: truncated mode 1")
        value = int.from_bytes(data[offset : offset + 2], "little") >> 2
        if value < COMPACT_MODE_BOUNDS[0]:
            raise WireError("compact: overlong mode 1")
        return value, offset + 2
    if mode == 2:
        if offset + 4 > len(data):
            raise WireError("compact: truncated mode 2")
        value = int.from_bytes(data[offset : offset + 4], "little") >> 2
        if value < COMPACT_MODE_BOUNDS[1]:
            raise WireError("compact: overlong mode 2")
        return value, offset + 4
    length = (first >> 2) + 4
    if length != 4:
        raise WireError("compact: exceeds u32")
    if offset + 1 + length > len(data):
        raise WireError("compact: truncated big mode")
    value = int.from_bytes(data[offset + 1 : offset + 1 + length], "little")
    if value < COMPACT_MODE_BOUNDS[2]:
        raise WireError("compact: overlong big mode")
    return value, offset + 1 + length


def scale_bool(value: bool) -> bytes:
    if not isinstance(value, bool):
        raise WireError("bool must be True or False")
    return b"\x01" if value else b"\x00"


def decode_bool(data: bytes, offset: int = 0) -> tuple[bool, int]:
    if offset >= len(data):
        raise WireError("bool: truncated")
    if data[offset] == 0:
        return False, offset + 1
    if data[offset] == 1:
        return True, offset + 1
    raise WireError(f"bool: invalid byte {data[offset]:#04x}")


# ------------------------------------------------------------------ F.1 identity & binding


def task_hash_v1(
    *,
    genesis_hash: bytes,
    agent: bytes,
    nonce: int,
    model_hash: bytes,
    payload_hash: bytes,
    commit_hash: bytes,
) -> bytes:
    """blake2_256 over "FLOP/POUI/TASK" || 01 || genesis || agent || nonce:u64LE
    || model || payload || commit."""
    return blake2_256(
        task_hash_preimage_v1(
            genesis_hash=genesis_hash,
            agent=agent,
            nonce=nonce,
            model_hash=model_hash,
            payload_hash=payload_hash,
            commit_hash=commit_hash,
        )
    )


def task_hash_preimage_v1(
    *,
    genesis_hash: bytes,
    agent: bytes,
    nonce: int,
    model_hash: bytes,
    payload_hash: bytes,
    commit_hash: bytes,
) -> bytes:
    return (
        TASK_HASH_DOMAIN_V1
        + WIRE_VERSION_V1
        + fixed(genesis_hash, H256_LEN, "genesis_hash")
        + fixed(agent, H256_LEN, "agent")
        + uint_le(nonce, 8, "nonce")
        + fixed(model_hash, H256_LEN, "model_hash")
        + fixed(payload_hash, H256_LEN, "payload_hash")
        + fixed(commit_hash, H256_LEN, "commit_hash")
    )


def channel_id_preimage_v1(*, genesis_hash: bytes, agent: bytes, miner: bytes, nonce: int) -> bytes:
    return (
        CHANNEL_ID_DOMAIN_V1
        + WIRE_VERSION_V1
        + fixed(genesis_hash, H256_LEN, "genesis_hash")
        + fixed(agent, H256_LEN, "agent")
        + fixed(miner, H256_LEN, "miner")
        + uint_le(nonce, 8, "nonce")
    )


def channel_id_v1(*, genesis_hash: bytes, agent: bytes, miner: bytes, nonce: int) -> bytes:
    """`blake2_256("FLOP/COMPUTE_CHANNEL/ID" || 01 || genesis || agent || miner || nonce:u64LE)`."""
    return blake2_256(
        channel_id_preimage_v1(genesis_hash=genesis_hash, agent=agent, miner=miner, nonce=nonce)
    )


class WorkloadClass(IntEnum):
    TEXT_GENERATION = 0
    IMAGE_DENOISE = 1
    ROLLOUT = 2
    CONTROL_LOOP = 3
    OTHER = 4


class TeeType(IntEnum):
    INTEL_TDX = 0
    NVIDIA_HOPPER_CC = 1
    NVIDIA_RUBIN_CC = 2
    SIMULATOR = 3


@dataclass(frozen=True, slots=True)
class SamplingParams:
    """Fixed-width SCALE, in this order; integer policy avoids float encodings."""

    temperature_milli: int = 0
    top_p_ppm: int = 1_000_000
    top_k: int = 0
    repetition_penalty_ppm: int = 1_000_000
    beam_width: int = 1
    seed: int = 0

    def encode(self) -> bytes:
        return (
            uint_le(self.temperature_milli, 4, "temperature_milli")
            + uint_le(self.top_p_ppm, 4, "top_p_ppm")
            + uint_le(self.top_k, 4, "top_k")
            + uint_le(self.repetition_penalty_ppm, 4, "repetition_penalty_ppm")
            + uint_le(self.beam_width, 2, "beam_width")
            + uint_le(self.seed, 8, "seed")
        )


@dataclass(frozen=True, slots=True)
class DecodePolicy:
    """version:u16(1), class, tokenizer_hash, SamplingParams, stop_conditions_hash,
    output_transform, class_policy_hash -- SCALE, in that order."""

    workload_class: WorkloadClass = WorkloadClass.TEXT_GENERATION
    other_class: int | None = None
    tokenizer_hash: bytes = bytes(H256_LEN)
    sampling: SamplingParams = field(default_factory=SamplingParams)
    stop_conditions_hash: bytes = bytes(H256_LEN)
    transform_id: bytes | None = None
    class_policy_hash: bytes = bytes(H256_LEN)
    version: int = 1

    def encode(self) -> bytes:
        klass = bytes([int(self.workload_class)])
        if self.workload_class is WorkloadClass.OTHER:
            if self.other_class is None:
                raise WireError("Other(u16) needs its code")
            klass += uint_le(self.other_class, 2, "other_class")
        transform = (
            b"\x00"
            if self.transform_id is None
            else b"\x01" + fixed(self.transform_id, H256_LEN, "transform_id")
        )
        return (
            uint_le(self.version, 2, "version")
            + klass
            + fixed(self.tokenizer_hash, H256_LEN, "tokenizer_hash")
            + self.sampling.encode()
            + fixed(self.stop_conditions_hash, H256_LEN, "stop_conditions_hash")
            + transform
            + fixed(self.class_policy_hash, H256_LEN, "class_policy_hash")
        )


def decode_policy_hash_v1(policy_scale: bytes) -> bytes:
    """`SHA256("FLOP_DECODE_POLICY_HASH_V1" || SCALE(DecodePolicy))`."""
    return sha256(DECODE_POLICY_HASH_DOMAIN_V1 + policy_scale).digest()


def report_data_preimage_v1(
    *,
    task_hash: bytes,
    gn_weight: int,
    latency_ms: int,
    model_hash: bytes,
    output_hash: bytes,
    decode_policy_hash: bytes,
    tee_type: TeeType,
) -> bytes:
    return (
        fixed(task_hash, H256_LEN, "task_hash")
        + uint_le(gn_weight, 8, "gn_weight")
        + uint_le(latency_ms, 8, "latency_ms")
        + fixed(model_hash, H256_LEN, "model_hash")
        + fixed(output_hash, H256_LEN, "output_hash")
        + fixed(decode_policy_hash, H256_LEN, "decode_policy_hash")
        + bytes([int(tee_type)])
    )


def report_data_v1(**fields: object) -> bytes:
    """`SHA256(preimage) || 00 x 32`: exactly 64 bytes."""
    return sha256(report_data_preimage_v1(**fields)).digest() + bytes(H256_LEN)  # type: ignore[arg-type]


# ------------------------------------------------------------------ F.2 attestation


@dataclass(frozen=True, slots=True)
class ValidatorAttestation:
    task_hash: bytes
    gn_weight: int
    latency_ms: int
    model_hash: bytes
    output_hash: bytes
    decode_policy_hash: bytes
    tee_type: TeeType
    quote_verified: bool
    event_log_verified: bool
    hardware_id_hash: bytes
    validator_id: bytes
    signature: bytes

    def signable(self) -> bytes:
        """The first ten fields, 179 bytes: what the validator signs."""
        return (
            fixed(self.task_hash, H256_LEN, "task_hash")
            + uint_le(self.gn_weight, 8, "gn_weight")
            + uint_le(self.latency_ms, 8, "latency_ms")
            + fixed(self.model_hash, H256_LEN, "model_hash")
            + fixed(self.output_hash, H256_LEN, "output_hash")
            + fixed(self.decode_policy_hash, H256_LEN, "decode_policy_hash")
            + bytes([int(self.tee_type)])
            + scale_bool(self.quote_verified)
            + scale_bool(self.event_log_verified)
            + fixed(self.hardware_id_hash, H256_LEN, "hardware_id_hash")
        )

    def encode(self) -> bytes:
        """Fixed-field SCALE, 275 bytes."""
        return (
            self.signable()
            + fixed(self.validator_id, H256_LEN, "validator_id")
            + fixed(self.signature, SIGNATURE_LEN, "signature")
        )


# ------------------------------------------------------------------ F.3 transcript


class TranscriptLeafVersion(IntEnum):
    V0 = 0
    V1 = 1
    V2 = 2
    V3 = 3


@dataclass(frozen=True, slots=True)
class TurnFields:
    """One turn's fields. Which of them a leaf version binds is decided by `leaf_preimage`."""

    turn_index: int
    h_in: bytes
    h_out: bytes
    g_n: int
    decode_policy_hash: bytes | None = None
    h_ids: bytes | None = None
    toploc_commitment_hash: bytes | None = None
    miner_recv_ms: int = 0
    miner_done_ms: int = 0
    latency_ms: int = 0


def leaf_preimage(version: TranscriptLeafVersion, channel_id: bytes, turn: TurnFields) -> bytes:
    """V3 = channel || idx:u32 || h_in || h_out || g_n:u128 || policy || h_ids || toploc
    || recv || done || latency (236 B).

    V2 drops h_ids and toploc (172 B); V1 also drops the policy (140 B); V0
    also drops the three timings (116 B).
    """
    head = (
        fixed(channel_id, H256_LEN, "channel_id")
        + uint_le(turn.turn_index, 4, "turn_index")
        + fixed(turn.h_in, H256_LEN, "h_in")
        + fixed(turn.h_out, H256_LEN, "h_out")
        + uint_le(turn.g_n, 16, "g_n")
    )
    timings = (
        uint_le(turn.miner_recv_ms, 8, "miner_recv_ms")
        + uint_le(turn.miner_done_ms, 8, "miner_done_ms")
        + uint_le(turn.latency_ms, 8, "latency_ms")
    )
    if version is TranscriptLeafVersion.V0:
        return head
    if version is TranscriptLeafVersion.V1:
        return head + timings
    if turn.decode_policy_hash is None:
        raise WireError(f"{version.name} leaf needs decode_policy_hash")
    policy = fixed(turn.decode_policy_hash, H256_LEN, "decode_policy_hash")
    if version is TranscriptLeafVersion.V2:
        return head + policy + timings
    if turn.h_ids is None or turn.toploc_commitment_hash is None:
        raise WireError("V3 leaf needs h_ids and toploc_commitment_hash")
    if turn.h_ids == bytes(H256_LEN):
        raise WireError("V3 leaf: h_ids must be non-zero")
    return (
        head
        + policy
        + fixed(turn.h_ids, H256_LEN, "h_ids")
        + fixed(turn.toploc_commitment_hash, H256_LEN, "toploc_commitment_hash")
        + timings
    )


def transcript_leaf(version: TranscriptLeafVersion, channel_id: bytes, turn: TurnFields) -> bytes:
    return blake2_256(leaf_preimage(version, channel_id, turn))


def merkle_node(left: bytes, right: bytes) -> bytes:
    """No prefix: the 64-byte preimage is length-disjoint from every leaf preimage."""
    return blake2_256(fixed(left, H256_LEN, "left") + fixed(right, H256_LEN, "right"))


def merkle_root(leaves: list[bytes]) -> bytes:
    """Leaf order is turn order; an odd last node is duplicated; empty root is zero."""
    if not leaves:
        return bytes(H256_LEN)
    level = [fixed(leaf, H256_LEN, "leaf") for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [merkle_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_path(leaves: list[bytes], index: int) -> list[tuple[bytes, bool]]:
    """`(sibling_hash, sibling_is_left)` from the leaf up, duplicating odd last nodes."""
    if index < 0 or index >= len(leaves):
        raise WireError("merkle path: index out of range")
    level = [fixed(leaf, H256_LEN, "leaf") for leaf in leaves]
    path: list[tuple[bytes, bool]] = []
    position = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling = position ^ 1
        path.append((level[sibling], sibling < position))
        level = [merkle_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        position //= 2
    return path


def root_from_path(leaf: bytes, path: list[tuple[bytes, bool]]) -> bytes:
    node = fixed(leaf, H256_LEN, "leaf")
    for sibling, sibling_is_left in path:
        node = merkle_node(sibling, node) if sibling_is_left else merkle_node(node, sibling)
    return node


def receipt_message_v1(
    *, channel_id: bytes, final_root: bytes, aggregate_gn: int, payable: int
) -> bytes:
    """ "FLOP/COMPUTE_CHANNEL/RECEIPT" || 01 || channel_id || final_root
    || aggregate_gn:u128LE || payable:u128LE."""
    return (
        RECEIPT_DOMAIN
        + WIRE_VERSION_V1
        + fixed(channel_id, H256_LEN, "channel_id")
        + fixed(final_root, H256_LEN, "final_root")
        + uint_le(aggregate_gn, 16, "aggregate_gn")
        + uint_le(payable, 16, "payable")
    )


def legacy_receipt_message(
    *, channel_id: bytes, final_root: bytes, aggregate_gn: int, payable: int
) -> bytes:
    """The historical untagged 96-byte preimage a current channel must refuse."""
    return (
        fixed(channel_id, H256_LEN, "channel_id")
        + fixed(final_root, H256_LEN, "final_root")
        + uint_le(aggregate_gn, 16, "aggregate_gn")
        + uint_le(payable, 16, "payable")
    )


@dataclass(frozen=True, slots=True)
class VerifiedTurn:
    """The settlement/dispute turn container (SCALE, `269 + compact_len(L) + 33L` bytes)."""

    leaf_version: TranscriptLeafVersion
    turn: TurnFields
    enclave_sig: bytes
    merkle_path: list[tuple[bytes, bool]]

    def encode(self) -> bytes:
        t = self.turn
        out = (
            bytes([int(self.leaf_version)])
            + uint_le(t.turn_index, 4, "turn_index")
            + fixed(t.h_in, H256_LEN, "h_in")
            + fixed(t.h_out, H256_LEN, "h_out")
            + uint_le(t.g_n, 16, "g_n")
            + fixed(t.decode_policy_hash or bytes(H256_LEN), H256_LEN, "decode_policy_hash")
            + fixed(t.h_ids or bytes(H256_LEN), H256_LEN, "h_ids")
            + fixed(t.toploc_commitment_hash or bytes(H256_LEN), H256_LEN, "toploc")
            + uint_le(t.miner_recv_ms, 8, "miner_recv_ms")
            + uint_le(t.miner_done_ms, 8, "miner_done_ms")
            + uint_le(t.latency_ms, 8, "latency_ms")
            + fixed(self.enclave_sig, SIGNATURE_LEN, "enclave_sig")
            + compact_u32(len(self.merkle_path))
        )
        for sibling, is_left in self.merkle_path:
            out += fixed(sibling, H256_LEN, "sibling") + scale_bool(is_left)
        return out


def decode_verified_turn(data: bytes, offset: int = 0) -> tuple[VerifiedTurn, int]:
    """Decode one VerifiedTurn at `offset`. Unknown tags and truncation are refused."""

    def take(n: int, name: str) -> bytes:
        nonlocal offset
        if offset + n > len(data):
            raise WireError(f"VerifiedTurn: truncated at {name}")
        chunk = data[offset : offset + n]
        offset += n
        return chunk

    tag = take(1, "leaf_version")[0]
    try:
        version = TranscriptLeafVersion(tag)
    except ValueError as exc:
        raise WireError(f"VerifiedTurn: unknown leaf version tag {tag}") from exc
    turn = TurnFields(
        turn_index=int.from_bytes(take(4, "turn_index"), "little"),
        h_in=take(32, "h_in"),
        h_out=take(32, "h_out"),
        g_n=int.from_bytes(take(16, "g_n"), "little"),
        decode_policy_hash=take(32, "decode_policy_hash"),
        h_ids=take(32, "h_ids"),
        toploc_commitment_hash=take(32, "toploc"),
        miner_recv_ms=int.from_bytes(take(8, "miner_recv_ms"), "little"),
        miner_done_ms=int.from_bytes(take(8, "miner_done_ms"), "little"),
        latency_ms=int.from_bytes(take(8, "latency_ms"), "little"),
    )
    sig = take(64, "enclave_sig")
    count, offset = decode_compact_u32(data, offset)
    path: list[tuple[bytes, bool]] = []
    for _ in range(count):
        sibling = take(32, "sibling")
        is_left, offset = decode_bool(data, offset)
        path.append((sibling, is_left))
    return VerifiedTurn(leaf_version=version, turn=turn, enclave_sig=sig, merkle_path=path), offset


def leaf_fields_consistent(version: TranscriptLeafVersion, turn: TurnFields) -> bool:
    """FCC4 / VerifiedTurn version-field consistency: V0/V1 carry no policy and zero
    V3 fields; V2 a policy and zero V3 fields; V3 a policy and a non-zero h_ids."""
    zero = bytes(H256_LEN)
    policy = turn.decode_policy_hash not in (None, zero)
    h_ids = turn.h_ids not in (None, zero)
    toploc = turn.toploc_commitment_hash not in (None, zero)
    if version in (TranscriptLeafVersion.V0, TranscriptLeafVersion.V1):
        return not policy and not h_ids and not toploc
    if version is TranscriptLeafVersion.V2:
        return policy and not h_ids and not toploc
    return policy and h_ids


def verify_turn_proof(turn: VerifiedTurn, *, channel_id: bytes, final_root: bytes) -> None:
    """Version/field consistency, then leaf-from-fields, then path-to-root. Raises on failure."""
    if not leaf_fields_consistent(turn.leaf_version, turn.turn):
        raise WireError("LeafFieldsInconsistent")
    leaf = transcript_leaf(turn.leaf_version, channel_id, turn.turn)
    if root_from_path(leaf, turn.merkle_path) != final_root:
        raise WireError("LeafNotInRoot")


def accepts_leaf_version(
    version: TranscriptLeafVersion, *, channel_has_decode_policy: bool
) -> bool:
    """A channel with a pinned decode policy accepts only V2/V3; one without accepts V0-V3."""
    if channel_has_decode_policy:
        return version in (TranscriptLeafVersion.V2, TranscriptLeafVersion.V3)
    return True


def verified_work_from_turns(turns: list[VerifiedTurn]) -> int:
    """Checked sum of distinct submitted turns' g_n. Duplicate turn indices are refused."""
    seen: set[int] = set()
    total = 0
    for turn in turns:
        if turn.turn.turn_index in seen:
            raise WireError("DuplicateVerifiedTurn")
        seen.add(turn.turn.turn_index)
        total += turn.turn.g_n
        if total >= 1 << 128:
            raise WireError("aggregate_gn overflows u128")
    return total


@dataclass(frozen=True, slots=True)
class TurnAck:
    send_ms: int
    receive_ms: int
    agent_sig: bytes


@dataclass(frozen=True, slots=True)
class TranscriptTurn:
    leaf_version: TranscriptLeafVersion
    turn: TurnFields
    enclave_sig: bytes
    ack: TurnAck | None = None


def encode_transcript_blob(channel_id: bytes, turns: list[TranscriptTurn]) -> bytes:
    """`FCC4 || channel_id || turn_count:u32LE || turns...` with the optional policy and ack."""
    out = (
        TRANSCRIPT_BLOB_MAGIC
        + fixed(channel_id, H256_LEN, "channel_id")
        + uint_le(len(turns), 4, "turn_count")
    )
    for entry in turns:
        t = entry.turn
        if not leaf_fields_consistent(entry.leaf_version, t):
            raise WireError("FCC4: leaf version and fields disagree")
        out += bytes([int(entry.leaf_version)])
        out += (
            uint_le(t.turn_index, 4, "turn_index")
            + fixed(t.h_in, 32, "h_in")
            + fixed(t.h_out, 32, "h_out")
        )
        out += uint_le(t.g_n, 16, "g_n")
        if t.decode_policy_hash is None:
            out += b"\x00"
        else:
            out += b"\x01" + fixed(t.decode_policy_hash, 32, "decode_policy_hash")
        out += fixed(t.h_ids or bytes(32), 32, "h_ids") + fixed(
            t.toploc_commitment_hash or bytes(32), 32, "toploc"
        )
        out += (
            uint_le(t.miner_recv_ms, 8, "recv")
            + uint_le(t.miner_done_ms, 8, "done")
            + uint_le(t.latency_ms, 8, "latency")
        )
        out += fixed(entry.enclave_sig, 64, "enclave_sig")
        if entry.ack is None:
            out += b"\x00"
        else:
            out += (
                b"\x01"
                + uint_le(entry.ack.send_ms, 8, "send")
                + uint_le(entry.ack.receive_ms, 8, "receive")
            )
            out += fixed(entry.ack.agent_sig, 64, "agent_sig")
    return out


def decode_transcript_blob(data: bytes) -> tuple[bytes, list[TranscriptTurn]]:
    """Consume exactly the declared turns; reject unknown magic, truncation and trailing bytes."""
    offset = 0

    def take(n: int, name: str) -> bytes:
        nonlocal offset
        if offset + n > len(data):
            raise WireError(f"FCC4: truncated at {name}")
        chunk = data[offset : offset + n]
        offset += n
        return chunk

    if take(4, "magic") != TRANSCRIPT_BLOB_MAGIC:
        raise WireError("FCC4: unknown container version")
    channel_id = take(32, "channel_id")
    count = int.from_bytes(take(4, "turn_count"), "little")
    turns: list[TranscriptTurn] = []
    for _ in range(count):
        tag = take(1, "leaf_version")[0]
        try:
            version = TranscriptLeafVersion(tag)
        except ValueError as exc:
            raise WireError(f"FCC4: unknown leaf version tag {tag}") from exc
        turn_index = int.from_bytes(take(4, "turn_index"), "little")
        h_in, h_out = take(32, "h_in"), take(32, "h_out")
        g_n = int.from_bytes(take(16, "g_n"), "little")
        has_policy = take(1, "has_policy")[0]
        if has_policy not in (0, 1):
            raise WireError("FCC4: has_policy must be 0 or 1")
        policy = take(32, "decode_policy_hash") if has_policy else None
        h_ids, toploc = take(32, "h_ids"), take(32, "toploc")
        recv, done, latency = (
            int.from_bytes(take(8, n), "little") for n in ("recv", "done", "latency")
        )
        enclave_sig = take(64, "enclave_sig")
        has_ack = take(1, "has_ack")[0]
        if has_ack not in (0, 1):
            raise WireError("FCC4: has_ack must be 0 or 1")
        ack = None
        if has_ack:
            send = int.from_bytes(take(8, "send"), "little")
            receive = int.from_bytes(take(8, "receive"), "little")
            ack = TurnAck(send_ms=send, receive_ms=receive, agent_sig=take(64, "agent_sig"))
        fields = TurnFields(
            turn_index=turn_index,
            h_in=h_in,
            h_out=h_out,
            g_n=g_n,
            decode_policy_hash=policy,
            h_ids=h_ids,
            toploc_commitment_hash=toploc,
            miner_recv_ms=recv,
            miner_done_ms=done,
            latency_ms=latency,
        )
        if not leaf_fields_consistent(version, fields):
            raise WireError("FCC4: leaf version and fields disagree")
        turns.append(
            TranscriptTurn(leaf_version=version, turn=fields, enclave_sig=enclave_sig, ack=ack)
        )
    if offset != len(data):
        raise WireError("FCC4: trailing bytes")
    return channel_id, turns


# ------------------------------------------------------------------ F.4 data availability


class RetentionClass(IntEnum):
    EPHEMERAL = 0
    LEASED = 1


def data_ref_v1(*, commitment: bytes, provider_id: int, retention: RetentionClass) -> bytes:
    """Ordered SCALE `commitment:H256, provider_id:u8, retention_class`: 34 bytes."""
    return (
        fixed(commitment, H256_LEN, "commitment")
        + uint_le(provider_id, 1, "provider_id")
        + bytes([int(retention)])
    )


def decode_retention(data: bytes) -> RetentionClass:
    if len(data) != 1:
        raise WireError("retention: expected one tag byte")
    try:
        return RetentionClass(data[0])
    except ValueError as exc:
        raise WireError(f"retention: unknown tag {data[0]}") from exc


def decode_leaf_version(data: bytes) -> TranscriptLeafVersion:
    if len(data) != 1:
        raise WireError("leaf version: expected one tag byte")
    try:
        return TranscriptLeafVersion(data[0])
    except ValueError as exc:
        raise WireError(f"leaf version: unknown tag {data[0]}") from exc


__all__ = [
    "CHANNEL_ID_DOMAIN_V1",
    "DECODE_POLICY_HASH_DOMAIN_V1",
    "RECEIPT_DOMAIN",
    "TASK_HASH_DOMAIN_V1",
    "TRANSCRIPT_BLOB_MAGIC",
    "DecodePolicy",
    "RetentionClass",
    "SamplingParams",
    "TeeType",
    "TranscriptLeafVersion",
    "TranscriptTurn",
    "TurnAck",
    "TurnFields",
    "ValidatorAttestation",
    "VerifiedTurn",
    "WireError",
    "WorkloadClass",
    "accepts_leaf_version",
    "blake2_256",
    "channel_id_preimage_v1",
    "channel_id_v1",
    "compact_u32",
    "data_ref_v1",
    "decode_bool",
    "decode_compact_u32",
    "decode_leaf_version",
    "decode_policy_hash_v1",
    "decode_retention",
    "decode_transcript_blob",
    "decode_verified_turn",
    "encode_transcript_blob",
    "fixed",
    "leaf_fields_consistent",
    "leaf_preimage",
    "legacy_receipt_message",
    "merkle_node",
    "merkle_path",
    "merkle_root",
    "receipt_message_v1",
    "report_data_preimage_v1",
    "report_data_v1",
    "root_from_path",
    "scale_bool",
    "task_hash_preimage_v1",
    "task_hash_v1",
    "transcript_leaf",
    "uint_le",
    "verified_work_from_turns",
    "verify_turn_proof",
]
