"""Appendix F reproduced against the Yellow Paper's public corpus, byte for byte.

`conformance/flop/wire-format-v1.json` is `evidence/wire-format-v1.json` from
`flop-labs/yellowpaper` at the commit recorded beside it, copied verbatim. The
module under test was written from the appendix's text; this file is where it
meets the corpus. Four vectors are sr25519 signatures, which this project
does not implement; they are checked for shape and said so.

Integers wider than JSON carries exactly (every u64 and u128 input) are written
in the corpus as canonical decimal strings, its schema's `decimal_u64` and
`decimal_u128`. `num` reads them in that form only and fails the test on any
other, so a corpus that changes how it writes a number is noticed, not coerced.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from lineageauth.flop import wire
from lineageauth.flop.wire import (
    DecodePolicy,
    RetentionClass,
    TeeType,
    TranscriptLeafVersion,
    TurnAck,
    TurnFields,
    ValidatorAttestation,
    VerifiedTurn,
    WireError,
)

CORPUS = Path(__file__).resolve().parents[1] / "conformance" / "flop" / "wire-format-v1.json"
PROVENANCE = CORPUS.with_name("wire-format-v1.provenance.json")


@pytest.fixture(scope="module")
def corpus() -> dict:  # type: ignore[type-arg]
    return dict(json.loads(CORPUS.read_text(encoding="utf-8")))


def hx(text: str) -> bytes:
    return bytes.fromhex(text)


# Every field the corpus schema types `decimal_u64` or `decimal_u128`, and its width.
DECIMAL_BITS = {
    "nonce": 64,
    "gn_weight": 64,
    "latency_ms": 64,
    "miner_recv_ms": 64,
    "miner_done_ms": 64,
    "agent_send_ms": 64,
    "agent_recv_ms": 64,
    "g_n": 128,
    "aggregate_gn": 128,
    "payable": 128,
}
_CANONICAL_DECIMAL = re.compile(r"0|[1-9][0-9]*")


def dec(value: object, bits: int) -> int:
    """A canonical unsigned decimal string that fits `bits`, as an int; anything else fails."""
    if not isinstance(value, str) or not _CANONICAL_DECIMAL.fullmatch(value):
        raise AssertionError(f"not a canonical decimal string: {value!r}")
    number = int(value)
    if number >= 1 << bits:
        raise AssertionError(f"{value} does not fit u{bits}")
    return number


def num(table: dict, key: str) -> int:  # type: ignore[type-arg]
    return dec(table[key], DECIMAL_BITS[key])


class TestProvenance:
    def test_the_corpus_is_pinned_to_a_commit_and_a_hash(self) -> None:
        meta = json.loads(PROVENANCE.read_text(encoding="utf-8"))
        assert meta["repository"] == "flop-labs/yellowpaper"
        assert len(meta["commit"]) == 40
        import hashlib

        assert meta["sha256"] == "sha256:" + hashlib.sha256(CORPUS.read_bytes()).hexdigest()

    def test_the_corpus_calls_itself_canonical(self, corpus: dict) -> None:  # type: ignore[type-arg]
        assert corpus["profile"] == "flop-wire-v1"
        assert corpus["status"] == "public-canonical"

    def test_the_families_blocks_and_negative_cases_are_listed(self, corpus: dict) -> None:  # type: ignore[type-arg]
        """A family, a compute-channel or direct-rail block, or a negative case that a
        re-sync adds fails here, so none arrives silently. This forces the lists, and
        what reads each entry, to be looked at again; it does not by itself prove a
        test reads the new entry. Some listed entries are read by no test, among
        them `$schema`, `generation` (upstream's commands), `domains`, the direct
        rail's `expected`, and the receipt and validator signature negative cases."""
        assert set(corpus) == {
            "$schema",
            "codec",
            "compute_channel_v1",
            "coverage",
            "data_ref_v1",
            "decode_policy_v1",
            "direct_rail_v1",
            "generation",
            "h_ids_v1",
            "negative_cases",
            "profile",
            "status",
        }
        assert set(corpus["compute_channel_v1"]) == {
            "channel_id",
            "domains",
            "fcc4_transcript_blob_hex",
            "fcc4_transcript_with_ack",
            "leaf_inputs",
            "leaf_versions",
            "merkle",
            "receipt",
            "v3_leaf_signature",
            "verified_turn_v3_scale_hex",
        }
        assert set(corpus["direct_rail_v1"]) == {
            "expected",
            "inputs",
            "report_data_hex",
            "report_data_preimage_hex",
            "task_hash",
            "validator_attestation_scale_hex",
            "validator_attestation_signable_hex",
            "validator_id_hex",
            "validator_signature_hex",
        }
        assert [c["id"] for c in corpus["negative_cases"]] == [
            "unknown_leaf_enum",
            "unknown_retention_enum",
            "truncated_fcc4",
            "trailing_fcc4",
            "unknown_fcc_version",
            "invalid_agent_ack_signature",
            "duplicate_turn_index",
            "wrong_path_orientation",
            "wrong_genesis_network",
            "wrong_session",
            "wrong_leaf_version",
            "invalid_receipt_signature",
            "invalid_validator_signature",
            "legacy_leaf_current_channel",
            "legacy_receipt_current_channel",
        ]
        assert [(c["appendix"], c["family"]) for c in corpus["coverage"]] == [
            ("F.1", "decode_policy_v1/compute_channel_v1.channel_id"),
            ("F.2/G.2", "direct_rail_v1"),
            ("F.3/G.1 settle", "compute_channel_v1"),
            ("F.3", "h_ids_v1"),
            ("F.3/G.1 dispute", "compute_channel_v1"),
            ("F.4/G.3", "data_ref_v1"),
            ("F.5/G.1", "compute_channel_v1.leaf_versions.V3"),
        ]


class TestNumbers:
    """The b03378c0 corpus writes every u64 and u128 as a canonical decimal string (D-125)."""

    def test_every_wide_integer_is_a_canonical_decimal_string(self, corpus: dict) -> None:  # type: ignore[type-arg]
        seen: set[str] = set()

        def walk(node: object) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in DECIMAL_BITS:
                        dec(value, DECIMAL_BITS[key])
                        seen.add(key)
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(corpus)
        assert seen == set(DECIMAL_BITS)

    def test_the_reader_takes_the_canonical_form_at_both_widths(self) -> None:
        assert dec("0", 64) == 0
        assert dec(str((1 << 64) - 1), 64) == (1 << 64) - 1
        assert dec(str((1 << 128) - 1), 128) == (1 << 128) - 1

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "01",
            "00",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1" + chr(10),
            chr(10) + "1",
            chr(0xA0) + "1",
            "1" + chr(0x200B),
            "1_0",
            "1.0",
            "0x1",
            chr(0x661),
            chr(0xFF11),
            chr(0xB9),
            "1" + chr(0x661),
            "1" + chr(0xFF10),
            1,
            True,
            None,
        ],
    )
    def test_the_reader_refuses_every_other_form(self, value: object) -> None:
        with pytest.raises(AssertionError):
            dec(value, 64)

    def test_the_reader_refuses_a_value_wider_than_its_field(self) -> None:
        with pytest.raises(AssertionError, match="does not fit"):
            dec(str(1 << 64), 64)
        with pytest.raises(AssertionError, match="does not fit"):
            dec(str(1 << 128), 128)


class TestCodec:
    def test_compact_u32_round_trips_every_mode_boundary(self, corpus: dict) -> None:  # type: ignore[type-arg]
        for case in corpus["codec"]["scale_compact_u32"]:
            assert wire.compact_u32(case["value"]).hex() == case["bytes_hex"], case
            value, end = wire.decode_compact_u32(hx(case["bytes_hex"]))
            assert (value, end) == (case["value"], len(case["bytes_hex"]) // 2)

    def test_malformed_compact_encodings_are_refused(self, corpus: dict) -> None:  # type: ignore[type-arg]
        for case in corpus["codec"]["malformed_compact"]:
            with pytest.raises(WireError):
                wire.decode_compact_u32(hx(case["bytes_hex"]))

    def test_bool(self, corpus: dict) -> None:  # type: ignore[type-arg]
        table = corpus["codec"]["scale_bool"]
        assert wire.scale_bool(False).hex() == table["false"]
        assert wire.scale_bool(True).hex() == table["true"]
        with pytest.raises(WireError):
            wire.decode_bool(b"\x02")

    def test_fixed_integers_reject_negative_and_overflow(self) -> None:
        with pytest.raises(WireError):
            wire.uint_le(-1, 4)
        with pytest.raises(WireError):
            wire.uint_le(1 << 32, 4)
        with pytest.raises(WireError):
            wire.uint_le(True, 1)  # type: ignore[arg-type]


class TestIdentityPreimages:
    def test_channel_id_v1(self, corpus: dict) -> None:  # type: ignore[type-arg]
        c = corpus["compute_channel_v1"]["channel_id"]
        i = c["inputs"]
        preimage = wire.channel_id_preimage_v1(
            genesis_hash=hx(i["genesis_hash_hex"]),
            agent=hx(i["agent_account_id32_hex"]),
            miner=hx(i["miner_account_id32_hex"]),
            nonce=num(i, "nonce"),
        )
        assert preimage.hex() == c["preimage_hex"]
        assert wire.blake2_256(preimage).hex() == c["hash_hex"]

    def test_task_hash_v1(self, corpus: dict) -> None:  # type: ignore[type-arg]
        t = corpus["direct_rail_v1"]["task_hash"]
        i = t["inputs"]
        preimage = wire.task_hash_preimage_v1(
            genesis_hash=hx(i["genesis_hash_hex"]),
            agent=hx(i["agent_account_id32_hex"]),
            nonce=num(i, "nonce"),
            model_hash=hx(i["model_hash_hex"]),
            payload_hash=hx(i["payload_hash_hex"]),
            commit_hash=hx(i["commit_hash_hex"]),
        )
        assert preimage.hex() == t["preimage_hex"]
        assert wire.blake2_256(preimage).hex() == t["hash_hex"]

    def test_decode_policy_default_and_its_hash(self, corpus: dict) -> None:  # type: ignore[type-arg]
        d = corpus["decode_policy_v1"]
        scale = DecodePolicy().encode()
        assert scale.hex() == d["scale_bytes_hex"]
        assert (wire.DECODE_POLICY_HASH_DOMAIN_V1 + scale).hex() == d["hash_preimage_hex"]
        assert wire.decode_policy_hash_v1(scale).hex() == d["sha256_hex"]

    def test_report_data_v1(self, corpus: dict) -> None:  # type: ignore[type-arg]
        r = corpus["direct_rail_v1"]
        i = r["inputs"]
        fields = dict(
            task_hash=hx(i["task_hash_hex"]),
            gn_weight=num(i, "gn_weight"),
            latency_ms=num(i, "latency_ms"),
            model_hash=hx(i["model_hash_hex"]),
            output_hash=hx(i["output_hash_hex"]),
            decode_policy_hash=hx(i["decode_policy_hash_hex"]),
            tee_type=TeeType(i["tee_type"]["scale_tag"]),
        )
        assert wire.report_data_preimage_v1(**fields).hex() == r["report_data_preimage_hex"]
        report = wire.report_data_v1(**fields)
        assert report.hex() == r["report_data_hex"]
        assert len(report) == 64


class TestAttestation:
    def test_validator_attestation_scale_and_signable(self, corpus: dict) -> None:  # type: ignore[type-arg]
        r = corpus["direct_rail_v1"]
        i = r["inputs"]
        att = ValidatorAttestation(
            task_hash=hx(i["task_hash_hex"]),
            gn_weight=num(i, "gn_weight"),
            latency_ms=num(i, "latency_ms"),
            model_hash=hx(i["model_hash_hex"]),
            output_hash=hx(i["output_hash_hex"]),
            decode_policy_hash=hx(i["decode_policy_hash_hex"]),
            tee_type=TeeType(i["tee_type"]["scale_tag"]),
            quote_verified=i["quote_verified"],
            event_log_verified=i["event_log_verified"],
            hardware_id_hash=hx(i["hardware_id_hash_hex"]),
            validator_id=hx(r["validator_id_hex"]),
            signature=hx(r["validator_signature_hex"]),
        )
        assert att.signable().hex() == r["validator_attestation_signable_hex"]
        assert len(att.signable()) == 179
        assert att.encode().hex() == r["validator_attestation_scale_hex"]
        assert len(att.encode()) == 275


def turn_from_corpus(corpus: dict) -> TurnFields:  # type: ignore[type-arg]
    li = corpus["compute_channel_v1"]["leaf_inputs"]
    return TurnFields(
        turn_index=li["turn_index"],
        h_in=hx(li["h_in_hex"]),
        h_out=hx(li["h_out_hex"]),
        g_n=num(li, "g_n"),
        decode_policy_hash=hx(li["decode_policy_hash_hex"]),
        h_ids=hx(li["h_ids_hex"]),
        toploc_commitment_hash=hx(li["toploc_commitment_hash_hex"]),
        miner_recv_ms=num(li, "miner_recv_ms"),
        miner_done_ms=num(li, "miner_done_ms"),
        latency_ms=num(li, "latency_ms"),
    )


class TestTranscript:
    def test_every_leaf_version_preimage_and_hash(self, corpus: dict) -> None:  # type: ignore[type-arg]
        cc = corpus["compute_channel_v1"]
        channel_id = hx(cc["leaf_inputs"]["channel_id_hex"])
        turn = turn_from_corpus(corpus)
        sizes = {"V0": 116, "V1": 140, "V2": 172, "V3": 236}
        for case in cc["leaf_versions"]:
            version = TranscriptLeafVersion(case["scale_tag"])
            assert version.name == case["version"]
            preimage = wire.leaf_preimage(version, channel_id, turn)
            assert len(preimage) == sizes[version.name]
            assert preimage.hex() == case["preimage_hex"], version
            assert wire.transcript_leaf(version, channel_id, turn).hex() == case["hash_hex"]

    def test_merkle_root_and_path(self, corpus: dict) -> None:  # type: ignore[type-arg]
        cc = corpus["compute_channel_v1"]
        by_name = {c["version"]: hx(c["hash_hex"]) for c in cc["leaf_versions"]}
        leaves = [by_name[name] for name in cc["merkle"]["leaf_order"]]
        assert wire.merkle_root(leaves).hex() == cc["merkle"]["root_hex"]
        path = wire.merkle_path(leaves, 2)
        assert [(s.hex(), left) for s, left in path] == [
            (p["sibling_hex"], p["sibling_is_left"]) for p in cc["merkle"]["path_for_index_2"]
        ]
        assert wire.root_from_path(leaves[2], path).hex() == cc["merkle"]["root_hex"]

    def test_merkle_edge_cases_from_the_appendix(self) -> None:
        assert wire.merkle_root([]) == bytes(32)
        leaf = bytes([7]) * 32
        assert wire.merkle_root([leaf]) == leaf
        assert wire.merkle_path([leaf], 0) == []

    def test_receipt_message_v1(self, corpus: dict) -> None:  # type: ignore[type-arg]
        r = corpus["compute_channel_v1"]["receipt"]
        i = r["inputs"]
        message = wire.receipt_message_v1(
            channel_id=hx(i["channel_id_hex"]),
            final_root=hx(i["final_root_hex"]),
            aggregate_gn=num(i, "aggregate_gn"),
            payable=num(i, "payable"),
        )
        assert message.hex() == r["preimage_hex"]

    def test_the_legacy_receipt_preimage_is_the_untagged_96_bytes(self, corpus: dict) -> None:  # type: ignore[type-arg]
        r = corpus["compute_channel_v1"]["receipt"]["inputs"]
        legacy = next(
            c for c in corpus["negative_cases"] if c["id"] == "legacy_receipt_current_channel"
        )
        message = wire.legacy_receipt_message(
            channel_id=hx(r["channel_id_hex"]),
            final_root=hx(r["final_root_hex"]),
            aggregate_gn=num(r, "aggregate_gn"),
            payable=num(r, "payable"),
        )
        assert len(message) == 96
        assert legacy["bytes_hex"].startswith(message.hex())

    def test_verified_turn_v3_scale_round_trips(self, corpus: dict) -> None:  # type: ignore[type-arg]
        cc = corpus["compute_channel_v1"]
        turn = turn_from_corpus(corpus)
        path = [
            (hx(p["sibling_hex"]), p["sibling_is_left"]) for p in cc["merkle"]["path_for_index_2"]
        ]
        vt = VerifiedTurn(
            leaf_version=TranscriptLeafVersion.V3,
            turn=turn,
            enclave_sig=hx(cc["v3_leaf_signature"]["signature_hex"]),
            merkle_path=path,
        )
        encoded = vt.encode()
        assert encoded.hex() == cc["verified_turn_v3_scale_hex"]
        assert len(encoded) == 269 + 1 + 33 * 2
        decoded, end = wire.decode_verified_turn(encoded)
        assert end == len(encoded)
        assert decoded == vt
        wire.verify_turn_proof(
            decoded,
            channel_id=hx(cc["leaf_inputs"]["channel_id_hex"]),
            final_root=hx(cc["merkle"]["root_hex"]),
        )

    def test_fcc4_blob_round_trips(self, corpus: dict) -> None:  # type: ignore[type-arg]
        cc = corpus["compute_channel_v1"]
        blob = hx(cc["fcc4_transcript_blob_hex"])
        channel_id, turns = wire.decode_transcript_blob(blob)
        assert channel_id.hex() == cc["leaf_inputs"]["channel_id_hex"]
        assert len(turns) == 1
        assert turns[0].leaf_version is TranscriptLeafVersion.V3
        assert turns[0].turn == turn_from_corpus(corpus)
        assert turns[0].ack is None
        assert wire.encode_transcript_blob(channel_id, turns) == blob

    def test_an_ack_round_trips_too(self, corpus: dict) -> None:  # type: ignore[type-arg]
        cc = corpus["compute_channel_v1"]
        channel_id = hx(cc["leaf_inputs"]["channel_id_hex"])
        entry = wire.TranscriptTurn(
            leaf_version=TranscriptLeafVersion.V3,
            turn=turn_from_corpus(corpus),
            enclave_sig=bytes(64),
            ack=TurnAck(send_ms=1, receive_ms=2, agent_sig=bytes([9]) * 64),
        )
        blob = wire.encode_transcript_blob(channel_id, [entry])
        assert wire.decode_transcript_blob(blob) == (channel_id, [entry])


class TestTokenIds:
    """F.3 `h_ids` v1, new in the b03378c0 corpus (D-125): the billed token ids a V3 leaf binds."""

    def test_every_h_ids_vector(self, corpus: dict) -> None:  # type: ignore[type-arg]
        family = corpus["h_ids_v1"]
        assert "not SCALE Compact" in family["encoding"]
        assert {"endianness", "leaf_fixture"} <= {v["id"] for v in family["vectors"]}
        for v in family["vectors"]:
            preimage = wire.h_ids_preimage_v1(v["prompt_ids"], v["generated_ids"])
            assert preimage.hex() == v["preimage_hex"], v["id"]
            assert len(preimage) == 4 * (2 + len(v["prompt_ids"]) + len(v["generated_ids"]))
            hashed = wire.h_ids_v1(v["prompt_ids"], v["generated_ids"])
            assert hashed.hex() == v["hash_hex"], v["id"]

    def test_the_leaf_fixture_is_the_h_ids_the_v3_leaf_binds(self, corpus: dict) -> None:  # type: ignore[type-arg]
        fixture = next(v for v in corpus["h_ids_v1"]["vectors"] if v["id"] == "leaf_fixture")
        assert fixture["hash_hex"] == corpus["compute_channel_v1"]["leaf_inputs"]["h_ids_hex"]
        assert turn_from_corpus(corpus).h_ids == wire.h_ids_v1(
            fixture["prompt_ids"], fixture["generated_ids"]
        )

    def test_counts_are_fixed_width_not_compact(self) -> None:
        assert wire.h_ids_preimage_v1([7], []) == hx("01000000 07000000 00000000")
        assert wire.h_ids_preimage_v1((), ()) == bytes(8)
        assert wire.h_ids_preimage_v1([1], [2]) != wire.h_ids_preimage_v1([], [1, 2])

    @pytest.mark.parametrize("bad", [-1, 1 << 32, True, "1", 1.0, None])
    def test_a_token_id_that_is_not_a_u32_is_refused(self, bad: object) -> None:
        with pytest.raises(WireError):
            wire.h_ids_preimage_v1([bad], [])  # type: ignore[list-item]
        with pytest.raises(WireError):
            wire.h_ids_preimage_v1([], [0, bad])  # type: ignore[list-item]

    @pytest.mark.parametrize("bad", [b"\x01\x02", "12", range(3), {1, 2}, None, 3])
    def test_only_a_list_or_tuple_of_ids_is_taken(self, bad: object) -> None:
        with pytest.raises(WireError, match="list of token ids"):
            wire.h_ids_preimage_v1(bad, [])  # type: ignore[arg-type]
        with pytest.raises(WireError, match="list of token ids"):
            wire.h_ids_v1([], bad)  # type: ignore[arg-type]

    def test_a_count_that_does_not_fit_u32_is_refused(self) -> None:
        class Huge(list):  # type: ignore[type-arg]
            def __len__(self) -> int:
                return 1 << 32

        with pytest.raises(WireError, match="prompt_ids count"):
            wire.h_ids_preimage_v1(Huge(), [])


class TestNegativeCases:
    def case(self, corpus: dict, case_id: str) -> dict:  # type: ignore[type-arg]
        return next(c for c in corpus["negative_cases"] if c["id"] == case_id)

    def test_unknown_enum_tags(self, corpus: dict) -> None:  # type: ignore[type-arg]
        with pytest.raises(WireError):
            wire.decode_leaf_version(hx(self.case(corpus, "unknown_leaf_enum")["bytes_hex"]))
        with pytest.raises(WireError):
            wire.decode_retention(hx(self.case(corpus, "unknown_retention_enum")["bytes_hex"]))

    @pytest.mark.parametrize("case_id", ["truncated_fcc4", "trailing_fcc4", "unknown_fcc_version"])
    def test_fcc4_container_defects(self, corpus: dict, case_id: str) -> None:  # type: ignore[type-arg]
        with pytest.raises(WireError):
            wire.decode_transcript_blob(hx(self.case(corpus, case_id)["bytes_hex"]))

    def test_duplicate_turn_index_is_refused(self, corpus: dict) -> None:  # type: ignore[type-arg]
        data = hx(self.case(corpus, "duplicate_turn_index")["bytes_hex"])
        count, offset = wire.decode_compact_u32(data)
        turns = []
        for _ in range(count):
            turn, offset = wire.decode_verified_turn(data, offset)
            turns.append(turn)
        assert offset == len(data) and len(turns) == 2
        with pytest.raises(WireError, match="DuplicateVerifiedTurn"):
            wire.verified_work_from_turns(turns)
        assert wire.verified_work_from_turns(turns[:1]) == turns[0].turn.g_n

    def test_wrong_path_orientation_is_leaf_not_in_root(self, corpus: dict) -> None:  # type: ignore[type-arg]
        """The corpus's flipped sibling is now one F.3 can tell apart (D-121).

        The corpus this project first met (yellowpaper@cb3cbf97) flipped the leaf's
        own duplicate, the odd last node of a three-leaf tree, so `blake2_256(left
        || right)` gave the same node either way round and the case could not be
        refused under F.3's stated rule; flop-labs/yellowpaper#44 reported it and
        this test pinned it. The 3c97bbc8 sync regenerated the corpus to flip a
        sibling that is not the duplicate, and the vector now refuses exactly as
        the corpus expects. The test checks both halves: which item moved, and
        that the recomputed root no longer equals the committed one.
        """
        cc = corpus["compute_channel_v1"]
        data = hx(self.case(corpus, "wrong_path_orientation")["bytes_hex"])
        turn, end = wire.decode_verified_turn(data)
        assert end == len(data)
        canonical = [
            (hx(p["sibling_hex"]), p["sibling_is_left"]) for p in cc["merkle"]["path_for_index_2"]
        ]
        assert [item[0] for item in turn.merkle_path] == [item[0] for item in canonical]
        flipped = [i for i, item in enumerate(turn.merkle_path) if item[1] is not canonical[i][1]]
        assert len(flipped) == 1
        channel_id = hx(cc["leaf_inputs"]["channel_id_hex"])
        leaf = wire.transcript_leaf(turn.leaf_version, channel_id, turn.turn)
        assert turn.merkle_path[flipped[0]][0] != leaf, (
            "the flipped sibling must not be the duplicate"
        )
        assert wire.root_from_path(leaf, turn.merkle_path).hex() != cc["merkle"]["root_hex"]
        with pytest.raises(WireError, match="LeafNotInRoot"):
            wire.verify_turn_proof(
                turn, channel_id=channel_id, final_root=hx(cc["merkle"]["root_hex"])
            )

    def test_a_genuinely_wrong_orientation_is_leaf_not_in_root(self, corpus: dict) -> None:  # type: ignore[type-arg]
        """Flip the orientation of a sibling that is not a self-duplicate: refused."""
        cc = corpus["compute_channel_v1"]
        turn, _ = wire.decode_verified_turn(hx(cc["verified_turn_v3_scale_hex"]))
        path = list(turn.merkle_path)
        path[1] = (path[1][0], not path[1][1])
        flipped = VerifiedTurn(turn.leaf_version, turn.turn, turn.enclave_sig, path)
        with pytest.raises(WireError, match="LeafNotInRoot"):
            wire.verify_turn_proof(
                flipped,
                channel_id=hx(cc["leaf_inputs"]["channel_id_hex"]),
                final_root=hx(cc["merkle"]["root_hex"]),
            )

    def test_v3_fields_under_a_v2_tag_are_inconsistent(self, corpus: dict) -> None:  # type: ignore[type-arg]
        cc = corpus["compute_channel_v1"]
        data = hx(self.case(corpus, "wrong_leaf_version")["bytes_hex"])
        turn, _ = wire.decode_verified_turn(data)
        assert turn.leaf_version is TranscriptLeafVersion.V2
        with pytest.raises(WireError, match="LeafFieldsInconsistent"):
            wire.verify_turn_proof(
                turn,
                channel_id=hx(cc["leaf_inputs"]["channel_id_hex"]),
                final_root=hx(cc["merkle"]["root_hex"]),
            )

    def test_a_legacy_leaf_is_refused_on_a_channel_with_a_pinned_policy(self, corpus: dict) -> None:  # type: ignore[type-arg]
        data = hx(self.case(corpus, "legacy_leaf_current_channel")["bytes_hex"])
        turn, _ = wire.decode_verified_turn(data)
        assert turn.leaf_version is TranscriptLeafVersion.V1
        assert not wire.accepts_leaf_version(turn.leaf_version, channel_has_decode_policy=True)
        assert wire.accepts_leaf_version(turn.leaf_version, channel_has_decode_policy=False)

    def test_a_different_genesis_or_session_changes_the_channel_id(self, corpus: dict) -> None:  # type: ignore[type-arg]
        """The corpus states the mutated hashes without the mutated inputs, so what can be
        checked is that they differ from the canonical id and are well-formed."""
        canonical = corpus["compute_channel_v1"]["channel_id"]["hash_hex"]
        for case_id in ("wrong_genesis_network", "wrong_session"):
            other = self.case(corpus, case_id)["bytes_hex"]
            assert len(other) == 64 and other != canonical

    def test_signature_vectors_are_carried_but_not_verified_here(self, corpus: dict) -> None:  # type: ignore[type-arg]
        """sr25519 is not implemented in this project. Stated, not hidden."""
        cc = corpus["compute_channel_v1"]
        for sig_hex in (
            cc["receipt"]["signature_hex"],
            cc["v3_leaf_signature"]["signature_hex"],
            corpus["direct_rail_v1"]["validator_signature_hex"],
            cc["fcc4_transcript_with_ack"]["agent_signature_hex"],
        ):
            assert len(bytes.fromhex(sig_hex)) == 64
        assert not hasattr(wire, "verify_sr25519")


class TestDataRef:
    def test_data_ref_v1(self, corpus: dict) -> None:  # type: ignore[type-arg]
        d = corpus["data_ref_v1"]
        i = d["input"]
        encoded = wire.data_ref_v1(
            commitment=hx(i["commitment_hex"]),
            provider_id=i["provider_id"],
            retention=RetentionClass[i["retention"].upper()],
        )
        assert encoded.hex() == d["scale_bytes_hex"]
        assert len(encoded) == 34


class TestTheAgentAck:
    """`fcc4_transcript_with_ack`, added by the 3c97bbc8 sync (D-121).

    D-121 checked its 84-byte ack preimage for shape only, recording the layout as
    absent from the Appendix F text. The mirror at cb3cbf97, the commit D-116
    met, did lack it, but 3c97bbc8 itself added F.3's "per-turn agent ack" row,
    and D-121 did not re-read F.3 at that commit. The preimage is now written
    from that row and reproduced (D-125). The 64-byte agent signature over it is
    sr25519 and is still checked for shape only."""

    def test_the_ack_preimage_reproduces_from_the_decoded_blob(self, corpus: dict) -> None:  # type: ignore[type-arg]
        block = corpus["compute_channel_v1"]["fcc4_transcript_with_ack"]
        assert block["expected"] == "accept"
        blob = hx(block["blob_hex"])
        channel_id, turns = wire.decode_transcript_blob(blob)
        assert len(turns) == 1
        entry = turns[0]
        assert entry.ack is not None
        assert entry.ack.send_ms == num(block, "agent_send_ms")
        assert entry.ack.receive_ms == num(block, "agent_recv_ms")
        assert entry.ack.agent_sig == hx(block["agent_signature_hex"])
        message = wire.turn_ack_message(
            channel_id=channel_id,
            turn_index=entry.turn.turn_index,
            leaf_hash=wire.transcript_leaf(entry.leaf_version, channel_id, entry.turn),
            send_ms=entry.ack.send_ms,
            receive_ms=entry.ack.receive_ms,
        )
        assert len(message) == 84
        assert message.hex() == block["ack_preimage_hex"]
        assert wire.encode_transcript_blob(channel_id, turns) == blob
        assert len(hx(block["agent_public_key_hex"])) == 32

    def test_every_field_is_in_order_and_little_endian(self) -> None:
        """The corpus's ack pins the field order, but not the byte order of two
        fields: its turn index is u32::MAX and its agent_recv_ms u64::MAX, the same
        bytes either way round. Here every field has a value that is not."""
        message = wire.turn_ack_message(
            channel_id=bytes(range(32)),
            turn_index=0x01020304,
            leaf_hash=bytes(range(32, 64)),
            send_ms=0x0102030405060708,
            receive_ms=0x1112131415161718,
        )
        assert message == (
            bytes(range(32))
            + hx("04030201")
            + bytes(range(32, 64))
            + hx("0807060504030201")
            + hx("1817161514131211")
        )

    @pytest.mark.parametrize(
        "field, value",
        [
            ("channel_id", bytes(31)),
            ("leaf_hash", bytes(33)),
            ("turn_index", 1 << 32),
            ("send_ms", 1 << 64),
            ("receive_ms", -1),
            ("send_ms", True),
        ],
    )
    def test_a_field_of_the_wrong_size_is_refused(self, field: str, value: object) -> None:
        args: dict[str, object] = dict(
            channel_id=bytes(32), turn_index=0, leaf_hash=bytes(32), send_ms=0, receive_ms=0
        )
        args[field] = value
        with pytest.raises(WireError):
            wire.turn_ack_message(**args)  # type: ignore[arg-type]


class TestTheRegeneratedCorpus:
    """What the 3c97bbc8 sync added beyond the orientation fix and the ack (D-121)."""

    def test_the_bad_ack_signature_differs_only_inside_the_signature(
        self,
        corpus: dict,  # type: ignore[type-arg]
    ) -> None:
        """`invalid_agent_ack_signature` is the accepted ack blob with a byte of the
        agent's signature flipped. Refusing it takes sr25519, which this project does
        not implement, so the case is not decided here. What is checked: every byte
        that differs lies inside the 64-byte signature, and the blob still decodes to
        the same turn and the same ack preimage."""
        case = next(c for c in corpus["negative_cases"] if c["id"] == "invalid_agent_ack_signature")
        assert case["expected"].startswith("reject")
        block = corpus["compute_channel_v1"]["fcc4_transcript_with_ack"]
        good, bad = hx(block["blob_hex"]), hx(case["bytes_hex"])
        assert len(good) == len(bad)
        assert good[-64:] == hx(block["agent_signature_hex"])
        differing = [i for i in range(len(good)) if good[i] != bad[i]]
        assert differing and all(i >= len(good) - 64 for i in differing)
        channel_id, turns = wire.decode_transcript_blob(bad)
        (entry,) = turns
        assert entry.ack is not None
        assert entry.ack.agent_sig != hx(block["agent_signature_hex"])
        assert turns[0].turn == wire.decode_transcript_blob(good)[1][0].turn
        message = wire.turn_ack_message(
            channel_id=channel_id,
            turn_index=entry.turn.turn_index,
            leaf_hash=wire.transcript_leaf(entry.leaf_version, channel_id, entry.turn),
            send_ms=entry.ack.send_ms,
            receive_ms=entry.ack.receive_ms,
        )
        assert message.hex() == block["ack_preimage_hex"]
