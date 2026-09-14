"""Appendix F reproduced against the Yellow Paper's public corpus, byte for byte.

`conformance/flop/wire-format-v1.json` is `evidence/wire-format-v1.json` from
`flop-labs/yellowpaper` at the commit recorded beside it, copied verbatim. The
module under test was written from the appendix's text; this file is where it
meets the corpus. Three vectors are sr25519 signatures, which this project
does not implement; they are checked for shape and said so.
"""

from __future__ import annotations

import json
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
            nonce=i["nonce"],
        )
        assert preimage.hex() == c["preimage_hex"]
        assert wire.blake2_256(preimage).hex() == c["hash_hex"]

    def test_task_hash_v1(self, corpus: dict) -> None:  # type: ignore[type-arg]
        t = corpus["direct_rail_v1"]["task_hash"]
        i = t["inputs"]
        preimage = wire.task_hash_preimage_v1(
            genesis_hash=hx(i["genesis_hash_hex"]),
            agent=hx(i["agent_account_id32_hex"]),
            nonce=i["nonce"],
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
            gn_weight=i["gn_weight"],
            latency_ms=i["latency_ms"],
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
            gn_weight=i["gn_weight"],
            latency_ms=i["latency_ms"],
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
        g_n=int(li["g_n"]),
        decode_policy_hash=hx(li["decode_policy_hash_hex"]),
        h_ids=hx(li["h_ids_hex"]),
        toploc_commitment_hash=hx(li["toploc_commitment_hash_hex"]),
        miner_recv_ms=int(li["miner_recv_ms"]),
        miner_done_ms=int(li["miner_done_ms"]),
        latency_ms=li["latency_ms"],
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
            aggregate_gn=i["aggregate_gn"],
            payable=i["payable"],
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
            aggregate_gn=r["aggregate_gn"],
            payable=r["payable"],
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

    def test_wrong_path_orientation_cannot_be_told_from_the_root(self, corpus: dict) -> None:  # type: ignore[type-arg]
        """The corpus expects `reject LeafNotInRoot`; F.3's own rule cannot deliver it.

        The flipped item is the leaf's own duplicate (the odd last node of a
        three-leaf tree), so `blake2_256(left || right)` gives the same node either
        way round and the recomputed root equals the canonical root. Rejecting this
        vector needs a rule Appendix F does not state. flop-labs/yellowpaper#44
        reports the same thing; this test keeps the discrepancy visible rather
        than papering over it with an orientation rule of this project's own.
        """
        cc = corpus["compute_channel_v1"]
        data = hx(self.case(corpus, "wrong_path_orientation")["bytes_hex"])
        turn, end = wire.decode_verified_turn(data)
        assert end == len(data)
        canonical = [
            (hx(p["sibling_hex"]), p["sibling_is_left"]) for p in cc["merkle"]["path_for_index_2"]
        ]
        assert turn.merkle_path[0][0] == canonical[0][0]
        assert turn.merkle_path[0][1] is not canonical[0][1]
        channel_id = hx(cc["leaf_inputs"]["channel_id_hex"])
        leaf = wire.transcript_leaf(turn.leaf_version, channel_id, turn.turn)
        assert turn.merkle_path[0][0] == leaf, "the flipped sibling is the leaf's own duplicate"
        assert wire.root_from_path(leaf, turn.merkle_path).hex() == cc["merkle"]["root_hex"]
        wire.verify_turn_proof(turn, channel_id=channel_id, final_root=hx(cc["merkle"]["root_hex"]))

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
