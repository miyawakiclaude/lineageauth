"""Technocore's native `delegate:` records, read by a second implementation.

The format is `llms.txt`'s DELEGATION section (served 2026-09-08) and the
reference reader is `scripts/sign.py check` in flop-labs/technocore-chat. This
port reproduces the token scan, the signed string, the ASCII-decimal grammar
and highest-nonce-wins, and pins one ordering difference: signatures are
checked before nonces are ranked (technocore-chat#782).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.adapters.technocore.delegation import (
    DelegationVerdict,
    check_delegations,
    delegation_scopes,
    live_delegations,
    note_path,
    parse_delegations,
    permitting_record,
    signing_message,
)
from lineageauth.errors import LineageAuthError
from lineageauth.scopes import parse_scopes
from tests.testkeys import AGENT_1, OUTSIDER, RECOVERY_1, ROOT_A, unsafe_signer

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
OTHER = unsafe_signer(RECOVERY_1)
STRANGER = unsafe_signer(OUTSIDER)

AT = datetime(2026, 9, 8, 12, 0, 0, tzinfo=UTC)
IN_30_DAYS = str(int((AT + timedelta(days=30)).timestamp()))
YESTERDAY = str(int((AT - timedelta(days=1)).timestamp()))


def record(*, agent=AGENT, scope="*", expires=IN_30_DAYS, nonce="5", root=ROOT, signer=None) -> str:  # type: ignore[no-untyped-def]
    """One `delegate:` record as the root would append it to its note."""
    who = signer or root
    sig = who.sign_b64u(signing_message(root.did, agent.did, scope, expires, nonce).encode())
    return f"delegate: {agent.did} {scope} {expires} {nonce} {sig}"


class TestParsing:
    def test_records_are_found_by_token_not_by_line(self) -> None:
        body = f"technocore-profile-v1 mailbox: mb-x {record()} {record(nonce='6')}"
        found = parse_delegations(body)
        assert [r.nonce for r in found] == ["5", "6"]
        assert found[0].agent == AGENT.did

    def test_a_newline_separated_note_reads_the_same_as_the_swept_one(self) -> None:
        one = record()
        assert parse_delegations(one + "\n" + record(nonce="6")) == parse_delegations(
            one + " " + record(nonce="6")
        )

    def test_a_token_with_too_few_fields_is_not_a_record(self) -> None:
        assert parse_delegations("delegate: did:key:z6Mk only three") == ()

    def test_the_note_path_matches_the_reference(self) -> None:
        fingerprint = hashlib.sha256(ROOT.did.encode()).hexdigest()[:16]
        assert note_path(ROOT.did) == f"/kv/did-{fingerprint[:2]}/{fingerprint[2:]}"

    def test_the_note_path_refuses_a_non_key(self) -> None:
        with pytest.raises(LineageAuthError):
            note_path("did:key:zNotAKey")


class TestVerdicts:
    def test_a_record_the_root_signed_is_live(self) -> None:
        (checked,) = check_delegations(ROOT.did, record(), at=AT)
        assert checked.verdict is DelegationVerdict.OK
        assert checked.live
        assert "30d left" in checked.detail

    def test_a_record_signed_by_another_key_is_forged(self) -> None:
        (checked,) = check_delegations(ROOT.did, record(signer=STRANGER), at=AT)
        assert checked.verdict is DelegationVerdict.FORGED

    def test_a_record_lifted_from_another_roots_note_does_not_verify_here(self) -> None:
        """The root DID is inside the signed string, so the proof names its issuer."""
        lifted = record(root=OTHER)  # OTHER really signed it, for OTHER's note
        (checked,) = check_delegations(ROOT.did, lifted, at=AT)
        assert checked.verdict is DelegationVerdict.FORGED

    def test_an_expired_record_is_expired_not_forged(self) -> None:
        (checked,) = check_delegations(ROOT.did, record(expires=YESTERDAY), at=AT)
        assert checked.verdict is DelegationVerdict.EXPIRED
        assert checked.expires_at is not None

    def test_expiry_is_exclusive_at_the_boundary(self) -> None:
        exact = str(int(AT.timestamp()))
        (checked,) = check_delegations(ROOT.did, record(expires=exact), at=AT)
        assert checked.verdict is DelegationVerdict.EXPIRED

    def test_the_highest_nonce_wins_and_the_older_record_is_superseded(self) -> None:
        body = record(scope="*", nonce="5") + " " + record(scope="r:lobby", nonce="6")
        old, new = check_delegations(ROOT.did, body, at=AT)
        assert old.verdict is DelegationVerdict.SUPERSEDED
        assert new.verdict is DelegationVerdict.OK
        assert new.record.scope == "r:lobby"

    def test_a_replayed_old_record_cannot_undo_a_narrowing(self) -> None:
        """The note is world-writable: putting the old `*` record back is a no-op."""
        body = record(scope="r:lobby", nonce="6") + " " + record(scope="*", nonce="5")
        narrow, replayed = check_delegations(ROOT.did, body, at=AT)
        assert narrow.live and replayed.verdict is DelegationVerdict.SUPERSEDED

    def test_a_nonce_tie_goes_to_the_last_record(self) -> None:
        body = record(scope="*", nonce="7") + " " + record(scope="r:lobby", nonce="7")
        first, last = check_delegations(ROOT.did, body, at=AT)
        assert first.verdict is DelegationVerdict.SUPERSEDED and last.live

    def test_records_for_different_agents_do_not_supersede_each_other(self) -> None:
        body = record(agent=AGENT, nonce="9") + " " + record(agent=OTHER, nonce="1")
        assert all(entry.live for entry in check_delegations(ROOT.did, body, at=AT))

    @pytest.mark.parametrize(
        ("field", "value", "reason"),
        [
            ("scope", "rooms:lobby", "scope"),
            ("scope", "r:Lobby", "scope"),
            ("expires", "١٢٣", "expires"),
            ("expires", "1e99", "expires"),
            ("nonce", "0x7f", "nonce"),
        ],
    )
    def test_a_malformed_field_is_reported_as_malformed(
        self, field: str, value: str, reason: str
    ) -> None:
        kwargs = {field: value}
        (checked,) = check_delegations(ROOT.did, record(**kwargs), at=AT)
        assert checked.verdict is DelegationVerdict.MALFORMED
        assert reason in checked.detail

    def test_a_signature_of_the_wrong_shape_is_malformed_not_forged(self) -> None:
        body = f"delegate: {AGENT.did} * {IN_30_DAYS} 5 AAAA"
        (checked,) = check_delegations(ROOT.did, body, at=AT)
        assert checked.verdict is DelegationVerdict.MALFORMED

    def test_the_root_must_be_a_key_and_the_instant_must_be_aware(self) -> None:
        with pytest.raises(LineageAuthError):
            check_delegations("did:key:zNope", record(), at=AT)
        with pytest.raises(LineageAuthError):
            check_delegations(ROOT.did, record(), at=AT.replace(tzinfo=None))


class TestIssue782:
    """technocore-chat#782: a forged record with a high nonce must not suppress a real one.

    The reference at 45921c3e ranks every record by nonce before verifying
    any signature, so anyone can append `delegate: <agent> r:x <t> 999 AAAA...`
    to a world-writable note and turn a live grant into SUPERSEDED. This port
    ranks only records the root signed, and this class keeps it that way.
    """

    def test_a_forged_high_nonce_record_does_not_supersede_a_real_grant(self) -> None:
        forged = f"delegate: {AGENT.did} r:lobby {IN_30_DAYS} 999 " + "A" * 86
        body = record(nonce="5") + " " + forged
        real, fake = check_delegations(ROOT.did, body, at=AT)
        assert real.verdict is DelegationVerdict.OK, real.detail
        assert fake.verdict is DelegationVerdict.FORGED
        assert len(live_delegations((real, fake))) == 1

    def test_a_forged_record_signed_by_a_stranger_does_not_supersede_either(self) -> None:
        body = record(nonce="5") + " " + record(nonce="999", signer=STRANGER)
        real, fake = check_delegations(ROOT.did, body, at=AT)
        assert real.live and fake.verdict is DelegationVerdict.FORGED

    def test_an_expired_record_the_root_did_sign_still_ranks(self) -> None:
        """Expiry is the only revocation, and a re-issue that has since expired
        was still the root's last word: the older, longer grant does not come
        back to life. That part of the reference's semantics is kept."""
        body = (
            record(scope="*", nonce="5")
            + " "
            + record(scope="r:lobby", nonce="6", expires=YESTERDAY)
        )
        old, newer = check_delegations(ROOT.did, body, at=AT)
        assert newer.verdict is DelegationVerdict.EXPIRED
        assert old.verdict is DelegationVerdict.SUPERSEDED
        assert live_delegations((old, newer)) == ()


class TestWhatARecordReaches:
    def test_star_reaches_everything_and_a_room_reaches_only_itself(self) -> None:
        body = record(agent=AGENT, scope="*") + " " + record(agent=OTHER, scope="r:lobby")
        checked = check_delegations(ROOT.did, body, at=AT)
        assert permitting_record(checked, agent=AGENT.did, target="kv:notes") is not None
        assert permitting_record(checked, agent=OTHER.did, target="r:lobby") is not None
        assert permitting_record(checked, agent=OTHER.did, target="r:ops") is None
        assert permitting_record(checked, agent=STRANGER.did, target="r:lobby") is None

    def test_a_superseded_or_forged_record_reaches_nothing(self) -> None:
        body = record(scope="*", nonce="5") + " " + record(scope="r:lobby", nonce="6")
        checked = check_delegations(ROOT.did, body, at=AT)
        assert permitting_record(checked, agent=AGENT.did, target="kv:notes") is None

    @pytest.mark.parametrize("scope", ["*", "r:lobby", "kv:contrib"])
    def test_the_lap_correspondence_is_a_valid_technocore_scope(self, scope: str) -> None:
        parsed = parse_scopes(delegation_scopes(scope))
        assert parsed and all(s.namespace == "technocore" for s in parsed)

    def test_the_correspondence_refuses_a_non_scope(self) -> None:
        with pytest.raises(LineageAuthError):
            delegation_scopes("everything")


class TestNoNetworkAndNoKeys:
    def test_the_module_imports_nothing_that_opens_a_socket(self) -> None:
        import ast
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[1]
            / "packages"
            / "py"
            / "lineageauth"
            / "adapters"
            / "technocore"
            / "delegation.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        modules = {
            (node.module if isinstance(node, ast.ImportFrom) else alias.name)
            for node in ast.walk(tree)
            if isinstance(node, ast.Import | ast.ImportFrom)
            for alias in (node.names if isinstance(node, ast.Import) else [None])
        }
        assert not {m for m in modules if m and m.split(".")[0] in {"socket", "urllib", "http"}}
        assert "lineageauth.crypto" in modules  # verify only; LocalSigner is never named
        assert "LocalSigner" not in path.read_text(encoding="utf-8")
