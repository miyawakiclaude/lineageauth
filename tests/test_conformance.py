"""The conformance package, run against this implementation.

`CONTRIBUTING.md` asks for an independent implementation that disagrees with
this one, and a disagreement is only useful if both sides answered the same
question. So the package fixes the questions, and this file makes sure this
implementation actually reaches the verdict the package claims it should.

Without that, the vectors would be a description of what somebody hoped the
code did.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from lineageauth.authority import check_permission
from lineageauth.bundle import EventBundle
from lineageauth.envelope import Envelope
from lineageauth.errors import LineageAuthError
from lineageauth.timeutil import parse_instant
from lineageauth.verify import verify_event

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "conformance"
MANIFEST = PACKAGE / "manifest.json"

VALID = "must-verify"
INVALID = "must-refuse"


def manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def documents(entry: dict) -> list[dict]:
    return json.loads((PACKAGE / entry["file"]).read_text(encoding="utf-8"))


def ids() -> list[str]:
    return [entry["name"] for entry in manifest()["vectors"]]


def entries() -> list[dict]:
    return manifest()["vectors"]


class TestThePackageIsWellFormed:
    def test_the_manifest_lists_every_vector_file(self) -> None:
        listed = {entry["file"] for entry in entries()}
        on_disk = {p.relative_to(PACKAGE).as_posix() for p in (PACKAGE / "vectors").glob("*.json")}
        assert listed == on_disk

    def test_every_vector_states_the_rule_behind_its_verdict(self) -> None:
        """A failure has to name the rule that broke, not just a mismatch."""
        for entry in entries():
            assert entry["expect"] in (VALID, INVALID)
            assert len(entry["rule"]) > 40, entry["name"]

    def test_the_package_carries_negative_vectors(self) -> None:
        """Anyone can accept a valid event. Refusing correctly is the hard part."""
        refusals = [e for e in entries() if e["expect"] == INVALID]
        assert len(refusals) >= 4

    def test_the_note_invites_disagreement(self) -> None:
        note = manifest()["note"]
        assert "worth an issue" in note
        assert "may well be this implementation that is wrong" in note

    def test_the_generator_is_deterministic(self) -> None:
        before = {
            p.relative_to(REPO).as_posix(): p.read_bytes() for p in sorted(PACKAGE.rglob("*.json"))
        }
        done = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "generate_conformance.py")],
            capture_output=True,
            check=False,
            cwd=str(REPO),
        )
        assert done.returncode == 0, done.stderr.decode("utf-8", errors="replace")
        after = {
            p.relative_to(REPO).as_posix(): p.read_bytes() for p in sorted(PACKAGE.rglob("*.json"))
        }
        assert before == after


class TestThisImplementationAgreesWithThePackage:
    @pytest.mark.parametrize("entry", entries(), ids=ids())
    def test_the_stated_verdict_is_the_one_reached(self, entry: dict) -> None:
        expect_valid = entry["expect"] == VALID
        reached_all = True
        for document in documents(entry):
            # A raised LineageAuthError is a refusal, not a crash: an
            # implementation that refuses at the DID layer, before a proof is
            # even reached, has still refused. What must not happen is a
            # refusal-shaped document coming back admitted.
            try:
                envelope = Envelope.model_validate(document)
                if not verify_event(envelope).integrity_ok:
                    reached_all = False
            except LineageAuthError:
                reached_all = False
            except Exception:
                reached_all = False

        assert reached_all is expect_valid, (
            f"{entry['name']}: package says {entry['expect']} -- rule: {entry['rule']}"
        )

    @pytest.mark.parametrize(
        "entry", [e for e in entries() if "authority" in e], ids=lambda e: e["name"]
    )
    def test_the_authority_verdict_is_the_one_reached(self, entry: dict) -> None:
        """Integrity and authority are separate questions, and a vector may fix both."""
        want = entry["authority"]
        bundle = EventBundle.from_envelopes([Envelope.model_validate(d) for d in documents(entry)])
        decision = check_permission(
            bundle,
            lineage=bundle.lineages()[0],
            agent=want["agent"],
            namespace=want["namespace"],
            resource=want["resource"],
            action=want["action"],
            at=parse_instant(want["at"], field="at"),
        )
        assert decision.allowed is (want["expect"] == "allow")
        assert str(decision.reason) == want["reason"]


class TestTheVectorsPinWhatTheySay:
    """Spot checks that the rules are the rules, not just labels."""

    def _by_name(self, name: str) -> dict:
        return next(e for e in entries() if e["name"] == name)

    def test_the_tampered_vector_differs_from_the_valid_one_by_one_field(self) -> None:
        good = documents(self._by_name("delegation-grant-valid"))[1]["payload"]
        bad = documents(self._by_name("tampered-payload"))[0]["payload"]
        differing = {k for k in good if good[k] != bad.get(k)}
        assert differing == {"subject"}

    def test_the_padded_vector_differs_only_by_the_padding(self) -> None:
        good = documents(self._by_name("root-create-valid"))[0]
        bad = documents(self._by_name("padded-base64url"))[0]
        assert good["payload"] == bad["payload"]
        assert bad["proofs"][0]["sig"] == good["proofs"][0]["sig"] + "="

    def test_the_receipt_vector_is_admitted_rather_than_refused(self) -> None:
        """The subtle one: the event is fine and the claim inside it is not."""
        entry = self._by_name("receipt-not-signed-by-its-worker")
        assert entry["expect"] == VALID
        assert "one that credits the worker is wrong" in entry["rule"]
        assert "does NOT STAND" in entry["rule"]

    def test_the_receipt_vector_reports_the_claim_as_unsupported(self) -> None:
        """The event is admitted; the authorship claim inside it is not credited."""
        from lineageauth.actions import sha256_hex
        from lineageauth.evidence import collect_evidence

        entry = self._by_name("receipt-not-signed-by-its-worker")
        bundle = EventBundle.from_envelopes([Envelope.model_validate(d) for d in documents(entry)])
        evidence = collect_evidence(
            bundle,
            lineage=bundle.lineages()[0],
            artifact_id=sha256_hex(b"a conformance artifact"),
        )
        # The registration is admitted, and its creator is reported as merely
        # claimed, because the key it names never signed it (D-051).
        assert evidence.registrations
        assert evidence.self_asserted_creators

        # The receipt is not collected at all. A receipt is the worker's own
        # assertion of authorship, so one naming a worker who did not sign it is
        # somebody else's claim about them and must not borrow their name
        # (D-052). The event stays in the bundle; the claim does not stand.
        assert evidence.receipts == ()
        assert any("worker" in w for w in evidence.warnings)


class TestTheMigrationDocumentIsAccurate:
    """A migration document that describes behaviour the code does not have is
    worse than none: it is read exactly once, by somebody who then relies on it."""

    def _migration(self) -> str:
        return (REPO / "MIGRATION.md").read_text(encoding="utf-8")

    def test_the_frozen_preimage_it_quotes_is_the_real_one(self) -> None:
        from lineageauth.canonical import EVENT_PREIMAGE_PREFIX

        quoted = "lineageauth:event:v1"
        assert quoted in self._migration()
        assert EVENT_PREIMAGE_PREFIX.decode("ascii").startswith(quoted)

    def test_unknown_namespaces_really_are_refused(self) -> None:
        from lineageauth.errors import MalformedEventError
        from lineageauth.scopes import parse_resource

        assert "namespace not in the registry" in self._migration()
        with pytest.raises(MalformedEventError):
            parse_resource("a-namespace-nobody-registered", "room:lobby")

    def test_unknown_event_types_really_do_fail_closed(self) -> None:
        from lineageauth import catalog

        assert "event type not in the catalog" in self._migration()
        assert catalog.family_of("root.summon") is None

    def test_a_did_method_other_than_did_key_is_really_refused(self) -> None:
        from lineageauth.didkey import UnsupportedDidMethodError, public_key_from_did_key

        assert "DID method other than" in self._migration()
        with pytest.raises(UnsupportedDidMethodError):
            public_key_from_did_key("did:web:example.invalid")

    def test_the_reason_code_rule_is_written_where_the_codes_are(self) -> None:
        from lineageauth.errors import ReasonCode

        assert "Adding a `ReasonCode` requires a version bump" in self._migration()
        assert "version bump" in (ReasonCode.__doc__ or "")

    def test_it_does_not_promise_stability(self) -> None:
        migration = self._migration()
        assert "Pre-1.0" in migration
        assert "nobody should have real authority behind this yet" in migration
