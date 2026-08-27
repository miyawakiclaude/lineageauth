"""The encrypted key file, and the rules it exists to keep.

This is the one place in the project where a private key exists at all, so the
tests are mostly about what must never happen to it: the seed does not reach the
disk in the clear, does not reach a screen, does not reach an argument, and the
passphrase does not either.

`did:key` has no revocation. An identity created here and then lost is lost, and
the only thing that helps is a `recovery.policy` published while the key still
works. The tooling says so; these tests check that it says so.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lineageauth import keyfile
from lineageauth.cli import app
from lineageauth.didkey import public_key_from_did_key

PASSPHRASE = "correct horse battery staple"
runner = CliRunner()

PACKAGE = Path(__file__).resolve().parents[1] / "packages" / "py" / "lineageauth"


@pytest.fixture
def created(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "identity.json"
    handle = keyfile.create(path, PASSPHRASE)
    return path, handle.did


class TestTheSeedNeverEscapes:
    def test_the_file_contains_no_usable_key_material(self, created: tuple[Path, str]) -> None:
        path, did = created
        text = path.read_text(encoding="utf-8")
        document = json.loads(text)

        # Everything in the file is either public or ciphertext.
        assert set(document) == {"format", "did", "kdf", "salt", "nonce", "ciphertext", "note"}
        assert document["did"] == did

        # The public key is derivable from the DID, so finding it proves nothing.
        # Finding the *private* half would. It is not there in any encoding.
        signer = keyfile.unlock(path, PASSPHRASE)
        public = signer.public_key_bytes
        assert public.hex() not in text
        # 32 bytes of ciphertext plus a 16-byte tag: nothing seed-shaped in clear.
        assert len(keyfile.b64u_decode(document["ciphertext"])) == 48

    def test_unlock_returns_something_that_signs_and_not_something_that_copies(
        self, created: tuple[Path, str]
    ) -> None:
        path, _ = created
        signer = keyfile.unlock(path, PASSPHRASE)
        assert hasattr(signer, "sign")
        for accessor in ("seed", "private_bytes", "private_seed", "export"):
            assert not hasattr(signer, accessor), f"LocalSigner exposes {accessor}"

    def test_the_module_never_prints(self) -> None:
        """A seed reaches a log by being printed. There is nothing here to print it."""
        source = (PACKAGE / "keyfile.py").read_text(encoding="utf-8")
        assert "print(" not in source
        assert "logging" not in source


class TestTheEncryption:
    def test_it_round_trips(self, created: tuple[Path, str]) -> None:
        path, did = created
        assert keyfile.unlock(path, PASSPHRASE).did == did

    def test_a_wrong_passphrase_is_refused(self, created: tuple[Path, str]) -> None:
        path, _ = created
        with pytest.raises(keyfile.KeyfileError, match="could not decrypt"):
            keyfile.unlock(path, "not the passphrase at all")

    def test_the_error_does_not_say_which_of_the_two_things_went_wrong(
        self, created: tuple[Path, str]
    ) -> None:
        """Distinguishing a wrong passphrase from a tampered file tells an
        attacker which one they are making progress on."""
        path, _ = created
        document = json.loads(path.read_text(encoding="utf-8"))
        document["ciphertext"] = keyfile.b64u_encode(b"\x00" * 48)
        path.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(keyfile.KeyfileError) as wrong:
            keyfile.unlock(path, "not the passphrase at all")
        with pytest.raises(keyfile.KeyfileError) as tampered:
            keyfile.unlock(path, PASSPHRASE)
        assert str(wrong.value) == str(tampered.value)

    def test_swapping_the_did_breaks_decryption(self, created: tuple[Path, str]) -> None:
        """The DID is bound in as associated data, so a file whose public half was
        replaced fails rather than yielding a key that signs for somebody else."""
        path, _ = created
        document = json.loads(path.read_text(encoding="utf-8"))
        document["did"] = "did:key:z6MkqFRbThS1M62TP7pUYo8DGxizE5TD66mbf6vXh6kmyE6X"
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(keyfile.KeyfileError):
            keyfile.unlock(path, PASSPHRASE)

    def test_a_short_passphrase_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(keyfile.KeyfileError, match="at least"):
            keyfile.create(tmp_path / "k.json", "short")

    def test_the_kdf_is_memory_hard_and_says_its_parameters(
        self, created: tuple[Path, str]
    ) -> None:
        """A fast KDF here is not a KDF: it is the only thing between a stolen
        file and an identity that cannot be revoked."""
        path, _ = created
        kdf = json.loads(path.read_text(encoding="utf-8"))["kdf"]
        assert kdf["name"] == "scrypt"
        assert kdf["n"] >= 2**16

    def test_two_keys_never_collide(self, tmp_path: Path) -> None:
        dids = {keyfile.create(tmp_path / f"k{n}.json", PASSPHRASE).did for n in range(5)}
        assert len(dids) == 5


class TestItRefusesToDestroyAnIdentity:
    def test_it_will_not_overwrite(self, created: tuple[Path, str]) -> None:
        path, _ = created
        with pytest.raises(keyfile.KeyfileError, match=r"[Rr]efusing to overwrite"):
            keyfile.create(path, PASSPHRASE)

    def test_the_file_says_what_losing_the_passphrase_costs(
        self, created: tuple[Path, str]
    ) -> None:
        path, _ = created
        note = json.loads(path.read_text(encoding="utf-8"))["note"]
        assert "no revocation" in note
        assert "recovery.policy" in note


class TestTheDidIsUsable:
    def test_it_decodes_as_an_ed25519_did_key(self, created: tuple[Path, str]) -> None:
        _, did = created
        assert len(public_key_from_did_key(did)) == 32

    def test_it_signs_something_the_verifier_accepts(self, created: tuple[Path, str]) -> None:
        from datetime import UTC, datetime

        from lineageauth.builders import build_root_create, sign_payload
        from lineageauth.verify import verify_event

        path, did = created
        signer = keyfile.unlock(path, PASSPHRASE)
        payload = build_root_create(root_did=did, issued_at=datetime.now(tz=UTC))
        assert verify_event(sign_payload(payload, [signer])).integrity_ok


class TestTheCliSurface:
    def test_no_command_takes_a_passphrase_or_a_seed_as_an_argument(self) -> None:
        """Both would land in shell history and the process table."""
        for command in (["key", "create", "--help"], ["sign", "--help"], ["key", "show", "--help"]):
            result = runner.invoke(app, command)
            assert result.exit_code == 0
            flat = " ".join(result.stdout.split())
            for forbidden in ("--passphrase", "--password", "--seed", "--private"):
                assert forbidden not in flat, f"{command} accepts {forbidden}"

    def test_the_cli_reads_the_passphrase_from_a_prompt(self) -> None:
        source = (PACKAGE / "cli.py").read_text(encoding="utf-8")
        assert "getpass" in source

    def test_a_piped_passphrase_is_read_rather_than_hanging(self, tmp_path: Path) -> None:
        """The drill found this: `getpass` on Windows opens the console, not stdin.

        A piped passphrase there does not fail, it hangs -- which made the one
        procedure nobody can afford to get wrong also the one procedure nobody
        could rehearse unattended. Every operator script in this repository grew
        a stdin fallback for exactly that reason; the shipped CLI had not.

        Piping is the operator choosing to. An argument would be visible to
        everyone on the machine whether they chose it or not, which is why
        `test_no_command_takes_a_passphrase_or_a_seed_as_an_argument` still
        stands above this one.
        """
        target = tmp_path / "piped.json"
        result = runner.invoke(
            app, ["key", "create", str(target)], input=f"{PASSPHRASE}\n{PASSPHRASE}\n"
        )
        assert result.exit_code == 0, result.stdout
        assert target.is_file()

        reopened = runner.invoke(app, ["key", "show", str(target)])
        assert reopened.exit_code == 0

    def test_an_empty_stdin_refuses_instead_of_waiting(self, tmp_path: Path) -> None:
        """A scheduled task with no input must fail, not block until it is killed."""
        result = runner.invoke(app, ["key", "create", str(tmp_path / "nope.json")], input="")
        assert result.exit_code != 0
        assert not (tmp_path / "nope.json").exists()

    def test_key_show_prints_only_the_did(self, created: tuple[Path, str]) -> None:
        path, did = created
        result = runner.invoke(app, ["key", "show", str(path)])
        assert result.exit_code == 0
        assert result.stdout.strip() == did

    def test_creating_prints_the_did_and_warns_about_revocation(self, tmp_path: Path) -> None:
        target = tmp_path / "new.json"
        result = runner.invoke(
            app, ["key", "create", str(target)], input=f"{PASSPHRASE}\n{PASSPHRASE}\n"
        )
        assert result.exit_code == 0, result.stdout
        assert "KEY CREATED" in result.stdout
        assert "did:key:z" in result.stdout
        assert "cannot be revoked" in " ".join(result.stdout.split())

    def test_mismatched_passphrases_are_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "new.json"
        result = runner.invoke(
            app, ["key", "create", str(target)], input="aaaaaaaaaaaa\nbbbbbbbbbbbb\n"
        )
        assert result.exit_code == 2
        assert not target.exists()

    def test_the_passphrase_is_not_echoed_back(self, tmp_path: Path) -> None:
        target = tmp_path / "new.json"
        result = runner.invoke(
            app, ["key", "create", str(target)], input=f"{PASSPHRASE}\n{PASSPHRASE}\n"
        )
        assert PASSPHRASE not in result.stdout

    def test_signing_produces_a_verifying_envelope(
        self, created: tuple[Path, str], tmp_path: Path
    ) -> None:
        from datetime import UTC, datetime

        from lineageauth.builders import build_root_create
        from lineageauth.envelope import Envelope
        from lineageauth.verify import verify_event

        path, did = created
        payload_file = tmp_path / "payload.json"
        payload_file.write_text(
            json.dumps(build_root_create(root_did=did, issued_at=datetime.now(tz=UTC))),
            encoding="utf-8",
        )
        result = runner.invoke(
            app, ["sign", str(payload_file), "--key", str(path)], input=f"{PASSPHRASE}\n"
        )
        assert result.exit_code == 0, result.stdout
        envelope = Envelope.from_json(result.stdout[result.stdout.index("{") :])
        assert verify_event(envelope).integrity_ok
        assert envelope.proofs[0].signer == did

    def test_signing_refuses_a_whole_envelope(
        self, created: tuple[Path, str], tmp_path: Path
    ) -> None:
        """Signing an envelope would sign the proofs, which is not a thing."""
        path, _ = created
        target = tmp_path / "envelope.json"
        target.write_text(json.dumps({"payload": {}, "proofs": []}), encoding="utf-8")
        result = runner.invoke(
            app, ["sign", str(target), "--key", str(path)], input=f"{PASSPHRASE}\n"
        )
        assert result.exit_code == 2

    def test_a_created_key_would_not_be_committed(self) -> None:
        """The gitignore already refuses the shapes this tool produces."""
        ignore = (Path(__file__).resolve().parents[1] / ".gitignore").read_text(encoding="utf-8")
        assert re.search(r"^\*\.key$", ignore, re.M)
        assert re.search(r"^\*_private\*$", ignore, re.M)
