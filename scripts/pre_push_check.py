"""Refuse a push that would send this project somewhere it does not belong.

Installed as a git `pre-push` hook. Run directly to check without pushing:

    uv run python scripts/pre_push_check.py

`CLAUDE.md` 2.8 keeps this project off every company resource, and the moment
that rule can actually be broken is a push. Everything before that is local and
recoverable; a push is the irreversible part, because a public repository that
briefly contained company material has published it, and deleting the commit
afterwards does not unpublish it.

So the checks here are the ones that only matter at that moment:

  * the remote is the personal account
  * no company identity or path is in the tree
  * no key material is in the tree
  * the committer address is not a company address

None of this is clever. It is a stop sign in the one place where being wrong
cannot be undone.

Bypassing it is `git push --no-verify`, which is deliberately easy: a check
that cannot be bypassed gets deleted the first time it is wrong, and a check
that says out loud how to bypass it gets read instead.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

PERSONAL_ACCOUNT = "miyawakiclaude"

COMPANY_IDENTITY = ("katagrma", "katagruma", "カタグルマ")
COMPANY_PATH = re.compile(
    r"""[A-Za-z]:[\\/][^\s"']*(?:OneDrive|デスクトップ)""",
    re.IGNORECASE,
)
SECRETS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r'"d"\s*:\s*"[A-Za-z0-9_-]{20,}"'),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # This project's own key material, which the list above did not describe at
    # all. An Ed25519 seed here is 64 hex characters; none of the patterns above
    # would see one. The scanner knew every shape except the one it exists to
    # protect.
    #
    # `(?<!sha256:)` because an event id is also 64 hex characters and they are
    # everywhere in this repository. Matching those would fire on every commit
    # until somebody deleted the check, which is how a scanner that cries wolf
    # ends up not existing.
    re.compile(r"(?<!sha256:)(?<![0-9a-fA-F])[0-9a-f]{64}(?![0-9a-fA-F])"),
    re.compile(r"\b(?:SIGN_SEED|SEED|seed)\s*[:=]\s*[\"']?[0-9a-fA-F]{64}"),
)

# Names that are key material whatever happens to be inside them.
SECRET_NAMES = re.compile(r"(?:^|/)(?:seed\.txt|[^/]*\.pem|[^/]*\.key|\.env)$", re.IGNORECASE)

# The scan names what it looks for, so it necessarily contains those strings.
EXEMPT = {
    "scripts/pre_push_check.py",
    "tests/test_final_gate.py",
}

TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".html",
    ".css",
    ".js",
    ".txt",
    ".cfg",
    ".ini",
}


GIT = shutil.which("git")


def git(*args: str) -> str | None:
    """Run one read-only git command, with the executable resolved explicitly.

    Resolved rather than left to PATH lookup: this runs as a hook, in whatever
    environment the push happened to have, and a check that can be redirected by
    a PATH entry is not much of a check.

    Returns None when the command failed, rather than an empty string. The two
    are not the same thing and treating them alike was a hole: `check_remote`
    turned "" into a refusal, but `tracked_text` split it into an empty list and
    reported a clean tree. A scanner that finds nothing because it looked at
    nothing must not be able to say "clean".
    """
    if GIT is None:
        return None
    done = subprocess.run(  # noqa: S603
        [GIT, "-C", str(REPO), *args], capture_output=True, text=True, check=False
    )
    return done.stdout.strip() if done.returncode == 0 else None


def tracked_text() -> tuple[list[tuple[str, str]], list[str]]:
    """Every scannable file, and every file that could not be scanned.

    A file this cannot read is not a file without secrets. Two ways that
    mattered here: `git ls-files` failing produced an empty list that read as a
    clean tree, and a UTF-16 file -- which is what PowerShell's `>` writes on
    this machine, as `cli.py` says in as many words -- was skipped silently. The
    most likely encoding on the operator's own console was a blind spot in the
    check that guards the irreversible step.
    """
    files: list[tuple[str, str]] = []
    unreadable: list[str] = []

    # `--others --exclude-standard` so a file that exists and has never been
    # staged is still seen. A push does not send it, but somebody about to push
    # is somebody about to commit, and the cheap moment to catch this is now.
    listing = git("ls-files", "--cached", "--others", "--exclude-standard")
    if listing is None:
        return [], ["git ls-files failed, so no file was scanned at all"]

    for name in listing.splitlines():
        if not name or name in EXEMPT:
            continue
        path = REPO / name
        # Before the suffix filter, not after it. A `.pem` or a `seed.txt` is
        # key material by its name, and those are exactly the extensions the
        # text filter was dropping -- so the check that looked for secrets never
        # saw the files most likely to be one.
        if SECRET_NAMES.search(name):
            unreadable.append(f"{name} is named like key material and must not be in the tree")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            unreadable.append(f"{name} could not be read ({exc.__class__.__name__})")
            continue
        for encoding in ("utf-8-sig", "utf-16-le", "utf-16-be"):
            try:
                files.append((name, raw.decode(encoding)))
                break
            except UnicodeDecodeError:
                continue
        else:
            unreadable.append(f"{name} is not text this check can decode, so it went unscanned")
    return files, unreadable


def check_remote() -> list[str]:
    url = git("remote", "get-url", "origin")
    if not url:
        return ["no origin remote is configured, so there is nothing to check it against"]
    if f"/{PERSONAL_ACCOUNT}/" not in url and f":{PERSONAL_ACCOUNT}/" not in url:
        return [
            f"origin is {url}, which is not the personal account "
            f"{PERSONAL_ACCOUNT!r}. This project must not be pushed anywhere else"
        ]
    return []


def check_identity() -> list[str]:
    raw = git("config", "--get", "user.email")
    email = (raw or "").lower()
    if not email:
        # Not a violation. An unset address is not a company address, and git
        # will not let a commit happen without one anyway. Treating "unset" as a
        # failure was a false positive -- it fired in CI, where nobody is
        # committing -- and a check that cries wolf is a check somebody
        # bypasses and then deletes.
        return []
    return [
        f"the committer address {email} looks like a company identity"
        for marker in COMPANY_IDENTITY
        if marker in email
    ]


# tclk/1 ids, statements and hash-shaped fields are `0x` + 64 hex by wire format
# (flop-labs/tclk SPEC.md 3), so the reference's golden vectors and the synthetic
# transcript under conformance/tclk/ are made of exactly the string the 64-hex
# rule exists to catch. Scoped to that directory and to the `0x` spelling only:
# a bare 64-hex anywhere, or a `0x` one anywhere else, still fires. The one
# field there that really is a secret -- the reveal's preimage -- is pinned to
# the documented UNSAFE test constant by tests/test_tclk.py, so this exemption
# cannot quietly become a place to leave a real one.
TCLK_FIXTURES = "conformance/tclk/"
_TCLK_WIRE_HEX = re.compile(r"0x[0-9a-f]{64}(?![0-9a-fA-F])")


def scannable_text(name: str, text: str) -> str:
    """The text the secret patterns run over. Identity except under conformance/tclk/."""
    if not name.startswith(TCLK_FIXTURES):
        return text
    return _TCLK_WIRE_HEX.sub("0x<tclk-wire-hex>", text)


def check_tree() -> list[str]:
    problems: list[str] = []
    scanned, unreadable = tracked_text()
    problems.extend(unreadable)
    if not scanned:
        problems.append("scanned 0 files -- this check did nothing and cannot say 'clean'")
    for name, raw_text in scanned:
        text = scannable_text(name, raw_text)
        lowered = text.lower()
        problems.extend(
            f"{name} names the company ({marker})"
            for marker in COMPANY_IDENTITY
            if marker.lower() in lowered
        )
        problems.extend(
            f"{name} embeds a path into the company tree ({hit})"
            for hit in COMPANY_PATH.findall(text)
        )
        problems.extend(
            f"{name} matches a secret pattern ({pattern.pattern})"
            for pattern in SECRETS
            if pattern.search(text)
        )
    return problems


def main() -> int:
    if GIT is None:
        print("pre-push: git is not on PATH, so nothing could be checked", file=sys.stderr)
        return 1

    problems = check_remote() + check_identity() + check_tree()

    if not problems:
        print("pre-push: remote, identity and tree are clean")
        return 0

    print("\npre-push REFUSED\n", file=sys.stderr)
    for problem in problems:
        print(f"  !! {problem}", file=sys.stderr)
    print(
        "\nA push is the irreversible part. A public repository that briefly held\n"
        "company material has published it, and deleting the commit afterwards\n"
        "does not unpublish it.\n"
        "\nIf this is wrong, `git push --no-verify` and then fix the check.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
