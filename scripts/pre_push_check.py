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
)

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


def git(*args: str) -> str:
    """Run one read-only git command, with the executable resolved explicitly.

    Resolved rather than left to PATH lookup: this runs as a hook, in whatever
    environment the push happened to have, and a check that can be redirected by
    a PATH entry is not much of a check.
    """
    if GIT is None:
        return ""
    done = subprocess.run(  # noqa: S603
        [GIT, "-C", str(REPO), *args], capture_output=True, text=True, check=False
    )
    return done.stdout.strip() if done.returncode == 0 else ""


def tracked_text() -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    for name in git("ls-files").splitlines():
        if not name or name in EXEMPT:
            continue
        path = REPO / name
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            files.append((name, path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return files


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
    email = git("config", "--get", "user.email").lower()
    if not email:
        return ["no committer address is configured"]
    return [
        f"the committer address {email} looks like a company identity"
        for marker in COMPANY_IDENTITY
        if marker in email
    ]


def check_tree() -> list[str]:
    problems: list[str] = []
    for name, text in tracked_text():
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
