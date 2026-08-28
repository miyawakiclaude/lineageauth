"""Run every check CI runs, and fail if any of them fails.

Run: `uv run python scripts/gate.py`

This exists because of a mistake worth not repeating. Running the four checks
by hand and reading their output is not the same as running them and honouring
their exit codes -- piping `ruff check` into `tail` to see the last line makes
the pipeline's status `tail`'s status, which is always zero. A lint failure got
committed that way: the output said so, and the shell said everything was fine.

So the four are one command now, each one's exit status is checked, and the
summary at the end is the thing to read.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# The same four, in the same order, as .github/workflows/ci.yml. `ruff check`
# passing is not `ruff format --check` passing: the first finds lint problems
# and the second finds formatting ones, and CI runs both.
CHECKS: tuple[tuple[str, list[str]], ...] = (
    ("lint", ["ruff", "check", "."]),
    ("format", ["ruff", "format", "--check", "."]),
    ("types", ["mypy"]),
    # No -q here. `pyproject.toml` already has -q in addopts, and the two combine
    # into -qq, which suppresses the "N passed" line entirely. A gate that cannot
    # say how many tests ran can only report that nothing objected -- and a suite
    # that collected nothing reports exactly that too. (D-097.)
    ("tests", ["pytest"]),
)


def _test_tally(output: str) -> str:
    """The "N passed" line, so the summary says what actually ran."""
    for line in reversed(output.splitlines()):
        if " passed" in line or " failed" in line or "no tests ran" in line:
            return line.strip().strip("=").strip()
    return "no result line found -- did the suite collect anything?"


def main() -> int:
    results: list[tuple[str, int, str]] = []
    for name, command in CHECKS:
        print(f"\n=== {name}: {' '.join(command)}")
        if name != "tests":
            done = subprocess.run(command, cwd=str(REPO), check=False)  # noqa: S603
            results.append((name, done.returncode, ""))
            continue
        # Captured so the count can be read back, then echoed in full so that
        # capturing it hides nothing from whoever is watching the run.
        captured = subprocess.run(  # noqa: S603
            command, cwd=str(REPO), check=False, capture_output=True, text=True
        )
        print(captured.stdout, end="")
        if captured.stderr:
            print(captured.stderr, end="", file=sys.stderr)
        results.append((name, captured.returncode, _test_tally(captured.stdout)))

    print("\n=== summary")
    for name, code, note in results:
        detail = f"  -- {note}" if note else ""
        print(f"  {'PASS' if code == 0 else 'FAIL'}  {name}{detail}")

    failed = [name for name, code, _ in results if code != 0]
    if failed:
        print(f"\n{len(failed)} check(s) failed: {', '.join(failed)}")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
