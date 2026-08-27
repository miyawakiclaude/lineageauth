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
    ("tests", ["pytest", "-q"]),
)


def main() -> int:
    results: list[tuple[str, int]] = []
    for name, command in CHECKS:
        print(f"\n=== {name}: {' '.join(command)}")
        done = subprocess.run(command, cwd=str(REPO), check=False)  # noqa: S603
        results.append((name, done.returncode))

    print("\n=== summary")
    for name, code in results:
        print(f"  {'PASS' if code == 0 else 'FAIL'}  {name}")

    failed = [name for name, code in results if code != 0]
    if failed:
        print(f"\n{len(failed)} check(s) failed: {', '.join(failed)}")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
