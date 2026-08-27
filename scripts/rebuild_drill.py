"""The backup and rebuild drill (`docs/25`).

Run: `uv run python scripts/rebuild_drill.py ./events --db ./index.sqlite3`

A backup you have never restored is a hope, not a backup. This is the restore,
run against the real store, and it is cheap enough to run on a schedule.

What it proves, and the order matters:

1. the index's checksum before anything happens;
2. the index file is **deleted** -- not truncated, not "rebuilt in place",
   because the failure mode worth catching is an index that only looks
   reconstructible while the old file is still there;
3. a fresh index is built from the store alone;
4. the checksum matches.

If step 4 fails, the index was holding state that never came from a signed
event, and that is a bug in the index rather than a problem with the drill. The
store is the authoritative side and the only thing that has to survive; this
drill is how you find out whether that is true here rather than only in the
design.

Nothing is written to the store. The only file this touches is the index, and
it is a file whose entire purpose is being safe to delete.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "packages" / "py"))

from lineageauth.index import EventIndex  # noqa: E402
from lineageauth.store import FileEventStore  # noqa: E402


def drill(store_path: Path, db_path: Path) -> int:
    store = FileEventStore(store_path)
    print(f"  store        {store_path} ({len(store)} event(s))")

    with EventIndex(str(db_path)) as index:
        before = index.checksum()
        before_count = len(index)
    print(f"  before       {before}  ({before_count} indexed)")

    # Keep a copy only so a failed drill is diagnosable. It is never read back
    # into the rebuild: reading it would be the drill grading its own work.
    backup = Path(tempfile.mkdtemp(prefix="la-drill-")) / db_path.name
    if db_path.exists():
        shutil.copy2(db_path, backup)
        db_path.unlink()
        print(f"  deleted      {db_path}")
        print(f"  (a copy is at {backup} for diagnosis only; the rebuild does not read it)")

    with EventIndex(str(db_path)) as rebuilt:
        indexed, rejected = rebuilt.rebuild(store)
        after = rebuilt.checksum()
        after_count = len(rebuilt)
    print(f"  rebuilt      {indexed} indexed, {rejected} refused")
    print(f"  after        {after}  ({after_count} indexed)")

    if rejected:
        print(f"\n  FAIL  {rejected} event(s) in the store did not verify on the way back in")
        return 1
    if after != before:
        print("\n  FAIL  the checksum changed across a rebuild.")
        print("        The index was holding state that never came from a signed event.")
        return 1
    print("\n  PASS  the index reconstructed from the store alone, byte for byte")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("store", help="Directory holding the event store.")
    parser.add_argument("--db", required=True, help="Path to the SQLite index.")
    args = parser.parse_args()
    return drill(Path(args.store), Path(args.db))


if __name__ == "__main__":
    sys.exit(main())
