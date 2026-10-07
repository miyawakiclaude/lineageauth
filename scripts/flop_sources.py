"""Fetch the official FLOP sources and hold the registry to them (D-119).

Run: `uv run python scripts/flop_sources.py check`
     `uv run python scripts/flop_sources.py snapshot --note "..." [overrides]`

`check` fetches every source named in `conformance/flop/official-sources.json`,
keeps the bodies under `.flop-sources/<instant>/` (git-ignored; bodies never
enter the repository), and prints for each one whether its bytes and its
wording moved since the recorded snapshot. It then checks every quotation in
`conformance/flop/rule-registry.json` against the fresh bodies. It writes
nothing under `conformance/`. Exit status 1 when a fetch failed or a quotation
is no longer in its source: that is the signal to take a snapshot and re-quote.

`snapshot` does the same fetch and then writes the next `official-sources.json`,
re-stamps every verified rule in `rule-registry.json` to the new hashes, and
regenerates the rules table in `docs/FLOP_RULE_REGISTRY.md` between its
markers. It refuses when a quotation is missing unless `--allow-stale` is
given, in which case that rule keeps its old hash and shows as RULE UPDATED at
runtime until someone re-quotes it. The prose around the table, the version
hints and the notes are a person's reading of the pages: pass them with
`--hint id=text`, `--source-note id=text`, `--rule-source id=version|date`, and
say what the snapshot found in `--note`. A new official page is added with
`--add id=url` and needs `--status id=status`. Each id may be given once per
flag, and every id, status and added URL is checked before anything is fetched.

This is the only place in the FLOP layer that opens a network connection. It
reads public pages over HTTPS and sends nothing but the request.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "packages" / "py"))

from lineageauth.errors import MalformedEventError  # noqa: E402
from lineageauth.flop.rules import RULE_REGISTRY_FILE  # noqa: E402
from lineageauth.flop.snapshot import (  # noqa: E402
    SOURCE_STATUSES,
    FetchedBody,
    QuotationCheck,
    build_sources_document,
    history_entry,
    render_rules_table,
    replace_rules_table,
    restamp_registry,
    verify_registry,
)
from lineageauth.flop.sources import OFFICIAL_SOURCES_FILE, classify_source, read_json  # noqa: E402

DOCS_PAGE = REPO / "docs" / "FLOP_RULE_REGISTRY.md"
BODIES_ROOT = REPO / ".flop-sources"
USER_AGENT = "lineageauth-source-check (+https://github.com/miyawakiclaude/lineageauth)"
TIMEOUT_SECONDS = 30


def now_instant() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch(url: str) -> tuple[int, bytes]:
    """GET one official page. HTTPS only; the classifier decides what is official."""
    if urlsplit(url).scheme != "https":
        raise ValueError(f"refusing a non-HTTPS source: {url}")
    if not classify_source(url).source_class.value == "official":
        raise ValueError(f"refusing a source the classifier does not call official: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            return int(response.status), bytes(response.read())
    except urllib.error.HTTPError as error:
        return int(error.code), b""


NEW_SOURCE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


def _same_page(url: str) -> str:
    """A URL reduced to what names the page: host case and a trailing slash do not."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc.lower()}{parts.path.rstrip('/') or '/'}"


def parse_additions(values: list[str], document: dict[str, object]) -> list[dict[str, str]]:
    """`--add ID=URL` entries, refused unless the id is new, the URL is official HTTPS,
    and the page is not already a source under another id (or added twice)."""
    sources = document.get("sources")
    entries = [e for e in sources if isinstance(e, dict)] if isinstance(sources, list) else []
    existing = {str(e["id"]) for e in entries}
    pages = {_same_page(str(e["url"])): str(e["id"]) for e in entries if e.get("url")}
    added: list[dict[str, str]] = []
    for source_id, url in parse_pairs(values, flag="--add").items():
        if not NEW_SOURCE_ID.fullmatch(source_id):
            raise SystemExit(f"--add: {source_id!r} is not a valid source id")
        if source_id in existing:
            raise SystemExit(f"--add: {source_id!r} is already a source")
        if urlsplit(url).scheme != "https" or classify_source(url).source_class.value != "official":
            raise SystemExit(f"--add: {url!r} is not an official HTTPS source")
        page = _same_page(url)
        if page in pages:
            raise SystemExit(f"--add: {url!r} is already recorded as {pages[page]!r}")
        pages[page] = source_id
        added.append({"id": source_id, "url": url, "sha256": "new"})
    return added


def check_overrides(
    document: dict[str, object],
    additions: list[dict[str, str]],
    *,
    statuses: dict[str, str],
    hints: dict[str, str],
    notes: dict[str, str],
    rule_sources: dict[str, str],
) -> None:
    """Refuse, before anything is fetched, what `build_sources_document` would refuse
    after twenty fetches: an added source without a status, a status outside the
    vocabulary, or an override naming a source that neither exists nor is added."""
    sources = document.get("sources")
    known = (
        {str(e["id"]) for e in sources if isinstance(e, dict)}
        if isinstance(sources, list)
        else set()
    )
    added = {a["id"] for a in additions}
    unstated = sorted(added - set(statuses))
    if unstated:
        raise SystemExit(f"--add needs --status for each new source: {unstated}")
    bad = sorted(f"{k}={v}" for k, v in statuses.items() if v not in SOURCE_STATUSES)
    if bad:
        raise SystemExit(f"--status must be one of {', '.join(SOURCE_STATUSES)}: {bad}")
    for flag, overrides in (
        ("--status", statuses),
        ("--hint", hints),
        ("--source-note", notes),
        ("--rule-source", rule_sources),
    ):
        unknown = sorted(set(overrides) - known - added)
        if unknown:
            raise SystemExit(f"{flag} names sources that do not exist: {unknown}")


def fetch_all(
    document: dict[str, object], additions: list[dict[str, str]] | None = None
) -> tuple[list[FetchedBody], dict[str, int], list[str]]:
    """Every source with a recorded hash is fetched, plus any `--add` sources; the
    listing gets a status only."""
    bodies: list[FetchedBody] = []
    statuses: dict[str, int] = {}
    failures: list[str] = []
    sources = document.get("sources")
    if not isinstance(sources, list):
        raise SystemExit("official-sources.json needs a sources array")
    for entry in [*sources, *(additions or [])]:
        if not isinstance(entry, dict):
            continue
        source_id, url = str(entry["id"]), str(entry["url"])
        instant = now_instant()
        try:
            status, body = fetch(url)
        except (urllib.error.URLError, ValueError, TimeoutError, OSError) as error:
            failures.append(f"{source_id}: {error}")
            continue
        if entry.get("sha256") is None:
            statuses[source_id] = status
            continue
        if status != 200 or not body:
            failures.append(f"{source_id}: HTTP {status}, {len(body)} bytes")
            continue
        bodies.append(FetchedBody(source_id, url, status, body, instant))
    return bodies, statuses, failures


def keep_bodies(bodies: list[FetchedBody], instant: str) -> Path:
    folder = BODIES_ROOT / instant.replace(":", "")
    folder.mkdir(parents=True, exist_ok=True)
    for item in bodies:
        (folder / f"{item.source_id}.body").write_bytes(item.body)
    return folder


def report_history(previous: dict[str, object], bodies: list[FetchedBody]) -> int:
    old_sources = previous.get("sources")
    old_by_id = (
        {str(e["id"]): e for e in old_sources if isinstance(e, dict)}
        if isinstance(old_sources, list)
        else {}
    )
    moved = 0
    for item in bodies:
        line = history_entry(
            item.source_id,
            old_by_id.get(item.source_id),
            new_hash=item.sha256,
            new_text_hash=item.text_sha256,
        )
        if line.text == "changed" or line.change == "added":
            moved += 1
        size = f"{len(item.body):>7} B"
        print(
            f"  {item.source_id:<32} {item.http_status} {size}  {line.change:<13} text={line.text}"
        )
    return moved


def report_checks(checks: tuple[QuotationCheck, ...]) -> list[QuotationCheck]:
    failed = [check for check in checks if check.failed]
    quoted = sum(1 for check in checks if check.kind == "quotation")
    print(f"  quotations checked: {quoted}, not found: {len(failed)}")
    for check in failed:
        print(f"    NOT FOUND  {check.rule_id}  (source {check.source_id})")
    unchecked = [check for check in checks if check.kind == "no-body"]
    for check in unchecked:
        print(f"    no body    {check.rule_id}  (source {check.source_id} was not fetched)")
    return failed


def parse_pairs(values: list[str], *, separator: str = "=", flag: str = "") -> dict[str, str]:
    """`id=text` pairs. The same id twice is refused: a dict would keep the last one
    silently, and which of two hints or statuses was meant is not ours to guess."""
    prefix = f"{flag}: " if flag else ""
    out: dict[str, str] = {}
    for value in values:
        key, sep, rest = value.partition(separator)
        if not sep or not key:
            raise SystemExit(f"{prefix}expected id{separator}text, got {value!r}")
        if key in out:
            raise SystemExit(f"{prefix}{key!r} is given more than once")
        out[key] = rest
    return out


def command_check(args: argparse.Namespace) -> int:
    previous = read_json(OFFICIAL_SOURCES_FILE)
    registry = read_json(RULE_REGISTRY_FILE)
    instant = now_instant()
    bodies, statuses, failures = fetch_all(previous)
    folder = keep_bodies(bodies, instant)
    print(f"fetched {len(bodies)} bodies at {instant}; kept under {folder.relative_to(REPO)}")
    for source_id, status in statuses.items():
        print(f"  {source_id:<32} {status}  listing (no hash recorded)")
    moved = report_history(previous, bodies)
    checks = verify_registry(registry, {item.source_id: item for item in bodies})
    failed = report_checks(checks)
    for failure in failures:
        print(f"  FETCH FAILED  {failure}")
    print(
        f"wording moved on {moved} source(s); {len(failed)} quotation(s) missing; "
        f"{len(failures)} fetch failure(s). Nothing under conformance/ was written."
    )
    return 1 if failed or failures else 0


def command_snapshot(args: argparse.Namespace) -> int:
    try:
        return _snapshot(args)
    except MalformedEventError as error:
        # Anything the checks before the fetch did not catch still ends in one line.
        raise SystemExit(f"snapshot refused: {error}") from None


def _snapshot(args: argparse.Namespace) -> int:
    previous = read_json(OFFICIAL_SOURCES_FILE)
    registry = read_json(RULE_REGISTRY_FILE)
    instant = now_instant()
    additions = parse_additions(args.add, previous)
    version_hints = parse_pairs(args.hint, flag="--hint")
    notes = parse_pairs(args.source_note, flag="--source-note")
    source_statuses = parse_pairs(args.status, flag="--status")
    rule_source_pairs = parse_pairs(args.rule_source, flag="--rule-source")
    check_overrides(
        previous,
        additions,
        statuses=source_statuses,
        hints=version_hints,
        notes=notes,
        rule_sources=rule_source_pairs,
    )
    bodies, statuses, failures = fetch_all(previous, additions)
    if failures:
        for failure in failures:
            print(f"  FETCH FAILED  {failure}")
        print("a snapshot needs every source; nothing written")
        return 1
    folder = keep_bodies(bodies, instant)
    print(f"fetched {len(bodies)} bodies at {instant}; kept under {folder.relative_to(REPO)}")
    report_history(previous, bodies)
    checks = verify_registry(registry, {item.source_id: item for item in bodies})
    failed = report_checks(checks)
    if failed and not args.allow_stale:
        print("a quotation is no longer in its source; re-quote it, or pass --allow-stale")
        print("to leave that rule at its old hash (it will show as RULE UPDATED). Nothing written.")
        return 1

    listing_status = next(iter(statuses.values()), None)
    sources_document = build_sources_document(
        previous,
        bodies,
        fetched_at=instant,
        version_hints=version_hints,
        notes=notes,
        statuses=source_statuses,
        listing_status=listing_status,
    )
    rule_sources = {
        source_id: (version, date)
        for source_id, pair in rule_source_pairs.items()
        for version, _, date in [pair.partition("|")]
    }
    new_registry = restamp_registry(
        registry,
        sources_document,
        checks,
        generated_at=instant,
        revision_note=args.note,
        source_versions=rule_sources,
    )
    if args.dry_run:
        print("dry run: documents built and valid; nothing written")
        return 0
    OFFICIAL_SOURCES_FILE.write_text(
        json.dumps(sources_document, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    RULE_REGISTRY_FILE.write_text(
        json.dumps(new_registry, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    page = DOCS_PAGE.read_text(encoding="utf-8")
    DOCS_PAGE.write_text(
        replace_rules_table(page, render_rules_table(new_registry)), encoding="utf-8", newline="\n"
    )
    print("wrote official-sources.json, rule-registry.json and the rules table in docs/")
    print("the prose around the table and docs/29_DECISIONS.md are yours to write")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "check", help="fetch, compare with the snapshot, verify every quotation; write nothing"
    )
    snap = sub.add_parser("snapshot", help="fetch and write the next snapshot and registry")
    snap.add_argument(
        "--note", required=True, help="the registry's revisionNote: what this snapshot found"
    )
    snap.add_argument(
        "--hint", action="append", default=[], metavar="ID=TEXT", help="versionHint override"
    )
    snap.add_argument(
        "--source-note", action="append", default=[], metavar="ID=TEXT", help="note override"
    )
    snap.add_argument(
        "--rule-source",
        action="append",
        default=[],
        metavar="ID=VERSION|DATE",
        help="sourceVersion and sourceDate for every rule citing that source",
    )
    snap.add_argument(
        "--add",
        action="append",
        default=[],
        metavar="ID=URL",
        help="a new official source to fetch and record as added (needs --status)",
    )
    snap.add_argument(
        "--status",
        action="append",
        default=[],
        metavar="ID=STATUS",
        help="official-draft, official-reference or official-final",
    )
    snap.add_argument(
        "--allow-stale", action="store_true", help="write even if a quotation is missing"
    )
    snap.add_argument(
        "--dry-run", action="store_true", help="build the documents and write nothing"
    )
    args = parser.parse_args(argv)
    if args.command == "check":
        return command_check(args)
    return command_snapshot(args)


if __name__ == "__main__":
    raise SystemExit(main())
