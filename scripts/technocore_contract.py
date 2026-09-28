"""Re-derive conformance/technocore/route-contract.json from the served /openapi.json.

Run: `uv run python scripts/technocore_contract.py [--allow-route-change]`

The contract (D-115) lists every operation Technocore serves and marks the
seven that mutate. The service moves faster than its routes: 0.13.0, 0.14.3 and
0.14.5 served the same 31 operations with three different document hashes. This
script fetches the current document, rebuilds the operation table by the same
rule, and refuses to write if any operation's method, path, operationId,
summary or mutating mark differs from the pinned set - a moved route is a
change to `adapters/technocore/routes.py` and to `docs/18_TECHNOCORE.md`, not a
re-pin, and `--allow-route-change` is the explicit way to say that work has been
done. The previous pin stays in `_meta.previous`.

Network: one HTTPS GET of a URL the source classifier calls official. Nothing
is sent but the request. The document body is not stored; its hash is.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "packages" / "py"))

from lineageauth.flop.sources import classify_source  # noqa: E402

CONTRACT = REPO / "conformance" / "technocore" / "route-contract.json"
README = REPO / "conformance" / "technocore" / "README.md"
SOURCE_URL = "https://technocore.chat/openapi.json"
MUTATING = {
    "say",
    "saySigned",
    "writeNote",
    "writeNoteSigned",
    "postMessage",
    "postToEvents",
    "postNote",
}
REFUSED = {"postToEvents"}
USER_AGENT = "lineageauth-source-check (+https://github.com/miyawakiclaude/lineageauth)"


def operations_of(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Every operation, in document order, with the mutating mark applied by operationId."""
    rows: list[dict[str, Any]] = []
    for path, methods in document["paths"].items():
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue
            operation_id = str(op.get("operationId", ""))
            rows.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "operationId": operation_id,
                    "mutating": operation_id in MUTATING,
                    "serverRefuses": operation_id in REFUSED,
                    "summary": str(op.get("summary") or "")[:120],
                }
            )
    return rows


def fetch(url: str) -> bytes:
    if classify_source(url).source_class.value != "official" or not url.startswith("https://"):
        raise SystemExit(f"refusing to fetch {url}: not an official HTTPS source")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return bytes(response.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--allow-route-change", action="store_true", help="write even if the operation set moved"
    )
    parser.add_argument("--dry-run", action="store_true", help="fetch and compare; write nothing")
    args = parser.parse_args(argv)

    previous = json.loads(CONTRACT.read_text(encoding="utf-8"))
    fetched_at = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = fetch(SOURCE_URL)
    document = json.loads(raw)
    operations = operations_of(document)
    mutating = sum(1 for op in operations if op["mutating"])
    version = str(document.get("info", {}).get("version"))
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    same_routes = operations == previous["operations"]
    pinned_version = previous["_meta"]["serviceVersion"]
    print(f"served {version}: {len(operations)} operations, {mutating} mutating, {len(raw)} bytes")
    print(f"  {digest}")
    print(f"pinned {pinned_version}: routes {'unchanged' if same_routes else 'CHANGED'}")
    if not same_routes:
        pinned = {(o["method"], o["path"]): o for o in previous["operations"]}
        served = {(o["method"], o["path"]): o for o in operations}
        for key in sorted(set(served) - set(pinned)):
            print("  added  ", *key)
        for key in sorted(set(pinned) - set(served)):
            print("  removed", *key)
        for key in sorted(set(served) & set(pinned)):
            if served[key] != pinned[key]:
                print("  changed", *key)
        if not args.allow_route_change:
            print("the operation set moved: update routes.py and docs/18 first,")
            print("then pass --allow-route-change")
            return 1
    if mutating != 7 and not args.allow_route_change:
        print(f"{mutating} mutating operations, not seven: the mutating rule needs a person")
        return 1
    if digest == previous["_meta"]["sha256"]:
        print("the served document is the pinned document; nothing to write")
        return 0
    if args.dry_run:
        print("dry run; nothing written")
        return 0

    meta = dict(previous["_meta"])
    meta.update(
        {
            "fetchedAt": fetched_at,
            "openapiVersion": document.get("openapi"),
            "serviceVersion": version,
            "sha256": digest,
            "bytes": len(raw),
            "previous": {
                "serviceVersion": previous["_meta"]["serviceVersion"],
                "fetchedAt": previous["_meta"]["fetchedAt"],
                "sha256": previous["_meta"]["sha256"],
                "operationsChanged": not same_routes,
                "note": f"Re-derived at {version} by scripts/technocore_contract.py. "
                + (
                    "Every operation - method, path, operationId, summary and the mutating "
                    f"mark - is identical to the {pinned_version} document; only the "
                    "version string, and therefore the hash, moved."
                    if same_routes
                    else "The operation set moved; routes.py and docs/18_TECHNOCORE.md were "
                    "updated with it."
                ),
            },
        }
    )
    CONTRACT.write_text(
        json.dumps({"_meta": meta, "operations": operations}, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    readme = README.read_text(encoding="utf-8")
    marker = "(fetched "
    start = readme.find(marker)
    end = readme.find(", hash recorded", start)
    if start >= 0 and end > start:
        readme = (
            readme[:start] + f"(fetched {fetched_at[:10]}, technocore-chat {version}" + readme[end:]
        )
        README.write_text(readme, encoding="utf-8", newline="\n")
    print("wrote route-contract.json; the test pin, routes.py note and docs/18 are yours")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
