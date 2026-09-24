"""Taking an official-source snapshot: the pure half (D-119).

Everything here works on bytes already fetched. Fetching is the job of
`scripts/flop_sources.py`, which is the only place a network call is made; this
module can be tested without one and is subject to the FLOP layer's ban on
network imports.

What a snapshot is made of, and what this module computes for it:

- the **byte hash** of each body, which `official-sources.json` has always
  recorded and `RULE UPDATED` keys on;
- the **text hash** (D-117): the same body with tags, scripts and styles
  removed, entities decoded and whitespace collapsed, so a page rebuilt without
  a word changing shows `hash-changed` and `text=unchanged`;
- the **history** entry per source against the previous snapshot;
- the **quotation check**: every registry rule marked `statementIsQuotation`
  must occur, after light normalisation, in the body its source names. A rule
  that fails is reported and left as it was, so that the runtime shows it as
  `RULE UPDATED` rather than the snapshot quietly re-stamping a quotation the
  page no longer contains;
- the **re-stamped registry** and the **rules table** for the docs.

Bodies never enter the repository. The functions that write documents return
dicts; the caller decides where they go.
"""

from __future__ import annotations

import hashlib
import html
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from lineageauth.errors import MalformedEventError

TEXT_DOCUMENT_SUFFIXES = (".md", ".txt", ".json")
"""Bodies served as text: hashed as they are, never stripped of tags."""

HISTORY_NOTE = (
    "Diff against the previous snapshot, by source id and body hash, and since the fourth "
    "snapshot by textSha256 as well: sha256 of the body with tags, scripts and styles "
    "removed, entities decoded and whitespace collapsed, so a page rebuilt without a word "
    "changing shows change=hash-changed, text=unchanged. Bodies are not stored; a reader "
    "with the previous hash can confirm the change but not read the old page here."
)

_TAG_BLOCKS = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)
_TAGS = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")
# Em dash, en dash, non-breaking hyphen, minus sign, curly quotes, <=, ->, middle dot;
# by code point, so the file itself never carries a character a reader could mistake.
_QUOTATION_FOLD = str.maketrans(
    {
        0x2014: "-",
        0x2013: "-",
        0x2011: "-",
        0x2212: "-",
        0x2019: "'",
        0x2018: "'",
        0x201C: '"',
        0x201D: '"',
        0x2264: "<=",
        0x2192: "->",
        0x00B7: ".",
    }
)


def is_text_document(url: str) -> bool:
    """Whether a URL names a body that is served as plain text rather than HTML."""
    path = url.split("?", 1)[0].split("#", 1)[0]
    return path.endswith(TEXT_DOCUMENT_SUFFIXES)


def plain_text(body: bytes, *, html_like: bool) -> str:
    """The reading text of a body: HTML stripped to its words, text left alone."""
    raw = body.decode("utf-8", errors="replace")
    if not html_like:
        return raw
    raw = _TAG_BLOCKS.sub(" ", raw)
    return html.unescape(_TAGS.sub(" ", raw))


def normalised_text(body: bytes, *, html_like: bool) -> str:
    """`plain_text` with whitespace collapsed: the string `textSha256` hashes."""
    return _WHITESPACE.sub(" ", plain_text(body, html_like=html_like)).strip()


def body_sha256(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def text_sha256(body: bytes, *, html_like: bool) -> str:
    return (
        "sha256:" + hashlib.sha256(normalised_text(body, html_like=html_like).encode()).hexdigest()
    )


def quotation_key(text: str) -> str:
    """Fold the punctuation a page may re-encode and drop all whitespace.

    Em and en dashes, curly quotes, `≤`, `→` and the middle dot are folded to
    ASCII; whitespace is removed entirely, so a quotation that wraps differently
    or gains a non-breaking space still matches. Letters and digits are never
    touched: a changed figure is a changed quotation.
    """
    return _WHITESPACE.sub("", text.translate(_QUOTATION_FOLD))


def quotation_occurs(statement: str, text: str) -> bool:
    """Whether `statement` occurs in `text` under `quotation_key` folding."""
    return quotation_key(statement) in quotation_key(text)


@dataclass(frozen=True, slots=True)
class FetchedBody:
    """One official source as fetched: the bytes, and when."""

    source_id: str
    url: str
    http_status: int
    body: bytes
    fetched_at: str

    @property
    def html_like(self) -> bool:
        return not is_text_document(self.url)

    @property
    def sha256(self) -> str:
        return body_sha256(self.body)

    @property
    def text_sha256(self) -> str:
        return text_sha256(self.body, html_like=self.html_like)

    @property
    def text(self) -> str:
        return plain_text(self.body, html_like=self.html_like)


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """What moved for one source between two snapshots."""

    source_id: str
    change: str
    old_hash: str | None
    new_hash: str | None
    text: str
    old_text_hash: str | None
    new_text_hash: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.source_id,
            "change": self.change,
            "from": self.old_hash,
            "to": self.new_hash,
            "text": self.text,
            "textFrom": self.old_text_hash,
            "textTo": self.new_text_hash,
        }


def history_entry(
    source_id: str,
    previous: Mapping[str, Any] | None,
    *,
    new_hash: str | None,
    new_text_hash: str | None,
) -> HistoryEntry:
    """The history line for one source. `previous` is its entry in the old document."""
    old_hash = previous.get("sha256") if previous else None
    old_text = previous.get("textSha256") if previous else None
    if previous is None:
        change = "added"
    elif old_hash != new_hash:
        change = "hash-changed"
    else:
        change = "unchanged"
    if new_text_hash is None or not isinstance(old_text, str):
        text = "not-compared"
    elif old_text == new_text_hash:
        text = "unchanged"
    else:
        text = "changed"
    return HistoryEntry(
        source_id=source_id,
        change=change,
        old_hash=old_hash if isinstance(old_hash, str) else None,
        new_hash=new_hash,
        text=text,
        old_text_hash=old_text if isinstance(old_text, str) else None,
        new_text_hash=new_text_hash,
    )


def _entries_by_id(document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    raw = document.get("sources")
    if not isinstance(raw, list):
        raise MalformedEventError("official-sources.json needs a sources array")
    by_id: dict[str, Mapping[str, Any]] = {}
    for entry in raw:
        if isinstance(entry, Mapping) and isinstance(entry.get("id"), str):
            by_id[entry["id"]] = entry
    return by_id


def build_sources_document(
    previous: Mapping[str, Any],
    fetched: Sequence[FetchedBody],
    *,
    fetched_at: str,
    version_hints: Mapping[str, str] | None = None,
    notes: Mapping[str, str] | None = None,
    listing_status: int | None = None,
) -> dict[str, Any]:
    """The next `official-sources.json`, from the previous one and fresh bodies.

    Every source keeps its `status`, `versionHint` and `note` from the previous
    document unless `version_hints` / `notes` override it by id: those fields
    are a person's reading of the page and this function does not read pages.
    A previous source without a body (the organisation listing, which records no
    hash) is carried forward with `listing_status` as its HTTP status. A body
    for an id the previous document does not know is added with an empty note.
    """
    old_by_id = _entries_by_id(previous)
    hints = dict(version_hints or {})
    new_notes = dict(notes or {})
    fetched_by_id = {item.source_id: item for item in fetched}
    unknown = sorted(set(hints) - set(old_by_id) - set(fetched_by_id))
    unknown += sorted(set(new_notes) - set(old_by_id) - set(fetched_by_id))
    if unknown:
        raise MalformedEventError(f"overrides name sources that do not exist: {unknown}")

    sources: list[dict[str, Any]] = []
    history: list[dict[str, Any]] = []
    ordered_ids = list(old_by_id) + [i for i in fetched_by_id if i not in old_by_id]
    for source_id in ordered_ids:
        before = old_by_id.get(source_id)
        item = fetched_by_id.get(source_id)
        if item is None:
            if before is None:  # pragma: no cover - ordered_ids guarantees one of the two
                continue
            entry = dict(before)
            entry["fetchedAt"] = fetched_at
            if listing_status is not None:
                entry["httpStatus"] = listing_status
            new_hash, new_text = None, None
        else:
            entry = {
                "id": source_id,
                "url": item.url,
                "httpStatus": item.http_status,
                "bytes": len(item.body),
                "sha256": item.sha256,
                "textSha256": item.text_sha256,
                "fetchedAt": item.fetched_at,
                "versionHint": before.get("versionHint") if before else None,
                "status": before.get("status", "official-reference")
                if before
                else "official-reference",
                "note": before.get("note", "") if before else "",
            }
            new_hash, new_text = item.sha256, item.text_sha256
        if source_id in hints:
            entry["versionHint"] = hints[source_id]
        if source_id in new_notes:
            entry["note"] = new_notes[source_id]
        sources.append(entry)
        history.append(
            history_entry(source_id, before, new_hash=new_hash, new_text_hash=new_text).to_dict()
        )

    old_meta = previous.get("_meta")
    meta: dict[str, Any] = dict(old_meta) if isinstance(old_meta, Mapping) else {}
    meta["fetchedAt"] = fetched_at
    meta["previousFetchedAt"] = old_meta.get("fetchedAt") if isinstance(old_meta, Mapping) else None
    meta["history"] = history
    meta["historyNote"] = HISTORY_NOTE
    return {"_meta": meta, "sources": sources, "notObserved": list(previous.get("notObserved", []))}


@dataclass(frozen=True, slots=True)
class QuotationCheck:
    """Whether one rule's statement still occurs in its source."""

    rule_id: str
    source_id: str
    kind: str
    """`quotation`, `derived`, `unknown`, or `no-body` when the source was not fetched."""
    found: bool | None
    """True/False for a quotation with a body; None when nothing was checked."""

    @property
    def failed(self) -> bool:
        return self.found is False


def verify_registry(
    registry: Mapping[str, Any], bodies: Mapping[str, FetchedBody]
) -> tuple[QuotationCheck, ...]:
    """Check every quotation in the registry against the fetched bodies."""
    rules = registry.get("rules")
    if not isinstance(rules, list):
        raise MalformedEventError("rule-registry.json needs a rules array")
    checks: list[QuotationCheck] = []
    for rule in rules:
        if not isinstance(rule, Mapping):
            continue
        rule_id = str(rule.get("id", ""))
        source = rule.get("source")
        source_id = str(source.get("sourceId", "")) if isinstance(source, Mapping) else ""
        if rule.get("status") == "unknown":
            checks.append(QuotationCheck(rule_id, source_id, "unknown", None))
        elif rule.get("derivation") == "derived" or rule.get("statementIsQuotation") is not True:
            checks.append(QuotationCheck(rule_id, source_id, "derived", None))
        elif source_id not in bodies:
            checks.append(QuotationCheck(rule_id, source_id, "no-body", None))
        else:
            statement = str(rule.get("statement", ""))
            found = quotation_occurs(statement, bodies[source_id].text)
            checks.append(QuotationCheck(rule_id, source_id, "quotation", found))
    return tuple(checks)


def restamp_registry(
    registry: Mapping[str, Any],
    sources_document: Mapping[str, Any],
    checks: Iterable[QuotationCheck],
    *,
    generated_at: str,
    revision_note: str,
    source_versions: Mapping[str, tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """The registry with every verified rule pointing at the new snapshot.

    A rule whose quotation was not found keeps its old `fetchedAt` and `hash`
    untouched, so `rules.py` reports it as `RULE UPDATED` until a person
    re-quotes it. `source_versions` maps a source id to the `(sourceVersion,
    sourceDate)` pair its rules should now carry, for a source whose served
    version moved.
    """
    by_id = _entries_by_id(sources_document)
    verdicts = {check.rule_id: check for check in checks}
    versions = dict(source_versions or {})
    rules_out: list[Any] = []
    for rule in registry.get("rules", []):
        if not isinstance(rule, Mapping):
            rules_out.append(rule)
            continue
        entry = dict(rule)
        check = verdicts.get(str(rule.get("id", "")))
        source = rule.get("source")
        if check is not None and not check.failed and isinstance(source, Mapping):
            new_source = dict(source)
            current = by_id.get(str(source.get("sourceId", "")))
            if current is not None:
                new_source["fetchedAt"] = current.get("fetchedAt")
                new_source["hash"] = current.get("sha256")
                if check.source_id in versions:
                    new_source["sourceVersion"], new_source["sourceDate"] = versions[
                        check.source_id
                    ]
            entry["source"] = new_source
        rules_out.append(entry)

    old_meta = registry.get("_meta")
    meta: dict[str, Any] = dict(old_meta) if isinstance(old_meta, Mapping) else {}
    previous_generated = meta.get("generatedAt")
    meta["generatedAt"] = generated_at
    meta["previousGeneratedAt"] = previous_generated
    history = meta.get("snapshotHistory")
    history_list = (
        [item for item in history if isinstance(item, str)] if isinstance(history, list) else []
    )
    if generated_at not in history_list:
        history_list.append(generated_at)
    meta["snapshotHistory"] = history_list
    meta["revisionNote"] = revision_note
    return {"_meta": meta, "rules": rules_out}


TABLE_HEADER = "| id | status | phase | source | what it records |\n|---|---|---|---|---|"


def render_rules_table(registry: Mapping[str, Any]) -> str:
    """The rules table `docs/FLOP_RULE_REGISTRY.md` carries, one row per rule."""
    rows = [TABLE_HEADER]
    for rule in registry.get("rules", []):
        if not isinstance(rule, Mapping):
            continue
        status = str(rule.get("status", ""))
        if rule.get("derivation") == "derived":
            status += ", **derived**"
        what = (
            "`UNKNOWN_FROM_OFFICIAL_SPEC`"
            if rule.get("status") == "unknown"
            else str(rule.get("statement", ""))
        )
        if len(what) > 110:
            what = what[:107].rstrip() + "..."
        what = what.replace("|", "\\|")
        source = rule.get("source")
        source_id = source.get("sourceId", "") if isinstance(source, Mapping) else ""
        rows.append(
            f"| `{rule.get('id', '')}` | {status} | {rule.get('effectiveNetworkPhase', '')} "
            f"| `{source_id}` | {what} |"
        )
    return "\n".join(rows)


TABLE_BEGIN = "<!-- flop-rules-table:begin -->"
TABLE_END = "<!-- flop-rules-table:end -->"


def replace_rules_table(document: str, table: str) -> str:
    """`document` with the text between the table markers replaced by `table`."""
    start = document.find(TABLE_BEGIN)
    end = document.find(TABLE_END)
    if start < 0 or end < 0 or end < start:
        raise MalformedEventError("the docs page carries no flop-rules-table markers")
    head = document[: start + len(TABLE_BEGIN)]
    tail = document[end:]
    return f"{head}\n{table}\n{tail}"
