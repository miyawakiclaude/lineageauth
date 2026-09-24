"""The pure half of taking an official-source snapshot (D-119).

Nothing here touches the network. The bodies are made up; the one real
document used is the committed registry, whose rendered table must equal the
table the docs page carries.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lineageauth.errors import MalformedEventError
from lineageauth.flop.rules import RULE_REGISTRY_FILE
from lineageauth.flop.snapshot import (
    TABLE_BEGIN,
    TABLE_END,
    FetchedBody,
    body_sha256,
    build_sources_document,
    history_entry,
    is_text_document,
    normalised_text,
    quotation_key,
    quotation_occurs,
    render_rules_table,
    replace_rules_table,
    restamp_registry,
    text_sha256,
    verify_registry,
)
from lineageauth.flop.sources import OFFICIAL_SOURCES_FILE

REPO = Path(__file__).resolve().parents[1]
DOCS_PAGE = REPO / "docs" / "FLOP_RULE_REGISTRY.md"

PAGE_V1 = b"""<html><head><style>body{color:red}</style><script>var build="a1";</script></head>
<body><h1>Teaser</h1><p>Flop Testnet is planned for Q4&nbsp;2026 and runs for
roughly ninety days.</p></body></html>"""
PAGE_V2 = PAGE_V1.replace(b'"a1"', b'"b2"').replace(b"\n<body>", b"\n\n  <body>")
PAGE_V3 = PAGE_V1.replace(b"ninety", b"sixty")


class TestNormalisation:
    def test_html_is_reduced_to_its_words(self) -> None:
        text = normalised_text(PAGE_V1, html_like=True)
        assert (
            text == "Teaser Flop Testnet is planned for Q4 2026 and runs for roughly ninety days."
        )

    def test_a_rebuilt_page_moves_the_byte_hash_and_not_the_text_hash(self) -> None:
        assert body_sha256(PAGE_V1) != body_sha256(PAGE_V2)
        assert text_sha256(PAGE_V1, html_like=True) == text_sha256(PAGE_V2, html_like=True)

    def test_a_changed_word_moves_the_text_hash(self) -> None:
        assert text_sha256(PAGE_V1, html_like=True) != text_sha256(PAGE_V3, html_like=True)

    def test_text_documents_are_not_stripped(self) -> None:
        body = b"CAPACITY: at most <300000> rooms"
        assert normalised_text(body, html_like=False) == "CAPACITY: at most <300000> rooms"
        assert normalised_text(body, html_like=True) == "CAPACITY: at most rooms"

    @pytest.mark.parametrize(
        ("url", "text"),
        [
            ("https://technocore.chat/llms.txt", True),
            ("https://flop.finance/design.md?v=2", True),
            ("https://flop.finance/teaser/", False),
            ("https://flop.finance/intro/yellowpaper/", False),
        ],
    )
    def test_text_documents_are_told_by_suffix(self, url: str, text: bool) -> None:
        assert is_text_document(url) is text

    def test_hashes_carry_the_prefix_the_scanner_expects(self) -> None:
        assert body_sha256(b"x").startswith("sha256:")
        assert text_sha256(b"x", html_like=True).startswith("sha256:")


class TestQuotations:
    def test_punctuation_and_whitespace_are_folded_but_figures_are_not(self) -> None:
        em_dash, nbsp, le = chr(0x2014), chr(0xA0), chr(0x2264)
        assert quotation_key(f"a {em_dash} b{nbsp}c") == quotation_key("a - b c")
        assert quotation_key(f"{le} 864,000") == quotation_key("<= 864,000")
        assert quotation_key("300000 rooms") != quotation_key("250000 rooms")

    def test_a_quotation_is_found_across_a_rewrap(self) -> None:
        body = FetchedBody(
            "t", "https://flop.finance/teaser/", 200, PAGE_V1, "2026-09-22T00:00:00Z"
        )
        assert quotation_occurs("planned for Q4 2026 and runs for roughly ninety days", body.text)
        assert not quotation_occurs("runs for roughly sixty days", body.text)

    def test_the_registry_is_checked_rule_by_rule(self) -> None:
        registry = {
            "rules": [
                {
                    "id": "q-ok",
                    "statement": "ninety days",
                    "statementIsQuotation": True,
                    "status": "official-draft",
                    "source": {"sourceId": "t"},
                },
                {
                    "id": "q-gone",
                    "statement": "sixty days",
                    "statementIsQuotation": True,
                    "status": "official-draft",
                    "source": {"sourceId": "t"},
                },
                {
                    "id": "q-nobody",
                    "statement": "anything",
                    "statementIsQuotation": True,
                    "status": "official-draft",
                    "source": {"sourceId": "missing"},
                },
                {
                    "id": "d",
                    "statement": "paraphrase",
                    "statementIsQuotation": False,
                    "derivation": "derived",
                    "status": "official-draft",
                    "source": {"sourceId": "t"},
                },
                {
                    "id": "u",
                    "statement": "UNKNOWN_FROM_OFFICIAL_SPEC",
                    "status": "unknown",
                    "source": {"sourceId": "t"},
                },
            ]
        }
        body = FetchedBody(
            "t", "https://flop.finance/teaser/", 200, PAGE_V1, "2026-09-22T00:00:00Z"
        )
        checks = {c.rule_id: c for c in verify_registry(registry, {"t": body})}
        assert (checks["q-ok"].kind, checks["q-ok"].found) == ("quotation", True)
        assert (checks["q-gone"].kind, checks["q-gone"].failed) == ("quotation", True)
        assert (checks["q-nobody"].kind, checks["q-nobody"].found) == ("no-body", None)
        assert (checks["d"].kind, checks["d"].failed) == ("derived", False)
        assert (checks["u"].kind, checks["u"].failed) == ("unknown", False)


def _previous() -> dict[str, object]:
    return {
        "_meta": {"purpose": "p", "fetchedAt": "2026-09-14T00:00:00Z", "bodiesAreNotStored": True},
        "sources": [
            {
                "id": "t",
                "url": "https://flop.finance/teaser/",
                "httpStatus": 200,
                "bytes": len(PAGE_V1),
                "sha256": body_sha256(PAGE_V1),
                "textSha256": text_sha256(PAGE_V1, html_like=True),
                "fetchedAt": "2026-09-14T00:00:00Z",
                "versionHint": "v0.1",
                "status": "official-draft",
                "note": "The teaser.",
            },
            {
                "id": "old-no-text",
                "url": "https://flop.finance/brand/",
                "httpStatus": 200,
                "bytes": 3,
                "sha256": body_sha256(b"abc"),
                "fetchedAt": "2026-09-14T00:00:00Z",
                "versionHint": None,
                "status": "official-reference",
                "note": "",
            },
            {
                "id": "org",
                "url": "https://github.com/flop-labs",
                "httpStatus": 200,
                "bytes": None,
                "sha256": None,
                "fetchedAt": "2026-09-14T00:00:00Z",
                "versionHint": "repos",
                "status": "official-reference",
                "note": "listing",
            },
        ],
        "notObserved": [{"id": "testnet-endpoint"}],
    }


class TestHistory:
    def test_the_four_verdicts(self) -> None:
        prev = {"sha256": "sha256:a", "textSha256": "sha256:t"}
        assert (
            history_entry("x", None, new_hash="sha256:b", new_text_hash="sha256:t").change
            == "added"
        )
        same = history_entry("x", prev, new_hash="sha256:a", new_text_hash="sha256:t")
        assert (same.change, same.text) == ("unchanged", "unchanged")
        rebuilt = history_entry("x", prev, new_hash="sha256:b", new_text_hash="sha256:t")
        assert (rebuilt.change, rebuilt.text) == ("hash-changed", "unchanged")
        rewritten = history_entry("x", prev, new_hash="sha256:b", new_text_hash="sha256:u")
        assert (rewritten.change, rewritten.text) == ("hash-changed", "changed")
        untracked = history_entry(
            "x", {"sha256": "sha256:a"}, new_hash="sha256:a", new_text_hash="sha256:t"
        )
        assert untracked.text == "not-compared"

    def test_the_next_document_carries_notes_forward_and_diffs_the_bodies(self) -> None:
        fetched = [
            FetchedBody("t", "https://flop.finance/teaser/", 200, PAGE_V2, "2026-09-22T00:00:01Z"),
            FetchedBody(
                "old-no-text", "https://flop.finance/brand/", 200, b"abd", "2026-09-22T00:00:02Z"
            ),
            FetchedBody(
                "new", "https://flop.finance/new/", 200, b"<p>n</p>", "2026-09-22T00:00:03Z"
            ),
        ]
        doc = build_sources_document(
            _previous(),
            fetched,
            fetched_at="2026-09-22T00:00:00Z",
            listing_status=200,
            version_hints={"t": "v0.2"},
        )
        by_id = {e["id"]: e for e in doc["sources"]}
        assert by_id["t"]["versionHint"] == "v0.2"
        assert by_id["t"]["note"] == "The teaser."
        assert by_id["t"]["status"] == "official-draft"
        assert by_id["t"]["textSha256"] == text_sha256(PAGE_V2, html_like=True)
        assert by_id["org"]["fetchedAt"] == "2026-09-22T00:00:00Z"
        assert by_id["org"]["sha256"] is None
        assert by_id["new"]["note"] == ""
        history = {h["id"]: h for h in doc["_meta"]["history"]}
        assert (history["t"]["change"], history["t"]["text"]) == ("hash-changed", "unchanged")
        assert (history["old-no-text"]["change"], history["old-no-text"]["text"]) == (
            "hash-changed",
            "not-compared",
        )
        assert history["new"]["change"] == "added"
        assert history["org"] == {**history["org"], "change": "unchanged", "text": "not-compared"}
        assert doc["_meta"]["previousFetchedAt"] == "2026-09-14T00:00:00Z"
        assert doc["_meta"]["bodiesAreNotStored"] is True
        assert doc["notObserved"] == [{"id": "testnet-endpoint"}]
        assert not any("body" in e for e in doc["sources"])

    def test_an_override_for_an_unknown_source_is_refused(self) -> None:
        with pytest.raises(MalformedEventError):
            build_sources_document(
                _previous(), [], fetched_at="2026-09-22T00:00:00Z", notes={"nope": "x"}
            )


class TestRestamp:
    def test_verified_rules_move_and_a_missing_quotation_stays_where_it_was(self) -> None:
        registry = {
            "_meta": {
                "generatedAt": "2026-09-14T00:00:00Z",
                "snapshotHistory": ["2026-09-14T00:00:00Z"],
            },
            "rules": [
                {
                    "id": "q-ok",
                    "statement": "ninety days",
                    "statementIsQuotation": True,
                    "status": "official-draft",
                    "source": {
                        "sourceId": "t",
                        "sourceVersion": "v0.1",
                        "sourceDate": "2026-08-26",
                        "fetchedAt": "2026-09-14T00:00:00Z",
                        "hash": "sha256:old",
                    },
                },
                {
                    "id": "q-gone",
                    "statement": "sixty days",
                    "statementIsQuotation": True,
                    "status": "official-draft",
                    "source": {
                        "sourceId": "t",
                        "sourceVersion": "v0.1",
                        "sourceDate": "2026-08-26",
                        "fetchedAt": "2026-09-14T00:00:00Z",
                        "hash": "sha256:old",
                    },
                },
                {
                    "id": "u",
                    "statement": "UNKNOWN_FROM_OFFICIAL_SPEC",
                    "status": "unknown",
                    "source": {
                        "sourceId": "t",
                        "sourceVersion": "v0.1",
                        "sourceDate": "2026-08-26",
                        "fetchedAt": "2026-09-14T00:00:00Z",
                        "hash": "sha256:old",
                    },
                },
            ],
        }
        body = FetchedBody(
            "t", "https://flop.finance/teaser/", 200, PAGE_V1, "2026-09-22T00:00:01Z"
        )
        doc = build_sources_document(_previous(), [body], fetched_at="2026-09-22T00:00:00Z")
        checks = verify_registry(registry, {"t": body})
        out = restamp_registry(
            registry,
            doc,
            checks,
            generated_at="2026-09-22T00:00:00Z",
            revision_note="fourth",
            source_versions={"t": ("v0.2", "2026-09-22")},
        )
        rules = {r["id"]: r for r in out["rules"]}
        assert rules["q-ok"]["source"]["hash"] == body_sha256(PAGE_V1)
        assert rules["q-ok"]["source"]["fetchedAt"] == "2026-09-22T00:00:01Z"
        assert (
            rules["q-ok"]["source"]["sourceVersion"],
            rules["q-ok"]["source"]["sourceDate"],
        ) == (
            "v0.2",
            "2026-09-22",
        )
        assert rules["q-gone"]["source"]["hash"] == "sha256:old"
        assert rules["q-gone"]["source"]["fetchedAt"] == "2026-09-14T00:00:00Z"
        assert rules["u"]["source"]["hash"] == body_sha256(PAGE_V1)
        assert out["_meta"]["snapshotHistory"] == ["2026-09-14T00:00:00Z", "2026-09-22T00:00:00Z"]
        assert out["_meta"]["previousGeneratedAt"] == "2026-09-14T00:00:00Z"
        assert out["_meta"]["revisionNote"] == "fourth"


class TestTheDocsTable:
    def test_the_committed_registry_renders_the_table_the_docs_carry(self) -> None:
        registry = json.loads(RULE_REGISTRY_FILE.read_text(encoding="utf-8"))
        page = DOCS_PAGE.read_text(encoding="utf-8")
        start = page.index(TABLE_BEGIN) + len(TABLE_BEGIN)
        end = page.index(TABLE_END)
        assert page[start:end].strip() == render_rules_table(registry)

    def test_the_table_is_replaced_between_the_markers_only(self) -> None:
        page = f"before\n{TABLE_BEGIN}\nold\n{TABLE_END}\nafter\n"
        assert (
            replace_rules_table(page, "new") == f"before\n{TABLE_BEGIN}\nnew\n{TABLE_END}\nafter\n"
        )
        with pytest.raises(MalformedEventError):
            replace_rules_table("no markers", "new")

    def test_the_committed_snapshot_and_registry_agree_on_every_hash(self) -> None:
        """What `snapshot` writes must be what the loaders already expect."""
        sources = json.loads(OFFICIAL_SOURCES_FILE.read_text(encoding="utf-8"))
        by_id = {e["id"]: e for e in sources["sources"]}
        registry = json.loads(RULE_REGISTRY_FILE.read_text(encoding="utf-8"))
        for rule in registry["rules"]:
            source = by_id[rule["source"]["sourceId"]]
            assert rule["source"]["hash"] == source["sha256"], rule["id"]
