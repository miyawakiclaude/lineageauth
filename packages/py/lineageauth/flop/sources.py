"""Which sources may be called official, and what they said when we looked.

There is exactly one input to `classify_source`: a URL. Not a nickname, not a
room name, not a topic, not a note namespace, not the word "official" in a
message, and not a valid signature. `https://technocore.chat/auth.md` says in as
many words that the service has no authentication, so a signature there proves
control of a key and nothing about who anybody is -- and a key can call itself
whatever it likes.

The origin allowlist is deliberately small and the default is `UNKNOWN`. That is
the same shape as `adapters/technocore/routes.py`: a source this table does not
recognise is not "probably fine", it is "do not treat this as authority".

`SUSPICIOUS` is reserved for a URL that looks like it is trying to be an
official one -- an official host as a substring of a longer host, a
character-substituted lookalike, a userinfo component, a plain-HTTP downgrade of
an official origin, a punycode host. Those are not unknown sources; they are
unknown sources dressed up, and the difference is worth a louder badge.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import OfficialSourceSnapshot, SourceClass

CONFORMANCE_ROOT = Path(__file__).resolve().parents[4] / "conformance" / "flop"

OFFICIAL_SOURCES_FILE = CONFORMANCE_ROOT / "official-sources.json"
UI_TOKENS_FILE = CONFORMANCE_ROOT / "ui-tokens.json"

RULE_UPDATED_LABEL = "RULE UPDATED"

# Hosts whose content is published by the projects themselves.
FLOP_HOST = "flop.finance"
TECHNOCORE_HOST = "technocore.chat"
GITHUB_HOST = "github.com"
GITHUB_API_HOST = "api.github.com"

OFFICIAL_HOSTS: frozenset[str] = frozenset({FLOP_HOST, TECHNOCORE_HOST})

# Technocore paths that are the service describing itself. Everything else on
# that host is content somebody else wrote and the service merely carries.
TECHNOCORE_SERVICE_PATHS: frozenset[str] = frozenset(
    {
        "/",
        "/llms.txt",
        "/auth.md",
        "/patterns.md",
        "/skill.md",
        "/interop.md",
        "/openapi.json",
        "/healthz",
    }
)

GITHUB_OFFICIAL_PREFIX = "/flop-labs"
GITHUB_API_OFFICIAL_PREFIX = "/repos/flop-labs"

# Substitutions a lookalike domain reaches for. Used only to notice that two
# hosts collapse to the same string, never to rewrite a URL.
_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "-": "", ".": ""})


class SnapshotChangeKind(StrEnum):
    """How two snapshots of the same source list differ."""

    ADDED = "added"
    REMOVED = "removed"
    HASH_CHANGED = "hash-changed"
    STATUS_CHANGED = "status-changed"


@dataclass(frozen=True, slots=True)
class SourceDecision:
    """A classification and the reason for it.

    The reason travels with the verdict because the UI has to show it. A badge
    that cannot explain itself trains people to ignore badges.
    """

    url: str
    source_class: SourceClass
    rule_id: str
    reason: str
    host: str | None = None

    @property
    def may_carry_official_badge(self) -> bool:
        return self.source_class.may_carry_official_badge

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "sourceClass": str(self.source_class),
            "ruleId": self.rule_id,
            "reason": self.reason,
            "host": self.host,
            "mayCarryOfficialBadge": self.may_carry_official_badge,
        }


@dataclass(frozen=True, slots=True)
class SnapshotChange:
    """One difference between an old snapshot and a new one."""

    source_id: str
    kind: SnapshotChangeKind
    old: str | None
    new: str | None

    @property
    def label(self) -> str:
        return RULE_UPDATED_LABEL

    def to_dict(self) -> dict[str, Any]:
        return {
            "sourceId": self.source_id,
            "kind": str(self.kind),
            "old": self.old,
            "new": self.new,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class SourceSnapshotSet:
    """The official sources as they were at one fetch, plus what was missing."""

    fetched_at: str
    snapshots: tuple[OfficialSourceSnapshot, ...]
    not_observed: tuple[Mapping[str, Any], ...] = ()

    def by_id(self, source_id: str) -> OfficialSourceSnapshot | None:
        for snapshot in self.snapshots:
            if snapshot.source_id == source_id:
                return snapshot
        return None

    def hash_for(self, source_id: str) -> str | None:
        snapshot = self.by_id(source_id)
        return None if snapshot is None else snapshot.sha256

    def to_dict(self) -> dict[str, Any]:
        return {
            "fetchedAt": self.fetched_at,
            "bodiesStored": False,
            "sources": [snapshot.to_dict() for snapshot in self.snapshots],
            "notObserved": [dict(entry) for entry in self.not_observed],
        }


def read_json(path: Path) -> dict[str, Any]:
    """Read one conformance file, or say which one is missing.

    A missing file here is a deployment problem, not a data problem, and the
    message says the path so it can be fixed without reading the source.
    """
    if not path.is_file():
        raise MalformedEventError(f"FLOP conformance data is missing: {path}")
    loaded: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise MalformedEventError(f"{path.name} must contain a JSON object")
    return loaded


def _normalised_host(host: str) -> str:
    return host.lower().translate(_CONFUSABLES)


def _concealed_path(path: str) -> tuple[str, str] | None:
    """Whether a path lands somewhere other than where it reads.

    A browser removes dot segments before it sends the request, so
    `https://github.com/flop-labs/../evil-org/payout` is a request for
    `github.com/evil-org/payout` while still reading as a FLOP Labs URL, and a
    prefix test on the raw path calls it official. Percent-encoding hides the
    same trick from a plain string comparison (`%2e%2e%2f`) and an encoded slash
    (`%2f`) hides where the segments even are.

    This does not normalise and re-test. A URL that needs normalising before it
    can be classified is a URL written to be misread, and the honest verdict for
    one of those is `SUSPICIOUS` rather than whatever the tidied version says.
    """
    lowered = path.lower()
    if "%2f" in lowered or "%5c" in lowered:
        return (
            "encoded-separator-path",
            "the path encodes a separator, which hides where its segments begin and end",
        )
    for segment in lowered.split("/"):
        if segment.replace("%2e", ".") in (".", ".."):
            return (
                "dot-segment-path",
                "the path contains a relative segment, so it does not land where it reads",
            )
    return None


def _host_relation(host: str) -> tuple[str, str] | None:
    """How this host relates to an official one: subdomain, imitation, or neither.

    The imitation test strips dots, hyphens and the digit substitutions a
    lookalike reaches for, then asks whether the official name survives inside
    what is left. `flop.finance.claim.example`, `fl0p.finance` and
    `flop-finance.com` all collapse onto `flopfinance`; each is a different
    trick and none of them is the official host.

    A genuine subdomain is separated out and reported as a subdomain rather than
    an imitation. It is still not official -- none was observed, so none is in
    the snapshot -- but calling `docs.flop.finance` an impersonation would be
    wrong about what it is.
    """
    lowered = host.lower()
    for official in sorted(OFFICIAL_HOSTS):
        if lowered == official:
            return None
        if lowered.endswith(f".{official}"):
            return ("subdomain", official)
        if _normalised_host(official) in _normalised_host(lowered):
            return ("lookalike", official)
    return None


def _decide(url: str) -> SourceDecision:
    parts = urlsplit(url)
    host = parts.hostname
    if host is None or not parts.scheme:
        return SourceDecision(
            url=url,
            source_class=SourceClass.UNKNOWN,
            rule_id="not-a-url",
            reason="not an absolute URL with a host",
        )

    if parts.username is not None or parts.password is not None:
        return SourceDecision(
            url=url,
            source_class=SourceClass.SUSPICIOUS,
            rule_id="userinfo-present",
            reason="the URL carries a userinfo component, which hides the real host from a reader",
            host=host,
        )

    concealed = _concealed_path(parts.path)
    if concealed is not None:
        rule_id, reason = concealed
        return SourceDecision(
            url=url,
            source_class=SourceClass.SUSPICIOUS,
            rule_id=rule_id,
            reason=reason,
            host=host,
        )

    if host.lower().startswith("xn--") or ".xn--" in host.lower() or not host.isascii():
        return SourceDecision(
            url=url,
            source_class=SourceClass.SUSPICIOUS,
            rule_id="internationalised-host",
            reason="the host is punycode or non-ASCII and can render as a different name",
            host=host,
        )

    relation = _host_relation(host)
    if relation is not None:
        kind, official = relation
        if kind == "lookalike":
            return SourceDecision(
                url=url,
                source_class=SourceClass.SUSPICIOUS,
                rule_id="lookalike-host",
                reason=f"the host imitates {official} without being it",
                host=host,
            )
        return SourceDecision(
            url=url,
            source_class=SourceClass.UNKNOWN,
            rule_id="unsnapshotted-subdomain",
            reason=(
                f"a subdomain of {official} that does not appear in the recorded snapshot; "
                "official status comes from having been observed, not from the parent domain"
            ),
            host=host,
        )

    if parts.scheme != "https":
        # A downgrade on a host that publishes over https is louder than an
        # unknown one: it is either an interception or an imitation, and both
        # deserve more than "we do not recognise this".
        publishes_over_https = host.lower() in OFFICIAL_HOSTS or host.lower() in (
            GITHUB_HOST,
            GITHUB_API_HOST,
        )
        return SourceDecision(
            url=url,
            source_class=(SourceClass.SUSPICIOUS if publishes_over_https else SourceClass.UNKNOWN),
            rule_id="not-https",
            reason=(
                f"scheme {parts.scheme!r} is not https"
                + (" on a host that publishes over https" if publishes_over_https else "")
            ),
            host=host,
        )

    lowered = host.lower()
    if parts.port not in (None, 443) and lowered in OFFICIAL_HOSTS:
        return SourceDecision(
            url=url,
            source_class=SourceClass.SUSPICIOUS,
            rule_id="non-standard-port",
            reason=f"port {parts.port} is not the official service's",
            host=host,
        )

    path = parts.path or "/"

    if lowered == FLOP_HOST:
        return SourceDecision(
            url=url,
            source_class=SourceClass.OFFICIAL,
            rule_id="flop-finance-origin",
            reason="published by the FLOP project on its own origin",
            host=host,
        )

    if lowered == TECHNOCORE_HOST:
        if path in TECHNOCORE_SERVICE_PATHS or path.startswith("/.well-known/"):
            return SourceDecision(
                url=url,
                source_class=SourceClass.OFFICIAL,
                rule_id="technocore-service-document",
                reason="the Technocore service describing itself",
                host=host,
            )
        return SourceDecision(
            url=url,
            source_class=SourceClass.COMMUNITY,
            rule_id="technocore-carried-content",
            reason=(
                "an official service carrying content somebody else wrote; the transport "
                "is official, the message is not"
            ),
            host=host,
        )

    if lowered == GITHUB_HOST:
        if path == GITHUB_OFFICIAL_PREFIX or path.startswith(f"{GITHUB_OFFICIAL_PREFIX}/"):
            return SourceDecision(
                url=url,
                source_class=SourceClass.OFFICIAL,
                rule_id="flop-labs-repository",
                reason="a repository in the FLOP Labs organisation",
                host=host,
            )
        return SourceDecision(
            url=url,
            source_class=SourceClass.COMMUNITY,
            rule_id="public-code-host",
            reason="a public repository outside the FLOP Labs organisation",
            host=host,
        )

    if lowered == GITHUB_API_HOST:
        if path.startswith(f"{GITHUB_API_OFFICIAL_PREFIX}/") or path == GITHUB_API_OFFICIAL_PREFIX:
            return SourceDecision(
                url=url,
                source_class=SourceClass.OFFICIAL,
                rule_id="flop-labs-repository-api",
                reason="the API view of a FLOP Labs repository",
                host=host,
            )
        return SourceDecision(
            url=url,
            source_class=SourceClass.COMMUNITY,
            rule_id="public-code-host-api",
            reason="the API view of a repository outside the FLOP Labs organisation",
            host=host,
        )

    return SourceDecision(
        url=url,
        source_class=SourceClass.UNKNOWN,
        rule_id="not-allowlisted",
        reason="no allowlisted official origin matches this host",
        host=host,
    )


def classify_source(url: object) -> SourceDecision:
    """Classify a URL by origin. Nothing else is consulted.

    Deliberately total: a malformed string gets `UNKNOWN` with a reason rather
    than an exception, because this is called on URLs pulled out of untrusted
    text and a scanner that crashes on bad input stops scanning.
    """
    if not isinstance(url, str) or not url:
        return SourceDecision(
            url="",
            source_class=SourceClass.UNKNOWN,
            rule_id="not-a-url",
            reason="a URL to classify must be a non-empty string",
        )
    if len(url) > 4096:
        return SourceDecision(
            url=url[:256],
            source_class=SourceClass.SUSPICIOUS,
            rule_id="oversized-url",
            reason="the URL is longer than any legitimate one this tool reads",
        )
    try:
        return _decide(url)
    except ValueError:
        # `urlsplit` raises on a malformed IPv6 literal, among others.
        return SourceDecision(
            url=url,
            source_class=SourceClass.UNKNOWN,
            rule_id="unparseable-url",
            reason="the URL could not be parsed",
        )


def _snapshot_from(entry: Mapping[str, Any]) -> OfficialSourceSnapshot:
    source_id = entry.get("id")
    url = entry.get("url")
    if not isinstance(source_id, str) or not isinstance(url, str):
        raise MalformedEventError("each official source needs a string id and url")
    status = entry.get("status")
    fetched_at = entry.get("fetchedAt")
    if not isinstance(status, str) or not isinstance(fetched_at, str):
        raise MalformedEventError(f"source {source_id} needs a string status and fetchedAt")
    http_status = entry.get("httpStatus")
    byte_length = entry.get("bytes")
    sha256 = entry.get("sha256")
    version_hint = entry.get("versionHint")
    note = entry.get("note")
    return OfficialSourceSnapshot(
        source_id=source_id,
        url=url,
        http_status=http_status if isinstance(http_status, int) else None,
        byte_length=byte_length if isinstance(byte_length, int) else None,
        sha256=sha256 if isinstance(sha256, str) else None,
        fetched_at=fetched_at,
        version_hint=version_hint if isinstance(version_hint, str) else None,
        status=status,
        note=note if isinstance(note, str) else "",
    )


def load_snapshot(path: Path | None = None) -> SourceSnapshotSet:
    """Load the recorded official-source snapshot.

    Reads a file. Fetches nothing: the snapshot is the record of a fetch that
    already happened, and a loader that quietly went to the network would make
    every test that uses it a network test.
    """
    document = read_json(path or OFFICIAL_SOURCES_FILE)
    meta = document.get("_meta")
    fetched_at = ""
    if isinstance(meta, dict):
        candidate = meta.get("fetchedAt")
        if isinstance(candidate, str):
            fetched_at = candidate
    raw_sources = document.get("sources")
    if not isinstance(raw_sources, list):
        raise MalformedEventError("official-sources.json needs a sources array")
    snapshots = tuple(_snapshot_from(entry) for entry in raw_sources if isinstance(entry, Mapping))
    raw_absent = document.get("notObserved")
    not_observed: tuple[Mapping[str, Any], ...] = ()
    if isinstance(raw_absent, list):
        not_observed = tuple(entry for entry in raw_absent if isinstance(entry, Mapping))
    return SourceSnapshotSet(fetched_at=fetched_at, snapshots=snapshots, not_observed=not_observed)


def compare_snapshots(
    old: Iterable[OfficialSourceSnapshot], new: Iterable[OfficialSourceSnapshot]
) -> tuple[SnapshotChange, ...]:
    """Diff two snapshots of the source list.

    Every difference is reported, including a source disappearing. `docs/29`
    D-063 in another context: the interesting case is usually the one that
    removes something, and a diff that only reports additions will not show it.
    """
    old_by_id = {snapshot.source_id: snapshot for snapshot in old}
    new_by_id = {snapshot.source_id: snapshot for snapshot in new}
    changes: list[SnapshotChange] = []
    for source_id in sorted(set(old_by_id) | set(new_by_id)):
        before = old_by_id.get(source_id)
        after = new_by_id.get(source_id)
        if before is None and after is not None:
            changes.append(SnapshotChange(source_id, SnapshotChangeKind.ADDED, None, after.sha256))
            continue
        if after is None and before is not None:
            changes.append(
                SnapshotChange(source_id, SnapshotChangeKind.REMOVED, before.sha256, None)
            )
            continue
        if before is None or after is None:  # pragma: no cover - defensive
            continue
        if before.sha256 != after.sha256:
            changes.append(
                SnapshotChange(
                    source_id, SnapshotChangeKind.HASH_CHANGED, before.sha256, after.sha256
                )
            )
        if before.status != after.status:
            changes.append(
                SnapshotChange(
                    source_id, SnapshotChangeKind.STATUS_CHANGED, before.status, after.status
                )
            )
    return tuple(changes)


def load_ui_tokens(path: Path | None = None) -> dict[str, Any]:
    """Load the design tokens, provenance and baseline diff.

    The CSS is generated from this file rather than hand-typed, so a colour that
    is not in here cannot appear on the page, and every colour that is in here
    can say where it came from.
    """
    return read_json(path or UI_TOKENS_FILE)


def contrast_ratio(foreground: str, background: str) -> float:
    """WCAG 2.x relative-contrast between two `#rrggbb` colours.

    Implemented rather than trusted: `ui-tokens.json` records the ratios
    design.md publishes, and a test recomputes each one. A published number and
    a measured number that disagree is a thing worth finding before a user with
    low vision does.
    """
    return _relative_contrast(_luminance(foreground), _luminance(background))


def _channel(value: int) -> float:
    scaled = value / 255
    return scaled / 12.92 if scaled <= 0.04045 else ((scaled + 0.055) / 1.055) ** 2.4


def _luminance(colour: str) -> float:
    text = colour.strip().lstrip("#")
    if len(text) != 6:
        raise MalformedEventError(f"expected a #rrggbb colour, got {colour!r}")
    try:
        red, green, blue = (int(text[index : index + 2], 16) for index in (0, 2, 4))
    except ValueError as exc:
        raise MalformedEventError(f"expected a #rrggbb colour, got {colour!r}") from exc
    return 0.2126 * _channel(red) + 0.7152 * _channel(green) + 0.0722 * _channel(blue)


def _relative_contrast(first: float, second: float) -> float:
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


def classify_all(urls: Sequence[str]) -> tuple[SourceDecision, ...]:
    """Classify several URLs at once, in the order given."""
    return tuple(classify_source(url) for url in urls)


__all__ = [
    "CONFORMANCE_ROOT",
    "OFFICIAL_HOSTS",
    "OFFICIAL_SOURCES_FILE",
    "RULE_UPDATED_LABEL",
    "UI_TOKENS_FILE",
    "SnapshotChange",
    "SnapshotChangeKind",
    "SourceDecision",
    "SourceSnapshotSet",
    "classify_all",
    "classify_source",
    "compare_snapshots",
    "contrast_ratio",
    "load_snapshot",
    "load_ui_tokens",
    "read_json",
]
