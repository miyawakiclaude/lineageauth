"""The safety shield: read untrusted text, report what is dangerous, act on none of it.

Every string that reaches this module came from somewhere else -- a room, a
note, a repository, a task description -- and is data rather than instruction
(`CLAUDE.md` 2.4). The scanner's whole job is to say what a human should look
at before deciding, and its whole prohibition is that a clean result is not
permission. `SafetyFinding` cannot be constructed with `executed=True`, so the
type itself refuses to represent "the scanner allowed it".

Two detections are worth naming.

*GET-write Technocore URLs.* Technocore performs writes through plain `GET`, so
a URL in a message can have a side effect just by being fetched. Classification
is delegated to `adapters/technocore/routes.py` rather than re-implemented here,
because there is already one table that is kept correct and a second one would
drift. Nothing in this module fetches anything.

*Contradiction with the network phase.* "Buy $FLOP now" is not suspicious in the
abstract; it is suspicious because no official source says a token exists on the
current phase. That check reads the phase it is given, so the day a testnet
launches the same text stops being a contradiction without anyone editing a
pattern.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from lineageauth.adapters.technocore.routes import (
    SERVICE_HOST,
    Consequence,
    classify,
)
from lineageauth.flop.model import (
    NOT_VERIFIED_BY_OFFICIAL,
    NetworkPhase,
    SafetyFinding,
    SafetyLevel,
    SourceClass,
)
from lineageauth.flop.sources import classify_source

SCANNER_NOTE = (
    "A scan result never authorises execution. Finding nothing is the absence of a "
    "finding, not permission."
)

# A suppressed detection is still reported, as itself. Silence would let the two
# parameters that soften this scanner -- the phase and the source class -- turn
# a scan into "SAFE TO REVIEW" for text that matched a rule.
SUPPRESSED_BY_PHASE_PATTERN = "network.claim-not-contradicted-by-phase"
SUPPRESSED_BY_PROVENANCE_PATTERN = "authority.check-skipped-for-asserted-official"

MAX_SCAN_CHARS = 64_000
_EXCERPT_CHARS = 120

_URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp|file|data|javascript):[^\s<>\"'`\]\)]{1,4000}")

# Zero-width and bidirectional-override characters. Text that reads one way to a
# person and another way to a parser is the whole trick.
_INVISIBLES = re.compile("[\\u200b\\u200c\\u200d\\u2060\\ufeff\\u202a-\\u202e\\u2066-\\u2069]")

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


class _Rule:
    """One text pattern, what it means, and how loudly to say so."""

    __slots__ = ("level", "pattern", "pattern_id", "reason")

    def __init__(self, pattern_id: str, pattern: str, level: SafetyLevel, reason: str) -> None:
        self.pattern_id = pattern_id
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.level = level
        self.reason = reason


# Ordered by severity so the first match on a piece of text is the worst one.
_SECRET_RULES: tuple[_Rule, ...] = (
    _Rule(
        "secret.seed-phrase",
        r"seed\s*phrase|mnemonic|recovery\s*phrase|twelve\s*words|12\s*words|24\s*words",
        SafetyLevel.BLOCKED,
        "asks for a seed phrase; no legitimate FLOP process needs one and this tool "
        "never takes one",
    ),
    _Rule(
        "secret.private-key",
        r"private\s*key|secret\s*key|keystore|export\s+your\s+key|paste\s+your\s+key",
        SafetyLevel.BLOCKED,
        "asks for private key material",
    ),
    _Rule(
        "secret.wallet-connect",
        r"connect\s+(your\s+)?wallet|walletconnect|link\s+your\s+wallet",
        SafetyLevel.BLOCKED,
        "asks to connect a wallet; this tool takes no custody and performs no wallet action",
    ),
    _Rule(
        "secret.sign-transaction",
        r"sign\s+(this|the)\s+(transaction|message\s+to\s+claim)|approve\s+(this\s+)?transaction",
        SafetyLevel.BLOCKED,
        "asks for a transaction signature",
    ),
)

_INJECTION_RULES: tuple[_Rule, ...] = (
    _Rule(
        "injection.override",
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions"
        r"|disregard\s+(all\s+)?(previous|prior)\s+"
        r"|forget\s+(your|all)\s+(instructions|rules)"
        r"|override\s+your\s+(rules|instructions|safety)",
        SafetyLevel.HIGH_RISK,
        "tries to replace the instructions the reader is operating under",
    ),
    _Rule(
        "injection.role-change",
        r"you\s+are\s+now\s+|new\s+instructions\s*:|system\s+prompt|act\s+as\s+(the\s+)?admin",
        SafetyLevel.HIGH_RISK,
        "tries to change the reader's role",
    ),
    _Rule(
        "injection.shell",
        r"curl\s+-|wget\s+http|bash\s+-c|\|\s*sh\b|powershell\s+-|rm\s+-rf\s+/"
        r"|chmod\s+\+x|iex\s*\(|invoke-expression",
        SafetyLevel.HIGH_RISK,
        "carries a shell command; content is never executed by this tool",
    ),
    _Rule(
        "injection.run-script",
        r"run\s+(this\s+)?(script|installer)|npm\s+install\s+-g|pip\s+install\s+http",
        SafetyLevel.HIGH_RISK,
        "asks for a script to be run from untrusted content",
    ),
)

_NETWORK_CLAIM_RULES: tuple[_Rule, ...] = (
    _Rule(
        "network.buy-or-mint",
        r"buy\s+\$?flop|mint\s+\$?flop|presale|token\s+sale|purchase\s+\$?flop",
        SafetyLevel.HIGH_RISK,
        "offers to sell or mint a token",
    ),
    _Rule(
        "network.claim",
        r"claim\s+(your\s+)?(\$?flop|airdrop|token)|airdrop\s+claim|claim\s+now",
        SafetyLevel.HIGH_RISK,
        "offers an airdrop claim",
    ),
    _Rule(
        "network.live",
        r"mainnet\s+is\s+live|testnet\s+is\s+live|token\s+is\s+live|now\s+trading",
        SafetyLevel.HIGH_RISK,
        "asserts a network stage",
    ),
)

_AUTHORITY_RULES: tuple[_Rule, ...] = (
    _Rule(
        "authority.fake-official",
        r"official\s+flop|flop\s+labs\s+official|official\s+(airdrop|task|announcement)"
        r"|i\s+am\s+(an?\s+)?(admin|moderator|flop\s+labs)|verified\s+by\s+flop\s+labs",
        SafetyLevel.HIGH_RISK,
        "claims to speak for FLOP Labs",
    ),
)


def extract_urls(text: str) -> tuple[str, ...]:
    """Pull URL-shaped substrings out of untrusted text.

    Extraction, not resolution. Nothing here opens, follows, HEADs or previews
    any of them; they are handed to the classifiers as strings.
    """
    if not isinstance(text, str):
        return ()
    seen: dict[str, None] = {}
    for match in _URL_PATTERN.finditer(text[:MAX_SCAN_CHARS]):
        seen.setdefault(match.group(0).rstrip(".,;:"), None)
    return tuple(seen)


def _excerpt(text: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - 30)
    end = min(len(text), match.end() + 30)
    return text[start:end].replace("\n", " ").strip()[:_EXCERPT_CHARS]


def _finding_id(prefix: str, index: int) -> str:
    return f"{prefix}-{index:03d}"


def _scan_rules(
    text: str,
    rules: Iterable[_Rule],
    *,
    source_class: SourceClass,
    counter: list[int],
) -> list[SafetyFinding]:
    found: list[SafetyFinding] = []
    for rule in rules:
        match = rule.pattern.search(text)
        if match is None:
            continue
        counter[0] += 1
        found.append(
            SafetyFinding(
                finding_id=_finding_id("finding", counter[0]),
                level=rule.level,
                pattern_id=rule.pattern_id,
                reason=rule.reason,
                source_class=source_class,
                excerpt=_excerpt(text, match),
            )
        )
    return found


def _scan_urls(
    urls: Sequence[str], *, source_class: SourceClass, counter: list[int]
) -> list[SafetyFinding]:
    found: list[SafetyFinding] = []
    for url in urls:
        decision = classify_source(url)
        lowered = url.lower()
        if lowered.startswith(("javascript:", "data:", "file:")):
            counter[0] += 1
            found.append(
                SafetyFinding(
                    finding_id=_finding_id("finding", counter[0]),
                    level=SafetyLevel.HIGH_RISK,
                    pattern_id="url.dangerous-scheme",
                    reason=(
                        "the URL uses a scheme that executes or reads locally rather than fetching"
                    ),
                    source_class=source_class,
                    url=url,
                )
            )
            continue
        if decision.host == SERVICE_HOST:
            classification = classify(url)
            if classification.consequence is Consequence.WRITE:
                counter[0] += 1
                found.append(
                    SafetyFinding(
                        finding_id=_finding_id("finding", counter[0]),
                        level=SafetyLevel.HIGH_RISK,
                        pattern_id="url.technocore-get-write",
                        reason=(
                            "this Technocore URL performs a write when it is fetched "
                            f"({classification.description}); it was not opened"
                        ),
                        source_class=source_class,
                        url=url,
                    )
                )
                continue
            if classification.consequence is Consequence.UNKNOWN:
                counter[0] += 1
                found.append(
                    SafetyFinding(
                        finding_id=_finding_id("finding", counter[0]),
                        level=SafetyLevel.CAUTION,
                        pattern_id="url.technocore-unclassified",
                        reason=(
                            "the Technocore route table does not recognise this URL, so what "
                            "fetching it would do is unknown"
                        ),
                        source_class=source_class,
                        url=url,
                    )
                )
                continue
        if decision.source_class is SourceClass.SUSPICIOUS:
            counter[0] += 1
            found.append(
                SafetyFinding(
                    finding_id=_finding_id("finding", counter[0]),
                    level=SafetyLevel.HIGH_RISK,
                    pattern_id="url.lookalike",
                    reason=f"{decision.reason}; it was not opened",
                    source_class=source_class,
                    url=url,
                )
            )
            continue
        if decision.source_class is SourceClass.UNKNOWN:
            counter[0] += 1
            found.append(
                SafetyFinding(
                    finding_id=_finding_id("finding", counter[0]),
                    level=SafetyLevel.CAUTION,
                    pattern_id="url.unknown-origin",
                    reason="no allowlisted official origin matches this URL; it was not opened",
                    source_class=source_class,
                    url=url,
                )
            )
    return found


def scan_text(
    text: str,
    *,
    source_class: SourceClass = SourceClass.UNKNOWN,
    network_phase: NetworkPhase = NetworkPhase.PRE_TESTNET,
    urls: Sequence[str] | None = None,
) -> tuple[SafetyFinding, ...]:
    """Scan one piece of untrusted text and report what is in it.

    `source_class` travels onto every finding rather than changing what counts
    as dangerous: a signed message from a community source is exactly as
    untrusted as an unsigned one, and letting provenance downgrade a detection
    is how "it was signed, so it must be fine" gets into a product.

    `network_phase` does change one family of findings. A claim that a token is
    live is a contradiction only against a phase where it is not, and the phase
    is passed in so that fact stays a parameter.

    Neither parameter can empty a scan. When the phase or an asserted official
    provenance means a matched rule is not raised as itself, the suppression is
    reported instead, at `CAUTION`, naming what matched and why it was softened.
    A caller that hands this function a friendlier phase or a friendlier source
    class therefore changes the wording of the answer and never gets silence:
    the HTTP surface refuses to take either from a client anyway
    (`flop/api.py`), and this is the second lock on the same door.
    """
    if not isinstance(text, str):
        return ()
    body = text[:MAX_SCAN_CHARS]
    counter = [0]
    findings: list[SafetyFinding] = []

    findings.extend(_scan_rules(body, _SECRET_RULES, source_class=source_class, counter=counter))
    findings.extend(_scan_rules(body, _INJECTION_RULES, source_class=source_class, counter=counter))

    network_claims = _scan_rules(body, _NETWORK_CLAIM_RULES, source_class=source_class, counter=[0])
    if not network_phase.testnet_is_live:
        for finding in network_claims:
            counter[0] += 1
            findings.append(
                SafetyFinding(
                    finding_id=_finding_id("finding", counter[0]),
                    level=finding.level,
                    pattern_id=finding.pattern_id,
                    reason=(
                        f"{finding.reason}; {NOT_VERIFIED_BY_OFFICIAL} "
                        f"(current phase {network_phase.badge})"
                    ),
                    source_class=finding.source_class,
                    excerpt=finding.excerpt,
                )
            )
    elif network_claims:
        counter[0] += 1
        findings.append(
            SafetyFinding(
                finding_id=_finding_id("finding", counter[0]),
                level=SafetyLevel.CAUTION,
                pattern_id=SUPPRESSED_BY_PHASE_PATTERN,
                reason=(
                    f"the text claims a token is live, and the phase this scan was given "
                    f"({network_phase.badge}) does not contradict that, so the contradiction "
                    "check was not raised; the claim itself was checked against nothing"
                ),
                source_class=source_class,
                excerpt=network_claims[0].excerpt,
            )
        )

    authority_claims = _scan_rules(body, _AUTHORITY_RULES, source_class=source_class, counter=[0])
    if source_class is not SourceClass.OFFICIAL:
        for finding in authority_claims:
            counter[0] += 1
            findings.append(
                SafetyFinding(
                    finding_id=_finding_id("finding", counter[0]),
                    level=finding.level,
                    pattern_id=finding.pattern_id,
                    reason=(
                        f"{finding.reason}, but it did not arrive from an official origin; "
                        f"{NOT_VERIFIED_BY_OFFICIAL}"
                    ),
                    source_class=finding.source_class,
                    excerpt=finding.excerpt,
                )
            )
    elif authority_claims:
        counter[0] += 1
        findings.append(
            SafetyFinding(
                finding_id=_finding_id("finding", counter[0]),
                level=SafetyLevel.CAUTION,
                pattern_id=SUPPRESSED_BY_PROVENANCE_PATTERN,
                reason=(
                    "the text speaks for FLOP Labs and was presented to this scanner as "
                    "official, so the impersonation check was not raised; that provenance was "
                    "asserted by the caller and proved by nothing here"
                ),
                source_class=source_class,
                excerpt=authority_claims[0].excerpt,
            )
        )

    invisible = _INVISIBLES.search(body)
    if invisible is not None:
        counter[0] += 1
        findings.append(
            SafetyFinding(
                finding_id=_finding_id("finding", counter[0]),
                level=SafetyLevel.CAUTION,
                pattern_id="obfuscation.invisible-characters",
                reason=(
                    "the text contains zero-width or direction-override characters, so what a "
                    "person reads and what a parser reads can differ"
                ),
                source_class=source_class,
            )
        )

    blob = _BASE64_BLOB.search(body)
    if blob is not None:
        counter[0] += 1
        findings.append(
            SafetyFinding(
                finding_id=_finding_id("finding", counter[0]),
                level=SafetyLevel.CAUTION,
                pattern_id="obfuscation.encoded-blob",
                reason="the text carries a long encoded run whose content was not decoded here",
                source_class=source_class,
                excerpt=blob.group(0)[:40],
            )
        )

    candidates = tuple(urls) if urls is not None else extract_urls(body)
    findings.extend(_scan_urls(candidates, source_class=source_class, counter=counter))

    return tuple(findings)


def overall_level(findings: Iterable[SafetyFinding]) -> SafetyLevel:
    """The loudest finding, or INFO when there are none.

    INFO reads as "SAFE TO REVIEW", which is the strongest thing a scanner is
    entitled to say: safe to look at, by a person, who then decides.
    """
    worst = SafetyLevel.INFO
    for finding in findings:
        if finding.level.rank > worst.rank:
            worst = finding.level
    return worst


def scan_report(
    text: str,
    *,
    source_class: SourceClass = SourceClass.UNKNOWN,
    network_phase: NetworkPhase = NetworkPhase.PRE_TESTNET,
) -> dict[str, object]:
    """A scan shaped for the API and the page."""
    findings = scan_text(text, source_class=source_class, network_phase=network_phase)
    level = overall_level(findings)
    return {
        "level": str(level),
        "display": level.display,
        "sourceClass": str(source_class),
        "networkPhase": str(network_phase),
        "findings": [finding.to_dict() for finding in findings],
        "executedAnything": False,
        "followedAnyUrl": False,
        "note": SCANNER_NOTE,
    }


__all__ = [
    "MAX_SCAN_CHARS",
    "SCANNER_NOTE",
    "SUPPRESSED_BY_PHASE_PATTERN",
    "SUPPRESSED_BY_PROVENANCE_PATTERN",
    "extract_urls",
    "overall_level",
    "scan_report",
    "scan_text",
]
