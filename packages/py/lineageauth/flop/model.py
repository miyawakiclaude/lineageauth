"""The typed vocabulary of the FLOP layer.

Every distinction the product makes is an enum here rather than a string
compared in three places. Two of them matter more than the rest.

`EvidenceLevel` never collapses into a rating. A record is self-claimed,
cryptographically linked, evidence-supported or third-party attested, and those
four are not points on a scale that can be added -- `docs/09` says the same
thing about the core passport, and the reason is that summing them produces a
number that reads as a verdict nobody signed.

`CoverageState` includes `NOT_YET_AVAILABLE` on purpose. A network feature that
does not exist must not report zero: zero is an observation about a thing that
is there, and showing `0 FLOP spent` for a testnet that has not launched is a
lie told by a data model rather than by a person.

Nothing in this module reads a file, reaches a network, or holds a key. The
dataclasses are frozen so a record cannot be edited after the layer that knows
its provenance has handed it on.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from lineageauth.errors import LineageAuthError, MalformedEventError
from lineageauth.timeutil import format_instant

# The label that must appear wherever coverage does. Kept as a constant because
# a phrase that exists to prevent a misunderstanding is not decoration, and
# retyping it is how the wrong version of it gets shipped.
COVERAGE_LABEL = "Evidence coverage — not an airdrop score"
COVERAGE_LABEL_ASCII = "Evidence coverage - not an airdrop score"
"""The same sentence for a console that cannot print an em dash.

`tests/test_zero_cost.py` found this the hard way: one em dash in the CLI's help
text took the whole command down on a Japanese Windows console under cp932. The
CLI uses this spelling; the API and the page use the other."""

NOT_AFFILIATED_NOTICE = (
    "Independent tool for the FLOP ecosystem - not affiliated with or endorsed by FLOP Labs."
)

SEED_WARNING_NOTICE = (
    "FLOP token may not yet exist on the current network phase. Never enter a seed phrase "
    "or private key to claim an airdrop."
)

SYNTHETIC_BANNER = "SYNTHETIC MOCK DATA"

SIMULATION_BANNER = "SIMULATION - NO FLOP NETWORK ACTION"

VOLUME_NOTE = "Volume is not evidence of useful participation."

NOT_VERIFIED_BY_OFFICIAL = "NOT VERIFIED BY CURRENT OFFICIAL FLOP SOURCES"

UNKNOWN_FROM_OFFICIAL_SPEC = "UNKNOWN_FROM_OFFICIAL_SPEC"

# Words this product may not use about a person's activity. Checked by a test
# over every rendered response, because the prohibition is worth nothing if it
# only lives in a style guide.
FORBIDDEN_VOCABULARY: tuple[str, ...] = (
    "airdrop score",
    "eligibility score",
    "you will receive",
    "guaranteed eligible",
    "official airdrop rank",
    "estimated allocation",
)


class EvidenceLevel(StrEnum):
    """How well a record is backed. Four labels, never a rating."""

    SELF_CLAIMED = "self-claimed"
    CRYPTOGRAPHICALLY_LINKED = "cryptographically-linked"
    EVIDENCE_SUPPORTED = "evidence-supported"
    THIRD_PARTY_ATTESTED = "third-party-attested"

    @property
    def is_externally_supported(self) -> bool:
        """True when somebody other than the subject is involved."""
        return self in (EvidenceLevel.EVIDENCE_SUPPORTED, EvidenceLevel.THIRD_PARTY_ATTESTED)


class SourceClass(StrEnum):
    """Where a record came from, decided by origin and never by wording."""

    OFFICIAL = "official"
    VERIFIED_THIRD_PARTY = "verified-third-party"
    COMMUNITY = "community"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"

    @property
    def may_carry_official_badge(self) -> bool:
        return self is SourceClass.OFFICIAL


class VerificationState(StrEnum):
    """What this session actually checked."""

    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially-verified"
    UNVERIFIED = "unverified"
    CONFLICTED = "conflicted"
    INVALID = "invalid"


class CoverageState(StrEnum):
    """One coverage category's state. `NOT_YET_AVAILABLE` is not zero."""

    STRONG_EVIDENCE = "STRONG_EVIDENCE"
    SOME_EVIDENCE = "SOME_EVIDENCE"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_YET_AVAILABLE = "NOT_YET_AVAILABLE"
    SOURCE_UNKNOWN = "SOURCE_UNKNOWN"

    @property
    def is_covered(self) -> bool:
        return self in (CoverageState.STRONG_EVIDENCE, CoverageState.SOME_EVIDENCE)


class NetworkPhase(StrEnum):
    """How far the FLOP network has actually got, as this tool can tell.

    The discovered-unverified rungs exist because finding an endpoint is not the
    same as confirming it is the official one, and a state machine with no room
    for that difference will collapse the two the first time somebody publishes
    a convincing URL.
    """

    PRE_TESTNET = "PRE_TESTNET"
    TESTNET_DISCOVERED_UNVERIFIED = "TESTNET_DISCOVERED_UNVERIFIED"
    TESTNET_VERIFIED = "TESTNET_VERIFIED"
    TESTNET_ENABLED = "TESTNET_ENABLED"
    MAINNET_DISCOVERED_UNVERIFIED = "MAINNET_DISCOVERED_UNVERIFIED"
    MAINNET_VERIFIED = "MAINNET_VERIFIED"

    @property
    def testnet_is_live(self) -> bool:
        """Only the enabled rung. Verified means checked, not switched on."""
        return self is NetworkPhase.TESTNET_ENABLED

    @property
    def badge(self) -> str:
        if self is NetworkPhase.PRE_TESTNET:
            return "PRE-TESTNET"
        if self.value.startswith("TESTNET"):
            return "TESTNET"
        return "MAINNET"


class FeatureStatus(StrEnum):
    """Why a passport section is empty, which is not the same as being empty."""

    AVAILABLE = "available"
    NOT_YET_AVAILABLE = "not-yet-available"
    NOT_CONFIGURED = "not-configured"
    NOT_OBSERVED = "not-observed"
    UNSUPPORTED = "unsupported"


class SafetyLevel(StrEnum):
    """How dangerous a piece of untrusted text looks. Never an authorisation."""

    INFO = "INFO"
    CAUTION = "CAUTION"
    HIGH_RISK = "HIGH_RISK"
    BLOCKED = "BLOCKED"

    @property
    def display(self) -> str:
        return {
            SafetyLevel.INFO: "SAFE TO REVIEW",
            SafetyLevel.CAUTION: "CAUTION",
            SafetyLevel.HIGH_RISK: "HIGH RISK",
            SafetyLevel.BLOCKED: "BLOCKED",
        }[self]

    @property
    def rank(self) -> int:
        return {
            SafetyLevel.INFO: 0,
            SafetyLevel.CAUTION: 1,
            SafetyLevel.HIGH_RISK: 2,
            SafetyLevel.BLOCKED: 3,
        }[self]


class RecommendationType(StrEnum):
    """What kind of thing a suggestion is. Inferred advice is never official."""

    OFFICIAL_REQUIREMENT = "officialRequirement"
    OFFICIAL_DIRECTION = "officialDirection"
    EVIDENCE_GAP = "evidenceGap"
    SECURITY_RECOMMENDATION = "securityRecommendation"
    COMMUNITY_OBSERVATION = "communityObservation"

    @property
    def is_official(self) -> bool:
        return self in (
            RecommendationType.OFFICIAL_REQUIREMENT,
            RecommendationType.OFFICIAL_DIRECTION,
        )


class RuleStatus(StrEnum):
    """How settled a FLOP rule is. The directive fixes these four."""

    OFFICIAL_FINAL = "official-final"
    OFFICIAL_DRAFT = "official-draft"
    COMMUNITY = "community"
    UNKNOWN = "unknown"


class InferencePurpose(StrEnum):
    """Why an agent would buy inference. Stated by a human, never inferred."""

    EVALUATION = "evaluation"
    TRANSLATION = "translation"
    SUMMARISATION = "summarisation"
    CODE_REVIEW = "code-review"
    RESEARCH = "research"
    OTHER = "other"


class TestnetFailure(StrEnum):
    """Every way a testnet action can be refused, as a typed reason.

    `docs/29` D-098: refusing is only safe when the refusal says why. A boolean
    false teaches the caller nothing and invites a retry loop.
    """

    # pytest collects classes whose name starts with "Test". This is a FLOP
    # network type, not a test case, and the flag keeps the suite quiet.
    __test__ = False

    TESTNET_NOT_LIVE = "TESTNET_NOT_LIVE"
    KILL_SWITCH_ENGAGED = "KILL_SWITCH_ENGAGED"
    OFFICIAL_SOURCE_UNVERIFIED = "OFFICIAL_SOURCE_UNVERIFIED"
    ENDPOINT_NOT_OFFICIAL = "ENDPOINT_NOT_OFFICIAL"
    ENDPOINT_BLOCKED = "ENDPOINT_BLOCKED"
    REQUEST_INVALID = "REQUEST_INVALID"
    DID_NOT_ACTIVE = "DID_NOT_ACTIVE"
    AUTHORITY_DENIED = "AUTHORITY_DENIED"
    SPEND_LIMIT_EXCEEDED = "SPEND_LIMIT_EXCEEDED"
    APPROVAL_MISSING = "APPROVAL_MISSING"
    APPROVAL_MISMATCH = "APPROVAL_MISMATCH"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    QUOTE_EXPIRED = "QUOTE_EXPIRED"
    REPREPARE_REQUIRED = "REPREPARE_REQUIRED"
    SIGNER_NOT_CONFIGURED = "SIGNER_NOT_CONFIGURED"
    NETWORK_REFUSED = "NETWORK_REFUSED"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    RECEIPT_UNVERIFIED = "RECEIPT_UNVERIFIED"
    SUSPICIOUS_CONTENT = "SUSPICIOUS_CONTENT"


@dataclass(frozen=True, slots=True)
class TestnetRefusal:
    """Why a testnet action did not happen, in a form a caller can branch on.

    `docs/29` D-098 again: refusing safely is not the same as refusing usefully.
    A boolean false teaches the caller nothing and invites a retry loop, so
    every refusal names its stage as well as its reason -- "the phase gate said
    no" and "the spend policy said no" call for different fixes.
    """

    __test__ = False

    failure: TestnetFailure
    detail: str
    stage: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure": str(self.failure),
            "detail": self.detail,
            "stage": self.stage,
            "executed": False,
        }


class TestnetRefusedError(LineageAuthError):
    """Raised where a refusal cannot be a return value (a builder, a parser)."""

    __test__ = False

    def __init__(self, refusal: TestnetRefusal) -> None:
        super().__init__(f"{refusal.failure}: {refusal.detail}")
        self.refusal = refusal


class ActivityCategory(StrEnum):
    """What a record is about. The first eleven are the directive's list."""

    CODE_CONTRIBUTION = "code-contribution"
    CONNECTOR = "connector"
    DOCUMENTATION = "documentation"
    TRANSLATION = "translation"
    BUG_REPORT = "bug-report"
    REPRODUCIBLE_TEST = "reproducible-test"
    SECURITY_FINDING = "security-finding"
    AGENT_COLLABORATION = "agent-collaboration"
    USEFUL_ARTIFACT = "useful-artifact"
    PROTOCOL_IMPLEMENTATION = "protocol-implementation"
    EXTERNAL_VERIFICATION = "external-verification"
    # Not useful work. Kept apart so a counter can never be mistaken for one.
    MESSAGE_VOLUME = "message-volume"
    ROOM_PARTICIPATION = "room-participation"
    TCLK_DEAL = "tclk-deal"
    IDENTITY = "identity"
    INFERENCE = "inference"


USEFUL_WORK_CATEGORIES: frozenset[ActivityCategory] = frozenset(
    {
        ActivityCategory.CODE_CONTRIBUTION,
        ActivityCategory.CONNECTOR,
        ActivityCategory.DOCUMENTATION,
        ActivityCategory.TRANSLATION,
        ActivityCategory.BUG_REPORT,
        ActivityCategory.REPRODUCIBLE_TEST,
        ActivityCategory.SECURITY_FINDING,
        ActivityCategory.USEFUL_ARTIFACT,
        ActivityCategory.PROTOCOL_IMPLEMENTATION,
    }
)


def forbidden_vocabulary_in(text: str) -> tuple[str, ...]:
    """Which banned phrases a rendered response contains.

    The disclaimer is removed first, and only then is the text searched. The
    coverage label says "not an airdrop score", which contains the phrase it
    exists to disown; a check that flagged it would force the label to be
    rewritten into something vaguer, which is the opposite of the point. Only
    the negated form is exempted, and only that form -- "airdrop score" on its
    own still fires, in JSON-escaped text as well as plain, because the dash in
    the label is not what makes it safe.
    """
    haystack = text.lower().replace("not an airdrop score", " ")
    return tuple(phrase for phrase in FORBIDDEN_VOCABULARY if phrase in haystack)


def _as_text(value: object, *, field_name: str, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value:
        raise MalformedEventError(f"{field_name} must be a non-empty string")
    if len(value) > limit:
        raise MalformedEventError(f"{field_name} is limited to {limit} characters")
    return value


@dataclass(frozen=True, slots=True)
class OfficialSourceSnapshot:
    """One official document as it was at one instant.

    The body is not here and never will be. A hash is enough to notice a change,
    and keeping someone else's document in this repository is a licensing
    question this project has no answer to.
    """

    source_id: str
    url: str
    http_status: int | None
    byte_length: int | None
    sha256: str | None
    fetched_at: str
    version_hint: str | None
    status: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.source_id,
            "url": self.url,
            "httpStatus": self.http_status,
            "bytes": self.byte_length,
            "sha256": self.sha256,
            "fetchedAt": self.fetched_at,
            "versionHint": self.version_hint,
            "status": self.status,
            "note": self.note,
            "bodyStored": False,
        }


@dataclass(frozen=True, slots=True)
class RuleSource:
    """Where a rule came from, precisely enough to notice it moving."""

    source_id: str
    source_url: str
    source_version: str
    source_date: str
    fetched_at: str
    hash: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sourceId": self.source_id,
            "sourceUrl": self.source_url,
            "sourceVersion": self.source_version,
            "sourceDate": self.source_date,
            "fetchedAt": self.fetched_at,
            "hash": self.hash,
        }


@dataclass(frozen=True, slots=True)
class EconomicRule:
    """One published FLOP rule, with the sentence it came from.

    `formula` carries any arithmetic as data. The 3-to-1 unlock ratio lives
    there rather than in Python, because it is a provisional figure in a draft
    and the code should not have to change when the draft does.
    """

    rule_id: str
    statement: str
    status: RuleStatus
    effective_network_phase: str
    source: RuleSource
    statement_is_quotation: bool = True
    derivation: str | None = None
    derivation_note: str | None = None
    formula: Mapping[str, Any] | None = None
    absent_from: tuple[str, ...] = ()
    consequence: str | None = None

    @property
    def is_unknown(self) -> bool:
        return self.status is RuleStatus.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "statement": self.statement,
            "statementIsQuotation": self.statement_is_quotation,
            "status": str(self.status),
            "effectiveNetworkPhase": self.effective_network_phase,
            "derivation": self.derivation,
            "derivationNote": self.derivation_note,
            "formula": dict(self.formula) if self.formula is not None else None,
            "absentFrom": list(self.absent_from),
            "consequence": self.consequence,
            "source": self.source.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ActivityRecord:
    """One thing that happened, and how well it is backed.

    `secondary` is the answer to the message-volume problem. A room with five
    hundred posts in it is a fact, and it is not useful work; marking the record
    rather than dropping it lets the analytics view show the number while the
    evidence view refuses to count it.
    """

    record_id: str
    subject_did: str
    category: ActivityCategory
    title: str
    occurred_at: datetime
    source_id: str
    source_class: SourceClass
    evidence_level: EvidenceLevel
    verification_state: VerificationState
    artifact_hash: str | None = None
    artifact_ref: str | None = None
    event_id: str | None = None
    counterparties: tuple[str, ...] = ()
    third_party_ref: str | None = None
    synthetic: bool = False
    secondary: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        _as_text(self.record_id, field_name="record_id", limit=256)
        _as_text(self.title, field_name="title")

    @property
    def is_useful_work(self) -> bool:
        """Secondary records are never useful work, whatever their category."""
        return not self.secondary and self.category in USEFUL_WORK_CATEGORIES

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.record_id,
            "subjectDid": self.subject_did,
            "category": str(self.category),
            "title": self.title,
            "occurredAt": format_instant(self.occurred_at),
            "sourceId": self.source_id,
            "sourceClass": str(self.source_class),
            "evidenceLevel": str(self.evidence_level),
            "verificationState": str(self.verification_state),
            "artifactHash": self.artifact_hash,
            "artifactRef": self.artifact_ref,
            "eventId": self.event_id,
            "counterparties": list(self.counterparties),
            "thirdPartyRef": self.third_party_ref,
            "synthetic": self.synthetic,
            "secondary": self.secondary,
            "detail": self.detail,
            **({"banner": SYNTHETIC_BANNER} if self.synthetic else {}),
        }


@dataclass(frozen=True, slots=True)
class SafetyFinding:
    """Something the scanner noticed in untrusted text.

    `executed` exists to be permanently false. A scan result is an observation
    about a string; treating a clean scan as permission to act is the mistake
    the whole safety layer is built to prevent, so the type refuses to represent
    the other value.
    """

    finding_id: str
    level: SafetyLevel
    pattern_id: str
    reason: str
    source_class: SourceClass
    excerpt: str | None = None
    url: str | None = None
    executed: bool = False

    def __post_init__(self) -> None:
        if self.executed:
            raise MalformedEventError(
                "a safety finding may never record an execution: the scanner "
                "observes text and authorises nothing"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "level": str(self.level),
            "display": self.level.display,
            "patternId": self.pattern_id,
            "reason": self.reason,
            "sourceClass": str(self.source_class),
            "excerpt": self.excerpt,
            "url": self.url,
            "executed": False,
            "autoOpened": False,
        }


@dataclass(frozen=True, slots=True)
class WashSignal:
    """A pattern that is hard to tell apart from wash activity.

    Deliberately not an accusation. The wording is fixed in `wash.py` and says
    what is difficult to distinguish, not what somebody did.
    """

    signal_id: str
    pattern_id: str
    label: str
    reason: str
    record_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.signal_id,
            "patternId": self.pattern_id,
            "label": self.label,
            "reason": self.reason,
            "recordIds": list(self.record_ids),
            "isAccusation": False,
        }


@dataclass(frozen=True, slots=True)
class Recommendation:
    """A suggested next step, with the rule it came from and how sure it is."""

    recommendation_id: str
    title: str
    recommendation_type: RecommendationType
    reason: str
    confidence: str
    rule_id: str | None = None

    @property
    def official(self) -> bool:
        """Official only when the type says so. Inferred advice never claims it."""
        return self.recommendation_type.is_official and self.rule_id is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.recommendation_id,
            "title": self.title,
            "type": str(self.recommendation_type),
            "reason": self.reason,
            "confidence": self.confidence,
            "ruleId": self.rule_id,
            "official": self.official,
            "isEligibilityClaim": False,
        }


@dataclass(frozen=True, slots=True)
class CoverageCategory:
    """One of the ten categories, its state, and why it is in that state."""

    category_id: str
    label: str
    state: CoverageState
    observed: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.category_id,
            "label": self.label,
            "state": str(self.state),
            "observed": self.observed,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class PassportSection:
    """A named section of the passport and why it holds what it holds."""

    section_id: str
    status: FeatureStatus
    reason: str
    detail: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.section_id,
            "status": str(self.status),
            "reason": self.reason,
            "detail": dict(self.detail),
        }


@dataclass(frozen=True, slots=True)
class FlopActivityPassport:
    """The projection: observed activity, coverage, risks, and suggestions.

    A projection over the core passport rather than a replacement for it. The
    core answers "what does this bundle say about this DID"; this answers "what
    of that is relevant to FLOP participation, and what is still unknown". There
    is no combined figure, because there is nothing honest to combine.
    """

    subject_did: str
    lineage: str
    generated_at: datetime
    network_phase: NetworkPhase
    sections: tuple[PassportSection, ...]
    coverage: tuple[CoverageCategory, ...]
    activities: tuple[ActivityRecord, ...]
    safety: tuple[SafetyFinding, ...] = ()
    wash_signals: tuple[WashSignal, ...] = ()
    recommendations: tuple[Recommendation, ...] = ()
    sources: tuple[OfficialSourceSnapshot, ...] = ()
    warnings: tuple[str, ...] = ()
    contains_synthetic: bool = False

    @property
    def useful_work_count(self) -> int:
        return sum(1 for record in self.activities if record.is_useful_work)

    @property
    def covered_categories(self) -> int:
        return sum(1 for category in self.coverage if category.state.is_covered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subjectDid": self.subject_did,
            "lineage": self.lineage,
            "generatedAt": format_instant(self.generated_at),
            "networkPhase": str(self.network_phase),
            "networkPhaseBadge": self.network_phase.badge,
            "sections": [section.to_dict() for section in self.sections],
            "evidenceCoverage": {
                "label": COVERAGE_LABEL,
                "labelAscii": COVERAGE_LABEL_ASCII,
                "covered": self.covered_categories,
                "total": len(self.coverage),
                "isAirdropScore": False,
                "categories": [category.to_dict() for category in self.coverage],
            },
            "summary": {
                "usefulWork": self.useful_work_count,
                "activityRecords": len(self.activities),
                "safetyFindings": len(self.safety),
                "washSignals": len(self.wash_signals),
                "volumeNote": VOLUME_NOTE,
            },
            "activities": [record.to_dict() for record in self.activities],
            "safety": [finding.to_dict() for finding in self.safety],
            "washSignals": [signal.to_dict() for signal in self.wash_signals],
            "recommendations": [item.to_dict() for item in self.recommendations],
            "sources": [snapshot.to_dict() for snapshot in self.sources],
            "warnings": list(self.warnings),
            "containsSyntheticData": self.contains_synthetic,
            **({"banner": SYNTHETIC_BANNER} if self.contains_synthetic else {}),
            "notices": {
                "affiliation": NOT_AFFILIATED_NOTICE,
                "seedPhrase": SEED_WARNING_NOTICE,
                "coverage": COVERAGE_LABEL,
            },
            "holdsPrivateKeys": False,
            "walletCustody": False,
        }


def sort_records(records: Sequence[ActivityRecord]) -> tuple[ActivityRecord, ...]:
    """Order records so the same inputs always render the same way.

    By instant, then by id. Two records at the same second are common -- a
    contribution note lists several at once -- and leaving their order to
    whichever adapter ran first makes a diff of two identical runs look like a
    change.
    """
    return tuple(sorted(records, key=lambda record: (record.occurred_at, record.record_id)))


__all__ = [
    "COVERAGE_LABEL",
    "COVERAGE_LABEL_ASCII",
    "FORBIDDEN_VOCABULARY",
    "NOT_AFFILIATED_NOTICE",
    "NOT_VERIFIED_BY_OFFICIAL",
    "SEED_WARNING_NOTICE",
    "SIMULATION_BANNER",
    "SYNTHETIC_BANNER",
    "UNKNOWN_FROM_OFFICIAL_SPEC",
    "USEFUL_WORK_CATEGORIES",
    "VOLUME_NOTE",
    "ActivityCategory",
    "ActivityRecord",
    "CoverageCategory",
    "CoverageState",
    "EconomicRule",
    "EvidenceLevel",
    "FeatureStatus",
    "FlopActivityPassport",
    "InferencePurpose",
    "NetworkPhase",
    "OfficialSourceSnapshot",
    "PassportSection",
    "Recommendation",
    "RecommendationType",
    "RuleSource",
    "RuleStatus",
    "SafetyFinding",
    "SafetyLevel",
    "SourceClass",
    "TestnetFailure",
    "TestnetRefusal",
    "TestnetRefusedError",
    "VerificationState",
    "WashSignal",
    "forbidden_vocabulary_in",
    "sort_records",
]
