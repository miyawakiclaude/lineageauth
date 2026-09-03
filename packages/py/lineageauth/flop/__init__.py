"""FLOP Activity Console: an application layer, never a protocol change.

The FLOP network does not exist yet. Its teaser is a draft, its Yellow Paper is
unpublished, and no testnet endpoint has been announced. This package is what an
agent can honestly build against that: a record of what it has actually done, a
statement of which FLOP rules are officially published today, a scanner for the
untrusted text it meets on the way, and an explicit refusal to turn any of it
into a number that looks like an airdrop allocation.

Four rules shape every module here.

*Nothing about FLOP is hard-coded.* Every economic rule is a row in
`conformance/flop/rule-registry.json` carrying the official sentence it came
from, the version and date of the document, and that document's hash. The 3-to-1
unlock ratio is data. When the draft changes, the code does not.

*Official is an origin, never a word.* `sources.classify_source` looks at a URL
and nothing else. A room called "official", a nickname, a topic, a note
namespace and a valid signature all fail to make a message official, because
`https://technocore.chat/auth.md` says the service authenticates nobody.

*Coverage is not a score.* `coverage.py` reports ten categories in five states
and refuses to add them up. `Evidence coverage - not an airdrop score` is a
constant in this package because it has to appear wherever coverage does.

*The scanner never authorises anything.* `safety.SafetyFinding` cannot be built
with `executed=True`. Finding nothing is not permission; it is the absence of a
finding.

This package holds no key, signs nothing, reaches no network, and writes nothing
outside the process. The protocol core underneath it is untouched.
"""

from lineageauth.flop.activity import (
    ActivityCollection,
    ActivitySourceAdapter,
    ActivitySubject,
    LocalEventsAdapter,
    MockAdapter,
    PublicEvidenceAdapter,
    TclkAdapter,
    TechnocoreAdapter,
    collect_activities,
)
from lineageauth.flop.coverage import (
    COVERAGE_CATEGORIES,
    CoverageReport,
    compute_coverage,
)
from lineageauth.flop.model import (
    COVERAGE_LABEL,
    COVERAGE_LABEL_ASCII,
    NOT_AFFILIATED_NOTICE,
    SEED_WARNING_NOTICE,
    SYNTHETIC_BANNER,
    ActivityCategory,
    ActivityRecord,
    CoverageCategory,
    CoverageState,
    EconomicRule,
    EvidenceLevel,
    FeatureStatus,
    FlopActivityPassport,
    NetworkPhase,
    OfficialSourceSnapshot,
    PassportSection,
    Recommendation,
    RecommendationType,
    RuleSource,
    RuleStatus,
    SafetyFinding,
    SafetyLevel,
    SourceClass,
    VerificationState,
    WashSignal,
)
from lineageauth.flop.passport import build_flop_passport
from lineageauth.flop.recommend import next_best_action, recommend
from lineageauth.flop.rules import FlopRuleRegistry, RuleFreshness, unlock_ratio
from lineageauth.flop.safety import (
    SCANNER_NOTE,
    extract_urls,
    overall_level,
    scan_text,
)
from lineageauth.flop.sources import (
    SourceDecision,
    SourceSnapshotSet,
    classify_source,
    compare_snapshots,
    load_snapshot,
    load_ui_tokens,
)
from lineageauth.flop.wash import POSSIBLE_LOW_VALUE_LABEL, detect_wash_signals

__all__ = [
    "COVERAGE_CATEGORIES",
    "COVERAGE_LABEL",
    "COVERAGE_LABEL_ASCII",
    "NOT_AFFILIATED_NOTICE",
    "POSSIBLE_LOW_VALUE_LABEL",
    "SCANNER_NOTE",
    "SEED_WARNING_NOTICE",
    "SYNTHETIC_BANNER",
    "ActivityCategory",
    "ActivityCollection",
    "ActivityRecord",
    "ActivitySourceAdapter",
    "ActivitySubject",
    "CoverageCategory",
    "CoverageReport",
    "CoverageState",
    "EconomicRule",
    "EvidenceLevel",
    "FeatureStatus",
    "FlopActivityPassport",
    "FlopRuleRegistry",
    "LocalEventsAdapter",
    "MockAdapter",
    "NetworkPhase",
    "OfficialSourceSnapshot",
    "PassportSection",
    "PublicEvidenceAdapter",
    "Recommendation",
    "RecommendationType",
    "RuleFreshness",
    "RuleSource",
    "RuleStatus",
    "SafetyFinding",
    "SafetyLevel",
    "SourceClass",
    "SourceDecision",
    "SourceSnapshotSet",
    "TclkAdapter",
    "TechnocoreAdapter",
    "VerificationState",
    "WashSignal",
    "build_flop_passport",
    "classify_source",
    "collect_activities",
    "compare_snapshots",
    "compute_coverage",
    "detect_wash_signals",
    "extract_urls",
    "load_snapshot",
    "load_ui_tokens",
    "next_best_action",
    "overall_level",
    "recommend",
    "scan_text",
    "unlock_ratio",
]
