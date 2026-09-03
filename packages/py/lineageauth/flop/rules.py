"""The FLOP rule registry: published rules, with their age attached.

FLOP's only published economics are in a draft that says of itself that its
figures are provisional. A tool built on that has two obligations. The first is
never to hard-code any of it -- the 3-to-1 unlock ratio is a `formula` object in
`conformance/flop/rule-registry.json`, and `unlock_ratio` reads it. The second
is to notice when the draft moves: every rule records the hash of its source
document as it was when the rule was written down, and `freshness` compares that
against the current snapshot. A mismatch is `RULE UPDATED`, and a stale rule is
never served as though it were current.

Rules whose answer the official sources do not give are registered too, with the
statement `UNKNOWN_FROM_OFFICIAL_SPEC`. An unanswered question that appears in
the registry can be shown on a screen; one that was left out looks like a
question nobody thought to ask.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import (
    UNKNOWN_FROM_OFFICIAL_SPEC,
    EconomicRule,
    RuleSource,
    RuleStatus,
)
from lineageauth.flop.sources import (
    CONFORMANCE_ROOT,
    RULE_UPDATED_LABEL,
    SourceSnapshotSet,
    read_json,
)

RULE_REGISTRY_FILE = CONFORMANCE_ROOT / "rule-registry.json"

UNLOCK_RULE_ID = "flop-agent-unlock-ratio"


class Freshness(StrEnum):
    """Whether a rule still matches the source it was taken from."""

    CURRENT = "current"
    STALE = "stale"
    UNVERIFIABLE = "unverifiable"
    SOURCE_MISSING = "source-missing"


@dataclass(frozen=True, slots=True)
class RuleFreshness:
    """One rule's standing against the current source snapshot."""

    rule_id: str
    freshness: Freshness
    recorded_hash: str | None
    current_hash: str | None
    detail: str

    @property
    def label(self) -> str | None:
        return RULE_UPDATED_LABEL if self.freshness is Freshness.STALE else None

    @property
    def may_be_treated_as_current(self) -> bool:
        """Only a rule that still matches its source. Fails closed otherwise."""
        return self.freshness is Freshness.CURRENT

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "freshness": str(self.freshness),
            "recordedHash": self.recorded_hash,
            "currentHash": self.current_hash,
            "detail": self.detail,
            "label": self.label,
            "mayBeTreatedAsCurrent": self.may_be_treated_as_current,
        }


def _source_from(entry: Mapping[str, Any], *, rule_id: str) -> RuleSource:
    required = ("sourceId", "sourceUrl", "sourceVersion", "sourceDate", "fetchedAt")
    values: dict[str, str] = {}
    for name in required:
        value = entry.get(name)
        if not isinstance(value, str):
            raise MalformedEventError(f"rule {rule_id}: source.{name} must be a string")
        values[name] = value
    raw_hash = entry.get("hash")
    return RuleSource(
        source_id=values["sourceId"],
        source_url=values["sourceUrl"],
        source_version=values["sourceVersion"],
        source_date=values["sourceDate"],
        fetched_at=values["fetchedAt"],
        hash=raw_hash if isinstance(raw_hash, str) else None,
    )


def _rule_from(entry: Mapping[str, Any]) -> EconomicRule:
    rule_id = entry.get("id")
    statement = entry.get("statement")
    status = entry.get("status")
    phase = entry.get("effectiveNetworkPhase")
    if not isinstance(rule_id, str) or not rule_id:
        raise MalformedEventError("every rule needs a string id")
    if not isinstance(statement, str) or not statement:
        raise MalformedEventError(f"rule {rule_id}: statement must be a non-empty string")
    if not isinstance(status, str) or status not in tuple(RuleStatus):
        raise MalformedEventError(
            f"rule {rule_id}: status must be one of {[str(s) for s in RuleStatus]}"
        )
    if not isinstance(phase, str) or not phase:
        raise MalformedEventError(f"rule {rule_id}: effectiveNetworkPhase must be a string")
    source_entry = entry.get("source")
    if not isinstance(source_entry, Mapping):
        raise MalformedEventError(f"rule {rule_id}: source must be an object")

    rule_status = RuleStatus(status)
    if rule_status is RuleStatus.UNKNOWN and statement != UNKNOWN_FROM_OFFICIAL_SPEC:
        raise MalformedEventError(
            f"rule {rule_id}: an unknown rule must say {UNKNOWN_FROM_OFFICIAL_SPEC}, "
            "never a paraphrase that reads like an answer"
        )

    quotation = entry.get("statementIsQuotation")
    formula = entry.get("formula")
    absent = entry.get("absentFrom")
    derivation = entry.get("derivation")
    derivation_note = entry.get("derivationNote")
    consequence = entry.get("consequence")

    if derivation == "derived" and quotation is True:
        raise MalformedEventError(
            f"rule {rule_id}: a derived statement may not also claim to be a quotation"
        )

    return EconomicRule(
        rule_id=rule_id,
        statement=statement,
        status=rule_status,
        effective_network_phase=phase,
        source=_source_from(source_entry, rule_id=rule_id),
        statement_is_quotation=bool(quotation),
        derivation=derivation if isinstance(derivation, str) else None,
        derivation_note=derivation_note if isinstance(derivation_note, str) else None,
        formula=formula if isinstance(formula, Mapping) else None,
        absent_from=tuple(item for item in absent if isinstance(item, str))
        if isinstance(absent, list)
        else (),
        consequence=consequence if isinstance(consequence, str) else None,
    )


@dataclass(frozen=True, slots=True)
class FlopRuleRegistry:
    """Every published FLOP rule this tool knows, loaded from data."""

    rules: tuple[EconomicRule, ...]

    @classmethod
    def load(cls, path: Path | None = None) -> FlopRuleRegistry:
        document = read_json(path or RULE_REGISTRY_FILE)
        raw = document.get("rules")
        if not isinstance(raw, list):
            raise MalformedEventError("rule-registry.json needs a rules array")
        rules = tuple(_rule_from(entry) for entry in raw if isinstance(entry, Mapping))
        seen: set[str] = set()
        for rule in rules:
            if rule.rule_id in seen:
                raise MalformedEventError(f"rule {rule.rule_id} is registered twice")
            seen.add(rule.rule_id)
        return cls(rules=rules)

    def get(self, rule_id: str) -> EconomicRule | None:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def with_status(self, status: RuleStatus) -> tuple[EconomicRule, ...]:
        return tuple(rule for rule in self.rules if rule.status is status)

    @property
    def unknown_rules(self) -> tuple[EconomicRule, ...]:
        """The questions the official sources do not answer."""
        return self.with_status(RuleStatus.UNKNOWN)

    def freshness(self, snapshot: SourceSnapshotSet) -> tuple[RuleFreshness, ...]:
        """Compare every rule's recorded source hash against the current one."""
        results: list[RuleFreshness] = []
        for rule in self.rules:
            current = snapshot.by_id(rule.source.source_id)
            if current is None:
                results.append(
                    RuleFreshness(
                        rule_id=rule.rule_id,
                        freshness=Freshness.SOURCE_MISSING,
                        recorded_hash=rule.source.hash,
                        current_hash=None,
                        detail=(
                            f"source {rule.source.source_id} is not in the current snapshot, "
                            "so this rule cannot be checked against anything"
                        ),
                    )
                )
                continue
            if rule.source.hash is None or current.sha256 is None:
                results.append(
                    RuleFreshness(
                        rule_id=rule.rule_id,
                        freshness=Freshness.UNVERIFIABLE,
                        recorded_hash=rule.source.hash,
                        current_hash=current.sha256,
                        detail=(
                            "no body hash was recorded for this source, so a change in it "
                            "would go unnoticed here"
                        ),
                    )
                )
                continue
            if rule.source.hash != current.sha256:
                results.append(
                    RuleFreshness(
                        rule_id=rule.rule_id,
                        freshness=Freshness.STALE,
                        recorded_hash=rule.source.hash,
                        current_hash=current.sha256,
                        detail=(
                            f"{RULE_UPDATED_LABEL}: {rule.source.source_url} has changed since "
                            "this rule was recorded; re-read it before relying on the rule"
                        ),
                    )
                )
                continue
            results.append(
                RuleFreshness(
                    rule_id=rule.rule_id,
                    freshness=Freshness.CURRENT,
                    recorded_hash=rule.source.hash,
                    current_hash=current.sha256,
                    detail="matches the recorded source",
                )
            )
        return tuple(results)

    def stale_rules(self, snapshot: SourceSnapshotSet) -> tuple[RuleFreshness, ...]:
        return tuple(
            entry for entry in self.freshness(snapshot) if entry.freshness is Freshness.STALE
        )

    def to_dict(self, snapshot: SourceSnapshotSet | None = None) -> dict[str, Any]:
        freshness = self.freshness(snapshot) if snapshot is not None else ()
        by_rule = {entry.rule_id: entry for entry in freshness}
        return {
            "rules": [
                {
                    **rule.to_dict(),
                    "freshness": (
                        by_rule[rule.rule_id].to_dict() if rule.rule_id in by_rule else None
                    ),
                }
                for rule in self.rules
            ],
            "unknownCount": len(self.unknown_rules),
            "staleCount": sum(1 for entry in freshness if entry.freshness is Freshness.STALE),
            "note": (
                "Every statement above is quoted from a published source or marked "
                f"{UNKNOWN_FROM_OFFICIAL_SPEC}. None of it is an eligibility rule."
            ),
        }


def unlock_ratio(registry: FlopRuleRegistry) -> int | None:
    """How much inference spend the draft says unlocks one airdropped $FLOP.

    Read from the registry's `formula`, never written in this file. Returns None
    when the rule is absent or carries no formula, and the caller shows "not yet
    available" rather than guessing a number.
    """
    rule = registry.get(UNLOCK_RULE_ID)
    if rule is None or rule.formula is None:
        return None
    value = rule.formula.get("spentPerUnlocked")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def unlocked_from_spend(registry: FlopRuleRegistry, spend: int) -> int | None:
    """Apply the registered unlock formula to an observed spend.

    Observed. There is no testnet, so nothing calls this with a real number yet,
    and the signature takes an integer of $FLOP actually spent rather than an
    estimate -- `docs/FLOP_DATA_MODEL` and the directive both say never to
    calculate spend from a guess.
    """
    ratio = unlock_ratio(registry)
    if ratio is None or spend < 0:
        return None
    rule = registry.get(UNLOCK_RULE_ID)
    per_ratio = 1
    if rule is not None and rule.formula is not None:
        candidate = rule.formula.get("unlockedPerRatio")
        if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0:
            per_ratio = candidate
    return (spend // ratio) * per_ratio


def rules_for_phase(registry: FlopRuleRegistry, phases: Iterable[str]) -> tuple[EconomicRule, ...]:
    """The rules that apply to any of these phases, plus the ones that always do."""
    wanted = set(phases) | {"any"}
    return tuple(rule for rule in registry.rules if rule.effective_network_phase in wanted)


__all__ = [
    "RULE_REGISTRY_FILE",
    "UNLOCK_RULE_ID",
    "FlopRuleRegistry",
    "Freshness",
    "RuleFreshness",
    "rules_for_phase",
    "unlock_ratio",
    "unlocked_from_spend",
]
