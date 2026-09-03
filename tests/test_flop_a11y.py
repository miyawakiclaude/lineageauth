"""WCAG contrast for the FLOP Console's palette, computed from first principles.

`conformance/flop/ui-tokens.json#contrast` records the ratio `design.md`
publishes for each foreground/background pair it names, and whether the pair
is `textSafe` -- fit to carry body text at WCAG AA (4.5:1). This file does not
trust either claim: it recomputes relative luminance and contrast from the raw
hex values using the same formula the W3C publishes, and fails if its own
number disagrees with the published one by more than a rounding tolerance, or
if a pair the file calls text-safe fails to clear AA.

The other half of the file is the rule `design.md` states in prose --
`doNotUseFlopBlueAsBodyTextOnBase`, `doNotUseGreyAsBodyTextOnBase` -- checked
the only way a prose rule can be: by reading `app.css` and confirming neither
raw brand colour is ever assigned to a `color:` declaration.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOKENS_JSON = REPO / "conformance" / "flop" / "ui-tokens.json"
APP_CSS = REPO / "apps" / "flop" / "app.css"
TOKENS_CSS = REPO / "apps" / "flop" / "tokens.css"

# How far this session's recomputation may drift from the value design.md
# publishes before it counts as a disagreement worth reporting, rather than
# rounding in the source document.
TOLERANCE = 0.1

WCAG_AA_NORMAL_TEXT = 4.5


def _channel(value: float) -> float:
    return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4


def _luminance(hex_colour: str) -> float:
    raw = hex_colour.lstrip("#")
    r, g, b = (_channel(int(raw[i : i + 2], 16) / 255) for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(a: str, b: str) -> float:
    high, low = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _tokens() -> dict:
    return json.loads(TOKENS_JSON.read_text(encoding="utf-8"))


class TestPublishedContrastRecomputes:
    def test_every_pair_on_base_matches_the_published_ratio(self) -> None:
        doc = _tokens()
        failures = []
        for pair in doc["contrast"]["onBase"]:
            ratio = _contrast(pair["foreground"], pair["background"])
            if abs(ratio - pair["published"]) > TOLERANCE:
                failures.append(
                    f"{pair['id']}: recomputed {ratio:.2f}:1, design.md publishes "
                    f"{pair['published']}:1"
                )
        assert not failures, "\n".join(failures)

    def test_every_pair_on_ice_matches_the_published_ratio(self) -> None:
        doc = _tokens()
        failures = []
        for pair in doc["contrast"]["onIce"]:
            ratio = _contrast(pair["foreground"], pair["background"])
            if abs(ratio - pair["published"]) > TOLERANCE:
                failures.append(
                    f"{pair['id']}: recomputed {ratio:.2f}:1, design.md publishes "
                    f"{pair['published']}:1"
                )
        assert not failures, "\n".join(failures)

    def test_every_pair_marked_text_safe_actually_clears_aa(self) -> None:
        doc = _tokens()
        failures = []
        for surface in ("onBase", "onIce"):
            for pair in doc["contrast"][surface]:
                ratio = _contrast(pair["foreground"], pair["background"])
                clears = ratio >= WCAG_AA_NORMAL_TEXT
                if clears != pair["textSafe"]:
                    failures.append(
                        f"{surface}/{pair['id']}: {ratio:.2f}:1, textSafe={pair['textSafe']} "
                        f"but AA requires >= {WCAG_AA_NORMAL_TEXT}"
                    )
        assert not failures, "\n".join(failures)

    def test_the_boundary_cases_are_exercised(self) -> None:
        """Blue and grey on Base sit just under AA -- the whole reason they are fill-only."""
        doc = _tokens()
        by_id = {pair["id"]: pair for pair in doc["contrast"]["onBase"]}
        for pair_id in ("blue-on-base", "grey-on-base"):
            pair = by_id[pair_id]
            assert pair["textSafe"] is False
            ratio = _contrast(pair["foreground"], pair["background"])
            assert ratio < WCAG_AA_NORMAL_TEXT, f"{pair_id} recomputed to {ratio:.2f}:1"


class TestBaseNeverCarriesBlueOrGreyBodyText:
    """`design.md`: `doNotUseFlopBlueAsBodyTextOnBase` / `doNotUseGreyAsBodyTextOnBase`.

    `--flop-secondary` is the raw FLOP Blue (3.3:1 on Base); the raw brand grey
    has no dark-theme text token at all -- only its 7.7:1 derived
    `--flop-text-secondary` does. Neither the palette variables nor the raw
    hex may appear on the text-colour side of a rule.
    """

    UNSAFE_ON_BASE = (
        "flop-secondary",
        "flop-palette-blue",
        "flop-palette-grey",
        "flop-warning-fill",  # the same blue, under another name
    )

    @staticmethod
    def _color_declarations() -> list[str]:
        css = re.sub(r"/\*.*?\*/", "", APP_CSS.read_text(encoding="utf-8"), flags=re.S)
        return re.findall(r"(?<![-\w])color:\s*([^;]+);", css)

    def test_no_declaration_uses_an_unsafe_token_as_text_colour(self) -> None:
        failures = []
        for value in self._color_declarations():
            match = re.fullmatch(r"var\(--([a-z0-9-]+)\)", value.strip())
            if not match:
                continue
            if match.group(1) in self.UNSAFE_ON_BASE:
                failures.append(value)
        assert not failures, f"text colour set to an unsafe-on-Base token: {failures}"

    def test_every_text_colour_declaration_is_a_token_not_a_literal(self) -> None:
        literals = [
            value
            for value in self._color_declarations()
            if re.fullmatch(r"#[0-9a-fA-F]{3,8}|rgba?\([^)]*\)", value.strip())
        ]
        assert not literals, f"text colours that bypass tokens.css: {literals}"

    def test_error_red_is_never_the_text_colour(self) -> None:
        """design.md publishes red-on-Base (5.5:1) but no red-on-Ice pair.

        Without a published ratio for the light theme, `--flop-error` stays a
        border/icon colour only -- exactly the "always with an icon or a text
        label" rule design.md states for it -- and never the text colour
        itself, on either theme.
        """
        failures = [
            value for value in self._color_declarations() if value.strip() == "var(--flop-error)"
        ]
        assert not failures, "flop-error used as a text colour with no published Ice ratio"

    def test_the_caution_fill_pairs_blue_with_ice_text_not_blue_text(self) -> None:
        """The one place FLOP Blue legitimately appears is as a filled background."""
        css = APP_CSS.read_text(encoding="utf-8")
        rule = re.search(r"\.badge-safety-caution\s*\{([^}]*)\}", css)
        assert rule, "the caution badge rule is gone"
        body = rule.group(1)
        assert "background: var(--flop-warning-fill)" in body
        assert "color: var(--flop-warning-text)" in body


class TestTokensCssHasNoLiteralColour:
    def test_generated_tokens_are_all_hex_or_references(self) -> None:
        """Sanity check on the generator's own output, independent of the JSON round-trip test."""
        css = TOKENS_CSS.read_text(encoding="utf-8")
        for line in css.splitlines():
            match = re.match(r"\s*--flop-([a-z0-9-]+):\s*(.+);", line)
            if not match:
                continue
            name, value = match.group(1), match.group(2).strip()
            if name.startswith("font-") or name.endswith("-family"):
                continue  # font stacks, not colours
            if value.startswith("var(") or value.startswith('"'):
                continue
            assert re.fullmatch(r"#[0-9a-fA-F]{6}|\d+(px)?|[\d.]+", value), (
                f"unexpected token value shape: {line!r}"
            )
