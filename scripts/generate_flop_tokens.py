"""Generate `apps/flop/tokens.css` from `conformance/flop/ui-tokens.json`.

The FLOP Console's colours, radii, spacing and type scale are not typed by
hand into a stylesheet: they are read from the token file that records where
each value came from (`design.md`, `brand`, or this application), and this
script is the one place that turns that record into CSS custom properties.
`tests/test_flop_ui.py` regenerates the file and asserts it matches what is
checked in, so a hand edit to either file is caught rather than silently
drifting from the other.

Deterministic on purpose: the same `ui-tokens.json` always produces the same
bytes, in the same order, with a trailing newline and `\n` line endings (the
project's Windows checkout still commits LF). No network access, no keys, no
randomness.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

_CAMEL = re.compile(r"(?<!^)(?=[A-Z])")


def _kebab(name: str) -> str:
    """camelCase -> kebab-case, so every custom property reads the same way."""
    return _CAMEL.sub("-", name).lower()


REPO = Path(__file__).resolve().parents[1]
TOKENS_JSON = REPO / "conformance" / "flop" / "ui-tokens.json"
TOKENS_CSS = REPO / "apps" / "flop" / "tokens.css"

HEADER = """/* GENERATED FILE -- do not edit by hand.
 *
 * Produced by `py -3 -m uv run python scripts/generate_flop_tokens.py` from
 * `conformance/flop/ui-tokens.json`, which records where every value in this
 * file came from. To change a colour, a radius, a spacing step or a type
 * size, change the token file and regenerate; `tests/test_flop_ui.py` fails
 * the build if this file and that regeneration ever disagree.
 */

"""


def _num(value: Any) -> str:
    """An integer stays an integer; anything else is left as JSON would print it."""
    if isinstance(value, int):
        return f"{value}px" if value != 0 else "0"
    return str(value)


def _line(name: str, value: str) -> str:
    return f"  --flop-{name}: {value};\n"


def generate() -> str:
    doc = json.loads(TOKENS_JSON.read_text(encoding="utf-8"))
    palette = doc["palette"]
    dark = doc["theme"]["dark"]
    light = doc["theme"]["light"]
    chart = doc["chart"]
    typography = doc["typography"]
    radius = doc["radius"]
    spacing = doc["spacing"]
    layout = doc["layout"]

    out: list[str] = [HEADER, ":root {\n"]

    out.append("  /* palette (conformance/flop/ui-tokens.json#palette) */\n")
    for name, entry in palette.items():
        out.append(_line(f"palette-{_kebab(name)}", entry["value"]))

    out.append("\n  /* dark theme -- the default (conformance/flop/ui-tokens.json#theme.dark) */\n")
    for name, entry in dark.items():
        out.append(_line(_kebab(name), entry["value"]))

    out.append("\n  /* chart series (conformance/flop/ui-tokens.json#chart) */\n")
    for name, entry in chart.items():
        out.append(_line(f"chart-{_kebab(name)}", entry["value"]))

    out.append("\n  /* typography: no web font is loaded; these are fallback stacks */\n")
    out.append(_line("font-mono", typography["monoStack"]))
    out.append(_line("font-sans", typography["sansStack"]))
    for name, scale in typography["scale"].items():
        family = "mono" if scale["family"] == "mono" else "sans"
        slug = _kebab(name)
        out.append(_line(f"text-{slug}-family", f"var(--flop-font-{family})"))
        out.append(_line(f"text-{slug}-size", _num(scale["sizePx"])))
        out.append(_line(f"text-{slug}-weight", str(scale["weight"])))
        out.append(_line(f"text-{slug}-line", str(scale["lineHeight"])))

    out.append("\n  /* radius (design.md's rounded scale) */\n")
    for name, entry in radius.items():
        out.append(_line(f"radius-{name}", _num(entry["value"])))

    out.append('\n  /* spacing -- design.md: "don\'t introduce arbitrary spacing values" */\n')
    for name, entry in spacing.items():
        out.append(_line(f"space-{name}", _num(entry["value"])))

    layout_names = {
        "desktopSidebarWidth": "sidebar-width",
        "contentMaxWidth": "content-max",
        "mobileBreakpoint": "mobile-breakpoint",
    }
    out.append("\n  /* layout -- application tokens, not published by design.md */\n")
    for name, entry in layout.items():
        out.append(_line(layout_names.get(name, _kebab(name)), _num(entry["value"])))

    out.append("}\n\n")

    out.append(
        "/* light theme: an explicit choice, never mixed with dark tokens on one screen */\n"
    )
    out.append(':root[data-theme="light"] {\n')
    for name, entry in light.items():
        out.append(_line(_kebab(name), entry["value"]))
    out.append("}\n")

    return "".join(out)


def main() -> int:
    css = generate()
    TOKENS_CSS.write_text(css, encoding="utf-8", newline="\n")
    sys.stdout.write(f"wrote {TOKENS_CSS.relative_to(REPO)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
