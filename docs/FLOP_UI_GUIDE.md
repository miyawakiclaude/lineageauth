# FLOP UI guide

How the FLOP Console looks, why it looks that way, and which of it came from
FLOP's published design system rather than from this project. `apps/flop/`,
`conformance/flop/ui-tokens.json`, `scripts/generate_flop_tokens.py`.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** The Console uses the published design language as an ecosystem
visual language. It does not clone the website, draws no logo and no mascot,
and never says or implies that it is FLOP software.

## Three sources, in order

1. `https://flop.finance/design.md` (front matter `version: alpha`, "Mascot
   V3.0 design system"), sha256 `476fe27b0cebf5fe…`, fetched
   2026-09-03T04:25:46Z. The authority for every colour, radius, spacing step
   and type size.
2. `https://flop.finance/brand/`, sha256 `5211800919428e2a…`, the same fetch.
   The six published swatches.
3. `flop_ui_tokens.json`, supplied with the console directive. The baseline.
   Wherever it disagrees with `design.md`, `design.md` wins, and the
   difference is recorded in `ui-tokens.json#diffFromBaseline`.

The judgement behind the order: the directive itself said to read the
official design system before implementing, and a token file written before
that reading is a guess about it.

## The pipeline: no colour is typed by hand

```text
conformance/flop/ui-tokens.json     every value with its provenance (design.md | brand | app)
        |  scripts/generate_flop_tokens.py   deterministic, LF, no network
        v
apps/flop/tokens.css                GENERATED -- custom properties, --flop-*
        |  apps/flop/app.css        references var(--flop-*) only
        v
apps/flop/index.html + app.js       no inline style, no inline script
```

`tests/test_flop_ui.py` regenerates `tokens.css` and fails if it differs from
the checked-in file; `tests/test_flop_a11y.py` fails if any `color:`
declaration in `app.css` is a literal instead of a token, or names a token
that is not text-safe on its surface. A hand-edited hex value therefore has no
place to hide.

## Token reconciliation table

Baseline = `flop_ui_tokens.json`. Official = `design.md` / `brand`. The
"adopted" column is what `ui-tokens.json` carries.

| Item | Baseline | Official | Adopted | Provenance |
|---|---|---|---|---|
| Six swatches | Base `#0A1128`, Grey `#5C6670`, FLOP Blue `#0466C8`, Accent `#00B4D8`, Electric Green `#32D74B`, Ice White `#F5F7FA` | identical | identical | brand |
| Dark background | `#0A1128` | `#0A1128` | `#0A1128` | design.md |
| Dark surface | `#111B36` | `#151D32` | **`#151D32`** | design.md |
| Dark surface raised | `#162241` | `surface-light` `#232A3E` (one raised tone, used for lift and dividers) | **`#232A3E`** | design.md |
| Dark border | `#284164` | `#232A3E` (border equals surface-light) | **`#232A3E`** | design.md |
| Dark text primary | Ice White | Ice White, 17.4:1 on Base | Ice White | design.md |
| Dark text secondary | `#D7DEE8` | `text-secondary` `#A1A7AE`, 7.7:1 on Base | **`#A1A7AE`** | design.md |
| Primary / link | `#00B4D8` | `#00B4D8`, 7.6:1 on Base | `#00B4D8` | design.md |
| Primary hover | none | `#3DC5E0` | **`#3DC5E0`** | design.md |
| Error | none | `#FF453A`, operational failure only, always with an icon or a text label | **`#FF453A`** | design.md |
| Warning / caution | none | FLOP Blue fill with Ice White text; blue *text* on Base is forbidden | **fill `#0466C8` + text `#F5F7FA`** | design.md |
| Light background | Ice White | Ice White | Ice White | design.md |
| Light surface | `#FFFFFF` | `surface-alt` `#FFFFFF`, lifted by a Mist border rather than by contrast | `#FFFFFF` | design.md |
| Light surface raised | `#EEF3F8` | no third light tone | **removed** | design.md |
| Light border | `#CBD5E1` | `border-alt` Mist `#D9DDE1` | **`#D9DDE1`** | design.md |
| Light link | `#0466C8` | `#0466C8`, 5.2:1 on Ice | `#0466C8` | design.md |
| Radius | 8 / 12 / 16 / 999 | none 0 / sm 2 / md 4 / lg 8 / full 9999; button, card, input = md; hero = lg; badge = full | **0 / 2 / 4 / 8 / 9999** | design.md |
| Spacing | 4 / 8 / 16 / 24 / 32 / 48 | 4 / 8 / 16 / 24 / 32, "don't introduce arbitrary spacing values" | **48 removed** | design.md |
| Typography | none | Space Mono (h1 32/700, h2 24/700, h3 18/700, label 12/400, code 13/400) + Inter (body-md 14, body-sm 12) | **the scale, as fallback stacks** | design.md |
| Chart series | none | `#00B4D8` / `#32D74B` / `#0466C8` / `#A1A7AE`; series 3 and 4 fill only on Base | **adopted** | design.md |
| Gradients | false | forbidden | false | design.md |
| Drop shadows | — | forbidden; depth is tonal layers Base → surface → surface-light | **false** | design.md |
| Logo, mascot | — | supplied files only, never redrawn | **not used at all** | — |
| Layout: sidebar 240, max width 1440, mobile 768 | present | not published | kept | app |

Contrast ratios `design.md` publishes are carried in `ui-tokens.json#contrast`
with a `textSafe` flag per pair, and `tests/test_flop_a11y.py` recomputes each
one from the hex values (tolerance 0.1) and checks the AA boundary in both
directions: every pair marked text-safe clears 4.5:1, every pair marked unsafe
falls short of it. The one published figure that recomputation disagrees with
is the caution pair (published 5.6:1, recomputed 5.2:1); both clear AA, and
the token records both numbers rather than picking one.

## Items replaced by the official value

The list, so a reviewer of the baseline can see what moved and why:

1. Dark `surface` `#111B36` → `#151D32`.
2. Dark `surfaceRaised` `#162241` → `#232A3E`, and dark `border` `#284164` →
   `#232A3E`. `design.md` has one raised tone and uses it for both.
3. Dark `textMuted` `#D7DEE8` → `#A1A7AE`. The baseline's muted text was
   nearly primary text; the official secondary is a distinct, still-AAA tone.
4. `primaryHover`, `error`, `warningFill`/`warningText` added; the baseline had
   no hover, error or caution token, and `design.md` publishes all three with
   usage rules.
5. Light `surfaceRaised` `#EEF3F8` removed; light `border` `#CBD5E1` →
   `#D9DDE1`.
6. Radius scale replaced. `md` 4 px is the default for button, card and input.
7. Spacing `2xl` 48 removed.
8. Typography scale added. **No web font is loaded**: the page's CSP sets
   `font-src 'none'`, the project runs at ¥0, and no request leaves the page.
   `"Space Mono", ui-monospace, Menlo, Consolas, monospace` and
   `Inter, system-ui, "Segoe UI", sans-serif` name the official families
   first so a viewer who has them sees them.
9. Chart series and the no-drop-shadow rule added.

Kept from the baseline, marked `provenance: app`: the three layout numbers,
because `design.md` does not publish a layout and the Console needs one.

## Two rules that follow from the palette

**FLOP Blue and Grey are never body text on Base.** 3.3:1 and 3.2:1. Blue is a
fill (buttons, the caution treatment) and Grey is not used as text in the dark
theme at all; the secondary text tone is `#A1A7AE`. On Ice, Cyan (2.3:1) and
Electric Green (1.8:1) are fills only. `tests/test_flop_a11y.py` enforces this
against every `color:` declaration in `app.css`.

**Colour never carries meaning alone.** Every badge is a text label; every
alert level is a word; the synthetic marker is the words `SYNTHETIC MOCK
DATA`. A pair without a published contrast ratio — red on Ice, for instance —
is limited to borders and icons, so `.badge-synthetic` is a border-only
treatment rather than the red-on-Ice text the first draft used. That is half a
step more conservative than `design.md` requires, taken because there was no
published number to lean on.

## Themes

Dark is the default, tokens on `:root`. Light is an explicit choice:
`data-theme="light"` on the root element redefines the eight light tokens and
nothing else. The two are never mixed on one screen — `design.md` says so and
the generator's output has no third block in which they could be. The choice
is stored under `flop-theme` in `localStorage`, and the Settings screen's
reset button clears it. No secret ever goes near `localStorage`; the only
other keys are the last lineage id and DID typed into the subject form.

## Components

The console directive's six components map onto these classes:

| Component | Class | Text label | Rule |
|---|---|---|---|
| `SourceBadge` | `.badge-source-{official,verified-third-party,community,unknown,suspicious}` | the class | decided by origin, never by wording (`docs/FLOP_SAFETY.md`); `official` is the only one with the accent treatment |
| `EvidenceBadge` | `.badge-evidence-{self-claimed,cryptographically-linked,evidence-supported,third-party-attested}` | the level | four levels, never a scale |
| `ActivityCard` | `.card`, `.card-row` | title, timestamp, category, source badge, evidence badge, artifact hash, verification state, expandable detail | opens the Evidence screen for one record |
| `SecurityAlert` | `.alert-{info,caution,high_risk,blocked}`, `.badge-safety-*` | `SAFE TO REVIEW`, `CAUTION`, `HIGH RISK`, `BLOCKED` | the display string comes from the API, never retyped in the page |
| `RuleSource` | rendered in the Sources screen's rule table; `.badge-rule-updated` | status, version, date, `fetchedAt`, `RULE UPDATED` | a stale rule is shown as stale, never as current |
| `EmptyFutureState` | `.empty-future` | the reason from the API, e.g. `Waiting for official FLOP Testnet` | never a zero that implies the feature is live |
| synthetic marker | `.badge-synthetic` | `SYNTHETIC MOCK DATA` | border-only; appears wherever a synthetic record does |
| synthetic header strip | `.notice-synthetic` | `SYNTHETIC MOCK DATA - this console is showing synthetic records mixed with real ones.` | shown while `status.syntheticDataEnabled`; in the notice block, so no screen change removes it |

Every string a badge shows is the server's constant, drawn by `textContent`.
The page hard-codes no badge text, no banner and no disclaimer except the two
that are markup (`Testnet tokens have no assumed monetary value.` and the
footer's affiliation line); the header notices are filled from
`GET /v1/flop/status` so the page cannot retype them wrongly
(`test_the_seed_warning_is_rendered_from_the_api_not_retyped_wrong`).

## Navigation and layout

Desktop (≥ 768 px): a 240 px left navigation with ten entries in the
directive's order — Overview, Activity, Evidence, Technocore, tclk, Inference,
Passport, Safety, Sources, Settings. Mobile (< 768 px): a bottom navigation
with Overview, Activity, Passport, Safety and **More**, where More opens
Settings and the side navigation carries the rest. Both `<nav>` elements have
an `aria-label`; every entry is a `<button>`, not a `div` with a click handler.

Routing is a hash router: `#/activity`, `#/passport/<did>?lineage=…`. The
server also answers `/flop/passport/{did}` with the same `index.html`, so a
pasted passport link survives a full page load. No `SOON` badge is rendered
today; a `.soon` class exists for the day a live entry is added beside a
disabled one, and the Inference screen carries its waiting state as an
`EmptyFutureState` instead.

The header shows the phase badge (`PRE-TESTNET` / `TESTNET` / `MAINNET`,
collapsed from the six phases by `NetworkPhase.badge`), data freshness (the
snapshot's `fetchedAt`), a security status line, **Sync (read-only)** — which
re-fetches the local API and nothing else — and the theme toggle. Beneath it,
three persistent notices: the affiliation line, the seed-phrase warning, and
the testnet-value line. The footer repeats the affiliation line and explains
why the page renders every value as text.

## The approval in the walkthrough

The page holds no keys, so the Inference form carries an optional
`Approval receipt` textarea: a signed `approval.receipt` envelope, pasted as
JSON, bound to the request hash the security review shows. The run response
says where the approval came from (`pasted`, `demo-approver`, or `none`) and
the page prints that line and the accompanying note next to the outcome. A demo
server signs one with its public test key so the walkthrough completes; a
production mount never does, and the run stops at the approval step with the
instruction to paste one.

## Copy rules the page is tested against

- The forbidden vocabulary (`airdrop score`, `eligibility score`, `you will
  receive`, `guaranteed eligible`, `official airdrop rank`, `estimated
  allocation`) appears nowhere in the HTML or the script
  (`test_no_forbidden_airdrop_vocabulary_is_hard_coded`).
- The coverage label is shown as the API sends it — `Evidence coverage — not
  an airdrop score` — and never as a synonym for a score.
- `Not yet available` is the Inference hero card's value in `PRE_TESTNET`,
  not `0`.
- Every disclosure the directives require is present:
  `test_the_persistent_notices_appear` checks the affiliation line, the
  seed-phrase warning and the testnet-value line.

## Accessibility

- A skip link to `#main`; a polite live region announcing screen changes; no
  `outline: none` anywhere; every control a native element with a label.
- WCAG AA for normal text, computed rather than asserted:
  `tests/test_flop_a11y.py`, nine tests.
- Meaning is never colour alone (above).
- The viewport meta allows zoom; nothing is fixed-size except the sidebar
  width, which collapses below 768 px.

## Security properties of the page

The same discipline as the Explorer (`apps/explorer/`, D-089's "render, never
interpret"), pinned by `tests/test_flop_ui.py`:

- Text reaches the DOM only through `textContent`; `innerHTML`, `outerHTML`,
  `insertAdjacentHTML`, `document.write` and `eval` are absent from the script
  (`test_the_script_uses_no_markup_sink`).
- No inline script or style; the CSP is `default-src 'none'; script-src
  'self'; style-src 'self'; connect-src 'self'; img-src 'none'; font-src
  'none'; base-uri 'none'`, sent as a header by the server and repeated as a
  meta tag for a static host.
- Every request is same-origin; no asset is loaded from another origin.
- Source URLs on the Sources screen are shown as text and are **not links**.
  The page never generates an `href` from data, so there is no auto-open path
  from a room message to a browser tab.
- No CORS header is sent, and the local API refuses a `POST` whose `Origin`
  header is not its own.

## Changing the design

Edit `conformance/flop/ui-tokens.json` with the provenance of the new value,
run `py -3 -m uv run python scripts/generate_flop_tokens.py`, and let
`tests/test_flop_ui.py` and `tests/test_flop_a11y.py` say whether the result
is consistent and readable. If `design.md` changes, re-snapshot it into
`official-sources.json` first; the token file's `primarySourceHash` is the
record of which version it was reconciled against.

A screen that counts synthetic records labels them. Activity and Passport
labelled each record and Overview did not, which put the unlabelled number on
the first screen anybody sees: `/coverage` and `/recommendations` now carry
`containsSyntheticData`, Overview draws a badge when either says so, and the
header carries a strip for as long as demo mode is on.

The Safety form offers no `official` provenance and no phase selector. Both of
those inputs make the scanner quieter, official is decided by origin, and the
phase is what the service observed -- see `docs/FLOP_SAFETY.md`.
