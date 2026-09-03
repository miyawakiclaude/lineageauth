# FLOP safety shield

What the FLOP layer does with text it did not write, URLs it did not choose,
and claims it cannot check. `packages/py/lineageauth/flop/{sources,safety}.py`,
the `POST /v1/flop/safety/scan` route, and the Safety screen.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** The persistent notice on every screen: *FLOP token may not yet
exist on the current network phase. Never enter a seed phrase or private key to
claim an airdrop.*

## The one property

A scan is an observation about a string. It authorises nothing. `SafetyFinding`
carries `executed`, and the field exists to be permanently `false` — the
constructor raises if it is ever set (`docs/FLOP_DATA_MODEL.md`). `scan_report`
emits `executedAnything: false` and `followedAnyUrl: false` on every report.
No URL the scanner sees is fetched, opened or resolved.

A clean scan is not permission to act, either. The executor runs the same
scanner at prepare time and refuses `BLOCKED` content, but a clean result only
lets the request proceed to the next of nine checks
(`test_acceptance_i_a_clean_scan_is_still_not_permission_to_execute`).

## Source classification — by origin, never by wording

`flop.sources.classify_source(url)` takes a URL and nothing else. A nickname, a
room topic, a display name, the word "official" in a message, a badge somebody
pasted: none of these are inputs, so none can move the answer.

| Origin | Class |
|---|---|
| `https://flop.finance/…` | `official` |
| `https://technocore.chat/…` | `official` (the coordination layer's own documents) |
| `https://github.com/flop-labs/…`, `https://api.github.com/repos/flop-labs/…` | `official` |
| any other `github.com` path | `community` |
| an unlisted origin | `unknown` |
| a lookalike | `suspicious` |

Fail-closed rules the decision applies:

- `http://` where the allowlist says `https://` is a downgrade — `suspicious`.
- Userinfo in the URL (`https://flop.finance@evil.example/`) — `suspicious`.
- A path that does not land where it reads — `suspicious`. A browser removes
  dot segments before it sends, so `https://github.com/flop-labs/../evil-org/x`
  is a request for `github.com/evil-org/x` while still reading as FLOP Labs;
  `%2e%2e` hides the same trick from a string comparison and `%2f` hides where
  the segments begin. These are not normalised and re-tested: a URL that needs
  tidying before it can be classified was written to be misread, and the honest
  verdict is `suspicious` rather than whatever the tidy version says
  (`dot-segment-path`, `encoded-separator-path`).
- Punycode or non-ASCII in the host, a non-standard port — `suspicious`.
- Confusable spellings: `fl0p.finance`, `flop-finance.com`,
  `flop.finance.x.example` — `suspicious`. The comparison folds `0→o`, `1→l`,
  `3→e`, `5→s` and strips dots and hyphens before looking for the official
  names inside a foreign host.
- A subdomain of an official host that the snapshot has not observed —
  `unknown`, not `official`. The allowlist is the observed set.

Every decision is a `SourceDecision` with a `rule_id` and a reason, so the
Sources screen can say *why* a badge is or is not shown. Acceptance test 1: a
community message claiming an official task gets no official badge, in the
classifier (`tests/test_flop_sources.py`) and in the scanner
(`tests/test_flop_safety.py`).

## The scanner

`safety.scan_text(text, *, source_class, network_phase)` returns findings; the
text is capped at 64,000 characters and the excerpt at 120. Twelve rules, four
URL checks, two obfuscation checks and two suppression notices:

| pattern id | level | fires on |
|---|---|---|
| `secret.seed-phrase` | BLOCKED | seed phrase, mnemonic, recovery phrase, 12/24 words |
| `secret.private-key` | BLOCKED | private key, secret key, keystore, export/paste your key |
| `secret.wallet-connect` | BLOCKED | connect your wallet, WalletConnect, link your wallet |
| `secret.sign-transaction` | BLOCKED | sign this transaction / message to claim, approve this transaction |
| `injection.override` | HIGH_RISK | ignore previous instructions, override your rules |
| `injection.role-change` | HIGH_RISK | you are now …, new instructions:, system prompt, act as admin |
| `injection.shell` | HIGH_RISK | `curl … \| sh`, `chmod +x`, `iex(`, Invoke-Expression |
| `injection.run-script` | HIGH_RISK | run this script/installer, `npm install -g`, `pip install http…` |
| `network.buy-or-mint` | HIGH_RISK | buy/mint/purchase $FLOP, presale, token sale |
| `network.claim` | HIGH_RISK | claim your FLOP/airdrop/token, claim now |
| `network.live` | HIGH_RISK | mainnet/testnet/token is live, now trading |
| `authority.fake-official` | HIGH_RISK | I am an admin/moderator/FLOP Labs, verified by FLOP Labs |
| `url.dangerous-scheme` | BLOCKED | `javascript:`, `data:`, `file:` |
| `url.technocore-get-write` | HIGH_RISK | a Technocore URL that `adapters.technocore.routes.classify` says writes on GET |
| `url.technocore-unclassified` | CAUTION | a Technocore URL the route table does not know |
| `url.lookalike` | HIGH_RISK | a `suspicious` origin |
| `url.unknown-origin` | CAUTION | an `unknown` origin |
| `obfuscation.invisible-characters` | CAUTION | zero-width and bidi control characters |
| `obfuscation.encoded-blob` | CAUTION | a long base64-looking run |

Two adjustments after matching:

- A `network.*` finding is a claim about the network's status. While the phase
  is below the one the claim needs, the reason is prefixed `NOT VERIFIED BY
  CURRENT OFFICIAL FLOP SOURCES` — "mainnet is live" is not verified while the
  registry says `PRE_TESTNET`.
- A `secret.*` or `authority.*` finding in a *signed* message is not softened
  by the signature. A valid signature proves the key signed it; it does not
  make the request safe. Acceptance test 2: a signed message asking to connect
  a wallet is `BLOCKED`.

`overall_level` is the maximum rank of the findings, and the Safety screen's
`SecurityAlert` renders it with the display string (`SAFE TO REVIEW`,
`CAUTION`, `HIGH RISK`, `BLOCKED`) as a text label, never as colour alone.

## Technocore GET-write URLs

Technocore's route table has GETs that write (`docs/18_TECHNOCORE.md`, D-047).
The scanner delegates every `technocore.chat` URL to
`adapters.technocore.routes.classify` and reports a write-on-GET as
`HIGH_RISK`. This is the same code path the Technocore adapter uses before it
reads anything, so the two cannot disagree about which URLs are dangerous.

## Prompt injection into the executor

The scanner is one of two defences. The other is structural
(`docs/FLOP_TESTNET_EXECUTOR.md`): a prompt goes into the `workload` subtree of
a prepared request and nothing else. `build_plan` has no parameter that could
carry it; `assemble_request` copies it field by field from a fixed list; a
workload that says `{"maxSpend": "999999", "endpoint": "https://evil…"}`
produces a request whose *workload* says that and whose *control* does not.
Tests H and I in `tests/test_flop_testnet_executor.py` and
`tests/test_flop_testnet_prepare_approve.py` pin both halves.

## Forbidden vocabulary

`FORBIDDEN_VOCABULARY` in `flop.model`: `airdrop score`, `eligibility score`,
`you will receive`, `guaranteed eligible`, `official airdrop rank`,
`estimated allocation`. `forbidden_vocabulary_in()` is run over every API
response, every CLI output, the passport and the page source, in tests. The
only permitted form is the label that disowns it: *Evidence coverage — not an
airdrop score*.

The recommendation engine cannot emit spam advice — no "post more", no "join
more rooms", no volume target — and a test fixes the banned words there too.

## The scan endpoint

`POST /v1/flop/safety/scan` is the one non-GET route the Console backend had
before the testnet routes were added, and the fixed set of POSTs is pinned by
`tests/test_flop_api_console.py`. Its body is `extra="forbid"`, capped at
32,000 characters; a request carrying an `Origin` header that is not this
server's own origin is refused with 403 (the same CSRF rule the tclk routes
use), and a request arriving under a `Host` this router was not built for is
refused with 421 before anything is read. It never stores what it scans.

Neither parameter that softens the scanner comes off the request. There is no
`networkPhase` field (422 if one is sent): the phase is what this service
observed, and a body that could name its own would turn "the mainnet is live"
from a contradiction into nothing. `sourceClass: "official"` is refused with
400 for the same reason in the other direction — official is an origin, and
asserting it would switch off `authority.fake-official` on text claiming to
speak for FLOP Labs. The page's provenance dropdown does not offer it.

Suppression is never silence. When a rule family is not raised — a phase where
a live-token claim is not a contradiction, or an official class supplied
in-process — `scan_text` emits one `CAUTION` finding saying what matched and
why it was softened (`network.claim-not-contradicted-by-phase`,
`authority.check-skipped-for-asserted-official`). A caller that asks for a
friendlier reading gets different wording, never an empty scan.

## Anti-wash signals

`flop.wash.detect_wash_signals` looks for five patterns:
`wash.duplicate-artifact-hash` (the same bytes submitted repeatedly),
`wash.repeated-title`, `wash.self-dealing` (the subject is its own
counterparty), `wash.same-operator-counterparty` (two DIDs a fleet disclosure
ties to one operator, `fleet.resolve_fleets`, D-105), and
`wash.rapid-churn-without-artifact` (five or more records inside one hour with
nothing to show). Every signal carries the fixed label `Possible low-value /
circular activity` and `isAccusation: false`. The wording says what is hard to distinguish, not
what somebody did, because this tool cannot know.

## What this layer does not do

- It does not decide whether a source is *trustworthy*. It decides whether the
  origin is one the snapshot lists.
- It does not block a person from reading a community message. It labels.
- It does not scan the user's own signed events for injection; those are
  verified, not read as instructions.
- It does not report a signed message as safe because it verified. See the
  second adjustment above.
