# FLOP conformance data

Five data files and this note. Everything the FLOP layer treats as a fact about
someone else's project lives here, as data, so that changing what FLOP says is a
diff in this directory rather than an edit spread across the code.

| File | What it is | May the code assume it? |
|---|---|---|
| `official-sources.json` | One read-only snapshot of each official source: URL, HTTP status, byte length, content hash, version hint | Yes — it records what was observed, not what is true |
| `rule-registry.json` | Every FLOP economic rule, each quoting the official text it came from | Only through `rules.py`, and only with its status attached |
| `ui-tokens.json` | The design tokens, each carrying its provenance, plus every difference from the supplied baseline | Yes |
| `public-evidence.json` | Real public contributions by the subject DID | Yes, at `partially-verified` and no higher |
| `mock-activity.json` | Synthetic data for the UI, copied unchanged from the directive | Only while it is labelled `SYNTHETIC MOCK DATA` |

## The rules these files exist to enforce

**No rule is hard-coded.** The 3-to-1 unlock ratio is a `formula` object in
`rule-registry.json`, not a `3` in a Python file. A provisional figure in a draft
should be changeable by editing the record of the draft.

**A rule knows how old it is.** Each rule carries the `sha256` of the source
document as it was when the rule was written down. `rules.py` compares that hash
against the current snapshot; a mismatch is reported as `RULE UPDATED` and the
stale rule is never quietly served as current.

**Absence is recorded, not filled in.** Seven things the official sources do not
say — the testnet endpoint, the faucet procedure, the inference API, its pricing,
the network identifier, the signing scheme, the Yellow Paper — are registered
with the statement `UNKNOWN_FROM_OFFICIAL_SPEC` and the status `unknown`. They
are entries so that a screen can show them as unanswered; a missing entry would
look like a question nobody asked.

**Bodies are not copied here.** `official-sources.json` records the hash and size
of each source and none of its text. Comparing a later fetch needs the hash;
redistributing someone else's document needs a reason this project does not have.

**Real and synthetic never mix.** `public-evidence.json` sets
`_meta.synthetic: false`, `mock-activity.json` sets it to `true`, and every
record that reaches the console carries which one it came from. A test fails if a
synthetic record loses that flag.

## Network phase at the time of the snapshot

`PRE_TESTNET`. No official testnet endpoint exists, and no repository in the
FLOP Labs organisation publishes one. The console therefore has no executable
endpoint to offer, and it says so rather than showing `0 FLOP spent`.

## Not affiliated

Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs. Nothing here is an eligibility claim, and evidence coverage is not an
airdrop score.
