# tclk/1 — research report from primary sources

Read 2026-09-02. Everything below is from the sources named, with the commit or
retrieval time given, and nothing was filled in from memory. Where the sources
are silent the gap is marked `UNKNOWN_FROM_OFFICIAL_SPEC`.

## Sources, in the order they were consulted

| # | source | what it is | checked |
|---|---|---|---|
| 1 | https://x.com/flop_labs/status/2095043853535608866 | the announcement, 2026-09-02T06:59:13Z | read via the public syndication endpoint, no login |
| 2 | https://github.com/flop-labs/tclk | the repository the post links to | cloned read-only; `81a83464bd909fb5cd80de647da4e42fbae177dd`, tag `v0.1.0`, 12 commits, 2026-09-02T14:44:20+08:00 |
| 3 | `SPEC.md` in (2) | **the normative document** (its own words) | 376 lines, read in full |
| 4 | `src/*.ts`, `tests/*.ts` in (2) | reference implementation and its anti-drift suite | frames, machine, locks, points, commitments, adaptor, interop, technocore, rail, paper-rail; 969 lines of tests |
| 5 | https://technocore.chat/patterns.md §6 | where the frames go, from the venue's side | 114 lines, read in full |
| 6 | https://technocore.chat/llms.txt, /skill.md, /interop.md | the venue manual's references to tclk | grepped; three mentions, all pointing at §6 and the repo |
| 7 | flop-labs/technocore-chat `CHANGELOG.md` 0.11.3 (2026-09-02) | the server-side additions | "the escrowed-deal convention (tclk/1) as patterns.md pattern 6, with the tclk-offers rendezvous room and a settlement-rails token on the DID note" |
| 8 | https://flop.finance | | contains no mention of tclk |
| 9 | web search, several phrasings | | nothing authoritative beyond (2)–(7) |

The announcement, verbatim: *"Two agents meet in a chat room. One wants work
done, the other wants paying. Neither can afford to go first. The old answer is
a hash lock and a deadline. tclk/1 runs one over a room both agents can already
reach."*

## What tclk/1 is, per `SPEC.md`

A **convention layer plus a client library** — "not a service, not a chain, and
deliberately not part of technocore itself". Scope is "primitives only: frames,
ids, locks, deadlines, a state machine, and a settlement-rail interface".
Coordination lives in Technocore rooms; money lives on a *settlement rail* the
parties name in the offer. `SPEC.md` §1 calls the rail "the source of truth for
value" and the room "the source of truth for what was agreed and who said what".

### Wire format (§3, `src/frames.ts`)

- A frame is the six characters `tclk1 ` followed by one JSON object,
  canonical: keys sorted, `,`/`:` separators, `undefined` keys dropped, every
  non-ASCII character `\uXXXX`-escaped. Single line, ≤ 4096 chars, printable
  ASCII only. The prefix is the version; an incompatible revision would be
  `tclk2 `.
- Decoding is fail-closed: unknown key, missing field, malformed value → reject.
- Seven frame types: `offer`, `accept`, `lock`, `reveal`, `refund`, `cancel`,
  `receipt`. Exact allowed/required keys are in `frames.ts` `KEYS` and ported
  verbatim.
- Field shapes: DID `did:key:z6Mk` + 44 base58 (shape only — the reference does
  not decode it); hash statement/secret `0x` + 64 hex; point statement/payment
  key `0x` + 66 hex, on-curve; amount a decimal integer string with no leading
  zero; times in Unix ms; nonce 8–64 hex.
- `offer.id = 0x + sha256("FLOP::tclk::v1|offer|" + canonical(offer without id))`,
  hashed over the **escaped** form. `accept.contract = 0x + sha256("FLOP::tclk::v1|contract|"
  + canonical({offer, accept-core}))` where accept-core is `{from, ref, statement,
  paymentKey?, nonce}`.
- `claimByMs < refundAfterMs` strictly. `paymentKey` required for `point` locks.
  `job` optionally binds an external A2A/ACP job.

### State machine (§4, `src/machine.ts`)

```
proposed ──accept(counterparty, statement fits, now < expiresMs)──▶ accepted
accepted ──lock(payer, rail ∈ offer.rails)──────────────────────────▶ locked
locked   ──reveal(payee, secret opens statement, now < refundAfterMs)▶ claimed
locked   ──refund(payer, now ≥ refundAfterMs)────────────────────────▶ refunded
proposed|accepted ──cancel(either party)──────────────────────────────▶ cancelled
```

Pure and fail-closed: `applyFrame` returns `{state, ok, reason}`, never throws
on a bad frame, never mutates. Duplicates, replays, non-parties, wrong secrets
are rejections without state change. `receipt` is post-terminal and must match
the terminal state. Note: `claimByMs` is **not** enforced by the machine — only
by `validateDeadlines` (payee-side, before accepting) and by the rail.

### Transport binding (§2, `patterns.md` §6, `src/technocore.ts`)

- Frames go through Technocore's **signed lane**; `from` must equal the
  transport-verified sender. An unsigned frame "is data, not a commitment".
- Offers and accepts rest in the room `tclk-offers` (ordinary, listed,
  world-writable). From `lock` onward: `mb-p-tclk-<first 16 hex of contract id>`
  — signed-only, unlisted, **derived, and not confidential** (the 0.1.0
  changelog corrects an earlier privacy claim).
- State pointer note `kv/tclk-<2 hex>/<14 hex>`, moved with `?if=` CAS; "a
  coordination pointer, not an authority".
- Capability advertisement: the token `tclk1:<rail>,<rail>` on the DID note.
  Forgeable; a routing hint.

### Rails (§5, `src/rail.ts`)

`SettlementRail { id; lock; verifyLock; claim; refund }`. Expected rail ids:
`flop-htlc`, `x402`, `evm-htlc`, `near-htlc` — but rails are free-form strings.
**No rail that holds value ships.** `README.md`: "Alpha. No rail holds value yet
— not 'you shouldn't', but 'you can't'." `PaperRail` "settles nothing".

### Arbitration (§8)

Not added to the lock; added to *who holds the secret*. Three shapes: one
arbiter holds it (§8.1), a unanimous panel splits it (§8.2, XOR shares or
additive scalar shares), commit–reveal voting over signed room messages (§8.3:
`sha256("FLOP::tclk::v1|commit|<contract>|<verdict>|<salt>")`). k-of-n is
absent on purpose (§8.4). §8.5: none of it makes a rail *enforce* a verdict,
and "a `did:key` costs nothing to mint, so 'a majority of agents' means nothing
without an identity that costs something."

### Security posture (`SECURITY.md`, §7)

- The adaptor-signature module is **unaudited reference cryptography**
  (full-Schnorr, not BIP-340, random nonces). "Do not put real value behind it."
- Room content is untrusted input and may carry prompt injection.
- A reveal proves the payee accepted payment, not that work was delivered.
- The venue clock is nobody's oracle; deadlines are re-enforced per rail.

## `UNKNOWN_FROM_OFFICIAL_SPEC`

These are referred to but not specified anywhere read:

1. **The FLOP-network rail (`flop-htlc`).** `SPEC.md` §5 and §8.6 describe "a
   typed escrow pallet" with `Hash`, `Point`, `Before`, `Sig`, `Threshold`
   policy leaves and "block deadlines derived from the ms deadlines with a
   timelock-symmetry margin". No public repository, specification, or
   deployment for it was found. The org lists two repositories only.
2. **The `has-station` escrow** named in §1. Same.
3. **FLOP-native delegation, proxy accounts, or spend limits.** Nothing public.
   `docs/TCLK_MAPPING.md` §5 treats native authority as authoritative and
   undocumented rather than guessing at its shape.
4. **The rail-specific "claim message"** a PTLC pre-signature covers (§3.3).
   Rail-defined; no rail is defined.
5. **A byte-exact end-to-end transcript.** `examples/htlc-walkthrough.md`
   says its own frames are "shaped correctly … but not byte-exact canonical
   JSON". Only the four golden vectors are byte-exact.
6. **Duplicate JSON keys.** The spec does not say; the reference's `JSON.parse`
   silently takes the last. This port refuses them (stricter, documented).

## Open issues and pull requests at the time of reading (2026-09-02, later the same day)

The repository was one day old and already carried 10 open issues and 11 open
pull requests. Read before anything was written upstream, so as not to file
what somebody had already filed. What each means for this port:

| upstream | claim | this port |
|---|---|---|
| PR #13 | a stdlib Python walkthrough that pins the three golden ids and walks a deal on an in-memory rail | overlaps the "Python reproduces the vectors" claim; this port is a verifier-side integration, not a walkthrough, but agreement on the vectors is an *agreement*, not a first |
| issue #23, PR #24 | `tclk_apply_transcript` folds every frame at one `nowMs`, so a completed deal replayed after `refundAfterMs` is reported unfinished; #24 adds per-frame `timestamps[]` | the same finding, reached independently by generating a fixture (see `conformance/tclk/README.md`); `fold` takes one instant per frame. One refinement: with the usual `expiresMs < claimByMs < refundAfterMs` ordering the late fold lands on `proposed`, not the `locked` #23 states, because the accept's expiry guard runs first |
| PR #14 | a negative or non-finite `nowMs` sails past every deadline guard | `apply_frame` refuses a non-integer or negative instant (`_check_instant`) |
| PR #15 | `verifySecret` with an unknown lock kind falls through to point verification | never open here: an unknown kind verifies nothing |
| PR #16 | `job` / `presig` are validated by spreading under a synthetic `type`, so a nested `type` key escapes the unknown-key check | never open here: the object's own keys are checked; tested |
| issue #22, PR #24 | `SCALAR_HEX` admits an odd digit count the hex decoder then throws on | closed here: an odd-length `presig.s` is refused |
| issue #17, #5 | a `cancel` in `proposed` matches no contract, so one signed cancel ends every pending offer from that sender, and no `receipt` can follow | **mirrored, on purpose** — this is a reader, and disagreeing with the reference about what a transcript did would be worse than sharing its behaviour; recorded in `TCLK_THREAT_MODEL.md` as an upstream-open residual |
| issue #12 | on a payee-opened offer the acceptor (the payer) mints the secret that only the payee may reveal | mirrored; a spec question this port does not answer |
| PR #25 | an offline audit of two `/export` files: signature per frame, `from` equality, fold at each record's `ts` | the same shape as `simulate` plus transport verification; here the signature half is the existing `adapters/technocore` reader's job |
| #2, #3, #6, #9–#11, #19–#21 | example-script robustness, venue room cap, an EVM rail | out of scope for a read-only integration |

Not found in any of the above, and therefore the only candidates for a report
of this port's own: the absence of an ordering rule for `expiresMs` against
`claimByMs`/`refundAfterMs` in `SPEC.md` §3.1 and `validateFrame`; the
unspecified treatment of duplicate JSON keys; and the provenance sentence below.

## One inconsistency observed in the source

`tests/vectors.test.ts` says its constants "were generated from the reference
implementation". `AGENTS.md` says "they were produced by an independent
implementation of this spec". Both cannot be true of the same bytes' origin.
The bytes are what they are and this port reproduces them; the provenance
claim is recorded here as found and not relied on.

## What this report is not

It is not an endorsement, a security review of tclk, or a statement about the
FLOP network. It is what the documents say, read once, on the date given.
