# 17 — UI / UX

## Screens

1. Lineage Dashboard
2. Authority Graph
3. DID Detail
4. Delegation Builder
5. Approval Review
6. Recovery
7. Evidence / Artifact
8. Task Detail
9. Passport
10. Router
11. Task Exchange
12. Jury Case
13. Fleet
14. Impact Graph
15. Protocol Inspector
16. tclk/1 Deal Inspector — read-only; no wallet, no settlement (`docs/TCLK_INTEGRATION.md`)
17. FLOP Activity Console — a separate page at `/flop`, ten screens: Overview,
    Activity, Evidence, Technocore, tclk, Inference, Passport, Safety, Sources,
    Settings. Read-only; independent tool for the FLOP ecosystem, not
    affiliated with or endorsed by FLOP Labs; evidence coverage is not an
    airdrop score (`docs/FLOP_ACTIVITY_CONSOLE.md`, `docs/FLOP_UI_GUIDE.md`)

## Approval UX

Must prominently show:
- agent DID
- authority path
- destination
- semantic action
- exact text/content summary
- content hash
- expiry
- irreversible warning if applicable

## Status language

Use:
- valid authority chain
- signature verified
- revoked
- superseded
- stale
- conflicted

Never:
- trusted human
- official
- guaranteed safe

## Visual graph

Nodes:
- root
- agent
- recovery
- task
- artifact

Edges:
- delegated
- succeeded
- recovered
- produced
- verified
- reused

## Security

- escape untrusted content
- strict CSP
- no auto-open links
- no secrets in localStorage
- no browser key generation MVP unless separately threat-modeled

## FLOP Console additions

- Tokens are generated from `conformance/flop/ui-tokens.json`; official
  `design.md` values replaced the supplied baseline where they differed, and
  every difference is listed (`docs/FLOP_UI_GUIDE.md`).
- Dark default, `data-theme="light"` for Ice White; never mixed on one screen.
- Every badge is a text label; meaning is never colour alone; WCAG AA ratios
  are recomputed by `tests/test_flop_a11y.py`.
- Persistent notices: the affiliation line, `FLOP token may not yet exist on
  the current network phase. Never enter a seed phrase or private key to claim
  an airdrop.`, and `Testnet tokens have no assumed monetary value.`
- The Inference screen's four steps (Purpose → Quote → Security Review →
  `Approve & Run (SIMULATION)`) show the DID, endpoint, exact spend cap,
  authority result, scan result and request hash before anything is approved,
  as the Approval UX section above requires. Real faucet and execute controls
  are disabled with the reason.
- Source URLs are rendered as text, never as links.
