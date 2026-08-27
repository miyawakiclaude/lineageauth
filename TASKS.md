# TASKS — Final Development Board

Claude Code must maintain this file.

**Current phase:** P1 Lineage (in progress).
**Last updated:** 2026-08-26.

Local checks, all passing at ¥0:

```bash
uv run pytest && uv run ruff check . && uv run mypy
```

## P0 Foundation
- [x] verify repository is outside company RPO repository
      — repo root `~/dev/lineageauth`, outside OneDrive and outside any company tree
- [~] verify intended personal account is `miyawakiclaude`
      — repo-local `user.name` set; the GitHub account itself is unverified
        because `gh` is not installed and no remote exists yet
- [x] add repository-local Git identity guidance without inventing email
      — see START_HERE.md; `user.email` deliberately left unset, so the first
        commit is blocked until the human supplies a personal address
- [ ] add pre-push personal-account safety check
      — deferred until a remote exists; must check account, owner, remote, branch
- [ ] add company contamination/release scan
      — CI scans for private key material; the contamination scan
        (company org names, internal domains, RPO paths) is still to be written
- [x] monorepo scaffold
- [x] Python 3.12 uv project
- [x] lint/type/test — ruff, mypy (strict), pytest, hypothesis
- [x] CI — `.github/workflows/ci.yml`, free on public repos (verified 2026-08-26)
- [x] secret-safe gitignore
- [x] package boundaries
- [ ] schema generation pipeline — JSON Schema emission from the event models

## P1 Lineage
- [x] JCS — RFC 8785 via the `rfc8785` library, never hand-rolled
- [x] event preimage — `b"lineageauth:event:v1" + LF + JCS(payload)`
- [x] event ID — `sha256:<64 lowercase hex>`, golden vectors computed externally
- [x] did:key Ed25519 parser — canonical-only, rejects DID URLs and other codecs
- [x] signature verify — per-proof results with reason codes, offline
- [x] root.create — draft builder + lineage derivation (D-025, D-026)
- [x] recovery.policy — draft builder, distinct members, ordered replacement
- [x] succession — draft builder, normal and recovery modes
- [x] epoch — `bundle.py` (admission) + `lineage.py` (`resolve_lineage`).
      `at` takes no part in the decision (D-033); duplicate event copies merge
      by union of verified signers (D-036)
- [x] conflict status — competing successions, unorderable policies, and forked
      policy chains all report `CONFLICTED` and fail closed. Never tie-broken
      by `issuedAt`; regression-guarded
- [x] CLI — `la lineage show BUNDLE [--lineage] [--at] [--json]`
- [~] vectors — 5 deterministic examples published; the full conformance
      package (query + expected result + evidence path) is still to come

## P2 Authority
- [x] scope types — `scopes.py`: namespace registry, resource grammar,
      `ApprovalMode` ordered `none < external-only < required`
- [x] Technocore containment — `room:`, `owned-room:`, `note:`
- [x] MCP containment — `server:`, `server:<id>/tool:<tool>`
- [x] A2A containment — `agent:`, `skill:`
- [x] GitHub placeholder — `repo:<owner>/<name>`
- [x] HTTP placeholder — `host:<hostname>`
- [x] delegation grant — `delegation.grant` builder + `authority.read_grant` (D-039)
- [x] attenuation — actions, resource, time window, depth, approval monotonicity
- [x] delegation depth — `maxDepth` counts *further* delegations; a leaf is 0
- [x] revoke — `delegation.revoke`; revoking a parent removes the whole
      subtree; revoker must be the issuer, an ancestor, or the root (D-041)
- [x] path resolver — `check_permission` + `la check`, reports the grant path
- [x] reason codes — DENIED / SCOPE_VIOLATION / REVOKED / EXPIRED /
      NOT_YET_VALID / SUPERSEDED / UNRESOLVED_PARENT / APPROVAL_REQUIRED
- [x] property tests — a child never permits what its parent forbids

## P3 Approval
- [x] canonical action descriptor — `actions.ActionRequest`
- [x] content/request hash — `requestHash = sha256(JCS(request))`, carried
      alongside the fields and re-derived on verification (D-043)
- [x] destination binding — control characters refused; the destination is what
      the human reads before consenting
- [x] nonce — at least 16 bytes, canonical unpadded base64url
- [x] expiry — exclusive at the boundary; a future-dated receipt is refused
- [x] approver authority — current root or an issuer on the path (D-042)
- [x] spent store — `InMemorySpentStore` and durable `SqliteSpentStore`
- [x] atomic reserve — primary-key insert, no read-then-write (D-044)
- [x] TOCTOU recheck — `check_execution` re-resolves everything, then reserves
- [x] tests — substitution, replay, races, and "approval is not authority"
- [ ] `la approval draft` / `la execute` CLI surface

## P4 Resolver/Explorer
- [x] immutable event store abstraction — `store.py`; content-addressed files,
      atomic writes, proofs unioned across copies of one id (D-036)
- [x] SQLite index — `index.py`; derived, never authority
- [ ] Postgres schema — documentation-only scale target, not provisioned
- [x] rebuild — `EventIndex.rebuild` + `checksum()` for the docs/25 drill
- [x] REST verify — `POST /v1/verify/event`, `POST /v1/check-permission`;
      both compute an answer and store nothing
- [x] REST read — events, lineages, DIDs; every assertion carries the event ids
      behind it so a client can reach its own verdict
- [x] graph projection — `graph.py`, `la graph`, `GET /v1/lineages/{id}/graph`;
      every status read off the resolver so the picture cannot disagree with it
- [x] explorer — plain HTML, CSS and one script, served by the API from the
      same origin. Not Next.js: a build step would add a second toolchain and a
      node_modules tree to a project whose zero-cost claim is checked by test,
      and the page needs neither (D-066)
- [x] security headers — CSP, nosniff, DENY, no-referrer on every response
- [x] no key storage — asserted: no private key material reaches the index

## P5 Technocore
*(brought forward ahead of P4: the read adapter and dry-run builder do not
depend on the indexer or the Explorer.)*
- [x] re-read official latest docs — llms.txt / auth.md / patterns.md,
      re-checked 2026-08-26; notes sign a different preimage from messages
- [x] read-only client — `TechnocoreReader` + `HttpsTransport`; no redirects,
      a response size cap, no cookies or credentials, and every read re-checked
      by the classifier at the last point before a socket opens
- [x] semantic endpoint table — `routes.py`; writes reachable by GET are
      classified as writes, and UNKNOWN is a refusal (D-046)
- [x] dry-run write builder — `prepare_signed_message`, returns the exact URL,
      bytes, signature and an `ActionRequest`; sends nothing
- [x] announcement formatter — `format_announcement`
- [x] confirmation boundary — publishing is not implemented at all; a prepared
      write can only be performed through `check_execution`
- [x] mock transport — `MockTransport`; the suite refuses sockets outright
- [x] no live writes tests — the suite refuses sockets outright for this module

## P6 MCP/A2A
- [x] verify latest MCP spec — 2026-07-28 re-read 2026-08-27; stateless core,
      opt-in extensions, and tool descriptions declared untrusted upstream
- [x] MCP server package — `adapters/mcp`; tool layer imports no SDK (D-049)
- [x] verify/check tools — verify_event, resolve_lineage, resolve_did,
      check_permission, check_mcp_invocation, list_grants, authority_graph,
      verify_approval
- [x] draft tools — build_delegation, build_approval; both return unsigned
      drafts, and no tool can sign
- [x] latest A2A mapping — spec re-read 2026-08-27; skills map onto
      `a2a` / `skill:<id>` through the scope grammar (D-063)
- [x] namespaced extension — `capabilities.extensions`, data-only, and
      `required` is hard-coded false with no way to ask for true
- [x] native auth coexistence tests — every permission answer states that the
      target system's own authorization still applies

## P7 Evidence
- [x] artifact.register — content-addressed; `createdBy` reported as a *claim*
      unless that DID signed the registration (D-051)
- [x] artifact.receipt — must be signed by the worker it names; cited authority
      is resolved and checked against the worker, never trusted (D-052)
- [x] attestation — one signer's opinion; distinct issuers counted, not rows;
      unknown predicates displayable but inert
- [x] private artifact hash-only support — `uri` optional and
      non-authoritative; a hash is never read as availability
- [x] evidence bundle — `collect_evidence` keeps self-asserted, signed, and
      third-party claims in separate fields
- [x] tests

## P8 Useful Work
- [x] task.request — acceptance criteria mandatory; `rewardReference` opaque
- [x] task.claim — nonce required; signed by the claimant (D-055)
- [x] release — only the holder may hand a claim back
- [x] result — must cite its own claim and at least one artifact
- [x] verify — accepted/rejected; disagreement yields CONTESTED, not a verdict
- [x] work.receipt — derived; carries no number that could be summed (D-056)
- [x] derived state machine — `resolve_task`; removing a verification un-accepts
- [x] anti-gaming signals — self-created task, self-verification, independent
      verifier count, reciprocal verifier pairs; reported, never weighted
- [x] tests

## P9 Passport
- [x] profile statement — self-claimed; control characters refused (D-053)
- [x] skill claim — a claim whoever signs it; `evidenceRefs` point at artifacts
- [x] claim/evidence categories — four separate collections, no combined field;
      a test fails any key that reads as a rating
- [x] passport projection — `build_passport`; skill support needs both a signed
      receipt and an independent attester
- [x] passport API — `GET /v1/passports/{did}` + `la passport`
- [x] passport UI — an Explorer screen (D-066)

## P10 Router
- [x] query schema — skills, authority requirements, approval ceiling, availability
- [x] skill index — claimed vs evidence-supported kept apart
- [x] authority index — every requirement re-checked through `check_permission`
- [x] availability — `availability.statement`, capped at 7 days; stale is
      reported, not dropped (D-058)
- [x] explainable ranking v1 — `explainable-v1`; contributions sum to the
      relevance and the weights ship with the response (D-057)
- [x] fleet independence signals — independent counterparties, attestation
      concentration, reciprocal verifier pairs; reported, never a Sybil verdict
- [x] search API — `POST /v1/router/search`
- [x] search UI — an Explorer screen, contributions shown summing to the relevance

## P11 Task Exchange
- [x] task registry — `browse`, filtered by status, requester, claimability
- [x] claim coordinator — competing claims all listed and none awarded unless
      the coordinator named in the task settles it (D-062)
- [x] task states — `CANCELLED` added; `DISPUTED` layered as a listing view
      that never overwrites the task's own status
- [x] cancellation — checked against the bundle, not against timestamps, so a
      backdated cancel cannot erase submitted work
- [x] moderation — reader-supplied blocklists that hide, count, and delete
      nothing
- [x] `GET /v1/exchange`
- [x] UI — an Explorer screen; DISPUTED shown over the task's own status
- [x] independent-agent test — three unrelated keys through the whole loop

## P12 Jury
- [x] `dispute.open` — carries its own policy, so the quorum cannot be chosen
      after the tally is visible (D-061)
- [x] selection — named jurors, or a deterministic draw from a declared pool
      that is labelled reproducible rather than unbiased
- [x] `jury.disclose` — conflicts disclosed by the juror; detected conflicts
      computed alongside, and neither voids a vote
- [x] `jury.vote` — signed by the juror; one seat, one counted finding
- [x] verdict — derived; a split jury is UNDECIDED and nothing breaks the tie
- [x] passport display — beside the four claim categories, never inside one
- [x] `GET /v1/disputes/{case}` — the procedure served with the outcome
- [x] UI — an Explorer screen showing the tally, every juror's conflicts,
      and what the outcome would have been without them
- [x] tests

## P13 Fleet
- [x] fleet.create — signed by the controller
- [x] bind — signed by the controller, not the member (D-059)
- [x] unbind — forward-only; only the controller that bound may unbind
- [ ] graph — fleet edges in the authority graph projection
- [x] router integration — siblings excluded from the independent count and
      never subtracted; disclosing costs exactly the uncounted counterparty
- [x] clear limitations — an absent fleet is silence, not independence, and
      both the router and passport say so

## P14 Impact
- [x] `artifact.reuse` — signed by the reuser, so an author cannot mint their
      own adoption
- [x] `artifact.improve` — signed by its author
- [x] `impact.attest` — a third party reporting use they observed; its own edge
      kind because who is speaking differs from a first-person reuse
- [x] impact edges with three-tier independence (same key / same fleet /
      independent) (D-060)
- [x] independent impact summary — distinct keys, not edge count; ten reuses by
      one key are one adopter
- [x] fraud heuristics presentation — reported with reasons, never as proof
- [x] passport `downstreamUse`
- [x] impact UI — downstream use on the passport screen

## P15 Production
- [x] zero-cost deployment architecture — static first; compute only when a
      third party must verify without cloning (D-065)
- [x] `docs/31_ZERO_COST_OPERATIONS.md` — its definition of done is now
      executed by `tests/test_zero_cost.py`
- [x] `infra/cost-policy.yaml` — free tiers checked 2026-08-27, with dates
- [x] free-limit stop/degrade behavior — asserted by test; nothing paid is on
      the path to degrade from
- [x] verify no automatic paid upgrades — the paid-service detector runs in CI
- [x] local full-stack ¥0 runbook — `RUNBOOK.md`, every command run first
- [x] multi-source resolver — union merge, so no mirror can suppress a
      revocation (D-064)
- [x] freshness policy — `checkedAt`/`newestEventSeen`/`freshnessAge`, and
      `STALE_STATUS` with a fail-closed `require_fresh()` for the high-risk path
- [x] conflict monitoring — every answering source that omitted an admitted
      event is named; missing revocations and successions sort first
- [ ] deployment
- [ ] optional PostgreSQL scale design (do not provision if paid)
- [ ] optional object storage design (do not provision if paid)
- [ ] observability
- [ ] backup/rebuild drill
- [ ] dependency audit
- [ ] fuzz
- [ ] conformance package
- [ ] version/migration docs
- [ ] v1 release checklist

## Final gate
- [ ] repository is owned/targeted by personal account `miyawakiclaude`
- [ ] no company RPO remote/account is used for writes
- [ ] no company secrets/code/customer data are present
- [ ] no company cloud/billing environment is required
- [ ] complete local/reference system runs at ¥0
- [ ] no paid service is required by default
- [ ] no billing/automatic upgrade is enabled
- [ ] all selected hosted free tiers were re-verified before deployment
- [ ] all protocol tests pass
- [ ] property tests pass
- [ ] conformance vectors publishable
- [ ] no secrets
- [ ] no unapproved external side effect
- [ ] DB rebuild validated
- [ ] recovery conflicts tested
- [ ] exact approval demo
- [ ] useful-work demo
- [ ] passport/router demo
- [ ] Technocore adapter safe
- [ ] MCP current
- [ ] A2A current
- [ ] README/security/limitations complete
