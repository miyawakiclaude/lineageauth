# tclk/1 × LineageAuth — gap analysis

What the existing LineageAuth model can say about a tclk/1 frame, what it
cannot, and what would have to change to close each gap. Nothing marked
`SPEC CHANGE REQUIRED` was done; those are proposals awaiting a decision.

## Expressible today — reused, no change

| need | how LineageAuth expresses it | evidence |
|---|---|---|
| may this agent post to the offer board | `technocore` / `room:tclk-offers` / `write` | `docs/04` namespace table; `scopes.NAMESPACES["technocore"]` |
| may this agent post into one deal room | `technocore` / `room:mb-p-tclk-<16hex>` / `write` | same; the room is derived by `venue.deal_room` |
| a human must consent to each post | grant `approval: required` naming its `approvers`; receipt over `ActionRequest.over_bytes(content=<frame line>)` | `docs/06`; `approval.check_execution` |
| a changed byte after approval | `requestHash` covers `contentHash` covers the line | `actions.py` |
| the grant expired / was revoked / root superseded / lineage conflicted | `check_permission` reason codes | `EXPIRED`, `REVOKED`, `SUPERSEDED`, `CONFLICTED` |
| the frame is not tclk/1 at all | `MALFORMED`; a different version prefix → `UNKNOWN_VERSION` | `authority.verify_tclk_authority` |
| a frame's bytes as evidence | `artifact.register` with `artifactId = sha256:<line bytes>` | `docs/07` |
| a party's view of the outcome | `attestation.issue`, predicate `tclk.contract.outcome` (unregistered) | `docs/07`: unknown predicates stay displayable |
| two DIDs are one disclosed operator | `fleet.bind`; `FleetView.same_fleet` | `docs/13`, D-105 |

## Reason codes

The directive's list maps onto existing codes with no additions:

| directive | LineageAuth | note |
|---|---|---|
| AUTHORIZED | `VALID_AUTHORITY_CHAIN` | |
| APPROVAL_REQUIRED | `APPROVAL_REQUIRED` | |
| NO_AUTHORITY | `DENIED` | |
| SCOPE_VIOLATION | `SCOPE_VIOLATION` | |
| EXPIRED / REVOKED / SUPERSEDED / CONFLICTED | same | |
| UNSUPPORTED_TCLK_VERSION | `UNKNOWN_VERSION` | already exists; `tclk2 ` → this |
| SPEND_LIMIT_EXCEEDED | **none** | there is no spend limit to exceed; see below |

## Not expressible — `GAP`

These are what a tclk-aware policy would want and the scope grammar cannot
carry. Every decision from `verify_tclk_authority` names them in `unchecked`
so a caller cannot mistake an allow for a judgement about them.

| gap | why the current model cannot say it | what LineageAuth does instead |
|---|---|---|
| **spend limit** — "at most 1 000 000 FLOP per offer" | a `Scope` is `{namespace, resource, actions}` and refuses any other field (`Scope.parse`); there is no numeric constraint anywhere in the grant | reports `spend-limit` as unchecked; surfaces `amount`/`asset` in `RequiredAuthority` for a human preview |
| **rail allowlist** — "only `flop-htlc`" | same | refuses a `lock` naming a rail outside the verifier's `KNOWN_RAILS` (a local, fail-closed policy, not a delegation) and reports `rail-allowlist` |
| **counterparty restriction** — "only with DID X" | same | reports `counterparty` |
| **per-frame-type permission** — "may offer but not lock" | every frame is a `write` to a room; the action grammar has no finer verb | reports `frame-type`; the *room* separates offers from later frames, which is the only structural handle available |
| **settlement** | out of scope by design and by directive | reports `settlement`; `rail.py` has no value-moving member |

## `SPEC CHANGE REQUIRED` — proposals, not changes

Each of these would be a protocol change per `scopes.py` ("Adding a namespace
or an action is a protocol change") and `docs/24`. None was made.

### 1. A `tclk` namespace

```
namespace: tclk
resources: contract:<contract-id> | contract:*
actions:   offer | accept | lock | reveal | refund | cancel | receipt
```

*Closes:* per-frame-type permission. *Cost:* a second authority the same post
needs (the `technocore` room write does not go away), a new family in
`frozen-shapes.json`, and a second implementation (`packages/js/`) that must
agree. *Interaction with D-105 / PRIOR_ART:* the `authority` family is held
pending the UCAN question; adding a namespace to a held family is the wrong
moment.

### 2. Typed constraints on a scope

```
{"namespace": "tclk", "resource": "contract:*", "actions": ["offer"],
 "constraints": {"maxAmount": {"asset": "FLOP", "value": "1000000"},
                 "rails": ["flop-htlc"], "counterparty": ["did:key:…"]}}
```

*Closes:* spend limit, rail allowlist, counterparty. *Cost:* attenuation
semantics for each constraint (a child may only tighten — what is "tighter" for
a rail list is clear; for two assets it is not), a canonical comparison rule,
and — the reason to be slow — this is exactly the constraint language
`PRIOR_ART.md` credits to ADTP and UCAN caveats. Reinventing it beside them is
the outcome that page exists to prevent.

### 3. Registering `tclk.contract.outcome`

*Closes:* nothing functional; would let the predicate count in a ranking.
*Cost:* a vocabulary change; and the value it would carry (`claimed`,
`refunded`, `cancelled`) is what a transcript already shows. Leaving it
unregistered keeps it visible and inert, which is right for a claim this layer
cannot verify.

### 4. A `tclk` action on the `a2a` namespace

tclk's `job = {proto: "a2a", id}` binds a contract to an A2A task.
LineageAuth's `a2a` resources are `agent:<id>` and `skill:<id>`, not tasks, so
the link is carried as data (`interop.job_reference`) and not as authority.
Making it authority would need a task resource, which is the same question as
(1).

## What was not changed, and could have been mistaken for a gap

- **The DID shape.** The reference matches `did:key:z6Mk` + 44 base58 and does
  not decode it; so do the golden vectors, whose DIDs are not real keys. This
  port keeps the shape check for parity. Decoding is Technocore's job at the
  transport and LineageAuth's job when the same DID appears in a signed event.
- **`claimByMs`.** Not enforced by the state machine in the reference either;
  it is the payee's pre-accept check and the rail's business.
- **Non-canonical lines and duplicate keys.** Accepted by the reference,
  refused here. Documented in `frames.py`; every reference-emitted frame is
  canonical, so the difference bites only hand-built lines.

## Dependency check (§26 of the directive)

No new dependency. Canonical JSON is `json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=True)` and reproduces the golden vectors;
sha256 is `hashlib`; secp256k1 point validation and `y·G` come from
`cryptography`, already required, which refuses off-curve points, bad prefixes,
short encodings and out-of-range scalars.
