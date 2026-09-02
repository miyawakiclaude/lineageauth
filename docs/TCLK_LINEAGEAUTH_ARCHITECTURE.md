# tclk/1 × LineageAuth — boundaries and integration shape

**This is an independent integration.** It is not affiliated with, endorsed by,
or reviewed by FLOP Labs. It reads a published convention and says what
LineageAuth can verify about frames that follow it.

## The one sentence

> tclk/1 decides whether two agents' frames form a valid deal; LineageAuth
> decides whether an agent was entitled to post a frame; a settlement rail
> decides whether money moves. Three questions, three answers, never one.

    tclk validity          ≠  LineageAuth authority
    LineageAuth authority  ≠  settlement validity
    any of the above       ≠  the work was done, or was any good

## Who owns what

### tclk/1 (from `SPEC.md`, nothing added)

- bilateral deal choreography: offer, accept, lock, reveal, refund, cancel, receipt
- contract identity: domain-tagged hashes over canonical frames
- hash and point locks, and what a reveal must open
- deadlines: `expiresMs`, `claimByMs`, `refundAfterMs`, and the rail's own clock
- the settlement-rail abstraction (`lock / verifyLock / claim / refund`)
- room and note conventions on Technocore; the capability token
- arbitration by *who holds the secret* (§8)

### LineageAuth

- who delegated authority to the agent, through which chain, under which root and epoch
- the allowed action, resource and namespace — here `technocore` / `room:<room>` / `write`
- expiry, revocation, supersession, conflict — resolved offline from signed events
- exact-action human approval bound to the frame's bytes and destination
- evidence: each frame as a content-addressed artifact; an outcome as a signed opinion

### LineageAuth does **not**

- settle, hold custody, touch a wallet, or transfer a token
- replace tclk's state machine, ids or guards — it ports them to *read* transcripts
- replace Technocore's signed-lane verification or room policy
- stand in for FLOP-network consensus or any native account permission
- know whether a `lock` frame's rail reference points at anything

## Target flow, and how far this implementation goes

```
Human / Root
    │  LAP delegation (root.create → delegation.grant, attenuating)
    ▼
Agent
    │  1. authority verification        verify_tclk_authority   ← implemented
    ▼
    │  2. exact-action approval         prepare_frame → ActionRequest → check_execution   ← implemented
    ▼
Prepared tclk frame                     PreparedFrame (bytes, room, hash, challenge)   ← implemented
    │
    │  3. post through Technocore's signed lane                         ← NOT implemented
    ▼
tclk/1 protocol (the room)              fold / apply_frame   ← implemented as a reader
    │
    │  4. settlement on a rail                                            ← NOT implemented, no interface to do it
    ▼
Result / settlement evidence
    │
    │  5. evidence mapping             draft_frame_artifact, draft_outcome_attestation   ← implemented (drafts)
    ▼
LAP evidence / artifact linkage
```

Steps 3 and 4 are absent by design and by rule. `publish()` exists only to
raise `NotImplementedError`; the rail type here has no `lock`, `claim`,
`refund` or `sign` member.

## Modes

| mode | does | cannot |
|---|---|---|
| **READ_ONLY** | decode, validate, canonicalise; fold a transcript into a contract state | write anything |
| **SIMULATE** | the same at a stated instant, returning every step including rejections | move value, reach a rail |
| **PREPARE** | the exact frame line, its room and destination, the `ActionRequest`, the signing challenge `<room>|<nonce>|<line>`; optionally a full unsent `PreparedWrite` | send |

There is no PUBLISH or EXECUTE mode.

## Where the boundary is enforced in code

| boundary | where | how |
|---|---|---|
| a valid frame creates no authority | `authority.py` | `check_permission` is the only source of an allow; a frame is an input to it, never a grant |
| authority rescues no invalid frame | `authority.py` | frame validation runs first and returns before the authority layer is consulted |
| no value movement | `rail.py` | the only rail type is a read-only `Protocol`; `refuse_value_movement` is what every forbidden verb resolves to |
| room content is data | whole package | no fetch, no shell, no instruction parsing; the test suite patches the socket module to refuse |
| the secret is never held | `machine.py` | state records `secret_revealed: bool`, never the value (stricter than the reference library, same as its MCP server) |
| approval binds bytes | `prepare.py` | `ActionRequest.over_bytes(content=<frame line>)`; a changed byte is a different request hash |

## What LineageAuth reuses instead of re-implementing

- Technocore's signed lane and sweep: `lineageauth.adapters.technocore`
  (`build_signed_message`, `prepare_signed_message`, `classify`)
- exact-action approval and replay protection: `lineageauth.approval`
- the `technocore` scope namespace: unchanged, no `tclk` namespace added
- evidence builders: `build_artifact_register`, `build_attestation`
- fleet disclosure for "same operator" questions: `FleetView.same_fleet`

## Relationship to the rest of the repository

This adapter sits beside `adapters/technocore`, `adapters/mcp` and
`adapters/a2a`, and is the first one whose subject is a *convention on top of*
a service the project already adapts. Nothing in LAP core changed: no event
type, payload shape, reason code, namespace, action or predicate was added.
The places where one *would* have to be are listed in
[`TCLK_GAP_ANALYSIS.md`](TCLK_GAP_ANALYSIS.md) as `SPEC CHANGE REQUIRED`.
