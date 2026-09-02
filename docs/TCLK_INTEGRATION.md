# tclk/1 integration

**Pre-1.0. Read-only. Independent.** LineageAuth can verify whether an agent
has a declared authority chain for a proposed tclk/1 action before that action
is executed. That is the whole claim. This integration is not affiliated with
or endorsed by FLOP Labs, posts nothing, settles nothing, and holds no key that
could.

## What tclk/1 is

A convention published by FLOP Labs (`flop-labs/tclk`, `SPEC.md`) under which
two agents that met in a Technocore room strike a hash- or point-locked deal by
exchanging signed single-line frames — offer, accept, lock, reveal, refund,
cancel, receipt. The room records who agreed to what; a *settlement rail*
elsewhere holds the money. At the version read (`v0.1.0`, commit `81a8346`),
no rail that holds value exists.

## What LineageAuth adds

One question tclk/1 does not ask: **was this agent entitled to post this
frame?** A tclk frame is a Technocore signed-lane message, so posting one is
the LineageAuth action `technocore` / `room:<room>` / `write`, and everything
LineageAuth already does for that action applies — delegation chains,
attenuation, expiry, revocation, root succession, conflict handling, and
exact-action human approval bound to the frame's bytes.

It also lets a reader fold a room transcript into a contract state offline,
using a port of the reference state machine that reproduces the reference's
golden vectors byte for byte.

## What LineageAuth does not replace

- tclk's own validity rules — they are ported to *read*, not altered
- Technocore's signed-lane verification and room policy
- any settlement rail, FLOP-network consensus, or native account permission
- the judgement of whether work was delivered or was any good

## Authority before deal

```python
from lineageauth.adapters.tclk import verify_tclk_authority

decision = verify_tclk_authority(
    bundle,
    lineage=lineage,
    agent=agent_did,
    frame_line=line,
    at=now,
)
decision.allowed  # LineageAuth authority for the room write, and only that
decision.reason  # a LineageAuth ReasonCode; MALFORMED / UNKNOWN_VERSION if tclk refused first
decision.unchecked  # ("spend-limit", "rail-allowlist", "counterparty", "frame-type", "settlement")
```

Order of checks, which a caller must not reorder:

1. the line is a valid tclk/1 frame (structural, fail-closed; a `tclk2 ` line
   is `UNKNOWN_VERSION`, anything else malformed is `MALFORMED`)
2. the frame's `from` is the agent asking
3. a `lock` names a rail this verifier knows (local policy; fail closed)
4. LineageAuth authority for the write to the room `SPEC.md` §2 assigns

An allow says nothing about the five `unchecked` items. See
[`TCLK_GAP_ANALYSIS.md`](TCLK_GAP_ANALYSIS.md).

## Exact-action approval

```python
from lineageauth.adapters.tclk import prepare_frame

prepared = prepare_frame(line, nonce=nonce)  # no signer needed
prepared.request  # the ActionRequest a receipt binds to
prepared.signing_challenge  # "<room>|<nonce>|<line>", sign it where your key lives
prepared.preview()  # what a human is shown
```

The bytes hashed are the frame line itself, after Technocore's single-line
sweep — which is the identity for a canonical frame, and is asserted rather
than assumed. The receipt therefore binds the contract id, counterparty,
rail list, amount, asset and deadlines, because all of them are inside those
bytes. Change one byte and `check_execution` sees a different request.

Approval creates no authority: a receipt with no underlying grant is `DENIED`,
not `APPROVAL_REQUIRED`.

## Evidence

Each frame is an artifact (`sha256:` over its line). A contract's outcome is a
signed opinion (`attestation.issue`, predicate `tclk.contract.outcome`,
deliberately unregistered so it stays visible and inert). What that evidence
proves: these bytes existed, these DIDs signed them, these transitions applied
under tclk/1 guards at the stated instant. What it does not: that work was
delivered, that money moved, that a rail reference points at anything, or that
the parties are two people.

## Settlement boundary

The only rail type in this package is a read-only `Protocol` with
`validate_reference` and `inspect`. There is no `lock`, `claim`, `refund` or
`sign`. `publish()` raises `NotImplementedError`. This is not a stub awaiting a
flag; it is the shape of the integration.

## Security model, briefly

See [`TCLK_THREAT_MODEL.md`](TCLK_THREAT_MODEL.md). The short form: room
content is untrusted data and is never executed, fetched or obeyed; a signed
frame proves who wrote bytes, not that a deal is real; the state never holds a
revealed secret; no wallet, seed or payment key is read; the test suite refuses
the network.

## Limitations

- LineageAuth cannot express a spend limit, a rail allowlist, a counterparty
  restriction or a per-frame-type permission. It says so on every decision.
- The DID shape is checked, not decoded, for parity with the reference.
- Non-canonical lines and duplicate JSON keys are refused; the reference
  accepts them. Every reference-emitted frame is canonical.
- The PTLC adaptor-signature path is not ported; the reference marks it
  unaudited.
- The FLOP-network rail, its escrow policy language and any native delegation
  are undocumented publicly; nothing here assumes their shape.
- tclk/1 is alpha and may change. This port is pinned to commit `81a8346`.

## Explorer screen and API

The Explorer's ninth screen, **Deal (tclk)**, is a read-only inspector: paste
the frames of one deal, give the instant to judge them at, and optionally name
the agent that would post the last line. It shows the contract id, protocol
version, participants, status, deadlines, frame hashes, the authority result
for the room write, the exact-action approval result as a dry run, and what the
transcript does and does not establish. It calls three compute-only endpoints
on the local API — `POST /v1/tclk/inspect`, `/simulate`, `/authorize` — and
there is no endpoint that posts, locks, claims, refunds, reveals or pays. The
API has no default clock for a transcript; a caller states one instant or one
per frame, which is where the reference tool's issue #23 came from.

## Read-only CLI

```
la tclk inspect  FRAME              decode one frame line; --json
la tclk simulate TRANSCRIPT --now   fold frames into a state at an instant
la tclk authorize BUNDLE --agent DID --frame FRAME [--lineage --at --room]
la tclk prepare  FRAME [--nonce N] [--room ROOM]
```

There is no `send`, `publish`, `lock`, `claim`, `refund`, `reveal` or `pay`.
