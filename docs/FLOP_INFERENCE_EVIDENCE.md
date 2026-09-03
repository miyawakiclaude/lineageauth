# FLOP inference evidence

How an execution receipt becomes LineageAuth evidence, and where it stops.
`packages/py/lineageauth/flop/testnet/{receipts,evidence}.py`.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** Today every receipt this tool can produce is a simulation, and
every piece of evidence it drafts says so twice.

## The receipt

`FlopTestnetExecutionReceipt`:

```text
actionId, subjectDid, network, actionType, endpointId
requestHash            sha256 of the canonical request bytes (JCS)
responseHash           sha256 of the response body, or null
observedSpend          read from the response, never from the quote; null if absent
quoteAmount            what the network said it would charge (informational)
startedAt, completedAt
sourceSnapshotId       which official snapshot the action was prepared under
verificationState      verified | partially-verified | unverified | conflicted | invalid
model, miner, validator, transactionRef    as the response states them, or null
resultAvailable        whether a result body came back
synthetic, simulation  both true for every receipt producible today
unverifiedBecause      the reasons for anything short of verified
```

Facts and judgements are separated on purpose. `observedSpend` is what the
response *said*; a quote recorded as spend would be a number this tool made up.
`verificationState` is what this session *checked*, and its reasons are listed
rather than summarised.

A response that arrives is not a receipt. A receipt is not proof the inference
was performed. Neither is proof the result is true. So `receipt_from_response`
returns `partially-verified` for a response that carries no receipt reference,
naming each field it could not confirm (acceptance L,
`tests/test_flop_testnet_evidence.py`), and the Inference screen shows the
state and its reasons rather than a green tick.

## The evidence drafts

`evidence.draft_evidence(receipt, …)` produces unsigned drafts built by the
core's own builders — the same pattern as `adapters/tclk/evidence.py`:

| Draft | Built by | Content |
|---|---|---|
| request artifact | `builders.build_artifact_register` | `artifactId = requestHash`, kind and network as data |
| response artifact | `builders.build_artifact_register` | `artifactId = responseHash` |
| attestation | `builders.build_attestation_issue` | predicate `flop.testnet.inference`, subject the agent DID, the receipt's ids as data |

All three are drafts. Signing is the holder's act, with the holder's key,
wherever that key lives; nothing here signs and nothing here submits. This is
the same boundary as `la … draft` commands and D-081.

**The predicate is not registered.** `flop.testnet.inference` is absent from
`catalog.KNOWN_PREDICATES`, and the draft carries `predicateRegistered: false`.
Registering a predicate is a protocol-vocabulary change this layer does not
make; an unregistered predicate stays displayable and can never silently affect
a ranking (`docs/07`, D-106 for the identical decision about
`tclk.contract.outcome`). That is the right standing for a claim about a
network that does not exist yet.

## Synthetic evidence is marked twice

The wrapper around the drafts carries `synthetic: true` and the banner
`SIMULATION - NO FLOP NETWORK ACTION`. The attestation itself carries
`reasonCode: SYNTHETIC_SIMULATION_NO_NETWORK_ACTION`, so the marker survives
into the signed event rather than living only in the envelope around it.

What is *not* done: no extra key is injected into a signed payload. The event
payloads are exactly what the core builders produce. A payload this layer
invented a field for is a payload the core verifier has never seen, and
`conformance/frozen-shapes.json` is unchanged. The reason code is the field the
core already provides for exactly this purpose.

Acceptance M (`test_acceptance_m_a_simulated_receipt_carries_both_banners`)
pins the two banners; acceptance test 7 pins that every mock record carries
the synthetic banner.

## Into the passport

`flop.passport.build_flop_passport` reads inference records through the
`LocalEventsAdapter` like any other artifact or attestation in the bundle. A
synthetic attestation therefore appears in the Activity timeline and on the
Passport screen — with its banner — and it is counted by the `inference`
coverage category only once the phase is `TESTNET_ENABLED`. Below that the
category reports `NOT_YET_AVAILABLE` regardless of what the bundle holds
(acceptance test 5, `…_not_yet_available_is_not_counted_as_covered`), because
a simulated spend on a network that has not launched is a rehearsal, not an
observation.

## The four verification states you will see

| State | When | What the screen says |
|---|---|---|
| `verified` | reserved for a response the official protocol lets this tool check end to end — none exists yet | — |
| `partially-verified` | a simulated response, or a live response missing a receipt reference or spend figure | the reasons, one per line |
| `unverified` | a response whose hash or origin could not be matched to the request | `RECEIPT_UNVERIFIED` |
| `invalid` | a response that fails schema or hash checks | `INVALID_RESPONSE` |

`la flop receipt verify RECEIPT` re-runs these checks on a receipt this tool
produced, offline. It cannot make a receipt more verified than the protocol
allows; it can only show what was checked.

## Mainnet unlock

`flop.testnet.mainnet.NotYetAvailable` is the only `MainnetUnlockAdapter`.
It reads the 3-to-1 ratio through `rules.unlock_ratio` from the registry
(`docs/FLOP_RULE_REGISTRY.md`) and answers `not-yet-available` for every
question. Its observation types have no field that could hold an allocation.
Nothing in this document, the receipt or the passport is a claim about any
allocation to anyone.
