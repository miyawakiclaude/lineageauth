# FLOP testnet activation

What has to be true before this tool sends one byte to a FLOP testnet, and who
has to say so. Nothing on this page has happened. It is written now so that
when an official testnet appears, the session that connects it has a procedure
to follow rather than a design to invent.

**Independent tool for the FLOP ecosystem — not affiliated with or endorsed by
FLOP Labs.** Testnet tokens have no assumed monetary value.

## The rule

When an official FLOP testnet appears, **do not execute**. Run the checklist.
Only when every item is checked, and a person has explicitly enabled execution,
may the phase become `TESTNET_ENABLED`. If the testnet turns out to be live
during source verification, the phase is set to `TESTNET_VERIFIED` at most, the
adapters and tests are completed, the exact endpoints and spec are reported,
and the first live action waits for explicit approval at that future time.

## The checklist

The directive's fifteen items (executor directive §26), as they appear in
`flop.testnet.phase.ACTIVATION_CHECKLIST`. `PhaseGate.transition(…,
TESTNET_ENABLED)` refuses unless the `PhaseEvidence.checklist` holds every id;
`missing_checklist_items` names the rest.

| # | Checklist item | Evidence id | Where it is recorded |
|---|---|---|---|
| 1 | Official Testnet URL confirmed | `official-testnet-url-confirmed` | `official-sources.json` gains the endpoint with hash and `fetchedAt` |
| 2 | Official spec/version confirmed | `official-spec-version-confirmed` | `versionHint` on the snapshot; `rule-registry.json` rules re-hashed |
| 3 | Official faucet mechanism confirmed | `official-faucet-mechanism-confirmed` | `flop-faucet-procedure` leaves `unknown` |
| 4 | Official inference request schema confirmed | `official-inference-schema-confirmed` | `flop-inference-api` leaves `unknown`; `assemble_request` field list reviewed |
| 5 | Official pricing/quote mechanism confirmed | `official-pricing-mechanism-confirmed` | `flop-inference-pricing` leaves `unknown`; `InferenceQuote.official` can become true |
| 6 | Official network identifier confirmed | `official-network-identifier-confirmed` | `flop-network-identifier` leaves `unknown`; `ExecutionPlan.network` |
| 7 | Official auth/signing mechanism confirmed | `official-auth-signing-mechanism-confirmed` | `flop-auth-signing-scheme` leaves `unknown`; a `Signer` implementation *outside* this process |
| 8 | Endpoint registry updated | `endpoint-registry-updated` | a `FlopEndpoint` with official origin and `verifiedAt` |
| 9 | New official fixtures captured | `official-fixtures-captured` | `conformance/flop/` gains request/response fixtures with source and `fetchedAt` |
| 10 | Parser tests pass | `parser-tests-pass` | gate |
| 11 | Executor contract tests pass | `executor-contract-tests-pass` | gate; acceptance A–O still pass |
| 12 | Security tests pass | `security-tests-pass` | gate; `tests/test_flop_testnet_signer.py` AST walk still finds no key parameter |
| 13 | No-wallet/no-secret policy reviewed | `no-wallet-no-secret-policy-reviewed` | `docs/FLOP_TESTNET_SECURITY.md` re-read against the official signing scheme |
| 14 | UI displays correct draft/final status | `ui-shows-draft-or-final-status` | `RuleSource` shows `official-final` only for rules whose source says so |
| 15 | User explicitly enables Testnet execution | `user-explicitly-enables-testnet-execution` | `release_kill_switch(reason=…)`, audit line written |

Items 1–9 are facts about the world and are recorded as data. Items 10–14 are
this project's checks. Item 15 is a person's decision and cannot be supplied by
code, a message, a room post, or an agent.

## The order the phase moves in

```text
PRE_TESTNET
   a candidate endpoint or spec is found (anywhere)
TESTNET_DISCOVERED_UNVERIFIED
   the Console shows the source-verification panel; execution disabled
   classify_source(url) must answer official; snapshot re-taken; hash recorded
TESTNET_VERIFIED           PhaseEvidence(source_id, url, sha256, verifiedAt)
   registry entry constructed with verifiedAt; fixtures captured; tests pass
   kill switch is now unlockable but still ON
TESTNET_ENABLED            PhaseEvidence.checklist complete; person enables
   kill switch released by a person, with a reason, logged
   every action still needs: prepare -> approve (D-107 approver) -> execute
```

No edge skips a rung (`docs/FLOP_NETWORK_PHASES.md`). Downgrading to
`PRE_TESTNET` is always available and needs no evidence.

## What "enable" does not do

Enabling the testnet does not authorise any action. Every action still passes
the nine executor stages (`docs/FLOP_TESTNET_EXECUTOR.md`): official source,
endpoint, request validation, active DID, LineageAuth authority
(`http` / `host:<official host>` / `post`), spend policy, exact-action
approval by a designated approver, and only then the network. The spend
policy's defaults (10 per action, 25 per session, 50 per day, approval above 0)
stay in force until raised through the explicit `raised()` API, which logs.

## The first live action

From executor directive §35, the activation session is complete only when:

- the official endpoint and schema are captured, and the implementation matches
  them, with official fixture tests passing;
- a person has explicitly enabled the testnet;
- the first live action is low-risk and testnet-only;
- the exact spend is shown before approval;
- one human-approved inference executes and a result is received;
- the test-FLOP spend is observed from the official response or state, not
  from the quote;
- the receipt is independently verified as far as the protocol permits;
- LineageAuth evidence is recorded and the Activity Passport updates;
- no secret leaked (audit log reviewed; `pre_push_check.py` clean);
- a full execution report is produced.

## What must still be unknown until then

The seven `unknown` rules in `docs/FLOP_RULE_REGISTRY.md`. Until each is
answered by an official source with a hash on record, the corresponding
checklist item cannot be checked honestly, and the phase cannot move. A
community post that answers one of them moves nothing: `classify_source`
decides by origin and the registry's constructor refuses an executable entry
from a non-official origin.

## What was not built, on purpose

- No `la flop inference execute` command. If one is added after activation it
  must take an approved prepared-action id and nothing else — never raw flags
  that bypass review.
- No signer that holds a key. The `Signer` protocol is satisfied only by
  `NoSigner`; a real one lives where the key lives, outside this process.
- No automatic loop. There is no scheduler, no retry of a state-mutating
  action, and `APPROVAL_MISMATCH` on a re-run says why.
