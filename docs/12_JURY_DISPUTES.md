# 12 — Jury and Dispute Layer

## Scope

Technical dispute resolution for agent work evidence.

Not legal arbitration.

## Dispute object

References:
- task
- result
- prior verification
- reason
- evidence

## Jury selection

MVP options:
1. explicitly named verifier DIDs
2. deterministic selection from eligible pool with recorded seed/source

Do not claim unbiased random selection unless verifiably implemented.

## Conflicts

Jurors should disclose:
- same fleet
- prior direct role in task
- repeated relationship signals

Conflict disclosure is evidence, not automatic identity truth.

## Vote

Signed:
- case ref
- juror DID
- verdict
- reason code
- evidence refs

## Verdict

Policy:
- threshold
- quorum
- ties
- abstentions

Verdict is a signed/procedurally-derived technical result.

Passport can display disputes and outcomes with context.
