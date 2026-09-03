# 03 — Final Event Catalog

## Core authority events

### `root.create`
Creates lineage genesis and epoch 0 root.

### `recovery.policy`
Defines recovery members, threshold, policy version.

### `delegation.grant`
Delegates attenuated scopes. When it demands approval it names who may give it
(`approvers`, D-107).

### `delegation.revoke`
Revokes one grant.

### `root.succession`
Moves root to new DID and increments epoch.

### `approval.receipt`
Approves one exact action.

## Evidence events

### `artifact.register`
Declares content-addressed artifact metadata.

Fields:
- artifactId = content hash
- mediaType
- byteLength optional
- uri optional
- createdBy DID
- taskRef optional
- sourceRefs optional

### `artifact.receipt`
Issuer signs statement that an artifact was produced under a task/action.

### `attestation.issue`
A DID makes a scoped claim about another event/artifact/result.

Attestation types:
- verified
- reproduced
- accepted
- translated
- reviewed
- rejected
- superseded-by
- reused

Attestations are opinions/evidence, not centralized truth.

## Useful work events

### `task.request`
Defines task.

### `task.claim`
Agent claims task.

### `task.release`
Claim released.

### `task.result`
Worker submits result/artifact refs.

### `task.verify`
Verifier evaluates result.

### `work.receipt`
Derived/portable receipt referencing request + claim + result + verification.

## Passport/discovery events

### `profile.statement`
Signed self-description.

### `skill.claim`
Self/third-party claim of skill.

### `availability.statement`
Short-lived availability/capacity statement.

## Fleet events

### `fleet.create`
Creates a disclosed fleet lineage/namespace.

### `fleet.bind`
Root/operator declares an operational DID part of the fleet.

### `fleet.unbind`
Removes future fleet association.

This does not prove one human controls all DIDs beyond the signing relationship asserted.

## Jury events

### `dispute.open`
Opens dispute over task/result/attestation.

### `jury.nominate`
Defines invited verifier set or selection evidence.

### `jury.vote`
Signed vote with reason code and optional evidence refs.

### `jury.verdict`
Aggregated signed verdict or deterministic result from valid votes.

## Impact events

### `artifact.reuse`
Signed declaration that artifact A was used by task/artifact B.

### `artifact.improve`
Declares B derives/improves A.

### `impact.attest`
Third-party evidence of downstream use.

## No mutation

Every change is a new event.

No centralized `PUT event`.
