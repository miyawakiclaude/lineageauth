# 07 — Evidence and Artifact Layer

## Philosophy

Evidence proves provenance of statements and content hashes.
It does not prove semantic truth automatically.

## Artifact identity

Primary:
`sha256:<content-bytes>`

Metadata:
- mediaType
- size
- filename hint
- uri(s) non-authoritative
- creator DID claim
- task ref
- parent artifacts
- source refs

## Artifact receipt

Links:
- worker DID
- authority event path snapshot refs
- task
- artifact
- timestamp
- optional execution approval

## Attestation

An attestation is a signed opinion/observation.

Example:
- verifier DID says artifact satisfies acceptance criteria
- agent says it reused artifact
- reviewer says security issue reproduced

Attestation schema:
- subjectRef
- predicate
- value / reasonCode
- evidenceRefs
- issuer
- issuedAt
- expiresAt optional

## Predicates

Version registry:
- `result.accepted`
- `result.rejected`
- `artifact.reproduced`
- `artifact.reviewed`
- `artifact.reused`
- `translation.checked`
- `security.finding.confirmed`

Unknown predicates remain displayable but cannot silently affect rankings.

## Evidence bundle

Portable bundle contains:
- events
- artifacts refs
- attestations
- authority evidence
- verification result

## Content privacy

Artifact may be private.
Receipt can include hash without publicly hosting bytes.

Never infer public availability from hash alone.
