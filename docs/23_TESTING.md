# 23 — Testing Strategy

## Test levels

1. Unit
2. Property-based
3. Test vectors
4. Integration with mocks
5. Cross-implementation conformance
6. Security/fuzz
7. End-to-end local
8. Optional approved live smoke tests

## Mandatory core vectors

- JCS ordering
- Unicode
- event ID
- Ed25519 valid/invalid
- mutation invalidates
- unsupported DID rejected

## Authority properties

- child never has permission parent lacks
- revocation monotonically removes authority
- higher valid epoch never restores old current root
- approval never grants missing base authority
- time window narrowing is monotonic

## Recovery

- threshold distinct signers
- duplicates don't count
- unknown member doesn't count
- conflicting succession => CONFLICTED

## Evidence

- changed artifact bytes change ID
- attestation signature only proves issuer
- missing bytes can still verify receipt hash but not content availability

## Router

- explainable ranking
- deterministic same inputs
- same-fleet signal correct
- stale availability excluded/flagged

## Technocore

- GET write classification
- zero live writes in tests
- untrusted URLs inert

## Conformance suite

Publish JSON vectors:
- input events
- query
- expected result
- evidence path
- reason codes

This enables independent implementations.
