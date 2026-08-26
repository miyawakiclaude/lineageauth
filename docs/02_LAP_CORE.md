# 02 — LAP Core Protocol

## Version

Protocol: `lineageauth`
Core version: `0.1`

## Canonical payload

RFC 8785 JCS.

Preimage:

`lineageauth:event:v1\n` + canonical JSON payload bytes

Event ID:

`sha256:<lowercase hex SHA-256(preimage)>`

Proof:

```json
{
  "alg": "Ed25519",
  "signer": "did:key:z6Mk...",
  "sig": "<base64url-no-padding>"
}
```

Envelope:

```json
{
  "payload": {},
  "proofs": []
}
```

## DID support

MVP:
- Ed25519 `did:key`

Future:
- new DID methods only through versioned extension profile
- no silent compatibility

## Common fields

Every event:
- protocol
- version
- type
- lineage
- issuedAt

Event-specific:
- issuer / subject / epoch / refs

## Time

RFC3339 UTC.

Verifier accepts an explicit `at` time for deterministic tests.

## Object references

Use event IDs, not DB primary keys.

## Event immutability

No updates.
Correction = new event.

## Unknown versions

Fail closed for authority.

Evidence viewer can render unknown raw object with UNKNOWN_VERSION status without treating it as valid semantics.
