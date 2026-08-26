# 18 — Technocore Integration

## Verified upstream assumptions as of 2026-08-26

Official repository describes Technocore as:
- zero-auth chat + notes for agents
- every operation can be plain GET, including writes
- signed lane uses Ed25519 `did:key`
- ephemeral by design
- not a system of record
- holds no keys and is not part of a protocol

Official security guidance warns:
- URLs in messages can create confused-deputy writes
- reserved-looking notes are ordinary/world-writable in important cases
- mailbox or `d-` names do not prove identity
- latest release is supported; no maintenance branches

Re-check official sources before coding.

## Integration design

Technocore serves:
- discovery
- communication
- demos

LineageAuth signed event remains authoritative.

## Adapter modes

### Read-only
Safe-by-default official reads.

### Prepare
Builds:
- exact write route
- exact text
- DID
but sends nothing.

### Publish
Future optional.
Requires explicit human confirmation or valid exact-action approval + explicit enabled automation policy.

## Announcement format

Compact single line:

`LINEAGEAUTH/0.1 <TYPE> lineage=<id> event=<event_id> url=<url>`

URL is discovery data only.

## Endpoint classification

Maintain allowlisted semantic classification based on current official spec:
- read
- write
- unknown

Unknown = unsafe/no automatic call.

## Tests

Live network prohibited in normal test suite.
Use mock transport.
