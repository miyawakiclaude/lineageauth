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

## Native delegation records (llms.txt, served 2026-09-08)

Technocore now documents its own delegation: a root key appends to its DID
note `delegate: <agent-did> <scope> <expires> <nonce> <sig>`, where `sig` is
the root's Ed25519 signature over
`delegate|<root-did>|<agent-did>|<scope>|<expires>|<nonce>`. Scope is `*`,
`r:<room>` or `kv:<ns>`; expiry is the only revocation; the server neither
checks nor stores any of it.

`adapters/technocore/delegation.py` is the reader's half, and only that half:
it parses a note by token (a note has no lines), verifies each record against
the root, applies the expiry, and ranks by highest nonce per agent. It issues
nothing. `la technocore delegations --root <did> --note <file>` prints the
verdicts; `--json` gives them all.

Two facts a caller has to hold onto:

- A live record proves that the root key signed it. It is not a
  `delegation.grant`, it creates no LAP authority, and `check_permission`
  never reads it. `delegation_scopes` shows which LAP `technocore` scopes a
  record's scope corresponds to, so the two views can be compared, and that is
  all it does.
- The nonce ranking runs over records whose signature verified, not over every
  record. The reference at 45921c3e ranks first and verifies second, so a
  forged record with a large nonce -- which anyone can append to a
  world-writable note -- reports the real grant as SUPERSEDED
  (flop-labs/technocore-chat#782). `tests/test_technocore_delegation.py`
  pins the ordering. Everything else, including that an expired re-issue
  still supersedes an older live grant, follows the reference.

## What a contributor corrected on #430 (2026-09-10)

Five assumptions the adapter encodes were put to upstream in #430. A
contributor answered against `main@20a4457`: all five hold, with three details
this document now carries.

- **A room is a ring, not a log.** `MAX_ROOM_BYTES` is 10 MiB and the store
  compacts a live room down to half of it, so a room drops its oldest records
  while still present and answering. Notes are the durable class, and they are
  reaped after seven idle days too. A reader that treats a room as replayable
  history is wrong before the room expires (#481).
- **The route contract is served.** `/openapi.json` lists every operation;
  exactly seven mutate (four GET-shaped writes and three POST routes).
  `conformance/technocore/route-contract.json` pins it and
  `tests/test_technocore_contract.py` holds `routes.py` to it. A route the
  contract does not list stays UNKNOWN. Re-derived at 0.14.3 on 2026-09-24
  (D-118): the same 31 operations; the 0.14.x releases changed the service
  behind the routes, not the routes.
- **Note namespaces.** World-writable by design, with three exceptions:
  `room-owners` and `room-allow` accept only the owner's signed write, and
  `room-nonce` accepts no client write at all (it is the replay counter).
  `note_namespace_policy` says which; nothing here drafts a write into
  `room-nonce`.

Also confirmed: a verified writer is shown as its DID and everything else as
`~nick`, so "unverified" is stated by the server rather than inferred here; and
the server accepts only `z6Mk` Ed25519 keys, the same input this adapter fails
closed on. The scope question -- whether portable delegation belongs in FLOP
or an external layer -- is the maintainer's and is still open.

## Tests

Live network prohibited in normal test suite.
Use mock transport.
