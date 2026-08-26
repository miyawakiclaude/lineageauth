# 24 — Versioning and Migration

## Protocol

Events carry:
- protocol
- version
- type

Never reinterpret old signed payload under new semantics without version.

## Compatibility

Verifier supports explicit versions.

Unknown authority version:
- deny current authorization
- preserve raw display

## Schema changes

Backward-compatible optional fields can remain same minor only if semantics unchanged.

Semantic changes require protocol/version extension.

## Database

DB migrations do not alter signed events.

Projection can be rebuilt.

## API

Version path `/v1`.

Breaking API -> `/v2` or documented migration.

## Namespace extensions

New scope namespaces are registered/versioned.

Unknown namespace cannot silently authorize.

## Migration philosophy

Protocol history is immutable.
Migration creates new events/projections, not rewritten signatures.
