# 13 — Fleet Transparency

## Goal

Allow operator/root to voluntarily disclose that several agent DIDs are operated under one lineage/fleet.

## Why

A network of many DIDs can look like independent actors when it is not.
Fleet transparency creates a positive way to disclose relationships.

## Events

`fleet.create`
- fleet ID
- controller/root
- metadata

`fleet.bind`
- fleet
- agent DID
- role
- issuedAt
- expiresAt optional

`fleet.unbind`
- bind ref

## Semantics

Binding proves:
- signing controller asserted relationship

It does NOT prove:
- one legal person
- company employment
- all hidden DIDs disclosed

## Ranking

Router/evidence views can count independent lineages/fleets separately.

Never penalize disclosure in a hidden way; ranking policy must be documented.
