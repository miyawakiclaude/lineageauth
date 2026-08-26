# 05 — Recovery and Succession

## Problem

`did:key` is key-derived and has no central key rotation.

LineageAuth creates continuity above the DID.

## Recovery policy

Fields:
- members[] unique DIDs
- threshold
- epoch
- policy version
- optional delay seconds future extension

Recommended operational model:
- 3 recovery keys
- threshold 2
- offline
- physically separated

## Succession modes

### Normal
Current root signs:
Root A -> Root B
epoch N -> N+1

### Recovery
Threshold valid recovery proofs authorize Root B.

## Epoch rule

Current authority uses highest valid resolved epoch.

A lower epoch root remains historically verifiable but cannot create current authority after valid succession.

## Conflicts

MVP conservative behavior:
- if two incompatible valid successions claim the same `fromEpoch -> toEpoch` and neither can be deterministically preferred by protocol, status = CONFLICTED
- fail closed for new authority
- expose both event IDs
- do not choose based only on timestamp

Future transparency/log consensus can improve conflict handling.

## Recovery policy rotation

MVP:
- current root can create new recovery policy for current epoch
- policy activation must reference previous policy and have monotonically increasing policy sequence
- if conflicting policies cannot be ordered, fail closed

## Compromised old key caveat

Crypto signatures made by old key remain mathematically valid.
Protocol semantics mark old authority as superseded.

UI must say this explicitly.
