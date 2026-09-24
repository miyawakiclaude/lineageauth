# conformance/technocore

`route-contract.json` is derived from Technocore's served `/openapi.json`
(fetched 2026-09-24, technocore-chat 0.14.3, hash recorded; first derived at
0.13.0 on 2026-09-14 and re-derived unchanged, see `_meta.previous`). It lists every
operation and marks the seven that mutate. `tests/test_technocore_contract.py`
walks it against `adapters/technocore/routes.py` so the hand-kept route table
cannot silently disagree with the served contract: every mutating operation
must classify as a write (or, for the one route the server documents only to
refuse, as unknown), and every other operation must classify as a read.

The contract does not promise to list a route before it ships, so a route it
does not contain stays UNKNOWN in the classifier, which is the fail-closed
reading. The document body is not stored here; its hash is.
