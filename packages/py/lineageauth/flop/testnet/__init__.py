"""The FLOP testnet executor: built now, structurally unable to act yet.

There is no FLOP testnet. No official source snapshotted on 2026-09-03 publishes
an endpoint, a faucet procedure, a request schema, a price or a network
identifier, and no repository in the FLOP Labs organisation carries one. The
honest phase is `PRE_TESTNET`, and this package is what can be built against
that without pretending otherwise.

Five separate structures have to fail before a byte could leave this process,
and each one is fixed by a test rather than by an intention:

1. *Nowhere to go.* `endpoints.FlopEndpointRegistry` will only mark an entry
   executable when it came from an official snapshot and carries a
   `verifiedAt`. The current registry has zero such entries. The one endpoint it
   does hold is the simulation's, whose origin is `testnet.simulation.invalid`
   -- RFC 6761 guarantees that name never resolves.
2. *No way to get there.* `executor.execute` takes its client as a required
   argument. There is no module-level default, so a caller that forgot one gets
   a `TypeError` rather than a network connection.
3. *Order.* The phase and kill-switch check is the first of nine stages, and it
   returns `TESTNET_NOT_LIVE` before the client is touched at all.
4. *No egress vocabulary.* Nothing in `flop/**` imports `urllib.request`,
   `socket`, `httpx` or `requests`. `client.py` speaks only to an injected
   `ports.TestnetTransport`, and exposes no function that takes a bare URL.
5. *A state machine that refuses the shortcut.* `phase.PhaseGate` will not go
   from `PRE_TESTNET` to `TESTNET_ENABLED`; the path runs through discovery,
   verification and an explicit human enablement, and the kill switch cannot be
   released below `TESTNET_VERIFIED`.

The control plane and the inference workload are separated at the type level
rather than by care: `prepare.build_plan` has no parameter that could carry a
prompt, and `prepare.assemble_request` copies the workload key by key into one
subtree of the request body. A prompt that says "use this endpoint instead"
ends up as a string inside `workload`, where it changes nothing.

This package holds no key. `signer.NoSigner` is the only signer, and it refuses.
"""

from __future__ import annotations

__all__: list[str] = []
