"""Every seam the executor is allowed to have, in one file.

The executor must not know how a request travels, who signs, what a clock says
or where an audit line is written. If it imported `simulation` to run a
simulated action, it would know one implementation by name, and connecting the
real testnet later would mean re-opening the executor -- the file whose ordering
of checks is the security property.

So the protocols live here and the implementations live elsewhere:
`simulation.SimulationTransport` and `client.NullTransport` both satisfy
`TestnetTransport`, and neither is imported by `executor`.

`TransportRequest` is deliberately not a URL and a body. It is the whole
description of one attempt, including the caps, so a transport cannot be handed
a request whose timeout or size limit was left to it to decide.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps this module dependency-free
    from lineageauth.flop.testnet.approve import ApprovedTestnetAction
    from lineageauth.flop.testnet.prepare import InferenceWorkload, PreparedTestnetAction, Untrusted
    from lineageauth.flop.testnet.receipts import FlopTestnetExecutionReceipt


@dataclass(frozen=True, slots=True)
class TransportRequest:
    """One attempt, described completely.

    The caps travel with the request rather than living in the transport,
    because a transport supplied by a future adapter is exactly the component
    whose defaults this layer should not be trusting.
    """

    method: str
    url: str
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    timeout_seconds: float = 10.0
    max_response_bytes: int = 262_144
    follow_redirects: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "byteLength": len(self.body),
            "timeoutSeconds": self.timeout_seconds,
            "maxResponseBytes": self.max_response_bytes,
            "followRedirects": self.follow_redirects,
        }


@dataclass(frozen=True, slots=True)
class RawResponse:
    """What a transport got back, before anything decides it is meaningful.

    `final_url` is separate from the requested URL so a redirect that a
    transport followed anyway can still be caught: the client compares the two
    and refuses when the origin moved, rather than trusting the transport's
    promise not to follow one.
    """

    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    final_url: str = ""
    redirected: bool = False


class TestnetTransport(Protocol):
    """Moves bytes. Knows nothing about approval, spend or evidence."""

    def send(self, request: TransportRequest) -> RawResponse:
        """Perform one attempt, or raise. Never retries a mutating action."""
        ...


class Signer(Protocol):
    """Signs bytes somewhere else. This process never holds the key."""

    @property
    def signer_id(self) -> str: ...

    @property
    def available(self) -> bool: ...

    @property
    def holds_private_keys(self) -> bool: ...

    def sign(self, data: bytes) -> bytes: ...


class AuditSink(Protocol):
    """Appends one line and returns its chain hash."""

    def append(self, kind: str, entry: Mapping[str, Any]) -> str: ...


class Clock(Protocol):
    """Time, injected, so a test never depends on the wall clock."""

    def now(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class FixedClock:
    """The only clock this package ships. A test states the instant it means."""

    instant: datetime

    def now(self) -> datetime:
        return self.instant


@dataclass(frozen=True, slots=True)
class SystemClock:
    """UTC now. Used by the CLI, never by a test."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class FlopTestnetAdapter(Protocol):
    """The shape a real testnet adapter will have to satisfy (directive 4).

    Written now so that the future activation task adds a file rather than
    reshapes the application. `prepare_faucet` is optional in the directive; it
    is present here and may return a refusal, which is what "optional" means
    once the answer has to be typed.
    """

    @property
    def adapter_id(self) -> str: ...

    def discover(self) -> Mapping[str, Any]: ...

    def verify_official_source(self) -> Mapping[str, Any]: ...

    def agent_state(self, subject_did: str) -> Mapping[str, Any]: ...

    def prepare_faucet(self, *, subject_did: str, at: datetime) -> PreparedTestnetAction: ...

    def prepare_inference(
        self,
        *,
        subject_did: str,
        workload: Untrusted[InferenceWorkload],
        at: datetime,
    ) -> PreparedTestnetAction: ...

    def execute(self, approved: ApprovedTestnetAction) -> FlopTestnetExecutionReceipt: ...


__all__ = [
    "AuditSink",
    "Clock",
    "FixedClock",
    "FlopTestnetAdapter",
    "RawResponse",
    "Signer",
    "SystemClock",
    "TestnetTransport",
    "TransportRequest",
]
