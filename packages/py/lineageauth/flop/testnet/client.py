"""The only thing in this package that could send bytes, and what it refuses to do.

There is no `fetch(url)` here. The one public method takes a `FlopEndpoint` that
the caller got from the registry and a path the endpoint's own pattern accepts,
so a URL that came from a prompt, a room message or a redirect has no way of
becoming a destination -- it is not that such a URL is rejected, it is that
there is no parameter to put it in (directive 23).

Redirects are the interesting case. This client never follows one; if a
transport followed one anyway, the response's `final_url` will disagree with the
request's, and the answer is discarded and the new origin re-classified through
`sources.classify_source` before being reported. A redirect that lands on a
different origin is a different side effect, and directive 3 says that needs a
new approval rather than a quiet continuation.

Secrets are redacted before anything is recorded. The patterns are the same
family `flop.safety` scans for, and the redaction happens on the way *into* the
record rather than on the way out of it, so a log that is written can never
have held the value.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from lineageauth.flop.model import TestnetFailure, TestnetRefusal, TestnetRefusedError
from lineageauth.flop.sources import classify_source
from lineageauth.flop.testnet.endpoints import FlopEndpoint, FlopEndpointRegistry
from lineageauth.flop.testnet.ports import RawResponse, TestnetTransport, TransportRequest

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 262_144

REDACTED = "[REDACTED]"

# Anything that looks like key material never reaches a hash input, a log line
# or an error message. Over-redacting a response body is harmless; the body is
# recorded by hash, and the hash is taken over the original bytes.
_SECRET_SHAPES: tuple[re.Pattern[str], ...] = (
    # To the end of the line, not to the next space: a seed phrase is words with
    # spaces in it, and a pattern that stopped at the first space would redact
    # one word of twelve and leave the rest in the log.
    re.compile(r"(?i)\b(seed|mnemonic|private[_-]?key|secret[_-]?key|api[_-]?key)\b\s*[:=]\s*.+"),
    re.compile(r"\b[0-9a-fA-F]{64}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}"),
    re.compile(r"(?i)\b([a-z]+\s+){11,23}[a-z]+\b(?=\s*(?:$|[\"',}]))"),
)

_SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "set-cookie", "proxy-authorization"})


def redact(text: str) -> str:
    """Replace anything shaped like key material. Applied before recording."""
    redacted = text
    for pattern in _SECRET_SHAPES:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: (REDACTED if name.lower() in _SENSITIVE_HEADERS else redact(value))
        for name, value in headers.items()
    }


def sha256_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def origin_of(url: str) -> str:
    split = urlsplit(url)
    return f"{split.scheme}://{split.netloc}"


@dataclass(frozen=True, slots=True)
class ClientResult:
    """What happened, hashed, with the failure typed when there was one."""

    ok: bool
    endpoint_id: str
    url: str
    method: str
    status: int | None
    request_sha256: str
    response_sha256: str | None
    body: bytes = b""
    final_url: str = ""
    refusal: TestnetRefusal | None = None
    side_effects: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "endpointId": self.endpoint_id,
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "requestSha256": self.request_sha256,
            "responseSha256": self.response_sha256,
            "finalUrl": self.final_url,
            "byteLength": len(self.body),
            "refusal": None if self.refusal is None else self.refusal.to_dict(),
            "sideEffects": list(self.side_effects),
            "warnings": list(self.warnings),
            "secretsRedacted": True,
        }


@dataclass(frozen=True, slots=True)
class NullTransport:
    """The transport wired in whenever the testnet is not enabled.

    It is not a no-op that returns an empty answer -- that would let a caller
    treat "nothing happened" as "nothing to report". It refuses, loudly, with
    the reason, so a code path that reached it by mistake shows up.
    """

    calls: list[TransportRequest] = field(default_factory=list)

    def send(self, request: TransportRequest) -> RawResponse:
        self.calls.append(request)
        raise TestnetRefusedError(
            TestnetRefusal(
                failure=TestnetFailure.TESTNET_NOT_LIVE,
                detail=(
                    "no transport is configured for this phase; the executor should have "
                    f"refused before reaching {request.url}"
                ),
                stage="network",
            )
        )


@dataclass(slots=True)
class CountingTransport:
    """A transport that records attempts and never makes one.

    Injected everywhere in the tests so that acceptance O can assert the number
    of attempts is zero rather than assert that an exception was raised, which
    would also pass if the call had been made and then failed.
    """

    calls: int = 0
    requests: list[TransportRequest] = field(default_factory=list)

    def send(self, request: TransportRequest) -> RawResponse:
        self.calls += 1
        self.requests.append(request)
        raise TestnetRefusedError(
            TestnetRefusal(
                failure=TestnetFailure.NETWORK_REFUSED,
                detail="the counting transport never performs a request",
                stage="network",
            )
        )


class RestrictedClient:
    """Sends only to registry entries, and records what it sent by hash.

    The registry is held by identity: `send` checks that the endpoint object it
    was handed is the one the registry holds under that id, so a caller cannot
    construct a lookalike `FlopEndpoint` with a different origin and pass it in.
    """

    def __init__(
        self,
        *,
        registry: FlopEndpointRegistry,
        transport: TestnetTransport,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self._registry = registry
        self._transport = transport
        self._timeout = timeout_seconds
        self._max_bytes = max_response_bytes

    @property
    def allowed_origins(self) -> frozenset[str]:
        return self._registry.allowed_origins

    def send(
        self,
        *,
        endpoint: FlopEndpoint,
        path: str,
        body: bytes,
        headers: Mapping[str, str] | None = None,
    ) -> ClientResult:
        """One attempt at one allowlisted endpoint. Returns a typed result, never raises."""
        request_hash = sha256_of(body)
        registered = self._registry.get(endpoint.endpoint_id)
        if registered is None or registered != endpoint:
            return ClientResult(
                ok=False,
                endpoint_id=endpoint.endpoint_id,
                url="",
                method=endpoint.method,
                status=None,
                request_sha256=request_hash,
                response_sha256=None,
                refusal=TestnetRefusal(
                    failure=TestnetFailure.ENDPOINT_BLOCKED,
                    detail=(
                        f"endpoint {endpoint.endpoint_id!r} is not the entry this client's "
                        "registry holds under that id"
                    ),
                    stage="network",
                ),
            )
        if not endpoint.matches_path(path):
            return ClientResult(
                ok=False,
                endpoint_id=endpoint.endpoint_id,
                url="",
                method=endpoint.method,
                status=None,
                request_sha256=request_hash,
                response_sha256=None,
                refusal=TestnetRefusal(
                    failure=TestnetFailure.REQUEST_INVALID,
                    detail=f"path {path!r} is outside {endpoint.path_pattern!r}",
                    stage="network",
                ),
            )
        url = endpoint.url_for(path)
        if not url.startswith("https://"):  # pragma: no cover - the endpoint type forbids it
            return ClientResult(
                ok=False,
                endpoint_id=endpoint.endpoint_id,
                url=url,
                method=endpoint.method,
                status=None,
                request_sha256=request_hash,
                response_sha256=None,
                refusal=TestnetRefusal(
                    failure=TestnetFailure.ENDPOINT_BLOCKED,
                    detail="only https destinations are attempted",
                    stage="network",
                ),
            )
        transport_request = TransportRequest(
            method=endpoint.method,
            url=url,
            body=body,
            headers=redact_headers(headers or {}),
            timeout_seconds=self._timeout,
            max_response_bytes=self._max_bytes,
            follow_redirects=False,
        )
        try:
            response = self._transport.send(transport_request)
        except TestnetRefusedError as exc:
            return ClientResult(
                ok=False,
                endpoint_id=endpoint.endpoint_id,
                url=url,
                method=endpoint.method,
                status=None,
                request_sha256=request_hash,
                response_sha256=None,
                refusal=exc.refusal,
            )
        return self._read(endpoint=endpoint, url=url, request_hash=request_hash, response=response)

    def _read(
        self,
        *,
        endpoint: FlopEndpoint,
        url: str,
        request_hash: str,
        response: RawResponse,
    ) -> ClientResult:
        final_url = response.final_url or url
        if response.redirected or origin_of(final_url) != origin_of(url):
            decision = classify_source(final_url)
            return ClientResult(
                ok=False,
                endpoint_id=endpoint.endpoint_id,
                url=url,
                method=endpoint.method,
                status=response.status,
                request_sha256=request_hash,
                response_sha256=None,
                final_url=final_url,
                refusal=TestnetRefusal(
                    failure=TestnetFailure.ENDPOINT_BLOCKED,
                    detail=(
                        f"the response came from {origin_of(final_url)} rather than "
                        f"{origin_of(url)}; that origin classifies as "
                        f"{decision.source_class} ({decision.reason}). A redirect changes "
                        "the side effect, so it needs its own approval, not a follow"
                    ),
                    stage="network",
                ),
                warnings=("redirect refused; the response body was discarded unread",),
            )
        if 300 <= response.status < 400:
            location = response.headers.get("location", "")
            redirect_target = classify_source(location) if location else None
            return ClientResult(
                ok=False,
                endpoint_id=endpoint.endpoint_id,
                url=url,
                method=endpoint.method,
                status=response.status,
                request_sha256=request_hash,
                response_sha256=None,
                final_url=final_url,
                refusal=TestnetRefusal(
                    failure=TestnetFailure.ENDPOINT_BLOCKED,
                    detail=(
                        f"the endpoint answered {response.status} pointing at "
                        f"{location or 'an unstated location'}"
                        + (
                            f", which classifies as {redirect_target.source_class}"
                            if redirect_target is not None
                            else ""
                        )
                        + "; redirects are not followed"
                    ),
                    stage="network",
                ),
            )
        if len(response.body) > self._max_bytes:
            return ClientResult(
                ok=False,
                endpoint_id=endpoint.endpoint_id,
                url=url,
                method=endpoint.method,
                status=response.status,
                request_sha256=request_hash,
                response_sha256=None,
                final_url=final_url,
                refusal=TestnetRefusal(
                    failure=TestnetFailure.INVALID_RESPONSE,
                    detail=(
                        f"the response is {len(response.body)} bytes, over the "
                        f"{self._max_bytes} byte limit; it was not parsed"
                    ),
                    stage="network",
                ),
            )
        if response.status >= 400:
            return ClientResult(
                ok=False,
                endpoint_id=endpoint.endpoint_id,
                url=url,
                method=endpoint.method,
                status=response.status,
                request_sha256=request_hash,
                response_sha256=sha256_of(response.body),
                body=response.body,
                final_url=final_url,
                refusal=TestnetRefusal(
                    failure=TestnetFailure.NETWORK_REFUSED,
                    detail=f"the endpoint answered {response.status}",
                    stage="network",
                ),
            )
        return ClientResult(
            ok=True,
            endpoint_id=endpoint.endpoint_id,
            url=url,
            method=endpoint.method,
            status=response.status,
            request_sha256=request_hash,
            response_sha256=sha256_of(response.body),
            body=response.body,
            final_url=final_url,
            side_effects=(
                ("state-mutating request performed",)
                if endpoint.mutates_state
                else ("read-only request performed",)
            ),
        )


__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "REDACTED",
    "ClientResult",
    "CountingTransport",
    "NullTransport",
    "RestrictedClient",
    "origin_of",
    "redact",
    "redact_headers",
    "sha256_of",
]
