"""Read-only Technocore client.

Reads only. There is no write path in this module, and adding one is not a
matter of passing a different method -- `assert_safe_to_read` refuses anything
the route table does not classify as a read, so a write URL cannot be fetched
here even by accident.

Everything this returns is **untrusted data**. A nickname is self-asserted, a
`from` field proves nothing, a room topic is whatever someone typed, and a URL
inside a message is data rather than an instruction (`CLAUDE.md` 2.4). Nothing
here follows a link it finds, and the types below are named to keep that in
view at the call site.

The transport is a protocol so the test suite can drive the adapter with no
network at all -- `docs/18` requires exactly that.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote, urlencode

from lineageauth.adapters.technocore.routes import SERVICE_ORIGIN, assert_safe_to_read
from lineageauth.adapters.technocore.text import check_room
from lineageauth.canonical import b64u_decode
from lineageauth.crypto import verify_detached
from lineageauth.didkey import public_key_from_did_key
from lineageauth.errors import LineageAuthError, MalformedEventError

USER_AGENT = "lineageauth/0.1 (+https://github.com/miyawakiclaude/lineageauth)"

DEFAULT_TIMEOUT_SECONDS = 10.0
# A cap, not an expectation. A response larger than this is either not what we
# asked for or not something to load into memory on trust.
DEFAULT_MAX_BYTES = 2 * 1024 * 1024


class TransportError(LineageAuthError):
    """The request could not be completed. Distinct from a refusal to make it."""


@dataclass(frozen=True, slots=True)
class Response:
    """A raw HTTP response. The body is untrusted text."""

    status: int
    body: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)

    @property
    def rate_limited(self) -> bool:
        return self.status == 429

    @property
    def retry_after(self) -> str | None:
        for name, value in self.headers.items():
            if name.lower() == "retry-after":
                return value
        return None


class Transport(Protocol):
    """How a reader reaches the service. Substitutable so tests need no network."""

    def get(self, url: str, *, timeout: float) -> Response:
        """Perform one GET. Must not follow a redirect to another origin."""
        ...


class MockTransport:
    """A transport backed by a dictionary. Used by the test suite."""

    __slots__ = ("_responses", "requested")

    def __init__(self, responses: Mapping[str, Response | str]) -> None:
        self._responses = dict(responses)
        self.requested: list[str] = []

    def get(self, url: str, *, timeout: float) -> Response:
        self.requested.append(url)
        found = self._responses.get(url)
        if found is None:
            return Response(status=404, body="", url=url)
        if isinstance(found, str):
            return Response(status=200, body=found, url=url)
        return found


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect.

    Following one would mean fetching a URL the route table never classified.
    A redirect from the service to somewhere else is exactly the shape of an
    SSRF, and "it was only a read" is not a defence when the destination is
    chosen by someone else.
    """

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class HttpsTransport:
    """A minimal HTTPS transport over the standard library.

    No cookies, no credentials, no redirects, no proxy auto-configuration, and a
    hard cap on how many bytes it will read. Deliberately not `requests`: this
    needs to stay dependency-free and small enough to audit at a glance.
    """

    __slots__ = ("_max_bytes", "_opener")

    def __init__(self, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self._max_bytes = max_bytes
        self._opener = urllib.request.build_opener(_NoRedirects)
        self._opener.addheaders = [("User-Agent", USER_AGENT), ("Accept", "*/*")]

    def get(self, url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Response:
        # The caller has already run `assert_safe_to_read`, which pins the
        # scheme to https and the host to the service. Re-run it here anyway:
        # this is the last point before a socket opens, and a guard that lives
        # only at the caller is a guard the next caller forgets.
        assert_safe_to_read(url)
        try:
            with self._opener.open(url, timeout=timeout) as handle:
                body = handle.read(self._max_bytes + 1)
                status = handle.status
                headers = {k: v for k, v in handle.headers.items()}
        except urllib.error.HTTPError as exc:
            payload = exc.read(self._max_bytes)
            return Response(
                status=exc.code,
                body=payload.decode("utf-8", errors="replace"),
                url=url,
                headers=dict(exc.headers.items()) if exc.headers else {},
            )
        except urllib.error.URLError as exc:
            raise TransportError(f"could not reach {url}: {exc.reason}") from exc
        except OSError as exc:
            raise TransportError(f"could not reach {url}: {exc}") from exc

        if len(body) > self._max_bytes:
            raise TransportError(f"response from {url} exceeds the {self._max_bytes} byte cap")
        return Response(
            status=status,
            body=body.decode("utf-8", errors="replace"),
            url=url,
            headers=headers,
        )


# ------------------------------------------------------------------ untrusted data


@dataclass(frozen=True, slots=True)
class UntrustedMessage:
    """One message read from a room.

    Named for what it is. `sender` is the `from` field, which upstream describes
    as a self-asserted nickname or did:key -- it is a label, not an attribution.
    Only a signature verifying over `<room>|<nonce>|<text>` attributes a message
    to a key, and even that proves key control and nothing more.
    """

    seq: int | None
    ts: str | None
    sender: str | None
    text: str | None
    nonce: int | None
    raw: Mapping[str, Any]


def _as_optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def parse_messages(body: str) -> tuple[UntrustedMessage, ...]:
    """Parse a `format=json` room response defensively.

    Unknown fields are kept in `raw` rather than dropped, and a field of an
    unexpected type becomes None rather than raising: this is someone else's
    service, its shape can change, and a reader that crashes on an added field
    is a reader that stops working the day upstream ships one.
    """
    try:
        document = json.loads(body)
    except json.JSONDecodeError as exc:
        raise MalformedEventError(f"room response is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise MalformedEventError("room response must be a JSON object")

    raw_messages = document.get("messages")
    if not isinstance(raw_messages, list):
        return ()

    out: list[UntrustedMessage] = []
    for item in raw_messages:
        if not isinstance(item, dict):
            continue
        out.append(
            UntrustedMessage(
                seq=_as_optional_int(item.get("seq")),
                ts=item.get("ts") if isinstance(item.get("ts"), str) else None,
                sender=item.get("from") if isinstance(item.get("from"), str) else None,
                text=item.get("text") if isinstance(item.get("text"), str) else None,
                nonce=_as_optional_int(item.get("nonce")),
                raw=dict(item),
            )
        )
    return tuple(out)


def verify_message_signature(*, room: str, nonce: int, text: str, did: str, signature: str) -> bool:
    """Verify a Technocore signed-lane message.

    The preimage is `<room>|<nonce>|<text>` with the text as stored -- already
    swept, since that is what the service holds and what the signer signed.

    The caller supplies the DID and signature explicitly. The JSON field that
    carries the signature was not confirmed while writing this, and guessing a
    field name would produce a verifier that silently reports "unsigned" for
    every signed message. Read them off `UntrustedMessage.raw` once the field is
    confirmed against the live service.

    A True here means one thing: whoever holds that key wrote those bytes in
    that room at that nonce. Not who they are, not that it is true.
    """
    public_key_from_did_key(did)
    return verify_detached(
        public_key_from_did_key(did),
        f"{room}|{nonce}|{text}".encode(),
        b64u_decode(signature),
    )


# ------------------------------------------------------------------ the reader


class TechnocoreReader:
    """Safe-by-default reads. Cannot write, and follows nothing it reads."""

    __slots__ = ("_origin", "_timeout", "_transport")

    def __init__(
        self,
        transport: Transport,
        *,
        origin: str = SERVICE_ORIGIN,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._transport = transport
        self._origin = origin.rstrip("/")
        self._timeout = timeout

    def _get(self, path: str, **query: Any) -> Response:
        url = f"{self._origin}{path}"
        params = {k: v for k, v in query.items() if v is not None}
        if params:
            url = f"{url}?{urlencode(params)}"
        # Every read passes the classifier. A path this table does not recognise
        # is refused rather than fetched, so a route added upstream cannot be
        # called by a reader that has not been updated to understand it.
        assert_safe_to_read(url)
        return self._transport.get(url, timeout=self._timeout)

    def room_raw(
        self, room: str, *, since: int | None = None, limit: int | None = None
    ) -> Response:
        """Fetch a room as plain text."""
        return self._get(f"/r/{quote(check_room(room), safe='')}", since=since, limit=limit)

    def room(
        self, room: str, *, since: int | None = None, limit: int | None = None
    ) -> tuple[UntrustedMessage, ...]:
        """Fetch and parse a room's recent messages. Everything returned is untrusted."""
        response = self._get(
            f"/r/{quote(check_room(room), safe='')}", since=since, limit=limit, format="json"
        )
        if response.rate_limited:
            raise TransportError(
                f"rate limited reading room {room!r}"
                + (f"; retry after {response.retry_after}" if response.retry_after else "")
            )
        if response.status != 200:
            raise TransportError(f"reading room {room!r} returned HTTP {response.status}")
        return parse_messages(response.body)

    def note(self, namespace: str, key: str) -> Response:
        """Read one note. The body is untrusted text and carries no JSON option."""
        return self._get(f"/kv/{quote(namespace, safe='')}/{quote(key, safe='')}")

    def namespace_keys(self, namespace: str) -> Response:
        """List the keys in a namespace."""
        return self._get(f"/kv/{quote(namespace, safe='')}")

    def rooms(self) -> Response:
        """Enumerate rooms. Upstream marks some fields untrusted; so do we, all of them."""
        return self._get("/rooms", format="json")

    def service_metadata(self) -> Mapping[str, Any]:
        """Read the service's own description of its limits."""
        response = self._get("/.well-known/agent.json")
        if response.status != 200:
            raise TransportError(f"service metadata returned HTTP {response.status}")
        try:
            document = json.loads(response.body)
        except json.JSONDecodeError as exc:
            raise MalformedEventError(f"service metadata is not JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise MalformedEventError("service metadata must be a JSON object")
        return document
