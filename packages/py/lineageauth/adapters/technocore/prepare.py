"""Dry-run preparation of a Technocore write. Nothing here sends anything.

`docs/18_TECHNOCORE.md` gives the adapter three modes -- read-only, prepare,
and publish -- and only the first two are implemented. Prepare builds the exact
route, the exact bytes, and the DID that would be used, and then stops. Turning
that into a request is a separate act that needs a human's explicit confirmation
or a valid exact-action approval, which is what `lineageauth.approval` is for.

The value of stopping here is that the `ActionRequest` produced is the same
object an approval binds to. The human sees the swept text and the destination;
the receipt commits to a hash of those exact bytes; the executor can compare
what it is about to send against what was approved. There is no step where a
preview and a payload can drift apart, because they are computed from one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from lineageauth.actions import ActionRequest, sha256_hex
from lineageauth.adapters.technocore.routes import (
    SERVICE_ORIGIN,
    Consequence,
    classify,
)
from lineageauth.adapters.technocore.text import SignedMessage, build_signed_message
from lineageauth.crypto import LocalSigner
from lineageauth.errors import MalformedEventError

# Upstream's URL budget for a GET write. Long text in non-Latin scripts hits
# this well before the character limit -- one CJK character costs 9 bytes
# percent-encoded, one emoji 12 -- and the answer then is POST, not truncation.
MAX_URL_BYTES = 16 * 1024

ANNOUNCE_PREFIX = "LINEAGEAUTH/0.1"


@dataclass(frozen=True, slots=True)
class PreparedWrite:
    """Everything needed to perform a write, and nothing that performs it."""

    url: str
    method: str
    message: SignedMessage
    signer_did: str
    signature: str
    request: ActionRequest

    @property
    def consequence(self) -> Consequence:
        return classify(self.url, method=self.method).consequence

    def preview(self) -> str:
        """What a human should be shown before consenting.

        The swept text, not the caller's text: those are the bytes that will be
        stored and signed, and showing anything else would be showing something
        other than the thing being approved.
        """
        lines = [
            "Technocore write (NOT SENT)",
            f"  destination  {self.url}",
            f"  method       {self.method}",
            f"  room         {self.message.room}",
            f"  signer       {self.signer_did}",
            f"  nonce        {self.message.nonce}",
            f"  text         {self.message.text!r}",
            f"  contentHash  {self.request.content_hash}",
            f"  requestHash  {self.request.request_hash}",
        ]
        if self.message.was_swept:
            lines.append(
                "  note         the text was altered by Technocore's single-line "
                "sweep; the swept form above is what would be stored"
            )
        return "\n".join(lines)


def _encode_segment(value: str) -> str:
    """Percent-encode one path segment.

    `safe=""` on purpose. Leaving `/` unescaped would let text containing a
    slash add path segments and change which route the URL names -- turning a
    message into a different operation entirely.
    """
    return quote(value, safe="")


def prepare_signed_message(
    *,
    room: str,
    text: str,
    nonce: int,
    signer: LocalSigner,
    origin: str = SERVICE_ORIGIN,
) -> PreparedWrite:
    """Build -- but do not send -- a signed-lane message.

    The signature covers `<room>|<nonce>|<swept text>`, which is upstream's
    preimage and not this protocol's; a LineageAuth event signature would not
    verify here and vice versa. Keeping the two apart is deliberate: a signature
    that verified under two different specifications would be a signature whose
    meaning depends on who is reading it.
    """
    message = build_signed_message(room=room, nonce=nonce, text=text)
    signature = signer.sign_b64u(message.signing_bytes)

    url = (
        f"{origin}/r/{_encode_segment(message.room)}/say-signed/"
        f"{_encode_segment(signer.did)}/{_encode_segment(signature)}/"
        f"{message.nonce}/{_encode_segment(message.text)}"
    )
    if len(url.encode()) > MAX_URL_BYTES:
        raise MalformedEventError(
            f"the prepared URL is {len(url.encode())} bytes, over Technocore's "
            f"~{MAX_URL_BYTES} byte budget; this text needs the POST form"
        )

    classification = classify(url)
    if classification.consequence is not Consequence.WRITE:
        # A prepared write that the route table does not recognise as a write is
        # a bug in one of the two, and either way the safe move is to stop.
        raise MalformedEventError(
            f"prepared a write whose URL classifies as {classification.consequence}: "
            f"{classification.detail}"
        )

    request = ActionRequest(
        namespace="technocore",
        resource=f"room:{message.room}",
        action="write",
        destination=f"{origin}/r/{message.room}",
        # The stored bytes, which are also the signed bytes. Hashing the
        # caller's original text would bind an approval to something other than
        # what Technocore ends up holding.
        content_hash=sha256_hex(message.text.encode()),
    )
    return PreparedWrite(
        url=url,
        method="GET",
        message=message,
        signer_did=signer.did,
        signature=signature,
        request=request,
    )


def format_announcement(*, event_type: str, lineage: str, event_id: str, url: str = "") -> str:
    """Format the single-line announcement from `docs/18`.

    The URL is discovery data. Anyone reading this line -- a person or an agent
    -- is receiving untrusted content, and a URL inside it is never an
    instruction to fetch anything.
    """
    parts = [ANNOUNCE_PREFIX, event_type, f"lineage={lineage}", f"event={event_id}"]
    if url:
        parts.append(f"url={url}")
    line = " ".join(parts)
    if "\n" in line or "\r" in line:  # pragma: no cover - defensive
        raise MalformedEventError("an announcement must be a single line")
    return line
