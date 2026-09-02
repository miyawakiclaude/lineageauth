"""tclk/1 wire frames: canonical bytes, ids, and a strict decoder.

Ported from `SPEC.md` section 3 and `src/frames.ts` of flop-labs/tclk at
commit `81a8346` (v0.1.0, read 2026-09-02). The golden vectors that
repository pins are reproduced byte for byte by `tests/test_tclk.py`, from
`conformance/tclk/golden-vectors.json`; if they ever stop matching, this
port is wrong, never the vector.

Canonical form: object keys sorted, `,`/`:` separators, every non-ASCII
character `\\uXXXX`-escaped. That is exactly `json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=True)`, which is why this module has no
canonicaliser of its own. The id of a frame hashes the *escaped* form -- the
bytes the wire carries -- and the domain tag `FLOP::tclk::v1` in front of it.

Three states are kept apart on purpose, because collapsing them is how a room
message becomes a deal:

    a line that starts with `tclk1 `        -- looks like a frame
    a Frame                                  -- PARSED and structurally VALID
    a state transition that applied          -- see machine.py
    an agent entitled to post it             -- see authority.py

Where this decoder is stricter than the reference it says so: the reference
accepts a non-canonical line and a JSON object with duplicate keys (last one
wins); this refuses both. Every frame the reference *emits* is canonical, so
the difference bites only hand-built lines, and fail-closed is the rule here.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NoReturn

from lineageauth.adapters.tclk.locks import LOCK_KINDS, is_valid_point_statement
from lineageauth.errors import MalformedEventError

TCLK_VERSION = "tclk/1"
TCLK_PREFIX = "tclk1 "
TCLK_DOMAIN = "FLOP::tclk::v1"
MAX_FRAME_CHARS = 4096
"""Technocore's message cap: a frame must fit one single-line room message."""

FRAME_TYPES: tuple[str, ...] = (
    "offer",
    "accept",
    "lock",
    "reveal",
    "refund",
    "cancel",
    "receipt",
)
ROLES: frozenset[str] = frozenset({"payer", "payee"})
OUTCOMES: frozenset[str] = frozenset({"claimed", "refunded", "cancelled"})

# Field shapes, verbatim from the reference.
HEX32 = re.compile(r"^0x[0-9a-f]{64}$")
HEX33 = re.compile(r"^0x[0-9a-f]{66}$")
DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
AMOUNT = re.compile(r"^[1-9][0-9]*$")
ASSET = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
RAIL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
NONCE = re.compile(r"^[0-9a-f]{8,64}$")
SCALAR_HEX = re.compile(r"^0x[0-9a-f]{1,64}$")
JOB_PROTO = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
STATEMENT = re.compile(r"^0x(?:[0-9a-f]{64}|[0-9a-f]{66})$")
_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]*$")
_VERSIONED_PREFIX = re.compile(r"^tclk([0-9]+) ")

# JavaScript's Number.isSafeInteger bound; the reference requires it of every ms.
_MAX_SAFE_INTEGER = 2**53 - 1

_KEYS: dict[str, tuple[frozenset[str], tuple[str, ...]]] = {
    "offer": (
        frozenset(
            {
                "type",
                "from",
                "role",
                "amount",
                "asset",
                "lock",
                "rails",
                "claimByMs",
                "refundAfterMs",
                "expiresMs",
                "paymentKey",
                "job",
                "nonce",
                "id",
            }
        ),
        (
            "from",
            "role",
            "amount",
            "asset",
            "lock",
            "rails",
            "claimByMs",
            "refundAfterMs",
            "expiresMs",
            "nonce",
            "id",
        ),
    ),
    "accept": (
        frozenset({"type", "from", "ref", "statement", "contract", "paymentKey", "nonce"}),
        ("from", "ref", "statement", "contract", "nonce"),
    ),
    "lock": (
        frozenset({"type", "from", "contract", "rail", "ref", "presig"}),
        ("from", "contract", "rail", "ref"),
    ),
    "reveal": (frozenset({"type", "from", "contract", "secret"}), ("from", "contract", "secret")),
    "refund": (frozenset({"type", "from", "contract", "reason"}), ("from", "contract")),
    "cancel": (frozenset({"type", "from", "contract", "reason"}), ("from", "contract")),
    "receipt": (
        frozenset({"type", "from", "contract", "outcome", "rail", "ref"}),
        ("from", "contract", "outcome"),
    ),
}


class FrameError(MalformedEventError):
    """A line that is not a valid tclk/1 frame. Carries the reference's wording."""


def _fail(message: str) -> NoReturn:
    raise FrameError(f"tclk: {message}")


# ── Canonical encoding and ids ───────────────────────────────────────────────


def canonical_json(value: object) -> str:
    """Sorted keys, compact separators, non-ASCII escaped. The wire form."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise FrameError(f"tclk: frame contains an unsupported value: {exc}") from exc


def domain_hash(tag: str, payload: str) -> str:
    """`0x` + sha256 over `FLOP::tclk::v1|<tag>|<payload>`."""
    return "0x" + hashlib.sha256(f"{TCLK_DOMAIN}|{tag}|{payload}".encode()).hexdigest()


def offer_id(fields: Mapping[str, Any]) -> str:
    """The offer id: over the canonical offer fields without `id`."""
    body = {key: value for key, value in fields.items() if key != "id"}
    return domain_hash("offer", canonical_json(body))


def accept_core(accept: Mapping[str, Any]) -> dict[str, Any]:
    """The accept fields the contract id commits to."""
    core: dict[str, Any] = {
        "from": accept["from"],
        "ref": accept["ref"],
        "statement": accept["statement"],
        "nonce": accept["nonce"],
    }
    if "paymentKey" in accept:
        core["paymentKey"] = accept["paymentKey"]
    return core


def contract_id(offer: Mapping[str, Any], core: Mapping[str, Any]) -> str:
    """The contract id: over the canonical `{offer, accept}` pair, offer id included."""
    return domain_hash("contract", canonical_json({"offer": dict(offer), "accept": dict(core)}))


# ── Structural validation (fail-closed) ──────────────────────────────────────


def _require_string(value: object, name: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{name} must be a non-empty string")
    assert isinstance(value, str)
    if pattern is not None and not pattern.match(value):
        _fail(f"{name} is malformed: {value}")
    return value


def _require_ms(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{name} must be a positive unix-ms integer")
    assert isinstance(value, int)
    if value <= 0 or value > _MAX_SAFE_INTEGER:
        _fail(f"{name} must be a positive unix-ms integer")
    return value


def _require_keys(
    record: Mapping[str, Any], allowed: frozenset[str], required: tuple[str, ...], label: str
) -> None:
    for key in record:
        if key not in allowed:
            _fail(f"unknown field on {label}: {key}")
    for key in required:
        if key not in record:
            _fail(f"missing field on {label}: {key}")


def _validate_payment_key(value: object, name: str) -> str:
    key = _require_string(value, name, HEX33)
    if not is_valid_point_statement(key):
        _fail(f"{name} is not a valid secp256k1 point")
    return key


def _validate_job(value: object) -> None:
    if not isinstance(value, Mapping):
        _fail("job must be an object")
    assert isinstance(value, Mapping)
    _require_keys(value, frozenset({"proto", "id", "context"}), ("proto", "id"), "job")
    _require_string(value.get("proto"), "job.proto", JOB_PROTO)
    _require_string(value.get("id"), "job.id")
    if "context" in value:
        _require_string(value.get("context"), "job.context")


def validate_frame(value: object) -> dict[str, Any]:
    """Validate one frame structurally. Raises `FrameError` on the first violation.

    Returns a plain dict copy of the frame. A `paymentKey` is checked to lie on
    the curve, an offer's `id` is recomputed and compared, and for a `point`
    lock the offer must carry a payment key -- all as the reference does.
    """
    if not isinstance(value, Mapping):
        _fail("frame must be an object")
    assert isinstance(value, Mapping)
    frame: dict[str, Any] = dict(value)
    kind = frame.get("type")
    if not isinstance(kind, str) or kind not in _KEYS:
        _fail(f"unknown frame type: {kind!r}")
    assert isinstance(kind, str)
    allowed, required = _KEYS[kind]
    _require_keys(frame, allowed, required, kind)
    _require_string(frame.get("from"), "from", DID)

    if kind == "offer":
        if frame.get("role") not in ROLES:
            _fail("role must be payer|payee")
        _require_string(frame.get("amount"), "amount", AMOUNT)
        _require_string(frame.get("asset"), "asset", ASSET)
        if frame.get("lock") not in LOCK_KINDS:
            _fail("lock must be hash|point")
        rails = frame.get("rails")
        if not isinstance(rails, list) or not rails:
            _fail("rails must be a non-empty array")
        assert isinstance(rails, list)
        for rail in rails:
            _require_string(rail, "rail", RAIL)
        claim_by = _require_ms(frame.get("claimByMs"), "claimByMs")
        refund_after = _require_ms(frame.get("refundAfterMs"), "refundAfterMs")
        _require_ms(frame.get("expiresMs"), "expiresMs")
        if claim_by >= refund_after:
            _fail("claimByMs must be strictly before refundAfterMs")
        if "paymentKey" in frame:
            _validate_payment_key(frame["paymentKey"], "paymentKey")
        if frame["lock"] == "point" and "paymentKey" not in frame:
            _fail("point locks require paymentKey")
        if "job" in frame:
            _validate_job(frame["job"])
        _require_string(frame.get("nonce"), "nonce", NONCE)
        expected = offer_id(frame)
        if frame.get("id") != expected:
            _fail(f"offer id mismatch (expected {expected})")
    elif kind == "accept":
        _require_string(frame.get("ref"), "ref", HEX32)
        _require_string(frame.get("statement"), "statement", STATEMENT)
        _require_string(frame.get("contract"), "contract", HEX32)
        if "paymentKey" in frame:
            _validate_payment_key(frame["paymentKey"], "paymentKey")
        _require_string(frame.get("nonce"), "nonce", NONCE)
    elif kind == "lock":
        _require_string(frame.get("contract"), "contract", HEX32)
        _require_string(frame.get("rail"), "rail", RAIL)
        _require_string(frame.get("ref"), "ref")
        if "presig" in frame:
            presig = frame["presig"]
            if not isinstance(presig, Mapping):
                _fail("presig must be an object")
            assert isinstance(presig, Mapping)
            _require_keys(presig, frozenset({"nonce", "s"}), ("nonce", "s"), "presig")
            _require_string(presig.get("nonce"), "presig.nonce", HEX33)
            scalar = _require_string(presig.get("s"), "presig.s", SCALAR_HEX)
            # Stricter than the reference regex, which admits an odd digit count
            # that its own hex decoder then throws on (its PR #24 closes the same
            # gap). Refusing here can only reject a value nothing could decode.
            if len(scalar) % 2 != 0:
                _fail("presig.s is malformed: odd number of hex digits")
    elif kind == "reveal":
        _require_string(frame.get("contract"), "contract", HEX32)
        _require_string(frame.get("secret"), "secret", HEX32)
    elif kind in ("refund", "cancel"):
        _require_string(frame.get("contract"), "contract", HEX32)
        if "reason" in frame:
            _require_string(frame.get("reason"), "reason")
    else:  # receipt
        _require_string(frame.get("contract"), "contract", HEX32)
        if frame.get("outcome") not in OUTCOMES:
            _fail("outcome must be claimed|refunded|cancelled")
        if "rail" in frame:
            _require_string(frame.get("rail"), "rail", RAIL)
        if "ref" in frame:
            _require_string(frame.get("ref"), "ref")
    return frame


# ── Line codec ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Frame:
    """A structurally valid tclk/1 frame and the canonical line that carries it.

    Being a `Frame` says the bytes parse and the fields are well-formed. It
    says nothing about whether the transition applies, whether the sender
    was entitled to post it, or whether any money exists behind it.
    """

    kind: str
    fields: Mapping[str, Any]
    line: str

    @property
    def sender(self) -> str:
        return str(self.fields["from"])

    @property
    def contract(self) -> str | None:
        """The contract id this frame names; None for an offer."""
        value = self.fields.get("contract")
        return str(value) if isinstance(value, str) else None

    def as_dict(self) -> dict[str, Any]:
        return dict(self.fields)


def is_tclk_line(text: str) -> bool:
    return isinstance(text, str) and text.startswith(TCLK_PREFIX)


def version_of_line(text: str) -> str | None:
    """`tclk/<n>` for a line carrying any tclk version prefix, else None."""
    match = _VERSIONED_PREFIX.match(text) if isinstance(text, str) else None
    return f"tclk/{match.group(1)}" if match else None


def encode_frame(value: Mapping[str, Any]) -> str:
    """Validate a frame and encode it to its room-message line."""
    line = TCLK_PREFIX + canonical_json(validate_frame(value))
    if len(line) > MAX_FRAME_CHARS:
        _fail(f"frame exceeds the {MAX_FRAME_CHARS}-char room-message cap ({len(line)})")
    if not _PRINTABLE_ASCII.match(line):
        _fail("frame line contains non-printable-ASCII characters")
    return line


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            _fail(f"duplicate key in frame: {key}")
        out[key] = value
    return out


def decode_frame(text: str, *, strict_canonical: bool = True) -> Frame:
    """Decode a room-message line into a `Frame`, or raise `FrameError`.

    `strict_canonical` refuses a line whose bytes differ from the canonical
    encoding of the frame they carry. The reference accepts such a line; this
    refuses it by default because the bytes a transport signature covers must
    be the bytes a reader reasons about, and a non-canonical line is one whose
    author did not use a conforming encoder.
    """
    if not isinstance(text, str):
        _fail("frame must be a string")
    if not is_tclk_line(text):
        seen = version_of_line(text)
        if seen is not None and seen != TCLK_VERSION:
            _fail(f"unsupported version prefix {seen}; this reader speaks {TCLK_VERSION} only")
        _fail("not a tclk/1 line")
    if len(text) > MAX_FRAME_CHARS:
        _fail(f"frame exceeds the {MAX_FRAME_CHARS}-char room-message cap ({len(text)})")
    if not _PRINTABLE_ASCII.match(text):
        _fail("frame line contains non-printable-ASCII characters")
    try:
        parsed = json.loads(text[len(TCLK_PREFIX) :], object_pairs_hook=_no_duplicate_keys)
    except json.JSONDecodeError:
        _fail("frame is not valid JSON")
    fields = validate_frame(parsed)
    line = TCLK_PREFIX + canonical_json(fields)
    if strict_canonical and line != text:
        _fail("frame line is not canonical; re-encode it with a conforming encoder")
    return Frame(kind=str(fields["type"]), fields=fields, line=line)


def try_decode_frame(text: str, *, strict_canonical: bool = True) -> Frame | None:
    """None for non-tclk lines and for malformed tclk lines. For folding a room."""
    try:
        return decode_frame(text, strict_canonical=strict_canonical)
    except MalformedEventError:
        return None


__all__ = [
    "AMOUNT",
    "ASSET",
    "DID",
    "FRAME_TYPES",
    "HEX32",
    "HEX33",
    "MAX_FRAME_CHARS",
    "NONCE",
    "OUTCOMES",
    "RAIL",
    "ROLES",
    "TCLK_DOMAIN",
    "TCLK_PREFIX",
    "TCLK_VERSION",
    "Frame",
    "FrameError",
    "accept_core",
    "canonical_json",
    "contract_id",
    "decode_frame",
    "domain_hash",
    "encode_frame",
    "is_tclk_line",
    "offer_id",
    "try_decode_frame",
    "validate_frame",
    "version_of_line",
]
