"""Technocore's single-line sweep, and the bytes its signed lane actually covers.

This module exists because of one sentence in the upstream specification:

    The signature covers exactly `<room>|<nonce>|<text>` as UTF-8, where <text>
    is the text AFTER the single-line sweep -- the bytes that get stored.

That makes the sweep part of the security boundary rather than a display
detail. `docs/06_APPROVAL_EXECUTION.md` requires every adapter to state which
bytes it hashes, and here the answer must be the swept text: hashing what the
caller typed would mean a human approves one string while a different one is
stored and signed.

    caller's text ---sweep---> stored text ---hash---> what the human approves

The sweep as documented upstream (checked 2026-08-26): every invisible
character -- C0/C1 controls including newline, format characters, zero-width
joiners, bidi overrides -- is replaced with a space before storage.

*This is a reimplementation from prose, not a shared library with the server.*
If upstream's sweep and this one ever disagree, an approval would bind bytes
that differ from the ones stored. Nothing in this package performs a live
write, so a divergence cannot cause an unapproved effect on its own -- but it
would silently weaken every approval that depends on it, so the equivalence
must be checked against the running service before writing is ever enabled.
That check is not automated here, and saying so is the point: an untested
assumption in the middle of a security boundary should be visible, not implied.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from lineageauth.errors import MalformedEventError

# Upstream limits, checked 2026-08-26.
MAX_MESSAGE_CHARS = 4096
MAX_NOTE_CHARS = 8192

# Nonces are decimal strings of 1-19 digits, strictly increasing per key per
# room. Not a timestamp, not random: the ordering is the replay defence.
MAX_NONCE = 10**19 - 1

SWEPT_REPLACEMENT = " "

# Categories swept to a space. `Cc` is C0 and C1 (newline, DEL, and friends);
# `Cf` covers format characters -- zero-width joiners, bidi overrides, the byte
# order mark, soft hyphen. Both are named in the upstream description.
_SWEPT_CATEGORIES = frozenset({"Cc", "Cf"})

# `Cs` (surrogates) cannot appear in well-formed text and would fail to encode
# as UTF-8 at all, so they are rejected rather than swept.
_SURROGATE_CATEGORY = "Cs"


def is_swept(character: str) -> bool:
    """True when the sweep would replace this character with a space."""
    return unicodedata.category(character) in _SWEPT_CATEGORIES


def sweep(text: str) -> str:
    """Apply Technocore's single-line sweep.

    One character in, one character out -- runs of spaces are not collapsed,
    because upstream describes a replacement and not a normalisation.
    """
    if not isinstance(text, str):
        raise MalformedEventError("message text must be a string")
    out: list[str] = []
    for character in text:
        category = unicodedata.category(character)
        if category == _SURROGATE_CATEGORY:
            raise MalformedEventError(
                "text contains an unpaired surrogate and cannot be encoded as UTF-8"
            )
        out.append(SWEPT_REPLACEMENT if category in _SWEPT_CATEGORIES else character)
    return "".join(out)


def check_nonce(nonce: object) -> int:
    """Validate a Technocore nonce and return it as an integer."""
    if isinstance(nonce, bool) or not isinstance(nonce, int):
        raise MalformedEventError("a Technocore nonce must be an integer")
    if not 0 <= nonce <= MAX_NONCE:
        raise MalformedEventError(f"a Technocore nonce must be 1-19 digits, got {nonce}")
    return nonce


def check_room(room: object) -> str:
    """Validate a room name.

    Deliberately narrow. A room name is interpolated into a URL path and shown
    to a human in an approval preview, so anything that could change how either
    reads -- a slash, a percent, whitespace, an invisible -- is refused rather
    than escaped.
    """
    if not isinstance(room, str) or not room:
        raise MalformedEventError("a Technocore room name must be a non-empty string")
    if len(room) > 128:
        raise MalformedEventError("a Technocore room name is limited to 128 characters")
    if room in (".", ".."):
        # Legal under the alphabet below, but a room named `..` reads as a path
        # element wherever a URL is displayed or joined.
        raise MalformedEventError(f"{room!r} is a relative path element, not a room name")
    for character in room:
        if character.isalnum() and character.isascii():
            continue
        if character in "-_.":
            continue
        raise MalformedEventError(
            f"room name contains {character!r}; only ASCII letters, digits, and -_. are "
            "accepted, so that a name cannot disguise itself in a URL or a preview"
        )
    return room


@dataclass(frozen=True, slots=True)
class SignedMessage:
    """A Technocore signed-lane message, reduced to exactly what gets signed."""

    room: str
    nonce: int
    text: str
    """The text after the sweep. This is what is stored and what is signed."""

    original_text: str
    """What the caller supplied, kept only so a preview can show the difference."""

    @property
    def was_swept(self) -> bool:
        """True when the sweep changed the text.

        Worth surfacing in an approval preview: it means the bytes about to be
        stored are not the bytes the caller wrote.
        """
        return self.text != self.original_text

    @property
    def signing_bytes(self) -> bytes:
        """`<room>|<nonce>|<text>` as UTF-8 -- upstream's signed preimage."""
        return f"{self.room}|{self.nonce}|{self.text}".encode()


def build_signed_message(*, room: str, nonce: int, text: str) -> SignedMessage:
    """Prepare a signed-lane message without sending anything."""
    room = check_room(room)
    nonce = check_nonce(nonce)
    swept = sweep(text)
    if not swept.strip():
        # `.strip()`, not a truthiness check. The sweep turns invisibles into
        # spaces, so text made entirely of zero-width joiners or newlines
        # survives as a run of blanks: visually empty, but it was carrying
        # something, and signing it would attest to a message nobody can read.
        raise MalformedEventError(
            "message text is empty after the single-line sweep; it contained nothing "
            "but whitespace and invisible characters"
        )
    if len(swept) > MAX_MESSAGE_CHARS:
        raise MalformedEventError(
            f"message is {len(swept)} characters after the sweep; the limit is {MAX_MESSAGE_CHARS}"
        )
    return SignedMessage(room=room, nonce=nonce, text=swept, original_text=text)


def note_signing_bytes(*, namespace: str, key: str, nonce: int, value: str) -> bytes:
    """`<namespace>|<key>|<nonce>|<value>` as UTF-8 -- the note signed preimage.

    A different shape from messages, which is exactly why it gets its own
    function: reusing the message preimage for a note would produce a signature
    over the wrong bytes, and it would still look plausible.
    """
    check_nonce(nonce)
    swept = sweep(value)
    if len(swept) > MAX_NOTE_CHARS:
        raise MalformedEventError(
            f"note value is {len(swept)} characters after the sweep; the limit is {MAX_NOTE_CHARS}"
        )
    return f"{namespace}|{key}|{nonce}|{swept}".encode()
