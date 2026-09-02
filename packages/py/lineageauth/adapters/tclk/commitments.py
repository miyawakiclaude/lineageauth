"""The commit-reveal vote of `SPEC.md` section 8.3, verification half only.

`voteCommitment(contract, verdict, salt) = 0x + sha256("FLOP::tclk::v1|commit|"
+ contract + "|" + verdict + "|" + salt)`. The contract id is inside the hash so
a juror's sealed verdict cannot be lifted into another deal; the salt is what
seals it, because verdicts come from a set of about two.

This lets a LineageAuth reader re-check a vote round from an exported room
transcript. It does not split or combine secrets (`SPEC.md` section 8.2) --
that is custody of a payment secret, and this integration holds none.
"""

from __future__ import annotations

import hashlib

from lineageauth.adapters.tclk.frames import HEX32, TCLK_DOMAIN, FrameError


def vote_commitment(contract: str, verdict: str, salt: str) -> str:
    if not isinstance(contract, str) or not HEX32.match(contract):
        raise FrameError("tclk: contract must be a 0x-hex contract id")
    if not isinstance(verdict, str) or not verdict:
        raise FrameError("tclk: verdict must not be empty")
    if "|" in verdict:
        raise FrameError("tclk: verdict must not contain '|'")
    if not isinstance(salt, str) or not HEX32.match(salt):
        raise FrameError("tclk: salt must be 32 bytes of 0x-hex")
    payload = f"{TCLK_DOMAIN}|commit|{contract}|{verdict}|{salt}".encode()
    return "0x" + hashlib.sha256(payload).hexdigest()


def verify_vote_commitment(commitment: str, contract: str, verdict: str, salt: str) -> bool:
    """Fail-closed: a malformed reveal is a mismatch, never a raise."""
    if not isinstance(commitment, str):
        return False
    try:
        return vote_commitment(contract, verdict, salt) == commitment.lower()
    except FrameError:
        return False


__all__ = ["verify_vote_commitment", "vote_commitment"]
