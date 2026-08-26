"""Shared fixtures.

The verification time is always passed explicitly. docs/02_LAP_CORE.md requires
that the same event set at the same stated time produce the same result, so no
test may depend on the wall clock.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from lineageauth.builders import build_root_create, sign_payload
from lineageauth.crypto import LocalSigner
from lineageauth.envelope import Envelope
from tests.testkeys import ROOT_A, unsafe_signer

FIXED_ISSUED_AT = datetime(2026, 8, 26, 9, 0, 0, tzinfo=UTC)


@pytest.fixture
def issued_at() -> datetime:
    return FIXED_ISSUED_AT


@pytest.fixture
def root_a() -> LocalSigner:
    """UNSAFE deterministic test key. See tests/testkeys.py."""
    return unsafe_signer(ROOT_A)


@pytest.fixture
def root_create_payload(root_a: LocalSigner, issued_at: datetime) -> dict[str, Any]:
    return build_root_create(root_did=root_a.did, issued_at=issued_at)


@pytest.fixture
def root_create_event(root_create_payload: dict[str, Any], root_a: LocalSigner) -> Envelope:
    return sign_payload(root_create_payload, [root_a])
