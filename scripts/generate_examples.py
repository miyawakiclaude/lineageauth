"""Regenerate the example envelopes in `examples/`.

Run: `uv run python scripts/generate_examples.py`

The output is deterministic -- fixed UNSAFE test keys and a fixed issuance
time -- so regenerating produces byte-identical files and a diff means a real
protocol change. These files double as the first conformance vectors
(docs/23_TESTING.md).

!! The keys behind these signatures are public and reproducible. Nothing here
!! is safe key material and none of these DIDs may be used for anything real.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "packages" / "py"))

from tests.testkeys import (  # noqa: E402
    AGENT_1,
    RECOVERY_1,
    RECOVERY_2,
    RECOVERY_3,
    ROOT_A,
    ROOT_B,
    unsafe_signer,
)

from lineageauth.builders import (  # noqa: E402
    NORMAL_SUCCESSION,
    RECOVERY_SUCCESSION,
    build_delegation_grant,
    build_delegation_revoke,
    build_recovery_policy,
    build_root_create,
    build_root_succession,
    sign_payload,
)
from lineageauth.envelope import Envelope  # noqa: E402
from lineageauth.identifiers import derive_lineage_id  # noqa: E402

EXAMPLES = REPO_ROOT / "examples"
ISSUED_AT = datetime(2026, 8, 26, 9, 0, 0, tzinfo=UTC)
RECOVERED_AT = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
EXPIRES_AT = datetime(2027, 8, 26, 9, 0, 0, tzinfo=UTC)


def write_bundle(name: str, envelopes: list[Envelope]) -> None:
    """Write several envelopes as one JSON array, ready for `la check`."""
    document = [json.loads(envelope.to_json()) for envelope in envelopes]
    write(name, json.dumps(document, indent=2, ensure_ascii=False))


def write(name: str, envelope_json: str) -> None:
    # newline="\n" is required, not cosmetic. The platform default would write
    # CRLF on Windows, so the same generator would produce different bytes on
    # different machines and the determinism check would fail depending on who
    # ran it. These files are signed material; their bytes are the point.
    path = EXAMPLES / name
    path.write_text(envelope_json + "\n", encoding="utf-8", newline="\n")
    print(f"wrote examples/{name}")


def main() -> None:
    EXAMPLES.mkdir(exist_ok=True)

    root_a = unsafe_signer(ROOT_A)
    root_b = unsafe_signer(ROOT_B)
    recovery = [unsafe_signer(label) for label in (RECOVERY_1, RECOVERY_2, RECOVERY_3)]
    lineage = derive_lineage_id(root_a.did)

    root_create = sign_payload(
        build_root_create(root_did=root_a.did, issued_at=ISSUED_AT), [root_a]
    )
    write("root-create.json", root_create.to_json())

    policy = sign_payload(
        build_recovery_policy(
            lineage=lineage,
            epoch=0,
            policy_seq=1,
            members=[signer.did for signer in recovery],
            threshold=2,
            issued_at=ISSUED_AT,
        ),
        [root_a],
    )
    write("recovery-policy.json", policy.to_json())

    # Recovery succession: root A is lost, two of three recovery keys install
    # root B. The lineage identifier does not change -- that is the continuity
    # the protocol exists to provide.
    succession = sign_payload(
        build_root_succession(
            lineage=lineage,
            from_root=root_a.did,
            to_root=root_b.did,
            from_epoch=0,
            mode=RECOVERY_SUCCESSION,
            recovery_policy_ref=policy.event_id,
            issued_at=RECOVERED_AT,
        ),
        recovery[:2],
    )
    write("root-succession-recovery.json", succession.to_json())

    normal = sign_payload(
        build_root_succession(
            lineage=lineage,
            from_root=root_a.did,
            to_root=root_b.did,
            from_epoch=0,
            mode=NORMAL_SUCCESSION,
            issued_at=RECOVERED_AT,
        ),
        [root_a],
    )
    write("root-succession-normal.json", normal.to_json())

    # A tampered copy, for demonstrating that verification actually fails.
    tampered = root_create.model_copy(deep=True)
    tampered.payload["epoch"] = 1
    write("tampered-root-create.json", tampered.to_json())

    # Demo A from docs/26_LAUNCH_ADOPTION.md: root delegates a Technocore write,
    # the agent is authorized, the grant is revoked, the agent is denied.
    agent = unsafe_signer(AGENT_1)
    grant = sign_payload(
        build_delegation_grant(
            lineage=lineage,
            issuer=root_a.did,
            subject=agent.did,
            epoch=0,
            scopes=[
                {
                    "namespace": "technocore",
                    "resource": "room:lobby",
                    "actions": ["read", "write"],
                }
            ],
            not_before=ISSUED_AT,
            expires_at=EXPIRES_AT,
            max_depth=0,
            approval="none",
            issued_at=ISSUED_AT,
        ),
        [root_a],
    )
    revocation = sign_payload(
        build_delegation_revoke(
            lineage=lineage,
            issuer=root_a.did,
            grant=grant.event_id,
            reason="agent key rotated",
            issued_at=RECOVERED_AT,
        ),
        [root_a],
    )
    write_bundle("delegation-allowed.json", [root_create, grant])
    write_bundle("delegation-revoked.json", [root_create, grant, revocation])

    print()
    print(f"lineage      {lineage}")
    print(f"root A       {root_a.did}")
    print(f"root B       {root_b.did}")
    print(f"agent        {agent.did}")
    print(f"root.create  {root_create.event_id}")
    print(f"grant        {grant.event_id}")


if __name__ == "__main__":
    main()
