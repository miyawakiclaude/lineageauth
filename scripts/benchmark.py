"""Measure what verification costs, so deployment choices stop being guesses.

Run: `uv run python scripts/benchmark.py`

`infra/scale-design.md` names verification CPU as the bottleneck. This produces
the number, because "probably fine" is not an input to a spending decision.

The comparison column is against **10 ms**, which is the CPU budget a Cloudflare
Worker gets per invocation on the free plan (checked 2026-08-27). That is the
one figure that decides whether a public verify endpoint is possible at zero
cost, and it was carried as an unmeasured caveat for too long.

Measured on native CPython with `cryptography` backed by Rust. Any WebAssembly
runtime will be **slower**, so treat every number here as a floor rather than an
estimate.

Not a microbenchmark of Ed25519. It measures the operations a request actually
performs, which is the thing that has to fit.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "packages" / "py"))

from tests.testkeys import AGENT_1, ROOT_A, unsafe_signer  # noqa: E402

from lineageauth.authority import check_permission  # noqa: E402
from lineageauth.builders import (  # noqa: E402
    build_delegation_grant,
    build_root_create,
    sign_payload,
)
from lineageauth.bundle import EventBundle  # noqa: E402
from lineageauth.envelope import Envelope  # noqa: E402
from lineageauth.identifiers import derive_lineage_id  # noqa: E402
from lineageauth.verify import verify_event  # noqa: E402

# The free-plan CPU budget for one Cloudflare Worker invocation, checked
# 2026-08-27. Recorded here rather than in prose so the comparison cannot drift
# away from the number it is comparing against.
WORKER_CPU_BUDGET_MS = 10.0

AT = datetime(2026, 8, 27, 12, tzinfo=UTC)
ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
LINEAGE = derive_lineage_id(ROOT.did)


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(n: int) -> Envelope:
    payload = build_delegation_grant(
        lineage=LINEAGE,
        issuer=ROOT.did,
        subject=AGENT.did,
        epoch=0,
        scopes=[{"namespace": "technocore", "resource": f"room:r{n}", "actions": ["write"]}],
        not_before=AT - timedelta(days=1),
        expires_at=AT + timedelta(days=30),
        max_depth=0,
        issued_at=AT,
    )
    return sign_payload(payload, [ROOT])


def timed(call: Callable[[], object], runs: int) -> float:
    call()  # warm the import and any lazy state
    start = time.perf_counter()
    for _ in range(runs):
        call()
    return (time.perf_counter() - start) / runs * 1000.0


def report(label: str, ms: float) -> None:
    share = ms / WORKER_CPU_BUDGET_MS * 100
    verdict = "fits" if share <= 100 else "OVER"
    print(f"{label:<46}{ms:>9.3f} ms{share:>9.1f}%  {verdict}")


def main() -> int:
    print(f"Budget for comparison: {WORKER_CPU_BUDGET_MS} ms of CPU per request")
    print("Native CPython. Any WebAssembly runtime is slower, so these are floors.\n")
    print(f"{'operation':<46}{'cost':>12}{'of budget':>10}")
    print("-" * 78)

    report("verify one event (single proof)", timed(lambda: verify_event(genesis()), 300))

    for size in (10, 50, 200):
        envelopes = [genesis(), *(grant(i) for i in range(size))]
        report(
            f"admit a bundle of {size + 1} events",
            timed(lambda e=envelopes: EventBundle.from_envelopes(e), 20 if size > 100 else 100),
        )

    envelopes = [genesis(), *(grant(i) for i in range(50))]
    bundle = EventBundle.from_envelopes(envelopes)
    report(
        "check_permission on an admitted 51-event bundle",
        timed(
            lambda: check_permission(
                bundle,
                lineage=LINEAGE,
                agent=AGENT.did,
                namespace="technocore",
                resource="room:r0",
                action="write",
                at=AT,
            ),
            200,
        ),
    )
    report(
        "one whole request: admit 51 events, then check",
        timed(
            lambda e=envelopes: check_permission(
                EventBundle.from_envelopes(e),
                lineage=LINEAGE,
                agent=AGENT.did,
                namespace="technocore",
                resource="room:r0",
                action="write",
                at=AT,
            ),
            50,
        ),
    )

    print(
        "\nAdmission dominates, and it is linear in events: every event in the bundle\n"
        "is verified, and the caller chooses how many to send. A public endpoint that\n"
        "admits a caller-supplied bundle is therefore paying whatever the caller asks\n"
        "it to pay -- which is a denial-of-service shape before it is a cost problem."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
