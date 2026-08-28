"""Build the static site published to GitHub Pages.

Run: `uv run python scripts/build_site.py --out site`

There is no API on a static host, so every answer the Explorer can ask for is
computed here, once, into `data/site.json`. The Explorer resolves requests from
that file instead of fetching them, and shows a banner saying so.

Three things this build must never let a reader get wrong, in order of how much
damage each would do:

1. **These keys are public.** The demo lineage is signed with the reproducible
   UNSAFE test keys. Anybody can produce identical signatures, so no DID on the
   published site belongs to anybody. The banner says it and this script refuses
   to build without it.
2. **The page verifies nothing.** It renders precomputed answers. The place to
   check them is `la verify`, offline, from a clone.
3. **It is a snapshot.** A page serving stale answers as though they were
   current is doing exactly what this protocol's freshness rules exist to stop,
   so the build stamps the time it ran and the Explorer displays it.

Deterministic apart from that timestamp, which is the point of a snapshot.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "packages" / "py"))

from tests.testkeys import (  # noqa: E402
    AGENT_1,
    OUTSIDER,
    RECOVERY_1,
    RECOVERY_2,
    ROOT_A,
    unsafe_signer,
)

from lineageauth import __version__, catalog  # noqa: E402
from lineageauth.actions import sha256_hex  # noqa: E402
from lineageauth.builders import (  # noqa: E402
    build_artifact_receipt,
    build_artifact_register,
    build_artifact_reuse,
    build_attestation,
    build_delegation_grant,
    build_dispute_open,
    build_jury_vote,
    build_root_create,
    build_skill_claim,
    build_task_claim,
    build_task_request,
    build_task_result,
    build_task_verify,
    sign_payload,
)
from lineageauth.bundle import EventBundle  # noqa: E402
from lineageauth.envelope import Envelope  # noqa: E402
from lineageauth.exchange import browse  # noqa: E402
from lineageauth.graph import build_graph  # noqa: E402
from lineageauth.identifiers import derive_lineage_id  # noqa: E402
from lineageauth.jury import resolve_dispute  # noqa: E402
from lineageauth.lineage import resolve_lineage  # noqa: E402
from lineageauth.passport import build_passport  # noqa: E402
from lineageauth.router import Query, search  # noqa: E402

UNSAFE_KEYS_NOTE = (
    "Every signature on this site was produced with the project's public, "
    "reproducible test keys. Anybody can generate identical ones. No DID here "
    "belongs to any person or organisation, and none of them may be used for "
    "anything real."
)

SNAPSHOT_NOTE = (
    "A static snapshot. Nothing here is live and nothing here verifies a "
    "signature -- the answers were computed once, at the build time stamped "
    "below. To check any of it, clone the repository and run `la verify`, which "
    "needs no network and no service."
)

# Dated in the past so the demo is not full of "issuedAt is ahead of the reader's
# clock" warnings, which are correct and would teach the wrong lesson about
# which warnings matter.
AT = datetime(2026, 8, 20, 9, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
WORKER = unsafe_signer(AGENT_1)
CHECKER = unsafe_signer(RECOVERY_1)
JUROR = unsafe_signer(RECOVERY_2)
OTHER = unsafe_signer(OUTSIDER)
LINEAGE = derive_lineage_id(ROOT.did)
ARTIFACT = sha256_hex(b"the published demo artifact")


def demo() -> tuple[list[Envelope], dict[str, str]]:
    """One lineage that exercises every screen, and the ids the routes need."""
    events: list[Envelope] = [
        sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])
    ]
    events.append(
        sign_payload(
            build_delegation_grant(
                lineage=LINEAGE,
                issuer=ROOT.did,
                subject=WORKER.did,
                epoch=0,
                scopes=[
                    {"namespace": "technocore", "resource": "room:lobby", "actions": ["write"]}
                ],
                not_before=AT - timedelta(days=1),
                expires_at=AT + timedelta(days=365),
                max_depth=0,
                issued_at=AT,
            ),
            [ROOT],
        )
    )
    events.append(
        sign_payload(
            build_skill_claim(
                lineage=LINEAGE,
                subject=WORKER.did,
                skill="summarise",
                evidence_refs=[ARTIFACT],
                issued_at=AT,
            ),
            [WORKER],
        )
    )
    task = sign_payload(
        build_task_request(
            lineage=LINEAGE,
            requester=CHECKER.did,
            title="index the room list",
            acceptance_criteria=["every room reachable"],
            issued_at=AT,
        ),
        [CHECKER],
    )
    claim = sign_payload(
        build_task_claim(
            lineage=LINEAGE,
            task=task.event_id,
            claimant=WORKER.did,
            nonce=b"published-demo16",
            expires_at=AT + timedelta(days=2),
            issued_at=AT,
        ),
        [WORKER],
    )
    artifact = sign_payload(
        build_artifact_register(
            lineage=LINEAGE, artifact_id=ARTIFACT, created_by=WORKER.did, issued_at=AT
        ),
        [WORKER],
    )
    receipt = sign_payload(
        build_artifact_receipt(
            lineage=LINEAGE, artifact_id=ARTIFACT, worker=WORKER.did, issued_at=AT
        ),
        [WORKER],
    )
    result = sign_payload(
        build_task_result(
            lineage=LINEAGE,
            task=task.event_id,
            claim=claim.event_id,
            worker=WORKER.did,
            artifact_refs=[ARTIFACT],
            summary="indexed 41 rooms",
            issued_at=AT,
        ),
        [WORKER],
    )
    rejected = sign_payload(
        build_task_verify(
            lineage=LINEAGE,
            task=task.event_id,
            result=result.event_id,
            verifier=CHECKER.did,
            verdict="rejected",
            issued_at=AT,
        ),
        [CHECKER],
    )
    attested = sign_payload(
        build_attestation(
            lineage=LINEAGE,
            issuer=OTHER.did,
            subject_ref=ARTIFACT,
            predicate="artifact.reviewed",
            issued_at=AT,
        ),
        [OTHER],
    )
    reuse = sign_payload(
        build_artifact_reuse(
            lineage=LINEAGE,
            reuser=OTHER.did,
            used=ARTIFACT,
            used_in=sha256_hex(b"a downstream project"),
            issued_at=AT,
        ),
        [OTHER],
    )
    case = sign_payload(
        build_dispute_open(
            lineage=LINEAGE,
            opener=WORKER.did,
            task=task.event_id,
            result=result.event_id,
            reason_code="criteria-misread",
            statement="the checker tested a stale snapshot",
            jurors=[JUROR.did, OTHER.did, CHECKER.did],
            quorum=2,
            threshold=2,
            issued_at=AT,
        ),
        [WORKER],
    )
    vote = sign_payload(
        build_jury_vote(
            lineage=LINEAGE,
            case=case.event_id,
            juror=JUROR.did,
            finding="result-meets-criteria",
            reason_code="reviewed-evidence",
            issued_at=AT,
        ),
        [JUROR],
    )
    events.extend([task, claim, artifact, receipt, result, rejected, attested, reuse, case, vote])
    return events, {"task": task.event_id, "case": case.event_id, "result": result.event_id}


def path_component(value: str) -> str:
    """Encode one path component the way the browser does.

    `encodeURIComponent` in the Explorer, `quote(safe="")` here. They have to
    agree, because in static mode the route key is matched **literally** -- and
    a live server decodes the path before routing, so a mismatch here is
    invisible until the site is static. It was: `lineage:la:...` in the keys
    against `lineage%3Ala%3A...` from the client, and every screen past the
    first failed with "not precomputed".
    """
    return quote(value, safe="")


def routes(events: list[Envelope], ids: dict[str, str], at: datetime) -> dict[str, Any]:
    """Every path the Explorer can ask for, answered once.

    The keys are the exact strings `api()` builds, minus the leading slash. If
    a screen asks for something absent, the Explorer says the question was not
    precomputed rather than showing an empty answer -- an empty answer is
    indistinguishable from "there is none", and they are different facts.
    """
    lineage_key = path_component(LINEAGE)
    bundle = EventBundle.from_envelopes(events)
    state = resolve_lineage(bundle, lineage=LINEAGE, at=at)

    answers: dict[str, Any] = {
        "v1/meta": {
            "version": __version__,
            "protocol": catalog.PROTOCOL,
            "holdsPrivateKeys": False,
            "acceptsEventsOverHttp": False,
            "note": f"{SNAPSHOT_NOTE} {UNSAFE_KEYS_NOTE}",
        },
        "v1/lineages": {"lineages": [LINEAGE]},
        f"v1/lineages/{lineage_key}": {
            "lineage": LINEAGE,
            "resolved": state.resolved,
            "reason": str(state.reason),
            "detail": state.detail,
            "root": state.root,
            "epoch": state.epoch,
            "superseded": list(state.superseded_roots),
            "warnings": list(state.warnings),
            "note": state.note,
        },
        f"v1/lineages/{lineage_key}/graph": build_graph(bundle, lineage=LINEAGE, at=at).to_dict(),
        f"v1/exchange?lineage={lineage_key}": browse(bundle, lineage=LINEAGE, at=at).to_dict(),
        "v1/router/search": search(bundle, lineage=LINEAGE, query=Query(), at=at).to_dict(),
        f"v1/disputes/{path_component(ids['case'])}?lineage={lineage_key}": resolve_dispute(
            bundle, lineage=LINEAGE, case_id=ids["case"], at=at
        ).to_dict(),
    }

    for signer in (ROOT, WORKER, CHECKER, JUROR, OTHER):
        answers[f"v1/passports/{path_component(signer.did)}?lineage={lineage_key}"] = (
            build_passport(bundle, lineage=LINEAGE, did=signer.did, at=at).to_dict()
        )
        answers[f"v1/dids/{path_component(signer.did)}"] = {
            "did": signer.did,
            "method": "key",
            "keyType": "Ed25519",
            "note": UNSAFE_KEYS_NOTE,
        }

    for envelope in events:
        answers[f"v1/events/{path_component(envelope.event_id)}"] = json.loads(envelope.to_json())

    return answers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="site", help="Directory to build into.")
    args = parser.parse_args()

    out = Path(args.out)
    if out.exists():
        # `--out` is a path from a command line, and this used to delete whatever
        # was there. A mistyped argument -- or a habit of passing a directory
        # that also holds something else -- would take the lot. Delete only a
        # directory that looks like a previous run of this script. (D-099.)
        made_by_us = (out / ".nojekyll").exists() or (out / "data" / "site.json").exists()
        if not made_by_us:
            sys.exit(
                f"refusing to delete {out}: it exists and does not look like a build "
                "output from this script (no .nojekyll, no data/site.json). Remove it "
                "yourself if that is really what you want."
            )
        shutil.rmtree(out)
    (out / "explorer").mkdir(parents=True)
    (out / "data").mkdir(parents=True)

    explorer = REPO_ROOT / "apps" / "explorer"
    shutil.copy2(explorer / "index.html", out / "index.html")
    shutil.copy2(explorer / "app.css", out / "explorer" / "app.css")
    shutil.copy2(explorer / "app.js", out / "explorer" / "app.js")
    # The second implementation, shipped beside the page that runs it. Same
    # origin, so `script-src 'self'` covers it and no CSP change is needed.
    shutil.copy2(
        REPO_ROOT / "packages" / "js" / "lineageauth.js", out / "explorer" / "lineageauth.js"
    )

    # Published as-is: they are already static, already deterministic, and the
    # point of a conformance package is that somebody else can fetch it.
    shutil.copytree(REPO_ROOT / "conformance", out / "conformance")
    shutil.copytree(REPO_ROOT / "schemas", out / "schemas")
    shutil.copytree(REPO_ROOT / "examples", out / "examples")

    built_at = datetime.now(tz=UTC)
    events, ids = demo()
    site = {
        "builtAt": built_at.isoformat().replace("+00:00", "Z"),
        "protocol": catalog.PROTOCOL,
        "version": __version__,
        "snapshotNote": SNAPSHOT_NOTE,
        "unsafeKeysNote": UNSAFE_KEYS_NOTE,
        "routes": routes(events, ids, AT + timedelta(days=1)),
    }

    # The guard rails this build is not allowed to ship without.
    banner = (out / "index.html").read_text(encoding="utf-8")
    for required in ("Static snapshot", "Public and reproducible", "Verified in your browser"):
        if required not in banner:
            print(f"refusing to build: the page does not say {required!r}", file=sys.stderr)
            return 1

    (out / "data" / "site.json").write_text(
        json.dumps(site, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    # GitHub Pages runs Jekyll by default, which drops files beginning with an
    # underscore and would rewrite nothing else usefully here.
    (out / ".nojekyll").write_text("", encoding="utf-8")

    print(f"built {out} with {len(site['routes'])} precomputed route(s)")
    print(f"  lineage {LINEAGE}")
    print(f"  worker  {WORKER.did}")
    print(f"  case    {ids['case']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
