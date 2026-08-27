"""Lose a root key on real files, and come back with a quorum.

    py -3 -m uv run python scripts/recovery_drill.py

`RELEASE.md` asks for recovery to be *rehearsed*, not only unit-tested, and the
distinction is the whole point of this script. `tests/test_lineage.py` covers
succession, quorums and `CONFLICTED` with payloads built in memory. It cannot
catch the failure that actually ends an identity: the procedure being
un-followable on the day it is needed, because a step nobody wrote down turns
out to be required.

So this runs the disaster end to end on files:

    create a root and three recovery keys, encrypted, with passphrases
    open the lineage and publish a 2-of-3 recovery policy
    DELETE the root key
    rebuild authority from the published bundle and two recovery files
    check that the refusals still refuse

It is deliberately a script rather than a test helper. A test proves the code
behaves; a drill proves a person can. `docs/RECOVERY.md` was written from what
this script had to do, and every friction note below marks a place where the
documentation had to grow to keep the two in step.

The passphrases here are literals on purpose. These keys protect nothing, exist
for one run, and are deleted at the end -- writing them out is what keeps the
drill honest about needing them at all.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "packages" / "py"))

from lineageauth import keyfile  # noqa: E402
from lineageauth.builders import (  # noqa: E402
    build_recovery_policy,
    build_root_create,
    build_root_succession,
    sign_payload,
)
from lineageauth.bundle import EventBundle  # noqa: E402
from lineageauth.canonical import compute_event_id  # noqa: E402
from lineageauth.crypto import LocalSigner  # noqa: E402
from lineageauth.envelope import Envelope  # noqa: E402
from lineageauth.identifiers import derive_lineage_id  # noqa: E402
from lineageauth.lineage import resolve_lineage  # noqa: E402

PASSPHRASES = {
    "root": "drill-root-passphrase",
    "r1": "drill-recovery-one-passphrase",
    "r2": "drill-recovery-two-passphrase",
    "r3": "drill-recovery-three-passphrase",
}

# An unrelated key, to stand in for somebody who is not a policy member. The seed
# is a public constant and the DID it produces belongs to nobody.
OUTSIDER_SEED = bytes(range(32))


class DrillFailure(RuntimeError):
    """The drill reached a state the documented procedure says is impossible."""


def run(workdir: Path, *, verbose: bool = True) -> list[str]:
    """Run the whole drill in `workdir`. Returns the checks that passed."""

    def say(text: str) -> None:
        if verbose:
            print(text)

    passed: list[str] = []
    now = datetime.now(tz=UTC)
    later = now + timedelta(minutes=10)

    # -- before the disaster --------------------------------------------------
    # `create` hands back the public half only -- a Keyfile is a DID and a path,
    # with no way to sign. Getting a signer means unlocking the file you just
    # wrote, which is the same thing a survivor does and is why the drill does
    # it rather than keeping the key it generated.
    for name, phrase in PASSPHRASES.items():
        keyfile.create(workdir / f"{name}.json", phrase)
    keys = {
        name: keyfile.unlock(workdir / f"{name}.json", phrase)
        for name, phrase in PASSPHRASES.items()
    }
    root = keys["root"]
    members = [keys[n].did for n in ("r1", "r2", "r3")]
    lineage = derive_lineage_id(root.did)
    say(f"  root     {root.did}")
    say(f"  lineage  {lineage}")

    genesis = sign_payload(build_root_create(root_did=root.did, issued_at=now), [root])
    policy = sign_payload(
        build_recovery_policy(
            lineage=lineage,
            epoch=0,
            policy_seq=1,
            members=members,
            threshold=2,
            issued_at=now,
        ),
        [root],
    )
    published = [genesis, policy]

    opened = resolve_lineage(EventBundle.from_envelopes(published), lineage=lineage, at=now)
    if not opened.resolved or opened.root != root.did or opened.epoch != 0:
        raise DrillFailure(f"the lineage did not open: {opened.reason}")
    passed.append("the lineage opens at epoch 0 under the root that created it")

    bundle_file = workdir / "lineage.json"
    bundle_file.write_text("[" + ",".join(e.to_json() for e in published) + "]", encoding="utf-8")

    # -- the disaster ---------------------------------------------------------
    (workdir / "root.json").unlink()
    root_did = root.did
    del root, keys["root"]
    say("\n  root key deleted. What survives: lineage.json, r1, r2, r3.\n")

    # -- recovery, knowing only what a survivor would have --------------------
    # Everything from here reads the published bundle rather than the variables
    # above, because a survivor has the file and not the session that made it.
    documents = [
        Envelope.from_json(text) for text in _split_bundle(bundle_file.read_text(encoding="utf-8"))
    ]
    policy_payload = _only(documents, "recovery.policy").payload
    from_root = _only(documents, "root.create").payload["root"]
    if from_root != root_did:
        raise DrillFailure("the published bundle names a different outgoing root")

    # The reference is the policy's *event id*. `docs/05` lists the field and
    # never says what goes in it; `docs/RECOVERY.md` now does, and this line is
    # what that sentence describes.
    policy_ref = compute_event_id(policy_payload)

    quorum = [keys["r1"], keys["r2"]]
    new_root_phrase = "drill-new-root-passphrase"
    keyfile.create(workdir / "new-root.json", new_root_phrase)
    new_root = keyfile.unlock(workdir / "new-root.json", new_root_phrase)

    def attempt(signers: list[LocalSigner], *, to: str, ref: str) -> tuple[bool, str]:
        envelope = sign_payload(
            build_root_succession(
                lineage=policy_payload["lineage"],
                from_root=from_root,
                to_root=to,
                from_epoch=0,
                mode="recovery",
                recovery_policy_ref=ref,
                issued_at=now,
            ),
            signers,
        )
        state = resolve_lineage(
            EventBundle.from_envelopes([*documents, envelope]),
            lineage=policy_payload["lineage"],
            at=later,
        )
        moved = bool(state.resolved and state.root == to and state.epoch == 1)
        return moved, state.reason

    # -- what must be refused -------------------------------------------------
    refusals = [
        ("one signature, below the threshold of two", [keys["r1"]], policy_ref),
        (
            "two signatures, one of them not a policy member",
            [keys["r1"], LocalSigner.from_seed(OUTSIDER_SEED)],
            policy_ref,
        ),
        ("two signatures from the same member, duplicated", [keys["r1"], keys["r1"]], policy_ref),
        (
            "a real quorum, pointing at a policy that does not exist",
            [keys["r1"], keys["r2"]],
            "sha256:" + "0" * 64,
        ),
    ]
    for label, signers, ref in refusals:
        moved, reason = attempt(signers, to=new_root.did, ref=ref)
        if moved:
            raise DrillFailure(f"recovery accepted what it must refuse: {label}")
        say(f"  refused  {label}  ({reason})")
        passed.append(f"refuses: {label}")

    # -- what must work -------------------------------------------------------
    moved, reason = attempt(quorum, to=new_root.did, ref=policy_ref)
    if not moved:
        raise DrillFailure(f"a valid 2-of-3 quorum did not recover the lineage: {reason}")
    say(f"\n  recovered to {new_root.did} at epoch 1 ({reason})")
    passed.append("a valid 2-of-3 quorum moves the lineage to a new root at epoch 1")

    return passed


def _split_bundle(text: str) -> list[str]:
    """Each document of a published bundle, as its own JSON text."""
    import json

    return [json.dumps(document) for document in json.loads(text)]


def _only(documents: list[Envelope], event_type: str) -> Envelope:
    found = [d for d in documents if d.payload.get("type") == event_type]
    if len(found) != 1:
        raise DrillFailure(f"expected exactly one {event_type}, found {len(found)}")
    return found[0]


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="lineageauth-recovery-drill-"))
    print(f"drill directory: {workdir}\n")
    try:
        passed = run(workdir)
    except DrillFailure as failure:
        print(f"\nDRILL FAILED: {failure}", file=sys.stderr)
        print(f"  files left for inspection: {workdir}", file=sys.stderr)
        return 1
    finally:
        if not sys.exc_info()[0]:
            shutil.rmtree(workdir, ignore_errors=True)

    print(f"\nDRILL PASSED -- {len(passed)} checks")
    for check in passed:
        print(f"  - {check}")
    print("\nThe procedure this exercises is written out in docs/RECOVERY.md.")
    print("If you changed one and not the other, they have drifted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
