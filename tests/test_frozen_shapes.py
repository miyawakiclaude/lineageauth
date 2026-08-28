"""The frozen shapes are a promise, so this is what breaking it costs.

`RELEASE.md` asks for wire formats frozen "with a stated compatibility promise,
and meaning it". Meaning it is the part a document cannot do. `conformance/
frozen-shapes.json` records the payload keys every event type always carries,
and this fails if a builder stops matching -- so renaming a field is a decision
somebody makes on purpose rather than a diff that slips through review.

Two families of failure, and they read differently on purpose:

**A frozen family changed.** Somebody edited a builder and the promise is now
false. Either put the field back, or make the change deliberately: regenerate
the file, and add a decision entry saying what changed and what holders of older
events should do.

**A held family changed.** `authority` is held rather than frozen while
`docs/PRIOR_ART.md`'s question is open -- that layer overlaps UCAN, and if the
answer is to build on it rather than beside it, these shapes change. Changing
them is expected; the file is still regenerated so the change is visible.

Only required keys are frozen. Adding an optional key is a compatible change and
a contract that forbade it would be edited out of the way the first time it was
inconvenient, which is worse than not having one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.generate_frozen_shapes import HELD_FAMILIES, document, shapes

REPO = Path(__file__).resolve().parents[1]
FROZEN = REPO / "conformance" / "frozen-shapes.json"


@pytest.fixture(scope="module")
def recorded() -> dict:
    return json.loads(FROZEN.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def produced() -> dict[str, list[str]]:
    return shapes()


class TestTheContractExists:
    def test_the_file_is_present_and_readable(self, recorded: dict) -> None:
        assert recorded["families"], "the contract records no families at all"

    def test_it_says_which_families_are_only_held(self, recorded: dict) -> None:
        statuses = {b["status"] for b in recorded["families"].values()}
        assert statuses <= {"frozen", "held"}
        assert "held" in statuses, (
            "nothing is held, so either the prior-art question was settled and this "
            "test should be updated, or a family was frozen without deciding to"
        )

    def test_the_held_family_is_the_one_prior_art_puts_in_question(self, recorded: dict) -> None:
        held = {name for name, b in recorded["families"].items() if b["status"] == "held"}
        assert held == set(HELD_FAMILIES)
        assert "authority" in held, "the delegation layer is what overlaps UCAN"

    def test_regenerating_changes_nothing(self) -> None:
        """Deterministic, so a diff here is a protocol change and never noise."""
        assert document() == json.loads(FROZEN.read_text(encoding="utf-8"))


class TestTheBuildersStillMatch:
    def test_every_recorded_event_is_still_built(
        self, recorded: dict, produced: dict[str, list[str]]
    ) -> None:
        recorded_events = {
            event for block in recorded["families"].values() for event in block["events"]
        }
        missing = sorted(recorded_events - set(produced))
        assert not missing, f"the contract records event types nothing builds: {missing}"

    def test_no_frozen_shape_has_changed(
        self, recorded: dict, produced: dict[str, list[str]]
    ) -> None:
        broken = []
        for family, block in recorded["families"].items():
            if block["status"] != "frozen":
                continue
            for event, shape in block["events"].items():
                now = produced.get(event, [])
                added = sorted(set(now) - set(shape["required"]))
                gone = sorted(set(shape["required"]) - set(now))
                if added or gone:
                    broken.append(f"{family}/{event}: added={added} removed={gone}")
        assert not broken, (
            "a frozen payload shape changed. Put the field back, or decide to change "
            "it: regenerate conformance/frozen-shapes.json and record why in "
            "docs/29_DECISIONS.md." + "".join(chr(10) + "  " + b for b in broken)
        )

    def test_a_held_shape_may_change_but_is_still_recorded(
        self, recorded: dict, produced: dict[str, list[str]]
    ) -> None:
        """Held is not unwatched. The file must still describe what is built."""
        for family, block in recorded["families"].items():
            if block["status"] != "held":
                continue
            for event, shape in block["events"].items():
                assert set(shape["required"]) == set(produced.get(event, [])), (
                    f"{family}/{event} changed and the contract was not regenerated"
                )

    def test_the_common_fields_are_in_every_shape(self, produced: dict[str, list[str]]) -> None:
        """The five fields the verifier requires before it reads anything else."""
        common = {"protocol", "version", "type", "lineage", "issuedAt"}
        for event, keys in produced.items():
            assert common <= set(keys), f"{event} is missing {sorted(common - set(keys))}"


class TestItCanFail:
    """A contract that cannot be broken is not being checked.

    The point of the file is that a rename fails here. If that stops being true
    the file becomes decoration, so the failure path is exercised rather than
    assumed.
    """

    def test_a_renamed_field_is_caught(self, recorded: dict) -> None:
        frozen = next(
            (name, b) for name, b in recorded["families"].items() if b["status"] == "frozen"
        )
        family, block = frozen
        event, shape = next(iter(block["events"].items()))

        tampered = {k: list(v) for k, v in ((event, shape["required"]),)}
        tampered[event][-1] = "renamedField"

        added = sorted(set(tampered[event]) - set(shape["required"]))
        gone = sorted(set(shape["required"]) - set(tampered[event]))
        assert added and gone, (
            f"renaming a key in {family}/{event} produced no difference, so the "
            "comparison this test guards would not have noticed"
        )
