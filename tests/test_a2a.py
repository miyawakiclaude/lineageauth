"""The A2A integration.

`docs/20` opens with one sentence -- "LineageAuth must not replace/bypass server
authorization" -- and most of these tests are that sentence, checked from a
different angle each time: the extension can never be marked required, the
provenance answer always ships the five-step order it is step 3 of, and a
resolver URL published by a stranger is carried as data and never fetched.

The upstream facts these rest on were checked against the A2A specification on
2026-08-27: extensions live at `capabilities.extensions`, an `AgentExtension`
is `{uri, description, required, params}`, and upstream says data-only
extensions should not be marked required.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lineageauth.adapters.a2a import (
    EXTENSION_URI,
    VERIFICATION_ORDER,
    a2a_resource_for,
    build_extension,
    check_a2a_invocation,
    read_extension,
)
from lineageauth.builders import build_delegation_grant, build_root_create, sign_payload
from lineageauth.bundle import EventBundle
from lineageauth.didkey import DidKeyError
from lineageauth.envelope import Envelope
from lineageauth.errors import MalformedEventError
from lineageauth.identifiers import derive_lineage_id
from tests.testkeys import AGENT_1, OUTSIDER, ROOT_A, unsafe_signer

AT = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)

ROOT = unsafe_signer(ROOT_A)
AGENT = unsafe_signer(AGENT_1)
STRANGER = unsafe_signer(OUTSIDER)
LINEAGE: str = derive_lineage_id(ROOT.did)

EVIDENCE = "sha256:" + "b" * 64


def genesis() -> Envelope:
    return sign_payload(build_root_create(root_did=ROOT.did, issued_at=AT), [ROOT])


def grant(*, resource: str = "skill:summarise", action: str = "invoke") -> Envelope:
    payload = build_delegation_grant(
        lineage=LINEAGE,
        issuer=ROOT.did,
        subject=AGENT.did,
        epoch=0,
        scopes=[{"namespace": "a2a", "resource": resource, "actions": [action]}],
        not_before=AT - timedelta(days=1),
        expires_at=AT + timedelta(days=30),
        max_depth=0,
        issued_at=AT,
    )
    return sign_payload(payload, [ROOT])


def card(extension: dict[str, object] | None, *, extra: list[object] | None = None) -> dict:
    extensions = list(extra or [])
    if extension is not None:
        extensions.append(extension)
    return {
        "name": "Summariser",
        "capabilities": {"streaming": True, "extensions": extensions},
        "skills": [{"id": "summarise", "name": "Summarise a document"}],
    }


# ------------------------------------------------------------ the extension


class TestExtensionIsDataOnly:
    def test_it_is_never_marked_required(self) -> None:
        """Upstream: data-only extensions should not be required. This is data only."""
        built = build_extension(lineage=LINEAGE, did=AGENT.did)
        assert built["required"] is False

    def test_there_is_no_way_to_ask_for_required(self) -> None:
        with pytest.raises(TypeError):
            build_extension(lineage=LINEAGE, did=AGENT.did, required=True)  # type: ignore[call-arg]

    def test_it_sits_where_the_spec_puts_extensions(self) -> None:
        built = build_extension(lineage=LINEAGE, did=AGENT.did)
        document = card(built)
        assert document["capabilities"]["extensions"] == [built]
        assert set(built) == {"uri", "description", "required", "params"}

    def test_the_description_says_it_authorizes_nothing(self) -> None:
        built = build_extension(lineage=LINEAGE, did=AGENT.did)
        assert "does not authorize anything" in built["description"]

    def test_evidence_references_must_be_event_ids(self) -> None:
        with pytest.raises(MalformedEventError, match="evidence reference"):
            build_extension(lineage=LINEAGE, did=AGENT.did, evidence=["not-an-id"])

    def test_a_did_that_does_not_decode_is_refused(self) -> None:
        # DidKeyError, like every other builder: the DID layer is the one that
        # knows why. `read_extension` converts it, because there the subject is
        # a whole foreign document rather than an argument the caller passed.
        with pytest.raises(DidKeyError):
            build_extension(lineage=LINEAGE, did="did:key:z6MkNOPE")

    def test_a_plaintext_http_resolver_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="must be https"):
            build_extension(lineage=LINEAGE, did=AGENT.did, resolver="http://example.invalid")


class TestReadingAStrangersCard:
    def test_a_card_without_the_extension_is_not_a_complaint(self) -> None:
        """Most agents will publish none, and that says nothing about them."""
        assert read_extension(card(None)) is None
        assert read_extension({"name": "Bare"}) is None

    def test_a_well_formed_extension_reads_back(self) -> None:
        built = build_extension(
            lineage=LINEAGE,
            did=AGENT.did,
            resolver="https://example.invalid/resolve",
            evidence=[EVIDENCE],
        )
        found = read_extension(card(built))
        assert found is not None
        assert found.did == AGENT.did
        assert found.evidence == (EVIDENCE,)

    def test_the_resolver_is_data_and_says_it_is_never_fetched(self) -> None:
        built = build_extension(
            lineage=LINEAGE, did=AGENT.did, resolver="https://example.invalid/resolve"
        )
        found = read_extension(card(built))
        assert found is not None
        assert found.resolver == "https://example.invalid/resolve"
        assert "never fetched by this library" in found.note

    def test_the_note_refuses_to_call_a_published_did_an_identity(self) -> None:
        found = read_extension(card(build_extension(lineage=LINEAGE, did=AGENT.did)))
        assert found is not None
        assert "not that they hold its key" in found.note

    def test_a_did_that_does_not_decode_is_refused_rather_than_half_read(self) -> None:
        broken = build_extension(lineage=LINEAGE, did=AGENT.did)
        broken["params"]["did"] = "did:key:z6MkNOPE"  # type: ignore[index]
        with pytest.raises(MalformedEventError, match="not a usable Ed25519"):
            read_extension(card(broken))

    def test_a_junk_evidence_reference_is_dropped_and_reported(self) -> None:
        built = build_extension(lineage=LINEAGE, did=AGENT.did)
        built["params"]["evidence"] = [EVIDENCE, "../../etc/passwd"]  # type: ignore[index]
        found = read_extension(card(built))
        assert found is not None
        assert found.evidence == (EVIDENCE,)
        assert any("not an event id" in w for w in found.warnings)

    def test_two_blocks_under_one_uri_are_refused(self) -> None:
        """Nothing says which is current, and choosing would be picking an identity."""
        one = build_extension(lineage=LINEAGE, did=AGENT.did)
        other = build_extension(lineage=LINEAGE, did=STRANGER.did)
        with pytest.raises(MalformedEventError, match="more than once"):
            read_extension(card(one, extra=[other]))

    def test_another_partys_extension_is_left_alone(self) -> None:
        theirs = {"uri": "https://example.invalid/other-ext", "params": {"did": "whatever"}}
        built = build_extension(lineage=LINEAGE, did=AGENT.did)
        found = read_extension(card(built, extra=[theirs]))
        assert found is not None
        assert found.did == AGENT.did

    def test_a_card_marking_it_required_is_reported_not_normalised(self) -> None:
        """What the card says is a fact about the card, so it is repeated back."""
        built = build_extension(lineage=LINEAGE, did=AGENT.did)
        built["required"] = True
        found = read_extension(card(built))
        assert found is not None
        assert found.declared_required
        assert any("using provenance to gate access" in w for w in found.warnings)

    def test_a_card_that_is_not_an_object_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="JSON object"):
            read_extension("https://example.invalid/card.json")


# ------------------------------------------------------------ skill mapping


class TestSkillMapping:
    def test_a_skill_id_maps_onto_the_a2a_namespace(self) -> None:
        assert a2a_resource_for(skill_id="summarise") == "skill:summarise"

    def test_an_agent_id_maps_too(self) -> None:
        assert a2a_resource_for(agent_id="planner") == "agent:planner"

    def test_exactly_one_target_is_required(self) -> None:
        with pytest.raises(MalformedEventError, match="exactly one"):
            a2a_resource_for()
        with pytest.raises(MalformedEventError, match="exactly one"):
            a2a_resource_for(agent_id="a", skill_id="b")

    def test_a_wildcard_is_refused_for_a_concrete_invocation(self) -> None:
        with pytest.raises(MalformedEventError, match="one concrete target"):
            a2a_resource_for(skill_id="*")

    def test_a_dot_segment_is_refused(self) -> None:
        with pytest.raises(MalformedEventError):
            a2a_resource_for(skill_id="..")

    def test_a_separator_smuggled_into_a_skill_id_is_refused(self) -> None:
        """The id comes off a published card, so it must not widen the resource."""
        for hostile in ("summarise/tool:x", "summarise:extra", "a b", "sum\x00marise"):
            with pytest.raises(MalformedEventError):
                a2a_resource_for(skill_id=hostile)


# ------------------------------------------------------------ the check


class TestProvenanceIsNotAuthorization:
    def _bundle(self, *envelopes: Envelope) -> EventBundle:
        return EventBundle.from_envelopes([genesis(), *envelopes])

    def test_a_granted_skill_is_allowed_inside_the_lineage(self) -> None:
        found = check_a2a_invocation(
            self._bundle(grant()),
            lineage=LINEAGE,
            agent=AGENT.did,
            skill_id="summarise",
            at=AT,
        )
        assert found["allowed"] is True
        assert found["resource"] == "skill:summarise"

    def test_an_ungranted_skill_is_denied(self) -> None:
        found = check_a2a_invocation(
            self._bundle(grant()),
            lineage=LINEAGE,
            agent=AGENT.did,
            skill_id="deploy",
            at=AT,
        )
        assert found["allowed"] is False

    def test_every_answer_carries_the_five_step_order(self) -> None:
        found = check_a2a_invocation(
            self._bundle(grant()),
            lineage=LINEAGE,
            agent=AGENT.did,
            skill_id="summarise",
            at=AT,
        )
        assert found["verificationOrder"] == list(VERIFICATION_ORDER)
        assert found["verificationOrder"][1] == "A2A server authorization"
        assert "this answer" in found["verificationOrder"][2]

    def test_an_allow_says_plainly_that_it_authorizes_nothing(self) -> None:
        found = check_a2a_invocation(
            self._bundle(grant()),
            lineage=LINEAGE,
            agent=AGENT.did,
            skill_id="summarise",
            at=AT,
        )
        assert "never bypassed" in found["note"]
        assert "says nothing about whether" in found["note"]

    def test_a_denial_still_leaves_the_server_in_charge(self) -> None:
        """A LineageAuth denial is not an instruction to the server either."""
        found = check_a2a_invocation(
            self._bundle(),
            lineage=LINEAGE,
            agent=STRANGER.did,
            skill_id="summarise",
            at=AT,
        )
        assert found["allowed"] is False
        assert "step 3 of 5" in found["note"]

    def test_the_approval_requirement_travels_with_the_answer(self) -> None:
        found = check_a2a_invocation(
            self._bundle(grant()),
            lineage=LINEAGE,
            agent=AGENT.did,
            skill_id="summarise",
            at=AT,
        )
        assert found["approval"] in ("none", "external-only", "required")


class TestNoSecretsInCards:
    def test_nothing_the_builder_emits_looks_like_a_secret(self) -> None:
        """docs/20: never include plaintext secrets. The builder takes none."""
        built = build_extension(
            lineage=LINEAGE,
            did=AGENT.did,
            resolver="https://example.invalid/resolve",
            evidence=[EVIDENCE],
        )
        flat = repr(built).lower()
        for word in ("secret", "token", "password", "apikey", "api_key", "private"):
            assert word not in flat

    def test_the_extension_uri_is_the_document_that_defines_it(self) -> None:
        assert EXTENSION_URI.startswith("https://")
        assert "20_A2A" in EXTENSION_URI
