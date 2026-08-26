"""Scope grammar and attenuation.

docs/23_TESTING.md names the property this file exists to defend:

    a child never has a permission its parent lacks.

Everything else here is the fail-closed behaviour that makes that property
meaningful -- an unregistered namespace, an unknown action, or a resource the
grammar cannot parse must be refused rather than waved through.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lineageauth.errors import MalformedEventError
from lineageauth.scopes import (
    NAMESPACES,
    ApprovalMode,
    Scope,
    attenuation_failure,
    parse_resource,
    parse_scopes,
)


def scope(namespace: str, resource: str, *actions: str) -> Scope:
    return Scope.parse({"namespace": namespace, "resource": resource, "actions": sorted(actions)})


class TestResourceGrammar:
    @pytest.mark.parametrize(
        ("namespace", "resource"),
        [
            ("technocore", "room:lobby"),
            ("technocore", "room:*"),
            ("technocore", "owned-room:lobby"),
            ("technocore", "note:agents/status"),
            ("mcp", "server:files"),
            ("mcp", "server:files/tool:read"),
            ("a2a", "agent:translator"),
            ("a2a", "skill:translate.ja"),
            ("github", "repo:miyawakiclaude/lineageauth"),
            ("github", "repo:miyawakiclaude/*"),
            ("http", "host:example.com"),
        ],
    )
    def test_accepts_the_documented_shapes(self, namespace: str, resource: str) -> None:
        assert parse_resource(namespace, resource).render()

    @pytest.mark.parametrize(
        ("namespace", "resource"),
        [
            ("technocore", "channel:lobby"),  # no such resource type
            ("technocore", "room:a/b"),  # too many segments
            ("technocore", "note:onlyone"),  # too few segments
            ("github", "repo:owner"),  # repo takes owner/name
            ("http", "host:a/b"),
            ("technocore", "room:"),  # empty segment
            ("technocore", "lobby"),  # no prefix
            ("technocore", ""),
        ],
    )
    def test_rejects_shapes_outside_the_grammar(self, namespace: str, resource: str) -> None:
        with pytest.raises(MalformedEventError):
            parse_resource(namespace, resource)

    def test_rejects_an_unregistered_namespace(self) -> None:
        with pytest.raises(MalformedEventError, match="unregistered scope namespace"):
            parse_resource("slack", "channel:general")

    @pytest.mark.parametrize(
        "resource",
        [
            "room:.*",
            "room:lob(by)",
            "room:lobby|admin",
            "room:lob by",
            "room:lobby\x1b[31m",
            "room:lob\nby",
        ],
    )
    def test_rejects_pattern_syntax_and_control_characters(self, resource: str) -> None:
        # docs/04: never use arbitrary regex from untrusted events. Keeping the
        # segment alphabet narrow also keeps terminal escapes out of anything
        # that later prints a resource back to a human.
        with pytest.raises(MalformedEventError, match="outside"):
            parse_resource("technocore", resource)

    @pytest.mark.parametrize("resource", ["note:../admin", "note:ns/..", "note:./x"])
    def test_rejects_relative_path_segments(self, resource: str) -> None:
        # Comparison is exact so these could never traverse anything, but a
        # resource that reads as traversal has no business in a signed grant.
        with pytest.raises(MalformedEventError, match="relative path element"):
            parse_resource("technocore", resource)

    def test_a_wildcard_is_only_valid_as_the_final_segment(self) -> None:
        with pytest.raises(MalformedEventError, match="final segment"):
            parse_resource("github", "repo:*/lineageauth")


class TestWildcardContainment:
    def test_a_wildcard_covers_one_segment(self) -> None:
        assert scope("technocore", "room:*", "read").covers(
            namespace="technocore", resource="room:lobby", action="read"
        )

    def test_a_wildcard_does_not_reach_into_deeper_segments(self) -> None:
        # `*` stands for exactly one segment. Reaching further would grant
        # authority nobody wrote down; refusing is the safe direction, and a
        # later widening stays compatible where a later narrowing would not.
        parent = scope("github", "repo:owner/*", "read")
        assert parent.covers(namespace="github", resource="repo:owner/api", action="read")
        assert not parent.covers(
            namespace="github", resource="repo:owner/api/issues", action="read"
        )

    def test_a_wildcard_does_not_cross_resource_types(self) -> None:
        parent = scope("technocore", "room:*", "read")
        assert not parent.covers(namespace="technocore", resource="owned-room:lobby", action="read")

    def test_a_wildcard_does_not_cross_namespaces(self) -> None:
        parent = scope("technocore", "room:*", "read")
        assert not parent.covers(namespace="a2a", resource="agent:lobby", action="discover")


class TestScopeParsing:
    def test_rejects_an_unknown_action(self) -> None:
        with pytest.raises(MalformedEventError, match="no action"):
            scope("technocore", "room:lobby", "merge")

    def test_rejects_an_unrecognised_scope_field(self) -> None:
        # A field this verifier cannot interpret may be a constraint it would
        # otherwise be silently dropping.
        with pytest.raises(MalformedEventError, match="unrecognised field"):
            Scope.parse(
                {
                    "namespace": "technocore",
                    "resource": "room:lobby",
                    "actions": ["read"],
                    "unlessRevoked": False,
                }
            )

    def test_rejects_duplicate_actions(self) -> None:
        with pytest.raises(MalformedEventError, match="distinct"):
            Scope.parse(
                {"namespace": "technocore", "resource": "room:lobby", "actions": ["read", "read"]}
            )

    def test_requires_actions_in_ascending_order(self) -> None:
        with pytest.raises(MalformedEventError, match="ascending order"):
            Scope.parse(
                {"namespace": "technocore", "resource": "room:lobby", "actions": ["write", "read"]}
            )

    def test_rejects_an_empty_action_list(self) -> None:
        with pytest.raises(MalformedEventError):
            Scope.parse({"namespace": "technocore", "resource": "room:lobby", "actions": []})

    @pytest.mark.parametrize("value", [None, "room:lobby", 42, ["room:lobby"]])
    def test_rejects_a_scope_that_is_not_an_object(self, value: Any) -> None:
        with pytest.raises(MalformedEventError):
            Scope.parse(value)

    def test_parse_scopes_rejects_an_empty_array(self) -> None:
        with pytest.raises(MalformedEventError):
            parse_scopes([])


class TestApprovalMode:
    def test_the_documented_order_holds(self) -> None:
        assert ApprovalMode.NONE < ApprovalMode.EXTERNAL_ONLY < ApprovalMode.REQUIRED

    @pytest.mark.parametrize(
        ("name", "mode"),
        [
            ("none", ApprovalMode.NONE),
            ("external-only", ApprovalMode.EXTERNAL_ONLY),
            ("required", ApprovalMode.REQUIRED),
        ],
    )
    def test_wire_spellings_round_trip(self, name: str, mode: ApprovalMode) -> None:
        assert ApprovalMode.parse(name) is mode
        assert mode.wire_name == name

    @pytest.mark.parametrize("value", ["NONE", "optional", "", None, 0, True])
    def test_rejects_an_unrecognised_mode(self, value: Any) -> None:
        with pytest.raises(MalformedEventError):
            ApprovalMode.parse(value)


class TestAttenuation:
    def test_an_identical_scope_attenuates(self) -> None:
        parent = (scope("technocore", "room:lobby", "read", "write"),)
        assert attenuation_failure(parent, parent) is None

    def test_a_narrower_action_set_attenuates(self) -> None:
        parent = (scope("technocore", "room:lobby", "read", "write"),)
        child = (scope("technocore", "room:lobby", "read"),)
        assert attenuation_failure(parent, child) is None

    def test_a_narrower_resource_attenuates(self) -> None:
        parent = (scope("technocore", "room:*", "read"),)
        child = (scope("technocore", "room:lobby", "read"),)
        assert attenuation_failure(parent, child) is None

    def test_an_added_action_does_not_attenuate(self) -> None:
        parent = (scope("technocore", "room:lobby", "read"),)
        child = (scope("technocore", "room:lobby", "read", "write"),)
        assert attenuation_failure(parent, child) is not None

    def test_a_broadened_resource_does_not_attenuate(self) -> None:
        parent = (scope("technocore", "room:lobby", "read"),)
        child = (scope("technocore", "room:*", "read"),)
        assert attenuation_failure(parent, child) is not None

    def test_a_different_namespace_does_not_attenuate(self) -> None:
        parent = (scope("technocore", "room:lobby", "read"),)
        child = (scope("a2a", "agent:lobby", "discover"),)
        assert attenuation_failure(parent, child) is not None

    def test_a_child_scope_may_not_be_assembled_from_several_parent_scopes(self) -> None:
        """Each child scope must fit inside one parent scope, not the union.

        Otherwise `read on repo A` plus `merge on repo B` would combine into
        `merge on repo A` -- two narrow grants manufacturing a broad one.
        """
        parent = (
            scope("github", "repo:owner/a", "read"),
            scope("github", "repo:owner/b", "merge"),
        )
        assert attenuation_failure(parent, (scope("github", "repo:owner/a", "read"),)) is None
        assert attenuation_failure(parent, (scope("github", "repo:owner/a", "merge"),)) is not None


# --------------------------------------------------------------------- properties

_RESOURCES: dict[str, list[str]] = {
    "technocore": ["room:*", "room:lobby", "room:ops", "owned-room:lobby", "note:ns/key"],
    "mcp": ["server:files", "server:*", "server:files/tool:read"],
    "a2a": ["agent:*", "agent:translator", "skill:translate.ja"],
    "github": ["repo:owner/*", "repo:owner/api", "repo:other/api"],
    "http": ["host:*", "host:example.com"],
}

namespaces = st.sampled_from(sorted(NAMESPACES))


@st.composite
def scopes(draw: st.DrawFn) -> Scope:
    namespace = draw(namespaces)
    resource = draw(st.sampled_from(_RESOURCES[namespace]))
    actions = draw(
        st.lists(
            st.sampled_from(sorted(NAMESPACES[namespace].actions)),
            min_size=1,
            max_size=3,
            unique=True,
        )
    )
    return scope(namespace, resource, *actions)


@st.composite
def narrowed(draw: st.DrawFn, parent: Scope) -> Scope:
    """Draw a scope genuinely contained by `parent`.

    Children are constructed rather than filtered for. Drawing two scopes at
    random and discarding the pairs that happen not to nest would spend the
    budget on rejects and leave the interesting cases -- the ones that *do*
    nest -- barely explored.
    """
    actions = draw(st.lists(st.sampled_from(sorted(parent.actions)), min_size=1, unique=True))
    resource = parent.resource
    if resource.has_wildcard:
        concrete = draw(st.sampled_from(["lobby", "ops", "api", "example.com", "translate.ja"]))
        resource_text = "/".join([*resource.segments[:-1], concrete])
        candidate = f"{resource.prefix}:{resource_text}"
        # `server/tool` renders back with its inner prefix; keep the wildcard
        # rather than emit a shape the grammar would refuse.
        if resource.prefix == "server/tool":
            candidate = f"server:{resource.segments[0]}/tool:{concrete}"
        return scope(parent.namespace, candidate, *actions)
    return scope(parent.namespace, resource.render(), *actions)


@st.composite
def requests(draw: st.DrawFn) -> tuple[str, str, str]:
    namespace = draw(namespaces)
    resource = draw(st.sampled_from([r for r in _RESOURCES[namespace] if "*" not in r]))
    action = draw(st.sampled_from(sorted(NAMESPACES[namespace].actions)))
    return namespace, resource, action


class TestAttenuationProperties:
    @given(st.lists(scopes(), min_size=1, max_size=3), scopes(), requests())
    @settings(max_examples=500)
    def test_a_child_never_permits_what_its_parent_forbids(
        self, parent: list[Scope], child: Scope, request: tuple[str, str, str]
    ) -> None:
        """The invariant the whole authority layer rests on.

        If a child attenuates from a parent, every concrete request the child
        permits must also be permitted by the parent. A counter-example here is
        a privilege escalation, not a style problem.
        """
        namespace, resource, action = request
        if attenuation_failure(tuple(parent), (child,)) is not None:
            return
        if not child.covers(namespace=namespace, resource=resource, action=action):
            return
        assert any(p.covers(namespace=namespace, resource=resource, action=action) for p in parent)

    @given(scopes(), st.data(), requests())
    @settings(max_examples=500)
    def test_a_constructed_child_is_always_within_its_parent(
        self, parent: Scope, data: st.DataObject, request: tuple[str, str, str]
    ) -> None:
        """The same invariant, exercised on pairs that actually nest."""
        child = data.draw(narrowed(parent))
        assert attenuation_failure((parent,), (child,)) is None
        namespace, resource, action = request
        if child.covers(namespace=namespace, resource=resource, action=action):
            assert parent.covers(namespace=namespace, resource=resource, action=action)

    @given(scopes(), st.data())
    @settings(max_examples=300)
    def test_containment_is_transitive_down_a_chain(self, root: Scope, data: st.DataObject) -> None:
        # Chains are built one delegation at a time; without transitivity a
        # grandchild could hold what its grandparent never did.
        child = data.draw(narrowed(root))
        grandchild = data.draw(narrowed(child))
        assert root.contains(child)
        assert child.contains(grandchild)
        assert root.contains(grandchild)

    @given(scopes())
    def test_containment_is_reflexive(self, one: Scope) -> None:
        assert one.contains(one)

    @given(scopes(), scopes())
    @settings(max_examples=500)
    def test_mutual_containment_means_equal_permissions(self, a: Scope, b: Scope) -> None:
        if not (a.contains(b) and b.contains(a)):
            return
        assert a.actions == b.actions
        assert a.resource.render() == b.resource.render()

    @given(scopes(), requests())
    @settings(max_examples=300)
    def test_a_malformed_request_is_never_covered(
        self, one: Scope, request: tuple[str, str, str]
    ) -> None:
        namespace, _resource, action = request
        for nonsense in ("", "room:", "..", "room:a/b/c/d", "*"):
            assert not one.covers(namespace=namespace, resource=nonsense, action=action)
