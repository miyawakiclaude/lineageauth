"""The allowlist, including acceptance B: a community faucet URL is blocked."""

from __future__ import annotations

import pytest

from lineageauth.errors import MalformedEventError
from lineageauth.flop.model import NetworkPhase, SourceClass, TestnetFailure, TestnetRefusal
from lineageauth.flop.testnet.endpoints import (
    SIMULATION_ENDPOINT_ID,
    SIMULATION_ORIGIN,
    EndpointDisposition,
    FlopEndpoint,
    FlopEndpointRegistry,
    endpoint_from_mapping,
)
from tests.flop_testnet_fixtures import OFFICIAL_LIVE_ENDPOINT, registry_with_live_endpoint


class TestTheShippedRegistry:
    def test_no_endpoint_is_executable_today(self) -> None:
        registry = FlopEndpointRegistry.default()
        assert registry.executable_entries == ()
        assert registry.to_dict()["officialTestnetExecutable"] is False

    def test_the_only_origin_is_one_that_cannot_resolve(self) -> None:
        registry = FlopEndpointRegistry.default()
        assert registry.allowed_origins == {SIMULATION_ORIGIN}
        assert SIMULATION_ORIGIN.endswith(".invalid")

    def test_a_simulation_entry_is_never_executable(self) -> None:
        entry = FlopEndpointRegistry.default().get(SIMULATION_ENDPOINT_ID)
        assert entry is not None
        assert entry.executable is False
        assert entry.disposition is EndpointDisposition.SIMULATION

    def test_a_simulation_entry_resolves_in_every_phase(self) -> None:
        registry = FlopEndpointRegistry.default()
        for phase in NetworkPhase:
            assert isinstance(registry.resolve(SIMULATION_ENDPOINT_ID, phase=phase), FlopEndpoint)


class TestConstructionRefusals:
    def test_an_http_origin_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="https is required"):
            FlopEndpoint(
                endpoint_id="downgrade",
                purpose="inference",
                origin="http://flop.finance",
                method="POST",
                path_pattern="/x",
                network="n",
                source_url="https://flop.finance/",
                source_version="1",
            )

    def test_an_origin_with_a_path_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="no path"):
            FlopEndpoint(
                endpoint_id="pathy",
                purpose="inference",
                origin="https://flop.finance/testnet",
                method="POST",
                path_pattern="/x",
                network="n",
                source_url="https://flop.finance/",
                source_version="1",
            )

    def test_a_live_entry_may_not_borrow_the_simulation_origin(self) -> None:
        with pytest.raises(MalformedEventError, match="simulation's origin"):
            FlopEndpoint(
                endpoint_id="pretend",
                purpose="inference",
                origin=SIMULATION_ORIGIN,
                method="POST",
                path_pattern="/x",
                network="n",
                source_url="https://flop.finance/",
                source_version="1",
                simulation=False,
            )

    def test_an_executable_entry_whose_source_is_not_official_cannot_be_registered(self) -> None:
        rogue = FlopEndpoint(
            endpoint_id="rogue",
            purpose="faucet",
            origin="https://faucet.flop-community.example",
            method="POST",
            path_pattern="/claim",
            network="n",
            source_url="https://technocore.chat/r/flop-faucet",
            source_version="1",
            verified_at="2026-09-03T00:00:00Z",
            enabled=True,
            source_class=SourceClass.OFFICIAL,
        )
        with pytest.raises(MalformedEventError, match="only an official source"):
            FlopEndpointRegistry.from_entries((rogue,))

    def test_a_duplicate_id_is_refused(self) -> None:
        entry = FlopEndpointRegistry.default().entries[0]
        with pytest.raises(MalformedEventError, match="duplicate endpoint id"):
            FlopEndpointRegistry.from_entries((entry, entry))


class TestAcceptanceB:
    def test_acceptance_b_a_community_faucet_url_is_blocked_and_never_executable(self) -> None:
        registry = FlopEndpointRegistry.default()
        verdict = registry.classify_candidate("https://technocore.chat/r/flop-faucet")
        assert verdict["sourceClass"] == "community"
        assert verdict["disposition"] == "READABLE_IF_SAFE"
        assert verdict["executable"] is False
        assert verdict["registeredEndpointId"] is None
        assert verdict["fetched"] is False

    def test_acceptance_b_an_unknown_faucet_url_is_blocked_outright(self) -> None:
        verdict = FlopEndpointRegistry.default().classify_candidate(
            "https://faucet.flop-community.example/claim"
        )
        assert verdict["disposition"] == "BLOCKED"
        assert verdict["executable"] is False

    def test_acceptance_b_a_lookalike_faucet_url_is_blocked(self) -> None:
        verdict = FlopEndpointRegistry.default().classify_candidate("https://fl0p.finance/faucet")
        assert verdict["sourceClass"] == "suspicious"
        assert verdict["disposition"] == "BLOCKED"

    def test_acceptance_b_resolving_an_unregistered_id_is_a_typed_refusal(self) -> None:
        refusal = FlopEndpointRegistry.default().resolve(
            "community-faucet", phase=NetworkPhase.PRE_TESTNET
        )
        assert isinstance(refusal, TestnetRefusal)
        assert refusal.failure is TestnetFailure.ENDPOINT_BLOCKED
        assert refusal.stage == "endpoint"


class TestAHypotheticalOfficialEntry:
    def test_it_is_executable_but_the_phase_still_refuses_it(self) -> None:
        registry = registry_with_live_endpoint()
        assert OFFICIAL_LIVE_ENDPOINT.executable is True
        refusal = registry.resolve(
            OFFICIAL_LIVE_ENDPOINT.endpoint_id, phase=NetworkPhase.PRE_TESTNET
        )
        assert isinstance(refusal, TestnetRefusal)
        assert refusal.failure is TestnetFailure.TESTNET_NOT_LIVE

    def test_it_resolves_once_the_phase_says_the_testnet_is_on(self) -> None:
        resolved = registry_with_live_endpoint().resolve(
            OFFICIAL_LIVE_ENDPOINT.endpoint_id, phase=NetworkPhase.TESTNET_ENABLED
        )
        assert isinstance(resolved, FlopEndpoint)

    def test_an_unverified_official_entry_is_readable_but_not_executable(self) -> None:
        unverified = FlopEndpoint(
            endpoint_id="unverified",
            purpose="inference",
            origin="https://flop.finance",
            method="POST",
            path_pattern="/testnet/v1/inference",
            network="n",
            source_url="https://flop.finance/teaser/",
            source_version="0.1-draft",
            verified_at=None,
            enabled=True,
            source_class=SourceClass.OFFICIAL,
        )
        assert unverified.executable is False
        assert unverified.disposition is EndpointDisposition.READABLE_IF_SAFE
        refusal = FlopEndpointRegistry.from_entries((unverified,)).resolve(
            "unverified", phase=NetworkPhase.TESTNET_ENABLED
        )
        assert isinstance(refusal, TestnetRefusal)
        assert refusal.failure is TestnetFailure.ENDPOINT_NOT_OFFICIAL


class TestPaths:
    def test_a_path_outside_the_pattern_is_refused(self) -> None:
        entry = FlopEndpointRegistry.default().entries[0]
        assert entry.matches_path("/simulation/faucet") is True
        assert entry.matches_path("/simulation/faucet/../../etc") is False
        assert entry.matches_path("/somewhere/else") is False
        with pytest.raises(MalformedEventError, match="does not match endpoint"):
            entry.url_for("/somewhere/else")

    def test_a_placeholder_segment_matches_exactly_one_segment(self) -> None:
        entry = FlopEndpoint(
            endpoint_id="templated",
            purpose="inference",
            origin="https://flop.finance",
            method="GET",
            path_pattern="/testnet/{model}/quote",
            network="n",
            source_url="https://flop.finance/",
            source_version="1",
        )
        assert entry.matches_path("/testnet/abc/quote") is True
        assert entry.matches_path("/testnet//quote") is False
        assert entry.matches_path("/testnet/a/b/quote") is False


class TestLoadingFromData:
    def test_a_mapping_without_an_origin_is_refused(self) -> None:
        with pytest.raises(MalformedEventError, match="non-empty 'origin'"):
            endpoint_from_mapping({"id": "x", "purpose": "p"})

    def test_a_loaded_entry_defaults_to_not_enabled(self) -> None:
        entry = endpoint_from_mapping(
            {
                "id": "loaded",
                "purpose": "inference",
                "origin": "https://flop.finance",
                "method": "POST",
                "pathPattern": "/x",
                "network": "n",
                "sourceUrl": "https://flop.finance/",
            }
        )
        assert entry.enabled is False
        assert entry.executable is False
        assert entry.source_class is SourceClass.UNKNOWN
