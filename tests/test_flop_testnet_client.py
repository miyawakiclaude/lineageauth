"""The restricted client, including acceptance J: a redirect to another origin is blocked."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from lineageauth.flop.model import TestnetFailure
from lineageauth.flop.testnet.client import (
    REDACTED,
    CountingTransport,
    RestrictedClient,
    origin_of,
    redact,
    redact_headers,
    sha256_of,
)
from lineageauth.flop.testnet.endpoints import (
    SIMULATION_ENDPOINT_ID,
    FlopEndpoint,
    FlopEndpointRegistry,
)
from lineageauth.flop.testnet.ports import RawResponse, TransportRequest


@dataclass(slots=True)
class ScriptedTransport:
    """Answers with whatever a test scripted. Opens nothing."""

    response: RawResponse
    calls: list[TransportRequest] = field(default_factory=list)

    def send(self, request: TransportRequest) -> RawResponse:
        self.calls.append(request)
        return self.response


def client_for(response: RawResponse) -> tuple[RestrictedClient, ScriptedTransport, FlopEndpoint]:
    registry = FlopEndpointRegistry.default()
    endpoint = registry.get(SIMULATION_ENDPOINT_ID)
    assert endpoint is not None
    transport = ScriptedTransport(response=response)
    return RestrictedClient(registry=registry, transport=transport), transport, endpoint


class TestAcceptanceJ:
    def test_acceptance_j_a_response_from_another_origin_is_blocked(self) -> None:
        client, _, endpoint = client_for(
            RawResponse(
                status=200,
                body=b'{"result":"trust me"}',
                final_url="https://faucet.example/claim",
            )
        )
        result = client.send(endpoint=endpoint, path="/simulation/inference", body=b"{}")
        assert result.ok is False
        assert result.refusal is not None
        assert result.refusal.failure is TestnetFailure.ENDPOINT_BLOCKED
        assert "redirect" in result.warnings[0]
        assert result.response_sha256 is None

    def test_acceptance_j_the_new_origin_is_reclassified_in_the_refusal(self) -> None:
        client, _, endpoint = client_for(
            RawResponse(
                status=200,
                body=b"{}",
                final_url="https://fl0p.finance/claim",
            )
        )
        result = client.send(endpoint=endpoint, path="/simulation/inference", body=b"{}")
        assert result.refusal is not None
        assert "suspicious" in result.refusal.detail
        assert "needs its own approval" in result.refusal.detail

    def test_acceptance_j_a_3xx_answer_is_not_followed(self) -> None:
        client, transport, endpoint = client_for(
            RawResponse(
                status=302,
                body=b"",
                headers={"location": "https://faucet.example/claim"},
                final_url="https://testnet.simulation.invalid/simulation/inference",
            )
        )
        result = client.send(endpoint=endpoint, path="/simulation/inference", body=b"{}")
        assert result.ok is False
        assert result.refusal is not None
        assert result.refusal.failure is TestnetFailure.ENDPOINT_BLOCKED
        assert "redirects are not followed" in result.refusal.detail
        assert len(transport.calls) == 1

    def test_acceptance_j_the_redirect_flag_alone_blocks_the_answer(self) -> None:
        client, _, endpoint = client_for(
            RawResponse(
                status=200,
                body=b"{}",
                final_url="https://testnet.simulation.invalid/simulation/inference",
                redirected=True,
            )
        )
        result = client.send(endpoint=endpoint, path="/simulation/inference", body=b"{}")
        assert result.ok is False

    def test_the_transport_is_told_not_to_follow_redirects(self) -> None:
        client, transport, endpoint = client_for(
            RawResponse(
                status=200,
                body=b"{}",
                final_url="https://testnet.simulation.invalid/simulation/inference",
            )
        )
        client.send(endpoint=endpoint, path="/simulation/inference", body=b"{}")
        assert transport.calls[0].follow_redirects is False


class TestAllowlist:
    def test_there_is_no_public_method_that_takes_a_bare_url(self) -> None:
        import inspect

        for name, member in inspect.getmembers(RestrictedClient, inspect.isfunction):
            if name.startswith("_"):
                continue
            parameters = set(inspect.signature(member).parameters)
            assert "url" not in parameters, name

    def test_a_lookalike_endpoint_object_is_refused(self) -> None:
        registry = FlopEndpointRegistry.default()
        lookalike = FlopEndpoint(
            endpoint_id=SIMULATION_ENDPOINT_ID,
            purpose="inference",
            origin="https://faucet.example",
            method="POST",
            path_pattern="/simulation/inference",
            network="n",
            source_url="https://faucet.example/",
            source_version="1",
        )
        client = RestrictedClient(registry=registry, transport=CountingTransport())
        result = client.send(endpoint=lookalike, path="/simulation/inference", body=b"{}")
        assert result.ok is False
        assert result.refusal is not None
        assert result.refusal.failure is TestnetFailure.ENDPOINT_BLOCKED

    def test_a_path_outside_the_pattern_is_refused_before_the_transport(self) -> None:
        registry = FlopEndpointRegistry.default()
        endpoint = registry.get(SIMULATION_ENDPOINT_ID)
        assert endpoint is not None
        transport = CountingTransport()
        client = RestrictedClient(registry=registry, transport=transport)
        result = client.send(endpoint=endpoint, path="/anything/else", body=b"{}")
        assert result.refusal is not None
        assert result.refusal.failure is TestnetFailure.REQUEST_INVALID
        assert transport.calls == 0

    def test_the_allowed_origins_are_the_registry_s(self) -> None:
        registry = FlopEndpointRegistry.default()
        client = RestrictedClient(registry=registry, transport=CountingTransport())
        assert client.allowed_origins == registry.allowed_origins


class TestLimits:
    def test_an_over_sized_response_is_not_parsed(self) -> None:
        registry = FlopEndpointRegistry.default()
        endpoint = registry.get(SIMULATION_ENDPOINT_ID)
        assert endpoint is not None
        transport = ScriptedTransport(
            response=RawResponse(
                status=200,
                body=b"x" * 500,
                final_url="https://testnet.simulation.invalid/simulation/inference",
            )
        )
        client = RestrictedClient(registry=registry, transport=transport, max_response_bytes=100)
        result = client.send(endpoint=endpoint, path="/simulation/inference", body=b"{}")
        assert result.ok is False
        assert result.refusal is not None
        assert result.refusal.failure is TestnetFailure.INVALID_RESPONSE

    def test_the_caps_travel_with_the_request(self) -> None:
        client, transport, endpoint = client_for(
            RawResponse(
                status=200,
                body=b"{}",
                final_url="https://testnet.simulation.invalid/simulation/inference",
            )
        )
        client.send(endpoint=endpoint, path="/simulation/inference", body=b"{}")
        sent = transport.calls[0]
        assert sent.timeout_seconds > 0
        assert sent.max_response_bytes > 0

    def test_a_4xx_answer_is_a_typed_network_refusal(self) -> None:
        client, _, endpoint = client_for(
            RawResponse(
                status=503,
                body=b"{}",
                final_url="https://testnet.simulation.invalid/simulation/inference",
            )
        )
        result = client.send(endpoint=endpoint, path="/simulation/inference", body=b"{}")
        assert result.refusal is not None
        assert result.refusal.failure is TestnetFailure.NETWORK_REFUSED


class TestHashesAndRedaction:
    def test_the_request_and_response_are_recorded_by_hash(self) -> None:
        client, _, endpoint = client_for(
            RawResponse(
                status=200,
                body=b'{"result":"ok"}',
                final_url="https://testnet.simulation.invalid/simulation/inference",
            )
        )
        result = client.send(endpoint=endpoint, path="/simulation/inference", body=b'{"a":1}')
        assert result.request_sha256 == sha256_of(b'{"a":1}')
        assert result.response_sha256 == sha256_of(b'{"result":"ok"}')
        assert result.to_dict()["secretsRedacted"] is True

    def test_a_seed_shaped_string_is_redacted(self) -> None:
        assert redact("seed: correct horse battery staple") == REDACTED
        assert redact("private_key=abcdef") == REDACTED
        assert REDACTED in redact("the value is " + "a" * 64)

    def test_sensitive_headers_are_replaced_wholesale(self) -> None:
        headers = redact_headers({"Authorization": "Bearer abc", "Accept": "application/json"})
        assert headers["Authorization"] == REDACTED
        assert headers["Accept"] == "application/json"

    def test_the_client_never_forwards_a_raw_authorization_header(self) -> None:
        client, transport, endpoint = client_for(
            RawResponse(
                status=200,
                body=b"{}",
                final_url="https://testnet.simulation.invalid/simulation/inference",
            )
        )
        client.send(
            endpoint=endpoint,
            path="/simulation/inference",
            body=b"{}",
            headers={"authorization": "Bearer super-secret-token-value"},
        )
        assert transport.calls[0].headers["authorization"] == REDACTED

    def test_origin_of_drops_the_path(self) -> None:
        assert origin_of("https://flop.finance/a/b?c=1") == "https://flop.finance"


class TestTransportFailure:
    def test_a_transport_refusal_becomes_a_typed_result(self) -> None:
        registry = FlopEndpointRegistry.default()
        endpoint = registry.get(SIMULATION_ENDPOINT_ID)
        assert endpoint is not None
        client = RestrictedClient(registry=registry, transport=CountingTransport())
        result = client.send(endpoint=endpoint, path="/simulation/inference", body=b"{}")
        assert result.ok is False
        assert result.refusal is not None
        assert result.refusal.failure is TestnetFailure.NETWORK_REFUSED

    def test_the_counting_transport_counts(self) -> None:
        transport = CountingTransport()
        with pytest.raises(Exception, match="never performs a request"):
            transport.send(
                TransportRequest(method="POST", url="https://flop.finance/x", body=b"{}")
            )
        assert transport.calls == 1
