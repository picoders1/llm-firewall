"""Error envelope, correlation IDs, and honest not-implemented responses."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.api


# --- Error envelope (docs/07-openai-compatible-api.md) ---------------------


async def test_unknown_route_uses_the_openai_error_shape(client: AsyncClient):
    response = await client.get("/v1/does-not-exist")

    assert response.status_code == 404
    error = response.json()["error"]
    assert error["type"] == "not_found_error"
    assert "message" in error
    assert error["request_id"]


async def test_error_body_carries_the_request_id_for_correlation(client: AsyncClient):
    response = await client.get("/nope")

    assert response.json()["error"]["request_id"] == response.headers["x-request-id"]


# --- Honest 501s (the Phase 0 boundary) ------------------------------------


async def test_chat_completions_is_implemented_and_inspected(client: AsyncClient):
    """The slice is live: the endpoint now proxies, and every request is
    inspected before it is forwarded."""
    response = await client.post(
        "/v1/chat/completions",
        json={"model": "any", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 200
    assert "choices" in response.json()
    assert response.headers["x-firewall-decision"] == "allow"


@pytest.mark.parametrize(("method", "path"), [("get", "/v1/models")])
async def test_reserved_endpoints_return_501(client: AsyncClient, method: str, path: str):
    """`/metrics` used to be listed here. Phase 5 implemented it, so it now
    returns a real Prometheus exposition — the expectation changed because the
    world changed, not because the assertion was inconvenient. Its behaviour is
    covered by `test_metrics_endpoint.py`."""
    response = await getattr(client, method)(path)

    assert response.status_code == 501
    assert response.json()["error"]["type"] == "not_implemented"


async def test_metrics_is_no_longer_reserved(client: AsyncClient):
    response = await client.get("/metrics")

    assert response.status_code == 200
    assert "openmetrics" in response.headers["content-type"]


# --- Correlation IDs (FR-050, FR-051) --------------------------------------


async def test_request_id_is_generated_when_absent(client: AsyncClient):
    request_id = (await client.get("/health")).headers["x-request-id"]

    assert request_id
    assert len(request_id) == 32


async def test_valid_client_request_id_is_reused(client: AsyncClient):
    response = await client.get("/health", headers={"X-Request-ID": "trace-abc.123:xyz_9"})

    assert response.headers["x-request-id"] == "trace-abc.123:xyz_9"


async def test_request_ids_are_unique_per_request(client: AsyncClient):
    first = (await client.get("/health")).headers["x-request-id"]
    second = (await client.get("/health")).headers["x-request-id"]

    assert first != second


@pytest.mark.security
@pytest.mark.parametrize(
    "malicious",
    [
        'evil"}\n{"level":"info","event":"forged',  # log injection via newline
        "abc\r\ninjected",
        "abc\ndef",
        "x" * 129,  # over the length bound
        "spaces are not allowed",
        "<script>alert(1)</script>",
    ],
)
async def test_malicious_request_id_is_replaced_not_echoed(client: AsyncClient, malicious: str):
    """A header with a newline and a forged JSON object would otherwise write
    attacker-controlled records into the security log (FR-051)."""
    response = await client.get("/health", headers={"X-Request-ID": malicious})

    returned = response.headers["x-request-id"]
    assert returned != malicious
    assert len(returned) == 32
    assert "\n" not in returned and "\r" not in returned
