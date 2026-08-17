"""Health and readiness.

Two endpoints with genuinely different meanings. Conflating them is how a
deployment routes traffic to a process whose detectors have not loaded.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.api


# --- Liveness --------------------------------------------------------------


async def test_health_returns_ok(client: AsyncClient):
    response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "llm-firewall"
    assert body["version"]


async def test_health_does_not_depend_on_startup(cold_client: AsyncClient):
    """Liveness must answer even when dependencies are not ready — otherwise a
    liveness probe restarts a container that is merely still starting."""
    assert (await cold_client.get("/health")).status_code == 200


async def test_health_reveals_no_configuration(client: AsyncClient):
    body = (await client.get("/health")).text.lower()
    for leak in ("postgres", "password", "api_key", "upstream", "policy"):
        assert leak not in body


# --- Readiness -------------------------------------------------------------


async def test_ready_returns_200_when_everything_passes(client: AsyncClient):
    response = await client.get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert all(check["passed"] for check in body["checks"])


async def test_ready_reports_a_per_check_breakdown(client: AsyncClient):
    checks = {check["name"] for check in (await client.get("/ready")).json()["checks"]}

    assert {"policy_loaded", "detectors_warmed", "database"} <= checks


async def test_ready_is_503_before_detectors_are_warmed(cold_client: AsyncClient):
    """An instance that cannot inspect must not receive traffic (ADR-007)."""
    response = await cold_client.get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    warmed = next(c for c in body["checks"] if c["name"] == "detectors_warmed")
    assert warmed["passed"] is False


async def test_ready_reports_disabled_persistence_without_failing(client: AsyncClient):
    """Persistence off is a configuration choice, not a fault — but it is still
    surfaced, so the breakdown never hides that auditing is disabled."""
    database = next(
        c for c in (await client.get("/ready")).json()["checks"] if c["name"] == "database"
    )

    assert database["passed"] is True
    assert database["detail"] == "persistence disabled"


async def test_ready_exposes_policy_version_not_policy_content(client: AsyncClient):
    policy_check = next(
        c for c in (await client.get("/ready")).json()["checks"] if c["name"] == "policy_loaded"
    )

    assert policy_check["detail"].startswith("sha256:")


# --- Headers ---------------------------------------------------------------


@pytest.mark.parametrize("path", ["/health", "/ready"])
async def test_security_headers_are_present(client: AsyncClient, path: str):
    headers = (await client.get(path)).headers

    assert headers["x-content-type-options"] == "nosniff"
    # Responses can carry completions; a caching proxy must not retain them.
    assert headers["cache-control"] == "no-store"
    assert headers["referrer-policy"] == "no-referrer"
