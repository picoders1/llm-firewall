"""Static delivery of the security console.

Serving HTML from the gateway changes an assumption the codebase made
explicitly: `SECURITY_HEADERS` omits CSP because "this is an API, not a browser
origin". These tests hold the new boundary — a Content Security Policy on
dashboard responses, and API responses unchanged.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.api

ASSETS = (
    "/dashboard/index.html",
    "/dashboard/css/tokens.css",
    "/dashboard/js/app.js",
    "/dashboard/js/api.js",
    "/dashboard/favicon.svg",
)


async def test_the_console_is_served(client: AsyncClient):
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "LLM Firewall" in response.text


@pytest.mark.parametrize("path", ASSETS)
async def test_assets_are_served_with_correct_types(client: AsyncClient, path: str):
    response = await client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"] not in (None, "application/octet-stream")


async def test_a_deep_link_survives_a_refresh(client: AsyncClient):
    """History-API routes must resolve to the shell, or refreshing an event page
    would 404."""
    for path in ("/dashboard/events/42", "/dashboard/evaluations/some-run-id", "/dashboard/system"):
        response = await client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")


async def test_a_missing_asset_is_a_404_not_the_shell(client: AsyncClient):
    """Returning HTML for a missing script makes the browser execute a document."""
    response = await client.get("/dashboard/js/does-not-exist.js")
    assert response.status_code == 404


async def test_path_traversal_is_refused(client: AsyncClient):
    for attempt in (
        "/dashboard/../app/main.py",
        "/dashboard/../../etc/passwd",
        "/dashboard/css/../../app/config/settings.py",
    ):
        response = await client.get(attempt)
        assert response.status_code == 404, attempt
        assert "settings" not in response.text.lower() or response.status_code == 404


# --- The header boundary ----------------------------------------------------


async def test_dashboard_responses_carry_a_strict_csp(client: AsyncClient):
    response = await client.get("/dashboard")
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    # The console is written so these are unnecessary; if either appears, the
    # frontend has regressed into inline script or eval.
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


async def test_the_console_cannot_be_framed(client: AsyncClient):
    response = await client.get("/dashboard")
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


async def test_api_responses_are_unchanged_by_the_dashboard(client: AsyncClient):
    """The existing header contract still holds; CSP is scoped to the console."""
    response = await client.get("/api/v1/policy")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "content-security-policy" not in response.headers


async def test_the_console_is_same_origin_so_no_cors_is_exposed(client: AsyncClient):
    """A CORS header would mean the console could be driven from another origin."""
    response = await client.get("/dashboard")
    assert "access-control-allow-origin" not in response.headers
