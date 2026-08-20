"""How the boundary answers: statuses, envelopes, headers and the notice page.

§16 asks for consistent failure semantics, and the reason it matters is on the
client side: a console that cannot tell "session expired" from "access denied"
from "gateway down" shows the same shrug for all three, and an operator debugs
the wrong thing during an incident.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.auth.notice import STYLE_HASH
from app.config.settings import Settings
from app.main import create_app
from app.middleware.request_id import HSTS_HEADER
from tests.conftest import TRUSTED_PEER, UNTRUSTED_PEER

pytestmark = pytest.mark.api

OPERATOR = {"X-Auth-Request-User": "alice@example.test"}
BROWSER = {"accept": "text/html,application/xhtml+xml"}


async def test_a_refusal_uses_the_projects_error_envelope(enforcing_client):
    """One envelope for every failure, so a client never has to guess a shape."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        response = await client.get("/api/v1/overview")
    body = response.json()
    assert response.status_code == 401
    assert body["error"]["type"] == "authentication_error"
    assert body["error"]["message"] == "Authentication required."
    assert body["error"]["request_id"]


async def test_a_refusal_carries_the_correlation_id_and_security_headers(enforcing_client):
    """A 401 is a response like any other. Registering the boundary inside the
    request-id and security-header middleware is what makes that true — an
    unauthenticated request is exactly the one an operator later needs to
    correlate."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        response = await client.get("/api/v1/overview")
    assert response.headers["x-request-id"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"


async def test_a_browser_gets_a_page_and_an_api_client_gets_json(enforcing_client):
    """A raw JSON blob is not an answer to a human who typed the console's URL,
    and an HTML page is not an answer to `fetch`."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        page = await client.get("/dashboard", headers=BROWSER)
        api = await client.get("/api/v1/overview", headers=BROWSER)
    assert page.headers["content-type"].startswith("text/html")
    assert "Not signed in" in page.text
    assert api.headers["content-type"].startswith("application/json")


async def test_the_notice_page_carries_a_hashed_style_not_unsafe_inline(enforcing_client):
    """The page needs one inline `<style>`, and a CSP hash admits exactly that
    block and nothing else. `'unsafe-inline'` would admit any script or style an
    injection managed to introduce."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        page = await client.get("/dashboard", headers=BROWSER)
    csp = page.headers["content-security-policy"]
    assert STYLE_HASH in csp
    assert "unsafe-inline" not in csp
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


async def test_the_notice_page_never_reflects_anything_from_the_request(enforcing_client):
    """Every string in it is a constant, so there is no escaping to get wrong."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        page = await client.get(
            "/dashboard/<script>alert(1)</script>",
            headers={**BROWSER, "X-Auth-Request-User": "<img src=x onerror=alert(1)>"},
        )
    assert "<script>alert" not in page.text
    assert "onerror" not in page.text


async def test_the_forbidden_page_does_not_offer_a_pointless_reload(enforcing_client):
    """Reloading fixes an expired session and can never fix an unauthorised
    account. Offering it there would be a loop dressed as a remedy."""
    async with enforcing_client(peer=TRUSTED_PEER, operator_roles="security-ops") as client:
        page = await client.get(
            "/dashboard", headers={**OPERATOR, **BROWSER, "X-Auth-Request-Groups": "interns"}
        )
    assert page.status_code == 403
    assert "Access denied" in page.text
    assert "Reload" not in page.text


# --- The session endpoint ---------------------------------------------------


async def test_the_session_endpoint_reports_the_authenticated_operator(enforcing_client):
    async with enforcing_client(peer=TRUSTED_PEER, console_logout_path="/oauth2/sign_out") as c:
        body = (await c.get("/api/v1/session", headers=OPERATOR)).json()
    assert body == {
        "authenticated": True,
        "enforced": True,
        "subject": "alice@example.test",
        "role": "operator",
        "logout_path": "/oauth2/sign_out",
    }


async def test_the_session_endpoint_is_itself_behind_the_boundary(enforcing_client):
    """Deliberately not a public "am I signed in?" probe. A 401 here *is* the
    answer, which means no second unprotected endpoint has to exist to report
    authentication state."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        assert (await client.get("/api/v1/session")).status_code == 401


async def test_the_session_endpoint_admits_when_authentication_is_off(client: AsyncClient):
    """Development. The console shows an explicit "auth disabled" state rather
    than inventing an operator — a fabricated security property is worse than a
    missing one."""
    body = (await client.get("/api/v1/session")).json()
    assert body["authenticated"] is False
    assert body["enforced"] is False
    assert body["subject"] is None


# --- Unchanged behaviour ----------------------------------------------------


async def test_the_default_development_stack_is_unchanged(client: AsyncClient):
    """The boundary is off outside production, so `docker compose up` still
    works with one command and no credential (NFR-012)."""
    for path in ("/health", "/ready", "/metrics", "/api/v1/detectors", "/dashboard"):
        assert (await client.get(path)).status_code == 200, path


async def test_hsts_is_absent_unless_https_is_declared(client: AsyncClient):
    """Sending HSTS from a plain-HTTP development server pins the operator's
    browser to a scheme localhost does not serve, and the lockout outlives the
    container."""
    response = await client.get("/health")
    assert "strict-transport-security" not in {k.lower() for k in response.headers}


async def test_hsts_is_sent_only_on_a_response_that_travelled_over_tls():
    """The world changed twice here, and the second change is the interesting one.

    Phase 9: `https_enforced` meant "add an HSTS header", so it needed nothing
    else and applied to every response. Phase 12 (ADR-026) makes it *enforce*
    HTTPS, which requires a trusted proxy to assert the client's scheme — and
    makes the header conditional on that same assertion.

    The reason is `/health`. It stays reachable over plaintext under enforcement
    so a misconfigured deployment is diagnosable, and a response that travelled
    in the clear must not pin the operator's browser to a scheme that hop did not
    serve. The pin outlives the mistake.
    """
    from httpx import ASGITransport

    app = create_app(Settings(https_enforced=True, trusted_proxies="127.0.0.1/32"))
    transport = ASGITransport(app=app, client=TRUSTED_PEER)
    async with AsyncClient(transport=transport, base_url="http://firewall") as client:
        async with app.router.lifespan_context(app):
            over_tls = await client.get("/health", headers={"X-Forwarded-Proto": "https"})
            in_the_clear = await client.get("/health")

    assert over_tls.headers["strict-transport-security"] == HSTS_HEADER[1].decode()
    assert "strict-transport-security" not in {k.lower() for k in in_the_clear.headers}


async def test_cors_is_still_absent(enforcing_client):
    """§13: the console is same-origin, so there is no CORS surface to configure
    and no `allow_origins` to get wrong. Adding authentication must not
    accidentally introduce one."""
    async with enforcing_client(peer=TRUSTED_PEER) as client:
        response = await client.get(
            "/api/v1/detectors", headers={**OPERATOR, "Origin": "https://evil.example"}
        )
    assert "access-control-allow-origin" not in {k.lower() for k in response.headers}
