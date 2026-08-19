"""OpenAI compatibility and failure semantics for the caller boundary (ADR-024).

The adoption argument for this whole project is one line —
`OpenAI(base_url=..., api_key=...)` — so an authentication mechanism that
requires a client change would cost more than it protects. These tests pin that
the mechanism is the one an OpenAI client already speaks, and that its failures
arrive in the envelope such a client already handles.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.auth.caller import digest
from app.config.settings import Settings
from app.main import create_app
from tests.conftest import CALLER_ID, CALLER_KEY, CHAT_BODY

pytestmark = pytest.mark.api

CHAT = "/v1/chat/completions"
AUTH = {"authorization": f"Bearer {CALLER_KEY}"}


async def test_an_unmodified_openai_client_authenticates(caller_client):
    """`api_key=` on the SDK becomes `Authorization: Bearer`, which is exactly
    what this boundary reads. Adopting the gateway stays a base-URL change."""
    async with caller_client() as client:
        # Precisely the header an OpenAI SDK emits, constructed the same way.
        response = await client.post(
            CHAT, json=CHAT_BODY, headers={"Authorization": f"Bearer {CALLER_KEY}"}
        )
    assert response.status_code == 200
    body = response.json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["role"] == "assistant"


async def test_the_refusal_uses_the_openai_error_envelope(caller_client):
    """An existing client's error handling reads `error.message`, `error.type`
    and `error.code`. A bespoke shape would surface as an unparsed exception."""
    async with caller_client() as client:
        response = await client.post(CHAT, json=CHAT_BODY)
    error = response.json()["error"]
    assert response.status_code == 401
    assert error["message"] == "Incorrect API key provided."
    assert error["type"] == "invalid_request_error"
    assert error["code"] == "invalid_api_key"
    assert error["request_id"]


async def test_a_refusal_carries_the_correlation_id_and_security_headers(caller_client):
    """Registering the boundary inside request-id and security-header middleware
    is what makes this true — an unauthorised request is exactly the one an
    operator later needs to correlate."""
    async with caller_client() as client:
        response = await client.post(CHAT, json=CHAT_BODY)
    assert response.headers["x-request-id"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


async def test_no_www_authenticate_header_is_sent(caller_client):
    """Matching the OpenAI API. Sending it makes a browser that wandered onto the
    endpoint pop a credential dialog, which is not where a service key belongs."""
    async with caller_client() as client:
        response = await client.post(CHAT, json=CHAT_BODY)
    assert "www-authenticate" not in {k.lower() for k in response.headers}


async def test_rate_limiting_returns_429_with_retry_after(caller_client):
    async with caller_client(caller_rate_limit_per_minute=2) as client:
        for _ in range(2):
            assert (await client.post(CHAT, json=CHAT_BODY, headers=AUTH)).status_code == 200
        limited = await client.post(CHAT, json=CHAT_BODY, headers=AUTH)

    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) >= 1
    error = limited.json()["error"]
    assert error["type"] == "rate_limit_exceeded"
    assert error["code"] == "rate"
    assert error["request_id"]


async def test_rate_limiting_never_reaches_the_model(caller_client, upstream):
    async with caller_client(caller_rate_limit_per_minute=1) as client:
        await client.post(CHAT, json=CHAT_BODY, headers=AUTH)
        await client.post(CHAT, json=CHAT_BODY, headers=AUTH)
    assert upstream.call_count == 1


# --- §14 / §17: ordering -------------------------------------------------------


async def test_authentication_precedes_schema_validation(caller_client):
    """An anonymous client must not be able to learn which fields the gateway
    validates — and, more importantly, must not get any work done on its behalf."""
    async with caller_client() as client:
        response = await client.post(CHAT, json={"nonsense": True})
    assert response.status_code == 401
    assert response.json()["error"]["type"] == "invalid_request_error"


async def test_the_body_limit_still_precedes_authentication(caller_client):
    """§17: an oversized body is rejected before a header is read, so a client
    cannot make the gateway buffer megabytes in order to be told it is
    unauthorised."""
    async with caller_client(max_request_bytes=2048) as client:
        response = await client.post(
            CHAT,
            content=b'{"padding": "' + b"x" * 4096 + b'"}',
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 413
    assert response.json()["error"]["type"] == "request_too_large"


async def test_authentication_precedes_detector_inference(caller_client):
    """The layer-2 transformer costs ~95 ms of CPU per call (ADR-021). Doing that
    work for a request about to be refused is a denial of service that
    authentication was supposed to prevent."""
    inspected: list[str] = []

    async with caller_client() as client:
        app = client._transport.app  # type: ignore[attr-defined]
        pipeline = app.state.pipeline
        original = pipeline.run

        async def counting(direction, ctx):
            inspected.append(ctx.request_id)
            return await original(direction, ctx)

        pipeline.run = counting
        await client.post(CHAT, json=CHAT_BODY)
        assert inspected == [], "an unauthenticated request reached the detectors"
        await client.post(CHAT, json=CHAT_BODY, headers=AUTH)
        assert inspected, "the authenticated request did not reach the detectors"


# --- §20: the audit trail ------------------------------------------------------


async def test_the_audit_row_records_the_caller_and_never_the_credential(caller_client, audit):
    async with caller_client() as client:
        await client.post(CHAT, json=CHAT_BODY, headers=AUTH)

    trace = audit.last
    assert trace.caller_id == CALLER_ID
    serialised = trace.model_dump_json()
    assert CALLER_KEY not in serialised
    assert digest(CALLER_KEY) not in serialised
    assert "authorization" not in serialised.lower()


async def test_an_unauthenticated_deployment_records_no_caller(client, audit):
    """`NULL` means "the boundary was off", which is a different fact from "an
    anonymous caller" — and inventing either would put a claim in the audit trail
    that nobody made."""
    await client.post(CHAT, json=CHAT_BODY)
    assert audit.last.caller_id is None


# --- Metrics -------------------------------------------------------------------


async def test_the_metrics_expose_caller_activity_without_the_credential(caller_client):
    async with caller_client(caller_rate_limit_per_minute=1) as client:
        await client.post(CHAT, json=CHAT_BODY, headers=AUTH)
        await client.post(CHAT, json=CHAT_BODY, headers=AUTH)  # rate limited
        await client.post(CHAT, json=CHAT_BODY)  # unauthenticated
        body = (await client.get("/metrics")).text

    assert f'firewall_caller_requests_total{{caller="{CALLER_ID}"}} 1.0' in body
    assert 'firewall_caller_auth_failures_total{reason="missing_credential"} 1.0' in body
    assert f'firewall_rate_limited_requests_total{{caller="{CALLER_ID}",limit="rate"}} 1.0' in body
    assert CALLER_KEY not in body
    assert digest(CALLER_KEY) not in body


# --- Unchanged behaviour --------------------------------------------------------


async def test_the_default_stack_is_unchanged(client: AsyncClient):
    for path in ("/health", "/ready", "/metrics", "/dashboard", "/api/v1/overview"):
        assert (await client.get(path)).status_code == 200, path
    assert (await client.post(CHAT, json=CHAT_BODY)).status_code == 200


async def test_both_boundaries_can_be_enforced_at_once():
    """They are independent, and a deployment turns on both. This is the
    configuration production actually runs, so it is worth one test of its own."""
    from httpx import ASGITransport

    settings = Settings(
        caller_auth_mode="api_key",
        caller_api_keys=f"{CALLER_ID}:{digest(CALLER_KEY)}",
        console_auth_mode="proxy",
        trusted_proxies="127.0.0.1/32",
    )
    app = create_app(settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 4444))
    async with AsyncClient(transport=transport, base_url="http://firewall") as client:
        async with app.router.lifespan_context(app):
            assert (await client.get("/health")).status_code == 200
            assert (await client.get("/api/v1/detectors")).status_code == 401
            assert (
                await client.get("/api/v1/detectors", headers={"X-Auth-Request-User": "alice"})
            ).status_code == 200
            assert (await client.post(CHAT, json=CHAT_BODY)).status_code == 401
            assert (await client.post(CHAT, json=CHAT_BODY, headers=AUTH)).status_code == 200
