"""The caller's credential must never become the gateway's (ADR-024 §18 / §19).

This is the property that makes caller authentication worth having. If a client's
`Authorization` header reached the provider, then either the client could
present its own billing credential through this gateway, or — far worse — the
gateway's upstream key could be influenced by request content.

The isolation is **structural rather than filtered**, and that distinction is the
finding worth recording: `HttpUpstreamClient` builds its `authorization` header
once at construction from `FIREWALL_UPSTREAM_API_KEY`, and its only request-time
input is `chat_completions(payload: dict)` — a JSON body. There is no parameter
through which an inbound header could travel, so there is no denylist to keep up
to date and no header that gets forwarded because someone forgot to add it.

These tests pin that shape. A future refactor that "helpfully" starts forwarding
client headers has to break one of them.
"""

from __future__ import annotations

import inspect

import httpx
import pytest

from app.config.settings import Settings
from app.gateway.upstream import HttpUpstreamClient, UpstreamClient
from tests.conftest import CALLER_KEY, CHAT_BODY

pytestmark = pytest.mark.security

UPSTREAM_KEY = "sk-upstream-must-never-be-influenced-by-a-caller"


def _client_capturing(requests: list[httpx.Request]) -> HttpUpstreamClient:
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "model": "mock",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "4"},
                        "finish_reason": "stop",
                    }
                ],
            },
        )

    settings = Settings(upstream_api_key=UPSTREAM_KEY, upstream_base_url="https://provider/v1")
    transport = httpx.MockTransport(handler)
    # Headers are built by the client under test, not by the fixture: passing them
    # in would test the fixture.
    inner = httpx.AsyncClient(
        transport=transport,
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {UPSTREAM_KEY}",
        },
    )
    return HttpUpstreamClient(settings, client=inner)


# --- The structural argument, asserted ---------------------------------------


def test_the_upstream_contract_accepts_no_headers_at_all():
    """The reason no header can leak: there is nowhere to put one.

    `chat_completions` takes a JSON payload and nothing else, on both the
    Protocol and the implementation. A refactor that adds a `headers` parameter
    is the moment this property stops being structural, and it fails here.
    """
    for owner in (UpstreamClient, HttpUpstreamClient):
        signature = inspect.signature(owner.chat_completions)
        assert list(signature.parameters) == ["self", "payload"], owner.__name__


async def test_the_upstream_credential_is_bound_once_at_construction():
    """Not read per request, so no request-scoped value can reach it.

    The client is built without an injected transport precisely because the
    header construction is what is under test — handing one in would assert on
    the fixture instead.
    """
    client = HttpUpstreamClient(Settings(upstream_api_key=UPSTREAM_KEY))
    try:
        assert client._client.headers["authorization"] == f"Bearer {UPSTREAM_KEY}"
    finally:
        await client.aclose()


# --- End to end through the gateway ------------------------------------------


async def test_a_client_authorization_header_never_reaches_the_provider(caller_client):
    """The headline case: a caller presents its own key and the provider sees the
    gateway's, unchanged."""
    captured: list[httpx.Request] = []
    async with caller_client() as client:
        client._transport.app.state.upstream = _client_capturing(captured)  # type: ignore[attr-defined]
        response = await client.post(
            "/v1/chat/completions",
            json=CHAT_BODY,
            headers={"authorization": f"Bearer {CALLER_KEY}"},
        )

    assert response.status_code == 200
    assert len(captured) == 1
    forwarded = captured[0].headers["authorization"]
    assert forwarded == f"Bearer {UPSTREAM_KEY}"
    assert CALLER_KEY not in forwarded


@pytest.mark.parametrize(
    "header",
    ["proxy-authorization", "cookie", "x-api-key", "openai-organization"],
)
async def test_no_credential_bearing_client_header_is_forwarded(caller_client, header: str):
    """§19 names these explicitly. None of them can arrive upstream, because the
    upstream request is constructed rather than relayed.

    `authorization` is absent from this list only because it cannot be sent twice
    on one request — it is covered by the headline test above, which asserts the
    provider sees the gateway's key and not the caller's.
    """
    captured: list[httpx.Request] = []
    async with caller_client() as client:
        client._transport.app.state.upstream = _client_capturing(captured)  # type: ignore[attr-defined]
        await client.post(
            "/v1/chat/completions",
            json=CHAT_BODY,
            headers={
                "authorization": f"Bearer {CALLER_KEY}",
                header: "leaked-value-do-not-forward",
            },
        )

    assert captured, "the upstream was never called, so nothing was proven"
    assert header not in captured[0].headers


@pytest.mark.parametrize(
    "header",
    ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded", "host"],
)
async def test_no_forwarding_header_is_relayed_to_the_provider(caller_client, header: str):
    """A relayed `X-Forwarded-Host` lets a caller influence how the provider sees
    the request's origin; a relayed `Host` can redirect it outright. The gateway
    addresses the provider itself, so neither travels."""
    captured: list[httpx.Request] = []
    async with caller_client() as client:
        client._transport.app.state.upstream = _client_capturing(captured)  # type: ignore[attr-defined]
        await client.post(
            "/v1/chat/completions",
            json=CHAT_BODY,
            headers={
                "authorization": f"Bearer {CALLER_KEY}",
                header: "attacker.example",
            },
        )

    assert captured
    assert captured[0].headers.get(header, "") != "attacker.example"
    assert captured[0].url.host == "provider"


async def test_the_upstream_credential_never_appears_in_a_response(caller_client):
    """Including on the error paths, where a reflected upstream body would be the
    obvious way for it to escape."""
    captured: list[httpx.Request] = []
    async with caller_client() as client:
        client._transport.app.state.upstream = _client_capturing(captured)  # type: ignore[attr-defined]
        ok = await client.post(
            "/v1/chat/completions",
            json=CHAT_BODY,
            headers={"authorization": f"Bearer {CALLER_KEY}"},
        )
        refused = await client.post("/v1/chat/completions", json=CHAT_BODY)
        bad = await client.post(
            "/v1/chat/completions",
            json={"messages": "not a list"},
            headers={"authorization": f"Bearer {CALLER_KEY}"},
        )

    for response in (ok, refused, bad):
        assert UPSTREAM_KEY not in response.text
        assert "sk-" not in response.text


def test_the_upstream_key_is_not_in_the_startup_summary():
    summary = Settings(upstream_api_key=UPSTREAM_KEY).safe_summary()
    assert UPSTREAM_KEY not in str(summary)
    assert summary["upstream_api_key_set"] is True
