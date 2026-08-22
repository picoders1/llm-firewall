"""An upstream error is an error, whatever status it carries (R-114).

`HttpUpstreamClient.chat_completions` raised only on `status_code >= 500`. A 4xx
fell through to the success path, and `app/api/v1/chat.py` hardcodes
`JSONResponse(status_code=200, ...)` — so an upstream **401, 404 or 429 reached the
caller as 200 OK**, carrying the provider's error body verbatim.

Two registered rules were broken at once. `docs/07-openai-compatible-api.md` maps
upstream failure to **502 `upstream_error`**, and states that **upstream response
bodies are never reflected** because they can echo the prompt or provider
internals. For 4xx, neither held.

Found by pointing the gateway at a real model instead of the mock: Ollama answers
404 for an unknown model, and the caller got 200. The mock only ever produces 200,
a 500 via `__return_500__`, or a malformed 200 — so no fixture in the repository
could reach this branch. With a paid provider it is worse than cosmetic: a bad API
key (401) and a rate limit (429) both become apparent successes, and the audit row
records `decision=allow, status=2xx` for a request the model never answered.

These tests pin the contract at the client boundary, where the decision is made.
"""

from __future__ import annotations

import httpx
import pytest

from app.config.settings import Settings
from app.core.exceptions import UpstreamError
from app.gateway.upstream import HttpUpstreamClient

pytestmark = pytest.mark.unit

PAYLOAD = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}

# What a provider actually sends back, with the detail that must not escape.
ERROR_BODIES = {
    401: {"error": {"message": "Incorrect API key provided: sk-live-abc123"}},
    404: {"error": {"message": "model 'no-such-model' not found"}},
    429: {"error": {"message": "Rate limit reached for gpt-4 in org org-XYZ"}},
    400: {"error": {"message": "your prompt contained: my card is 4111111111111111"}},
    500: {"error": {"message": "internal server error"}},
}


def client_returning(status: int, body: object) -> HttpUpstreamClient:
    """A client whose transport always answers with `status`.

    The credential is bound at construction (ADR-024) and `chat_completions` takes
    only a payload, so the injected `httpx.AsyncClient` is the seam for a test.
    """
    settings = Settings(upstream_base_url="http://upstream.invalid/v1")
    transport = httpx.MockTransport(lambda _req: httpx.Response(status, json=body))
    return HttpUpstreamClient(settings, httpx.AsyncClient(transport=transport))


@pytest.mark.parametrize("status", sorted(ERROR_BODIES))
async def test_every_non_2xx_upstream_status_raises(status: int):
    """Not just 5xx. A 4xx that returns normally becomes a 200 to the caller,
    because the handler does not consult `UpstreamResult.status_code` at all."""
    upstream = client_returning(status, ERROR_BODIES[status])
    try:
        with pytest.raises(UpstreamError):
            await upstream.chat_completions(PAYLOAD)
    finally:
        await upstream.aclose()


@pytest.mark.parametrize("status", sorted(ERROR_BODIES))
async def test_the_upstream_body_never_reaches_the_exception(status: int):
    """`docs/07`: upstream bodies are never reflected. The bodies above carry an
    API key fragment, an organisation id and a card number — exactly the material
    that must not be echoed to a caller."""
    upstream = client_returning(status, ERROR_BODIES[status])
    try:
        with pytest.raises(UpstreamError) as caught:
            await upstream.chat_completions(PAYLOAD)
    finally:
        await upstream.aclose()

    rendered = str(caught.value)
    for leaked in ("sk-live-abc123", "no-such-model", "org-XYZ", "4111111111111111"):
        assert leaked not in rendered


async def test_upstream_error_maps_to_the_registered_status():
    """502 `upstream_error` is the contract in docs/07's error table. A caller
    distinguishes "the gateway refused you" (403) from "the model is unavailable"
    (502), and that distinction is the whole reason the mapping is registered."""
    assert UpstreamError.status_code == 502
    assert UpstreamError.error_type == "upstream_error"


async def test_a_2xx_still_returns_normally():
    """The fix must not turn success into failure. 200 and 201 both pass."""
    for status in (200, 201):
        body = {
            "id": "x",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
        }
        upstream = client_returning(status, body)
        try:
            result = await upstream.chat_completions(PAYLOAD)
            assert result.status_code == status
            assert result.body == body
            assert result.latency_ms >= 0.0
        finally:
            await upstream.aclose()


async def test_a_raised_call_records_no_latency():
    """The signature R-107's accounting depends on: a call that raises never
    reaches the line that assigns a latency, and `record_trace` counts exactly
    that — `upstream_called` with no latency — as an upstream failure. If this
    ever returned a result instead of raising, the failure would stop being
    counted and `FirewallUpstreamErrorsHigh` would go quiet again."""
    upstream = client_returning(404, ERROR_BODIES[404])
    try:
        with pytest.raises(UpstreamError):
            await upstream.chat_completions(PAYLOAD)
    finally:
        await upstream.aclose()
