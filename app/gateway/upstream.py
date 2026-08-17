"""The upstream LLM client.

One pooled `httpx.AsyncClient` for the process lifetime, created in the lifespan.
Connection reuse is a first-order latency effect and a client per request is the
most common latency bug in Python proxies.

`UpstreamClient` is a Protocol so tests can substitute a counting fake and assert
the security invariant that blocked requests never reach the upstream — an
assertion that a 403 status code alone does not prove
(docs/16-testing-strategy.md).
"""

from __future__ import annotations

import time
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
import structlog

from app.config.settings import Settings
from app.core.exceptions import UpstreamError, UpstreamTimeout

logger = structlog.get_logger(__name__)


class UpstreamResult:
    """An upstream response plus the wall-clock it cost.

    The latency is measured around the HTTP call only, so gateway overhead can be
    derived by subtraction (docs/15-performance-benchmarking.md).
    """

    __slots__ = ("body", "latency_ms", "status_code")

    def __init__(self, status_code: int, body: dict[str, Any], latency_ms: float) -> None:
        self.status_code = status_code
        self.body = body
        self.latency_ms = latency_ms


class UpstreamClient(Protocol):
    async def chat_completions(self, payload: dict[str, Any]) -> UpstreamResult: ...
    async def aclose(self) -> None: ...


class HttpUpstreamClient:
    """Talks to any OpenAI-compatible endpoint over HTTP."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self._base_url = settings.upstream_base_url
        self._host = urlsplit(self._base_url).hostname or "unknown"
        headers = {"content-type": "application/json"}
        if settings.upstream_api_key is not None:
            headers["authorization"] = f"Bearer {settings.upstream_api_key.get_secret_value()}"
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=settings.upstream_connect_timeout_s,
                read=settings.upstream_read_timeout_s,
                write=settings.upstream_connect_timeout_s,
                pool=settings.upstream_connect_timeout_s,
            ),
            limits=httpx.Limits(max_connections=settings.upstream_max_connections),
            headers=headers,
        )

    @property
    def host(self) -> str:
        return self._host

    async def chat_completions(self, payload: dict[str, Any]) -> UpstreamResult:
        started = time.perf_counter()
        try:
            response = await self._client.post(f"{self._base_url}/chat/completions", json=payload)
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout("The upstream model timed out.") from exc
        except httpx.HTTPError as exc:
            # Log the class, never the URL with query or the exception text, which
            # can echo request content.
            logger.warning("upstream_transport_error", error_kind=type(exc).__name__)
            raise UpstreamError("The upstream model is unreachable.") from exc

        latency_ms = (time.perf_counter() - started) * 1000.0

        if response.status_code >= 500:
            # The upstream body is NEVER reflected: it can contain the reflected
            # prompt or provider internals (docs/07-openai-compatible-api.md).
            raise UpstreamError("The upstream model returned an error.")

        try:
            body = response.json()
        except ValueError as exc:
            raise UpstreamError("The upstream model returned a malformed response.") from exc

        if not isinstance(body, dict):
            raise UpstreamError("The upstream model returned a malformed response.")

        return UpstreamResult(response.status_code, body, latency_ms)

    async def aclose(self) -> None:
        await self._client.aclose()
