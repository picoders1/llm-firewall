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
        # An EMPTY key is treated as no key, not as an empty credential. Without
        # this, `Bearer ` — with its trailing space — is an illegal header value
        # that h11 refuses locally, so every upstream call fails with a
        # `LocalProtocolError` surfaced as an opaque 502 that says nothing about
        # the cause. An operator who creates the secret file and has not filled
        # it in yet is exactly who hits that, and a self-hosted upstream that
        # needs no credential is a legitimate configuration (ADR-028).
        api_key = (
            settings.upstream_api_key.get_secret_value()
            if settings.upstream_api_key is not None
            else ""
        )
        if api_key:
            headers["authorization"] = f"Bearer {api_key}"
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=settings.upstream_connect_timeout_s,
                read=settings.upstream_read_timeout_s,
                write=settings.upstream_connect_timeout_s,
                pool=settings.upstream_connect_timeout_s,
            ),
            limits=httpx.Limits(
                max_connections=settings.upstream_max_connections,
                # Bounded separately: an unbounded keepalive pool holds file
                # descriptors open against the provider long after the burst
                # that created them has passed (ADR-025).
                max_keepalive_connections=settings.upstream_max_keepalive_connections,
            ),
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

        if response.status_code < 200 or response.status_code >= 300:
            # ANY non-2xx, not just 5xx. This read `>= 500` until R-114, so a 4xx
            # fell straight through to the success path: the handler hardcodes
            # `JSONResponse(status_code=200, ...)`, so an upstream 401, 404 or 429
            # was relabelled **200 OK** with the provider's error body reflected
            # verbatim. Found the first time this gateway fronted a real model
            # rather than the mock — Ollama answered 404 for an unknown model and
            # the caller received 200. With a paid provider the same path turns a
            # bad API key (401) and a rate limit (429) into apparent successes.
            #
            # It also broke the rule the comment below states: `docs/07` says
            # upstream bodies are NEVER reflected, and for 4xx they were. Raising
            # here maps every upstream error onto the registered contract —
            # 502 `upstream_error` with a gateway-authored message — and lets
            # `record_trace` count it, because a raised call never records a
            # latency and that is precisely the signature R-107 counts on.
            #
            # Accepted cost: a 429 is no longer distinguishable from a 500 by the
            # caller. Propagating the upstream status instead would leak provider
            # behaviour and reflect its body, which is a policy change this fix
            # deliberately does not make on its own.
            #
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
