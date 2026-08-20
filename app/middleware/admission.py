"""Global admission control (ADR-025).

The outermost thing the application does that can say "no". It answers one
question — *will this process take another request right now* — and it answers
it before request-id binding, before the body is read and before either identity
boundary runs, because everything after this point costs memory or CPU.

## This is the safety net, not the defence

Volumetric abuse is the edge's job. nginx can refuse a connection for the price
of a `RST`; this middleware has already paid for a TCP handshake, a TLS
handshake and an ASGI scope by the time it runs. It exists so that a deployment
whose edge is missing or misconfigured degrades into "slow" rather than "out of
memory", and so that the process protects the detector thread pool and the
upstream connection pool behind it from its own accepted traffic.

## 503, not 429

A deliberate split, documented in ADR-025 §14 and worth stating where the code
lives: **429 means "you exceeded a limit that is yours"** — a per-caller rate or
concurrency ceiling — and **503 means "this server is at capacity"**, which is a
statement about the server and not about the client. A client that gets 503
should retry, possibly elsewhere; a client that gets 429 should slow down. Both
carry `Retry-After`.

## Release is unconditional

The semaphore is released in a `finally`, so a handler that raises, times out or
is cancelled still returns its slot. A leaked slot is permanent: the process
converges on refusing everything while appearing healthy, which is worse than
having no limit at all.
"""

from __future__ import annotations

import asyncio
import json

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.errors import error_body
from app.auth.admission import AdmissionConfig
from app.observability.metrics import Metrics

logger = structlog.get_logger(__name__)

AT_CAPACITY_MESSAGE = "The gateway is at capacity. Retry shortly."
RETRY_AFTER_SECONDS = 1

# Liveness and readiness are exempt. An orchestrator that cannot reach `/ready`
# during a burst restarts or de-pools the instance, turning a load spike into an
# outage — the probe must report saturation, not be a casualty of it.
EXEMPT_PATHS = frozenset({"/health", "/ready"})


class AdmissionMiddleware:
    """Bounds requests in flight in this process."""

    def __init__(self, app: ASGIApp, *, config: AdmissionConfig) -> None:
        self.app = app
        self.config = config
        self._semaphore = (
            asyncio.Semaphore(config.max_concurrent_requests)
            if config.concurrency_enabled
            else None
        )
        self._in_flight = 0

    @property
    def in_flight(self) -> int:
        return self._in_flight

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self._semaphore is None:
            await self.app(scope, receive, send)
            return

        if scope.get("path", "/").rstrip("/") in EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        metrics = self._metrics(scope)

        # `locked()` rather than `acquire()` with a timeout: waiting is what a
        # queue does, and an unbounded queue in front of a bounded worker pool is
        # how a burst becomes a memory problem instead of a rejection.
        if self._semaphore.locked():
            logger.warning(
                "admission_rejected",
                limit=self.config.max_concurrent_requests,
                path=scope.get("path"),
            )
            if metrics is not None:
                metrics.record_concurrency_rejection(scope_name="gateway")
            await self._refuse(scope, send)
            return

        await self._semaphore.acquire()
        self._in_flight += 1
        if metrics is not None:
            metrics.set_active_requests(self._in_flight)
        try:
            await self.app(scope, receive, send)
        finally:
            self._in_flight -= 1
            self._semaphore.release()
            if metrics is not None:
                metrics.set_active_requests(self._in_flight)

    def _metrics(self, scope: Scope) -> Metrics | None:
        metrics = getattr(getattr(scope.get("app"), "state", None), "metrics", None)
        return metrics if isinstance(metrics, Metrics) else None

    async def _refuse(self, scope: Scope, send: Send) -> None:
        payload = error_body(AT_CAPACITY_MESSAGE, "server_overloaded", code="at_capacity")
        request_id = scope.get("state", {}).get("request_id")
        if isinstance(request_id, str):
            payload["error"]["request_id"] = request_id
        body = json.dumps(payload).encode("utf-8")
        start: Message = {
            "type": "http.response.start",
            "status": 503,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"retry-after", str(RETRY_AFTER_SECONDS).encode()),
            ],
        }
        await send(start)
        await send({"type": "http.response.body", "body": body})


__all__ = ["AT_CAPACITY_MESSAGE", "EXEMPT_PATHS", "AdmissionMiddleware"]
