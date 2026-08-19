"""The caller access boundary for `/v1/**` (ADR-024).

Placed in the middleware stack rather than as a route dependency for the reason
§14 gives: an unauthorised request must be rejected *before* normalisation and
detector inference. The layer-2 transformer costs ~95 ms of CPU per call
(ADR-021), so authenticating inside the handler would let an anonymous client
spend real compute on every request it is about to be refused — a denial of
service that authentication was supposed to prevent.

It also means no route can forget the check. `/v1/models` is protected by the
same rule as `/v1/chat/completions` without either handler mentioning it.

## Order within the stack

    request-id → body limit → security headers → caller auth → router

The body limit stays outside, so an oversized body is rejected before this code
reads a header (§17). Everything expensive is inside.

## What a refusal says, and what it costs

Status and a fixed message, in the OpenAI error envelope so an existing client's
error handling works unchanged. The *reason* is a closed enum that goes to the
log and a metric, never to the wire: telling a caller apart "no credential" from
"wrong credential" turns the gateway into an oracle for enumerating which keys
exist.

Failed authentication is **not** written to the audit database. A client that
can create a security-event row per request has a cheap way to fill an
operator's disk (§21); counters and log lines cost bytes, not rows.
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.errors import error_body
from app.auth.caller import CallerAuthConfig, CallerDenyReason, CallerPrincipal
from app.auth.identity import AccessClass, classify_path
from app.auth.ratelimit import CallerLimiter, LimitRejection
from app.observability.metrics import Metrics

logger = structlog.get_logger(__name__)

UNAUTHORIZED_MESSAGE = "Incorrect API key provided."
RATE_LIMITED_MESSAGE = "Rate limit exceeded for this caller."


class CallerAuthMiddleware:
    """Authenticates and throttles application traffic to `/v1/**`."""

    def __init__(
        self, app: ASGIApp, *, config: CallerAuthConfig, limiter: CallerLimiter | None = None
    ) -> None:
        self.app = app
        self.config = config
        self.limiter = limiter or CallerLimiter(
            per_minute=config.rate_limit_per_minute,
            max_concurrent=config.max_concurrent_requests,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Exactly the class the operator boundary hands through. Sharing one
        # classifier keeps the two tables from drifting into a gap that belongs
        # to neither boundary.
        if classify_path(scope.get("path", "/")) is not AccessClass.GATEWAY:
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})

        if not self.config.enforcing:
            # Development and testing. No credential header is read at all, so a
            # key that would be honoured in production is inert here rather than
            # half-trusted.
            state["caller"] = None
            await self.app(scope, receive, send)
            return

        headers = {name.lower(): value for name, value in scope.get("headers", ())}
        principal, reason = self.config.authenticate(scope, headers)

        if principal is None:
            await self._refuse_unauthorized(scope, send, reason)
            return

        rejection = await self.limiter.acquire(principal.caller_id)
        if rejection is not None:
            await self._refuse_rate_limited(scope, send, principal, rejection)
            return

        state["caller"] = principal
        try:
            await self.app(scope, receive, send)
        finally:
            # In a `finally` so a handler that raises still returns its slot;
            # otherwise a burst of upstream errors would permanently consume the
            # caller's concurrency allowance.
            await self.limiter.release(principal.caller_id)

    # --- Refusals -----------------------------------------------------------

    def _metrics(self, scope: Scope) -> Metrics | None:
        metrics = getattr(getattr(scope.get("app"), "state", None), "metrics", None)
        return metrics if isinstance(metrics, Metrics) else None

    async def _refuse_unauthorized(
        self, scope: Scope, send: Send, reason: CallerDenyReason | None
    ) -> None:
        logger.warning(
            "caller_auth_denied",
            # A closed enum. Never the presented credential, and never a value
            # derived from one — a log line built from a header is how an audit
            # trail ends up carrying records the attacker wrote.
            reason=reason.value if reason else "unspecified",
            path=scope.get("path"),
            method=scope.get("method"),
        )
        metrics = self._metrics(scope)
        if metrics is not None:
            metrics.record_caller_auth_failure(reason=reason.value if reason else "unspecified")
        await self._send(
            scope,
            send,
            401,
            error_body(UNAUTHORIZED_MESSAGE, "invalid_request_error", code="invalid_api_key"),
        )

    async def _refuse_rate_limited(
        self, scope: Scope, send: Send, principal: CallerPrincipal, rejection: LimitRejection
    ) -> None:
        logger.warning(
            "caller_rate_limited",
            caller=principal.caller_id,
            limit=rejection.kind.value,
        )
        metrics = self._metrics(scope)
        if metrics is not None:
            metrics.record_rate_limited(caller=principal.caller_id, limit=rejection.kind.value)
        await self._send(
            scope,
            send,
            429,
            error_body(RATE_LIMITED_MESSAGE, "rate_limit_exceeded", code=rejection.kind.value),
            extra_headers=[(b"retry-after", str(rejection.retry_after_seconds).encode())],
        )

    async def _send(
        self,
        scope: Scope,
        send: Send,
        status: int,
        payload: dict[str, Any],
        *,
        extra_headers: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        request_id = scope.get("state", {}).get("request_id")
        if isinstance(request_id, str):
            payload["error"]["request_id"] = request_id
        body = json.dumps(payload).encode("utf-8")
        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        headers.extend(extra_headers or [])
        # `WWW-Authenticate` is deliberately absent, matching the OpenAI API:
        # sending it makes a browser that wandered onto the endpoint pop a
        # credential dialog, which is not where a service key belongs.
        start: Message = {"type": "http.response.start", "status": status, "headers": headers}
        await send(start)
        await send({"type": "http.response.body", "body": body})


__all__ = ["RATE_LIMITED_MESSAGE", "UNAUTHORIZED_MESSAGE", "CallerAuthMiddleware"]
