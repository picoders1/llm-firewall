"""Correlation-ID and security-header middleware.

Request-ID is outermost in the stack so that *every* failure — including a
rejected oversized body or a malformed request — is correlated and auditable.

The client-supplied header is untrusted input. Without validation, a header
containing a newline and a forged JSON object writes attacker-controlled records
into the security log: a real attack on the audit trail, not a theoretical one
(FR-051, docs/10-security-model.md).
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.ids import is_valid_request_id, new_request_id
from app.observability.logging import bind_request_id, reset_request_id

REQUEST_ID_HEADER = "X-Request-ID"

# `no-store` matters here specifically: responses can contain completions, and a
# caching proxy must not retain them. HSTS and CSP are deliberately absent — this
# is an API, not a browser origin, and TLS terminates at the ingress.
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"no-referrer"),
)


class RequestIdMiddleware:
    """Assigns a correlation ID and echoes it on every response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        supplied = Request(scope).headers.get(REQUEST_ID_HEADER)
        request_id = supplied if supplied and is_valid_request_id(supplied) else new_request_id()

        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        bind_request_id(request_id)

        async def send_with_header(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((REQUEST_ID_HEADER.lower().encode(), request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_header)
        finally:
            reset_request_id()


class SecurityHeadersMiddleware:
    """Adds the response headers the gateway is responsible for."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(SECURITY_HEADERS)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


__all__ = [
    "REQUEST_ID_HEADER",
    "SECURITY_HEADERS",
    "RequestIdMiddleware",
    "SecurityHeadersMiddleware",
]
