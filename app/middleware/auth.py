"""The operator access boundary (ADR-023).

One middleware, applied to every request, that answers two questions in order:
what does this path require, and who is asking. Routes are not decorated
individually — a boundary you have to remember to apply is a boundary that is
missing from the route somebody adds next week. `classify_path` defaults unknown
paths to operator-only for the same reason.

## Placement in the stack

Registered so it sits **inside** `RequestIdMiddleware` and
`SecurityHeadersMiddleware`: a 401 is a response like any other and must carry a
correlation ID and the standard headers. It sits **outside** the router, so no
route handler, dependency or database query runs for a request that will be
refused.

## What a refusal says

Status and a fixed message. No identity-provider name, no header name, no CIDR,
no configuration state — an unauthenticated client learns only that it is
unauthenticated. The *reason* is a closed enum written to the log, never to the
wire, and never built from a header value (which is attacker-controlled input,
and the classic way a log grows forged records).
"""

from __future__ import annotations

import json

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.errors import error_body
from app.auth.identity import (
    AccessClass,
    AuthConfig,
    AuthOutcome,
    DenyReason,
    Principal,
    Role,
    classify_path,
)
from app.auth.notice import STYLE_HASH, notice_html

logger = structlog.get_logger(__name__)

# The console never mutates anything (ADR-022, §10 of the Phase 9 brief). Routing
# already makes a POST to a GET-only route a 405, but enforcing it here means a
# future mutating endpoint cannot quietly inherit read-only authentication: it
# has to come through this file, where CSRF is documented.
READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_TYPE = {401: "authentication_error", 403: "permission_error", 405: "method_not_allowed"}
_MESSAGE = {
    401: "Authentication required.",
    403: "Not authorised for the security console.",
    405: "The security console is read-only.",
}


class OperatorAuthMiddleware:
    """Applies the access-class table to every request."""

    def __init__(self, app: ASGIApp, *, config: AuthConfig) -> None:
        self.app = app
        self.config = config

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        access_class = classify_path(scope.get("path", "/"))
        state = scope.setdefault("state", {})
        state["access_class"] = access_class

        if access_class in (AccessClass.PUBLIC, AccessClass.GATEWAY):
            await self.app(scope, receive, send)
            return

        if not self.config.enforcing:
            # Development and testing. No identity header is read at all, so a
            # header that would be honoured in production is inert here rather
            # than half-trusted.
            state["principal"] = None
            await self.app(scope, receive, send)
            return

        headers = {name.lower(): value for name, value in scope.get("headers", ())}
        outcome = self.config.authenticate(scope, headers)

        if access_class is AccessClass.INTERNAL:
            status, reason, principal = self._metrics_decision(scope, outcome)
        else:
            status, reason, principal = self._operator_decision(scope, outcome)

        if status is not None:
            await self._refuse(scope, send, status, reason, access_class)
            return

        state["principal"] = principal
        await self.app(scope, receive, send)

    # --- Per-class decisions -----------------------------------------------

    def _metrics_decision(
        self, scope: Scope, outcome: AuthOutcome
    ) -> tuple[int | None, DenyReason | None, Principal | None]:
        """`/metrics` is internal, and reachable two ways.

        A Prometheus scraper is not a person and should not need an operator
        identity, so a scrape from a declared network is admitted directly. An
        operator reading raw counters during an incident is admitted through the
        proxy like everything else. Anything else is refused — the endpoint is
        never open merely because it is boring.
        """
        if self.config.peer_may_scrape_metrics(scope):
            return None, None, Principal(subject="metrics-scraper", role=Role.INTERNAL_SERVICE)
        if outcome.principal is not None and outcome.principal.is_operator:
            return None, None, outcome.principal
        reason = outcome.reason or DenyReason.METRICS_NOT_PERMITTED
        return (401 if outcome.principal is None else 403), reason, None

    def _operator_decision(
        self, scope: Scope, outcome: AuthOutcome
    ) -> tuple[int | None, DenyReason | None, Principal | None]:
        if outcome.principal is None:
            return 401, outcome.reason, None
        if not outcome.principal.is_operator:
            return 403, DenyReason.NOT_AN_OPERATOR, None
        if scope.get("method", "GET") not in READ_ONLY_METHODS:
            return 405, DenyReason.READ_ONLY_SURFACE, None
        return None, None, outcome.principal

    # --- Refusal ------------------------------------------------------------

    def _wants_html(self, scope: Scope) -> bool:
        """A browser navigating to the console, rather than the console's own
        fetch. Only these get a page; an API client gets the error envelope it
        already knows how to read."""
        if scope.get("path", "").startswith("/api/"):
            return False
        headers = dict(scope.get("headers", ()))
        return b"text/html" in headers.get(b"accept", b"")

    async def _refuse(
        self,
        scope: Scope,
        send: Send,
        status: int,
        reason: DenyReason | None,
        access_class: AccessClass,
    ) -> None:
        logger.warning(
            "operator_auth_denied",
            status=status,
            # A closed enum, never a header value.
            reason=reason.value if reason else "unspecified",
            access_class=access_class.value,
            path=scope.get("path"),
            method=scope.get("method"),
        )
        metrics = getattr(getattr(scope.get("app"), "state", None), "metrics", None)
        if metrics is not None:
            metrics.auth_denials_total.labels(
                access_class=access_class.value,
                reason=reason.value if reason else "unspecified",
            ).inc()

        headers: list[tuple[bytes, bytes]]
        if status in (401, 403) and self._wants_html(scope):
            body = notice_html(status).encode("utf-8")
            headers = [
                (b"content-type", b"text/html; charset=utf-8"),
                # The page's own style block by exact hash — no 'unsafe-inline'.
                (
                    b"content-security-policy",
                    (
                        f"default-src 'none'; style-src {STYLE_HASH}; "
                        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                    ).encode(),
                ),
            ]
        else:
            request_id = scope.get("state", {}).get("request_id")
            payload = error_body(
                _MESSAGE[status],
                _TYPE[status],
                code=None,
                request_id=request_id if isinstance(request_id, str) else None,
            )
            body = json.dumps(payload).encode("utf-8")
            headers = [(b"content-type", b"application/json")]

        headers.append((b"content-length", str(len(body)).encode()))
        # `WWW-Authenticate` is deliberately absent: it would make the browser
        # pop its own basic-auth dialog, which is not where this deployment's
        # credentials live and would train operators to type them anywhere.
        start: Message = {"type": "http.response.start", "status": status, "headers": headers}
        await send(start)
        await send({"type": "http.response.body", "body": body})


__all__ = ["READ_ONLY_METHODS", "OperatorAuthMiddleware"]
