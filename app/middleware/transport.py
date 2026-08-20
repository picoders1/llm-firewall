"""Refuse to serve credentials over a hop that was not TLS (ADR-026).

`FIREWALL_HTTPS_ENFORCED` used to do one thing: add an HSTS header. That made it
a claim about the deployment that nothing checked — a process could announce
"always use HTTPS" to browsers while happily accepting operator identity and
service keys over plaintext.

This middleware makes the setting mean what it says. When it is on, the operator
and gateway surfaces are served only if a trusted proxy states the client's hop
was HTTPS. Probes are exempt, and so is everything a deployment needs in order to
notice it is broken.

## Placement

Immediately inside admission control and outside both identity boundaries, so a
plaintext request is refused before any credential in it is read — the point is
that the credential should never have been on the wire, and reading it would not
un-send it.

## 426, not 403

RFC 9110's `426 Upgrade Required` is exactly this condition: the request is
understood and the client must switch protocols. A 403 would read as "your
credential was rejected" and send an operator to debug the wrong boundary.
"""

from __future__ import annotations

import json

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.errors import error_body
from app.auth.identity import AccessClass, classify_path
from app.auth.transport import Transport, client_transport
from app.config.settings import IpNetwork

logger = structlog.get_logger(__name__)

INSECURE_MESSAGE = "This gateway requires HTTPS."
UNKNOWN_MESSAGE = "This gateway requires HTTPS."

# PUBLIC: an orchestrator that cannot reach /ready takes a healthy instance out
# of rotation, and a deployment whose TLS is misconfigured needs its probes to
# keep answering so the failure is legible rather than total.
#
# INTERNAL (`/metrics`): the reference edge returns 404 for it, so a scraper
# reaches the pod directly across the internal network — which this project
# documents as intentionally plaintext (ADR-026 §23). Enforcing HTTPS here would
# refuse every scrape in the topology the project actually ships. `/metrics`
# keeps its own boundary: a declared scrape network or an operator identity
# (ADR-023), and it carries no credential and no content.
EXEMPT = frozenset({AccessClass.PUBLIC, AccessClass.INTERNAL})


class HttpsRequiredMiddleware:
    """Refuses non-TLS requests when the deployment declares HTTPS."""

    def __init__(
        self, app: ASGIApp, *, enabled: bool, trusted_proxies: tuple[IpNetwork, ...]
    ) -> None:
        self.app = app
        self.enabled = enabled
        self.trusted_proxies = trusted_proxies

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        # Determined for every request, including exempt ones: the *record* of
        # what the transport was is separate from whether it is enforced, and
        # `SecurityHeadersMiddleware` needs it to decide about HSTS. Sending HSTS
        # on a response that travelled in the clear pins a browser to a scheme
        # that hop did not serve.
        transport = client_transport(scope, self.trusted_proxies)
        scope.setdefault("state", {})["transport"] = transport

        if classify_path(scope.get("path", "/")) in EXEMPT or transport is Transport.SECURE:
            await self.app(scope, receive, send)
            return

        logger.warning(
            "insecure_transport_refused",
            transport=transport.value,
            path=scope.get("path"),
            # No address, no header value. `transport` is a closed enum and says
            # everything an operator needs: `insecure` is a client on the wrong
            # scheme, `unknown` is an ingress that is not setting the header.
        )
        await self._refuse(scope, send)

    async def _refuse(self, scope: Scope, send: Send) -> None:
        payload = error_body(INSECURE_MESSAGE, "insecure_transport", code="https_required")
        request_id = scope.get("state", {}).get("request_id")
        if isinstance(request_id, str):
            payload["error"]["request_id"] = request_id
        body = json.dumps(payload).encode("utf-8")
        start: Message = {
            "type": "http.response.start",
            "status": 426,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                # RFC 9110 pairs 426 with the protocol the client should use.
                (b"upgrade", b"TLS/1.2, HTTP/1.1"),
                (b"connection", b"Upgrade"),
            ],
        }
        await send(start)
        await send({"type": "http.response.body", "body": body})


__all__ = ["INSECURE_MESSAGE", "HttpsRequiredMiddleware"]
