"""Was the browser's hop actually TLS, and may we believe the answer (ADR-026).

The application cannot observe its own transport security. TLS terminates at the
edge, so by the time a request reaches this process the connection it arrived on
is a plaintext hop across an internal network — which is correct, and which
means the only source of truth about the *client's* hop is the proxy that
terminated it.

That makes `X-Forwarded-Proto` a security-relevant input, and therefore one that
must not be read from just anybody. The rule is the one ADR-023 established for
identity and ADR-025 reused for throttling keys, applied a third time: **the
header is read only when the socket's peer falls inside
`FIREWALL_TRUSTED_PROXIES`.** A direct client sending `X-Forwarded-Proto: https`
convinces nobody, because nothing looks at the header until the peer has already
been vouched for.

## Why absence is refused rather than allowed

When `https_enforced` is on and a request carries no trusted statement about its
scheme, this module treats it as insecure. That is the uncomfortable direction —
it means an ingress that forgets to set the header takes the deployment down
rather than quietly serving credentials over plaintext.

It is the right direction anyway. The alternative fails silently and only
becomes visible when someone reads a packet capture; this one fails at the first
request, in a way that names the missing header. Probes are exempt so the
failure is visible to an operator without also being invisible to the
orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from app.auth.identity import peer_address
from app.config.settings import IpNetwork, Settings
from app.core.exceptions import ConfigurationError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starlette.types import Scope

FORWARDED_PROTO_HEADER = b"x-forwarded-proto"


class Transport(StrEnum):
    """What the client's own hop was, as far as this process can tell."""

    SECURE = "secure"
    INSECURE = "insecure"
    # No trusted proxy said anything. Distinct from INSECURE because the two
    # want different error messages: one is a client on the wrong scheme, the
    # other is an ingress that is not configured.
    UNKNOWN = "unknown"


def client_transport(scope: Scope, trusted_proxies: tuple[IpNetwork, ...]) -> Transport:
    """Classify the client's hop from a trusted proxy's assertion, or UNKNOWN.

    Only the single `X-Forwarded-Proto` header is consulted. The RFC 7239
    `Forwarded` header is deliberately not parsed: it is a structured field whose
    parsing has its own history of bugs, and no ingress this project documents
    emits it in preference.
    """
    peer = peer_address(scope)
    if peer is None or not any(peer in network for network in trusted_proxies):
        return Transport.UNKNOWN

    for name, value in scope.get("headers", ()):
        if name.lower() != FORWARDED_PROTO_HEADER:
            continue
        try:
            decoded = value.decode("ascii").strip().lower()
        except UnicodeDecodeError:
            return Transport.UNKNOWN
        # A proxy chain can append, producing "https,http". The FIRST entry is
        # the client's own hop, which is the one being asked about.
        first = decoded.split(",")[0].strip()
        if first == "https":
            return Transport.SECURE
        if first == "http":
            return Transport.INSECURE
        return Transport.UNKNOWN
    return Transport.UNKNOWN


@dataclass(frozen=True, slots=True)
class TransportPolicy:
    """Whether this deployment claims TLS, resolved and checked at startup."""

    https_enforced: bool
    trusted_proxies: tuple[IpNetwork, ...]

    @classmethod
    def from_settings(
        cls, settings: Settings, trusted_proxies: tuple[IpNetwork, ...]
    ) -> TransportPolicy:
        """Refuse to start rather than announce a transport guarantee nothing keeps.

        Two failures are caught here, and both are configurations that look fine
        until someone reads a packet capture:

        * **Production without HTTPS.** The gateway holds an upstream credential
          and accepts operator identities and service keys. Serving those over
          plaintext is not a degraded mode, it is an absent control.
        * **HTTPS declared with no trusted proxy.** Nothing could ever assert the
          hop was TLS, so every request would be refused — a deployment that is
          down rather than protected, and better discovered at startup than at
          the first request.
        """
        enforced = settings.https_enforced

        if settings.is_production and not enforced:
            raise ConfigurationError(
                "FIREWALL_HTTPS_ENFORCED must be true when environment=production. "
                "The gateway carries operator identities, caller credentials and an "
                "upstream key; serving them over plaintext is an absent control, not a "
                "degraded one (docs/adr/ADR-026-secure-transport.md)."
            )

        if enforced and not trusted_proxies:
            raise ConfigurationError(
                "FIREWALL_HTTPS_ENFORCED requires FIREWALL_TRUSTED_PROXIES. This process "
                "cannot observe its own transport — TLS terminates at the ingress — so "
                "without a trusted peer nothing can ever assert that a request arrived "
                "over HTTPS and every request would be refused."
            )

        return cls(https_enforced=enforced, trusted_proxies=trusted_proxies)


__all__ = [
    "FORWARDED_PROTO_HEADER",
    "Transport",
    "TransportPolicy",
    "client_transport",
]
