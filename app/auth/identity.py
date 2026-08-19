"""Who is asking, and may they ask it.

Identity is **terminated outside this process** and arrives as a header injected
by a reverse proxy or ingress. Nothing here stores a password, mints a token, or
knows what a user account is — see docs/adr/ADR-023-operator-authentication.md
for why that is the design rather than a shortcut.

## The one property that makes header identity safe

An identity header is worth exactly as much as the guarantee that only the proxy
could have set it. This module derives that guarantee from the **peer address of
the TCP connection** — ``scope["client"]``, which is the machine that actually
opened the socket — and refuses to read a single identity header until that peer
falls inside the configured trusted range.

``X-Forwarded-For`` is deliberately never consulted. A forwarded-for chain is
client-supplied: an attacker prepends whatever they like, so trusting it would
turn the anti-spoofing check into a self-signed permission slip. The peer address
is the one value in an HTTP request that a remote client cannot choose.

The proxy has the other half of the contract — it must strip inbound copies of
these headers before injecting its own. That half cannot be enforced from here,
so it is asserted against the shipped reference configuration in
``tests/security/test_operator_auth.py`` and stated as an obligation in
docs/17-deployment-architecture.md.
"""

from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from app.config.settings import ConsoleAuthMode, IpNetwork, Settings
from app.core.exceptions import ConfigurationError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starlette.types import Scope


class Role(StrEnum):
    """Deliberately two roles, and no mechanism for adding a third cheaply.

    RBAC is not free: every role is a decision an operator must get right during
    an incident. The console is read-only (ADR-022), so the only distinction that
    earns its place is "a person looking at security data" versus "a scraper
    collecting numbers".
    """

    OPERATOR = "operator"
    INTERNAL_SERVICE = "internal_service"


class AccessClass(StrEnum):
    """What a route requires. Assigned by path, and defaulting to OPERATOR."""

    PUBLIC = "public"
    OPERATOR = "operator"
    INTERNAL = "internal"
    GATEWAY = "gateway"


class DenyReason(StrEnum):
    """Why a request was refused, for the log. Never sent to the client.

    A fixed enum rather than a message, because these values are emitted for
    requests that are attacker-controlled by definition, and a free-text reason
    built from a header is how a log ends up carrying an injected record.
    """

    UNTRUSTED_PEER = "untrusted_peer"
    # The two below are denial reasons, not credentials.
    MISSING_PROXY_SECRET = "missing_proxy_secret"  # noqa: S105
    BAD_PROXY_SECRET = "bad_proxy_secret"  # noqa: S105
    MISSING_SUBJECT = "missing_subject"
    INVALID_SUBJECT = "invalid_subject"
    NOT_AN_OPERATOR = "not_an_operator"
    METRICS_NOT_PERMITTED = "metrics_not_permitted"
    READ_ONLY_SURFACE = "read_only_surface"


@dataclass(frozen=True, slots=True)
class Principal:
    """The minimum identity the console needs (§8): a subject and a role.

    No email, no display name, no group list beyond the role decision, and no
    identity-provider token. Everything not needed to answer "may this request
    proceed" is data this service would then be responsible for protecting.
    """

    subject: str
    role: Role | None

    @property
    def is_operator(self) -> bool:
        return self.role is Role.OPERATOR


@dataclass(frozen=True, slots=True)
class AuthOutcome:
    """The verdict for one request."""

    principal: Principal | None
    reason: DenyReason | None = None

    @property
    def authenticated(self) -> bool:
        return self.principal is not None


# Public because a load balancer must reach them without a credential, and an
# unreachable readiness probe takes a healthy instance out of rotation.
PUBLIC_PATHS = frozenset({"/health", "/ready"})
INTERNAL_PATHS = frozenset({"/metrics"})
# Application traffic. Out of scope for operator authentication — a caller here
# is an application, not a person, and it is authenticated (or not) by whatever
# fronts the gateway. Stated rather than assumed: see R-58.
GATEWAY_PREFIX = "/v1"

# Maximum accepted subject length. Long enough for an email address or a DN,
# short enough that the value can never dominate a log line.
MAX_SUBJECT_LENGTH = 256


def classify_path(path: str) -> AccessClass:
    """Map a request path to the access class it requires.

    **Unknown paths are OPERATOR, not PUBLIC.** A route added later is protected
    until someone deliberately classifies it otherwise, which is the direction
    this mistake should fail in. The cost is that an anonymous request for a
    nonexistent path gets 401 rather than 404 — which also stops the boundary
    being used to enumerate routes.
    """
    normalised = path.rstrip("/") or "/"
    if normalised in PUBLIC_PATHS:
        return AccessClass.PUBLIC
    if normalised in INTERNAL_PATHS:
        return AccessClass.INTERNAL
    if normalised == GATEWAY_PREFIX or normalised.startswith(f"{GATEWAY_PREFIX}/"):
        return AccessClass.GATEWAY
    return AccessClass.OPERATOR


def peer_address(scope: Scope) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    client = scope.get("client")
    if not client:
        return None
    try:
        address = ipaddress.ip_address(client[0])
    except ValueError:
        # A non-IP peer (a unix socket, or a test transport naming itself) is not
        # something a CIDR can vouch for, so it is not trusted.
        return None
    # `::ffff:10.0.0.1` and `10.0.0.1` are the same host; a dual-stack listener
    # reports the former, and a CIDR written for the latter must still match.
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped or address


def valid_subject(value: str) -> bool:
    """Printable ASCII, bounded, no control characters.

    The subject is written to logs and returned to the console. A value with a
    newline in it forges log records; a value with a control character in it is
    not a username. Rejecting is right — sanitising would silently accept a
    proxy that is misconfigured.
    """
    if not 0 < len(value) <= MAX_SUBJECT_LENGTH:
        return False
    return all(32 <= ord(char) < 127 for char in value)


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """Resolved authentication boundary for one process."""

    mode: ConsoleAuthMode
    trusted_proxies: tuple[IpNetwork, ...]
    shared_secret: str | None
    shared_secret_header: str
    subject_header: str
    roles_header: str
    operator_roles: frozenset[str]
    metrics_networks: tuple[IpNetwork, ...]
    logout_path: str | None

    @property
    def enforcing(self) -> bool:
        return self.mode is ConsoleAuthMode.PROXY

    @classmethod
    def from_settings(cls, settings: Settings) -> AuthConfig:
        """Resolve and validate, raising rather than starting up half-protected.

        A misconfigured boundary is not a runtime surprise to discover on the
        first anonymous request; it is a reason for the process to refuse to
        start, exactly like an invalid policy (NFR-009).
        """
        try:
            mode = settings.effective_console_auth_mode()
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from None

        trusted = settings.trusted_proxy_networks

        if mode is ConsoleAuthMode.PROXY:
            if not trusted:
                raise ConfigurationError(
                    "console_auth_mode=proxy requires FIREWALL_TRUSTED_PROXIES: without it "
                    "no peer can be trusted to assert an operator identity, so the console "
                    "would be unreachable rather than protected."
                )
            for network in trusted:
                if int(network.network_address) == 0 and network.prefixlen == 0:
                    raise ConfigurationError(
                        f"trusted_proxies={network} trusts every host on the network. "
                        "Name the ingress address or its subnet."
                    )

        secret = (
            settings.proxy_shared_secret.get_secret_value()
            if settings.proxy_shared_secret is not None
            else None
        )

        return cls(
            mode=mode,
            trusted_proxies=trusted,
            shared_secret=secret or None,
            shared_secret_header=settings.proxy_shared_secret_header,
            subject_header=settings.auth_subject_header,
            roles_header=settings.auth_roles_header,
            operator_roles=settings.operator_role_values,
            metrics_networks=settings.metrics_scrape_networks,
            logout_path=settings.console_logout_path,
        )

    # --- Decisions ---------------------------------------------------------

    def peer_is_trusted(self, scope: Scope) -> bool:
        address = peer_address(scope)
        if address is None:
            return False
        return any(address in network for network in self.trusted_proxies)

    def peer_may_scrape_metrics(self, scope: Scope) -> bool:
        address = peer_address(scope)
        if address is None:
            return False
        return any(address in network for network in self.metrics_networks)

    def authenticate(self, scope: Scope, headers: dict[bytes, bytes]) -> AuthOutcome:
        """Derive a principal, or say why not.

        Order matters: the peer is checked *before* any header is read, so a
        forged identity from an untrusted client is never parsed, never logged
        and never partially trusted.
        """
        if not self.peer_is_trusted(scope):
            return AuthOutcome(None, DenyReason.UNTRUSTED_PEER)

        if self.shared_secret is not None:
            presented = headers.get(self.shared_secret_header.lower().encode())
            if presented is None:
                return AuthOutcome(None, DenyReason.MISSING_PROXY_SECRET)
            # Constant-time: a byte-at-a-time comparison against a secret that an
            # attacker can retry is a timing oracle, and this one sits in front
            # of everything else.
            if not secrets.compare_digest(presented, self.shared_secret.encode()):
                return AuthOutcome(None, DenyReason.BAD_PROXY_SECRET)

        raw_subject = headers.get(self.subject_header.lower().encode())
        if raw_subject is None or not raw_subject.strip():
            return AuthOutcome(None, DenyReason.MISSING_SUBJECT)

        try:
            subject = raw_subject.decode("ascii").strip()
        except UnicodeDecodeError:
            return AuthOutcome(None, DenyReason.INVALID_SUBJECT)
        if not valid_subject(subject):
            return AuthOutcome(None, DenyReason.INVALID_SUBJECT)

        role = Role.OPERATOR if self._grants_operator(headers) else None
        return AuthOutcome(Principal(subject=subject, role=role))

    def _grants_operator(self, headers: dict[bytes, bytes]) -> bool:
        """No configured roles means the proxy's admission decision is the whole
        authorisation decision — which is correct when the proxy already only
        admits the operations team, and is the common deployment."""
        if not self.operator_roles:
            return True
        raw = headers.get(self.roles_header.lower().encode(), b"")
        try:
            decoded = raw.decode("ascii")
        except UnicodeDecodeError:
            return False
        presented = {item.strip() for item in decoded.split(",") if item.strip()}
        return bool(presented & self.operator_roles)


__all__ = [
    "GATEWAY_PREFIX",
    "INTERNAL_PATHS",
    "MAX_SUBJECT_LENGTH",
    "PUBLIC_PATHS",
    "AccessClass",
    "AuthConfig",
    "AuthOutcome",
    "DenyReason",
    "Principal",
    "Role",
    "classify_path",
    "peer_address",
    "valid_subject",
]
