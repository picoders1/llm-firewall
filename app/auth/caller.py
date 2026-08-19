"""Which application is calling, and may it spend the model budget.

This is the *other* trust boundary. `identity.py` answers "which operator is
reading the console"; this file answers "which application is driving the
model", and the two are kept apart on purpose (ADR-024 §5): a stolen dashboard
session must not be able to call the model, and a service key must not be able
to read the security event log. They share the peer-address rule and nothing
else — different settings, different headers, different principal type.

## Why the credential is a digest

`FIREWALL_CALLER_API_KEYS` holds `<caller_id>:<sha256-hex>` pairs. The raw key
exists only in the caller's own configuration, so the way this kind of secret
actually leaks — an environment dump, a `docker inspect`, a misrouted log — does
not yield anything presentable.

Unsalted SHA-256 is the right primitive *here* and would be wrong for a
password. `scripts/generate_caller_key.py` mints 256 bits of entropy, so there is
no dictionary to run; a work factor would only add latency to every request. The
assumption is load-bearing, which is why the helper generates the key rather than
accepting one someone typed.

## Why comparison is constant-time *and* order-independent

Every configured digest is compared with `hmac.compare_digest`, and **the loop
does not stop at the first match**. Returning early would make the response time
depend on a credential's position in the configured list, which leaks how many
callers precede a valid one.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from app.auth.identity import peer_address, valid_subject
from app.config.settings import CallerAuthMode, IpNetwork, Settings
from app.core.exceptions import ConfigurationError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starlette.types import Scope

BEARER_PREFIX = "bearer "

# The identity a request carries when the boundary is switched off. Named rather
# than `None` so an audit row records "authentication was not in force" instead
# of an ambiguous blank that reads like a bug.
UNAUTHENTICATED_CALLER = "anonymous"


class CallerDenyReason(StrEnum):
    """Why a caller was refused. For the log and the metric; never for the wire.

    §15: the client is told only that it is unauthorised. Distinguishing "no
    credential" from "wrong credential" from "disabled caller" on the wire turns
    the gateway into an oracle for enumerating which keys exist.
    """

    MISSING_CREDENTIAL = "missing_credential"
    MALFORMED_CREDENTIAL = "malformed_credential"
    UNKNOWN_CREDENTIAL = "unknown_credential"
    UNTRUSTED_PEER = "untrusted_peer"
    MISSING_PROXY_SECRET = "missing_proxy_secret"  # noqa: S105 - a denial reason
    BAD_PROXY_SECRET = "bad_proxy_secret"  # noqa: S105 - a denial reason
    MISSING_CALLER_HEADER = "missing_caller_header"
    INVALID_CALLER_HEADER = "invalid_caller_header"
    UNKNOWN_CALLER = "unknown_caller"


@dataclass(frozen=True, slots=True)
class CallerPrincipal:
    """A calling application. An identifier and nothing else.

    Deliberately *not* the same type as an operator `Principal`, so a function
    that expects one cannot be handed the other by a future refactor — the type
    checker enforces the separation the design depends on.
    """

    caller_id: str
    authenticated: bool = True


def digest(raw_key: str) -> str:
    """The stored representation of a caller credential."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CallerAuthConfig:
    """The resolved caller boundary for one process."""

    mode: CallerAuthMode
    key_digests: tuple[tuple[str, str], ...]
    trusted_proxies: tuple[IpNetwork, ...]
    proxy_shared_secret: str | None
    proxy_shared_secret_header: str
    identity_header: str
    rate_limit_per_minute: int
    max_concurrent_requests: int

    @property
    def enforcing(self) -> bool:
        return self.mode is not CallerAuthMode.DISABLED

    @property
    def caller_ids(self) -> tuple[str, ...]:
        return tuple(caller for caller, _ in self.key_digests)

    @classmethod
    def from_settings(cls, settings: Settings) -> CallerAuthConfig:
        """Resolve and validate, refusing to start rather than half-protecting.

        A gateway that starts with `api_key` mode and no configured keys would
        reject every caller while reporting itself protected. That is a different
        failure from an open gateway and an equally bad one, so both are refused
        here rather than discovered in production.
        """
        try:
            mode = settings.effective_caller_auth_mode()
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from None

        keys = settings.caller_key_digests
        trusted = settings.caller_trusted_proxy_networks

        if mode is CallerAuthMode.API_KEY and not keys:
            raise ConfigurationError(
                "caller_auth_mode=api_key requires FIREWALL_CALLER_API_KEYS. Without it "
                "every caller is rejected while the gateway reports itself protected. "
                "Generate a credential with scripts/generate_caller_key.py."
            )

        if mode is CallerAuthMode.PROXY:
            if not trusted:
                raise ConfigurationError(
                    "caller_auth_mode=proxy requires FIREWALL_CALLER_TRUSTED_PROXIES: without "
                    "it no peer can be trusted to assert a caller identity."
                )
            for network in trusted:
                if int(network.network_address) == 0 and network.prefixlen == 0:
                    raise ConfigurationError(
                        f"caller_trusted_proxies={network} trusts every host on the network. "
                        "Name the ingress address or its subnet."
                    )
            if not keys:
                raise ConfigurationError(
                    "caller_auth_mode=proxy requires FIREWALL_CALLER_API_KEYS to enumerate the "
                    "permitted caller ids. The proxy asserts *who* is calling; this gateway "
                    "still decides whether that caller is allowed, so an identity the ingress "
                    "invents is not automatically admitted."
                )

        secret = (
            settings.caller_proxy_shared_secret.get_secret_value()
            if settings.caller_proxy_shared_secret is not None
            else None
        )

        return cls(
            mode=mode,
            key_digests=keys,
            trusted_proxies=trusted,
            proxy_shared_secret=secret or None,
            proxy_shared_secret_header=settings.proxy_shared_secret_header,
            identity_header=settings.caller_identity_header,
            rate_limit_per_minute=settings.caller_rate_limit_per_minute,
            max_concurrent_requests=settings.caller_max_concurrent_requests,
        )

    # --- Authentication -----------------------------------------------------

    def authenticate(
        self, scope: Scope, headers: dict[bytes, bytes]
    ) -> tuple[CallerPrincipal | None, CallerDenyReason | None]:
        if self.mode is CallerAuthMode.API_KEY:
            return self._by_api_key(headers)
        return self._by_proxy(scope, headers)

    def _by_api_key(
        self, headers: dict[bytes, bytes]
    ) -> tuple[CallerPrincipal | None, CallerDenyReason | None]:
        """`Authorization: Bearer <key>`, which an OpenAI client already sends.

        That is the entire reason this mode is the default: adopting the gateway
        stays a base-URL change, because `OpenAI(base_url=..., api_key=...)`
        populates this header without knowing the gateway exists.
        """
        raw = headers.get(b"authorization")
        if raw is None:
            return None, CallerDenyReason.MISSING_CREDENTIAL
        try:
            value = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            return None, CallerDenyReason.MALFORMED_CREDENTIAL
        if not value.lower().startswith(BEARER_PREFIX):
            return None, CallerDenyReason.MALFORMED_CREDENTIAL
        presented = value[len(BEARER_PREFIX) :].strip()
        if not presented:
            return None, CallerDenyReason.MISSING_CREDENTIAL

        candidate = digest(presented)
        matched: str | None = None
        for caller_id, stored in self.key_digests:
            # No `break`. Stopping at the first match would make the response
            # time depend on a credential's position in the configured list.
            if hmac.compare_digest(candidate, stored):
                matched = caller_id
        if matched is None:
            return None, CallerDenyReason.UNKNOWN_CREDENTIAL
        return CallerPrincipal(caller_id=matched), None

    def _by_proxy(
        self, scope: Scope, headers: dict[bytes, bytes]
    ) -> tuple[CallerPrincipal | None, CallerDenyReason | None]:
        """Identity asserted by a trusted ingress, on ADR-023's rule exactly.

        The peer address of the socket decides whether the header is read at all.
        `X-Forwarded-For` is never consulted here either — it is client-supplied,
        so trusting it would let a caller write its own permission slip.
        """
        address = peer_address(scope)
        if address is None or not any(address in net for net in self.trusted_proxies):
            return None, CallerDenyReason.UNTRUSTED_PEER

        if self.proxy_shared_secret is not None:
            presented = headers.get(self.proxy_shared_secret_header.lower().encode())
            if presented is None:
                return None, CallerDenyReason.MISSING_PROXY_SECRET
            if not hmac.compare_digest(presented, self.proxy_shared_secret.encode()):
                return None, CallerDenyReason.BAD_PROXY_SECRET

        raw = headers.get(self.identity_header.lower().encode())
        if raw is None or not raw.strip():
            return None, CallerDenyReason.MISSING_CALLER_HEADER
        try:
            caller_id = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            return None, CallerDenyReason.INVALID_CALLER_HEADER
        if not valid_subject(caller_id):
            return None, CallerDenyReason.INVALID_CALLER_HEADER
        if caller_id not in self.caller_ids:
            # The ingress says who is calling; this gateway still says whether
            # that caller is allowed. A misconfigured proxy inventing an identity
            # does not silently gain access.
            return None, CallerDenyReason.UNKNOWN_CALLER
        return CallerPrincipal(caller_id=caller_id), None


__all__ = [
    "BEARER_PREFIX",
    "UNAUTHENTICATED_CALLER",
    "CallerAuthConfig",
    "CallerDenyReason",
    "CallerPrincipal",
    "digest",
]
