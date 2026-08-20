"""Admission control: what the gateway accepts before it spends anything.

Three separate concerns, deliberately not one knob:

* **Global concurrency** — how many requests this process will have in flight at
  once. Protects the process itself, and by extension the detector thread pool
  and the upstream connection pool behind it.
* **Anonymous authentication-failure throttling** — a client that keeps
  presenting bad credentials is refused *before* the credential comparison runs,
  so a guessing flood costs a dictionary lookup rather than a SHA-256 and a
  linear scan.
* **Bounded state** — the two above track per-client state, and per-client state
  keyed by something an attacker chooses is itself a denial-of-service vector.

## The identity used for throttling

`X-Forwarded-For` is never parsed. The client identity is the socket peer,
unless the peer is inside `FIREWALL_TRUSTED_PROXIES`, in which case a single
configured header (`X-Real-IP` by default) is read instead — the same rule as
ADR-023, for the same reason: the peer address is the one value in an HTTP
request a remote client cannot choose. A client that could pick its own
throttling key could evade the throttle by picking a new one per request.

## Why the state map is capped and not merely expiring

Expiry alone bounds nothing: an attacker sending from a new address every
millisecond adds entries faster than a 60-second window removes them. `_Bounded`
therefore has a hard capacity and evicts the least-recently-seen entry when
full. Under a distributed flood that means the throttle degrades — an attacker
who can cycle through more addresses than the cap can push their own entry out —
but it degrades into "no worse than having no throttle", never into unbounded
memory. Volumetric defence is the edge's job (ADR-025); this is the safety net
behind it.
"""

from __future__ import annotations

import ipaddress
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.auth.identity import peer_address

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starlette.types import Scope

    from app.config.settings import IpNetwork

# Cap on distinct client identities tracked for authentication-failure
# throttling. 16k entries of (str, float, int) is a few megabytes — small enough
# to be uninteresting, large enough that a real deployment's client population
# never reaches it.
MAX_TRACKED_CLIENTS = 16_384

UNKNOWN_CLIENT = "unknown"


class _Bounded:
    """An LRU-capped, time-expiring counter map.

    `OrderedDict` rather than a plain dict: eviction needs an ordering, and
    `move_to_end` makes "least recently seen" O(1). Expiry is checked lazily on
    access, because a background sweep would be a timer this process does not
    otherwise need.
    """

    __slots__ = ("_capacity", "_entries", "_window")

    def __init__(self, *, capacity: int, window_seconds: float) -> None:
        self._capacity = capacity
        self._window = window_seconds
        # key -> (window_started_at, count)
        self._entries: OrderedDict[str, tuple[float, int]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def hit(self, key: str, now: float) -> int:
        """Record one occurrence and return the count within the live window."""
        entry = self._entries.get(key)
        if entry is None or now - entry[0] >= self._window:
            count = 1
            self._entries[key] = (now, 1)
        else:
            count = entry[1] + 1
            self._entries[key] = (entry[0], count)
        self._entries.move_to_end(key)
        self._evict(now)
        return count

    def count(self, key: str, now: float) -> int:
        """The live count without recording anything."""
        entry = self._entries.get(key)
        if entry is None or now - entry[0] >= self._window:
            return 0
        self._entries.move_to_end(key)
        return entry[1]

    def clear_key(self, key: str) -> None:
        self._entries.pop(key, None)

    def _evict(self, now: float) -> None:
        # Drop expired entries from the cold end first: they are free to remove
        # and doing so avoids evicting a live entry while dead ones remain.
        while self._entries:
            oldest_key = next(iter(self._entries))
            started, _ = self._entries[oldest_key]
            if now - started >= self._window:
                self._entries.popitem(last=False)
                continue
            break
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)


def client_identity(scope: Scope, trusted_proxies: tuple[IpNetwork, ...], header: str) -> str:
    """The address to throttle by. Never a value the client chose for itself.

    Returns a string rather than an address object because it is only ever used
    as a map key and in a log field — and *never* as a metric label, which would
    be unbounded cardinality by definition (§16).
    """
    peer = peer_address(scope)
    if peer is None:
        return UNKNOWN_CLIENT

    if trusted_proxies and any(peer in network for network in trusted_proxies):
        headers = dict(scope.get("headers", ()))
        raw = headers.get(header.lower().encode())
        if raw is not None:
            try:
                # One address, validated. `X-Forwarded-For` chains are not parsed
                # at all: the leftmost entry is attacker-supplied, and picking
                # "the right one" from a chain is a class of bug this avoids by
                # not having the feature.
                return str(ipaddress.ip_address(raw.decode("ascii").strip()))
            except (ValueError, UnicodeDecodeError):
                # A malformed header from the trusted proxy means the proxy is
                # misconfigured. Falling back to the peer throttles every request
                # behind it as one client, which is degraded but safe — inventing
                # a per-request identity would silently disable the throttle.
                return str(peer)
    return str(peer)


@dataclass(frozen=True, slots=True)
class AdmissionConfig:
    """Resolved admission limits for one process."""

    max_concurrent_requests: int
    auth_failures_per_minute: int
    trusted_proxies: tuple[IpNetwork, ...]
    client_ip_header: str

    @property
    def concurrency_enabled(self) -> bool:
        return self.max_concurrent_requests > 0

    @property
    def auth_throttle_enabled(self) -> bool:
        return self.auth_failures_per_minute > 0


class AuthFailureThrottle:
    """Refuses a client that keeps presenting bad credentials.

    The point is *cost*, not lockout. Without it, a guessing flood makes the
    gateway compute a SHA-256 and scan every configured digest per attempt; with
    it, an over-limit client is refused by a dictionary lookup. The window is
    short and the response is 429 rather than a ban, because the throttling key
    is an address and addresses are shared — a NAT gateway or a corporate egress
    can put a legitimate caller behind the same key as an attacker, and a ban
    would turn a nuisance into an outage.

    A successful authentication clears the client's count, so a caller that
    fumbles a rotation and then succeeds is not left throttled.
    """

    __slots__ = ("_clock", "_config", "_state")

    def __init__(
        self,
        config: AdmissionConfig,
        *,
        clock: Callable[[], float],
        capacity: int = MAX_TRACKED_CLIENTS,
    ) -> None:
        self._config = config
        self._clock = clock
        self._state = _Bounded(capacity=capacity, window_seconds=60.0)

    @property
    def config(self) -> AdmissionConfig:
        return self._config

    @property
    def tracked(self) -> int:
        return len(self._state)

    def is_throttled(self, client: str) -> bool:
        if not self._config.auth_throttle_enabled:
            return False
        return self._state.count(client, self._clock()) >= self._config.auth_failures_per_minute

    def record_failure(self, client: str) -> int:
        if not self._config.auth_throttle_enabled:
            return 0
        return self._state.hit(client, self._clock())

    def record_success(self, client: str) -> None:
        self._state.clear_key(client)


__all__ = [
    "MAX_TRACKED_CLIENTS",
    "UNKNOWN_CLIENT",
    "AdmissionConfig",
    "AuthFailureThrottle",
    "client_identity",
]
