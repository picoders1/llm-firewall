"""Admission control, and the state it keeps (ADR-025).

The interesting property here is not that the limits work — it is that the
bookkeeping *behind* them cannot itself be turned into the attack. A rate
limiter keyed by something an attacker chooses is a memory leak with a security
justification, so most of this file is about the map rather than the limit.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.auth.admission import (
    MAX_TRACKED_CLIENTS,
    UNKNOWN_CLIENT,
    AdmissionConfig,
    AuthFailureThrottle,
    _Bounded,
    client_identity,
)

pytestmark = pytest.mark.unit


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _config(**overrides) -> AdmissionConfig:
    base = {
        "max_concurrent_requests": 0,
        "auth_failures_per_minute": 3,
        "trusted_proxies": (),
        "client_ip_header": "X-Real-IP",
    }
    return AdmissionConfig(**{**base, **overrides})


def _scope(host: str | None, headers: dict[str, str] | None = None) -> dict:
    return {
        "type": "http",
        "client": (host, 1234) if host else None,
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }


# --- §5: the throttling key is never the client's to choose -------------------


def test_the_client_key_is_the_socket_peer_by_default():
    assert client_identity(_scope("203.0.113.9"), (), "X-Real-IP") == "203.0.113.9"


def test_a_forwarded_header_from_an_untrusted_peer_is_ignored():
    """The attack this prevents is evasion, not impersonation: a client that
    could pick its own throttling key would simply pick a new one per request
    and never hit a limit."""
    scope = _scope("203.0.113.9", {"X-Real-IP": "10.0.0.1", "X-Forwarded-For": "10.0.0.2"})
    assert client_identity(scope, (), "X-Real-IP") == "203.0.113.9"


def test_a_forwarded_header_from_the_trusted_proxy_is_honoured():
    """The control case. Without it the test above would pass for a boundary that
    simply never reads the header."""
    trusted = (ipaddress.ip_network("10.9.0.1/32"),)
    scope = _scope("10.9.0.1", {"X-Real-IP": "198.51.100.7"})
    assert client_identity(scope, trusted, "X-Real-IP") == "198.51.100.7"


def test_x_forwarded_for_is_never_parsed_even_from_a_trusted_peer():
    """A forwarded-for chain is partly client-supplied, and choosing the right
    entry from it is a class of bug avoided by not having the feature. Only the
    single configured header is read."""
    trusted = (ipaddress.ip_network("10.9.0.1/32"),)
    scope = _scope("10.9.0.1", {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
    assert client_identity(scope, trusted, "X-Real-IP") == "10.9.0.1"


@pytest.mark.parametrize("value", ["not-an-ip", "", "10.0.0.1, 10.0.0.2", "999.999.999.999"])
def test_a_malformed_trusted_header_falls_back_to_the_peer(value: str):
    """Degraded but safe: everyone behind the misconfigured proxy is throttled as
    one client. Inventing a per-request identity would silently disable the
    throttle, which is the failure worth avoiding."""
    trusted = (ipaddress.ip_network("10.9.0.1/32"),)
    scope = _scope("10.9.0.1", {"X-Real-IP": value})
    assert client_identity(scope, trusted, "X-Real-IP") == "10.9.0.1"


def test_a_peerless_scope_has_a_single_known_key():
    """Not `None`, and not a fresh value per request — either would mean requests
    with no peer bypass the throttle entirely."""
    assert client_identity(_scope(None), (), "X-Real-IP") == UNKNOWN_CLIENT


def test_an_ipv4_mapped_peer_normalises_to_its_v4_form():
    """`::ffff:203.0.113.9` and `203.0.113.9` are the same host; two keys would
    give one client twice its allowance."""
    assert client_identity(_scope("::ffff:203.0.113.9"), (), "X-Real-IP") == "203.0.113.9"


# --- §9: the state map is bounded ---------------------------------------------


def test_the_map_never_exceeds_its_capacity_under_a_distributed_flood():
    """The headline memory-safety property. Expiry alone bounds nothing: an
    attacker sending from a new address every millisecond adds entries faster
    than a 60-second window removes them, so there is a hard cap and an eviction.
    """
    state = _Bounded(capacity=1_000, window_seconds=60.0)
    for index in range(50_000):
        state.hit(f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}", 1_000.0)
    assert len(state) <= 1_000


def test_the_throttle_survives_ten_thousand_distinct_clients():
    """§9's stress level, driven through the real object rather than the map."""
    clock = FakeClock()
    throttle = AuthFailureThrottle(_config(), clock=clock, capacity=4_096)
    for index in range(10_000):
        throttle.record_failure(f"198.51.{index // 256 % 256}.{index % 256}")
    assert throttle.tracked <= 4_096


def test_eviction_prefers_expired_entries_over_live_ones():
    """A live attacker's entry should not be pushed out by a burst of addresses
    that have already aged out — that would be a way to reset one's own count."""
    state = _Bounded(capacity=3, window_seconds=60.0)
    state.hit("old", 1_000.0)
    state.hit("live", 1_100.0)
    # 'old' is now expired; adding two more must drop it rather than 'live'.
    state.hit("a", 1_100.0)
    state.hit("b", 1_100.0)
    assert state.count("live", 1_100.0) == 1


def test_the_default_capacity_is_stated_rather_than_implicit():
    assert MAX_TRACKED_CLIENTS == 16_384


# --- §7: authentication-failure throttling -------------------------------------


def test_a_client_is_throttled_only_after_exceeding_the_allowance():
    clock = FakeClock()
    throttle = AuthFailureThrottle(_config(auth_failures_per_minute=3), clock=clock)
    for _ in range(3):
        assert throttle.is_throttled("1.2.3.4") is False
        throttle.record_failure("1.2.3.4")
    assert throttle.is_throttled("1.2.3.4") is True


def test_the_window_expires():
    clock = FakeClock()
    throttle = AuthFailureThrottle(_config(auth_failures_per_minute=1), clock=clock)
    throttle.record_failure("1.2.3.4")
    assert throttle.is_throttled("1.2.3.4") is True
    clock.advance(61)
    assert throttle.is_throttled("1.2.3.4") is False


def test_clients_are_throttled_independently():
    clock = FakeClock()
    throttle = AuthFailureThrottle(_config(auth_failures_per_minute=1), clock=clock)
    throttle.record_failure("1.2.3.4")
    assert throttle.is_throttled("1.2.3.4") is True
    assert throttle.is_throttled("5.6.7.8") is False


def test_a_success_clears_the_count():
    """A caller that fumbles a credential rotation and then gets it right must
    not stay throttled on the strength of its earlier attempts."""
    clock = FakeClock()
    throttle = AuthFailureThrottle(_config(auth_failures_per_minute=2), clock=clock)
    throttle.record_failure("1.2.3.4")
    throttle.record_failure("1.2.3.4")
    assert throttle.is_throttled("1.2.3.4") is True
    throttle.record_success("1.2.3.4")
    assert throttle.is_throttled("1.2.3.4") is False


def test_a_disabled_throttle_never_refuses_and_never_allocates():
    clock = FakeClock()
    throttle = AuthFailureThrottle(_config(auth_failures_per_minute=0), clock=clock)
    for _ in range(1_000):
        throttle.record_failure("1.2.3.4")
    assert throttle.is_throttled("1.2.3.4") is False
    assert throttle.tracked == 0
