"""The access-class table and peer resolution, as a truth table.

These are the two decisions everything else rests on, and both are pure
functions — so they can be tested exhaustively without an application, a socket
or a proxy. The middleware tests then only have to prove the wiring.
"""

from __future__ import annotations

import pytest

from app.auth.identity import (
    MAX_SUBJECT_LENGTH,
    AccessClass,
    AuthConfig,
    DenyReason,
    Role,
    classify_path,
)
from app.config.settings import Settings

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/health", AccessClass.PUBLIC),
        ("/ready", AccessClass.PUBLIC),
        ("/ready/", AccessClass.PUBLIC),
        ("/metrics", AccessClass.INTERNAL),
        ("/v1", AccessClass.GATEWAY),
        ("/v1/chat/completions", AccessClass.GATEWAY),
        ("/v1/models", AccessClass.GATEWAY),
        ("/dashboard", AccessClass.OPERATOR),
        ("/dashboard/js/app.js", AccessClass.OPERATOR),
        ("/api/v1/overview", AccessClass.OPERATOR),
        ("/api/v1/security/events/42", AccessClass.OPERATOR),
        ("/docs", AccessClass.OPERATOR),
        ("/openapi.json", AccessClass.OPERATOR),
        ("/", AccessClass.OPERATOR),
        ("/anything-added-later", AccessClass.OPERATOR),
    ],
)
def test_the_access_class_table(path: str, expected: AccessClass):
    assert classify_path(path) is expected


@pytest.mark.parametrize(
    "path",
    ["/healthz", "/health/deep", "/metrics/raw", "/v1x/chat", "/api/v1/../metrics"],
    ids=["near-miss-probe", "sub-path", "sub-metrics", "prefix-lookalike", "traversal-shaped"],
)
def test_paths_that_merely_resemble_a_public_one_are_not_public(path: str):
    """`/healthz` is not `/health`. Prefix matching on a public path is how an
    entire subtree ends up unauthenticated by accident."""
    assert classify_path(path) is AccessClass.OPERATOR


def _config(**overrides) -> AuthConfig:
    return AuthConfig.from_settings(
        Settings(console_auth_mode="proxy", trusted_proxies="10.0.0.5/32", **overrides)
    )


def _scope(host: str) -> dict:
    return {"type": "http", "client": (host, 1234)}


@pytest.mark.parametrize(
    ("host", "trusted"),
    [
        ("10.0.0.5", True),
        ("10.0.0.6", False),
        ("::ffff:10.0.0.5", True),
        ("2001:db8::1", False),
        ("not-an-ip", False),
    ],
    ids=["exact", "neighbour", "v4-mapped-v6", "v6", "non-ip-peer"],
)
def test_peer_trust(host: str, trusted: bool):
    """`::ffff:10.0.0.5` and `10.0.0.5` are the same host — a dual-stack listener
    reports the first, and a CIDR written for the second must still match, or the
    boundary silently locks out the proxy the day IPv6 is enabled."""
    assert _config().peer_is_trusted(_scope(host)) is trusted


def test_a_peerless_scope_is_never_trusted():
    """Some transports report no client at all. "Unknown" must resolve to
    untrusted, not to a permissive default."""
    assert _config().peer_is_trusted({"type": "http", "client": None}) is False
    assert _config().peer_is_trusted({"type": "http"}) is False


def test_authentication_stops_at_the_peer_check_before_reading_a_header():
    """Ordering, asserted directly: an untrusted peer's headers are never parsed,
    so a malformed forgery cannot even reach the parsing code."""
    outcome = _config().authenticate(_scope("10.0.0.6"), {b"x-auth-request-user": b"attacker"})
    assert outcome.principal is None
    assert outcome.reason is DenyReason.UNTRUSTED_PEER


def test_a_trusted_peer_with_no_subject_is_unauthenticated_not_anonymous_operator():
    outcome = _config().authenticate(_scope("10.0.0.5"), {})
    assert outcome.principal is None
    assert outcome.reason is DenyReason.MISSING_SUBJECT


def test_a_subject_at_the_length_limit_is_accepted():
    """The boundary value, so the limit is a limit and not an off-by-one that
    rejects one character early."""
    subject = "a" * MAX_SUBJECT_LENGTH
    outcome = _config().authenticate(_scope("10.0.0.5"), {b"x-auth-request-user": subject.encode()})
    assert outcome.principal is not None
    assert outcome.principal.subject == subject
    assert outcome.principal.role is Role.OPERATOR


def test_a_non_ascii_subject_is_refused():
    outcome = _config().authenticate(_scope("10.0.0.5"), {b"x-auth-request-user": "alïce".encode()})
    assert outcome.reason is DenyReason.INVALID_SUBJECT


def test_a_wrong_shared_secret_is_reported_distinctly_in_the_log_only():
    config = _config(proxy_shared_secret="right")
    outcome = config.authenticate(
        _scope("10.0.0.5"),
        {b"x-auth-request-user": b"alice", b"x-firewall-proxy-secret": b"wrong"},
    )
    assert outcome.reason is DenyReason.BAD_PROXY_SECRET
    assert outcome.principal is None


def test_header_names_are_validated_at_load_time():
    """A header name is used to read attacker-adjacent input. A malformed one is
    a configuration error to fail on, not something to paper over per request."""
    with pytest.raises(ValueError, match="not a valid HTTP header name"):
        Settings(auth_subject_header="X-Auth User")
    with pytest.raises(ValueError, match="not a valid HTTP header name"):
        Settings(auth_roles_header="")


def test_a_malformed_cidr_fails_at_load_time_naming_the_field():
    with pytest.raises(ValueError, match="trusted_proxies"):
        Settings(trusted_proxies="10.0.0.0/33")
    with pytest.raises(ValueError, match="metrics_networks"):
        Settings(metrics_networks="not-a-network")


def test_a_host_address_without_a_prefix_is_accepted_as_a_single_host():
    """`FIREWALL_TRUSTED_PROXIES=10.0.0.5` is what an operator will write for one
    ingress, and it should mean `/32` rather than fail."""
    config = _config()
    assert AuthConfig.from_settings(
        Settings(console_auth_mode="proxy", trusted_proxies="10.0.0.5")
    ).peer_is_trusted(_scope("10.0.0.5"))
    assert config.peer_is_trusted(_scope("10.0.0.5"))
