"""The readiness contract, evaluated without an HTTP layer (ADR-027).

`evaluate` takes application state rather than a request precisely so this file
can construct the states a running process is *supposed* to be impossible to
reach — a production app with an unauthenticated console, a boundary config that
startup would have rejected — and assert readiness catches them anyway. That is
the whole value of re-asserting a startup invariant: it has to hold even when
the thing that normally guarantees it has been removed.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.api.readiness import (
    BROAD_PREFIX_THRESHOLD,
    Category,
    Check,
    Requirement,
    database_checks,
    evaluate,
    is_ready,
)
from app.auth.caller import CallerAuthConfig, digest
from app.auth.identity import AuthConfig
from app.auth.transport import TransportPolicy
from app.config.settings import CallerAuthMode, ConsoleAuthMode, Settings, parse_networks

pytestmark = pytest.mark.unit

HEAD = "6b2f4c8d1a09"


def _state(**overrides):
    """A healthy application state, with the pieces `/ready` reads."""
    settings = overrides.pop("settings", Settings())
    trusted = parse_networks(overrides.pop("trusted", "10.0.0.5/32"), field="t")
    # Coerced to enum members because that is what `from_settings` produces and
    # what the checks compare with `is`. A raw string would silently satisfy
    # `mode is not CallerAuthMode.DISABLED` and make this helper test nothing.
    console_mode = ConsoleAuthMode(
        overrides.pop("console_mode", settings.effective_console_auth_mode())
    )
    caller_mode = CallerAuthMode(
        overrides.pop("caller_mode", settings.effective_caller_auth_mode())
    )
    base = {
        "config": SimpleNamespace(settings=settings, policy_version="sha256:deadbeef"),
        "auth": AuthConfig(
            mode=console_mode,
            trusted_proxies=trusted,
            shared_secret=None,
            shared_secret_header="X-Firewall-Proxy-Secret",
            subject_header="X-Auth-Request-User",
            roles_header="X-Auth-Request-Groups",
            operator_roles=frozenset(),
            metrics_networks=(),
            logout_path=None,
        ),
        "caller_auth": CallerAuthConfig(
            mode=caller_mode,
            key_digests=overrides.pop("digests", ()),
            trusted_proxies=trusted,
            proxy_shared_secret=None,
            proxy_shared_secret_header="X-Firewall-Proxy-Secret",
            identity_header="X-Firewall-Caller",
            rate_limit_per_minute=0,
            max_concurrent_requests=0,
        ),
        "transport": TransportPolicy(
            https_enforced=overrides.pop("https", settings.https_enforced),
            trusted_proxies=trusted,
        ),
        "detectors_warmed": True,
        "pipeline": SimpleNamespace(all_detectors=(1, 2, 3)),
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _named(checks: list[Check], name: str) -> Check:
    return next(c for c in checks if c.name == name)


# --- §5: the classification is the point --------------------------------------


def test_an_advisory_failure_does_not_make_the_instance_unready():
    """Marking everything REQUIRED is how a readiness probe turns a degraded
    dependency into an outage."""
    checks = [
        Check("a", Category.DATABASE, Requirement.REQUIRED, True),
        Check("b", Category.DATABASE, Requirement.ADVISORY, False),
    ]
    assert is_ready(checks) is True


def test_a_required_failure_does():
    checks = [Check("a", Category.CONFIGURATION, Requirement.REQUIRED, False)]
    assert is_ready(checks) is False


def test_every_check_declares_a_category_and_a_requirement():
    """A check with no classification is one nobody decided about."""
    for check in evaluate(_state()):
        assert isinstance(check.category, Category)
        assert isinstance(check.requirement, Requirement)


# --- §11: the database classification, which is a correction -------------------


def test_an_unreachable_database_is_advisory_when_audit_is_best_effort():
    """ADR-012: an audit-write failure does not fail the request — the security
    decision is unaffected and only the record is lost. The previous
    implementation failed readiness anyway, turning an audit outage into a
    traffic outage."""
    checks = database_checks(
        configured=True, reachable=False, revision=None, expected=HEAD, required=False
    )
    assert _named(checks, "database").requirement is Requirement.ADVISORY
    assert is_ready(checks) is True


def test_an_unreachable_database_is_fatal_when_audit_is_mandatory():
    """`require_audit=true` inverts ADR-012's trade: every request now fails, so
    the instance genuinely cannot serve."""
    checks = database_checks(
        configured=True, reachable=False, revision=None, expected=HEAD, required=True
    )
    assert _named(checks, "database").requirement is Requirement.REQUIRED
    assert is_ready(checks) is False


def test_persistence_disabled_is_a_configuration_choice_not_a_failure():
    checks = database_checks(
        configured=False, reachable=False, revision=None, expected=HEAD, required=False
    )
    assert len(checks) == 1
    assert checks[0].passed is True
    assert checks[0].detail == "persistence disabled"


def test_no_schema_check_is_reported_when_the_database_is_unreachable():
    """Reporting a schema mismatch you could not read would be inventing one."""
    checks = database_checks(
        configured=True, reachable=False, revision=None, expected=HEAD, required=True
    )
    assert [c.name for c in checks] == ["database"]


def test_a_stale_schema_is_reported_and_names_both_revisions():
    checks = database_checks(
        configured=True, reachable=True, revision="old", expected=HEAD, required=False
    )
    schema = _named(checks, "database_schema")
    assert schema.passed is False
    assert "old" in schema.detail and HEAD in schema.detail


def test_an_unmigrated_database_is_distinguished_from_a_stale_one():
    """No `alembic_version` row at all is a fresh database, not a version skew —
    and it sends an operator somewhere different."""
    checks = database_checks(
        configured=True, reachable=True, revision=None, expected=HEAD, required=True
    )
    schema = _named(checks, "database_schema")
    assert schema.passed is False
    assert "migrations have not been applied" in schema.detail


def test_an_unknown_expected_revision_does_not_assert_a_mismatch():
    """ "I cannot tell" is different from "they differ", and only one is a
    deployment error."""
    checks = database_checks(
        configured=True, reachable=True, revision="abc", expected=None, required=True
    )
    schema = _named(checks, "database_schema")
    assert schema.passed is True
    assert "expected revision unknown" in schema.detail


# --- §4 / §6 / §7 / §8: the security boundary ---------------------------------


def test_production_without_an_authenticated_console_is_not_ready():
    settings = Settings(environment="production", https_enforced=True)
    checks = evaluate(_state(settings=settings, console_mode="disabled"))
    assert _named(checks, "operator_boundary").passed is False
    assert is_ready(checks) is False


def test_production_without_caller_authentication_is_not_ready():
    settings = Settings(environment="production", https_enforced=True)
    checks = evaluate(_state(settings=settings, caller_mode="disabled"))
    assert _named(checks, "caller_boundary").passed is False
    assert is_ready(checks) is False


def test_api_key_mode_with_no_credentials_is_not_ready():
    """It would refuse every caller while reporting itself protected."""
    settings = Settings(environment="production", https_enforced=True)
    checks = evaluate(_state(settings=settings, caller_mode="api_key", digests=()))
    assert _named(checks, "caller_boundary").passed is False


def test_configured_credentials_are_counted_never_revealed():
    settings = Settings(environment="production", https_enforced=True)
    checks = evaluate(
        _state(
            settings=settings,
            caller_mode="api_key",
            digests=(("web-app", digest("k1")), ("batch", digest("k2"))),
        )
    )
    caller = _named(checks, "caller_boundary")
    assert caller.passed is True
    assert caller.detail == "2 caller(s) configured"
    assert "web-app" not in caller.detail


def test_https_enforced_without_a_trusted_peer_is_not_ready():
    """Nothing could ever assert the hop was TLS, so every request would 426 —
    an instance that is down rather than protected."""
    checks = evaluate(_state(https=True, trusted=""))
    assert _named(checks, "transport").passed is False
    assert is_ready(checks) is False


def test_production_without_https_is_not_ready():
    settings = Settings(environment="production", https_enforced=False)
    checks = evaluate(_state(settings=settings, https=False))
    assert _named(checks, "transport").passed is False


# --- §6: breadth is advisory, and reports something new -------------------------


def test_a_whole_private_network_as_trusted_proxy_is_flagged_but_not_fatal():
    """`0.0.0.0/0` is refused at startup; `10.0.0.0/8` is accepted — and means
    every workload on that network can assert an operator identity, a client
    address and a TLS claim. Usually a mistake, occasionally deliberate."""
    checks = evaluate(_state(trusted="10.0.0.0/8"))
    breadth = _named(checks, "trusted_proxy_breadth")
    assert breadth.requirement is Requirement.ADVISORY
    assert breadth.passed is False
    assert is_ready(checks) is True


def test_a_narrow_trusted_range_passes():
    checks = evaluate(_state(trusted="10.0.0.5/32,10.0.1.0/24"))
    assert _named(checks, "trusted_proxy_breadth").passed is True


def test_the_breadth_threshold_is_stated_rather_than_implicit():
    assert BROAD_PREFIX_THRESHOLD == 16


# --- §10: detectors ------------------------------------------------------------


def test_unwarmed_detectors_are_not_ready():
    checks = evaluate(_state(detectors_warmed=False))
    assert _named(checks, "detectors_warmed").passed is False
    assert is_ready(checks) is False


def test_a_policy_disabled_detector_does_not_block_readiness():
    """`injection.transformer` ships disabled and warn-only, so an instance
    without its weights is correctly ready — the pipeline only ever builds and
    warms detectors policy enabled."""
    state = _state(pipeline=SimpleNamespace(all_detectors=(1, 2, 3)))
    checks = evaluate(state)
    assert _named(checks, "detectors_warmed").passed is True
    assert "3 enabled detector(s)" in _named(checks, "detectors_warmed").detail


# --- §9: configuration -----------------------------------------------------------


def test_a_missing_policy_is_not_ready():
    checks = evaluate(SimpleNamespace(config=None, detectors_warmed=True))
    assert _named(checks, "policy_loaded").passed is False
    assert is_ready(checks) is False


def test_uninitialised_boundaries_fail_rather_than_being_skipped():
    """A boundary that is absent from state must not read as "fine"."""
    state = _state()
    state.auth = None
    state.caller_auth = None
    state.transport = None
    checks = evaluate(state)
    for name in ("operator_boundary", "caller_boundary", "transport"):
        assert _named(checks, name).passed is False, name
