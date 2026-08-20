"""`/ready` as a security contract, over HTTP (ADR-027).

Two properties this file exists for.

**Correspondence.** Most security-boundary checks restate an invariant the
process refuses to start without, so they can never fail in a running system —
which makes them exactly the kind of code that rots unnoticed. The
correspondence tests build the states startup would have rejected and assert
readiness catches them anyway, so the day someone relaxes a startup check the
probe still reports the truth.

**Discretion.** `/ready` is an unauthenticated probe reachable by anything that
can reach the instance, and it now describes the security boundary. It must
describe it without handing an attacker the configuration.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.caller import CallerAuthConfig, digest
from app.auth.identity import AuthConfig
from app.auth.transport import TransportPolicy
from app.config.settings import Settings
from app.core.exceptions import ConfigurationError
from app.main import create_app
from tests.conftest import CALLER_KEY, TRUSTED_PEER

pytestmark = pytest.mark.security

# Every configuration the process refuses to start with. Each must also be a
# readiness failure — the list is the contract, and it is walked twice below.
REFUSED_AT_STARTUP = [
    pytest.param(
        {"environment": "production", "console_auth_mode": "disabled"},
        "operator_boundary",
        id="production-console-open",
    ),
    pytest.param(
        {"environment": "production", "caller_auth_mode": "disabled"},
        "caller_boundary",
        id="production-gateway-open",
    ),
    pytest.param(
        {"environment": "production", "https_enforced": False},
        "transport",
        id="production-plaintext",
    ),
    pytest.param(
        {"caller_auth_mode": "api_key", "caller_api_keys": ""},
        "caller_boundary",
        id="api-key-mode-without-keys",
    ),
    pytest.param(
        {"https_enforced": True, "trusted_proxies": ""},
        "transport",
        id="https-without-a-trusted-peer",
    ),
]


@pytest.mark.parametrize(("overrides", "check_name"), REFUSED_AT_STARTUP)
def test_the_process_refuses_to_start(overrides: dict, check_name: str):
    """Half one of the correspondence: startup rejects each of these."""
    settings = Settings(environments_dir="/nonexistent", **overrides)
    with pytest.raises(ConfigurationError):
        create_app(settings)


@pytest.mark.parametrize(("overrides", "check_name"), REFUSED_AT_STARTUP)
def test_readiness_reports_the_same_configurations_as_unready(overrides: dict, check_name: str):
    """Half two: readiness catches them even with startup validation bypassed.

    The state is assembled directly rather than through `create_app`, which is
    the only way to reach a configuration the factory would have refused — and
    the only way to prove the readiness check is doing its own work rather than
    riding on the startup guarantee.
    """
    from types import SimpleNamespace

    from app.api.readiness import evaluate, is_ready
    from app.config.settings import CallerAuthMode, ConsoleAuthMode

    settings = Settings(environments_dir="/nonexistent", **overrides)
    trusted = settings.trusted_proxy_networks
    state = SimpleNamespace(
        config=SimpleNamespace(settings=settings, policy_version="sha256:x"),
        auth=AuthConfig(
            mode=ConsoleAuthMode(
                overrides.get("console_auth_mode")
                or ("proxy" if settings.is_production else "disabled")
            ),
            trusted_proxies=trusted,
            shared_secret=None,
            shared_secret_header="X-Firewall-Proxy-Secret",
            subject_header="X-Auth-Request-User",
            roles_header="X-Auth-Request-Groups",
            operator_roles=frozenset(),
            metrics_networks=(),
            logout_path=None,
        ),
        caller_auth=CallerAuthConfig(
            mode=CallerAuthMode(
                overrides.get("caller_auth_mode")
                or ("api_key" if settings.is_production else "disabled")
            ),
            key_digests=settings.caller_key_digests,
            trusted_proxies=settings.caller_trusted_proxy_networks,
            proxy_shared_secret=None,
            proxy_shared_secret_header="X-Firewall-Proxy-Secret",
            identity_header="X-Firewall-Caller",
            rate_limit_per_minute=0,
            max_concurrent_requests=0,
        ),
        transport=TransportPolicy(https_enforced=settings.https_enforced, trusted_proxies=trusted),
        detectors_warmed=True,
        pipeline=SimpleNamespace(all_detectors=()),
    )

    checks = evaluate(state)
    failed = {c.name for c in checks if not c.passed}
    assert check_name in failed, f"readiness missed what startup rejects: {failed}"
    assert is_ready(checks) is False


# --- §12: a stable, machine-readable contract ---------------------------------


async def test_the_response_shape_is_stable_and_classified(client: AsyncClient):
    body = (await client.get("/ready")).json()
    assert body["status"] in ("ready", "not_ready")
    assert isinstance(body["checks"], list)
    for check in body["checks"]:
        # The pre-Phase-13 fields are unchanged, because the operator console
        # renders this list and a reshaped payload would have broken it.
        assert set(check) == {"name", "passed", "detail", "category", "requirement"}
        assert check["category"] in {
            "configuration",
            "security_boundary",
            "detectors",
            "database",
        }
        assert check["requirement"] in {"required", "advisory"}


async def test_every_category_is_represented(client: AsyncClient):
    """A category with no check is a part of the contract nobody verifies."""
    body = (await client.get("/ready")).json()
    assert {c["category"] for c in body["checks"]} == {
        "configuration",
        "security_boundary",
        "detectors",
        "database",
    }


# --- Discretion: this is a public probe ----------------------------------------


async def test_readiness_describes_the_boundary_without_revealing_it(caller_client):
    """It says a boundary is configured, never how.

    An unauthenticated reader learns that the instance is ready. Not the trusted
    CIDR, not the authentication mode, not a caller id, and certainly not a
    credential — the operator-authenticated `/api/v1/system/status` carries the
    specifics.
    """
    async with caller_client(
        peer=TRUSTED_PEER,
        console_auth_mode="proxy",
        trusted_proxies="10.9.8.7/32",
        caller_api_keys=f"billing-svc:{digest(CALLER_KEY)}",
        operator_roles="security-ops",
    ) as client:
        response = await client.get("/ready")

    body = response.text
    for leaked in (
        "10.9.8.7",
        "billing-svc",
        CALLER_KEY,
        digest(CALLER_KEY),
        "api_key",
        "security-ops",
        "X-Auth-Request-User",
        "/etc/",
        "Traceback",
    ):
        assert leaked not in body, leaked


async def test_readiness_stays_reachable_without_a_credential(caller_client):
    """It is a probe. An orchestrator that cannot read it de-pools a healthy
    instance, so it stays in the PUBLIC access class even with both boundaries
    enforcing and HTTPS required."""
    async with caller_client(
        peer=TRUSTED_PEER,
        console_auth_mode="proxy",
        trusted_proxies="127.0.0.1/32",
        https_enforced=True,
    ) as client:
        assert (await client.get("/ready")).status_code == 200
        assert (await client.get("/health")).status_code == 200


# --- §3: /health stays lightweight ---------------------------------------------


async def test_health_checks_nothing_external():
    """It must answer when the database is unreachable and the boundary is
    misconfigured — that is the difference between "restart me" and "take me out
    of rotation"."""
    settings = Settings(
        persist_events=True,
        database_url="postgresql+asyncpg://nobody@127.0.0.1:1/none",
    )
    app = create_app(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://firewall") as client:
        async with app.router.lifespan_context(app):
            health = await client.get("/health")
            ready = await client.get("/ready")

    assert health.status_code == 200
    # Best-effort audit (require_audit=False), so an unreachable store is an
    # advisory failure and the instance keeps serving (ADR-012, ADR-027).
    assert ready.status_code == 200
    database = next(c for c in ready.json()["checks"] if c["name"] == "database")
    assert database["passed"] is False
    assert database["requirement"] == "advisory"


async def test_a_mandatory_audit_store_makes_an_outage_fatal():
    """`require_audit=true` inverts ADR-012's trade: every request would fail, so
    the instance genuinely cannot serve and must leave rotation."""
    settings = Settings(
        persist_events=True,
        require_audit=True,
        database_url="postgresql+asyncpg://nobody@127.0.0.1:1/none",
    )
    app = create_app(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://firewall") as client:
        async with app.router.lifespan_context(app):
            ready = await client.get("/ready")

    assert ready.status_code == 503
    assert ready.json()["status"] == "not_ready"
    database = next(c for c in ready.json()["checks"] if c["name"] == "database")
    assert database["requirement"] == "required"
