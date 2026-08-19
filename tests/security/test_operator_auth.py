"""The operator boundary, attacked rather than described (ADR-023).

Header-propagated identity has exactly one failure mode worth testing: a client
that sets the header itself. Everything here exists to prove that a request
arriving directly from an untrusted peer cannot become an authenticated operator
however it is dressed up — and that the *reason* it failed never travels back to
the client or into a log field an attacker chose.

The proxy owns the other half of the contract (strip inbound, inject
authoritative). That half runs in nginx and cannot be exercised from pytest, so
it is asserted against the shipped reference configuration instead of assumed.
"""

from __future__ import annotations

import json
from pathlib import Path

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
from app.core.exceptions import ConfigurationError
from tests.conftest import TRUSTED_PEER, UNTRUSTED_PEER

pytestmark = pytest.mark.security

REPO_ROOT = Path(__file__).resolve().parents[2]

OPERATOR = {"X-Auth-Request-User": "alice@example.test"}
PROTECTED = "/api/v1/detectors"


# --- §17: the spoofing attack ----------------------------------------------


async def test_identity_header_from_an_untrusted_client_is_refused(enforcing_client):
    """The whole attack, in one request: an attacker asserts they are an operator.

    This is what the boundary exists for. The header is well-formed and names a
    plausible subject; the only thing wrong with it is that the socket did not
    come from the proxy.
    """
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        response = await client.get(
            PROTECTED,
            headers={"X-Auth-Request-User": "attacker", "X-Auth-Request-Groups": "operators"},
        )
    assert response.status_code == 401


async def test_a_forwarded_for_chain_cannot_manufacture_a_trusted_peer(enforcing_client):
    """`X-Forwarded-For` is client-supplied, so trusting it would let the attacker
    write their own permission slip. The boundary never reads it."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        response = await client.get(
            PROTECTED,
            headers={
                "X-Auth-Request-User": "attacker",
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "Forwarded": "for=127.0.0.1",
            },
        )
    assert response.status_code == 401


async def test_the_same_headers_from_the_proxy_are_honoured(enforcing_client):
    """The control test that stops the one above being vacuous.

    Identical headers, different peer, opposite outcome — which proves the
    refusal is caused by the peer check and not by the request being malformed.
    """
    async with enforcing_client(peer=TRUSTED_PEER) as client:
        response = await client.get(PROTECTED, headers=OPERATOR)
    assert response.status_code == 200


async def test_the_shared_secret_is_required_when_configured(enforcing_client):
    """Defence in depth for the case the CIDR is a whole pod network: something
    else inside the trusted range still cannot impersonate the proxy."""
    async with enforcing_client(peer=TRUSTED_PEER, proxy_shared_secret="s3cret") as client:
        without = await client.get(PROTECTED, headers=OPERATOR)
        wrong = await client.get(
            PROTECTED, headers={**OPERATOR, "X-Firewall-Proxy-Secret": "s3crey"}
        )
        correct = await client.get(
            PROTECTED, headers={**OPERATOR, "X-Firewall-Proxy-Secret": "s3cret"}
        )
    assert (without.status_code, wrong.status_code, correct.status_code) == (401, 401, 200)


@pytest.mark.parametrize(
    "subject",
    [
        "alice\nX-Auth-Request-User: root",  # header/log injection
        "alice\r\nSet-Cookie: a=b",
        "alice\x00root",
        "",
        "   ",
        "a" * (MAX_SUBJECT_LENGTH + 1),
    ],
    ids=["newline", "crlf", "nul", "empty", "blank", "too-long"],
)
async def test_a_malformed_subject_is_refused_rather_than_sanitised(enforcing_client, subject):
    """Rejecting is right: a subject with a newline in it means the proxy is
    misconfigured, and quietly trimming it would hide that while writing a forged
    record into the security log."""
    async with enforcing_client(peer=TRUSTED_PEER) as client:
        response = await client.get(PROTECTED, headers={"X-Auth-Request-User": subject})
    assert response.status_code == 401


async def test_an_authenticated_non_operator_is_403_not_401(enforcing_client):
    """The distinction §16 requires: 401 means "who are you", 403 means "not you".
    Collapsing them sends an operator round a sign-in loop that cannot succeed."""
    async with enforcing_client(peer=TRUSTED_PEER, operator_roles="security-ops") as client:
        denied = await client.get(
            PROTECTED, headers={**OPERATOR, "X-Auth-Request-Groups": "interns,contractors"}
        )
        allowed = await client.get(
            PROTECTED, headers={**OPERATOR, "X-Auth-Request-Groups": "interns,security-ops"}
        )
    assert denied.status_code == 403
    assert allowed.status_code == 200


# --- What a refusal is allowed to say --------------------------------------


async def test_a_refusal_leaks_nothing_about_the_boundary(enforcing_client):
    """An unauthenticated client learns that it is unauthenticated, and no more.

    Not the header name, not the trusted range, not the identity provider, not
    which of the several checks failed — each of those is a step towards a
    working forgery.
    """
    async with enforcing_client(
        peer=UNTRUSTED_PEER, proxy_shared_secret="s3cret", operator_roles="security-ops"
    ) as client:
        response = await client.get(PROTECTED, headers={"X-Auth-Request-User": "attacker"})

    body = response.text.lower()
    for leaked in (
        "x-auth-request-user",
        "x-firewall-proxy-secret",
        "s3cret",
        "security-ops",
        "127.0.0.1",
        "untrusted_peer",
        "proxy",
        "traceback",
    ):
        assert leaked not in body, leaked
    assert response.json()["error"]["type"] == "authentication_error"


async def test_no_www_authenticate_header_is_sent(enforcing_client):
    """`WWW-Authenticate` would make the browser pop its own credential dialog,
    which is not where this deployment's credentials live — and training
    operators to type them into an unexpected box is its own vulnerability."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        response = await client.get(PROTECTED)
    assert "www-authenticate" not in {k.lower() for k in response.headers}


async def test_the_denial_log_never_carries_an_attacker_chosen_value(enforcing_client, capsys):
    """`reason` is a closed enum. Building it from a header value is how a log
    grows records the attacker wrote.

    Read from the real log stream rather than a structlog capture: the point is
    what a deployment's log actually contains, and the emitted line is the only
    thing that proves it.
    """
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        await client.get(PROTECTED, headers={"X-Auth-Request-User": "alice\nevent=admin_login"})

    emitted = capsys.readouterr().out
    denials = [
        record
        for line in emitted.splitlines()
        if line.startswith("{")
        for record in [json.loads(line)]
        if record.get("event") == "operator_auth_denied"
    ]
    assert denials, f"the refusal was not logged at all: {emitted!r}"
    for record in denials:
        assert record["reason"] in {reason.value for reason in DenyReason}
        assert "alice" not in json.dumps(record)


# --- §10: authentication does not make it a control plane -------------------


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
async def test_an_authenticated_operator_still_cannot_mutate(enforcing_client, method):
    """Routing already makes these 405. Enforcing it at the boundary as well
    means a mutating endpoint added later cannot inherit read-only
    authentication without coming through the file where CSRF is documented."""
    async with enforcing_client(peer=TRUSTED_PEER) as client:
        response = await getattr(client, method)(PROTECTED, headers=OPERATOR)
    assert response.status_code == 405


# --- Access classes ---------------------------------------------------------


@pytest.mark.parametrize("path", ["/health", "/ready"])
async def test_probes_stay_reachable_without_a_credential(enforcing_client, path):
    """A readiness probe that needs a credential takes healthy instances out of
    rotation the first time the credential rotates."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        response = await client.get(path)
    assert response.status_code == 200


async def test_metrics_is_not_public_and_not_operator_only(enforcing_client):
    """§4 asked for a decision, and the decision is *both*: a scraper is admitted
    by network, a human by identity, and nothing else is admitted at all."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        anonymous = await client.get("/metrics")
    async with enforcing_client(peer=TRUSTED_PEER) as client:
        operator = await client.get("/metrics", headers=OPERATOR)
    async with enforcing_client(peer=UNTRUSTED_PEER, metrics_networks="203.0.113.0/24") as client:
        scraper = await client.get("/metrics")

    assert anonymous.status_code == 401
    assert operator.status_code == 200
    assert scraper.status_code == 200


async def test_gateway_traffic_is_untouched_by_the_operator_boundary(enforcing_client):
    """Application traffic is a different access class with a different
    authentication story (R-60). This phase must not silently start refusing it."""
    async with enforcing_client(peer=UNTRUSTED_PEER) as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"model": "mock", "messages": [{"role": "user", "content": "hello"}]},
        )
    assert response.status_code != 401


async def test_an_unrecognised_path_is_operator_only_not_public():
    """Deny by default. A route added next week is protected until someone
    classifies it deliberately, which is the direction this mistake should fail
    in — and it also stops the boundary being used to enumerate routes."""
    assert classify_path("/some/route/added/later") is AccessClass.OPERATOR
    assert classify_path("/openapi.json") is AccessClass.OPERATOR
    assert classify_path("/docs") is AccessClass.OPERATOR


# --- Configuration cannot be half-safe --------------------------------------


def test_production_refuses_an_unauthenticated_console():
    settings = Settings(environment="production", console_auth_mode="disabled")
    with pytest.raises(ConfigurationError, match="refused when environment=production"):
        AuthConfig.from_settings(settings)


def test_production_defaults_to_enforcing_without_being_told():
    """The default is derived from the environment rather than written down, so a
    production deployment cannot inherit an open console by forgetting a
    variable."""
    settings = Settings(environment="production", trusted_proxies="10.0.0.5/32")
    assert AuthConfig.from_settings(settings).enforcing


def test_enforcing_without_a_trusted_peer_refuses_to_start():
    settings = Settings(console_auth_mode="proxy")
    with pytest.raises(ConfigurationError, match="FIREWALL_TRUSTED_PROXIES"):
        AuthConfig.from_settings(settings)


@pytest.mark.parametrize("everything", ["0.0.0.0/0", "::/0"])
def test_trusting_the_whole_internet_refuses_to_start(everything: str):
    """A `0.0.0.0/0` trusted range is the configuration that turns this boundary
    into decoration while still reporting `operator_auth_enforced` at startup."""
    settings = Settings(console_auth_mode="proxy", trusted_proxies=everything)
    with pytest.raises(ConfigurationError, match="trusts every host"):
        AuthConfig.from_settings(settings)


def test_a_logout_path_cannot_point_off_origin():
    """`//evil.example` starts with `/` and browsers navigate it off-origin, so
    `startswith("/")` alone is the check people get wrong."""
    for bad in ("//evil.example/x", "https://evil.example", "javascript:alert(1)"):
        with pytest.raises(ValueError, match="same-origin"):
            Settings(console_logout_path=bad)
    assert Settings(console_logout_path="/oauth2/sign_out").console_logout_path


def test_the_shared_secret_never_appears_in_the_startup_summary():
    settings = Settings(proxy_shared_secret="hunter2")
    summary = json.dumps(settings.safe_summary())
    assert "hunter2" not in summary
    assert '"proxy_shared_secret_set": true' in summary


# --- The proxy's half of the contract ---------------------------------------

PROXY_CONF = REPO_ROOT / "deploy" / "docker" / "console-proxy" / "default.conf.template"


def test_the_reference_proxy_overwrites_every_identity_header():
    """`proxy_set_header` replaces the named header, so an inbound copy is
    discarded. That only holds for headers explicitly set — an identity header
    the application reads but the proxy does not set would pass straight through
    from the client. This asserts the two lists agree."""
    conf = PROXY_CONF.read_text(encoding="utf-8")
    defaults = Settings()
    for header in (
        defaults.auth_subject_header,
        defaults.auth_roles_header,
        defaults.proxy_shared_secret_header,
    ):
        assert f"proxy_set_header {header}" in conf, header


def test_the_reference_proxy_authenticates_the_console_and_not_the_probes():
    conf = PROXY_CONF.read_text(encoding="utf-8")
    assert "auth_basic_user_file" in conf
    # The probe locations are declared before the authenticated catch-all and
    # carry no auth_basic directive of their own.
    probes = conf.split("location / {")[0]
    assert "location = /health" in probes and "auth_basic" not in probes


def test_the_reference_proxy_holds_no_committed_credential():
    """The development password is generated at container start from an
    environment variable. A password hash in git is a credential in git, however
    weak, and this repository's pre-commit secret scan exists to prevent that."""
    directory = PROXY_CONF.parent
    assert not list(directory.glob("*.htpasswd"))
    assert not list(REPO_ROOT.glob("**/operators.htpasswd"))
    script = (directory / "generate-htpasswd.sh").read_text(encoding="utf-8")
    assert "DEV_OPERATOR_PASSWORD" in script


def test_the_roles_header_is_only_load_bearing_when_roles_are_configured():
    """Empty `operator_roles` means the proxy's admission decision is the whole
    authorisation decision — correct when the proxy already only admits the
    operations team, and the common deployment."""
    open_config = AuthConfig.from_settings(
        Settings(console_auth_mode="proxy", trusted_proxies="10.0.0.5/32")
    )
    assert open_config._grants_operator({}) is True

    scoped = AuthConfig.from_settings(
        Settings(
            console_auth_mode="proxy", trusted_proxies="10.0.0.5/32", operator_roles="security-ops"
        )
    )
    assert scoped._grants_operator({}) is False
    assert scoped._grants_operator({b"x-auth-request-groups": b"security-ops"}) is True


async def test_a_scraper_is_an_internal_service_not_an_operator(enforcing_client):
    """The two roles exist to keep a Prometheus job out of the operator class,
    not to build an RBAC system."""
    async with enforcing_client(peer=UNTRUSTED_PEER, metrics_networks="203.0.113.0/24") as client:
        metrics = await client.get("/metrics")
        console = await client.get(PROTECTED)
    assert metrics.status_code == 200
    assert console.status_code == 401
    assert Role.INTERNAL_SERVICE.value == "internal_service"
