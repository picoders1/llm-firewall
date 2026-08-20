"""HTTPS enforcement and the forwarded-proto trust boundary (ADR-026).

The application cannot see its own transport — TLS terminates at the edge — so
the only statement about the client's hop comes from a proxy. That makes
`X-Forwarded-Proto` a security input, and this file exists to prove it is
treated like one: a direct client asserting `https` must convince nobody, and a
deployment that declares HTTPS must refuse the requests it cannot vouch for
rather than serving credentials over plaintext.
"""

from __future__ import annotations

import json

import pytest

from app.auth.transport import Transport, TransportPolicy, client_transport
from app.config.settings import Settings
from app.core.exceptions import ConfigurationError
from app.middleware.transport import INSECURE_MESSAGE
from tests.conftest import CALLER_KEY, CHAT_BODY, TRUSTED_PEER, UNTRUSTED_PEER

pytestmark = pytest.mark.security

CHAT = "/v1/chat/completions"
AUTH = {"authorization": f"Bearer {CALLER_KEY}"}
HTTPS = {"X-Forwarded-Proto": "https"}
TLS_ON = {"https_enforced": True, "trusted_proxies": "127.0.0.1/32"}


# --- §10: a client cannot promote its own connection -------------------------


async def test_a_direct_client_cannot_claim_its_hop_was_https(caller_client, upstream):
    """The attack in one request: an attacker on plaintext asserts `https` and
    expects to be believed. The header is well-formed; the only thing wrong with
    it is that the socket did not come from the trusted proxy."""
    async with caller_client(peer=UNTRUSTED_PEER, **TLS_ON) as client:
        response = await client.post(
            CHAT,
            json=CHAT_BODY,
            headers={**AUTH, **HTTPS, "X-Forwarded-For": "127.0.0.1", "Forwarded": "proto=https"},
        )
    assert response.status_code == 426
    assert upstream.call_count == 0


async def test_the_same_claim_from_the_trusted_proxy_is_honoured(caller_client, upstream):
    """The control test. Identical headers, different peer, opposite outcome —
    which is what makes the refusal above a statement about trust rather than
    about the header never being read."""
    async with caller_client(peer=TRUSTED_PEER, **TLS_ON) as client:
        response = await client.post(CHAT, json=CHAT_BODY, headers={**AUTH, **HTTPS})
    assert response.status_code == 200
    assert upstream.call_count == 1


async def test_a_trusted_proxy_reporting_plaintext_is_refused(caller_client, upstream):
    """The misconfigured-edge case: the proxy is trusted and honestly says the
    client's hop was HTTP. Believing it and serving anyway would make the whole
    setting decorative."""
    async with caller_client(peer=TRUSTED_PEER, **TLS_ON) as client:
        response = await client.post(
            CHAT, json=CHAT_BODY, headers={**AUTH, "X-Forwarded-Proto": "http"}
        )
    assert response.status_code == 426
    assert upstream.call_count == 0


async def test_a_missing_assertion_is_refused_rather_than_assumed_secure(caller_client):
    """Absence is not evidence of TLS.

    This is the uncomfortable direction — an ingress that forgets the header
    takes the deployment down. It is still right: the alternative fails silently
    and only becomes visible in a packet capture, while this one fails at the
    first request in a way that names the problem.
    """
    async with caller_client(peer=TRUSTED_PEER, **TLS_ON) as client:
        response = await client.post(CHAT, json=CHAT_BODY, headers=AUTH)
    assert response.status_code == 426


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("https", Transport.SECURE),
        ("HTTPS", Transport.SECURE),
        (" https ", Transport.SECURE),
        ("https,http", Transport.SECURE),
        ("http,https", Transport.INSECURE),
        ("http", Transport.INSECURE),
        ("ftp", Transport.UNKNOWN),
        ("", Transport.UNKNOWN),
    ],
    ids=["plain", "upper", "padded", "chain-secure", "chain-insecure", "http", "junk", "empty"],
)
def test_the_first_entry_of_a_proxy_chain_is_the_clients_own_hop(header: str, expected):
    """A chain appends, so `https,http` means the *client* spoke HTTPS to the
    outermost proxy. Reading the last entry instead would report the internal
    plaintext hop and refuse every request in a correct deployment."""
    import ipaddress

    scope = {
        "type": "http",
        "client": ("10.0.0.1", 1234),
        "headers": [(b"x-forwarded-proto", header.encode())],
    }
    trusted = (ipaddress.ip_network("10.0.0.1/32"),)
    assert client_transport(scope, trusted) is expected


def test_an_untrusted_peer_short_circuits_before_the_header_is_parsed():
    import ipaddress

    scope = {
        "type": "http",
        "client": ("203.0.113.9", 1234),
        "headers": [(b"x-forwarded-proto", b"https")],
    }
    assert client_transport(scope, (ipaddress.ip_network("10.0.0.1/32"),)) is Transport.UNKNOWN


# --- §9 / §31: HTTP must not bypass any prior control ------------------------


async def test_https_enforcement_does_not_replace_authentication(caller_client, upstream):
    """A secure transport is not a credential. A request that arrives over HTTPS
    with no bearer token is still 401 — the two boundaries compose rather than
    substitute."""
    async with caller_client(peer=TRUSTED_PEER, **TLS_ON) as client:
        response = await client.post(CHAT, json=CHAT_BODY, headers=HTTPS)
    assert response.status_code == 401
    assert upstream.call_count == 0


async def test_authentication_does_not_excuse_an_insecure_transport(caller_client, upstream):
    """And the other direction: a perfectly valid credential over plaintext is
    refused. The credential should never have been on that wire, and accepting
    it would not un-send it."""
    async with caller_client(peer=TRUSTED_PEER, **TLS_ON) as client:
        response = await client.post(
            CHAT, json=CHAT_BODY, headers={**AUTH, "X-Forwarded-Proto": "http"}
        )
    assert response.status_code == 426
    assert upstream.call_count == 0


async def test_the_operator_surface_is_refused_over_plaintext_too(caller_client):
    """Both boundaries sit behind the same transport requirement."""
    async with caller_client(peer=TRUSTED_PEER, console_auth_mode="proxy", **TLS_ON) as client:
        insecure = await client.get(
            "/api/v1/detectors",
            headers={"X-Auth-Request-User": "alice", "X-Forwarded-Proto": "http"},
        )
        secure = await client.get(
            "/api/v1/detectors", headers={"X-Auth-Request-User": "alice", **HTTPS}
        )
    assert insecure.status_code == 426
    assert secure.status_code == 200


@pytest.mark.parametrize("path", ["/health", "/ready"])
async def test_probes_answer_over_plaintext(caller_client, path: str):
    """Exempt deliberately. A deployment whose TLS is misconfigured needs its
    probes to keep answering, or the failure is total instead of legible — and an
    orchestrator that cannot reach `/ready` de-pools a healthy instance."""
    async with caller_client(peer=UNTRUSTED_PEER, **TLS_ON) as client:
        assert (await client.get(path)).status_code == 200


async def test_metrics_are_scrapable_over_the_plaintext_internal_network(caller_client):
    """Also exempt, and this one is a deliberate scope decision rather than an
    oversight.

    The reference edge returns 404 for `/metrics`, so a scraper reaches the pod
    directly across the internal network — which ADR-026 documents as
    intentionally plaintext. Enforcing HTTPS here would refuse every scrape in
    the topology this project actually ships. `/metrics` keeps its own boundary
    (a declared scrape network or an operator identity) and carries no credential
    and no content.
    """
    async with caller_client(peer=UNTRUSTED_PEER, **TLS_ON) as client:
        response = await client.get("/metrics")
    assert response.status_code == 200


# --- What a refusal is allowed to say ----------------------------------------


async def test_the_refusal_leaks_nothing_about_the_deployment(caller_client):
    async with caller_client(peer=UNTRUSTED_PEER, **TLS_ON) as client:
        response = await client.post(CHAT, json=CHAT_BODY, headers=AUTH)

    body = response.json()["error"]
    assert body["message"] == INSECURE_MESSAGE
    assert body["type"] == "insecure_transport"
    assert body["code"] == "https_required"
    assert response.headers["upgrade"].startswith("TLS/")
    for leaked in ("127.0.0.1", "x-forwarded-proto", "trusted", "proxy", CALLER_KEY):
        assert leaked.lower() not in response.text.lower(), leaked


async def test_the_refusal_log_carries_no_address_or_header_value(caller_client, capsys):
    async with caller_client(peer=UNTRUSTED_PEER, **TLS_ON) as client:
        await client.post(CHAT, json=CHAT_BODY, headers={**AUTH, **HTTPS})

    records = [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("{") and "insecure_transport_refused" in line
    ]
    assert records, "the refusal was not logged"
    for record in records:
        assert record["transport"] in {t.value for t in Transport}
        serialised = json.dumps(record)
        assert "127.0.0.1" not in serialised
        assert CALLER_KEY not in serialised


# --- §26 / §30: configuration cannot be half-safe ----------------------------


def test_production_refuses_a_plaintext_deployment():
    settings = Settings(environment="production", https_enforced=False)
    with pytest.raises(ConfigurationError, match="must be true when environment=production"):
        TransportPolicy.from_settings(settings, ())


def test_declaring_https_without_a_trusted_proxy_refuses_to_start():
    """Nothing could ever assert the hop was TLS, so every request would be
    refused — a deployment that is down rather than protected, and better
    discovered at startup than at the first request."""
    settings = Settings(https_enforced=True)
    with pytest.raises(ConfigurationError, match="requires FIREWALL_TRUSTED_PROXIES"):
        TransportPolicy.from_settings(settings, ())


def test_development_stays_plaintext_without_ceremony():
    """`docker compose up` must remain one command (NFR-012)."""
    policy = TransportPolicy.from_settings(Settings(), ())
    assert policy.https_enforced is False


async def test_the_default_development_stack_is_unchanged(client):
    for path in ("/health", "/ready", "/metrics", "/dashboard", "/api/v1/overview"):
        assert (await client.get(path)).status_code == 200, path
    assert (await client.post(CHAT, json=CHAT_BODY)).status_code == 200


async def test_the_metric_reports_whether_https_is_enforced(caller_client):
    async with caller_client(peer=TRUSTED_PEER, **TLS_ON) as client:
        body = (await client.get("/metrics")).text
    assert "firewall_https_enforced 1.0" in body

    async with caller_client() as client:
        body = (await client.get("/metrics")).text
    assert "firewall_https_enforced 0.0" in body
