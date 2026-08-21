"""The reference edge, actually executed (ADR-025 §19).

Phase 9 shipped an nginx configuration whose behaviour was *asserted from the
file* — the header list matched, the locations looked right — and
`docs/22-evidence-and-claims.md` recorded honestly that nginx had never been
started in CI. That is the gap this file closes for the gateway edge: every test
here drives a real proxy over a real socket, so a directive that is present but
ineffective fails.

The stack is not started here. Bringing containers up inside a test makes the
test own a build, a health wait and a teardown, and makes a failure ambiguous
between "the proxy is wrong" and "the build broke". Instead the suite skips with
the exact command, and CI runs that command before invoking pytest — so the
coverage claim is either true or the tests visibly skipped.
"""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest

pytestmark = pytest.mark.integration

# Deliberately NOT prefixed `FIREWALL_`: the root conftest strips every
# FIREWALL_* variable so a developer's shell cannot change what the suite tests,
# and a knob named that way would be silently deleted before the test read it.
EDGE = os.environ.get("EDGE_PROXY_URL", "http://localhost:8089")
GATEWAY = os.environ.get("EDGE_GATEWAY_URL", "http://localhost:8005")
CHAT = "/v1/chat/completions"
BODY = {"model": "mock", "messages": [{"role": "user", "content": "What is 2 + 2?"}]}

# Matches compose.edge.yaml: 5 r/s with a burst of 10.
EDGE_RATE_PER_SECOND = 5
EDGE_BURST = 10
# Time for a fully drained bucket to refill, derived from the configured limit
# rather than guessed, plus a margin for the proxy's own timekeeping.
EDGE_REFILL_SECONDS = EDGE_BURST / EDGE_RATE_PER_SECOND + 0.5


def _caller_auth_enforced() -> bool:
    """Whether the stack behind the edge authenticates callers.

    Read from the running gateway rather than assumed, because
    `compose.edge.yaml` deliberately does not configure caller credentials — a
    committed digest would be a credential in git (ADR-024). These tests are
    about what the *edge* is responsible for, so they state the application's
    contribution rather than depending on one configuration of it.
    """
    try:
        body = httpx.get(f"{GATEWAY}/api/v1/system/status", timeout=2.0).json()
        return bool(body["caller_auth_enforced"])
    except (httpx.HTTPError, KeyError, ValueError):
        return False


CALLER_AUTH = _caller_auth_enforced()
# What the application may answer for an unauthenticated /v1 request. The edge
# adds 429 on top of whichever it is.
APP_ANONYMOUS = {401} if CALLER_AUTH else {200}


def _edge_is_up() -> bool:
    try:
        return httpx.get(f"{EDGE}/health", timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _edge_is_up(),
        reason=(
            "edge proxy not running. Start it with:\n"
            "  docker compose -f compose.yaml -f compose.edge.yaml up -d --build"
        ),
    ),
]


@pytest.fixture(autouse=True)
async def _refilled_edge():
    """Let the bucket refill before each test.

    `limit_req` state lives in the proxy and is keyed by this machine's address,
    so every test in this file shares one bucket and they would otherwise be
    order-dependent — the first flood test would starve whatever ran next.

    A *passive* wait, not a polling probe: polling `/v1/` to check whether the
    limit has lifted consumes a token per check, so it competes with the refill
    it is waiting for. The duration is computed from the configured rate and
    burst rather than guessed, so it stays correct if those change.
    """
    await asyncio.sleep(EDGE_REFILL_SECONDS)


@pytest.fixture
async def edge():
    async with httpx.AsyncClient(base_url=EDGE, timeout=10.0) as client:
        yield client


# --- §6: the anonymous flood the application should never see ------------------


async def test_an_anonymous_flood_is_refused_at_the_edge(edge):
    """The property Phase 10 could not provide: requests refused *before* the
    application allocates anything for them.

    Sent sequentially rather than concurrently, because `limit_req` is a rate
    over time and a burst of concurrent connections would also trip `limit_conn`
    — which would make this pass for the wrong reason.
    """
    codes = []
    for _ in range(EDGE_BURST + 15):
        codes.append((await edge.post(CHAT, json=BODY)).status_code)

    assert 429 in codes, f"the edge never rate-limited: {codes}"
    # Whatever got through reached the application and was handled by it — the
    # edge authenticates nobody, so it neither adds nor removes a 401.
    assert set(codes) <= APP_ANONYMOUS | {429}, codes


async def test_the_edge_returns_429_not_nginxs_default_503(edge):
    """nginx's default for `limit_req` is 503, which tells a client the *server*
    is broken rather than that it should slow down. A client's backoff logic
    behaves differently for the two."""
    codes = [(await edge.post(CHAT, json=BODY)).status_code for _ in range(EDGE_BURST + 15)]
    assert 429 in codes
    assert 503 not in codes, codes


async def test_probes_are_never_rate_limited(edge):
    """An orchestrator that cannot reach `/ready` during a burst restarts or
    de-pools the instance, turning a load spike into an outage."""
    for _ in range(EDGE_BURST + 20):
        await edge.post(CHAT, json=BODY)
    assert (await edge.get("/health")).status_code == 200
    assert (await edge.get("/ready")).status_code == 200


# --- §18: the other edge controls ---------------------------------------------


async def test_an_oversized_body_is_refused_by_the_proxy(edge):
    """Refused for the price of a `413` from nginx, without the application
    reading a byte. `client_max_body_size` mirrors the application's own limit —
    which stays in place, because this proxy is not the only supported ingress.
    """
    oversized = {"model": "mock", "messages": [{"role": "user", "content": "x" * 400_000}]}
    response = await edge.post(CHAT, json=oversized)
    assert response.status_code == 413


async def test_the_operator_console_is_not_served_on_the_gateway_edge(edge):
    """The console belongs behind the operator boundary, which is a different
    proxy with a different credential. Returning 404 here stops a deployment
    accidentally publishing the security console on the gateway's address."""
    for path in ("/dashboard", "/api/v1/overview", "/metrics"):
        assert (await edge.get(path)).status_code == 404, path


async def test_the_edge_advertises_nothing_about_itself(edge):
    response = await edge.get("/health")
    assert "nginx/" not in response.headers.get("server", "")


# --- §5 / §12: identity through the edge ---------------------------------------


async def test_a_client_cannot_forge_an_operator_identity_through_the_edge(edge):
    """The edge clears the operator headers rather than relaying them. The
    application would refuse them anyway — the edge's peer address is not in the
    operator boundary's trusted range — so this is the second of two independent
    controls."""
    response = await edge.post(
        CHAT,
        json=BODY,
        headers={
            "X-Auth-Request-User": "attacker",
            "X-Auth-Request-Groups": "operators",
            "X-Firewall-Proxy-Secret": "guess",
            "X-Firewall-Caller": "web-app",
            "X-Forwarded-For": "127.0.0.1",
        },
    )
    # Never 403: a forged operator identity must not become a *recognised* one
    # that is merely unauthorised. It must not be recognised at all.
    assert response.status_code in APP_ANONYMOUS | {429}
    assert response.status_code != 403


async def test_a_valid_caller_credential_still_works_through_the_edge():
    """§15: the edge must not break the contract for allowed traffic.

    Skipped unless a credential is supplied, because the digest is deployment
    configuration and inventing one here would test nothing.
    """
    key = os.environ.get("EDGE_TEST_CALLER_KEY")
    if not key:
        pytest.skip("set EDGE_TEST_CALLER_KEY to exercise the authenticated path")
    async with httpx.AsyncClient(base_url=EDGE, timeout=30.0) as client:
        response = await client.post(CHAT, json=BODY, headers={"authorization": f"Bearer {key}"})
    assert response.status_code == 200
    assert response.json()["object"] == "chat.completion"


# --- The application behind it --------------------------------------------------


async def test_the_edge_is_not_the_only_thing_protecting_the_gateway(edge):
    """The overlay keeps the gateway published on host :8005 for local work; a production deployment
    does not (docs/17 obligation 8). What matters here is that the application's
    own answer is unchanged by the edge's presence — the edge is a layer in front
    of the application's controls, not a replacement for them."""
    async with httpx.AsyncClient(base_url=GATEWAY, timeout=10.0) as direct:
        assert (await direct.get("/health")).status_code == 200
        assert (await direct.post(CHAT, json=BODY)).status_code in APP_ANONYMOUS


async def test_concurrent_connections_are_bounded(edge):
    """`limit_conn` caps simultaneous connections per address. Exceeding it must
    produce a refusal rather than an accepted-and-queued connection, which is
    what turns a connection flood into a memory problem."""
    async with httpx.AsyncClient(
        base_url=EDGE, timeout=10.0, limits=httpx.Limits(max_connections=60)
    ) as client:
        responses = await asyncio.gather(
            *(client.post(CHAT, json=BODY) for _ in range(60)), return_exceptions=True
        )
    codes = {r.status_code for r in responses if isinstance(r, httpx.Response)}
    assert codes, "no request completed"
    assert codes <= APP_ANONYMOUS | {429}, codes
    assert 429 in codes, f"60 simultaneous requests hit no edge limit at all: {codes}"
