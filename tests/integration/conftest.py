"""Preflight for the integration suite: the stack under test must be the mock.

The integration tests assert end-to-end behaviour against a **controllable** mock
upstream (ADR-009): no API key, no egress, deterministic responses, and a call
counter that is what proves a blocked request never reached the model.

Nothing enforced that. `compose.yaml` sets the mock as the upstream *and* loads
`.env` via `env_file`, and on Compose 5.5.0 the file wins — so a developer whose
`.env` names a real provider silently redirects the containerised gateway. The
suite then fails with `502 upstream_error` on five assertions that expected 200,
which reads as a broken product rather than a misconfigured environment. That is
the misleading-failure mode this fixture removes.

The check is behavioural rather than a settings comparison: it sends one benign
request and asserts the **mock's own counter moved**. That detects a redirected
upstream however it was redirected — `env_file`, a shell variable, an overlay, or
an image rebuilt with a different default — which a string compare against
configuration would not.
"""

from __future__ import annotations

import os

import httpx
import pytest

GATEWAY = os.environ.get("FIREWALL_BASE_URL", "http://localhost:8005")
MOCK = os.environ.get("FIREWALL_MOCK_URL", "http://localhost:8081")

_BENIGN = {
    "model": "mock-model",
    "messages": [{"role": "user", "content": "What is the capital of France?"}],
}


def _mock_calls() -> int | None:
    try:
        response = httpx.get(f"{MOCK}/__stats", timeout=2.0)
        response.raise_for_status()
        return int(response.json().get("chat_completions", 0))
    except (httpx.HTTPError, ValueError, KeyError):
        return None


@pytest.fixture(scope="session", autouse=True)
def integration_stack_targets_the_mock_upstream() -> None:
    """Refuse to run the suite against anything but the mock upstream.

    Skips when the stack is simply not running — that is the existing contract
    and must stay, so the fast suite remains runnable without Docker.
    """
    before = _mock_calls()
    if before is None:
        pytest.skip("compose stack is not running (mock upstream unreachable)")

    try:
        response = httpx.post(f"{GATEWAY}/v1/chat/completions", json=_BENIGN, timeout=30.0)
    except httpx.HTTPError:
        pytest.skip("compose stack is not running (gateway unreachable)")

    after = _mock_calls()
    if after is not None and after > before:
        return

    # The gateway answered without the mock's counter moving: it is pointed
    # somewhere else. Say so as a configuration fault, and name the fix.
    pytest.fail(
        "Integration preflight failed: the gateway is NOT routing to the mock upstream.\n"
        f"  gateway {GATEWAY} returned HTTP {response.status_code}\n"
        f"  mock {MOCK} chat_completions counter did not move ({before} -> {after})\n"
        "\n"
        "The integration suite must run against the mock upstream: it needs no API key,\n"
        "makes no egress, and its call counter is what proves a blocked request never\n"
        "reached the model.\n"
        "\n"
        "Most likely cause: FIREWALL_UPSTREAM_BASE_URL in your local .env names a real\n"
        "provider. compose.yaml loads .env through env_file, which overrides the mock\n"
        "default it sets. Point it back at the mock and recreate the gateway:\n"
        "\n"
        "  FIREWALL_UPSTREAM_BASE_URL=http://mock-upstream:8081/v1\n"
        "  docker compose up -d firewall-api\n",
        pytrace=False,
    )
