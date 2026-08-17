"""Integration tests against the running Compose stack.

    docker compose up -d --build
    uv run pytest -m integration

Skipped (not failed) when the stack is not up: the fast suite must stay runnable
without Docker, but a silently-skipped integration suite in CI would be worse
than none, so CI starts the stack explicitly (docs/18-ci-cd-strategy.md).
"""

from __future__ import annotations

import subprocess

import httpx
import pytest

pytestmark = pytest.mark.integration

BASE_URL = "http://localhost:8000"
SERVICE = "firewall-api"


def stack_is_up() -> bool:
    try:
        httpx.get(f"{BASE_URL}/health", timeout=2.0)
    except httpx.HTTPError:
        return False
    return True


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not stack_is_up(), reason="compose stack is not running"),
]


def compose_exec(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["docker", "compose", "exec", "-T", SERVICE, *args],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


# --- Endpoints -------------------------------------------------------------


def test_health_is_reachable():
    response = httpx.get(f"{BASE_URL}/health", timeout=5.0)

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_ready_reports_all_checks_passing():
    response = httpx.get(f"{BASE_URL}/ready", timeout=5.0)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert all(check["passed"] for check in body["checks"])


def test_chat_completions_is_live_and_inspecting():
    """The slice is implemented; end-to-end behaviour lives in
    tests/integration/test_end_to_end.py."""
    response = httpx.post(
        f"{BASE_URL}/v1/chat/completions",
        json={"model": "m", "messages": [{"role": "user", "content": "hi"}]},
        timeout=15.0,
    )

    assert response.status_code == 200
    assert response.headers["x-firewall-decision"] == "allow"


def test_security_headers_survive_the_real_server():
    headers = httpx.get(f"{BASE_URL}/health", timeout=5.0).headers

    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"
    assert headers["x-request-id"]


# --- Container posture (docs/10-security-model.md) -------------------------


def test_container_runs_as_non_root():
    result = compose_exec("id", "-u")

    assert result.returncode == 0
    assert result.stdout.strip() == "10001"


def test_root_filesystem_is_read_only():
    result = compose_exec("sh", "-c", "touch /app/should-not-be-writable")

    assert result.returncode != 0
    assert "read-only" in (result.stderr + result.stdout).lower()


def test_image_contains_no_secrets_tests_or_build_tools():
    result = compose_exec(
        "sh",
        "-c",
        "ls /app/.env 2>&1; ls /app/tests 2>&1; command -v gcc uv 2>&1; true",
    )
    output = result.stdout + result.stderr

    assert "/app/.env" not in output.replace("cannot access '/app/.env'", "")
    assert "No such file" in output
    assert "/usr/bin/gcc" not in output
    assert "/usr/local/bin/uv" not in output


def test_alembic_is_available_for_migrations():
    """The migration mechanism must exist in the runtime image, not just in dev."""
    result = compose_exec("alembic", "--help")

    assert result.returncode == 0
    assert "usage" in result.stdout.lower()


# --- Logging (docs/10-security-model.md) -----------------------------------


def test_startup_log_is_structured_and_masks_secrets():
    logs = subprocess.run(  # noqa: S603
        ["docker", "compose", "logs", SERVICE],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    ).stdout

    assert '"event": "startup"' in logs
    assert "firewall:firewall@" not in logs, "database credential leaked into logs"
