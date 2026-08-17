"""Shared fixtures.

Fixtures build real objects. A test that mocks the policy engine to test the
policy engine tests nothing (docs/16-testing-strategy.md).

The counting upstream is the important one. Asserting that a blocked request
returned 403 does **not** prove the upstream was never called — the gateway could
have forwarded and then blocked on the way back, which would mean the prompt had
already reached the model. `CountingUpstream` makes that invariant directly
observable, which is what docs/16 §17 requires.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from app.config.settings import Settings
from app.gateway.upstream import UpstreamResult
from app.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Run every test against the `testing` environment, not the developer's.

    Any stray FIREWALL_* variable in the shell would otherwise silently change
    what the suite is testing — including the content-logging mode the canary
    test depends on.
    """
    for key in list(os.environ):
        if key.startswith("FIREWALL_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("FIREWALL_ENVIRONMENT", "testing")
    monkeypatch.chdir(REPO_ROOT)
    yield


@pytest.fixture
def policy_path() -> Path:
    return REPO_ROOT / "config" / "policies" / "default.yaml"


@pytest.fixture
def write_policy(tmp_path: Path):
    """Write a policy document to a temp file and return its path."""

    def _write(content: str) -> Path:
        path = tmp_path / "policy.yaml"
        path.write_text(content, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def settings() -> Settings:
    """Fresh Settings for the testing environment, bypassing the module cache."""
    return Settings()


# --- Application fixtures --------------------------------------------------


class CountingUpstream:
    """An in-process upstream that records every call it receives."""

    host = "counting-fake"

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response_text = "Mock completion."
        self.fail_with: Exception | None = None
        self.latency_ms = 1.0
        self.raw_body: dict[str, Any] | None = None

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def last_payload(self) -> dict[str, Any]:
        assert self.calls, "upstream was never called"
        return self.calls[-1]

    async def chat_completions(self, payload: dict[str, Any]) -> UpstreamResult:
        self.calls.append(payload)
        if self.fail_with is not None:
            raise self.fail_with
        body = self.raw_body or {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": payload.get("model", "mock"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": self.response_text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        return UpstreamResult(200, body, self.latency_ms)

    async def aclose(self) -> None:
        return None


class RecordingAudit:
    """Captures audit records so tests can assert on what was persisted."""

    def __init__(self) -> None:
        self.traces: list[Any] = []

    async def record(self, trace: Any) -> None:
        self.traces.append(trace)

    @property
    def last(self) -> Any:
        assert self.traces, "no audit record was written"
        return self.traces[-1]


@pytest.fixture
def app_settings() -> Settings:
    return Settings()


@pytest.fixture
def upstream() -> CountingUpstream:
    return CountingUpstream()


@pytest.fixture
def audit() -> RecordingAudit:
    return RecordingAudit()


@pytest.fixture
async def client(
    app_settings: Settings, upstream: CountingUpstream, audit: RecordingAudit
) -> AsyncIterator[AsyncClient]:
    """A client bound to a fully started app, lifespan included.

    Lifespan matters: it is where detectors are warmed and readiness becomes
    true, so a test that skips it would be testing a different application.
    """
    app = create_app(app_settings)
    app.state.upstream = upstream
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://firewall") as http:
        async with app.router.lifespan_context(app):
            # The lifespan installs the real audit sink; swap in the recorder
            # after startup so assertions can see what would have been written.
            app.state.audit = audit
            yield http


@pytest.fixture
async def cold_client(app_settings: Settings) -> AsyncIterator[AsyncClient]:
    """A client bound to an app whose lifespan has NOT run.

    Used to prove readiness reports the un-warmed state rather than assuming it.
    """
    app = create_app(app_settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://firewall") as http:
        yield http
