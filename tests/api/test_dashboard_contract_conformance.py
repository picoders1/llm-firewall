"""The console reads only fields the API actually returns.

Frontend and backend drift silently: a renamed DTO field shows up as a blank cell
or `undefined` in the browser, not as a failing test. This closes that gap by
checking the field names the JavaScript reads against the live response schemas.

It is deliberately a *presence* check, not a snapshot. Snapshots of API payloads
break on every unrelated change and get regenerated without being read.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.api

REPO_ROOT = Path(__file__).resolve().parents[2]
PAGES = REPO_ROOT / "dashboard" / "js" / "pages"


def fields_read_by(page: str) -> set[str]:
    """Property accesses in a page module, e.g. `row.event_type`."""
    source = (PAGES / page).read_text(encoding="utf-8")
    code = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith(("*", "//", "/*"))
    )
    names = set()
    for match in re.finditer(
        r"\b(?:row|event|run|policy|system|overview|latency|traffic|block|detector|payload|check|dep)\.([a-z_][a-z0-9_]*)\b",
        code,
    ):
        names.add(match.group(1))
    return names


async def keys_of(client: AsyncClient, path: str) -> set[str]:
    response = await client.get(path)
    assert response.status_code == 200, path
    body = response.json()
    if isinstance(body, list):
        return set(body[0]) if body else set()
    return set(body)


async def test_overview_fields_exist(client: AsyncClient):
    available = await keys_of(client, "/api/v1/overview")
    for field in (
        "total_requests",
        "allowed_requests",
        "warned_requests",
        "redacted_requests",
        "blocked_requests",
        "not_evaluated_requests",
        "detector_failures",
        "requests_by_category",
        "requests_by_detector",
        "decisions_over_time",
        "window",
        "status",
    ):
        assert field in available, f"overview page reads {field!r}, API does not return it"


async def test_detector_fields_exist(client: AsyncClient):
    available = await keys_of(client, "/api/v1/detectors")
    for field in (
        "name",
        "category",
        "directions",
        "enabled",
        "action",
        "threshold",
        "timeout_ms",
        "on_error",
        "consumes_provenance",
        "emits_spans",
        "calibrated",
        "baseline",
        "trust_overlays",
        "enforcing",
    ):
        assert field in available, f"detector page reads {field!r}"


async def test_policy_fields_exist(client: AsyncClient):
    available = await keys_of(client, "/api/v1/policy")
    for field in (
        "policy_version",
        "policy_name",
        "detector_count",
        "enabled_detector_count",
        "active_actions",
        "provenance_overlay_count",
        "inspect_roles",
        "blocking_detectors",
        "fail_open_detectors",
    ):
        assert field in available, f"policy view reads {field!r}"


async def test_latency_fields_exist(client: AsyncClient):
    body = (await client.get("/api/v1/metrics/latency")).json()
    for block in ("gateway_ms", "detector_ms", "upstream_ms"):
        assert block in body
        assert set(body[block]) >= {"p50", "p95", "p99", "n"}, block
    assert "by_detector" in body


async def test_traffic_fields_exist(client: AsyncClient):
    body = (await client.get("/api/v1/metrics/traffic")).json()
    assert {"points", "interval", "status", "window"} <= set(body)


async def test_events_page_fields_exist(client: AsyncClient):
    body = (await client.get("/api/v1/security/events")).json()
    assert {"items", "page", "window", "status"} <= set(body)
    assert {"page", "page_size", "total", "has_more"} <= set(body["page"])


async def test_system_fields_exist(client: AsyncClient):
    available = await keys_of(client, "/api/v1/system/status")
    for field in (
        "version",
        "environment",
        "ready",
        "started_at",
        "uptime_seconds",
        "dependencies",
        "detectors_warmed",
    ):
        assert field in available


async def test_evaluation_fields_exist(client: AsyncClient):
    body = (await client.get("/api/v1/evaluations")).json()
    assert {"items", "status"} <= set(body)
    if body["items"]:
        available = set(body["items"][0])
        for field in (
            "run_id",
            "status",
            "detector",
            "dataset",
            "threshold",
            "precision",
            "recall",
            "f1",
            "fpr",
            "fnr",
            "sample_count",
        ):
            assert field in available, f"evaluation page reads {field!r}"


async def test_the_console_never_reads_a_content_field(client: AsyncClient):
    """If a page ever starts reading `row.text` or `row.prompt`, that is a
    contract violation regardless of whether the API would return it."""
    forbidden = {"prompt", "text", "content", "completion", "response_body", "messages", "headers"}
    for page in PAGES.iterdir():
        read = fields_read_by(page.name)
        leaked = read & forbidden
        assert not leaked, f"{page.name} reads content field(s): {leaked}"


async def test_the_header_reads_only_session_fields_the_api_returns(client: AsyncClient):
    """The identity chip lives in the shell rather than a page, so the page scan
    above would never see it drift."""
    available = set((await client.get("/api/v1/session")).json())
    shell = (REPO_ROOT / "dashboard" / "js" / "components" / "shell.js").read_text(encoding="utf-8")
    for field in re.findall(r"\bsession\.([a-z_][a-z0-9_]*)\b", shell):
        assert field in available, (
            f"the header reads session.{field}, which the API does not return"
        )
    # And the fields it must read are actually there, so this is not vacuous.
    assert {"authenticated", "enforced", "subject", "logout_path"} <= available
