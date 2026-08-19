"""Security Operations API — shape, bounds, and empty states.

These run without a database, which is the point: a deployment with persistence
disabled is supported, and the API must say so rather than 500 or invent zeros.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.api

ENDPOINTS = (
    "/api/v1/overview",
    "/api/v1/security/events",
    "/api/v1/metrics/latency",
    "/api/v1/metrics/traffic",
    "/api/v1/detectors",
    "/api/v1/policy",
    "/api/v1/system/status",
    "/api/v1/evaluations",
)


@pytest.mark.parametrize("path", ENDPOINTS)
async def test_every_endpoint_answers(client: AsyncClient, path: str):
    assert (await client.get(path)).status_code == 200


# --- Empty and degraded states (§25) ---------------------------------------


async def test_no_requests_means_zero_not_a_plausible_number(client: AsyncClient):
    body = (await client.get("/api/v1/overview")).json()
    assert body["total_requests"] == 0
    assert body["blocked_requests"] == 0
    assert body["decisions_over_time"] == []
    # Without persistence the honest answer is "degraded", not "no traffic".
    assert body["status"] == "degraded"


async def test_no_events_means_an_empty_list(client: AsyncClient):
    body = (await client.get("/api/v1/security/events")).json()
    assert body["items"] == []
    assert body["page"]["total"] == 0
    assert body["page"]["has_more"] is False


async def test_no_observations_means_null_percentiles_not_zero(client: AsyncClient):
    """Zero is a measurement. Null is the absence of one, and they must not be
    confused on a latency dashboard."""
    body = (await client.get("/api/v1/metrics/latency")).json()
    for block in ("gateway_ms", "detector_ms", "upstream_ms"):
        assert body[block]["p50"] is None
        assert body[block]["p99"] is None
        assert body[block]["n"] == 0


async def test_every_percentile_block_carries_its_sample_size(client: AsyncClient):
    body = (await client.get("/api/v1/metrics/latency")).json()
    for block in ("gateway_ms", "detector_ms", "upstream_ms"):
        assert "n" in body[block]


async def test_evaluations_report_what_they_skipped(client: AsyncClient):
    """A run that vanished from the list is indistinguishable from one that never
    happened, so skipped directories are counted out loud."""
    body = (await client.get("/api/v1/evaluations")).json()
    assert body["status"] in {"ok", "empty"}
    if body["note"]:
        assert "no valid final artefact" in body["note"]


async def test_only_finalised_runs_are_reported_as_benchmarks(client: AsyncClient):
    body = (await client.get("/api/v1/evaluations")).json()
    for item in body["items"]:
        assert item["status"] in {"complete", "superseded", "failed", "invalid", "running"}
    # Supersession is derived, so at least the shape must be reachable.
    assert all(item["run_id"] for item in body["items"])


# --- Configuration is reported as configured, not as hoped ------------------


async def test_detector_status_reports_the_transformer_as_disabled_and_warn_only(
    client: AsyncClient,
):
    """§11: exactly as configuration says, with no implication that a warn-only
    model is enforcing."""
    detectors = {d["name"]: d for d in (await client.get("/api/v1/detectors")).json()}
    ml = detectors["injection.transformer"]
    assert ml["enabled"] is False
    assert ml["action"] == "warn"
    assert ml["threshold"] == 0.9955
    assert ml["enforcing"] is False
    assert ml["calibrated"] is True


async def test_the_heuristic_is_reported_as_an_uncalibrated_baseline(client: AsyncClient):
    detectors = {d["name"]: d for d in (await client.get("/api/v1/detectors")).json()}
    heuristic = detectors["injection.heuristic"]
    assert heuristic["enabled"] is True
    assert heuristic["threshold"] == 0.85
    assert heuristic["action"] == "block"
    assert heuristic["calibrated"] is False
    assert heuristic["baseline"] is True
    assert heuristic["enforcing"] is True


async def test_policy_reports_zero_provenance_overlays(client: AsyncClient):
    body = (await client.get("/api/v1/policy")).json()
    assert body["provenance_overlay_count"] == 0
    assert body["policy_version"].startswith("sha256:")
    assert "injection.heuristic" in body["blocking_detectors"]
    assert "injection.transformer" not in body["blocking_detectors"]


async def test_system_status_reports_readiness_and_dependencies(client: AsyncClient):
    body = (await client.get("/api/v1/system/status")).json()
    assert body["ready"] is True
    assert body["detectors_warmed"] is True
    names = {d["name"] for d in body["dependencies"]}
    assert {"database", "upstream"} <= names


# --- Bounds (§18, §16) ------------------------------------------------------


async def test_time_window_is_clamped_and_says_so(client: AsyncClient):
    body = (await client.get("/api/v1/overview?hours=100000")).json()
    assert body["window"]["granted_hours"] == 24 * 30
    assert body["window"]["requested_hours"] == 100000
    assert body["window"]["clamped"] is True


async def test_page_size_is_capped(client: AsyncClient):
    body = (await client.get("/api/v1/security/events?page_size=100000")).json()
    assert body["page"]["page_size"] == 200


async def test_an_unbounded_bucket_request_is_rejected(client: AsyncClient):
    """1-minute buckets over 30 days is 43,200 points. Refused, not truncated."""
    response = await client.get("/api/v1/metrics/traffic?hours=720&interval=1m")
    assert response.status_code == 400
    assert "buckets" in response.json()["error"]["message"]


async def test_an_unknown_interval_is_rejected(client: AsyncClient):
    response = await client.get("/api/v1/metrics/traffic?interval=7s")
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("decision", "obliterate"),
        ("direction", "sideways"),
        ("provenance", "telepathy"),
        ("trust", "absolute"),
        ("severity", "99"),
    ],
)
async def test_invalid_filters_are_rejected_not_ignored(
    client: AsyncClient, field: str, value: str
):
    """Silently ignoring an unknown filter would show unfiltered data under a
    filtered heading."""
    response = await client.get(f"/api/v1/security/events?{field}={value}")
    assert response.status_code == 400


@pytest.mark.parametrize("value", ["allow", "block", "warn", "redact"])
async def test_valid_decision_filters_are_accepted(client: AsyncClient, value: str):
    assert (await client.get(f"/api/v1/security/events?decision={value}")).status_code == 200


async def test_event_detail_404s_for_an_unknown_id(client: AsyncClient):
    response = await client.get("/api/v1/security/events/999999")
    assert response.status_code in {404, 503}


async def test_evaluation_detail_404s_for_an_unknown_run(client: AsyncClient):
    assert (await client.get("/api/v1/evaluations/nope")).status_code == 404


async def test_there_is_no_mutating_endpoint(client: AsyncClient):
    """The dashboard is a window, not a control panel (§12)."""
    for method in ("post", "put", "patch", "delete"):
        response = await getattr(client, method)("/api/v1/policy")
        assert response.status_code in {404, 405}
