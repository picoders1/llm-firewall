"""Liveness and readiness.

Two endpoints with genuinely different meanings. Conflating them is how a
deployment ends up routing traffic to a process whose detectors have not loaded.

* ``/health`` — is the process alive? No external checks, constant time. A
  failing liveness probe means "restart me".
* ``/ready`` — can it serve *correctly*? Policy loaded and valid, every detector
  warmed up, database reachable when persistence is enabled. A failing readiness
  probe means "take me out of rotation".

``/ready`` returning 503 for a detector that failed to warm up is the same
principle as fail-closed: an instance that cannot inspect should not receive
traffic it would have to either wave through or reject (ADR-007).

Neither endpoint requires authentication, and neither reveals configuration
values — only check names and outcomes.
"""

from __future__ import annotations

from typing import Literal

import structlog
from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from app.core.exceptions import NotImplementedYet

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["operations"])


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str = "llm-firewall"
    version: str


class CheckResult(BaseModel):
    name: str
    passed: bool
    detail: str | None = None


class ReadyResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    checks: list[CheckResult]


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
async def health(request: Request) -> HealthResponse:
    """Process liveness. Deliberately checks nothing external."""
    return HealthResponse(version=request.app.state.version)


@router.get("/ready", response_model=ReadyResponse, summary="Readiness probe")
async def ready(request: Request, response: Response) -> ReadyResponse:
    """Dependency-checked readiness."""
    state = request.app.state
    checks: list[CheckResult] = []

    policy_loaded = getattr(state, "config", None) is not None
    checks.append(
        CheckResult(
            name="policy_loaded",
            passed=policy_loaded,
            detail=state.config.policy_version if policy_loaded else "policy not loaded",
        )
    )

    detectors_ready = bool(getattr(state, "detectors_warmed", False))
    checks.append(
        CheckResult(
            name="detectors_warmed",
            passed=detectors_ready,
            detail=None if detectors_ready else "detector warmup did not complete",
        )
    )

    database = getattr(state, "database", None)
    if database is None:
        # Persistence disabled is a configuration choice, not a failure. It is
        # still reported so the breakdown never hides that auditing is off.
        checks.append(CheckResult(name="database", passed=True, detail="persistence disabled"))
    else:
        reachable = await database.check()
        checks.append(
            CheckResult(
                name="database",
                passed=reachable,
                detail=None if reachable else "database unreachable",
            )
        )

    all_passed = all(check.passed for check in checks)
    if not all_passed:
        response.status_code = 503
        logger.warning(
            "not_ready",
            failed=[check.name for check in checks if not check.passed],
        )

    return ReadyResponse(status="ready" if all_passed else "not_ready", checks=checks)


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """Prometheus exposition.

    Not implemented in this Phase 0 slice: the metric catalogue in
    docs/12-observability.md lands with the request pipeline, and an endpoint
    exposing an empty registry would be a claim of observability that does not
    exist yet.
    """
    raise NotImplementedYet(
        "Metrics are not implemented yet; see docs/19-implementation-roadmap.md (Phase 0)."
    )
