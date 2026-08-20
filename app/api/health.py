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

from app.api import readiness
from app.database.migrations import expected_schema_revision

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["operations"])


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str = "llm-firewall"
    version: str


class CheckResult(BaseModel):
    """One readiness check.

    `category` and `requirement` were added in Phase 13 and the existing fields
    were deliberately left alone: the operator console renders this list, and a
    reshaped payload would have broken it for no benefit. Additive is a stable
    contract; the brief's illustrative object-keyed shape is not worth an
    incompatibility (ADR-027).
    """

    name: str
    passed: bool
    detail: str | None = None
    category: Literal["configuration", "security_boundary", "detectors", "database"] = (
        "configuration"
    )
    # `advisory` failures are reported and do NOT take the instance out of
    # rotation. Which checks are which is the substance of ADR-027.
    requirement: Literal["required", "advisory"] = "required"


class ReadyResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    checks: list[CheckResult]


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
async def health(request: Request) -> HealthResponse:
    """Process liveness. Deliberately checks nothing external."""
    return HealthResponse(version=request.app.state.version)


@router.get("/ready", response_model=ReadyResponse, summary="Readiness probe")
async def ready(request: Request, response: Response) -> ReadyResponse:
    """Can this instance safely serve traffic through its configured boundary?

    Narrower than "is everything healthy" and wider than "did the process
    start". Only `required` checks decide the status code; `advisory` ones are
    reported so an operator can see a degradation without a dependency blip
    emptying the fleet (ADR-027).
    """
    state = request.app.state
    checks = readiness.evaluate(state)

    database = getattr(state, "database", None)
    if database is None:
        checks.extend(
            readiness.database_checks(
                configured=False, reachable=False, revision=None, expected=None, required=False
            )
        )
    else:
        probe = await database.readiness()
        settings = state.config.settings
        checks.extend(
            readiness.database_checks(
                configured=True,
                reachable=probe.reachable,
                revision=probe.revision,
                expected=expected_schema_revision(),
                required=settings.require_audit,
            )
        )

    all_passed = readiness.is_ready(checks)
    if not all_passed:
        response.status_code = 503
        logger.warning(
            "not_ready",
            failed=[c.name for c in checks if not c.passed and c.requirement == "required"],
        )
    degraded = [c.name for c in checks if not c.passed and c.requirement == "advisory"]
    if degraded:
        # Logged even while ready: an advisory failure is a real finding that
        # nothing else would surface, and it must not be silent just because it
        # is not fatal.
        logger.warning("ready_with_advisories", advisories=degraded)

    return ReadyResponse(
        status="ready" if all_passed else "not_ready",
        checks=[
            CheckResult(
                name=c.name,
                passed=c.passed,
                detail=c.detail,
                category=c.category.value,
                requirement=c.requirement.value,
            )
            for c in checks
        ],
    )


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    """Prometheus exposition of the catalogue in docs/12-observability.md.

    Unauthenticated by design and safe to scrape internally: every label value is
    a route template, an enum, a registry detector name, an exception class name
    or an HTTP status class. No label is derived from user content, and the
    cardinality of the open-ended ones is bounded in code rather than assumed
    (`app.observability.metrics.bounded_label`).

    A freshly started process legitimately exposes counters at zero. That is an
    empty state, not a broken one.
    """
    body, content_type = request.app.state.metrics.render()
    return Response(content=body, media_type=content_type)
