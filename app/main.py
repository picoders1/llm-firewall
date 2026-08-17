"""Application factory and lifespan.

Startup order is load-bearing:

    settings → policy → validate policy against the detector registry →
    build detectors → warm them up → database handle → ready

Configuration and policy are validated *before* anything is built, so a bad
policy fails the process at startup rather than surfacing as a runtime surprise
(NFR-009). Detector warm-up gates readiness, so an instance that cannot inspect
never receives traffic (ADR-007).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib import metadata

import structlog
from fastapi import FastAPI

from app.api import health
from app.api.errors import register_exception_handlers
from app.api.v1 import chat
from app.config.loader import AppConfig, load_config
from app.config.settings import Settings
from app.core.types import Direction
from app.database.repository import NullAuditRepository, PostgresAuditRepository
from app.database.session import Database
from app.detectors import registry
from app.detectors.pipeline import DetectorPipeline
from app.gateway.upstream import HttpUpstreamClient
from app.middleware.body_limit import BodyLimitMiddleware
from app.middleware.request_id import RequestIdMiddleware, SecurityHeadersMiddleware
from app.observability.logging import configure_logging

logger = structlog.get_logger(__name__)


def _version() -> str:
    try:
        return metadata.version("llm-firewall")
    except metadata.PackageNotFoundError:  # pragma: no cover - source checkout
        return "0.0.0+unknown"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    config: AppConfig = app.state.config

    logger.info("startup", **config.safe_summary())

    # Fail-open detectors are named at startup so an operator never discovers
    # one while reading YAML during an incident (ADR-007).
    if config.fail_open_detectors:
        logger.warning(
            "fail_open_detectors_configured",
            detectors=list(config.fail_open_detectors),
            note="these detectors will NOT block when they fail",
        )

    pipeline = DetectorPipeline.from_policy(config.policy)
    app.state.pipeline = pipeline
    app.state.detectors_warmed = False

    await pipeline.warmup()
    app.state.detectors_warmed = True
    logger.info(
        "detectors_ready",
        input=list(config.policy.enabled_detectors(Direction.INPUT)),
        output=list(config.policy.enabled_detectors(Direction.OUTPUT)),
    )

    database = Database.from_settings(config.settings)
    app.state.database = database
    app.state.audit = (
        PostgresAuditRepository(database, require_audit=config.settings.require_audit)
        if database is not None
        else NullAuditRepository()
    )

    # Tests may inject a counting fake to assert that blocked requests never
    # reach the upstream; only build the real client when none was supplied.
    owns_upstream = getattr(app.state, "upstream", None) is None
    if owns_upstream:
        app.state.upstream = HttpUpstreamClient(config.settings)

    try:
        yield
    finally:
        await pipeline.aclose()
        if owns_upstream:
            await app.state.upstream.aclose()
        if database is not None:
            await database.aclose()
        logger.info("shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application.

    Accepts explicit settings so tests can construct isolated instances without
    mutating process-wide state.
    """
    config = load_config(settings)
    configure_logging(config.settings)

    # Policy is checked against the detectors that actually exist before the app
    # is constructed. The capability map is passed *in* so app.config never
    # imports app.detectors (docs/02-system-architecture.md).
    config.policy.validate_against_registry(registry.capabilities())

    app = FastAPI(
        title="LLM Firewall",
        version=_version(),
        description=(
            "A security gateway for OpenAI-compatible LLM endpoints. "
            "Phase 0: configuration, policy engine and detector interfaces. "
            "The proxy itself is not implemented yet."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
    )

    app.state.config = config
    app.state.version = _version()
    app.state.detectors_warmed = False
    app.state.database = None
    app.state.audit = NullAuditRepository()

    # Starlette applies middleware in reverse registration order, so the LAST
    # registered is outermost. Request-id must be outermost so that even a
    # rejected oversized body is correlated and auditable.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodyLimitMiddleware, max_bytes=config.settings.max_request_bytes)
    app.add_middleware(RequestIdMiddleware)

    register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(chat.router)

    return app


app = create_app()
