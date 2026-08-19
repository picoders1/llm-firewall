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
from datetime import UTC, datetime
from importlib import metadata

import structlog
from fastapi import FastAPI

from app.api import dashboard_static, health
from app.api.dashboard import router as dashboard_router
from app.api.errors import register_exception_handlers
from app.api.v1 import chat
from app.auth.caller import CallerAuthConfig
from app.auth.identity import AuthConfig
from app.auth.ratelimit import CallerLimiter
from app.config.loader import AppConfig, load_config
from app.config.settings import Settings
from app.core.types import Direction
from app.database.repository import NullAuditRepository, PostgresAuditRepository
from app.database.session import Database
from app.detectors import registry
from app.detectors.pipeline import DetectorPipeline
from app.gateway.upstream import HttpUpstreamClient
from app.middleware.auth import OperatorAuthMiddleware
from app.middleware.body_limit import BodyLimitMiddleware
from app.middleware.caller_auth import CallerAuthMiddleware
from app.middleware.request_id import RequestIdMiddleware, SecurityHeadersMiddleware
from app.observability.logging import configure_logging
from app.observability.metrics import Metrics

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

    # Same principle as the fail-open warning below: a security property that is
    # off must be visible in the startup log, not discoverable only by trying it.
    caller: CallerAuthConfig = app.state.caller_auth
    if caller.enforcing:
        logger.info(
            "caller_auth_enforced",
            mode=caller.mode.value,
            callers=list(caller.caller_ids),
            rate_limit_per_minute=caller.rate_limit_per_minute or "unlimited",
            max_concurrent_requests=caller.max_concurrent_requests or "unlimited",
        )
    else:
        logger.warning(
            "caller_auth_disabled",
            note=(
                "/v1 is unauthenticated and this process holds the upstream credential; "
                "this mode is refused when FIREWALL_ENVIRONMENT=production"
            ),
        )

    auth: AuthConfig = app.state.auth
    if auth.enforcing:
        logger.info(
            "operator_auth_enforced",
            trusted_proxies=[str(net) for net in auth.trusted_proxies],
            proxy_shared_secret=auth.shared_secret is not None,
            operator_roles=sorted(auth.operator_roles) or "any authenticated subject",
            metrics_networks=[str(net) for net in auth.metrics_networks] or "operator only",
        )
    else:
        logger.warning(
            "operator_auth_disabled",
            note=(
                "the security console and its APIs are unauthenticated; "
                "this mode is refused when FIREWALL_ENVIRONMENT=production"
            ),
        )

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

    # Resolved and validated before the app exists, for the same reason as the
    # policy: a boundary that is misconfigured must stop the process, not be
    # discovered by the first anonymous request that gets through (ADR-023).
    auth = AuthConfig.from_settings(config.settings)
    caller_auth = CallerAuthConfig.from_settings(config.settings)
    caller_limiter = CallerLimiter(
        per_minute=caller_auth.rate_limit_per_minute,
        max_concurrent=caller_auth.max_concurrent_requests,
    )

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
    app.state.auth = auth
    app.state.caller_auth = caller_auth
    app.state.caller_limiter = caller_limiter
    app.state.version = _version()
    # One registry per application so tests get isolation instead of a
    # process-global that leaks counts between cases.
    app.state.metrics = Metrics()
    app.state.started_at = datetime.now(UTC)
    app.state.detectors_warmed = False
    app.state.database = None
    app.state.audit = NullAuditRepository()

    # Starlette applies middleware in reverse registration order, so the LAST
    # registered is outermost. Request-id must be outermost so that even a
    # rejected oversized body is correlated and auditable.
    #
    # The auth boundary is registered first, so it ends up INNERMOST of these
    # four: a 401 is a response like any other and must still carry a request ID
    # and the standard security headers. It is still outside the router, so no
    # handler or query runs for a request that will be refused.
    # Caller auth is innermost of the boundaries but still outside the router, so
    # an unauthorised /v1 request is refused before normalisation and detector
    # inference — the transformer costs ~95 ms of CPU per call, which is not a
    # bill an anonymous client should be able to run up (ADR-024 §14).
    app.add_middleware(CallerAuthMiddleware, config=caller_auth, limiter=caller_limiter)
    app.add_middleware(OperatorAuthMiddleware, config=auth)
    app.add_middleware(SecurityHeadersMiddleware, hsts=config.settings.https_enforced)
    app.add_middleware(BodyLimitMiddleware, max_bytes=config.settings.max_request_bytes)
    app.add_middleware(RequestIdMiddleware)

    register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(chat.router)
    # Read-only Security Operations API (Phase 5). No endpoint mutates
    # policy or data; see docs/dashboard-api-contract.md.
    app.include_router(dashboard_router.router)
    # Static console, same-origin so no CORS surface exists (ADR-022).
    app.include_router(dashboard_static.router)

    return app


app = create_app()
