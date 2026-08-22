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

import time
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
from app.auth.admission import AdmissionConfig, AuthFailureThrottle
from app.auth.caller import CallerAuthConfig
from app.auth.identity import AuthConfig
from app.auth.ratelimit import CallerLimiter
from app.auth.transport import TransportPolicy
from app.config.loader import AppConfig, load_config
from app.config.settings import AuditWriteMode, Settings
from app.core.exceptions import ConfigurationError
from app.core.types import Direction
from app.database.migrations import expected_schema_revision
from app.database.repository import (
    NullAuditRepository,
    PostgresAuditRepository,
    QueuedAuditRepository,
)
from app.database.retention import (
    RetentionPolicy,
    RetentionScheduler,
    RetentionSweeper,
)
from app.database.session import Database
from app.detectors import registry
from app.detectors.pipeline import DetectorPipeline
from app.gateway.upstream import HttpUpstreamClient
from app.middleware.admission import AdmissionMiddleware
from app.middleware.auth import OperatorAuthMiddleware
from app.middleware.body_limit import BodyLimitMiddleware
from app.middleware.caller_auth import CallerAuthMiddleware
from app.middleware.request_id import RequestIdMiddleware, SecurityHeadersMiddleware
from app.middleware.transport import HttpsRequiredMiddleware
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
    policy: TransportPolicy = app.state.transport
    if policy.https_enforced:
        logger.info(
            "https_required",
            trusted_proxies=[str(net) for net in policy.trusted_proxies],
            note="requests without a trusted X-Forwarded-Proto: https are refused with 426",
        )
    else:
        logger.warning(
            "https_not_enforced",
            note=(
                "credentials may cross a plaintext hop; this mode is refused when "
                "FIREWALL_ENVIRONMENT=production"
            ),
        )
    app.state.metrics.set_https_enforced(policy.https_enforced)

    admission: AdmissionConfig = app.state.admission
    logger.info(
        "admission_control",
        max_concurrent_requests=admission.max_concurrent_requests or "unlimited",
        auth_failures_per_minute=admission.auth_failures_per_minute or "unlimited",
        note=(
            "in-process safety net only; volumetric abuse is the edge's job "
            "(docs/adr/ADR-025-edge-abuse-protection.md)"
        ),
    )

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

    # Resolved here rather than on the first `/ready`. Alembic's loader prints to
    # stdout when it initialises, and a structured-log deployment should not have
    # that arrive mid-probe; it also keeps the first readiness call off the
    # filesystem. Cached for the process lifetime (ADR-027).
    logger.info("schema_revision_expected", revision=expected_schema_revision() or "unknown")

    database = Database.from_settings(config.settings)
    app.state.database = database
    if database is None:
        app.state.audit = NullAuditRepository()
    else:
        sink = PostgresAuditRepository(
            database,
            require_audit=config.settings.require_audit,
            # Passed in BOTH modes. The queue wraps this same sink, so a write
            # that fails behind the queue is the same failure and has to be
            # counted the same way (R-111).
            metrics=app.state.metrics,
        )
        mode = config.settings.audit_write_mode
        if mode is AuditWriteMode.SYNC:
            app.state.audit = sink
        else:
            # The queue is started here rather than at construction because it
            # needs a running event loop, and `create_app` has none.
            queued = QueuedAuditRepository(
                sink,
                max_size=config.settings.audit_queue_size,
                metrics=app.state.metrics,
            )
            await queued.start()
            app.state.audit = queued
            # Only in the queued modes: in `sync` there is no queue to saturate.
            # Note the gauge still READS 0 there — an unlabelled Prometheus gauge
            # is created with the registry and cannot be absent (R-106). The
            # saturation alert stays silent because depth is 0 too and `0 / 0` is
            # NaN, not because the series is missing.
            app.state.metrics.set_audit_queue_capacity(config.settings.audit_queue_size)
            logger.info(
                "audit_queue_started",
                mode=mode.value,
                queue_size=config.settings.audit_queue_size,
                note=(
                    "audit records are written off the request path; a served request "
                    "may briefly have no row (ADR-029)"
                ),
            )

    # Retention runs off the request path and, like the queue, is opt-in: a
    # deletion job that turns itself on during an upgrade would remove an
    # operator's audit trail because a default moved (ADR-030).
    retention: RetentionScheduler | None = None
    policy_retention = RetentionPolicy.from_settings(config.settings)
    # Reported by every process, on or off, so "nothing is enforcing retention"
    # is a value an alert can match rather than an absent series (ADR-031).
    app.state.metrics.set_retention_enabled(config.settings.retention_enabled)
    for rule in policy_retention.rules:
        app.state.metrics.set_retention_period(table=rule.table, seconds=float(rule.days * 86400))
    if not config.settings.retention_enabled:
        logger.warning(
            "audit_retention_disabled",
            **policy_retention.summary(),
            note=(
                "nothing deletes from the audit store; it grows without bound, "
                "which is a privacy liability as much as a disk one (ADR-012)"
            ),
        )
    elif database is None:
        logger.warning(
            "audit_retention_inactive",
            note="retention is enabled but no audit database is configured; nothing to sweep",
        )
    else:
        sweeper = RetentionSweeper(
            database,
            policy_retention,
            batch_size=config.settings.retention_batch_size,
            max_rows_per_sweep=config.settings.retention_max_rows_per_sweep,
            metrics=app.state.metrics,
        )
        retention = RetentionScheduler(
            sweeper,
            interval_s=config.settings.retention_interval_s,
            metrics=app.state.metrics,
        )
        await retention.start()
        logger.info(
            "audit_retention_started",
            interval_s=config.settings.retention_interval_s,
            batch_size=config.settings.retention_batch_size,
            max_rows_per_sweep=config.settings.retention_max_rows_per_sweep,
            **policy_retention.summary(),
        )
    app.state.retention = retention

    # Tests may inject a counting fake to assert that blocked requests never
    # reach the upstream; only build the real client when none was supplied.
    owns_upstream = getattr(app.state, "upstream", None) is None
    if owns_upstream:
        app.state.upstream = HttpUpstreamClient(config.settings)

    try:
        yield
    finally:
        # Drained BEFORE the database handle closes, or the drain would write into
        # a disposed engine. Bounded, and what it abandons is reported rather than
        # discovered later as a hole in the audit trail.
        # Cancelled before the database closes, and safe to cancel mid-sweep:
        # every batch commits on its own, so what it deleted stays deleted and
        # the remainder waits for the next process.
        if retention is not None:
            await retention.aclose()
        audit = getattr(app.state, "audit", None)
        if isinstance(audit, QueuedAuditRepository):
            abandoned = await audit.aclose(drain_timeout_s=config.settings.audit_drain_timeout_s)
            logger.info("audit_queue_drained", abandoned=abandoned, dropped=audit.dropped)
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
    # A queued writer cannot honour `require_audit`. That setting promises a
    # served request has a row; a queue is precisely the removal of that promise,
    # and a deployment that configured both would believe it had a guarantee it
    # did not have. Refused at startup rather than discovered in an audit
    # (ADR-029).
    if config.settings.require_audit and config.settings.audit_write_mode is not (
        AuditWriteMode.SYNC
    ):
        raise ConfigurationError(
            "require_audit=true cannot be combined with "
            f"audit_write_mode={config.settings.audit_write_mode.value}: a queued writer "
            "returns before the record is written, so a served request may have no audit "
            "row. Use audit_write_mode=sync where the audit trail must be guaranteed "
            "(docs/adr/ADR-029-audit-write-architecture.md)."
        )

    auth = AuthConfig.from_settings(config.settings)
    caller_auth = CallerAuthConfig.from_settings(config.settings)
    caller_limiter = CallerLimiter(
        per_minute=caller_auth.rate_limit_per_minute,
        max_concurrent=caller_auth.max_concurrent_requests,
    )
    # Admission control shares the operator boundary's trusted-proxy list: there
    # is one answer to "may this peer speak for a client", and two copies would
    # drift (ADR-025 §5).
    admission = AdmissionConfig(
        max_concurrent_requests=config.settings.max_concurrent_requests,
        auth_failures_per_minute=config.settings.auth_failures_per_minute,
        trusted_proxies=auth.trusted_proxies,
        client_ip_header=config.settings.client_ip_header,
    )
    auth_throttle = AuthFailureThrottle(admission, clock=time.monotonic)
    # Checked before the app exists, like the policy and both identity
    # boundaries: a deployment that announces HTTPS and cannot verify it, or a
    # production deployment that does not announce it at all, must stop the
    # process rather than serve credentials over plaintext (ADR-026).
    transport = TransportPolicy.from_settings(config.settings, auth.trusted_proxies)

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
    app.state.admission = admission
    app.state.auth_throttle = auth_throttle
    app.state.transport = transport
    app.state.version = _version()
    # One registry per application so tests get isolation instead of a
    # process-global that leaks counts between cases.
    app.state.metrics = Metrics()
    app.state.started_at = datetime.now(UTC)
    app.state.detectors_warmed = False
    app.state.database = None
    app.state.audit = NullAuditRepository()
    app.state.retention = None

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
    app.add_middleware(
        CallerAuthMiddleware,
        config=caller_auth,
        limiter=caller_limiter,
        throttle=auth_throttle,
    )
    app.add_middleware(OperatorAuthMiddleware, config=auth)
    # Inside the security headers so a 426 still carries them, and OUTSIDE both
    # identity boundaries so a plaintext request is refused before any credential
    # in it is read — reading it would not un-send it.
    app.add_middleware(
        HttpsRequiredMiddleware,
        enabled=transport.https_enforced,
        trusted_proxies=transport.trusted_proxies,
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=config.settings.https_enforced)
    app.add_middleware(BodyLimitMiddleware, max_bytes=config.settings.max_request_bytes)
    app.add_middleware(RequestIdMiddleware)
    # OUTERMOST of everything. Admission is the one refusal that must happen
    # before the process spends anything at all — before a correlation id is
    # bound, before a byte of body is read, before either identity boundary
    # runs. Its 503 therefore carries no request id, which is the honest cost of
    # rejecting that early (ADR-025).
    app.add_middleware(AdmissionMiddleware, config=admission)

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
