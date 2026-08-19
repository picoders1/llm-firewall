"""Security Operations API — the contract the future dashboard consumes.

Read-only. There is no endpoint here that mutates policy, thresholds, detectors or
data; the dashboard is a window, not a control panel. Runtime policy mutation is
deliberately absent (§12 of the Phase 5 brief) because a policy that can change
without a reviewed deployment is a policy nobody can audit.

**Real data only.** Every number is read from the audit tables or from committed
evaluation artefacts. Where there is nothing to report, these endpoints say so —
zero counts, empty lists, null percentiles and an explicit `status` of `empty` or
`degraded`. Nothing here invents a plausible-looking default, and the absence of a
database is reported as `degraded` rather than dressed up as zero traffic.

Exposure: every route here is in the **operator** access class
([ADR-023](../../../docs/adr/ADR-023-operator-authentication.md)). Identity is
terminated at a reverse proxy or ingress and enforced by
`app/middleware/auth.py` before any handler runs, so no route in this module
performs its own authentication check — a per-route check is one someone forgets
to add. In development the boundary is off and these endpoints are open, which is
why that mode is refused when `FIREWALL_ENVIRONMENT=production`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app.api.dashboard import evaluations as evaluation_store
from app.api.dashboard.queries import (
    DEFAULT_PAGE_SIZE,
    EventFilters,
    FilterRejected,
    counts_by_category_query,
    counts_by_detector_query,
    decisions_over_time_query,
    detector_failures_over_time_query,
    detector_failures_query,
    event_detail_query,
    events_count_query,
    events_query,
    latency_by_detector_query,
    latency_query,
    overview_totals_query,
    resolve_interval,
    resolve_page,
    resolve_window,
    traffic_query,
    upstream_failures_query,
)
from app.api.dashboard.schemas import (
    CountByKey,
    DecisionPoint,
    DependencyStatus,
    DetectorStatus,
    EvaluationDetail,
    EvaluationList,
    LatencyMetrics,
    OverviewMetrics,
    Page,
    Percentiles,
    PolicyStatus,
    SecurityEventDetail,
    SecurityEventPage,
    SecurityEventSummary,
    SessionStatus,
    SystemStatus,
    TrafficMetrics,
    TrafficPoint,
    Window,
)
from app.core.types import Direction

router = APIRouter(prefix="/api/v1", tags=["security-operations"])


def _window_dto(resolved: Any) -> Window:
    return Window(
        start=resolved.start,
        end=resolved.end,
        requested_hours=resolved.requested_hours,
        granted_hours=resolved.granted_hours,
        clamped=resolved.clamped,
    )


def _database(request: Request) -> Any | None:
    """None when persistence is not configured. That is a supported deployment,
    not an error — it must surface as `degraded`, never as a 500."""
    return getattr(request.app.state, "database", None)


def _num(value: Any) -> float | None:
    return None if value is None else float(value)


def _int(value: Any) -> int:
    return 0 if value is None else int(value)


# --- Security events --------------------------------------------------------


@router.get("/security/events", response_model=SecurityEventPage, summary="Query security events")
async def security_events(
    request: Request,
    hours: float | None = Query(None, description="Window size; clamped to 30 days"),
    page: int = Query(1, ge=1),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1),
    decision: str | None = None,
    category: str | None = None,
    detector: str | None = None,
    direction: str | None = None,
    severity: int | None = None,
    provenance: str | None = None,
    trust: str | None = None,
    request_id: str | None = None,
) -> SecurityEventPage:
    window = resolve_window(hours)
    try:
        filters = EventFilters(
            decision=decision,
            category=category,
            detector=detector,
            direction=direction,
            severity=severity,
            provenance=provenance,
            trust=trust,
            request_id=request_id,
        ).validated()
    except FilterRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    page_no, size = resolve_page(page, page_size)
    database = _database(request)
    if database is None:
        return SecurityEventPage(
            items=[],
            page=Page(page=page_no, page_size=size, total=0, has_more=False),
            window=_window_dto(window),
            status="degraded",
        )

    async with database.session() as session:
        total = _int((await session.execute(events_count_query(window, filters))).scalar())
        rows = (
            (
                await session.execute(
                    events_query(window, filters).offset((page_no - 1) * size).limit(size)
                )
            )
            .scalars()
            .all()
        )

    items = [
        SecurityEventSummary(
            event_id=row.id,
            request_id=row.request_id,
            timestamp=row.created_at,
            event_type=row.event_type,
            direction=row.direction,
            category=row.category,
            detector=row.detector,
            score=_num(row.score),
            severity=row.severity,
            provenance=row.provenance,
            trust=row.trust,
            content_hash=row.content_hash,
            content_length=row.content_length,
        )
        for row in rows
    ]
    return SecurityEventPage(
        items=items,
        page=Page(
            page=page_no,
            page_size=size,
            total=total,
            has_more=page_no * size < total,
        ),
        window=_window_dto(window),
        status="ok" if items else "empty",
    )


@router.get(
    "/security/events/{event_id}",
    response_model=SecurityEventDetail,
    summary="One security event, with its request context",
)
async def security_event_detail(request: Request, event_id: int) -> SecurityEventDetail:
    database = _database(request)
    if database is None:
        raise HTTPException(status_code=503, detail="Audit persistence is not configured")
    async with database.session() as session:
        row = (await session.execute(event_detail_query(event_id))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="event not found")

    event, trace = row
    return SecurityEventDetail(
        event_id=event.id,
        request_id=event.request_id,
        timestamp=event.created_at,
        event_type=event.event_type,
        direction=event.direction,
        category=event.category,
        detector=event.detector,
        score=_num(event.score),
        severity=event.severity,
        provenance=event.provenance,
        trust=event.trust,
        content_hash=event.content_hash,
        content_length=event.content_length,
        details=dict(event.details or {}),
        # Null throughout when the trace has aged out under retention. Null means
        # "not recorded", never zero.
        policy_version=trace.policy_version if trace else None,
        http_status=trace.status_code if trace else None,
        decision=trace.decision if trace else None,
        gateway_latency_ms=_num(trace.gateway_latency_ms) if trace else None,
        detector_latency_ms=_num(trace.detector_latency_ms) if trace else None,
        upstream_latency_ms=_num(trace.upstream_latency_ms) if trace else None,
        upstream_called=trace.upstream_called if trace else None,
    )


# --- Overview ---------------------------------------------------------------


@router.get("/overview", response_model=OverviewMetrics, summary="Dashboard summary")
async def overview(
    request: Request,
    hours: float | None = Query(None),
    interval: str | None = Query(None, description="1m | 5m | 1h"),
) -> OverviewMetrics:
    window = resolve_window(hours)
    try:
        bucket = resolve_interval(interval, window)
    except FilterRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    database = _database(request)
    if database is None:
        return OverviewMetrics(window=_window_dto(window), status="degraded")

    async with database.session() as session:
        totals = (await session.execute(overview_totals_query(window))).first()
        detector_failures = _int((await session.execute(detector_failures_query(window))).scalar())
        upstream_failures = _int((await session.execute(upstream_failures_query(window))).scalar())
        categories = (await session.execute(counts_by_category_query(window))).all()
        detectors = (await session.execute(counts_by_detector_query(window))).all()
        series = (await session.execute(decisions_over_time_query(window, bucket))).all()

    total = _int(totals.total if totals else 0)
    return OverviewMetrics(
        window=_window_dto(window),
        status="ok" if total else "empty",
        total_requests=total,
        allowed_requests=_int(totals.allowed if totals else 0),
        warned_requests=_int(totals.warned if totals else 0),
        redacted_requests=_int(totals.redacted if totals else 0),
        blocked_requests=_int(totals.blocked if totals else 0),
        not_evaluated_requests=_int(totals.not_evaluated if totals else 0),
        detector_failures=detector_failures,
        upstream_failures=upstream_failures,
        requests_by_category=[
            CountByKey(key=row[0] or "uncategorised", count=_int(row[1])) for row in categories
        ],
        requests_by_detector=[CountByKey(key=row[0], count=_int(row[1])) for row in detectors],
        decisions_over_time=[
            DecisionPoint(
                bucket=row.bucket,
                allowed=_int(row.allowed),
                warned=_int(row.warned),
                redacted=_int(row.redacted),
                blocked=_int(row.blocked),
                not_evaluated=_int(row.not_evaluated),
            )
            for row in series
        ],
    )


# --- Latency ----------------------------------------------------------------


@router.get("/metrics/latency", response_model=LatencyMetrics, summary="Latency percentiles")
async def latency(request: Request, hours: float | None = Query(None)) -> LatencyMetrics:
    window = resolve_window(hours)
    database = _database(request)
    empty = Percentiles()
    if database is None:
        return LatencyMetrics(
            window=_window_dto(window),
            status="degraded",
            gateway_ms=empty,
            detector_ms=empty,
            upstream_ms=empty,
            note="Audit persistence is not configured; no observations exist to summarise.",
        )

    async with database.session() as session:
        row = (await session.execute(latency_query(window))).first()
        per_detector = (await session.execute(latency_by_detector_query(window))).all()

    def block(prefix: str) -> Percentiles:
        if row is None:
            return Percentiles()
        count = _int(getattr(row, f"{prefix}_n"))
        if count == 0:
            # No observation, so no percentile. Not zero — zero is a measurement.
            return Percentiles(n=0)
        return Percentiles(
            p50=_num(getattr(row, f"{prefix}_p50")),
            p95=_num(getattr(row, f"{prefix}_p95")),
            p99=_num(getattr(row, f"{prefix}_p99")),
            n=count,
        )

    gateway = block("gateway")
    return LatencyMetrics(
        window=_window_dto(window),
        status="ok" if gateway.n else "empty",
        gateway_ms=gateway,
        detector_ms=block("detector"),
        upstream_ms=block("upstream"),
        by_detector={
            entry.detector: Percentiles(
                p50=_num(entry.p50), p95=_num(entry.p95), p99=_num(entry.p99), n=_int(entry.n)
            )
            for entry in per_detector
        },
    )


# --- Traffic ----------------------------------------------------------------


@router.get("/metrics/traffic", response_model=TrafficMetrics, summary="Traffic time-series")
async def traffic(
    request: Request,
    hours: float | None = Query(None),
    interval: str | None = Query(None, description="1m | 5m | 1h"),
) -> TrafficMetrics:
    window = resolve_window(hours)
    try:
        bucket = resolve_interval(interval, window)
    except FilterRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    database = _database(request)
    if database is None:
        return TrafficMetrics(window=_window_dto(window), status="degraded", interval=bucket)

    async with database.session() as session:
        rows = (await session.execute(traffic_query(window, bucket))).all()
        failures = {
            entry.bucket: _int(entry.detector_failures)
            for entry in (
                await session.execute(detector_failures_over_time_query(window, bucket))
            ).all()
        }

    points = [
        TrafficPoint(
            bucket=row.bucket,
            requests=_int(row.requests),
            success=_int(row.success),
            client_errors=_int(row.client_errors),
            server_errors=_int(row.server_errors),
            upstream_failures=_int(row.upstream_failures),
            detector_failures=failures.get(row.bucket, 0),
        )
        for row in rows
    ]
    totals = TrafficPoint(
        bucket=window.start,
        requests=sum(p.requests for p in points),
        success=sum(p.success for p in points),
        client_errors=sum(p.client_errors for p in points),
        server_errors=sum(p.server_errors for p in points),
        upstream_failures=sum(p.upstream_failures for p in points),
        detector_failures=sum(p.detector_failures for p in points),
    )
    return TrafficMetrics(
        window=_window_dto(window),
        status="ok" if points else "empty",
        interval=bucket,
        points=points,
        totals=totals if points else None,
    )


# --- Configuration ----------------------------------------------------------


@router.get("/detectors", response_model=list[DetectorStatus], summary="Detector configuration")
async def detectors(request: Request) -> list[DetectorStatus]:
    """Configuration exactly as loaded. Nothing here is aspirational."""
    from app.detectors.registry import capabilities

    config = request.app.state.config
    caps = capabilities()
    out: list[DetectorStatus] = []
    seen: set[str] = set()
    for direction in (Direction.INPUT, Direction.OUTPUT):
        section = config.policy.input if direction is Direction.INPUT else config.policy.output
        for entry in section.values():
            if entry.detector in seen:
                continue
            seen.add(entry.detector)
            capability = caps.get(entry.detector)
            # "Calibrated" means the score is a probability from a fitted model,
            # not a rule sum. Saying so is the difference between a baseline and
            # a claim (docs/05-detector-architecture.md).
            calibrated = entry.detector.endswith(".transformer")
            out.append(
                DetectorStatus(
                    name=entry.detector,
                    category=capability.name.split(".")[0] if capability else "unknown",
                    directions=sorted(d.value for d in capability.directions)
                    if capability
                    else [direction.value],
                    enabled=entry.enabled,
                    action=entry.action.value,
                    threshold=float(entry.threshold),
                    timeout_ms=entry.timeout_ms,
                    on_error=entry.on_error.value,
                    consumes_provenance=capability.consumes_provenance if capability else False,
                    emits_spans=capability.emits_spans if capability else False,
                    calibrated=calibrated,
                    baseline=not calibrated,
                    trust_overlays=len(entry.by_trust),
                    # A warn-only detector is not enforcing, however good it looks.
                    enforcing=entry.enabled and entry.action.value in {"block", "redact"},
                )
            )
    return sorted(out, key=lambda d: d.name)


@router.get("/policy", response_model=PolicyStatus, summary="Loaded policy, diagnostic only")
async def policy(request: Request) -> PolicyStatus:
    config = request.app.state.config
    loaded = config.policy
    entries = [*loaded.input.values(), *loaded.output.values()]
    return PolicyStatus(
        policy_version=config.policy_version,
        policy_name=loaded.policy_name,
        generated_at=datetime.now(UTC),
        detector_count=len(entries),
        enabled_detector_count=sum(1 for entry in entries if entry.enabled),
        active_actions=sorted({entry.action.value for entry in entries if entry.enabled}),
        provenance_overlay_count=sum(len(entry.by_trust) for entry in entries),
        inspect_roles=sorted(role.value for role in loaded.inspect_roles),
        blocking_detectors=sorted(
            {entry.detector for entry in entries if entry.enabled and entry.action.value == "block"}
        ),
        fail_open_detectors=sorted(loaded.fail_open_detectors()),
    )


@router.get("/system/status", response_model=SystemStatus, summary="Dashboard-safe system status")
async def system_status(request: Request) -> SystemStatus:
    state = request.app.state
    config = state.config
    database = _database(request)

    dependencies = [
        DependencyStatus(
            name="database",
            status="not_configured" if database is None else "ok",
            detail=None if database is not None else "audit persistence disabled",
        ),
        DependencyStatus(
            name="upstream",
            status="ok" if getattr(state, "upstream", None) is not None else "not_configured",
        ),
    ]
    started_at = getattr(state, "started_at", None)
    return SystemStatus(
        version=state.version,
        environment=config.settings.environment,
        ready=bool(getattr(state, "detectors_warmed", False)),
        started_at=started_at,
        uptime_seconds=(datetime.now(UTC) - started_at).total_seconds() if started_at else None,
        dependencies=dependencies,
        detectors_warmed=bool(getattr(state, "detectors_warmed", False)),
        caller_auth_mode=state.caller_auth.mode.value,
        caller_auth_enforced=state.caller_auth.enforcing,
    )


# --- Evaluations ------------------------------------------------------------


@router.get("/session", response_model=SessionStatus, summary="Authenticated operator, if any")
async def session(request: Request) -> SessionStatus:
    """The console's authenticated state.

    Reachable only through the boundary, so a 401 here is itself the answer
    "not signed in" — which is what lets the console distinguish an expired
    session from a gateway that is down, without a second unprotected endpoint
    existing purely to report auth state.
    """
    auth = request.app.state.auth
    principal = request.scope.get("state", {}).get("principal")
    return SessionStatus(
        authenticated=principal is not None,
        enforced=auth.enforcing,
        subject=principal.subject if principal is not None else None,
        role=principal.role.value if principal is not None and principal.role else None,
        logout_path=auth.logout_path,
    )


@router.get("/evaluations", response_model=EvaluationList, summary="Finalised evaluation runs")
async def list_evaluations() -> EvaluationList:
    items, skipped = evaluation_store.list_evaluations()
    note = (
        f"{skipped} result directories carry no valid final artefact and are not "
        "reported as benchmarks."
        if skipped
        else None
    )
    return EvaluationList(items=items, status="ok" if items else "empty", note=note)


@router.get(
    "/evaluations/{run_id}",
    response_model=EvaluationDetail,
    summary="One evaluation run",
)
async def evaluation_detail(run_id: str) -> EvaluationDetail:
    found = evaluation_store.get_evaluation(run_id)
    if found is None:
        raise HTTPException(status_code=404, detail="evaluation run not found")
    return found
