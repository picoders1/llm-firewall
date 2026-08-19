"""Read-side aggregation for the dashboard.

Every query here is **bounded before it reaches the database**: a clamped time
window, a capped page size, a whitelisted bucket interval, and a ceiling on the
number of buckets a single request may produce. An operator cannot ask this API
for a query that scans the whole table.

Filters are SQLAlchemy expressions with bound parameters, never string
interpolation, and every filter value is validated against a closed set before it
is used — so a filter is either a known enum value or a rejected request. There is
no code path that turns caller input into SQL text.

Aggregation happens in PostgreSQL (`percentile_cont`, `date_trunc`, `count`)
rather than by pulling rows into Python, because the interesting windows contain
more rows than a request should ever materialise.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import Select, and_, case, func, select

from app.database.models import DetectorResultRow, RequestTraceRow, SecurityEventRow

# --- Bounds. Documented in docs/dashboard-api-contract.md -------------------

MAX_WINDOW_HOURS: Final[float] = 24 * 30  # 30 days
DEFAULT_WINDOW_HOURS: Final[float] = 24
MIN_WINDOW_HOURS: Final[float] = 1 / 60  # one minute
MAX_PAGE_SIZE: Final[int] = 200
DEFAULT_PAGE_SIZE: Final[int] = 50
# A time-series response is a payload a browser has to render; beyond this it is
# neither useful nor cheap.
MAX_BUCKETS: Final[int] = 1500

INTERVAL_SECONDS: Final[dict[str, int]] = {"1m": 60, "5m": 300, "1h": 3600}

# Closed sets. A filter value outside these is rejected, not sanitised.
DECISIONS: Final[frozenset[str]] = frozenset(
    {"allow", "warn", "redact", "block", "not_evaluated", "detector_failure", "upstream_failure"}
)
DIRECTIONS: Final[frozenset[str]] = frozenset({"input", "output"})
PROVENANCES: Final[frozenset[str]] = frozenset(
    {"system_config", "user_input", "model_output", "tool_result", "external", "unknown"}
)
TRUST_LEVELS: Final[frozenset[str]] = frozenset(
    {"operator", "principal", "derived", "untrusted", "unknown"}
)


class FilterRejected(ValueError):
    """A filter value outside its closed set. Surfaced as 400, never coerced."""


@dataclass(frozen=True)
class ResolvedWindow:
    start: datetime
    end: datetime
    requested_hours: float
    granted_hours: float
    clamped: bool


def resolve_window(hours: float | None, *, now: datetime | None = None) -> ResolvedWindow:
    """Clamp a requested window and report honestly that it was clamped."""
    end = now or datetime.now(UTC)
    requested = DEFAULT_WINDOW_HOURS if hours is None else float(hours)
    granted = max(MIN_WINDOW_HOURS, min(requested, MAX_WINDOW_HOURS))
    return ResolvedWindow(
        start=end - timedelta(hours=granted),
        end=end,
        requested_hours=requested,
        granted_hours=granted,
        clamped=granted != requested,
    )


def resolve_page(page: int | None, page_size: int | None) -> tuple[int, int]:
    return max(1, int(page or 1)), max(1, min(int(page_size or DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE))


def default_interval(window: ResolvedWindow) -> str:
    """Finest whitelisted interval that keeps the window under MAX_BUCKETS.

    Without this, asking for a 30-day overview would be a 400: the default 5m
    bucket produces 8,640 points over that window. Auto-coarsening is only
    applied when the caller expressed no preference — an interval they *named*
    is still rejected if it would explode, because silently returning coarser
    data than requested is its own kind of lie.
    """
    for candidate in ("1m", "5m", "1h"):
        if (window.granted_hours * 3600) / INTERVAL_SECONDS[candidate] <= MAX_BUCKETS:
            return candidate
    return "1h"


def resolve_interval(interval: str | None, window: ResolvedWindow) -> str:
    """Whitelist the interval, then refuse combinations that explode the bucket
    count rather than silently returning thousands of points."""
    chosen = interval or default_interval(window)
    if chosen not in INTERVAL_SECONDS:
        raise FilterRejected(f"interval {chosen!r} is not one of {sorted(INTERVAL_SECONDS)}")
    buckets = (window.granted_hours * 3600) / INTERVAL_SECONDS[chosen]
    if buckets > MAX_BUCKETS:
        raise FilterRejected(
            f"interval {chosen!r} over {window.granted_hours:.2f}h would produce "
            f"{int(buckets)} buckets, above the {MAX_BUCKETS} limit. Use a coarser "
            "interval or a shorter window."
        )
    return chosen


def _validate(value: str | None, allowed: frozenset[str], field: str) -> str | None:
    if value is None:
        return None
    if value not in allowed:
        raise FilterRejected(f"{field} {value!r} is not one of {sorted(allowed)}")
    return value


def _bucket_expr(column: Any, interval: str) -> Any:
    """Bucket a timestamp. `date_trunc` handles the natural units; 5m needs epoch
    arithmetic because PostgreSQL has no five-minute truncation."""
    if interval == "1m":
        return func.date_trunc("minute", column)
    if interval == "1h":
        return func.date_trunc("hour", column)
    seconds = INTERVAL_SECONDS[interval]
    return func.to_timestamp(func.floor(func.extract("epoch", column) / seconds) * seconds)


# --- Security events --------------------------------------------------------


@dataclass(frozen=True)
class EventFilters:
    decision: str | None = None
    category: str | None = None
    detector: str | None = None
    direction: str | None = None
    severity: int | None = None
    provenance: str | None = None
    trust: str | None = None
    request_id: str | None = None

    def validated(self) -> EventFilters:
        _validate(self.decision, DECISIONS, "decision")
        _validate(self.direction, DIRECTIONS, "direction")
        _validate(self.provenance, PROVENANCES, "provenance")
        _validate(self.trust, TRUST_LEVELS, "trust")
        if self.severity is not None and not 0 <= self.severity <= 10:
            raise FilterRejected("severity must be between 0 and 10")
        for field, value in (("detector", self.detector), ("category", self.category)):
            # Not enum-bounded (the registry grows), so bound the shape instead.
            if value is not None and (
                len(value) > 64 or not value.replace(".", "").replace("_", "").isalnum()
            ):
                raise FilterRejected(f"{field} must be a short identifier")
        if self.request_id is not None and len(self.request_id) > 128:
            raise FilterRejected("request_id is too long")
        return self


def events_query(window: ResolvedWindow, filters: EventFilters) -> Select[Any]:
    clauses = [
        SecurityEventRow.created_at >= window.start,
        SecurityEventRow.created_at <= window.end,
    ]
    if filters.decision:
        clauses.append(SecurityEventRow.event_type == filters.decision)
    if filters.category:
        clauses.append(SecurityEventRow.category == filters.category)
    if filters.detector:
        clauses.append(SecurityEventRow.detector == filters.detector)
    if filters.direction:
        clauses.append(SecurityEventRow.direction == filters.direction)
    if filters.severity is not None:
        clauses.append(SecurityEventRow.severity == filters.severity)
    if filters.provenance:
        clauses.append(SecurityEventRow.provenance == filters.provenance)
    if filters.trust:
        clauses.append(SecurityEventRow.trust == filters.trust)
    if filters.request_id:
        clauses.append(SecurityEventRow.request_id == filters.request_id)
    # (created_at DESC, id DESC) — created_at alone is not unique, and an unstable
    # sort makes page 2 silently drop or repeat rows.
    return (
        select(SecurityEventRow)
        .where(and_(*clauses))
        .order_by(SecurityEventRow.created_at.desc(), SecurityEventRow.id.desc())
    )


def events_count_query(window: ResolvedWindow, filters: EventFilters) -> Select[Any]:
    return select(func.count()).select_from(events_query(window, filters).subquery())


def event_detail_query(event_id: int) -> Select[Any]:
    """One event LEFT JOINed to its trace.

    LEFT, not INNER: `security_events` outlives `request_traces` under retention
    (ADR-012), so an inner join would make old events disappear from the API
    rather than show them with null operational fields.
    """
    return (
        select(SecurityEventRow, RequestTraceRow)
        .outerjoin(RequestTraceRow, RequestTraceRow.request_id == SecurityEventRow.request_id)
        .where(SecurityEventRow.id == event_id)
    )


# --- Overview ---------------------------------------------------------------


def overview_totals_query(window: ResolvedWindow) -> Select[Any]:
    in_window = and_(
        RequestTraceRow.created_at >= window.start,
        RequestTraceRow.created_at <= window.end,
    )

    def counted(decision: str) -> Any:
        return func.sum(case((RequestTraceRow.decision == decision, 1), else_=0))

    return select(
        func.count().label("total"),
        counted("allow").label("allowed"),
        counted("warn").label("warned"),
        counted("redact").label("redacted"),
        counted("block").label("blocked"),
        counted("not_evaluated").label("not_evaluated"),
        func.sum(case((RequestTraceRow.status_code >= 500, 1), else_=0)).label("server_errors"),
    ).where(in_window)


def detector_failures_query(window: ResolvedWindow) -> Select[Any]:
    return select(func.count()).where(
        and_(
            DetectorResultRow.created_at >= window.start,
            DetectorResultRow.created_at <= window.end,
            DetectorResultRow.errored.is_(True),
        )
    )


def upstream_failures_query(window: ResolvedWindow) -> Select[Any]:
    """Upstream failure = the model was called and answered with a server error."""
    return select(func.count()).where(
        and_(
            RequestTraceRow.created_at >= window.start,
            RequestTraceRow.created_at <= window.end,
            RequestTraceRow.upstream_called.is_(True),
            RequestTraceRow.status_code >= 500,
        )
    )


def counts_by_category_query(window: ResolvedWindow) -> Select[Any]:
    return (
        select(SecurityEventRow.category, func.count().label("n"))
        .where(
            and_(
                SecurityEventRow.created_at >= window.start,
                SecurityEventRow.created_at <= window.end,
            )
        )
        .group_by(SecurityEventRow.category)
        .order_by(func.count().desc())
        .limit(50)
    )


def counts_by_detector_query(window: ResolvedWindow) -> Select[Any]:
    return (
        select(DetectorResultRow.detector, func.count().label("n"))
        .where(
            and_(
                DetectorResultRow.created_at >= window.start,
                DetectorResultRow.created_at <= window.end,
                DetectorResultRow.detected.is_(True),
            )
        )
        .group_by(DetectorResultRow.detector)
        .order_by(func.count().desc())
        .limit(50)
    )


def decisions_over_time_query(window: ResolvedWindow, interval: str) -> Select[Any]:
    bucket = _bucket_expr(RequestTraceRow.created_at, interval).label("bucket")

    def counted(decision: str) -> Any:
        return func.sum(case((RequestTraceRow.decision == decision, 1), else_=0))

    return (
        select(
            bucket,
            counted("allow").label("allowed"),
            counted("warn").label("warned"),
            counted("redact").label("redacted"),
            counted("block").label("blocked"),
            counted("not_evaluated").label("not_evaluated"),
        )
        .where(
            and_(
                RequestTraceRow.created_at >= window.start,
                RequestTraceRow.created_at <= window.end,
            )
        )
        .group_by(bucket)
        .order_by(bucket)
        .limit(MAX_BUCKETS)
    )


# --- Latency ----------------------------------------------------------------


def _pct(column: Any, quantile: float) -> Any:
    return func.percentile_cont(quantile).within_group(column.asc())


def latency_query(window: ResolvedWindow) -> Select[Any]:
    in_window = and_(
        RequestTraceRow.created_at >= window.start,
        RequestTraceRow.created_at <= window.end,
    )
    return select(
        _pct(RequestTraceRow.gateway_latency_ms, 0.50).label("gateway_p50"),
        _pct(RequestTraceRow.gateway_latency_ms, 0.95).label("gateway_p95"),
        _pct(RequestTraceRow.gateway_latency_ms, 0.99).label("gateway_p99"),
        func.count(RequestTraceRow.gateway_latency_ms).label("gateway_n"),
        _pct(RequestTraceRow.detector_latency_ms, 0.50).label("detector_p50"),
        _pct(RequestTraceRow.detector_latency_ms, 0.95).label("detector_p95"),
        _pct(RequestTraceRow.detector_latency_ms, 0.99).label("detector_p99"),
        func.count(RequestTraceRow.detector_latency_ms).label("detector_n"),
        _pct(RequestTraceRow.upstream_latency_ms, 0.50).label("upstream_p50"),
        _pct(RequestTraceRow.upstream_latency_ms, 0.95).label("upstream_p95"),
        _pct(RequestTraceRow.upstream_latency_ms, 0.99).label("upstream_p99"),
        func.count(RequestTraceRow.upstream_latency_ms).label("upstream_n"),
    ).where(in_window)


def latency_by_detector_query(window: ResolvedWindow) -> Select[Any]:
    return (
        select(
            DetectorResultRow.detector,
            _pct(DetectorResultRow.latency_ms, 0.50).label("p50"),
            _pct(DetectorResultRow.latency_ms, 0.95).label("p95"),
            _pct(DetectorResultRow.latency_ms, 0.99).label("p99"),
            func.count().label("n"),
        )
        .where(
            and_(
                DetectorResultRow.created_at >= window.start,
                DetectorResultRow.created_at <= window.end,
            )
        )
        .group_by(DetectorResultRow.detector)
        .limit(50)
    )


# --- Traffic ----------------------------------------------------------------


def traffic_query(window: ResolvedWindow, interval: str) -> Select[Any]:
    bucket = _bucket_expr(RequestTraceRow.created_at, interval).label("bucket")
    return (
        select(
            bucket,
            func.count().label("requests"),
            func.sum(case((RequestTraceRow.status_code < 400, 1), else_=0)).label("success"),
            func.sum(
                case(
                    (
                        and_(RequestTraceRow.status_code >= 400, RequestTraceRow.status_code < 500),
                        1,
                    ),
                    else_=0,
                )
            ).label("client_errors"),
            func.sum(case((RequestTraceRow.status_code >= 500, 1), else_=0)).label("server_errors"),
            func.sum(
                case(
                    (
                        and_(
                            RequestTraceRow.upstream_called.is_(True),
                            RequestTraceRow.status_code >= 500,
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("upstream_failures"),
        )
        .where(
            and_(
                RequestTraceRow.created_at >= window.start,
                RequestTraceRow.created_at <= window.end,
            )
        )
        .group_by(bucket)
        .order_by(bucket)
        .limit(MAX_BUCKETS)
    )


def detector_failures_over_time_query(window: ResolvedWindow, interval: str) -> Select[Any]:
    bucket = _bucket_expr(DetectorResultRow.created_at, interval).label("bucket")
    return (
        select(bucket, func.count().label("detector_failures"))
        .where(
            and_(
                DetectorResultRow.created_at >= window.start,
                DetectorResultRow.created_at <= window.end,
                DetectorResultRow.errored.is_(True),
            )
        )
        .group_by(bucket)
        .order_by(bucket)
        .limit(MAX_BUCKETS)
    )
