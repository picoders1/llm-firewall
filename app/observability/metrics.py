"""Prometheus exposition — the catalogue documented in docs/12-observability.md.

Nothing here is invented: every metric, label set and bucket layout comes from
that document, which was written before any of it existed.

## The cardinality rule, enforced rather than assumed

docs/12 says "model names and route templates are bounded sets". Route templates
genuinely are. **Model names are not** — they arrive from the client, and a caller
sending a unique string per request would turn one label into an unbounded memory
leak. `bounded_label` caps the distinct values a label may take and collapses the
rest to `other`, so the assumption is enforced by code instead of trusted.

## The privacy rule

No label is ever derived from user content. Every label value here is one of:
a route template, an enum value from `app.core.types`, a registry detector name,
an exception class name, or an HTTP status class. `tests/security/` asserts that
no metric label can carry prompt text, PII, or a `source_ref`.

The endpoint is unauthenticated and safe to scrape internally; exposure
assumptions are documented in `docs/dashboard-api-contract.md`.
"""

from __future__ import annotations

import threading
from typing import Final

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# docs/12: millisecond-resolution buckets, expressed in seconds because that is
# the Prometheus convention and dashboards assume it.
_MS = (1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)
LATENCY_BUCKETS: Final[tuple[float, ...]] = tuple(ms / 1000 for ms in _MS)
BYTE_BUCKETS: Final[tuple[float, ...]] = (256, 1024, 4096, 16384, 65536, 262144, 1048576)

# Above this many distinct values, a label collapses to `other`. Chosen to be
# comfortably larger than any real deployment's model list while still bounding
# memory if a caller sends junk.
MAX_LABEL_CARDINALITY: Final[int] = 32
OVERFLOW_LABEL: Final[str] = "other"
UNKNOWN_LABEL: Final[str] = "unknown"


class _BoundedLabels:
    """Remembers which values a label has taken and collapses the tail.

    Deliberately never forgets: a value that has been admitted stays admitted, so
    a series cannot appear and disappear across scrapes.
    """

    def __init__(self, limit: int = MAX_LABEL_CARDINALITY) -> None:
        self._limit = limit
        self._seen: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def __call__(self, label: str, value: str | None) -> str:
        if not value:
            return UNKNOWN_LABEL
        cleaned = value.strip()[:64]
        if not cleaned:
            return UNKNOWN_LABEL
        with self._lock:
            seen = self._seen.setdefault(label, set())
            if cleaned in seen:
                return cleaned
            if len(seen) >= self._limit:
                return OVERFLOW_LABEL
            seen.add(cleaned)
            return cleaned

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()


bounded_label = _BoundedLabels()


def status_class(status_code: int) -> str:
    """`2xx`, `4xx`… — bounded by construction, unlike the raw code."""
    return f"{status_code // 100}xx"


class Metrics:
    """The metric catalogue, bound to one registry.

    Instantiated per application so tests get an isolated registry instead of
    mutating a process-global one.
    """

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()

        self.requests_total = Counter(
            "firewall_requests_total",
            "Requests handled by the gateway.",
            ("route", "status", "decision"),
            registry=self.registry,
        )
        self.decisions_total = Counter(
            "firewall_decisions_total",
            "Policy decisions. Block rate by category is the primary false-positive alarm.",
            ("direction", "action", "category"),
            registry=self.registry,
        )
        self.detector_latency_seconds = Histogram(
            "firewall_detector_latency_seconds",
            "Per-detector inspection latency.",
            ("detector", "direction"),
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.detector_errors_total = Counter(
            "firewall_detector_errors_total",
            "Detector failures. Nonzero means protection is degraded now.",
            ("detector", "error_kind"),
            registry=self.registry,
        )
        self.gateway_overhead_seconds = Histogram(
            "firewall_gateway_overhead_seconds",
            "Handler wall-clock excluding upstream time.",
            ("route",),
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.upstream_latency_seconds = Histogram(
            "firewall_upstream_latency_seconds",
            "Upstream call latency, separating a slow firewall from a slow model.",
            ("model", "outcome"),
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.upstream_errors_total = Counter(
            "firewall_upstream_errors_total",
            "Upstream failures by kind.",
            ("kind",),
            registry=self.registry,
        )
        self.audit_write_failures_total = Counter(
            "firewall_audit_write_failures_total",
            "Audit sink failures. The audit trail going quiet is itself an event.",
            registry=self.registry,
        )
        self.request_bytes = Histogram(
            "firewall_request_bytes",
            "Inspected request size.",
            ("route",),
            buckets=BYTE_BUCKETS,
            registry=self.registry,
        )
        self.caller_requests_total = Counter(
            "firewall_caller_requests_total",
            "Authenticated gateway requests, by calling application.",
            ("caller",),
            registry=self.registry,
        )
        self.caller_auth_failures_total = Counter(
            "firewall_caller_auth_failures_total",
            "Refused gateway requests. A sustained rate means a caller's credential "
            "is wrong, rotated, or someone is probing for one.",
            ("reason",),
            registry=self.registry,
        )
        self.rate_limited_requests_total = Counter(
            "firewall_rate_limited_requests_total",
            "Gateway requests refused by the per-caller rate or concurrency ceiling.",
            ("caller", "limit"),
            registry=self.registry,
        )
        self.auth_failure_rate_limited_total = Counter(
            "firewall_auth_failure_rate_limited_total",
            "Requests refused because the client had already failed authentication too often. "
            "Rising means someone is guessing credentials.",
            registry=self.registry,
        )
        self.concurrency_rejections_total = Counter(
            "firewall_concurrency_rejections_total",
            "Requests refused because the process was already at its in-flight ceiling.",
            ("scope",),
            registry=self.registry,
        )
        self.active_requests = Gauge(
            "firewall_active_requests",
            "Requests in flight in this process. A gauge, so it is the current value "
            "and not a rate; compare it against the configured ceiling.",
            registry=self.registry,
        )
        self.audit_events_dropped_total = Counter(
            "firewall_audit_events_dropped_total",
            "Audit records discarded because the write queue was full. Named in "
            "ADR-012 before the queue existed: dropping must be visible in a metric, "
            "because an audit trail that thins out under load without saying so is "
            "worse than one that is honestly absent.",
            registry=self.registry,
        )
        self.audit_rows_deleted_total = Counter(
            "firewall_audit_rows_deleted_total",
            "Audit rows removed by the retention sweep, by table. Counts the rows "
            "the foreign key cascaded as well as the ones deleted directly, "
            "because the child table is four times the volume and a metric that "
            "reported only parents would understate the work by that factor.",
            ("table",),
            registry=self.registry,
        )
        self.retention_sweeps_total = Counter(
            "firewall_retention_sweeps_total",
            "Retention sweeps, by outcome. A sustained `failed` rate means the "
            "audit store is growing without bound and nothing is saying so louder.",
            ("outcome",),
            registry=self.registry,
        )
        self.retention_last_success_timestamp_seconds = Gauge(
            "firewall_retention_last_success_timestamp_seconds",
            "Unix time of the last successful sweep. Alert on its age, not on its "
            "value: retention failing silently is the failure mode that matters.",
            registry=self.registry,
        )
        self.audit_oldest_row_age_seconds = Gauge(
            "firewall_audit_oldest_row_age_seconds",
            "Age of the oldest surviving row, by table. This — not the delete "
            "counter — is what says retention is working: a counter can tick "
            "steadily while the backlog grows. Compare it against the configured "
            "period.",
            ("table",),
            registry=self.registry,
        )
        self.audit_queue_depth = Gauge(
            "firewall_audit_queue_depth",
            "Audit records waiting to be written. Sustained depth means the writer "
            "is not keeping up and records are about to be dropped or the request "
            "path is about to start waiting.",
            registry=self.registry,
        )
        # --- Configuration, exported so an alert never hardcodes a threshold the
        # application owns. A rule that says "older than 30 days" silently becomes
        # wrong the day someone sets FIREWALL_RETENTION_TRACE_DAYS=7; a rule that
        # compares against this gauge cannot (ADR-031).
        self.retention_enabled = Gauge(
            "firewall_retention_enabled",
            "1 when this process deletes audit rows past their retention period. "
            "Alert on a production instance reporting 0: nothing is enforcing the "
            "periods and the store grows without bound (ADR-030, R-84).",
            registry=self.registry,
        )
        self.audit_retention_period_seconds = Gauge(
            "firewall_audit_retention_period_seconds",
            "Configured maximum age per audit table. Exported so the backlog alert "
            "compares the oldest surviving row against the period actually in force "
            "rather than against a number copied into a rule file.",
            ("table",),
            registry=self.registry,
        )
        self.audit_queue_capacity = Gauge(
            "firewall_audit_queue_capacity",
            "Bound on the audit write queue. Reads 0 in `sync` mode, where there "
            "is no queue: the gauge is unlabelled and therefore always exists "
            "(R-106). Queue depth is 0 there too, and 0/0 is NaN, so the "
            "saturation alert stays silent.",
            registry=self.registry,
        )
        self.https_enforced = Gauge(
            "firewall_https_enforced",
            "1 when this process refuses requests whose client hop was not TLS. "
            "Alert on a production instance reporting 0.",
            registry=self.registry,
        )
        self.auth_denials_total = Counter(
            "firewall_auth_denials_total",
            "Refused operator-console requests. A sustained rate is either a "
            "misconfigured proxy or someone probing the boundary.",
            ("access_class", "reason"),
            registry=self.registry,
        )

    # -- recording helpers; every label passes through a bounding function ---

    def record_request(self, *, route: str, status_code: int, decision: str | None) -> None:
        self.requests_total.labels(
            route=bounded_label("route", route),
            status=status_class(status_code),
            decision=decision or "not_evaluated",
        ).inc()

    def record_decision(self, *, direction: str, action: str, category: str | None) -> None:
        self.decisions_total.labels(
            direction=direction,
            action=action,
            category=category or "none",
        ).inc()

    def record_detector(
        self,
        *,
        detector: str,
        direction: str,
        latency_ms: float,
        errored: bool = False,
        error_kind: str | None = None,
    ) -> None:
        self.detector_latency_seconds.labels(
            detector=bounded_label("detector", detector), direction=direction
        ).observe(latency_ms / 1000)
        if errored:
            self.detector_errors_total.labels(
                detector=bounded_label("detector", detector),
                error_kind=bounded_label("error_kind", error_kind),
            ).inc()

    def record_gateway_overhead(self, *, route: str, latency_ms: float) -> None:
        self.gateway_overhead_seconds.labels(route=bounded_label("route", route)).observe(
            latency_ms / 1000
        )

    def record_upstream(self, *, model: str | None, outcome: str, latency_ms: float) -> None:
        self.upstream_latency_seconds.labels(
            model=bounded_label("model", model), outcome=outcome
        ).observe(latency_ms / 1000)

    def record_caller_request(self, *, caller: str) -> None:
        self.caller_requests_total.labels(caller=bounded_label("caller", caller)).inc()

    def record_caller_auth_failure(self, *, reason: str) -> None:
        # `reason` is a `CallerDenyReason`, a closed enum — bounded by its type
        # rather than by the cap. Passed through anyway so a future caller of
        # this method cannot introduce an unbounded label without noticing.
        self.caller_auth_failures_total.labels(reason=bounded_label("deny_reason", reason)).inc()

    def record_audit_dropped(self) -> None:
        self.audit_events_dropped_total.inc()

    def set_audit_queue_depth(self, depth: int) -> None:
        self.audit_queue_depth.set(depth)

    def record_rows_deleted(self, *, table: str, rows: int) -> None:
        """`table` is one of a fixed set defined in `app.database.retention`, not
        a caller-supplied value, so the label cardinality is bounded by the
        schema. Zero is still recorded: a sweep that deleted nothing is
        information, and a counter that only appears when it moves cannot be
        alerted on for absence."""
        self.audit_rows_deleted_total.labels(table=table).inc(rows)

    def record_retention_sweep(self, *, outcome: str) -> None:
        self.retention_sweeps_total.labels(outcome=outcome).inc()

    def set_retention_last_success(self, *, timestamp: float) -> None:
        self.retention_last_success_timestamp_seconds.set(timestamp)

    def set_oldest_audit_row_age(self, *, table: str, age_seconds: float) -> None:
        self.audit_oldest_row_age_seconds.labels(table=table).set(age_seconds)

    def set_retention_enabled(self, enabled: bool) -> None:
        """A configuration fact, like `https_enforced`. Reported by every process
        whether or not it is on, so "nothing is enforcing retention" is a value
        rather than an absent series nobody notices."""
        self.retention_enabled.set(1 if enabled else 0)

    def set_retention_period(self, *, table: str, seconds: float) -> None:
        self.audit_retention_period_seconds.labels(table=table).set(seconds)

    def set_audit_queue_capacity(self, capacity: int) -> None:
        self.audit_queue_capacity.set(capacity)

    def set_https_enforced(self, enforced: bool) -> None:
        """A configuration fact, not a rate. No label: there is nothing to break
        it down by that would not be either constant or unbounded."""
        self.https_enforced.set(1 if enforced else 0)

    def record_auth_failure_throttled(self) -> None:
        """No label at all. The only value worth breaking this down by is the
        client address, which is unbounded by definition and is exactly what §16
        forbids as a label."""
        self.auth_failure_rate_limited_total.inc()

    def record_concurrency_rejection(self, *, scope_name: str) -> None:
        self.concurrency_rejections_total.labels(scope=scope_name).inc()

    def set_active_requests(self, value: int) -> None:
        self.active_requests.set(value)

    def record_rate_limited(self, *, caller: str, limit: str) -> None:
        self.rate_limited_requests_total.labels(
            caller=bounded_label("caller", caller), limit=limit
        ).inc()

    def record_upstream_error(self, *, kind: str) -> None:
        self.upstream_errors_total.labels(kind=bounded_label("error_kind", kind)).inc()

    def record_audit_failure(self) -> None:
        self.audit_write_failures_total.inc()

    def record_request_bytes(self, *, route: str, size: int) -> None:
        self.request_bytes.labels(route=bounded_label("route", route)).observe(size)

    def render(self) -> tuple[bytes, str]:
        # Both halves must come from the same exposition module. Until Phase 17
        # the content type was imported from `prometheus_client.openmetrics` while
        # the body came from `generate_latest`, which emits the Prometheus text
        # format. Prometheus trusts the declared type, parsed the body as
        # OpenMetrics, and rejected every scrape for missing the mandatory `# EOF`
        # terminator — so the entire metric catalogue was unreachable and no alert
        # could ever have fired (R-87).
        return generate_latest(self.registry), CONTENT_TYPE_LATEST


def record_trace(metrics: Metrics, trace: object, *, route: str) -> None:
    """Emit the whole catalogue for one finished request.

    Called from the single place that already knows everything — where the audit
    record is assembled — so metrics and audit cannot drift apart by construction.

    Typed loosely to keep `app.observability` from importing the request-path
    models; the attributes it reads are the documented `RequestTrace` surface.
    """
    decision = getattr(trace, "decision", None)
    metrics.record_request(
        route=route,
        status_code=getattr(trace, "status_code", 0),
        decision=getattr(decision, "value", None),
    )
    metrics.record_gateway_overhead(
        route=route, latency_ms=float(getattr(trace, "gateway_latency_ms", 0.0) or 0.0)
    )
    metrics.record_request_bytes(route=route, size=int(getattr(trace, "input_chars", 0) or 0))

    caller_id = getattr(trace, "caller_id", None)
    if caller_id:
        metrics.record_caller_request(caller=str(caller_id))

    upstream_latency = getattr(trace, "upstream_latency_ms", None)
    if getattr(trace, "upstream_called", False) and upstream_latency is not None:
        status_code = int(getattr(trace, "status_code", 0) or 0)
        metrics.record_upstream(
            model=getattr(trace, "model", None),
            outcome="ok" if status_code < 500 else "error",
            latency_ms=float(upstream_latency),
        )
        if status_code >= 500:
            metrics.record_upstream_error(kind=status_class(status_code))

    for outcome in getattr(trace, "detector_outcomes", ()) or ():
        metrics.record_detector(
            detector=outcome.detector,
            direction=outcome.direction.value,
            latency_ms=float(outcome.latency_ms or 0.0),
            errored=bool(outcome.errored),
            error_kind=outcome.error_kind,
        )

    for event in getattr(trace, "events", ()) or ():
        metrics.record_decision(
            direction=event.direction.value,
            action=event.event_type,
            category=getattr(event.category, "value", None),
        )
