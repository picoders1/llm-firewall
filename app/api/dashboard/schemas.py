"""Dashboard DTOs — the boundary that makes leakage a compile-time shape error.

No ORM row is ever returned from these endpoints. Every response passes through a
model here, and every model lists its fields explicitly. That is the mechanism:
a column added to the audit schema cannot reach the API by being picked up
automatically, because nothing here iterates over columns.

**What is deliberately absent**, and stays absent: prompt text, completion text,
PII values, headers, credentials, `source_ref`, stack traces, filesystem paths.
The audit schema cannot store the first four (docs/11-data-model.md) — these DTOs
are the second, independent line of defence for everything else.

Sample sizes travel with every aggregate. A percentile without an `n` is a claim
without a denominator, and this project does not publish those.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# A response may be honest about having nothing to say.
DataStatus = Literal["ok", "empty", "degraded"]


class Window(BaseModel):
    """The time range an aggregate actually covers, echoed back.

    Returned because the server clamps what the client asks for; a dashboard that
    renders "last 90 days" over a 30-day answer would be lying on the server's
    behalf.
    """

    model_config = ConfigDict(frozen=True)

    start: datetime
    end: datetime
    requested_hours: float
    granted_hours: float
    clamped: bool


class Page(BaseModel):
    model_config = ConfigDict(frozen=True)

    page: int
    page_size: int
    total: int
    has_more: bool


class SecurityEventSummary(BaseModel):
    """One row of the events table. Metadata only."""

    model_config = ConfigDict(frozen=True)

    event_id: int
    request_id: str
    timestamp: datetime
    event_type: str
    direction: str
    category: str | None
    detector: str | None
    score: float | None
    severity: int
    provenance: str
    trust: str
    # Fingerprint and size — never the content itself.
    content_hash: str | None
    content_length: int | None


class SecurityEventDetail(SecurityEventSummary):
    """One event, joined to its request trace for the operational fields.

    Every added field is null when the trace has been retained away or the event
    predates it. Null means "not recorded"; it never means zero.
    """

    model_config = ConfigDict(frozen=True)

    policy_version: str | None = None
    http_status: int | None = None
    decision: str | None = None
    gateway_latency_ms: float | None = None
    detector_latency_ms: float | None = None
    upstream_latency_ms: float | None = None
    upstream_called: bool | None = None
    # Bounded, label-only: rule ids, entity types and counts, offsets.
    details: dict[str, object] = Field(default_factory=dict)


class SecurityEventPage(BaseModel):
    model_config = ConfigDict(frozen=True)

    items: list[SecurityEventSummary]
    page: Page
    window: Window
    status: DataStatus


class CountByKey(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    count: int


class DecisionPoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    bucket: datetime
    allowed: int = 0
    warned: int = 0
    redacted: int = 0
    blocked: int = 0
    not_evaluated: int = 0


class OverviewMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)

    window: Window
    status: DataStatus
    total_requests: int = 0
    allowed_requests: int = 0
    warned_requests: int = 0
    redacted_requests: int = 0
    blocked_requests: int = 0
    not_evaluated_requests: int = 0
    detector_failures: int = 0
    upstream_failures: int = 0
    requests_by_category: list[CountByKey] = Field(default_factory=list)
    requests_by_detector: list[CountByKey] = Field(default_factory=list)
    decisions_over_time: list[DecisionPoint] = Field(default_factory=list)


class Percentiles(BaseModel):
    """Percentiles are null when no observation supports them.

    `n` is required, not optional: reporting p99 from four samples and reporting
    it from forty thousand are different claims, and the dashboard must be able to
    tell them apart.
    """

    model_config = ConfigDict(frozen=True)

    p50: float | None = None
    p95: float | None = None
    p99: float | None = None
    n: int = 0


class LatencyMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)

    window: Window
    status: DataStatus
    gateway_ms: Percentiles
    detector_ms: Percentiles
    upstream_ms: Percentiles
    by_detector: dict[str, Percentiles] = Field(default_factory=dict)
    note: str | None = None


class TrafficPoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    bucket: datetime
    requests: int = 0
    success: int = 0
    client_errors: int = 0
    server_errors: int = 0
    upstream_failures: int = 0
    detector_failures: int = 0


class TrafficMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)

    window: Window
    status: DataStatus
    interval: str
    points: list[TrafficPoint] = Field(default_factory=list)
    totals: TrafficPoint | None = None


class DetectorStatus(BaseModel):
    """Configuration as it actually is, not as it is hoped to be."""

    model_config = ConfigDict(frozen=True)

    name: str
    category: str
    directions: list[str]
    enabled: bool
    action: str
    threshold: float
    timeout_ms: int
    on_error: str
    consumes_provenance: bool
    emits_spans: bool
    # Whether the score is a calibrated probability. The heuristic's is not, and
    # saying so is the difference between a baseline and a claim.
    calibrated: bool
    baseline: bool
    trust_overlays: int
    # Present so a dashboard cannot imply a warn-only model is enforcing.
    enforcing: bool


class PolicyStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy_version: str
    policy_name: str
    generated_at: datetime
    detector_count: int
    enabled_detector_count: int
    active_actions: list[str]
    provenance_overlay_count: int
    inspect_roles: list[str]
    blocking_detectors: list[str]
    fail_open_detectors: list[str]


class DependencyStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    status: Literal["ok", "unavailable", "not_configured"]
    detail: str | None = None


class SystemStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    environment: str
    ready: bool
    started_at: datetime | None
    uptime_seconds: float | None
    dependencies: list[DependencyStatus]
    detectors_warmed: bool

    # Whether the gateway's own callers are authenticated (ADR-024). An operator
    # needs to be able to answer "is `/v1` protected right now?" during an
    # incident without shelling into the container, and the answer is a boolean
    # and a mode name — never a caller id, never a credential, never a digest.
    # §23 of the Phase 10 brief permits this on a documented operational need;
    # this is the need.
    caller_auth_mode: Literal["disabled", "api_key", "proxy"]
    caller_auth_enforced: bool


class EvaluationSummary(BaseModel):
    """A finalised evaluation artefact.

    `status` distinguishes a completed run from one that is incomplete or was
    superseded, so a dashboard cannot render an unfinished experiment as a
    benchmark (§15 of the Phase 5 brief).
    """

    model_config = ConfigDict(frozen=True)

    run_id: str
    status: Literal["complete", "failed", "invalid", "superseded", "running"]
    detector: str | None = None
    dataset: str | None = None
    dataset_version: str | None = None
    dataset_sha256: str | None = None
    model_version: str | None = None
    threshold: float | None = None
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    fpr: float | None = None
    fnr: float | None = None
    sample_count: int | None = None
    created_at: datetime | None = None
    protocol: str | None = None
    decision: str | None = None


class EvaluationDetail(EvaluationSummary):
    model_config = ConfigDict(frozen=True)

    # The harness records latency as nested blocks (total/preprocess/inference,
    # each with n and percentiles) plus a note, and per-category metrics carry
    # confidence-interval pairs. Typed to the artefact's real shape rather than a
    # flattened one that would silently drop fields.
    latency: dict[str, object] | None = None
    category_metrics: dict[str, dict[str, object]] = Field(default_factory=dict)
    confidence_intervals: dict[str, list[float]] = Field(default_factory=dict)
    benchmark_metadata: dict[str, object] = Field(default_factory=dict)
    artefact_path: str | None = None


class EvaluationList(BaseModel):
    model_config = ConfigDict(frozen=True)

    items: list[EvaluationSummary]
    status: DataStatus
    note: str | None = None


class SessionStatus(BaseModel):
    """Who the gateway thinks is asking (ADR-023).

    The minimum the console needs to render an authenticated state: a subject to
    display, a role, and the sign-out path the proxy published. No email, no
    group list, no token, no identity-provider name — a console that displays
    more identity than it needs is a console that leaks it into a screenshot.

    `authenticated` is `false` in development, where the boundary is off. That is
    a truthful answer, not an error: the console shows an explicit
    "authentication disabled" state rather than inventing an operator.
    """

    model_config = ConfigDict(frozen=True)

    authenticated: bool
    enforced: bool
    subject: str | None = None
    role: Literal["operator", "internal_service"] | None = None
    logout_path: str | None = None
