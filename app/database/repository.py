"""Audit persistence behind an interface.

The interface exists so that Phase 5 can replace synchronous writes with a
bounded queue and a background writer without touching a single caller
(ADR-012). In Phase 0 the implementation is the simplest thing that works.

**Audit failure does not fail the request** by default. The security *decision* is
unaffected by a database outage — the detectors ran, the policy was applied, the
block or allow is correct; only the record is lost. Turning a Postgres outage into
a total outage of the protected application trades a large availability loss for a
small integrity loss. `require_audit=true` inverts this for deployments that need
a guaranteed audit trail.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Protocol

import structlog

from app.core.exceptions import FirewallError
from app.database.models import DetectorResultRow, RequestTraceRow, SecurityEventRow
from app.database.session import Database
from app.models.events import RequestTrace

logger = structlog.get_logger(__name__)


class AuditWriteFailed(FirewallError):
    """Raised only when `require_audit` is enabled."""

    error_type = "audit_unavailable"
    status_code = 503


class AuditRepository(Protocol):
    async def record(self, trace: RequestTrace) -> None: ...


class NullAuditRepository:
    """Used when persistence is disabled.

    A visible no-op rather than a `None` check at every call site — but readiness
    still reports that auditing is off, so "no audit sink" is never silent.
    """

    async def record(self, trace: RequestTrace) -> None:
        return None


class PostgresAuditRepository:
    def __init__(
        self,
        database: Database,
        *,
        require_audit: bool = False,
        metrics: object | None = None,
    ) -> None:
        self._database = database
        self._require_audit = require_audit
        self._metrics = metrics

    async def record(self, trace: RequestTrace) -> None:
        try:
            await self._write(trace)
        except Exception as exc:
            # The exception text is not logged: it can contain SQL parameters.
            logger.error(
                "audit_write_failed",
                error_kind=type(exc).__name__,
                request_id=trace.request_id,
            )
            # COUNTED, not only logged. ADR-012 promised this in Phase 0 — "the
            # write failure is logged at ERROR and increments
            # firewall_audit_write_failures_total, which is an alerting metric" —
            # and `record_audit_failure()` was written, exported, given a rule
            # (FirewallAuditWriteFailing, severity critical) and a runbook entry,
            # and then never called from anywhere in the application.
            #
            # Measured in Run 3 against a stopped database: 660 `audit_write_failed`
            # log lines in five minutes with the counter still reading 0. A critical
            # alert whose numerator cannot move is worse than no alert, because the
            # silence reads as health — the same defect shape as R-107 (R-111).
            if self._metrics is not None:
                self._metrics.record_audit_failure()  # type: ignore[attr-defined]
            if self._require_audit:
                raise AuditWriteFailed(
                    "The audit trail is unavailable and this deployment requires it."
                ) from exc

    async def _write(self, trace: RequestTrace) -> None:
        async with self._database.session() as session:
            row = RequestTraceRow(
                request_id=trace.request_id,
                model=trace.model,
                upstream_host=trace.upstream_host,
                caller_id=trace.caller_id,
                status_code=trace.status_code,
                decision=trace.decision.value if trace.decision else "not_evaluated",
                block_category=trace.block_category.value if trace.block_category else None,
                policy_version=trace.policy_version,
                gateway_latency_ms=trace.gateway_latency_ms,
                upstream_latency_ms=trace.upstream_latency_ms,
                detector_latency_ms=trace.detector_latency_ms,
                normalization_latency_ms=trace.normalization_latency_ms,
                policy_latency_ms=trace.policy_latency_ms,
                upstream_called=trace.upstream_called,
                input_chars=trace.input_chars,
                output_chars=trace.output_chars,
                inspected_messages=trace.inspected_messages,
                truncated=trace.truncated,
            )
            row.detector_results = [
                DetectorResultRow(
                    detector=outcome.detector,
                    direction=outcome.direction.value,
                    category=outcome.category.value,
                    detected=outcome.detected,
                    score=outcome.score,
                    threshold=outcome.threshold,
                    latency_ms=outcome.latency_ms,
                    errored=outcome.errored,
                    error_kind=outcome.error_kind,
                    reasons=list(outcome.reasons),
                    provenance=outcome.provenance.value,
                    trust=outcome.trust.value,
                )
                for outcome in trace.detector_outcomes
            ]
            session.add(row)

            for event in trace.events:
                session.add(
                    SecurityEventRow(
                        request_id=event.request_id,
                        event_type=event.event_type,
                        direction=event.direction.value,
                        category=event.category.value if event.category else None,
                        detector=event.detector,
                        score=event.score,
                        severity=event.severity,
                        content_hash=event.content_hash,
                        content_length=event.content_length,
                        provenance=event.provenance.value,
                        trust=event.trust.value,
                        details=event.details,
                    )
                )

            await session.commit()


class QueuedAuditRepository:
    """A bounded queue and a background writer, in front of a real repository.

    ADR-012 registered this design in Phase 0 and named the evidence that would
    justify building it: "Phase 4 measurements show synchronous writes are a
    material share of gateway overhead". Phase 15 supplied that evidence — the
    synchronous write costs 10.5 ms p50 against 1.7 ms for the rest of the
    gateway span. This is that writer.

    ## Bounded, always

    An unbounded queue in front of a failing database converts a database outage
    into an out-of-memory kill. Dropping is visible in a metric; an OOM is
    visible as an outage.

    ## Drop, because blocking was measured and was worse

    When the queue is full the record is discarded and counted. The request path
    never waits, so a database that cannot keep up costs audit records rather
    than availability.

    The alternative — wait for space, so saturation degrades to synchronous
    behaviour — was implemented and benchmarked against a stalled database. It
    did not degrade to synchronous behaviour. Synchronous writes fail, get
    logged, and the request proceeds; a blocking queue has nothing to time out
    against and hung the request path until the client gave up. 120 requests
    became 120 read timeouts. Dropping, in the same scenario, served all 120 and
    counted 109 lost records (ADR-029).

    ## What it cannot do

    It cannot honour `require_audit=true`. That setting promises a served request
    has a record, and a queue is precisely the removal of that promise; the
    application refuses to start with both configured.
    """

    __slots__ = ("_dropped", "_inner", "_metrics", "_queue", "_task")

    def __init__(
        self,
        inner: AuditRepository,
        *,
        max_size: int,
        metrics: object | None = None,
    ) -> None:
        self._inner = inner
        self._queue: asyncio.Queue[RequestTrace] = asyncio.Queue(maxsize=max_size)
        self._metrics = metrics
        self._task: asyncio.Task[None] | None = None
        self._dropped = 0

    @property
    def dropped(self) -> int:
        return self._dropped

    def qsize(self) -> int:
        return self._queue.qsize()

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._drain_forever())

    async def record(self, trace: RequestTrace) -> None:
        try:
            self._queue.put_nowait(trace)
        except asyncio.QueueFull:
            # Counted, never silent. An audit trail that thins out under load
            # without saying so is worse than one that is honestly absent.
            self._dropped += 1
            logger.warning("audit_event_dropped", request_id=trace.request_id)
            if self._metrics is not None:
                self._metrics.record_audit_dropped()  # type: ignore[attr-defined]

    async def _drain_forever(self) -> None:
        while True:
            trace = await self._queue.get()
            try:
                await self._inner.record(trace)
            except Exception as exc:
                # `record` already logs and already honours require_audit. Anything
                # reaching here would otherwise kill the writer task and turn a
                # transient database error into permanent silence.
                logger.error("audit_writer_error", error_kind=type(exc).__name__)
            finally:
                self._queue.task_done()
            if self._metrics is not None:
                self._metrics.set_audit_queue_depth(self._queue.qsize())  # type: ignore[attr-defined]

    async def aclose(self, *, drain_timeout_s: float) -> int:
        """Drain what is queued, bounded, and report what was abandoned.

        Bounded because a stuck database must not hold a rolling deploy open. The
        return value is the number of records that never reached PostgreSQL,
        which is the honest measure of what an orderly shutdown costs.
        """
        if self._task is None:
            return self._queue.qsize()
        try:
            async with asyncio.timeout(drain_timeout_s):
                await self._queue.join()
        except TimeoutError:
            logger.warning("audit_drain_timed_out", remaining=self._queue.qsize())
        abandoned = self._queue.qsize()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        return abandoned
