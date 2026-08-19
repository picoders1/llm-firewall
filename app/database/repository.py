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
    def __init__(self, database: Database, *, require_audit: bool = False) -> None:
        self._database = database
        self._require_audit = require_audit

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
