"""`firewall_audit_write_failures_total` must move when a write fails (R-111).

Found in Run 3 while validating `FirewallAuditWriteFailing` — a **critical** alert,
"wake someone now", whose whole subject is a database outage. Against a stopped
PostgreSQL the gateway emitted 660 `audit_write_failed` ERROR lines in five minutes
and the counter read **0.0** throughout, so the alert could never fire.

ADR-012 fixed this contract in Phase 0: *"The write failure is logged at ERROR and
increments `firewall_audit_write_failures_total`, which is an alerting metric."*
`Metrics.record_audit_failure()` was written and exported, the rule was written, the
runbook entry was written — and the method had **zero call sites** in the whole
application. Logging and counting had drifted apart with nothing to notice.

That is the same failure shape as R-107, where `firewall_upstream_errors_total` sat
behind a guard that excluded every real upstream failure. Both were invisible for
the same reason: a metric can be defined, documented, alerted on and dead, and the
only thing that catches it is driving the real condition.

These tests pin the *behaviour*, not the call: a repository whose write fails must
increment the counter, in both write modes, once per failed record.
"""

from __future__ import annotations

import pytest

from app.core.types import Action
from app.database.repository import PostgresAuditRepository, QueuedAuditRepository
from app.models.events import RequestTrace
from app.observability.metrics import Metrics

pytestmark = pytest.mark.unit


class ExplodingDatabase:
    """A database whose session cannot be opened, as a stopped PostgreSQL is."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error or ConnectionRefusedError("connection refused")

    def session(self):
        raise self.error


def trace(request_id: str = "r-1") -> RequestTrace:
    return RequestTrace(
        request_id=request_id,
        status_code=200,
        decision=Action.ALLOW,
        policy_version="test",
        gateway_latency_ms=1.0,
    )


@pytest.fixture
def metrics() -> Metrics:
    return Metrics()


def failures(metrics: Metrics) -> float:
    return metrics.audit_write_failures_total._value.get()


async def test_a_failed_write_increments_the_counter(metrics: Metrics):
    repo = PostgresAuditRepository(ExplodingDatabase(), metrics=metrics)
    assert failures(metrics) == 0.0
    await repo.record(trace())
    assert failures(metrics) == 1.0


async def test_one_increment_per_failed_record(metrics: Metrics):
    """`rate()` over this counter is what the alert divides on, so a failure that
    counts twice, or once per batch, misstates the outage."""
    repo = PostgresAuditRepository(ExplodingDatabase(), metrics=metrics)
    for i in range(5):
        await repo.record(trace(f"r-{i}"))
    assert failures(metrics) == 5.0


async def test_a_successful_write_does_not_increment(metrics: Metrics):
    """The counter must mean "the audit trail is losing records", not "a write
    happened". A false positive here pages someone at 3am for nothing."""

    class Recording(PostgresAuditRepository):
        async def _write(self, _trace: RequestTrace) -> None:
            return None

    repo = Recording(ExplodingDatabase(), metrics=metrics)
    await repo.record(trace())
    assert failures(metrics) == 0.0


async def test_the_queued_mode_counts_the_same_failure(metrics: Metrics):
    """`queue_drop` wraps this same sink, so a write failing behind the queue is
    the same failure. Counting it only in `sync` would leave the alert dead in the
    mode `compose.prod.yaml` actually ships."""
    inner = PostgresAuditRepository(ExplodingDatabase(), metrics=metrics)
    queued = QueuedAuditRepository(inner, max_size=16, metrics=metrics)
    await queued.start()
    try:
        await queued.record(trace())
        # Deterministic drain, so the assertion is not a race with the writer task.
        await queued._queue.join()
    finally:
        await queued.aclose(drain_timeout_s=1.0)
    assert failures(metrics) == 1.0


async def test_the_request_still_succeeds_when_the_audit_write_fails(metrics: Metrics):
    """ADR-012's deliberate exception to fail-closed: a database outage costs the
    record, never the decision. `record` must not raise unless `require_audit`."""
    repo = PostgresAuditRepository(ExplodingDatabase(), metrics=metrics)
    await repo.record(trace())  # must not raise


async def test_metrics_are_optional(metrics: Metrics):
    """Constructed without metrics — as tests and scripts do — it must still not
    raise, or the fix would turn an audit outage into a crash."""
    repo = PostgresAuditRepository(ExplodingDatabase())
    await repo.record(trace())
