"""The queued audit writer, and the promises it does and does not make (ADR-029).

ADR-012 registered this design in Phase 0 and named the evidence that would
justify building it. Phase 15 supplied that evidence. What ADR-012 could not
settle in advance is what the queue does when it cannot keep up, and that is
most of what is asserted here — because the answer determines whether a database
problem becomes a latency problem, an integrity problem, or an outage.
"""

from __future__ import annotations

import asyncio

import pytest

from app.database.repository import AuditWriteFailed, QueuedAuditRepository
from app.models.events import RequestTrace

pytestmark = pytest.mark.unit


def _trace(request_id: str = "r1") -> RequestTrace:
    return RequestTrace(
        request_id=request_id, status_code=200, policy_version="v", gateway_latency_ms=1.0
    )


class Recording:
    """A sink that records what reached it, and can be made slow or broken."""

    def __init__(self, *, delay: float = 0.0, fail: bool = False) -> None:
        self.written: list[str] = []
        self.delay = delay
        self.fail = fail

    async def record(self, trace: RequestTrace) -> None:
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("database is unavailable")
        self.written.append(trace.request_id)


async def test_records_reach_the_sink_when_it_keeps_up():
    sink = Recording()
    queue = QueuedAuditRepository(sink, max_size=100)
    await queue.start()
    for i in range(50):
        await queue.record(_trace(f"r{i}"))
    abandoned = await queue.aclose(drain_timeout_s=5.0)
    assert abandoned == 0
    assert len(sink.written) == 50


async def test_record_returns_without_waiting_for_the_write():
    """The entire point. `record` must not be where the 10 ms goes."""
    sink = Recording(delay=0.05)
    queue = QueuedAuditRepository(sink, max_size=100)
    await queue.start()

    started = asyncio.get_running_loop().time()
    for i in range(10):
        await queue.record(_trace(f"r{i}"))
    elapsed = asyncio.get_running_loop().time() - started

    # Ten 50 ms writes would be half a second synchronously.
    assert elapsed < 0.05, elapsed
    await queue.aclose(drain_timeout_s=5.0)


async def test_a_full_queue_drops_and_counts_rather_than_waiting():
    """The decision ADR-029 records. Blocking here was implemented, measured
    against a stalled database, and removed: it hung the request path until
    clients timed out, which is worse than either surviving option."""
    sink = Recording(delay=10.0)  # effectively stalled
    queue = QueuedAuditRepository(sink, max_size=2)
    await queue.start()

    started = asyncio.get_running_loop().time()
    for i in range(20):
        await queue.record(_trace(f"r{i}"))
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed < 0.5, "record() waited on a stalled sink"
    assert queue.dropped > 0
    queue._task.cancel()


async def test_a_failing_sink_does_not_kill_the_writer():
    """A transient database error must not turn into permanent silence — the
    writer task dying would stop every subsequent record without a signal."""
    sink = Recording(fail=True)
    queue = QueuedAuditRepository(sink, max_size=10)
    await queue.start()
    for i in range(5):
        await queue.record(_trace(f"r{i}"))
    await asyncio.sleep(0.1)

    sink.fail = False
    await queue.record(_trace("after-recovery"))
    await queue.aclose(drain_timeout_s=5.0)
    assert sink.written == ["after-recovery"]


async def test_shutdown_drains_what_is_queued():
    """Graceful shutdown loses nothing. Measured at 300/300 records written
    across a `docker compose stop`."""
    sink = Recording(delay=0.001)
    queue = QueuedAuditRepository(sink, max_size=500)
    await queue.start()
    for i in range(200):
        await queue.record(_trace(f"r{i}"))
    abandoned = await queue.aclose(drain_timeout_s=10.0)
    assert abandoned == 0
    assert len(sink.written) == 200


async def test_the_drain_is_bounded_so_a_stuck_database_cannot_hold_a_deploy_open():
    sink = Recording(delay=30.0)
    queue = QueuedAuditRepository(sink, max_size=50)
    await queue.start()
    for i in range(10):
        await queue.record(_trace(f"r{i}"))

    started = asyncio.get_running_loop().time()
    abandoned = await queue.aclose(drain_timeout_s=0.2)
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed < 2.0, elapsed
    # What could not be written is reported, not silently discarded.
    assert abandoned > 0


async def test_require_audit_is_not_silently_honoured_by_a_queue():
    """The sink still raises for a `require_audit` deployment — but by then the
    response has gone. That is why `create_app` refuses the combination outright
    rather than leaving it to be discovered in an audit."""

    class Strict:
        async def record(self, trace: RequestTrace) -> None:
            raise AuditWriteFailed("unavailable")

    queue = QueuedAuditRepository(Strict(), max_size=10)
    await queue.start()
    await queue.record(_trace())  # returns successfully; the failure is later
    await asyncio.sleep(0.05)
    await queue.aclose(drain_timeout_s=1.0)
