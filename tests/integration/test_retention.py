"""Retention against real PostgreSQL (ADR-030).

The SQL is the substance here — `FOR UPDATE SKIP LOCKED`, `ON DELETE CASCADE`,
`now()` on the server, `rowcount` from the driver. None of that has an in-memory
substitute, so these tests run against the compose database or they skip.

**Nothing here touches rows this test did not create.** Every fixture row is aged
past the *default* 30/180-day periods and carries a `retention-test-` request id;
assertions count only those rows. That is not tidiness — a retention test that
shortened the period to make itself fast would delete the local development audit
trail as a side effect, which is exactly the accident the feature has to be
trusted not to have.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import func, select

from app.database.models import DetectorResultRow, RequestTraceRow, SecurityEventRow
from app.database.retention import RetentionPolicy, RetentionRule, RetentionSweeper
from app.database.session import Database

DATABASE_URL = "postgresql+asyncpg://firewall:firewall@localhost:5434/firewall"

# The shipped defaults. Used verbatim so the test exercises the configuration a
# deployment actually gets.
DEFAULT_POLICY = RetentionPolicy(
    rules=(
        RetentionRule(
            table="request_traces", days=30, reason="test", cascades=("detector_results",)
        ),
        RetentionRule(table="security_events", days=180, reason="test"),
    )
)


def database_is_up() -> bool:
    import socket

    with socket.socket() as sock:
        sock.settimeout(1.0)
        return sock.connect_ex(("localhost", 5434)) == 0


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
    pytest.mark.skipif(not database_is_up(), reason="compose PostgreSQL is not running"),
]


class _Settings:
    """Just enough of `Settings` for `Database.from_settings`."""

    persist_events = True
    database_pool_size = 2

    class _Url:
        @staticmethod
        def get_secret_value() -> str:
            return DATABASE_URL

    database_url = _Url()


@pytest_asyncio.fixture
async def database():
    db = Database.from_settings(_Settings())  # type: ignore[arg-type]
    assert db is not None
    yield db
    await db.aclose()


@pytest_asyncio.fixture
async def marker(database: Database):
    """A unique prefix per test, and removal of whatever survives it.

    The cleanup runs even when the assertion under test failed, so a broken
    retention run cannot leave rows behind that make the next run pass.
    """
    tag = f"retention-test-{uuid.uuid4().hex[:12]}"
    yield tag
    async with database.session() as session:
        traces = (
            await session.scalars(
                select(RequestTraceRow.id).where(RequestTraceRow.request_id.like(f"{tag}%"))
            )
        ).all()
        if traces:
            await session.execute(
                DetectorResultRow.__table__.delete().where(
                    DetectorResultRow.trace_id.in_(list(traces))
                )
            )
            await session.execute(
                RequestTraceRow.__table__.delete().where(RequestTraceRow.id.in_(list(traces)))
            )
        await session.execute(
            SecurityEventRow.__table__.delete().where(SecurityEventRow.request_id.like(f"{tag}%"))
        )
        await session.commit()


async def add_trace(
    database: Database, tag: str, *, age_days: float, index: int = 0, children: int = 0
) -> int:
    created = datetime.now(UTC) - timedelta(days=age_days)
    async with database.session() as session:
        row = RequestTraceRow(
            request_id=f"{tag}-{index}",
            created_at=created,
            model="test-model",
            status_code=200,
            decision="allow",
            policy_version="test",
            gateway_latency_ms=1.0,
        )
        row.detector_results = [
            DetectorResultRow(
                created_at=created,
                detector=f"test.detector{n}",
                direction="input",
                category="benign",
                detected=False,
                score=0.0,
                threshold=0.85,
            )
            for n in range(children)
        ]
        session.add(row)
        await session.commit()
        return row.id


async def add_event(database: Database, tag: str, *, age_days: float, index: int = 0) -> None:
    async with database.session() as session:
        session.add(
            SecurityEventRow(
                request_id=f"{tag}-{index}",
                created_at=datetime.now(UTC) - timedelta(days=age_days),
                event_type="block",
                direction="input",
                severity=5,
            )
        )
        await session.commit()


async def count_traces(database: Database, tag: str) -> int:
    async with database.session() as session:
        return int(
            await session.scalar(
                select(func.count())
                .select_from(RequestTraceRow)
                .where(RequestTraceRow.request_id.like(f"{tag}%"))
            )
            or 0
        )


async def count_children(database: Database, trace_ids: list[int]) -> int:
    async with database.session() as session:
        return int(
            await session.scalar(
                select(func.count())
                .select_from(DetectorResultRow)
                .where(DetectorResultRow.trace_id.in_(trace_ids))
            )
            or 0
        )


async def count_events(database: Database, tag: str) -> int:
    async with database.session() as session:
        return int(
            await session.scalar(
                select(func.count())
                .select_from(SecurityEventRow)
                .where(SecurityEventRow.request_id.like(f"{tag}%"))
            )
            or 0
        )


def sweeper(database: Database, **kwargs) -> RetentionSweeper:
    return RetentionSweeper(database, DEFAULT_POLICY, **kwargs)


async def test_deletes_rows_past_the_period(database: Database, marker: str):
    await add_trace(database, marker, age_days=40, index=0)
    await add_trace(database, marker, age_days=31, index=1)
    assert await count_traces(database, marker) == 2

    report = await sweeper(database).sweep()

    assert await count_traces(database, marker) == 0
    traces = next(t for t in report.tables if t.table == "request_traces")
    assert traces.deleted >= 2


async def test_does_not_delete_rows_inside_the_period(database: Database, marker: str):
    """The assertion that matters most, and the one an age-based purge gets wrong
    silently. 29 days is inside a 30-day period; 30.001 is not."""
    await add_trace(database, marker, age_days=29, index=0)
    await add_trace(database, marker, age_days=0, index=1)
    await add_trace(database, marker, age_days=30.001, index=2)

    await sweeper(database).sweep()

    async with database.session() as session:
        surviving = sorted(
            (
                await session.scalars(
                    select(RequestTraceRow.request_id).where(
                        RequestTraceRow.request_id.like(f"{marker}%")
                    )
                )
            ).all()
        )
    assert surviving == [f"{marker}-0", f"{marker}-1"]


async def test_cascade_removes_detector_results_and_counts_them(database: Database, marker: str):
    trace_id = await add_trace(database, marker, age_days=40, children=4)
    assert await count_children(database, [trace_id]) == 4

    report = await sweeper(database).sweep()

    assert await count_children(database, [trace_id]) == 0
    traces = next(t for t in report.tables if t.table == "request_traces")
    assert traces.cascaded["detector_results"] >= 4


async def test_security_events_outlive_traces(database: Database, marker: str):
    """Both tables are swept in the same pass, on different clocks. A 40-day-old
    event is well past the trace period and nowhere near its own."""
    await add_trace(database, marker, age_days=40, index=0)
    await add_event(database, marker, age_days=40, index=1)
    await add_event(database, marker, age_days=200, index=2)

    report = await sweeper(database).sweep()

    assert await count_traces(database, marker) == 0
    assert await count_events(database, marker) == 1
    events = next(t for t in report.tables if t.table == "security_events")
    assert events.deleted >= 1


async def test_dry_run_deletes_nothing(database: Database, marker: str):
    await add_trace(database, marker, age_days=40, children=3)

    report = await sweeper(database).sweep(dry_run=True)

    assert report.dry_run is True
    assert await count_traces(database, marker) == 1
    traces = next(t for t in report.tables if t.table == "request_traces")
    assert traces.deleted >= 1
    assert traces.cascaded["detector_results"] >= 3


async def test_running_twice_deletes_nothing_the_second_time(database: Database, marker: str):
    await add_trace(database, marker, age_days=40)
    engine = sweeper(database)

    first = await engine.sweep()
    second = await engine.sweep()

    assert first.total_rows >= 1
    assert second.total_rows == 0


async def test_per_sweep_ceiling_is_honoured_and_reported(database: Database, marker: str):
    """A budget that stops short must say so. A cap that silently truncates reads
    as 'retention is enforced' when it is only running behind."""
    for index in range(5):
        await add_trace(database, marker, age_days=40, index=index)

    limited = sweeper(database, batch_size=2, max_rows_per_sweep=3)
    first = await limited.sweep()

    traces = next(t for t in first.tables if t.table == "request_traces")
    assert traces.deleted == 3
    assert traces.budget_exhausted is True
    assert await count_traces(database, marker) == 2

    await sweeper(database).sweep()
    assert await count_traces(database, marker) == 0


async def test_batching_deletes_everything_across_batches(database: Database, marker: str):
    for index in range(7):
        await add_trace(database, marker, age_days=40, index=index)

    report = await sweeper(database, batch_size=2).sweep()

    assert await count_traces(database, marker) == 0
    traces = next(t for t in report.tables if t.table == "request_traces")
    assert traces.deleted >= 7
    assert traces.budget_exhausted is False


async def test_cutoff_comes_from_the_database_clock(database: Database):
    """Not the process clock. A gateway whose clock has drifted forward would
    otherwise delete rows that are not old yet — silently and unrecoverably."""
    swept = sweeper(database)
    report = await swept.sweep(dry_run=True)
    async with database.session() as session:
        server_now = await session.scalar(select(func.now()))

    traces = next(t for t in report.tables if t.table == "request_traces")
    expected = server_now - timedelta(days=30)
    assert abs((traces.cutoff - expected).total_seconds()) < 5
