"""Audit retention: the job that deletes.

[ADR-012](../../docs/adr/ADR-012-persistence-and-retention.md) specified retention
in Phase 0 — a maximum age per table, enforced by "a scheduled `DELETE` ... not a
manual process". Phase 5 built the schema and the console that reads it. Nothing
ever built the deletion, so every row ever written is still there. This module is
that job.

## What it deletes, and what it cannot be aimed at

The only predicate is **age**. There is no parameter for a decision, a category, a
detector or a caller, and there is no way to add one without changing this file:
`_eligible_ids` builds its `WHERE` from `created_at` alone. That is deliberate.
A retention job with a filter an operator can point at specific rows is a
supported mechanism for erasing evidence of a block, and
`tests/security/test_retention_safety.py` compiles the statements and asserts on
the SQL rather than trusting this paragraph.

## Why it is batched

`Database` sets a 5-second command timeout on every connection, so one
`DELETE FROM request_traces WHERE created_at < …` against a backlog would not
merely be slow — it would time out, roll back, and delete nothing, forever.
Deletion runs in bounded batches, each its own transaction. A sweep that is
cancelled mid-way has therefore committed everything it reported and left the
rest for the next sweep; partial progress is the normal state, not a failure.

## Where the cutoff comes from

`created_at` is stamped by PostgreSQL's clock (`server_default=now()`), so the
cutoff is computed from PostgreSQL's clock too. A gateway whose own clock has
drifted forward would otherwise delete rows that are not old yet — the one
failure mode of an age-based purge that is silent and unrecoverable.

## `detector_results` is not swept directly

It has no index on `created_at` alone (only `(detector, created_at)`), so an
age-based scan of it would be a sequential scan of the largest table in the
schema. It does not need one: the foreign key is `ON DELETE CASCADE`, so deleting
a trace deletes its detector rows through `ix_detector_results_trace_id`. The
cascade is counted before each batch so the metric reports the rows that were
actually removed rather than only the parents.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

import structlog
from sqlalchemy import Select, delete, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import MINIMUM_RETENTION_DAYS, Settings
from app.database.models import DetectorResultRow, RequestTraceRow, SecurityEventRow
from app.database.session import Database

logger = structlog.get_logger(__name__)

# `MINIMUM_RETENTION_DAYS` is defined in `app.config.settings` and re-exported
# here: `app.database` imports `app.config`, not the reverse. It is applied at
# both ends, because a policy can be built from the CLI without going through
# `Settings` and the floor must not depend on the route taken.

# Tables under retention, and the model that carries their timestamp. Anything
# here is deleted by age; anything reachable by cascade is deleted with its
# parent. `tests/unit/test_retention_policy.py` asserts that every table in the
# audit schema appears in one of those two roles, so a table added later cannot
# quietly escape retention by not being mentioned.
SWEPT_TABLES: tuple[str, ...] = ("request_traces", "security_events")
CASCADED_TABLES: tuple[str, ...] = ("detector_results",)


class RetentionMetrics(Protocol):
    """Only what this module emits. Narrower than `Metrics` so the dependency is
    visible and a test can pass a recorder without building a registry."""

    def record_rows_deleted(self, *, table: str, rows: int) -> None: ...
    def record_retention_sweep(self, *, outcome: str) -> None: ...
    def set_retention_last_success(self, *, timestamp: float) -> None: ...
    def set_oldest_audit_row_age(self, *, table: str, age_seconds: float) -> None: ...


@dataclass(frozen=True, slots=True)
class RetentionRule:
    """One table's maximum age.

    `reason` is carried into the startup log and the dry-run output: a retention
    period without its justification is a number nobody can safely change.
    """

    table: str
    days: int
    reason: str
    cascades: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    rules: tuple[RetentionRule, ...]

    @classmethod
    def from_settings(cls, settings: Settings) -> RetentionPolicy:
        trace_days = settings.retention_trace_days
        event_days = settings.retention_event_days
        for days in (trace_days, event_days):
            if days < MINIMUM_RETENTION_DAYS:
                # Belt and braces: `Settings` already refuses this. Repeated here
                # because this class is also constructed directly by the CLI and
                # by tests, and the floor must not depend on the route taken.
                raise ValueError(
                    f"retention period {days} is below the {MINIMUM_RETENTION_DAYS}-day floor"
                )
        return cls(
            rules=(
                RetentionRule(
                    table="request_traces",
                    days=trace_days,
                    reason=(
                        "operational tuning window; matches the console's maximum "
                        "query window, so retention never deletes a row the console "
                        "could still have shown (ADR-012)"
                    ),
                    cascades=("detector_results",),
                ),
                RetentionRule(
                    table="security_events",
                    days=event_days,
                    reason=(
                        "investigations begin long after the event; the denormalised "
                        "auditor table deliberately outlives the traces (ADR-012)"
                    ),
                ),
            )
        )

    def summary(self) -> dict[str, int]:
        return {rule.table: rule.days for rule in self.rules}


@dataclass(frozen=True, slots=True)
class TableSweep:
    """What one rule did, or would have done."""

    table: str
    cutoff: datetime
    deleted: int
    cascaded: dict[str, int] = field(default_factory=dict)
    budget_exhausted: bool = False

    @property
    def total(self) -> int:
        return self.deleted + sum(self.cascaded.values())


@dataclass(frozen=True, slots=True)
class SweepReport:
    tables: tuple[TableSweep, ...]
    duration_s: float
    dry_run: bool

    @property
    def total_rows(self) -> int:
        return sum(sweep.total for sweep in self.tables)

    @property
    def budget_exhausted(self) -> bool:
        return any(sweep.budget_exhausted for sweep in self.tables)


_MODELS: dict[str, type[RequestTraceRow] | type[SecurityEventRow]] = {
    "request_traces": RequestTraceRow,
    "security_events": SecurityEventRow,
}


def _eligible_ids(table: str, cutoff: datetime, limit: int) -> Select[tuple[int]]:
    """The only row-selection this module performs.

    Age, ordered by primary key, bounded. `FOR UPDATE SKIP LOCKED` so that two
    replicas sweeping concurrently divide the work instead of one waiting on the
    other's locks until the 5-second command timeout kills it.
    """
    model = _MODELS[table]
    return (
        select(model.id)
        .where(model.created_at < cutoff)
        .order_by(model.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )


class RetentionSweeper:
    """Deletes rows past their retention period, in bounded batches.

    Stateless between sweeps by design: everything it needs is the policy and the
    database clock, so an interrupted sweep needs no recovery and running it twice
    is the same as running it once.
    """

    def __init__(
        self,
        database: Database,
        policy: RetentionPolicy,
        *,
        batch_size: int = 1000,
        max_rows_per_sweep: int = 50_000,
        metrics: RetentionMetrics | None = None,
    ) -> None:
        self._database = database
        self._policy = policy
        self._batch_size = batch_size
        self._max_rows = max_rows_per_sweep
        self._metrics = metrics

    @property
    def policy(self) -> RetentionPolicy:
        return self._policy

    async def sweep(self, *, dry_run: bool = False) -> SweepReport:
        started = time.perf_counter()
        now = await self._database_now()
        results: list[TableSweep] = []
        for rule in self._policy.rules:
            cutoff = now - timedelta(days=rule.days)
            if dry_run:
                results.append(await self._count(rule, cutoff))
            else:
                results.append(await self._delete(rule, cutoff))
        report = SweepReport(
            tables=tuple(results),
            duration_s=time.perf_counter() - started,
            dry_run=dry_run,
        )
        if not dry_run:
            await self._observe(now)
        return report

    async def _database_now(self) -> datetime:
        """The database's clock, not this process's — see the module docstring."""
        async with self._database.session() as session:
            value = (await session.execute(select(func.now()))).scalar_one()
        if not isinstance(value, datetime):  # pragma: no cover - defensive
            raise TypeError(f"database clock returned {type(value).__name__}")
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

    async def _count(self, rule: RetentionRule, cutoff: datetime) -> TableSweep:
        """Dry run: how many rows *would* go. Deletes nothing.

        Counts the cascade too, by joining rather than scanning, because
        "30 days is fine" and "30 days removes 180,000 child rows" are different
        pieces of information and only one of them is on the parent table.
        """
        model = _MODELS[rule.table]
        async with self._database.session() as session:
            eligible = await session.scalar(
                select(func.count()).select_from(model).where(model.created_at < cutoff)
            )
            cascaded: dict[str, int] = {}
            if "detector_results" in rule.cascades:
                cascaded["detector_results"] = (
                    await session.scalar(
                        select(func.count())
                        .select_from(DetectorResultRow)
                        .join(RequestTraceRow, DetectorResultRow.trace_id == RequestTraceRow.id)
                        .where(RequestTraceRow.created_at < cutoff)
                    )
                    or 0
                )
        return TableSweep(
            table=rule.table,
            cutoff=cutoff,
            deleted=int(eligible or 0),
            cascaded=cascaded,
            budget_exhausted=(eligible or 0) > self._max_rows,
        )

    async def _delete(self, rule: RetentionRule, cutoff: datetime) -> TableSweep:
        model = _MODELS[rule.table]
        deleted = 0
        cascaded: dict[str, int] = dict.fromkeys(rule.cascades, 0)
        exhausted = False

        while deleted < self._max_rows:
            batch = min(self._batch_size, self._max_rows - deleted)
            async with self._database.session() as session:
                ids = list((await session.scalars(_eligible_ids(rule.table, cutoff, batch))).all())
                if not ids:
                    break
                for child in rule.cascades:
                    cascaded[child] += await self._count_cascade(session, child, ids)
                result = cast(
                    "CursorResult[Any]",
                    await session.execute(delete(model).where(model.id.in_(ids))),
                )
                await session.commit()
                # `rowcount` rather than `len(ids)`: with SKIP LOCKED another
                # sweeper can have removed a row between the select and the
                # delete, and the metric must report what this process removed.
                removed = result.rowcount if result.rowcount is not None else len(ids)
                deleted += removed
            if len(ids) < batch:
                break
        else:
            # The `while` condition ended the loop, so there may be more rows than
            # this sweep was allowed to remove. Logged rather than left silent: a
            # cap that quietly truncates reads as "retention is enforced" when it
            # is merely running behind.
            exhausted = await self._has_more(rule, cutoff)

        return TableSweep(
            table=rule.table,
            cutoff=cutoff,
            deleted=deleted,
            cascaded=dict(cascaded),
            budget_exhausted=exhausted,
        )

    async def _count_cascade(self, session: AsyncSession, child: str, ids: Sequence[int]) -> int:
        """Children about to be removed by the foreign key, counted through
        `ix_detector_results_trace_id` before the parent goes."""
        if child != "detector_results":  # pragma: no cover - only one cascade exists
            raise ValueError(f"unknown cascade target {child!r}")
        count = await session.scalar(
            select(func.count())
            .select_from(DetectorResultRow)
            .where(DetectorResultRow.trace_id.in_(ids))
        )
        return int(count or 0)

    async def _has_more(self, rule: RetentionRule, cutoff: datetime) -> bool:
        model = _MODELS[rule.table]
        async with self._database.session() as session:
            found = await session.scalar(select(model.id).where(model.created_at < cutoff).limit(1))
        return found is not None

    async def _observe(self, now: datetime) -> None:
        """Age of the oldest surviving row per swept table.

        This, not the delete counter, is the metric that says retention is
        *working*: a counter can tick while the backlog grows. Only the tables
        with a standalone `created_at` index are reported — `min()` on
        `detector_results` would be a sequential scan, and a metric is not worth
        a full table read every sweep.
        """
        if self._metrics is None:
            return
        async with self._database.session() as session:
            for table in SWEPT_TABLES:
                model = _MODELS[table]
                oldest = await session.scalar(select(func.min(model.created_at)))
                if oldest is None:
                    age = 0.0
                else:
                    if oldest.tzinfo is None:  # pragma: no cover - PostgreSQL is tz-aware
                        oldest = oldest.replace(tzinfo=UTC)
                    age = max(0.0, (now - oldest).total_seconds())
                self._metrics.set_oldest_audit_row_age(table=table, age_seconds=age)


class RetentionScheduler:
    """Runs the sweeper on an interval, off the request path.

    A sweep runs at startup and then every `interval_s`. At startup because a
    feature whose first observable effect is an hour away is a feature nobody can
    verify they enabled; on an interval rather than at midnight because there is
    no scheduler in this deployment (OD-41) and a daily job in a process that is
    redeployed daily never runs.
    """

    __slots__ = ("_interval_s", "_metrics", "_sweeper", "_task")

    def __init__(
        self,
        sweeper: RetentionSweeper,
        *,
        interval_s: float,
        metrics: RetentionMetrics | None = None,
    ) -> None:
        self._sweeper = sweeper
        self._interval_s = interval_s
        self._metrics = metrics
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run_forever())

    async def _run_forever(self) -> None:
        while True:
            await self.run_once()
            await asyncio.sleep(self._interval_s)

    async def run_once(self) -> SweepReport | None:
        """One sweep, with its failure contained.

        Nothing raised in here may escape: an exception would kill the task and
        turn a transient database error into permanent, silent growth — the same
        reasoning as the audit writer's drain loop (ADR-029).
        """
        try:
            report = await self._sweeper.sweep()
        except Exception as exc:
            # The exception text is not logged: it can carry SQL parameters.
            logger.error("retention_sweep_failed", error_kind=type(exc).__name__)
            if self._metrics is not None:
                self._metrics.record_retention_sweep(outcome="failed")
            return None

        for sweep in report.tables:
            if self._metrics is not None:
                self._metrics.record_rows_deleted(table=sweep.table, rows=sweep.deleted)
                for child, rows in sweep.cascaded.items():
                    self._metrics.record_rows_deleted(table=child, rows=rows)
            if sweep.budget_exhausted:
                logger.warning(
                    "retention_budget_exhausted",
                    table=sweep.table,
                    deleted=sweep.deleted,
                    note="rows remain past their retention period; the next sweep continues",
                )
        if self._metrics is not None:
            self._metrics.record_retention_sweep(outcome="success")
            self._metrics.set_retention_last_success(timestamp=time.time())
        if report.total_rows:
            logger.info(
                "retention_sweep",
                rows=report.total_rows,
                duration_ms=round(report.duration_s * 1000, 3),
                **{sweep.table: sweep.deleted for sweep in report.tables},
            )
        return report

    async def aclose(self) -> None:
        """Cancel, possibly mid-sweep. Safe because every batch commits on its
        own: what was deleted stays deleted and the rest waits for next time."""
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None


__all__ = [
    "CASCADED_TABLES",
    "MINIMUM_RETENTION_DAYS",
    "SWEPT_TABLES",
    "RetentionPolicy",
    "RetentionRule",
    "RetentionScheduler",
    "RetentionSweeper",
    "SweepReport",
    "TableSweep",
]
