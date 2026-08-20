"""The retention policy, its floor, and the guarantee that no table escapes it."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from app.config.settings import MINIMUM_RETENTION_DAYS, Settings
from app.database.models import Base
from app.database.retention import (
    CASCADED_TABLES,
    SWEPT_TABLES,
    RetentionPolicy,
    RetentionScheduler,
    SweepReport,
    TableSweep,
)

pytestmark = pytest.mark.unit


def settings(**overrides) -> Settings:
    return Settings(**overrides)


def test_defaults_are_the_periods_adr_012_registered():
    policy = RetentionPolicy.from_settings(settings())
    assert policy.summary() == {"request_traces": 30, "security_events": 180}


def test_every_rule_carries_its_reason():
    """A retention period without its justification is a number nobody can
    safely change."""
    for rule in RetentionPolicy.from_settings(settings()).rules:
        assert len(rule.reason) > 20


def test_no_audit_table_escapes_retention():
    """Every table in the audit schema is either swept by age or removed with its
    parent. A table added later that is neither fails here rather than growing
    for a year before anyone notices."""
    known = set(SWEPT_TABLES) | set(CASCADED_TABLES)
    assert set(Base.metadata.tables) == known


def test_cascaded_tables_are_reachable_from_a_swept_one():
    cascades = {
        name for rule in RetentionPolicy.from_settings(settings()).rules for name in rule.cascades
    }
    assert cascades == set(CASCADED_TABLES)


@pytest.mark.parametrize("field", ("retention_trace_days", "retention_event_days"))
@pytest.mark.parametrize("value", (0, -1))
def test_a_period_below_the_floor_is_refused(field: str, value: int):
    """Zero means 'delete everything on the next sweep'. A mistyped environment
    variable must not be recoverable only from a backup."""
    with pytest.raises(ValidationError):
        settings(**{field: value})


def test_the_floor_is_one_day():
    assert MINIMUM_RETENTION_DAYS == 1
    assert settings(retention_trace_days=1, retention_event_days=1)


def test_events_may_not_be_deleted_before_traces():
    """The console's event detail LEFT JOINs an event to its trace precisely
    because events outlive traces. Inverting that order would make the
    longer-lived table the one that disappears first."""
    with pytest.raises(ValidationError, match="must be >="):
        settings(retention_trace_days=90, retention_event_days=30)


def test_equal_periods_are_allowed():
    assert RetentionPolicy.from_settings(
        settings(retention_trace_days=30, retention_event_days=30)
    ).summary() == {"request_traces": 30, "security_events": 30}


def test_policy_built_directly_still_applies_the_floor():
    """The CLI and tests construct a policy without going through `Settings`.
    The floor must not depend on the route taken."""

    class Bypass:
        retention_trace_days = 0
        retention_event_days = 180

    with pytest.raises(ValueError, match="floor"):
        RetentionPolicy.from_settings(Bypass())  # type: ignore[arg-type]


def test_retention_is_off_by_default():
    """Deletion is irreversible. An upgrade must not start removing an
    operator's audit trail because a default moved (ADR-029's precedent)."""
    assert settings().retention_enabled is False


def test_settings_summary_reports_the_periods():
    summary = settings().safe_summary()
    assert summary["retention_enabled"] is False
    assert summary["retention_trace_days"] == 30
    assert summary["retention_event_days"] == 180


def test_report_totals_include_cascaded_rows():
    report = SweepReport(
        tables=(
            TableSweep(
                table="request_traces",
                cutoff=None,  # type: ignore[arg-type]
                deleted=10,
                cascaded={"detector_results": 40},
            ),
            TableSweep(table="security_events", cutoff=None, deleted=2),  # type: ignore[arg-type]
        ),
        duration_s=0.1,
        dry_run=False,
    )
    assert report.total_rows == 52
    assert report.budget_exhausted is False


class _Recorder:
    def __init__(self) -> None:
        self.deleted: list[tuple[str, int]] = []
        self.sweeps: list[str] = []
        self.last_success: float | None = None
        self.ages: list[tuple[str, float]] = []

    def record_rows_deleted(self, *, table: str, rows: int) -> None:
        self.deleted.append((table, rows))

    def record_retention_sweep(self, *, outcome: str) -> None:
        self.sweeps.append(outcome)

    def set_retention_last_success(self, *, timestamp: float) -> None:
        self.last_success = timestamp

    def set_oldest_audit_row_age(self, *, table: str, age_seconds: float) -> None:
        self.ages.append((table, age_seconds))


class _FailingSweeper:
    async def sweep(self, *, dry_run: bool = False) -> SweepReport:
        raise RuntimeError("database is gone")


class _CountingSweeper:
    def __init__(self) -> None:
        self.calls = 0

    async def sweep(self, *, dry_run: bool = False) -> SweepReport:
        self.calls += 1
        return SweepReport(
            tables=(
                TableSweep(
                    table="request_traces",
                    cutoff=None,  # type: ignore[arg-type]
                    deleted=3,
                    cascaded={"detector_results": 12},
                ),
            ),
            duration_s=0.0,
            dry_run=dry_run,
        )


def test_a_failed_sweep_is_counted_and_does_not_escape():
    """An exception here would kill the task and turn a transient database error
    into permanent, silent growth — the audit writer's reasoning (ADR-029)."""
    metrics = _Recorder()
    scheduler = RetentionScheduler(_FailingSweeper(), interval_s=1.0, metrics=metrics)  # type: ignore[arg-type]

    assert asyncio.run(scheduler.run_once()) is None
    assert metrics.sweeps == ["failed"]
    assert metrics.last_success is None


def test_a_successful_sweep_records_both_direct_and_cascaded_rows():
    metrics = _Recorder()
    scheduler = RetentionScheduler(_CountingSweeper(), interval_s=1.0, metrics=metrics)  # type: ignore[arg-type]

    asyncio.run(scheduler.run_once())

    assert ("request_traces", 3) in metrics.deleted
    assert ("detector_results", 12) in metrics.deleted
    assert metrics.sweeps == ["success"]
    assert metrics.last_success is not None


def test_the_scheduler_sweeps_at_startup_rather_than_after_one_interval():
    """A feature whose first observable effect is an hour away is a feature
    nobody can verify they enabled."""
    sweeper = _CountingSweeper()

    async def run() -> None:
        scheduler = RetentionScheduler(sweeper, interval_s=3600.0)  # type: ignore[arg-type]
        await scheduler.start()
        await asyncio.sleep(0.05)
        await scheduler.aclose()

    asyncio.run(run())
    assert sweeper.calls == 1
