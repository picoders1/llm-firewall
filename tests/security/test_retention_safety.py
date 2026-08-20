"""Retention is a deletion capability inside a security product.

The risk it introduces is not that it deletes too little. It is that a purge with
a predicate an operator can aim becomes a supported mechanism for erasing the
evidence of a specific block — a cleaner one than editing rows, because it leaves
a legitimate-looking gap. These tests assert on the compiled SQL and on the
module's own source, so the property survives someone adding "just a category
filter" for a good reason.
"""

from __future__ import annotations

import inspect
import re
from datetime import UTC, datetime

import pytest
from sqlalchemy.dialects import postgresql

from app.database import retention
from app.database.retention import SWEPT_TABLES, RetentionSweeper, _eligible_ids

pytestmark = pytest.mark.security

# Columns that would let a purge be pointed at particular requests rather than at
# an age. Every one of them exists on a table under retention.
AIMABLE_COLUMNS = (
    "decision",
    "block_category",
    "category",
    "detector",
    "caller_id",
    "request_id",
    "content_hash",
    "severity",
    "provenance",
    "trust",
    "score",
    "detected",
    "policy_version",
    "model",
    "upstream_host",
    "event_type",
)


@pytest.mark.parametrize("table", SWEPT_TABLES)
def test_row_selection_filters_on_age_and_nothing_else(table: str):
    statement = _eligible_ids(table, datetime.now(UTC), 100)
    sql = str(statement.compile(dialect=postgresql.dialect()))

    assert "created_at <" in sql
    for column in AIMABLE_COLUMNS:
        assert not re.search(rf"\b{column}\b", sql), f"{table} selection references {column}"


@pytest.mark.parametrize("table", SWEPT_TABLES)
def test_row_selection_is_bounded_and_ordered(table: str):
    """Bounded because `Database` applies a 5-second command timeout: one
    unbounded DELETE against a backlog would time out, roll back, and delete
    nothing — permanently. Ordered so batches make forward progress."""
    sql = str(_eligible_ids(table, datetime.now(UTC), 100).compile(dialect=postgresql.dialect()))
    assert "LIMIT" in sql
    assert "ORDER BY" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql


def test_the_only_delete_removes_the_ids_that_age_selected():
    """One `delete` in the module, keyed on the id list `_eligible_ids` returned.

    The age comparison appears elsewhere too — in the dry-run count and the
    backlog check — but both are `SELECT`s. What this pins is that no second
    route into a `DELETE` exists, and that the one that does cannot be handed a
    list assembled any other way.
    """
    source = inspect.getsource(retention)
    assert source.count("delete(model)") == 1
    assert "delete(model).where(model.id.in_(ids))" in source

    assignments = [line for line in source.splitlines() if line.strip().startswith("ids = ")]
    assert len(assignments) == 1
    assert "_eligible_ids(" in assignments[0]


def test_the_sweeper_exposes_no_filter():
    """Not merely unused — absent. A parameter that exists is a parameter a
    caller can be persuaded to pass."""
    parameters = set(inspect.signature(RetentionSweeper.__init__).parameters)
    assert parameters == {
        "self",
        "database",
        "policy",
        "batch_size",
        "max_rows_per_sweep",
        "metrics",
    }
    assert set(inspect.signature(RetentionSweeper.sweep).parameters) == {"self", "dry_run"}


def test_the_cli_requires_an_explicit_execute_flag():
    """A deletion tool invoked with no arguments will eventually be invoked with
    no arguments by someone who only wanted to see what it would do."""
    from scripts.purge_audit import main

    parser_source = inspect.getsource(main)
    assert '"--execute"' in parser_source
    assert 'action="store_true"' in parser_source


def test_the_cli_offers_no_way_to_choose_a_period_or_a_target():
    """The periods come from configuration so that what the CLI does is what the
    scheduled sweep does. A CLI that could delete on its own terms would be a
    second, undocumented retention policy."""
    source = inspect.getsource(__import__("scripts.purge_audit", fromlist=["main"]))
    for forbidden in ("--days", "--older-than", "--before", "--category", "--decision", "--caller"):
        assert forbidden not in source


def test_sweep_logging_carries_counts_and_no_row_identity(monkeypatch: pytest.MonkeyPatch):
    """An audit-deletion log line that named the rows it removed would reproduce,
    in the log store, exactly what retention exists to remove from the database."""
    emitted: list[tuple[str, dict]] = []

    class _Logger:
        def info(self, event: str, **kw: object) -> None:
            emitted.append((event, dict(kw)))

        def warning(self, event: str, **kw: object) -> None:
            emitted.append((event, dict(kw)))

        def error(self, event: str, **kw: object) -> None:
            emitted.append((event, dict(kw)))

    monkeypatch.setattr(retention, "logger", _Logger())

    import asyncio

    class _Sweeper:
        async def sweep(self, *, dry_run: bool = False) -> retention.SweepReport:
            return retention.SweepReport(
                tables=(
                    retention.TableSweep(
                        table="request_traces",
                        cutoff=datetime.now(UTC),
                        deleted=5,
                        cascaded={"detector_results": 20},
                        budget_exhausted=True,
                    ),
                ),
                duration_s=0.01,
                dry_run=False,
            )

    scheduler = retention.RetentionScheduler(_Sweeper(), interval_s=1.0)  # type: ignore[arg-type]
    asyncio.run(scheduler.run_once())

    assert emitted, "the sweep reported nothing at all"
    for _event, fields in emitted:
        for value in fields.values():
            assert not isinstance(value, (bytes, dict, list))
        assert not {"request_id", "content_hash", "ids", "rows_deleted_ids"} & set(fields)
