#!/usr/bin/env python3
"""Seed backdated audit rows into the DISPOSABLE fault database (ADR-035, Fixture C).

    uv run python scripts/seed_backdated_audit.py              # dry run: writes nothing
    uv run python scripts/seed_backdated_audit.py --execute    # actually inserts

Exists for exactly one alert: **#11 `FirewallAuditBacklogExceedsRetention`**, which
compares `firewall_audit_oldest_row_age_seconds` against the configured period.
Producing that condition needs rows older than 1.5x the period, and the only
honest way to have a 10-day-old row today is to write one with a 10-day-old
`created_at`.

**The alert also needs sweeps to SUCCEED while never keeping up.** A failing sweep
raises before `RetentionSweeper._observe()` and never sets the gauge at all, so
the numerator would not exist. `compose.fault.yaml` therefore pairs this backlog
with `FIREWALL_RETENTION_MAX_ROWS_PER_SWEEP=1`: each sweep deletes one row,
exhausts its budget, and reports the oldest survivor.

## What this refuses to do

**It inserts. It never updates and never deletes** — there is no code path here
that removes a row, because a tool that can both fabricate and erase audit history
is a tool for rewriting it. Deletion belongs to `scripts/purge_audit.py`, which
deletes by age and by nothing else.

**It refuses to run anywhere but the fault database.** Host, port and role are
identical between the development stack and the fault stack, so the database NAME
is the only thing that can carry the distinction — `compose.fault.yaml` sets
`firewall_fault` for precisely this check. Pointing it at `firewall` is refused,
not warned about.

**It refuses to run in production**, on `FIREWALL_ENVIRONMENT` and on the resolved
setting, whichever says production first.

**Dry run is the default and `--execute` is required**, for the reason
`purge_audit.py` gives: a tool that mutates when invoked with no arguments will
eventually be invoked with no arguments by someone who wanted to see what it does.

Every row it writes is marked — `request_id` prefixed `fault-seed-`, `caller_id`
and `policy_version` both `fault-seed` — so seeded history is never mistaken for
observed history in an evaluation artefact. The rows carry no content: the audit
schema has no column that can hold a prompt (ADR-012), and this changes nothing
about that.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, insert, select
from sqlalchemy.engine import make_url

from app.config.settings import Settings
from app.database.models import RequestTraceRow
from app.database.session import Database

# The one database this script may write to. Not configurable: an override flag
# would defeat the check, and the fault stack is the only place it belongs.
FAULT_DATABASE = "firewall_fault"

SEED_MARKER = "fault-seed"
BATCH = 500


class Refused(RuntimeError):
    """A safety precondition failed. Nothing has been written."""


def _resolve_database_name(settings: Settings) -> str:
    if not settings.persist_events or settings.database_url is None:
        raise Refused(
            "No audit database is configured. Export FIREWALL_PERSIST_EVENTS=true and "
            "FIREWALL_DATABASE_URL for the FAULT stack, e.g.\n"
            "  FIREWALL_DATABASE_URL=postgresql+asyncpg://firewall:firewall@localhost:5435/"
            f"{FAULT_DATABASE}"
        )
    name = make_url(settings.database_url.get_secret_value()).database
    return name or ""


def _check_preconditions(settings: Settings) -> str:
    """Every refusal, before a connection is opened. Returns the database name."""
    declared = os.environ.get("FIREWALL_ENVIRONMENT", "").strip().lower()
    if declared == "production" or settings.is_production:
        raise Refused(
            "FIREWALL_ENVIRONMENT is production. This script fabricates audit history; "
            "there is no circumstance in which that belongs in a production trail."
        )

    name = _resolve_database_name(settings)
    if name != FAULT_DATABASE:
        raise Refused(
            f"Refusing to write to database {name!r}. This script only ever writes to "
            f"{FAULT_DATABASE!r}, the disposable store created by compose.fault.yaml on "
            "the firewall-fault-pgdata volume. The development database holds an audit "
            "trail that is not this fixture's to invent."
        )
    return name


def _rows(now: datetime, count: int, age_days: float) -> list[dict[str, object]]:
    """`count` traces, all `age_days` old, spread over a minute so `min(created_at)`
    is stable rather than a tie across identical timestamps."""
    created = now - timedelta(days=age_days)
    return [
        {
            "request_id": f"{SEED_MARKER}-{uuid.uuid4().hex}",
            "created_at": created + timedelta(seconds=i % 60),
            "model": "seeded",
            "upstream_host": None,
            "caller_id": SEED_MARKER,
            "status_code": 200,
            "decision": "allow",
            "block_category": None,
            "policy_version": SEED_MARKER,
            "gateway_latency_ms": 0,
            "upstream_latency_ms": None,
            "upstream_called": False,
            "input_chars": 0,
            "output_chars": 0,
            "inspected_messages": 0,
            "truncated": False,
        }
        for i in range(count)
    ]


async def _run(*, execute: bool, count: int, age_days: float) -> int:
    settings = Settings()
    try:
        database_name = _check_preconditions(settings)
    except Refused as refusal:
        print(f"REFUSED: {refusal}", file=sys.stderr)
        return 2

    database = Database.from_settings(settings)
    if database is None:  # pragma: no cover - _check_preconditions already covers this
        print("REFUSED: no database handle could be built.", file=sys.stderr)
        return 2

    period_days = settings.retention_trace_days
    bound_days = 1.5 * period_days

    try:
        async with database.session() as session:
            # The database's clock, not this process's — the same choice ADR-030
            # makes in the sweeper, so the seeded age and the swept age agree.
            now = (await session.execute(select(func.now()))).scalar_one()
            if not isinstance(now, datetime):  # pragma: no cover - PostgreSQL is tz-aware
                raise TypeError(f"database clock returned {type(now).__name__}")
            if now.tzinfo is None:  # pragma: no cover - PostgreSQL is tz-aware
                now = now.replace(tzinfo=UTC)
            existing = await session.scalar(select(func.count()).select_from(RequestTraceRow))
            oldest = await session.scalar(select(func.min(RequestTraceRow.created_at)))

        print(f"database        : {database_name}  (clock {now.isoformat(timespec='seconds')})")
        print(f"existing traces : {existing:,}")
        if oldest is not None:
            if oldest.tzinfo is None:  # pragma: no cover - PostgreSQL is tz-aware
                oldest = oldest.replace(tzinfo=UTC)
            print(f"oldest trace    : {(now - oldest).total_seconds() / 86400:.2f} days")
        print(f"retention period: {period_days} day(s); #11 fires above {bound_days:.1f} days")
        print(f"to insert       : {count:,} traces backdated {age_days} days")

        if age_days <= bound_days:
            print(
                f"\nWARNING: {age_days} days does not exceed the 1.5x bound "
                f"({bound_days:.1f} days). #11 will NOT fire on these rows.",
                file=sys.stderr,
            )

        if not execute:
            print("\nDry run. Nothing was written. Re-run with --execute to insert.\n")
            return 0

        payload = _rows(now, count, age_days)
        written = 0
        for start in range(0, len(payload), BATCH):
            chunk = payload[start : start + BATCH]
            async with database.session() as session:
                await session.execute(insert(RequestTraceRow), chunk)
                await session.commit()
            written += len(chunk)

        async with database.session() as session:
            oldest_now = await session.scalar(select(func.min(RequestTraceRow.created_at)))
        if oldest_now is not None and oldest_now.tzinfo is None:  # pragma: no cover
            oldest_now = oldest_now.replace(tzinfo=UTC)
        age = (now - oldest_now).total_seconds() / 86400 if oldest_now else 0.0
        print(f"\ninserted        : {written:,} traces")
        print(f"oldest trace    : {age:.2f} days — #11 bound is {bound_days:.1f} days")
        print(
            "\nThe gauge only appears after a SUCCESSFUL sweep: retention must be enabled "
            "and the database reachable. compose.fault.yaml sweeps every 30 s with a "
            "one-row budget, which is what makes deletion succeed while never keeping up.\n"
        )
        return 0
    finally:
        await database.aclose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--execute",
        action="store_true",
        help="actually insert. Without it, this reports what it would write and changes nothing.",
    )
    parser.add_argument(
        "--rows",
        type=int,
        default=5_000,
        help="how many backdated traces to insert (default: 5000)",
    )
    parser.add_argument(
        "--age-days",
        type=float,
        default=10.0,
        help="how far back to date them (default: 10, against a 1-day fault period)",
    )
    args = parser.parse_args(argv)
    if args.rows <= 0:
        parser.error("--rows must be positive")
    if args.age_days <= 0:
        parser.error("--age-days must be positive")

    try:
        return asyncio.run(_run(execute=args.execute, count=args.rows, age_days=args.age_days))
    except KeyboardInterrupt:  # pragma: no cover - interactive
        print("\nInterrupted. Batches already committed stay committed.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
