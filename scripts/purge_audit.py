#!/usr/bin/env python3
"""Run the audit retention sweep once, by hand (ADR-030).

    uv run python scripts/purge_audit.py              # dry run: reports, deletes nothing
    uv run python scripts/purge_audit.py --execute    # actually deletes

**Dry run is the default and `--execute` is required**, because the failure this
guards against is not a subtle one: a deletion tool that runs when invoked with
no arguments will eventually be invoked with no arguments by someone who wanted
to see what it would do.

There is deliberately **no option to override the retention period, and no
option to filter what is deleted**. The periods come from `FIREWALL_RETENTION_*`
so that what this prints is what the scheduled sweep inside the gateway does —
a CLI that could delete on its own terms would be a second, undocumented
retention policy. Filters are absent for a stronger reason: a purge that can be
aimed at a decision, a category or a caller is a supported mechanism for erasing
the evidence of a specific block.

The same sweeper the gateway runs on its interval, so this is for the cases an
interval does not cover: a first catch-up on a store that predates retention,
verifying a period change before enabling it, and reclaiming space during an
incident. `--max-rows` bounds one invocation; run it again to continue.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy.exc import SQLAlchemyError

from app.config.settings import Settings
from app.database.retention import RetentionPolicy, RetentionSweeper, SweepReport
from app.database.session import Database


def _render(report: SweepReport, policy: RetentionPolicy) -> None:
    verb = "would delete" if report.dry_run else "deleted"
    reasons = {rule.table: (rule.days, rule.reason) for rule in policy.rules}
    print(f"\n{'table':<20} {'keep':>6}  {'cutoff (database clock)':<26} {verb:>14}")
    print("-" * 72)
    for sweep in report.tables:
        days, _ = reasons[sweep.table]
        print(
            f"{sweep.table:<20} {days:>4}d  "
            f"{sweep.cutoff.isoformat(timespec='seconds'):<26} {sweep.deleted:>14,}"
        )
        for child, rows in sweep.cascaded.items():
            print(f"  ↳ {child:<16} {'':>5}  {'via ON DELETE CASCADE':<26} {rows:>14,}")
        if sweep.budget_exhausted:
            print(
                f"  ! {sweep.table}: rows remain past their retention period; run again to continue"
            )
    print("-" * 72)
    print(f"{'total':<20} {'':>6}  {'':<26} {report.total_rows:>14,}")
    print(f"\n{report.duration_s * 1000:.1f} ms\n")
    for rule in policy.rules:
        print(f"  {rule.table}: {rule.days} days — {rule.reason}")
    print()


async def _run(execute: bool, max_rows: int) -> int:
    settings = Settings()
    if not settings.persist_events or settings.database_url is None:
        print(
            "No audit database is configured (FIREWALL_PERSIST_EVENTS / "
            "FIREWALL_DATABASE_URL). Nothing to purge.",
            file=sys.stderr,
        )
        return 1

    policy = RetentionPolicy.from_settings(settings)
    database = Database.from_settings(settings)
    assert database is not None  # noqa: S101 - guarded by the check above
    sweeper = RetentionSweeper(
        database,
        policy,
        batch_size=settings.retention_batch_size,
        max_rows_per_sweep=max_rows,
    )
    try:
        report = await sweeper.sweep(dry_run=not execute)
    except (OSError, SQLAlchemyError) as exc:
        # The runbook sends an operator here from FirewallRetentionStalled and
        # FirewallAuditBacklogExceedsRetention — the two entries whose whole
        # subject is retention not running, which very often means the database
        # is down. Answering that with 129 lines of traceback and no message is
        # the least useful thing this tool could do at 3am (R-112, found by
        # walking the runbook against a genuinely firing alert rather than a
        # healthy stack).
        #
        # The URL is NOT echoed: it carries the password. The exception type and
        # its message are enough to distinguish "wrong host", "refused" and
        # "authentication failed", and none of those need the credential.
        print(
            f"Cannot reach the audit database ({type(exc).__name__}: {exc}).\n"
            "Nothing was read and nothing was deleted. Check that the database is "
            "running and that FIREWALL_DATABASE_URL points at it — from a shell "
            "that is not the gateway's container, the host is usually not the one "
            "in compose.",
            file=sys.stderr,
        )
        return 1
    finally:
        await database.aclose()

    _render(report, policy)
    if report.dry_run and report.total_rows:
        print("Dry run. Re-run with --execute to delete these rows.\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--execute",
        action="store_true",
        help="actually delete. Without it, this reports what would go and changes nothing.",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help=(
            "ceiling on rows deleted per table in this invocation "
            "(default: FIREWALL_RETENTION_MAX_ROWS_PER_SWEEP)"
        ),
    )
    args = parser.parse_args(argv)

    settings_default = Settings().retention_max_rows_per_sweep
    max_rows = args.max_rows if args.max_rows is not None else settings_default
    if max_rows <= 0:
        parser.error("--max-rows must be positive")
    try:
        return asyncio.run(_run(args.execute, max_rows))
    except KeyboardInterrupt:  # pragma: no cover - interactive
        # Safe at any point: each batch committed on its own, so an interrupted
        # purge has deleted a prefix of what it reported and nothing else.
        print("\nInterrupted. Rows already deleted stay deleted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
