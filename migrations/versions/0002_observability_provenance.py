"""Record provenance/trust on audit rows, and index the dashboard's hot filters.

Phase 5 observability. Two changes, both additive:

1. `detector_results` and `security_events` gain `provenance` and `trust`. The
   values already exist at request time — `app.core.provenance` derives them from
   the message role — they were simply never persisted. Recording them is what
   lets an operator ask "did this arrive in retrieved content?" without re-running
   anything. **Neither column can hold a caller-supplied string**: provenance is
   derived from role, `trust_inline_provenance_claims` defaults to False, and both
   are closed enums (6 and 5 values). They are recorded and never consulted by the
   decision (ADR-017).

2. Two indexes on `security_events` for the filters the dashboard actually uses:
   event_type and detector, each paired with created_at. Deliberately **no** index
   on provenance/trust — at present those columns are overwhelmingly a single
   value, so an index would not be selective. Add one when the distribution
   justifies it (docs/12-observability.md, §18 of the Phase 5 brief).

Backfill is `'unknown'`, which is the honest value for rows written before the
columns existed — not a guess at what the provenance would have been.

Revision ID: 3c1d90b4e2a7
Revises: 79f8a37ae46f
Create Date: 2026-08-18

`downgrade` drops what `upgrade` added and nothing else, so a rollback cannot lose
the audit trail (docs/17-deployment-architecture.md).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "3c1d90b4e2a7"
down_revision: str | None = "79f8a37ae46f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = ("detector_results", "security_events")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(
            table,
            sa.Column(
                "provenance",
                sa.String(length=16),
                nullable=False,
                server_default="unknown",
            ),
        )
        op.add_column(
            table,
            sa.Column(
                "trust",
                sa.String(length=16),
                nullable=False,
                server_default="unknown",
            ),
        )

    op.create_index(
        "ix_security_events_event_type_created_at",
        "security_events",
        ["event_type", "created_at"],
    )
    op.create_index(
        "ix_security_events_detector_created_at",
        "security_events",
        ["detector", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_security_events_detector_created_at", table_name="security_events")
    op.drop_index("ix_security_events_event_type_created_at", table_name="security_events")
    for table in _TABLES:
        op.drop_column(table, "trust")
        op.drop_column(table, "provenance")
