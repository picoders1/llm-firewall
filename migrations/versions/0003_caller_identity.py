"""Record which application made each gateway request.

Phase 10 caller authentication (ADR-024). One additive, nullable column.

`caller_id` holds an operator-chosen label from `FIREWALL_CALLER_API_KEYS` — the
same value that appears in the `firewall_caller_requests_total` metric. It is
**not** a credential, not a hash of one, and not anything the caller can
influence: an unrecognised identity never becomes a principal, so only configured
labels reach this column.

**Nullable on purpose, and it stays nullable.** `NULL` means the request arrived
before caller authentication existed, or while the boundary was switched off in
development. That is a genuinely different fact from "an anonymous caller", and
backfilling either a placeholder or a guess would put a claim in the audit trail
that nobody made. An audit row that is confidently wrong is worse than one that
is honestly blank (the same reasoning as `decision = NULL` in 0001).

No index. The dashboard does not filter by caller today, and an index on a column
with a handful of distinct values would not be selective. Add one when a query
needs it.

Revision ID: 6b2f4c8d1a09
Revises: 3c1d90b4e2a7
Create Date: 2026-08-19

`downgrade` drops exactly what `upgrade` added, so a rollback cannot lose the
audit trail (docs/17-deployment-architecture.md).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "6b2f4c8d1a09"
down_revision: str | None = "3c1d90b4e2a7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("request_traces", sa.Column("caller_id", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("request_traces", "caller_id")
