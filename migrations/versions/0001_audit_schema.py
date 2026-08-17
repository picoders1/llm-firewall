"""Audit schema: request_traces, detector_results, security_events.

The first schema in the project, created only now that a real security pipeline
writes to it. No column can hold a prompt or a completion; that guarantee is
structural and is asserted by tests/security/test_audit_privacy.py
(docs/11-data-model.md, ADR-012).

Revision ID: 79f8a37ae46f
Revises:
Create Date: 2026-08-17 13:09:10.924316

Every revision must provide a working `downgrade`. Destructive changes are split
into expand/contract steps across releases so that a rollback never loses the
audit trail (docs/17-deployment-architecture.md).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "79f8a37ae46f"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "request_traces",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("upstream_host", sa.String(length=255), nullable=True),
        sa.Column("status_code", sa.SmallInteger(), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("block_category", sa.String(length=32), nullable=True),
        sa.Column("policy_version", sa.String(length=80), nullable=False),
        sa.Column("gateway_latency_ms", sa.Numeric(precision=10, scale=3), nullable=False),
        sa.Column("upstream_latency_ms", sa.Numeric(precision=10, scale=3), nullable=True),
        sa.Column("detector_latency_ms", sa.Numeric(precision=10, scale=3), nullable=False),
        sa.Column("normalization_latency_ms", sa.Numeric(precision=10, scale=3), nullable=False),
        sa.Column("policy_latency_ms", sa.Numeric(precision=10, scale=3), nullable=False),
        sa.Column("upstream_called", sa.Boolean(), nullable=False),
        sa.Column("input_chars", sa.Integer(), nullable=False),
        sa.Column("output_chars", sa.Integer(), nullable=False),
        sa.Column("inspected_messages", sa.Integer(), nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id"),
    )
    op.create_index("ix_request_traces_created_at", "request_traces", ["created_at"], unique=False)
    op.create_index(
        "ix_request_traces_decision_created_at",
        "request_traces",
        ["decision", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_request_traces_model_created_at",
        "request_traces",
        ["model", "created_at"],
        unique=False,
    )
    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("direction", sa.String(length=8), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=True),
        sa.Column("detector", sa.String(length=64), nullable=True),
        sa.Column("score", sa.Numeric(precision=6, scale=5), nullable=True),
        sa.Column("severity", sa.SmallInteger(), nullable=False),
        sa.Column("content_hash", sa.String(length=80), nullable=True),
        sa.Column("content_length", sa.Integer(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_events_category_created_at",
        "security_events",
        ["category", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_events_content_hash", "security_events", ["content_hash"], unique=False
    )
    op.create_index(
        "ix_security_events_created_at", "security_events", ["created_at"], unique=False
    )
    op.create_index(
        "ix_security_events_request_id", "security_events", ["request_id"], unique=False
    )
    op.create_table(
        "detector_results",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("trace_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("detector", sa.String(length=64), nullable=False),
        sa.Column("direction", sa.String(length=8), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("detected", sa.Boolean(), nullable=False),
        sa.Column("score", sa.Numeric(precision=6, scale=5), nullable=False),
        sa.Column("threshold", sa.Numeric(precision=6, scale=5), nullable=False),
        sa.Column("latency_ms", sa.Numeric(precision=10, scale=3), nullable=False),
        sa.Column("errored", sa.Boolean(), nullable=False),
        sa.Column("error_kind", sa.String(length=64), nullable=True),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["trace_id"], ["request_traces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_detector_results_detector_created_at",
        "detector_results",
        ["detector", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_detector_results_errored",
        "detector_results",
        ["errored"],
        unique=False,
        postgresql_where=sa.text("errored IS true"),
    )
    op.create_index("ix_detector_results_trace_id", "detector_results", ["trace_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_detector_results_trace_id", table_name="detector_results")
    op.drop_index(
        "ix_detector_results_errored",
        table_name="detector_results",
        postgresql_where=sa.text("errored IS true"),
    )
    op.drop_index("ix_detector_results_detector_created_at", table_name="detector_results")
    op.drop_table("detector_results")
    op.drop_index("ix_security_events_request_id", table_name="security_events")
    op.drop_index("ix_security_events_created_at", table_name="security_events")
    op.drop_index("ix_security_events_content_hash", table_name="security_events")
    op.drop_index("ix_security_events_category_created_at", table_name="security_events")
    op.drop_table("security_events")
    op.drop_index("ix_request_traces_model_created_at", table_name="request_traces")
    op.drop_index("ix_request_traces_decision_created_at", table_name="request_traces")
    op.drop_index("ix_request_traces_created_at", table_name="request_traces")
    op.drop_table("request_traces")
