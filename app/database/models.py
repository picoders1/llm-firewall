"""Audit schema.

Three tables — the minimum that lets an operator reconstruct what happened:
`request_traces` (one row per request), `detector_results` (one row per detector
per direction), `security_events` (append-only record of non-benign outcomes).

`policy_decisions` and the evaluation tables in docs/11-data-model.md are
deliberately **not** created yet: nothing writes them, and a table nobody writes
is schema nobody can justify.

## The structural privacy guarantee

There is **no column anywhere that can hold a prompt or a completion.** Not a
truncated one, not an optional one. Adding one requires a new column, which is a
visible migration and a reviewable decision rather than a one-line change
(ADR-012). `tests/security/test_audit_privacy.py` asserts this against the
metadata, so the guarantee is enforced by the test suite and not by memory.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base

# Column names that would imply stored content. Enforced by test, and listed here
# so the intent is visible at the point someone would add one.
FORBIDDEN_COLUMN_SUBSTRINGS: tuple[str, ...] = (
    "prompt",
    "completion",
    "content_text",
    "raw_",
    "message_text",
    "response_body",
    "api_key",
    "token",
    "password",
    "authorization",
)


class RequestTraceRow(Base):
    __tablename__ = "request_traces"

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    model: Mapped[str | None] = mapped_column(String(128))
    # Host only — never a full URL, which can carry a query string.
    upstream_host: Mapped[str | None] = mapped_column(String(255))
    # WHICH APPLICATION called, never HOW it proved it (ADR-024 §20). The
    # identifier is an operator-chosen label from configuration, so it carries no
    # secret and cannot be influenced by the caller. `NULL` means the request
    # predates caller authentication or arrived while the boundary was off —
    # which is a different fact from "anonymous" and is recorded as such.
    caller_id: Mapped[str | None] = mapped_column(String(64))
    status_code: Mapped[int] = mapped_column(SmallInteger, nullable=False)

    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    block_category: Mapped[str | None] = mapped_column(String(32))
    policy_version: Mapped[str] = mapped_column(String(80), nullable=False)

    gateway_latency_ms: Mapped[float] = mapped_column(Numeric(10, 3), nullable=False)
    upstream_latency_ms: Mapped[float | None] = mapped_column(Numeric(10, 3))
    detector_latency_ms: Mapped[float] = mapped_column(Numeric(10, 3), default=0)
    normalization_latency_ms: Mapped[float] = mapped_column(Numeric(10, 3), default=0)
    policy_latency_ms: Mapped[float] = mapped_column(Numeric(10, 3), default=0)

    upstream_called: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    input_chars: Mapped[int] = mapped_column(Integer, default=0)
    output_chars: Mapped[int] = mapped_column(Integer, default=0)
    inspected_messages: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)

    detector_results: Mapped[list[DetectorResultRow]] = relationship(
        back_populates="trace", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_request_traces_created_at", "created_at"),
        Index("ix_request_traces_decision_created_at", "decision", "created_at"),
        Index("ix_request_traces_model_created_at", "model", "created_at"),
    )


class DetectorResultRow(Base):
    """One detector's result. Scores from detectors that did *not* fire are
    recorded too — that is what makes retrospective threshold tuning possible."""

    __tablename__ = "detector_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    trace_id: Mapped[int] = mapped_column(
        ForeignKey("request_traces.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    detector: Mapped[str] = mapped_column(String(64), nullable=False)
    direction: Mapped[str] = mapped_column(String(8), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    detected: Mapped[bool] = mapped_column(Boolean, nullable=False)
    score: Mapped[float] = mapped_column(Numeric(6, 5), nullable=False)
    # The threshold in force at decision time; without it an old row cannot be
    # interpreted after a policy change.
    threshold: Mapped[float] = mapped_column(Numeric(6, 5), nullable=False)
    latency_ms: Mapped[float] = mapped_column(Numeric(10, 3), default=0)
    errored: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error_kind: Mapped[str | None] = mapped_column(String(64))
    # Rule identifiers only — never matched text.
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Bounded enums (6 and 5 values). Recorded so an operator can ask which
    # origin an attack arrived through; never used to make the decision.
    provenance: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    trust: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)

    trace: Mapped[RequestTraceRow] = relationship(back_populates="detector_results")

    __table_args__ = (
        Index("ix_detector_results_trace_id", "trace_id"),
        Index("ix_detector_results_detector_created_at", "detector", "created_at"),
        Index(
            "ix_detector_results_errored",
            "errored",
            postgresql_where=(errored.is_(True)),
        ),
    )


class SecurityEventRow(Base):
    """Append-only record of non-benign outcomes.

    Denormalised on purpose: an auditor reads one table, and it survives
    independently of the trace tables' retention.
    """

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    direction: Mapped[str] = mapped_column(String(8), nullable=False)
    category: Mapped[str | None] = mapped_column(String(32))
    detector: Mapped[str | None] = mapped_column(String(64))
    score: Mapped[float | None] = mapped_column(Numeric(6, 5))
    severity: Mapped[int] = mapped_column(SmallInteger, default=5, nullable=False)

    # Fingerprint, not content. Indexed so "has this exact payload been tried
    # before" is a GROUP BY rather than a forensic exercise.
    content_hash: Mapped[str | None] = mapped_column(String(80))
    content_length: Mapped[int | None] = mapped_column(Integer)

    # Bounded, label-only detail: entity types and counts, rule ids, offsets.
    details: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    provenance: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    trust: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)

    __table_args__ = (
        Index("ix_security_events_created_at", "created_at"),
        Index("ix_security_events_category_created_at", "category", "created_at"),
        # The dashboard's two most common filters. Deliberately no index on
        # provenance/trust: at present those columns are overwhelmingly one
        # value, so an index would not be selective. Add one when the
        # distribution justifies it, not before (docs/12-observability.md).
        Index("ix_security_events_event_type_created_at", "event_type", "created_at"),
        Index("ix_security_events_detector_created_at", "detector", "created_at"),
        Index("ix_security_events_content_hash", "content_hash"),
        Index("ix_security_events_request_id", "request_id"),
    )
