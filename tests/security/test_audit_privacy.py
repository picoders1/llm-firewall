"""The audit schema cannot hold content — asserted structurally.

ADR-012 promises that adding prompt storage requires a visible migration rather
than a one-line change. That promise is only real if something checks the schema,
so this reads the SQLAlchemy metadata directly. It fails the moment a
content-bearing column is introduced, regardless of whether any code writes to it.
"""

from __future__ import annotations

import pytest
from sqlalchemy import String, Text

from app.database.models import (
    FORBIDDEN_COLUMN_SUBSTRINGS,
    DetectorResultRow,
    RequestTraceRow,
    SecurityEventRow,
)
from app.database.session import Base

pytestmark = [pytest.mark.security, pytest.mark.unit]

AUDIT_TABLES = (RequestTraceRow, DetectorResultRow, SecurityEventRow)

# Columns allowed to be free-form strings, with the reason each is safe.
ALLOWED_TEXT_COLUMNS = {
    ("request_traces", "request_id"),  # correlation id, validated charset
    ("request_traces", "model"),  # model name from the request
    ("request_traces", "upstream_host"),  # host only, never a full URL
    ("request_traces", "decision"),  # enum value
    ("request_traces", "block_category"),  # enum value
    ("request_traces", "policy_version"),  # hash
    ("detector_results", "detector"),  # registry name
    ("detector_results", "direction"),  # enum value
    ("detector_results", "category"),  # enum value
    ("detector_results", "error_kind"),  # exception class name
    ("security_events", "request_id"),
    ("security_events", "event_type"),
    ("security_events", "direction"),
    ("security_events", "category"),
    ("security_events", "detector"),
    ("security_events", "content_hash"),  # fingerprint, not content
}


def test_no_audit_column_name_implies_stored_content():
    for table in AUDIT_TABLES:
        for column in table.__table__.columns:
            lowered = column.name.lower()
            for forbidden in FORBIDDEN_COLUMN_SUBSTRINGS:
                assert forbidden not in lowered, (
                    f"{table.__tablename__}.{column.name} looks like it stores content "
                    f"or a secret. Adding one requires an ADR amendment (ADR-012)."
                )


def test_every_free_text_column_is_explicitly_accounted_for():
    """A new string column must be justified here, which is the review gate."""
    for table in AUDIT_TABLES:
        for column in table.__table__.columns:
            if not isinstance(column.type, String | Text):
                continue
            key = (table.__tablename__, column.name)
            assert key in ALLOWED_TEXT_COLUMNS, (
                f"unreviewed free-text column {key}: justify it in "
                f"ALLOWED_TEXT_COLUMNS or store a hash instead"
            )


def test_no_unbounded_text_columns():
    """`Text` is unbounded; a bounded `String(n)` cannot silently accumulate a
    prompt."""
    for table in AUDIT_TABLES:
        for column in table.__table__.columns:
            assert not isinstance(column.type, Text), (
                f"{table.__tablename__}.{column.name} is unbounded Text"
            )
            if isinstance(column.type, String):
                assert column.type.length is not None
                # Long enough for hashes and identifiers, far too short for a prompt.
                assert column.type.length <= 255


def test_only_the_expected_tables_exist():
    """Phase 0 creates three tables. `policy_decisions` and the evaluation tables
    are deliberately deferred until something writes them."""
    assert set(Base.metadata.tables) == {
        "request_traces",
        "detector_results",
        "security_events",
    }


def test_content_hash_is_a_fingerprint_column_not_a_content_column():
    column = SecurityEventRow.__table__.columns["content_hash"]
    assert isinstance(column.type, String)
    # sha256: + 16 hex chars is 23; the bound leaves no room for a prompt.
    assert column.type.length <= 80


def test_details_column_is_json_not_free_text():
    """Structured, so what goes in it is reviewable — labels, counts, offsets."""
    from sqlalchemy import JSON

    assert isinstance(SecurityEventRow.__table__.columns["details"].type, JSON)
    assert isinstance(DetectorResultRow.__table__.columns["reasons"].type, JSON)
