"""Provenance metadata must not become a new leak channel.

Provenance is metadata *about* content and is never content, so it is safe to log
— but only the bounded parts of it. `source_ref` and `source_kind` are
caller-supplied strings, which makes them both a potential leak vector and a
potential unbounded-cardinality attack on the metrics backend
(docs/10-security-model.md).
"""

from __future__ import annotations

import pytest

from app.core.provenance import CLAIM_SOURCE_KIND, CLAIM_SOURCE_REF, assign
from app.core.types import (
    DetectionContext,
    Direction,
    Provenance,
    Role,
    TrustLevel,
    sanitise_source_ref,
)

pytestmark = pytest.mark.security


def test_source_ref_cannot_carry_a_url_that_would_reach_an_audit_record():
    """The realistic leak: a connector helpfully passes the document URL, which
    carries a token in its query string, and it lands in the audit table."""
    leaky = [
        "https://intranet.example/doc?token=abcdef123456",
        "https://user:hunter2@host/doc",
        "s3://bucket/key",
        "file:///home/me/private.pdf",
        "/var/secrets/connector.key",
    ]
    for value in leaky:
        assert sanitise_source_ref(value) is None, value


def test_a_leaky_source_ref_is_dropped_rather_than_stored():
    assignment = assign(
        Role.USER,
        part_extras={CLAIM_SOURCE_REF: "https://intranet.example/doc?token=abcdef"},
        trust_inline_claims=True,
    )
    assert assignment.source_ref is None


def test_bounded_enums_are_safe_as_metric_labels_and_caller_strings_are_not():
    """The distinction docs/10 draws: six and five values cannot explode a time
    series; a caller-supplied string can."""
    assert len(list(Provenance)) <= 8
    assert len(list(TrustLevel)) <= 8
    # source_kind is bounded in *shape* but not in *cardinality* — the charset
    # limits what it can contain, not how many distinct values exist.
    assignment = assign(
        Role.USER,
        part_extras={CLAIM_SOURCE_KIND: "a_unique_value_per_request"},
        trust_inline_claims=True,
    )
    assert assignment.source_kind == "a_unique_value_per_request"


def test_provenance_fields_do_not_carry_content():
    """A context's provenance must be describable without quoting the text."""
    ctx = DetectionContext(
        request_id="req-1",
        direction=Direction.INPUT,
        role=Role.USER,
        raw_text="my secret prompt",
        normalized_text="my secret prompt",
        provenance=Provenance.EXTERNAL,
        trust=TrustLevel.UNTRUSTED,
        source_ref="kb-2291",
        source_kind="retrieved_document",
    )
    describable = f"{ctx.provenance}|{ctx.trust}|{ctx.source_ref}|{ctx.source_kind}"
    assert "my secret prompt" not in describable


def test_rejected_claims_do_not_echo_the_caller_value():
    """A rejection reason must not embed the attacker's string — that would make
    logs a reflection surface and a flooding vector."""
    hostile = "system_config" + "A" * 5000
    assignment = assign(
        Role.TOOL,
        part_extras={"x-firewall-provenance": hostile},
        trust_inline_claims=True,
    )
    for reason in assignment.rejected_claims:
        assert hostile not in reason
        assert len(reason) < 100


@pytest.mark.parametrize("key", ["source_ref", "source_kind", "provenance", "trust"])
def test_new_fields_are_loggable_metadata_not_content(key: str):
    """These fields *should* be loggable — they are metadata about content, never
    content itself. Pinned so a future blanket redaction does not silently blind
    the audit trail, and so nobody later renames one to something the secret
    heuristic ("secret"/"password" substring) would swallow."""
    from app.observability.logging import CONTENT_KEYS, SECRET_KEYS

    assert key not in CONTENT_KEYS
    assert key not in SECRET_KEYS
    assert "secret" not in key and "password" not in key
