"""Span-based redaction.

Redaction operates on the original text using spans relative to `raw_text`.
Getting offsets wrong here corrupts user-visible content, so the offset
arithmetic is tested directly rather than assumed.
"""

from __future__ import annotations

import pytest

from app.core.normalize import normalize
from app.core.types import TextSpan
from app.policy.redaction import apply_redactions, redaction_summary

pytestmark = pytest.mark.unit


def span(start: int, end: int, label: str = "EMAIL") -> TextSpan:
    return TextSpan(start=start, end=end, label=label)


def test_single_span_is_replaced_with_a_labelled_token():
    text = "Contact me at alice@example.com please"
    result = apply_redactions(text, [span(14, 31)])

    assert result == "Contact me at <EMAIL_REDACTED> please"


def test_surrounding_text_is_preserved_exactly():
    text = "prefix SECRET suffix"
    assert apply_redactions(text, [span(7, 13, "X")]) == "prefix <X_REDACTED> suffix"


def test_multiple_spans_all_replaced_with_correct_offsets():
    """Right-to-left application keeps earlier offsets valid as length changes."""
    text = "a@b.com and c@d.com and e@f.com"
    spans = [span(0, 7), span(12, 19), span(24, 31)]

    result = apply_redactions(text, spans)

    assert result == "<EMAIL_REDACTED> and <EMAIL_REDACTED> and <EMAIL_REDACTED>"


def test_span_order_does_not_matter():
    text = "a@b.com and c@d.com"
    forwards = apply_redactions(text, [span(0, 7), span(12, 19)])
    backwards = apply_redactions(text, [span(12, 19), span(0, 7)])

    assert forwards == backwards


def test_replacement_longer_than_the_span_keeps_later_offsets_valid():
    text = "x@y.z|a@b.c"
    result = apply_redactions(text, [span(0, 5), span(6, 11)])

    assert result == "<EMAIL_REDACTED>|<EMAIL_REDACTED>"


def test_empty_spans_returns_the_original_text():
    assert apply_redactions("unchanged", []) == "unchanged"


def test_custom_template_is_honoured():
    result = apply_redactions("secret", [span(0, 6, "pii")], template="[{entity}]")

    assert result == "[PII]"


def test_explicit_replacement_overrides_the_template():
    replacement_span = TextSpan(start=0, end=6, label="EMAIL", replacement="***")

    assert apply_redactions("secret", [replacement_span]) == "***"


@pytest.mark.parametrize(("start", "end"), [(0, 999), (100, 200)])
def test_out_of_range_spans_are_skipped_not_fatal(start: int, end: int):
    """A stale offset must not take down the request."""
    text = "short"
    assert apply_redactions(text, [TextSpan(start=start, end=end, label="X")]) == text


def test_zero_length_span_is_skipped():
    assert apply_redactions("abc", [span(1, 1, "X")]) == "abc"


def test_inverted_span_cannot_be_constructed():
    """An inverted span would splice rather than replace."""
    with pytest.raises(ValueError, match="precedes start"):
        TextSpan(start=5, end=2, label="X")


# --- Integration with normalisation (ADR-010) ------------------------------


def test_redaction_after_confusable_folding_hits_the_right_source_range():
    """Matching on folded text and redacting the original is the whole point of
    the index-preserving offset map."""
    text = "email: аlice@example.com now"  # leading Cyrillic 'а' (U+0430)
    result = normalize(text)

    start = result.text.index("alice@example.com")
    source = result.source_span(start, start + len("alice@example.com"), "EMAIL")

    assert source is not None
    redacted = apply_redactions(text, [source])
    assert redacted == "email: <EMAIL_REDACTED> now"


def test_redaction_removes_hidden_characters_inside_the_match():
    text = "email: al​ice@example.com end"  # zero-width space inside
    result = normalize(text)

    start = result.text.index("alice@example.com")
    source = result.source_span(start, start + len("alice@example.com"), "EMAIL")

    assert source is not None
    redacted = apply_redactions(text, [source])
    assert "​" not in redacted
    assert redacted == "email: <EMAIL_REDACTED> end"


# --- Audit summary ---------------------------------------------------------


def test_summary_counts_entities_without_recording_values():
    """An audit record of what was redacted must not contain the PII."""
    spans = [span(0, 5, "EMAIL"), span(10, 15, "EMAIL"), span(20, 25, "PHONE")]

    assert redaction_summary(spans) == {"EMAIL": 2, "PHONE": 1}
