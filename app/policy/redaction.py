"""Span-based redaction.

Labelled tokens rather than fixed-width masks: the text stays readable, the
sentence keeps the structure the model needs, and the caller can see what was
removed (docs/08-pii-security.md).

Redaction operates on the **original** text using spans the detector reported,
which are always relative to ``DetectionContext.raw_text``. This is what the
index-preserving offset map in :mod:`app.core.normalize` exists to make possible:
matching on folded text while replacing exactly the right source range.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.core.types import TextSpan


def apply_redactions(
    text: str,
    spans: Sequence[TextSpan],
    *,
    template: str = "<{entity}_REDACTED>",
) -> str:
    """Replace each span in `text` with its labelled token.

    Spans are applied right-to-left so that earlier offsets remain valid as the
    string length changes. Spans outside the text are skipped rather than raising:
    a detector reporting a stale offset must not take down the request, and the
    engine has already merged overlaps.
    """
    if not spans:
        return text

    ordered = sorted(spans, key=lambda s: s.start, reverse=True)
    result = text
    for span in ordered:
        if span.start < 0 or span.end > len(result) or span.start >= span.end:
            continue
        replacement = span.replacement or template.format(entity=span.label.upper())
        result = result[: span.start] + replacement + result[span.end :]
    return result


def redaction_summary(spans: Sequence[TextSpan]) -> dict[str, int]:
    """Count redactions by entity label, for the audit record.

    Labels and counts only. An audit record of what was redacted must never
    contain the redacted values (docs/10-security-model.md).
    """
    summary: dict[str, int] = {}
    for span in spans:
        summary[span.label] = summary.get(span.label, 0) + 1
    return summary
