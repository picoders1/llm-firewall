"""The policy engine — the only component that decides.

A **pure function** of ``(results, config, direction)``. No I/O, no clock, no
logging, no global state, no randomness. Same inputs produce the same output,
always.

That purity is not stylistic. It is what makes the entire security decision
surface an exhaustive truth table testable in milliseconds with no models, no
HTTP and no database (docs/06-policy-engine.md,
docs/adr/ADR-003-policy-engine-design.md).

Because the engine cannot log, :class:`~app.core.types.PolicyDecision` is
self-describing: the caller persists it and the reasoning survives.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.config.policy import DetectorPolicy, PolicyConfig
from app.core.types import (
    ACTION_PRECEDENCE,
    Action,
    Category,
    DetectionResult,
    Direction,
    ErrorPolicy,
    PolicyDecision,
    TextSpan,
)


def is_more_severe(candidate: Action, current: Action) -> bool:
    """Severity comparison, so callers never re-implement the ordering.

    A request may inspect several messages, each producing its own decision.
    Aggregating them is a severity comparison, not a merge: spans belong to one
    specific string and merging them across messages would corrupt content.
    """
    return ACTION_PRECEDENCE[candidate] > ACTION_PRECEDENCE[current]


def _merge_spans(spans: Sequence[TextSpan]) -> tuple[TextSpan, ...]:
    """Union overlapping or adjacent spans, longest label wins on overlap.

    Two detectors flagging overlapping ranges must not produce two replacements
    on the same text, which would corrupt the output.
    """
    if not spans:
        return ()
    ordered = sorted(spans, key=lambda s: (s.start, -len(s)))
    merged: list[TextSpan] = [ordered[0]]
    for span in ordered[1:]:
        last = merged[-1]
        if span.start <= last.end:
            if span.end > last.end:
                merged[-1] = TextSpan(
                    start=last.start,
                    end=span.end,
                    label=last.label if len(last) >= len(span) else span.label,
                )
        else:
            merged.append(span)
    return tuple(merged)


class _Contribution:
    """One detector's contribution to the decision."""

    __slots__ = ("action", "category", "detector", "reason")

    def __init__(self, action: Action, category: Category, detector: str, reason: str) -> None:
        self.action = action
        self.category = category
        self.detector = detector
        self.reason = reason


def _contribution(result: DetectionResult, entry: DetectorPolicy) -> _Contribution | None:
    """Map one detection result to a contribution, or None if it contributes nothing."""
    if result.errored:
        if entry.on_error is ErrorPolicy.FAIL_CLOSED:
            # A detector that stopped inspecting is an availability failure, not
            # an attack; it gets its own category so it can never be counted as
            # a detection in any security metric (ADR-007).
            return _Contribution(
                action=Action.BLOCK,
                category=Category.DETECTOR_FAILURE,
                detector=result.detector,
                reason=f"{result.detector}:fail_closed:{result.error_kind or 'error'}",
            )
        return None

    if result.score >= entry.threshold:
        return _Contribution(
            action=entry.action,
            category=result.category,
            detector=result.detector,
            reason=f"{result.detector}:score={result.score:.4f}>=threshold={entry.threshold:.4f}",
        )
    return None


def evaluate(
    results: Sequence[DetectionResult],
    config: PolicyConfig,
    direction: Direction,
) -> PolicyDecision:
    """Convert detection evidence into exactly one action.

    Selection is by **severity precedence** — ``BLOCK > REDACT > WARN > ALLOW`` —
    which has two properties worth stating:

    * **Order-independent.** The outcome does not depend on the order detectors
      ran or were configured.
    * **Monotone.** Adding a detector can only make a decision more severe. A new
      detector can never silently weaken an existing protection.

    There is no voting and no averaging. An ALLOW is not evidence of safety, only
    the absence of evidence of one particular attack, so it never outvotes a
    positive finding. The cost — false positives compound across detectors — is
    real, measured, and the reason ``WARN`` exists as a staging state.
    """
    contributions: list[_Contribution] = []
    considered: list[DetectionResult] = []
    redaction_spans: list[TextSpan] = []

    for result in results:
        entry = config.for_detector(direction, result.detector)
        if entry is None or not entry.enabled:
            # Not configured for this direction, or disabled: contributes
            # nothing. It is still dropped from `results` so the audit record
            # reflects what actually informed the decision.
            continue

        considered.append(result)
        contribution = _contribution(result, entry)
        if contribution is None:
            continue
        contributions.append(contribution)

        if contribution.action is Action.REDACT:
            redaction_spans.extend(result.spans)

    if not contributions:
        return PolicyDecision(
            action=Action.ALLOW,
            direction=direction,
            results=tuple(considered),
        )

    winner = max(contributions, key=lambda c: ACTION_PRECEDENCE[c.action])
    reasons = tuple(c.reason for c in contributions)

    spans = _merge_spans(redaction_spans) if winner.action is Action.REDACT else ()

    return PolicyDecision(
        action=winner.action,
        direction=direction,
        category=winner.category,
        triggering_detector=winner.detector,
        reasons=reasons,
        results=tuple(considered),
        redaction_spans=spans,
    )
