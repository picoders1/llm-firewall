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
    ProvenanceContext,
    TextSpan,
    TrustLevel,
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


def _contribution(
    result: DetectionResult,
    entry: DetectorPolicy,
    trust: TrustLevel | None,
) -> _Contribution | None:
    """Map one detection result to a contribution, or None if it contributes nothing.

    `trust` selects the effective threshold and action via `entry.effective()`.
    A detector *failure* is deliberately unaffected by provenance: failing closed
    is about availability of inspection, not about how much the source is trusted,
    and making it trust-conditional would let a policy author accidentally turn a
    fail-closed detector into a fail-open one for some origins (ADR-007).
    """
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

    threshold, action, provenance_reason = entry.effective(trust)
    if result.score >= threshold:
        reason = f"{result.detector}:score={result.score:.4f}>=threshold={threshold:.4f}"
        if provenance_reason:
            # Surfaced so a provenance-driven escalation is visible in the audit
            # record rather than being an unexplained change of action.
            reason = f"{reason}:{provenance_reason}"
        return _Contribution(
            action=action,
            category=result.category,
            detector=result.detector,
            reason=reason,
        )
    return None


def evaluate(
    results: Sequence[DetectionResult],
    config: PolicyConfig,
    direction: Direction,
    provenance: ProvenanceContext | None = None,
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

    `provenance` carries **only** origin facts — never the text — so the function
    stays pure and its truth table stays enumerable (ADR-017). Passing ``None``
    means "no provenance-conditional adjustment", which is exactly how a request
    that declares no origin behaves: identically to one evaluated before
    provenance existed. Any adjustment can only ever *tighten*, enforced when the
    policy is loaded rather than here.
    """
    trust = provenance.trust if provenance is not None else None
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
        contribution = _contribution(result, entry, trust)
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
