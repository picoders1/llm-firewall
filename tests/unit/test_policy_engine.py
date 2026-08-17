"""The policy-engine truth table.

The highest-value test in the repository. It covers the entire security decision
surface — every combination of score-vs-threshold, configured action, error state
and error policy — and it runs in milliseconds with no models, no HTTP and no
database. That is the direct payoff of the purity constraint in ADR-003; if this
test ever becomes slow or awkward, the engine has grown a dependency it should
not have.
"""

from __future__ import annotations

import pytest

from app.config.policy import DetectorPolicy, PolicyConfig
from app.core.types import (
    Action,
    Category,
    DetectionResult,
    Direction,
    ErrorPolicy,
    TextSpan,
)
from app.policy.engine import evaluate

pytestmark = pytest.mark.unit


def make_policy(
    *,
    detector: str = "d.one",
    enabled: bool = True,
    threshold: float = 0.85,
    action: Action = Action.BLOCK,
    on_error: ErrorPolicy = ErrorPolicy.FAIL_CLOSED,
    direction: Direction = Direction.INPUT,
    extra: dict[str, DetectorPolicy] | None = None,
) -> PolicyConfig:
    entry = DetectorPolicy(
        detector=detector,
        enabled=enabled,
        threshold=threshold,
        action=action,
        on_error=on_error,
    )
    section = {"primary": entry} | (extra or {})
    key = "input" if direction is Direction.INPUT else "output"
    return PolicyConfig.model_validate({key: {k: v.model_dump() for k, v in section.items()}})


def result(
    *,
    detector: str = "d.one",
    score: float = 0.0,
    detected: bool = False,
    category: Category = Category.PROMPT_INJECTION,
    errored: bool = False,
    error_kind: str | None = None,
    spans: tuple[TextSpan, ...] = (),
) -> DetectionResult:
    return DetectionResult(
        detector=detector,
        detected=detected,
        score=score,
        category=category,
        errored=errored,
        error_kind=error_kind,
        spans=spans,
    )


# --- Core truth table ------------------------------------------------------


@pytest.mark.parametrize("action", [Action.BLOCK, Action.REDACT, Action.WARN])
@pytest.mark.parametrize(
    ("score", "threshold", "triggers"),
    [
        (0.90, 0.85, True),  # above
        (0.85, 0.85, True),  # exactly at threshold — inclusive by contract
        (0.84, 0.85, False),  # just below
        (0.00, 0.85, False),
        (1.00, 1.00, True),  # threshold 1.0 triggers only at maximum score
        (0.99, 1.00, False),
        (0.00, 0.00, True),  # threshold 0.0 always triggers
    ],
)
def test_threshold_and_action(action: Action, score: float, threshold: float, triggers: bool):
    config = make_policy(threshold=threshold, action=action)
    decision = evaluate([result(score=score)], config, Direction.INPUT)

    assert decision.action is (action if triggers else Action.ALLOW)
    assert decision.direction is Direction.INPUT
    if triggers:
        assert decision.triggering_detector == "d.one"
        assert decision.category is Category.PROMPT_INJECTION
    else:
        assert decision.triggering_detector is None


def test_no_results_allows():
    decision = evaluate([], make_policy(), Direction.INPUT)
    assert decision.action is Action.ALLOW
    assert decision.results == ()


def test_disabled_detector_contributes_nothing():
    config = make_policy(enabled=False)
    decision = evaluate([result(score=1.0)], config, Direction.INPUT)

    assert decision.action is Action.ALLOW
    # And it is excluded from the record, so the audit trail reflects what
    # actually informed the decision.
    assert decision.results == ()


def test_unconfigured_detector_contributes_nothing():
    config = make_policy(detector="d.one")
    decision = evaluate([result(detector="d.unknown", score=1.0)], config, Direction.INPUT)
    assert decision.action is Action.ALLOW
    assert decision.results == ()


def test_wrong_direction_contributes_nothing():
    """A detector configured for input must not influence an output decision."""
    config = make_policy(direction=Direction.INPUT)
    decision = evaluate([result(score=1.0)], config, Direction.OUTPUT)
    assert decision.action is Action.ALLOW


# --- Failure semantics (ADR-007) -------------------------------------------


@pytest.mark.parametrize("error_kind", ["timeout", "RuntimeError", "ValueError"])
def test_fail_closed_blocks_on_error(error_kind: str):
    config = make_policy(on_error=ErrorPolicy.FAIL_CLOSED)
    decision = evaluate([result(errored=True, error_kind=error_kind)], config, Direction.INPUT)

    assert decision.action is Action.BLOCK
    # Never counted as an attack: conflating an availability failure with a
    # detection would corrupt every security metric in the system.
    assert decision.category is Category.DETECTOR_FAILURE
    assert any("fail_closed" in reason for reason in decision.reasons)


def test_fail_open_contributes_nothing_but_is_recorded():
    config = make_policy(on_error=ErrorPolicy.FAIL_OPEN)
    decision = evaluate([result(errored=True, error_kind="timeout")], config, Direction.INPUT)

    assert decision.action is Action.ALLOW
    assert len(decision.results) == 1
    assert decision.results[0].errored is True


def test_errored_result_score_is_ignored():
    """A failed detector's score is meaningless and must not trigger anything."""
    config = make_policy(threshold=0.5, on_error=ErrorPolicy.FAIL_OPEN)
    decision = evaluate(
        [result(score=1.0, errored=True, error_kind="timeout")], config, Direction.INPUT
    )
    assert decision.action is Action.ALLOW


# --- Precedence and conflict resolution ------------------------------------


@pytest.mark.parametrize(
    ("actions", "expected"),
    [
        ((Action.WARN, Action.BLOCK), Action.BLOCK),
        ((Action.BLOCK, Action.WARN), Action.BLOCK),
        ((Action.WARN, Action.REDACT), Action.REDACT),
        ((Action.REDACT, Action.BLOCK), Action.BLOCK),
        ((Action.BLOCK, Action.REDACT), Action.BLOCK),
        ((Action.WARN, Action.WARN), Action.WARN),
    ],
)
def test_most_severe_action_wins(actions: tuple[Action, Action], expected: Action):
    config = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "d.a", "threshold": 0.5, "action": actions[0].value},
                "b": {"detector": "d.b", "threshold": 0.5, "action": actions[1].value},
            }
        }
    )
    results = [result(detector="d.a", score=0.9), result(detector="d.b", score=0.9)]
    assert evaluate(results, config, Direction.INPUT).action is expected


def test_allow_never_outvotes_a_positive_finding():
    """One detector finding nothing is not evidence of safety (docs/06)."""
    config = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "d.a", "threshold": 0.5, "action": "block"},
                "b": {"detector": "d.b", "threshold": 0.5, "action": "block"},
            }
        }
    )
    results = [result(detector="d.a", score=0.0), result(detector="d.b", score=0.99)]
    decision = evaluate(results, config, Direction.INPUT)

    assert decision.action is Action.BLOCK
    assert decision.triggering_detector == "d.b"


def test_precedence_is_order_independent():
    config = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "d.a", "threshold": 0.5, "action": "warn"},
                "b": {"detector": "d.b", "threshold": 0.5, "action": "block"},
                "c": {"detector": "d.c", "threshold": 0.5, "action": "redact"},
            }
        }
    )
    results = [
        result(detector="d.a", score=0.9),
        result(detector="d.b", score=0.9),
        result(detector="d.c", score=0.9, spans=(TextSpan(start=0, end=2, label="EMAIL"),)),
    ]
    expected = evaluate(results, config, Direction.INPUT).action
    for permutation in ([results[2], results[0], results[1]], [results[1], results[2], results[0]]):
        assert evaluate(permutation, config, Direction.INPUT).action is expected is Action.BLOCK


def test_adding_a_detector_cannot_weaken_a_decision():
    """Monotonicity: severity precedence means a new detector only escalates."""
    strict = PolicyConfig.model_validate(
        {"input": {"a": {"detector": "d.a", "threshold": 0.5, "action": "block"}}}
    )
    with_extra = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "d.a", "threshold": 0.5, "action": "block"},
                "b": {"detector": "d.b", "threshold": 0.5, "action": "warn"},
            }
        }
    )
    results = [result(detector="d.a", score=0.9), result(detector="d.b", score=0.0)]
    assert evaluate(results[:1], strict, Direction.INPUT).action is Action.BLOCK
    assert evaluate(results, with_extra, Direction.INPUT).action is Action.BLOCK


# --- Redaction spans -------------------------------------------------------


def test_redact_collects_and_merges_spans():
    config = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "d.a", "threshold": 0.5, "action": "redact"},
                "b": {"detector": "d.b", "threshold": 0.5, "action": "redact"},
            }
        }
    )
    results = [
        result(detector="d.a", score=0.9, spans=(TextSpan(start=0, end=10, label="EMAIL"),)),
        result(detector="d.b", score=0.9, spans=(TextSpan(start=5, end=20, label="PHONE"),)),
    ]
    decision = evaluate(results, config, Direction.INPUT)

    assert decision.action is Action.REDACT
    assert len(decision.redaction_spans) == 1, "overlapping spans must merge"
    assert decision.redaction_spans[0].start == 0
    assert decision.redaction_spans[0].end == 20


def test_non_overlapping_spans_are_kept_separate():
    config = make_policy(threshold=0.5, action=Action.REDACT)
    spans = (TextSpan(start=0, end=5, label="EMAIL"), TextSpan(start=10, end=15, label="PHONE"))
    decision = evaluate(
        [result(score=0.9, spans=spans)],
        make_policy(threshold=0.5, action=Action.REDACT),
        Direction.INPUT,
    )
    assert len(decision.redaction_spans) == 2
    assert config is not None


def test_block_discards_redaction_spans():
    """A blocked request is not forwarded, so there is nothing to redact."""
    config = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "d.a", "threshold": 0.5, "action": "redact"},
                "b": {"detector": "d.b", "threshold": 0.5, "action": "block"},
            }
        }
    )
    results = [
        result(detector="d.a", score=0.9, spans=(TextSpan(start=0, end=5, label="EMAIL"),)),
        result(detector="d.b", score=0.9),
    ]
    decision = evaluate(results, config, Direction.INPUT)

    assert decision.action is Action.BLOCK
    assert decision.redaction_spans == ()


# --- Decision record -------------------------------------------------------


def test_decision_carries_all_considered_results():
    """The engine cannot log, so the decision must explain itself (ADR-003)."""
    config = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "d.a", "threshold": 0.5, "action": "block"},
                "b": {"detector": "d.b", "threshold": 0.5, "action": "warn"},
            }
        }
    )
    results = [result(detector="d.a", score=0.9), result(detector="d.b", score=0.1)]
    decision = evaluate(results, config, Direction.INPUT)

    assert len(decision.results) == 2, "non-triggering scores are kept for threshold tuning"
    assert decision.blocked is True
