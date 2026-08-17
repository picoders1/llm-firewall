"""Provenance-conditional policy — Phase 2P-C.

The invariant every test here serves: **an overlay may only tighten.** A policy
that could weaken a decision must fail to load, so an operator learns from a
failed deployment rather than from an incident review.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config.policy import DetectorPolicy, PolicyConfig, TrustOverlay
from app.core.exceptions import ConfigurationError
from app.core.types import (
    ACTION_PRECEDENCE,
    Action,
    Category,
    DetectionResult,
    Direction,
    Provenance,
    ProvenanceContext,
    TrustLevel,
)
from app.policy import engine

pytestmark = pytest.mark.unit


def entry(**overrides) -> DetectorPolicy:
    return DetectorPolicy(**{"detector": "injection.heuristic", **overrides})


def config_with(**overrides) -> PolicyConfig:
    return PolicyConfig(input={"prompt_injection": entry(**overrides)})


def result(score: float, *, errored: bool = False) -> DetectionResult:
    return DetectionResult(
        detector="injection.heuristic",
        category=Category.PROMPT_INJECTION,
        detected=score > 0,
        score=score,
        errored=errored,
        error_kind="timeout" if errored else None,
    )


def provenance(trust: TrustLevel) -> ProvenanceContext:
    return ProvenanceContext(provenance=Provenance.EXTERNAL, trust=trust)


# --- ProvenanceContext carries origin facts and nothing else ---------------


def test_provenance_context_has_no_text_field():
    """The engine must not be able to reach content. If this ever gains a text
    field, the policy engine's purity argument collapses (ADR-003)."""
    assert set(ProvenanceContext.model_fields) == {"provenance", "trust"}


def test_provenance_context_projects_from_a_detection_context():
    from app.core.types import DetectionContext, Role

    ctx = DetectionContext(
        request_id="r",
        direction=Direction.INPUT,
        role=Role.USER,
        raw_text="secret prompt",
        normalized_text="secret prompt",
        provenance=Provenance.EXTERNAL,
        trust=TrustLevel.UNTRUSTED,
    )
    projected = ProvenanceContext.from_context(ctx)
    assert projected.provenance is Provenance.EXTERNAL
    assert projected.trust is TrustLevel.UNTRUSTED
    assert "secret prompt" not in projected.model_dump_json()


def test_provenance_context_is_frozen():
    ctx = provenance(TrustLevel.UNTRUSTED)
    with pytest.raises(ValidationError):
        ctx.trust = TrustLevel.OPERATOR  # type: ignore[misc]


# --- Overlay validation: loosening is rejected at load ---------------------


@pytest.mark.parametrize("trust", list(TrustLevel))
def test_a_higher_threshold_is_rejected_for_every_trust_level(trust: TrustLevel):
    with pytest.raises(ValidationError, match="may only tighten"):
        entry(threshold=0.85, by_trust={trust: TrustOverlay(threshold=0.86)})


@pytest.mark.parametrize(
    ("base", "overlay_action"),
    [
        (Action.BLOCK, Action.REDACT),
        (Action.BLOCK, Action.WARN),
        (Action.REDACT, Action.WARN),
    ],
)
def test_a_less_severe_action_is_rejected(base: Action, overlay_action: Action):
    with pytest.raises(ValidationError, match="may only tighten"):
        entry(action=base, by_trust={TrustLevel.UNTRUSTED: TrustOverlay(action=overlay_action)})


def test_allow_is_not_configurable_in_an_overlay():
    with pytest.raises(ValidationError, match="not configurable"):
        entry(
            action=Action.BLOCK, by_trust={TrustLevel.UNTRUSTED: TrustOverlay(action=Action.ALLOW)}
        )


@pytest.mark.parametrize(
    ("base", "overlay_action"),
    [
        (Action.WARN, Action.REDACT),
        (Action.WARN, Action.BLOCK),
        (Action.REDACT, Action.BLOCK),
        (Action.BLOCK, Action.BLOCK),
    ],
)
def test_an_equal_or_more_severe_action_is_accepted(base: Action, overlay_action: Action):
    policy = entry(
        action=base, by_trust={TrustLevel.UNTRUSTED: TrustOverlay(action=overlay_action)}
    )
    _, action, _ = policy.effective(TrustLevel.UNTRUSTED)
    assert ACTION_PRECEDENCE[action] >= ACTION_PRECEDENCE[base]


def test_a_lower_threshold_is_accepted():
    policy = entry(threshold=0.85, by_trust={TrustLevel.UNTRUSTED: TrustOverlay(threshold=0.30)})
    threshold, _, _ = policy.effective(TrustLevel.UNTRUSTED)
    assert threshold == 0.30


def test_an_empty_overlay_is_permitted_and_inert():
    """It records that a trust level was considered and left alone."""
    policy = entry(threshold=0.85, by_trust={TrustLevel.UNKNOWN: TrustOverlay()})
    assert policy.effective(TrustLevel.UNKNOWN) == (0.85, Action.BLOCK, None)


def test_an_unknown_trust_key_is_rejected():
    with pytest.raises(ValidationError):
        DetectorPolicy.model_validate(
            {"detector": "d", "by_trust": {"super_trusted": {"threshold": 0.1}}}
        )


def test_an_unknown_overlay_field_is_rejected():
    with pytest.raises(ValidationError):
        DetectorPolicy.model_validate(
            {"detector": "d", "by_trust": {"untrusted": {"thresshold": 0.1}}}
        )


# --- The same rejection through the real YAML path ------------------------


def test_a_loosening_overlay_fails_to_load_from_yaml(write_policy):
    from app.config.loader import load_policy

    path = write_policy(
        """
version: 1
input:
  prompt_injection:
    detector: injection.heuristic
    threshold: 0.85
    action: block
    by_trust:
      untrusted:
        action: warn
"""
    )
    with pytest.raises((ConfigurationError, ValidationError)):
        load_policy(path)


def test_a_tightening_overlay_loads_from_yaml(write_policy):
    from app.config.loader import load_policy

    path = write_policy(
        """
version: 1
input:
  prompt_injection:
    detector: injection.heuristic
    threshold: 0.85
    action: warn
    by_trust:
      untrusted:
        threshold: 0.40
        action: block
"""
    )
    policy = load_policy(path)
    configured = policy.for_detector(Direction.INPUT, "injection.heuristic")
    assert configured is not None
    threshold, action, reason = configured.effective(TrustLevel.UNTRUSTED)
    assert (threshold, action) == (0.40, Action.BLOCK)
    assert reason is not None


# --- Effective resolution --------------------------------------------------


def test_no_provenance_means_no_adjustment():
    policy = entry(threshold=0.85, by_trust={TrustLevel.UNTRUSTED: TrustOverlay(threshold=0.1)})
    assert policy.effective(None) == (0.85, Action.BLOCK, None)


def test_a_trust_level_without_an_overlay_is_unadjusted():
    policy = entry(threshold=0.85, by_trust={TrustLevel.UNTRUSTED: TrustOverlay(threshold=0.1)})
    assert policy.effective(TrustLevel.PRINCIPAL) == (0.85, Action.BLOCK, None)


def test_the_reason_names_the_trust_level_and_the_effect():
    policy = entry(
        threshold=0.85,
        action=Action.WARN,
        by_trust={TrustLevel.UNTRUSTED: TrustOverlay(threshold=0.30, action=Action.BLOCK)},
    )
    _, _, reason = policy.effective(TrustLevel.UNTRUSTED)
    assert reason is not None
    assert "untrusted" in reason and "0.3000" in reason and "block" in reason


# --- Engine behaviour ------------------------------------------------------


def test_same_score_different_provenance_different_action():
    """The point of Phase C, stated as one assertion."""
    config = config_with(
        threshold=0.85,
        action=Action.WARN,
        by_trust={TrustLevel.UNTRUSTED: TrustOverlay(threshold=0.30, action=Action.BLOCK)},
    )
    scored = [result(0.50)]
    assert engine.evaluate(scored, config, Direction.INPUT).action is Action.ALLOW
    assert (
        engine.evaluate(scored, config, Direction.INPUT, provenance(TrustLevel.PRINCIPAL)).action
        is Action.ALLOW
    )
    assert (
        engine.evaluate(scored, config, Direction.INPUT, provenance(TrustLevel.UNTRUSTED)).action
        is Action.BLOCK
    )


def test_omitting_provenance_reproduces_the_pre_phase_c_decision():
    """Backward compatibility for every existing caller of `evaluate`."""
    config = config_with(threshold=0.85, action=Action.BLOCK)
    for score in (0.0, 0.5, 0.84, 0.85, 1.0):
        without = engine.evaluate([result(score)], config, Direction.INPUT)
        with_none = engine.evaluate([result(score)], config, Direction.INPUT, None)
        assert without.action is with_none.action
        assert without.reasons == with_none.reasons


def test_a_provenance_driven_escalation_appears_in_reasons():
    """§17: no hidden provenance behaviour. An operator reading the audit record
    must be able to see why the action changed."""
    config = config_with(
        threshold=0.85,
        action=Action.WARN,
        by_trust={TrustLevel.UNTRUSTED: TrustOverlay(threshold=0.30, action=Action.BLOCK)},
    )
    decision = engine.evaluate(
        [result(0.50)], config, Direction.INPUT, provenance(TrustLevel.UNTRUSTED)
    )
    assert decision.reasons
    assert any("trust=untrusted" in reason for reason in decision.reasons)


def test_fail_closed_is_not_provenance_conditional():
    """A detector failure is an availability problem, not a trust question.
    Making it trust-conditional would let a policy author accidentally turn a
    fail-closed detector into a fail-open one for some origins (ADR-007)."""
    # A valid (tightening) overlay on every level, to prove the failure path
    # ignores all of them rather than merely ignoring an absent one.
    config = config_with(
        threshold=0.85,
        action=Action.WARN,
        by_trust={t: TrustOverlay(threshold=0.10, action=Action.REDACT) for t in TrustLevel},
    )
    for trust in TrustLevel:
        decision = engine.evaluate(
            [result(0.0, errored=True)], config, Direction.INPUT, provenance(trust)
        )
        assert decision.action is Action.BLOCK
        assert decision.category is Category.DETECTOR_FAILURE


# --- Monotonicity, exhaustively -------------------------------------------


@pytest.mark.parametrize("trust", list(TrustLevel))
@pytest.mark.parametrize("score", [0.0, 0.25, 0.5, 0.75, 0.9, 1.0])
def test_provenance_can_never_produce_a_less_severe_action(trust: TrustLevel, score: float):
    """Every trust level x every score band: the provenance-aware decision is
    always at least as severe as the provenance-blind one. This is the executable
    form of the load-bearing rule."""
    config = config_with(
        threshold=0.85,
        action=Action.WARN,
        by_trust={
            TrustLevel.UNTRUSTED: TrustOverlay(threshold=0.20, action=Action.BLOCK),
            TrustLevel.UNKNOWN: TrustOverlay(threshold=0.50),
            TrustLevel.DERIVED: TrustOverlay(action=Action.REDACT),
        },
    )
    blind = engine.evaluate([result(score)], config, Direction.INPUT)
    aware = engine.evaluate([result(score)], config, Direction.INPUT, provenance(trust))
    assert ACTION_PRECEDENCE[aware.action] >= ACTION_PRECEDENCE[blind.action], (
        f"trust={trust} score={score} weakened {blind.action} -> {aware.action}"
    )


@pytest.mark.parametrize("trust", list(TrustLevel))
def test_no_overlay_can_suppress_a_detection_that_already_fired(trust: TrustLevel):
    config = config_with(
        threshold=0.50,
        action=Action.BLOCK,
        by_trust={t: TrustOverlay(threshold=0.10) for t in TrustLevel},
    )
    decision = engine.evaluate([result(0.90)], config, Direction.INPUT, provenance(trust))
    assert decision.action is Action.BLOCK


# --- Purity ----------------------------------------------------------------


def test_engine_remains_pure_and_deterministic():
    config = config_with(
        threshold=0.85, by_trust={TrustLevel.UNTRUSTED: TrustOverlay(threshold=0.3)}
    )
    args = ([result(0.5)], config, Direction.INPUT, provenance(TrustLevel.UNTRUSTED))
    first = engine.evaluate(*args)
    second = engine.evaluate(*args)
    assert first.action is second.action
    assert first.reasons == second.reasons
