"""Detector pipeline: construction from policy and concurrent fan-out."""

from __future__ import annotations

import asyncio
import time

import pytest

from app.config.policy import PolicyConfig
from app.core.types import Category, DetectionContext, DetectionResult, Direction, Role
from app.detectors.base import BaseDetector
from app.detectors.guarded import GuardedDetector
from app.detectors.pipeline import DetectorPipeline

pytestmark = pytest.mark.unit


def context(direction: Direction = Direction.INPUT) -> DetectionContext:
    return DetectionContext(
        request_id="test",
        direction=direction,
        role=Role.USER,
        raw_text="hello",
        normalized_text="hello",
    )


class DelayDetector(BaseDetector):
    category = Category.PROMPT_INJECTION

    def __init__(self, name: str, delay_s: float) -> None:
        super().__init__()
        self.name = name
        self.delay_s = delay_s

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        await asyncio.sleep(self.delay_s)
        return self._result(detected=False, score=0.0)


# --- Construction from policy ---------------------------------------------


def test_pipeline_is_built_from_enabled_policy_entries():
    policy = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "injection.heuristic"},
                "b": {"detector": "jailbreak.heuristic", "enabled": False},
            },
            "output": {"c": {"detector": "output.stub"}},
        }
    )
    pipeline = DetectorPipeline.from_policy(policy)

    assert [d.name for d in pipeline.for_direction(Direction.INPUT)] == ["injection.heuristic"]
    assert [d.name for d in pipeline.for_direction(Direction.OUTPUT)] == ["output.stub"]


def test_each_detector_gets_its_configured_timeout():
    policy = PolicyConfig.model_validate(
        {"input": {"a": {"detector": "injection.heuristic", "timeout_ms": 37}}}
    )
    detector = DetectorPipeline.from_policy(policy).for_direction(Direction.INPUT)[0]

    assert detector._timeout_s == pytest.approx(0.037)


def test_empty_policy_produces_an_empty_pipeline():
    pipeline = DetectorPipeline.from_policy(PolicyConfig())

    assert pipeline.for_direction(Direction.INPUT) == ()
    assert pipeline.all_detectors == ()


async def test_running_an_empty_pipeline_is_not_an_error():
    pipeline = DetectorPipeline.from_policy(PolicyConfig())

    assert await pipeline.run(Direction.INPUT, context()) == ()


# --- Fan-out ---------------------------------------------------------------


async def test_detectors_run_concurrently_not_sequentially():
    """Stage cost is the slowest detector, not the sum — which is why
    per-detector latency is recorded separately (docs/05)."""
    delay = 0.05
    pipeline = DetectorPipeline(
        {
            Direction.INPUT: tuple(
                GuardedDetector(DelayDetector(f"d{i}", delay), timeout_ms=2000) for i in range(5)
            )
        }
    )

    started = time.perf_counter()
    results = await pipeline.run(Direction.INPUT, context())
    elapsed = time.perf_counter() - started

    assert len(results) == 5
    assert elapsed < delay * 3, f"ran sequentially: {elapsed:.3f}s for 5 x {delay}s"


async def test_all_results_are_returned_even_when_one_fails():
    """Every enabled detector runs on every request: the audit record wants all
    scores, including from detectors that did not fire."""

    class Boom(BaseDetector):
        name = "boom"
        category = Category.PII

        async def detect(self, ctx: DetectionContext) -> DetectionResult:
            raise RuntimeError("broken")

    pipeline = DetectorPipeline(
        {
            Direction.INPUT: (
                GuardedDetector(DelayDetector("ok", 0.0), timeout_ms=1000),
                GuardedDetector(Boom(), timeout_ms=1000),
            )
        }
    )

    results = await pipeline.run(Direction.INPUT, context())

    assert len(results) == 2
    assert {r.detector for r in results} == {"ok", "boom"}
    assert next(r for r in results if r.detector == "boom").errored is True


async def test_direction_isolation():
    """An input-side detector must not run on the output path."""
    policy = PolicyConfig.model_validate({"input": {"a": {"detector": "injection.heuristic"}}})
    pipeline = DetectorPipeline.from_policy(policy)

    assert await pipeline.run(Direction.OUTPUT, context(Direction.OUTPUT)) == ()


async def test_warmup_covers_every_detector():
    policy = PolicyConfig.model_validate(
        {
            "input": {"a": {"detector": "injection.heuristic"}},
            "output": {"b": {"detector": "output.stub"}},
        }
    )
    pipeline = DetectorPipeline.from_policy(policy)

    await pipeline.warmup()
    await pipeline.aclose()

    assert len(pipeline.all_detectors) == 2


# --- Baseline detectors on benign traffic ----------------------------------


async def test_all_baseline_detectors_stay_silent_on_benign_text():
    """The false-positive floor: ordinary text must trigger nothing.

    A detector suite that fires on "hello" is a denial-of-service tool, which is
    why FPR — not recall — is the headline metric in docs/13-evaluation-strategy.md.
    """
    policy = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "injection.heuristic"},
                "b": {"detector": "jailbreak.heuristic"},
                "c": {"detector": "pii.regex", "action": "redact"},
            }
        }
    )
    pipeline = DetectorPipeline.from_policy(policy)

    results = await pipeline.run(Direction.INPUT, context())

    assert len(results) == 3
    assert all(r.detected is False and r.score == 0.0 for r in results)
    assert all(r.errored is False for r in results)


async def test_baseline_detectors_declare_themselves_uncalibrated():
    """The honesty invariant: nothing in this repository may present these
    heuristics as calibrated detection (docs/05-detector-architecture.md)."""
    policy = PolicyConfig.model_validate(
        {
            "input": {
                "a": {"detector": "injection.heuristic"},
                "b": {"detector": "jailbreak.heuristic"},
            }
        }
    )
    pipeline = DetectorPipeline.from_policy(policy)

    results = await pipeline.run(Direction.INPUT, context())

    assert all(r.metadata.get("calibrated") is False for r in results)
    assert all(r.metadata.get("baseline") is True for r in results)
