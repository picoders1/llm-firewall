"""GuardedDetector: timeout, failure capture and latency.

The guard *records*; it never decides. Conversion of a failure into a BLOCK
belongs to the policy engine, where it is part of the tested truth table
(ADR-007).
"""

from __future__ import annotations

import asyncio

import pytest

from app.core.types import Category, DetectionContext, DetectionResult, Direction, Role
from app.detectors.base import BaseDetector, SyncDetectorAdapter
from app.detectors.guarded import GuardedDetector

pytestmark = pytest.mark.unit


def make_context(text: str = "hello") -> DetectionContext:
    return DetectionContext(
        request_id="test",
        direction=Direction.INPUT,
        role=Role.USER,
        raw_text=text,
        normalized_text=text,
    )


class SlowDetector(BaseDetector):
    name = "slow"
    category = Category.PROMPT_INJECTION

    def __init__(self, delay_s: float) -> None:
        super().__init__()
        self.delay_s = delay_s

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        await asyncio.sleep(self.delay_s)
        return self._result(detected=False, score=0.0)


class ExplodingDetector(BaseDetector):
    name = "boom"
    category = Category.JAILBREAK

    def __init__(self, exc: Exception) -> None:
        super().__init__()
        self.exc = exc

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        raise self.exc


class QuietDetector(BaseDetector):
    name = "quiet"
    category = Category.PII

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        return self._result(detected=True, score=0.7, reasons=("found",))


# --- Success path ----------------------------------------------------------


async def test_successful_result_passes_through_with_latency():
    guarded = GuardedDetector(QuietDetector(), timeout_ms=1000)
    result = await guarded.detect(make_context())

    assert result.detected is True
    assert result.score == 0.7
    assert result.errored is False
    assert result.latency_ms >= 0.0


# --- Timeout ---------------------------------------------------------------


async def test_timeout_produces_an_errored_result_not_an_exception():
    guarded = GuardedDetector(SlowDetector(delay_s=5), timeout_ms=20)
    result = await guarded.detect(make_context())

    assert result.errored is True
    assert result.error_kind == "timeout"
    assert result.detected is False
    assert result.score == 0.0


async def test_timeout_is_bounded_by_the_configured_budget():
    """A hanging detector must not hang the request."""
    guarded = GuardedDetector(SlowDetector(delay_s=10), timeout_ms=30)

    async with asyncio.timeout(2):  # fails the test if the guard does not cut it off
        result = await guarded.detect(make_context())

    assert result.error_kind == "timeout"


# --- Exceptions ------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [RuntimeError("model missing"), ValueError("bad input"), KeyError("weights"), OSError("disk")],
)
async def test_exceptions_are_captured_and_named(exc: Exception):
    guarded = GuardedDetector(ExplodingDetector(exc), timeout_ms=1000)
    result = await guarded.detect(make_context())

    assert result.errored is True
    assert result.error_kind == type(exc).__name__
    assert result.detected is False


async def test_failure_result_keeps_the_detector_identity():
    """The audit record must attribute the failure to a specific detector."""
    guarded = GuardedDetector(ExplodingDetector(RuntimeError("x")), timeout_ms=1000)
    result = await guarded.detect(make_context())

    assert result.detector == "boom"
    assert result.category is Category.JAILBREAK


async def test_cancellation_propagates_rather_than_being_recorded():
    """A client disconnect is not a detector fault."""

    class Canceller(BaseDetector):
        name = "cancel"
        category = Category.PII

        async def detect(self, ctx: DetectionContext) -> DetectionResult:
            raise asyncio.CancelledError

    guarded = GuardedDetector(Canceller(), timeout_ms=1000)
    with pytest.raises(asyncio.CancelledError):
        await guarded.detect(make_context())


async def test_guard_never_returns_detected_true_on_failure():
    """A failed detector must not be able to fabricate a detection."""
    guarded = GuardedDetector(ExplodingDetector(RuntimeError("x")), timeout_ms=1000)
    result = await guarded.detect(make_context())

    assert result.detected is False
    assert result.score == 0.0


# --- Sync adapter (ADR-002) ------------------------------------------------


async def test_sync_adapter_runs_blocking_code_off_the_event_loop():
    """Establishes the pattern before the first blocking ML detector exists."""
    import time

    class BlockingDetector(SyncDetectorAdapter):
        name = "blocking"
        category = Category.PROMPT_INJECTION

        def detect_sync(self, ctx: DetectionContext) -> DetectionResult:
            time.sleep(0.05)
            return self._result(detected=False, score=0.0)

    detector = BlockingDetector(max_threads=4)
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        for _ in range(10):
            await asyncio.sleep(0.005)
            ticks += 1

    await asyncio.gather(detector.detect(make_context()), ticker())

    assert ticks == 10, "the event loop was blocked during synchronous detection"
