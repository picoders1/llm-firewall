"""Timeout, failure capture and latency measurement — in exactly one place.

Every registered detector is wrapped. Individual detectors therefore contain no
timeout logic and no ``try/except`` around their own work.

The reason this is centralised rather than left to each detector: the failure we
most need to prevent is a security component that stops inspecting without anyone
noticing. If each detector implemented its own error handling, one
``except Exception: return no_finding`` would disable that protection permanently
and silently, and it would pass review because it looks like defensive coding.

`GuardedDetector` **records** failures; it never decides. Conversion of a failure
into a BLOCK (or into nothing) belongs to the policy engine, where it is part of
the exhaustively tested truth table.
See docs/adr/ADR-007-detector-failure-semantics.md.
"""

from __future__ import annotations

import asyncio
import time

import structlog

from app.core.types import Category, DetectionContext, DetectionResult, Direction
from app.detectors.base import Detector

logger = structlog.get_logger(__name__)

TIMEOUT_ERROR_KIND = "timeout"


class GuardedDetector:
    """Wraps a detector with a timeout budget, failure capture and timing."""

    def __init__(self, inner: Detector, *, timeout_ms: int) -> None:
        self._inner = inner
        self._timeout_s = timeout_ms / 1000.0

    @property
    def name(self) -> str:
        return self._inner.name

    @property
    def category(self) -> Category:
        return self._inner.category

    @property
    def directions(self) -> frozenset[Direction]:
        return self._inner.directions

    @property
    def emits_spans(self) -> bool:
        return self._inner.emits_spans

    @property
    def inner(self) -> Detector:
        return self._inner

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        started = time.perf_counter()
        try:
            result = await asyncio.wait_for(self._inner.detect(ctx), timeout=self._timeout_s)
        except TimeoutError:
            return self._failure(ctx, TIMEOUT_ERROR_KIND, started)
        except asyncio.CancelledError:
            # Client disconnect or shutdown. Not a detector failure — propagate
            # so the task actually cancels rather than being recorded as a fault.
            raise
        except Exception as exc:
            # The traceback goes to the operator; the inspected content never
            # does, at any log level (docs/10-security-model.md).
            logger.exception(
                "detector_failed",
                detector=self._inner.name,
                error_kind=type(exc).__name__,
                direction=ctx.direction.value,
            )
            return self._failure(ctx, type(exc).__name__, started)

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return result.model_copy(update={"latency_ms": elapsed_ms})

    def _failure(self, ctx: DetectionContext, error_kind: str, started: float) -> DetectionResult:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if error_kind == TIMEOUT_ERROR_KIND:
            logger.warning(
                "detector_timeout",
                detector=self._inner.name,
                timeout_ms=self._timeout_s * 1000.0,
                direction=ctx.direction.value,
            )
        return DetectionResult(
            detector=self._inner.name,
            detected=False,
            score=0.0,
            category=self._inner.category,
            reasons=(f"detector_error:{error_kind}",),
            latency_ms=elapsed_ms,
            errored=True,
            error_kind=error_kind,
        )

    async def warmup(self) -> None:
        await self._inner.warmup()

    async def aclose(self) -> None:
        await self._inner.aclose()
