"""Concurrent detector fan-out for one direction.

All enabled detectors for a direction run concurrently, so the wall-clock cost of
the detection stage is the **slowest** detector rather than the sum. This is why
per-detector latency, not just total latency, is recorded on every event.

Every enabled detector runs on every request, even after another has already
found a blocking issue. That is deliberate: the audit record wants all scores,
and retrospective threshold tuning depends on scores from detectors that did not
fire (docs/11-data-model.md).
"""

from __future__ import annotations

import asyncio

import structlog

from app.config.policy import PolicyConfig
from app.core.types import DetectionContext, DetectionResult, Direction
from app.detectors import registry
from app.detectors.guarded import GuardedDetector

logger = structlog.get_logger(__name__)


class DetectorPipeline:
    """Holds the guarded detectors for each direction, built once at startup."""

    def __init__(self, detectors: dict[Direction, tuple[GuardedDetector, ...]]) -> None:
        self._detectors = detectors

    @classmethod
    def from_policy(cls, policy: PolicyConfig) -> DetectorPipeline:
        built: dict[Direction, tuple[GuardedDetector, ...]] = {}
        for direction in (Direction.INPUT, Direction.OUTPUT):
            guarded: list[GuardedDetector] = []
            for entry in policy.section(direction).values():
                if not entry.enabled:
                    continue
                detector = registry.create(entry.detector, entry)
                guarded.append(GuardedDetector(detector, timeout_ms=entry.timeout_ms))
            built[direction] = tuple(guarded)
        return cls(built)

    def for_direction(self, direction: Direction) -> tuple[GuardedDetector, ...]:
        return self._detectors.get(direction, ())

    @property
    def all_detectors(self) -> tuple[GuardedDetector, ...]:
        seen: dict[int, GuardedDetector] = {}
        for group in self._detectors.values():
            for detector in group:
                seen.setdefault(id(detector), detector)
        return tuple(seen.values())

    async def run(self, direction: Direction, ctx: DetectionContext) -> tuple[DetectionResult, ...]:
        """Run every enabled detector for `direction` against one context."""
        detectors = self.for_direction(direction)
        if not detectors:
            return ()
        results = await asyncio.gather(*(d.detect(ctx) for d in detectors))
        return tuple(results)

    async def warmup(self) -> None:
        """Load every detector's resources before the process reports ready.

        Failures propagate: an instance that cannot inspect must fail readiness
        rather than serve traffic it would have to block (ADR-007).
        """
        for detector in self.all_detectors:
            await detector.warmup()
            logger.debug("detector_warmed", detector=detector.name)

    async def aclose(self) -> None:
        for detector in self.all_detectors:
            await detector.aclose()
