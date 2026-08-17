"""Detector contracts.

A detector answers **one question about one piece of text and returns evidence**.
It does not decide, does not log content, does not touch the database, and cannot
import :mod:`app.policy`. That constraint is what makes the security decision
surface testable in isolation (docs/adr/ADR-002-detector-plugin-architecture.md).

Cross-cutting concerns live outside this contract on purpose:

* timeout and failure handling → :mod:`app.detectors.guarded`
* concurrency and fan-out → :mod:`app.detectors.pipeline`
* action selection → :mod:`app.policy.engine`

`Action` is deliberately absent from this module and from every module beneath
``app/detectors/``; ``tests/unit/test_layer_boundaries.py`` enforces it.
"""

from __future__ import annotations

import abc
from typing import Any, Protocol, runtime_checkable

import anyio
from anyio import CapacityLimiter

from app.config.policy import DetectorCapabilities, DetectorPolicy
from app.core.types import Category, DetectionContext, DetectionResult, Direction

BOTH_DIRECTIONS: frozenset[Direction] = frozenset({Direction.INPUT, Direction.OUTPUT})


@runtime_checkable
class Detector(Protocol):
    """The interface every detector implements."""

    name: str
    category: Category
    directions: frozenset[Direction]
    emits_spans: bool

    # Advertisement, not a requirement (ADR-017). A detector declaring `True`
    # may read `ctx.provenance` / `ctx.trust`; one declaring `False` ignores them
    # and behaves exactly as it did before provenance existed.
    #
    # There is deliberately no `requires_provenance`: such a detector would fail
    # on every request whose origin is UNKNOWN, and the only safe response —
    # failing closed per ADR-007 — would block ordinary traffic. A capability
    # mismatch must never become an outage. A detector that wants provenance must
    # degrade gracefully without it.
    consumes_provenance: bool

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        """Inspect one piece of text and return evidence.

        Must not raise for ordinary input; genuine failures may raise and will be
        captured by :class:`~app.detectors.guarded.GuardedDetector`.
        """
        ...

    async def warmup(self) -> None:
        """Load models and warm caches. Called once at startup, never per request.

        Model loading costs seconds; paying it on the first request would make
        that request an outlier and hide the cost from every benchmark.
        """
        ...

    async def aclose(self) -> None:
        """Release resources at shutdown."""
        ...


class BaseDetector(abc.ABC):
    """Convenience base providing the boilerplate parts of the protocol."""

    name: str = "unnamed"
    category: Category = Category.PROMPT_INJECTION
    directions: frozenset[Direction] = BOTH_DIRECTIONS
    emits_spans: bool = False
    # Default False so every existing detector keeps its exact behaviour without
    # being edited.
    consumes_provenance: bool = False

    def __init__(self, policy: DetectorPolicy | None = None) -> None:
        self.policy = policy

    @abc.abstractmethod
    async def detect(self, ctx: DetectionContext) -> DetectionResult: ...

    async def warmup(self) -> None:  # pragma: no cover - trivial default
        return None

    async def aclose(self) -> None:  # pragma: no cover - trivial default
        return None

    @classmethod
    def capabilities(cls) -> DetectorCapabilities:
        return DetectorCapabilities(
            name=cls.name,
            emits_spans=cls.emits_spans,
            directions=cls.directions,
            consumes_provenance=cls.consumes_provenance,
        )

    def _result(
        self,
        *,
        detected: bool,
        score: float,
        reasons: tuple[str, ...] = (),
        **extra: Any,
    ) -> DetectionResult:
        return DetectionResult(
            detector=self.name,
            detected=detected,
            score=score,
            category=self.category,
            reasons=reasons,
            **extra,
        )


class SyncDetectorAdapter(BaseDetector):
    """Bridges a blocking, CPU-bound detector onto the event loop.

    Transformers, ONNX Runtime and Presidio are synchronous and hold the GIL.
    Awaiting them directly would stall the loop for *every* concurrent request
    for the duration of the inference.

    The capacity limiter is not optional. Without it, N concurrent requests
    create N concurrent inferences, and CPU oversubscription turns a 20 ms model
    into a 2 s one under load — a latency failure that only appears under
    exactly the conditions nobody tests.

    This exists in Phase 0, before any blocking detector, because retrofitting it
    afterwards means retrofitting after the first production incident.
    """

    def __init__(
        self,
        policy: DetectorPolicy | None = None,
        *,
        max_threads: int = 8,
        limiter: CapacityLimiter | None = None,
    ) -> None:
        super().__init__(policy)
        self._limiter = limiter or CapacityLimiter(max_threads)

    @abc.abstractmethod
    def detect_sync(self, ctx: DetectionContext) -> DetectionResult:
        """Blocking inspection, executed in a worker thread."""

    async def detect(self, ctx: DetectionContext) -> DetectionResult:
        return await anyio.to_thread.run_sync(self.detect_sync, ctx, limiter=self._limiter)
