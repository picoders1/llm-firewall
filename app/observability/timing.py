"""Per-stage latency accounting.

The definition that matters (docs/15-performance-benchmarking.md)::

    gateway_overhead = total_wall_clock - upstream_latency

Recording the stages separately is what makes that number defensible rather than
folklore: "the gateway is slow" and "the model is slow" become distinguishable,
and the detection stage can be attributed to a specific detector.

Measured with `time.perf_counter` (monotonic). No claim is made about these
numbers yet — no benchmark has been run.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class RequestTimings:
    """Accumulates stage timings for one request, in milliseconds."""

    normalization_ms: float = 0.0
    detector_ms: float = 0.0
    policy_ms: float = 0.0
    upstream_ms: float = 0.0
    output_detector_ms: float = 0.0
    audit_ms: float = 0.0
    total_ms: float = 0.0
    _started: float = field(default_factory=time.perf_counter, repr=False)

    @contextmanager
    def measure(self, stage: str) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            elapsed = (time.perf_counter() - started) * 1000.0
            setattr(self, stage, getattr(self, stage) + elapsed)

    def finish(self) -> None:
        self.total_ms = (time.perf_counter() - self._started) * 1000.0

    @property
    def gateway_overhead_ms(self) -> float:
        """Everything the gateway cost, excluding the upstream call.

        This is the figure a latency claim must be based on; reporting total
        latency instead measures the model.
        """
        return max(0.0, self.total_ms - self.upstream_ms)

    def as_dict(self) -> dict[str, float]:
        return {
            "normalization_ms": round(self.normalization_ms, 3),
            "detector_ms": round(self.detector_ms, 3),
            "policy_ms": round(self.policy_ms, 3),
            "upstream_ms": round(self.upstream_ms, 3),
            "output_detector_ms": round(self.output_detector_ms, 3),
            "audit_ms": round(self.audit_ms, 3),
            "total_ms": round(self.total_ms, 3),
            "gateway_overhead_ms": round(self.gateway_overhead_ms, 3),
        }
