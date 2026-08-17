"""Latency and throughput statistics.

Deliberately kept separate from classification metrics: conflating security
quality with speed is how a comparison table becomes unreadable, and the two
have completely different validity requirements
(docs/15-performance-benchmarking.md).

**These are detector-level measurements, not gateway overhead.** Gateway overhead
is `total − upstream` measured through the HTTP path and is a different
experiment (conditions A–D in docs/15). Nothing here may be quoted as a gateway
latency figure.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

# Below this, percentile estimates — p99 especially — are noise.
MIN_SAMPLES_FOR_PERCENTILES = 30


def percentile(values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile, `q` in [0, 1]."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = q * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


@dataclass(frozen=True, slots=True)
class LatencyStats:
    n: int
    mean_ms: float
    median_ms: float
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    stdev_ms: float
    throughput_per_s: float
    percentiles_reliable: bool

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "n": self.n,
            "mean_ms": round(self.mean_ms, 4),
            "median_ms": round(self.median_ms, 4),
            "p50_ms": round(self.p50_ms, 4),
            "p90_ms": round(self.p90_ms, 4),
            "p95_ms": round(self.p95_ms, 4),
            "p99_ms": round(self.p99_ms, 4),
            "min_ms": round(self.min_ms, 4),
            "max_ms": round(self.max_ms, 4),
            "stdev_ms": round(self.stdev_ms, 4),
            "throughput_per_s_single_threaded": round(self.throughput_per_s, 2),
            "percentiles_reliable": self.percentiles_reliable,
        }
        if not self.percentiles_reliable:
            payload["percentiles_warning"] = (
                f"n={self.n} < {MIN_SAMPLES_FOR_PERCENTILES}; tail percentiles are "
                "not meaningful at this sample size and must not be quoted"
            )
        return payload


def latency_stats(samples_ms: Sequence[float]) -> LatencyStats:
    """Summarise per-call latencies.

    p99 and max are always computed and reported. Dropping them is how a tail
    that is 40x the median — the thing that actually causes incidents — stays
    invisible.

    `throughput_per_s` is the single-threaded reciprocal of mean latency, not a
    concurrency measurement. Real throughput under concurrency is a separate
    experiment and is labelled as such in the report.
    """
    if not samples_ms:
        return LatencyStats(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, False)

    n = len(samples_ms)
    mean = sum(samples_ms) / n
    variance = sum((value - mean) ** 2 for value in samples_ms) / n if n > 1 else 0.0
    return LatencyStats(
        n=n,
        mean_ms=mean,
        median_ms=percentile(samples_ms, 0.5),
        p50_ms=percentile(samples_ms, 0.5),
        p90_ms=percentile(samples_ms, 0.9),
        p95_ms=percentile(samples_ms, 0.95),
        p99_ms=percentile(samples_ms, 0.99),
        min_ms=min(samples_ms),
        max_ms=max(samples_ms),
        stdev_ms=variance**0.5,
        throughput_per_s=(1000.0 / mean) if mean > 0 else 0.0,
        percentiles_reliable=n >= MIN_SAMPLES_FOR_PERCENTILES,
    )
