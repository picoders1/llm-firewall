"""The evaluation engine: dataset + detector + configuration → evidence.

Deliberately generic. It knows nothing about *which* detector it is driving, so
the same code path, safeguards and report format serve the heuristic baseline
today and a transformer classifier or guard model later.

Three safeguards are built in rather than left to the operator:

* **Scope filtering.** A detector is evaluated only on the categories it is
  answerable for. Scoring the injection classifier against PII samples would
  manufacture a false recall number.
* **Frozen test split.** Calibration refuses the test split, and reporting on it
  demands an explicit `--frozen` acknowledgement.
* **Refuses to write an unstamped report.** No commit, checksum and machine
  metadata means no report.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from eval.detectors import Prediction, build_detector
from eval.loaders.base import RegistryEntry, filter_split
from eval.loaders.registry_loader import load_benchmark
from eval.metadata import run_metadata
from eval.metrics.calibration import Objective, OperatingPoint, calibrate, operating_point_table
from eval.metrics.classification import (
    ThresholdPoint,
    average_precision,
    category_breakdown,
    confusion_at,
    roc_auc,
)
from eval.metrics.latency import latency_stats
from eval.schema import Sample, Split, dataset_checksum, validate_dataset

DEFAULT_SEED = 20260817


@dataclass
class EvaluationResult:
    run_id: str
    detector: str
    benchmark: str
    split: Split
    samples: list[Sample]
    predictions: list[Prediction]
    metadata: dict[str, Any]
    dataset_report: dict[str, Any]
    sources: dict[str, RegistryEntry]
    operating_point: OperatingPoint | None = None
    sweep: list[ThresholdPoint] = field(default_factory=list)
    threshold: float = 0.5
    warnings: list[str] = field(default_factory=list)

    @property
    def labels(self) -> list[bool]:
        return [sample.label for sample in self.samples]

    @property
    def scores(self) -> list[float]:
        return [prediction.score for prediction in self.predictions]

    @property
    def categories(self) -> list[str]:
        return [sample.category.value for sample in self.samples]

    def metrics(self) -> dict[str, Any]:
        matrix = confusion_at(self.labels, self.scores, self.threshold)
        predictions_at_threshold = [score >= self.threshold for score in self.scores]
        latencies = [prediction.total_ms for prediction in self.predictions]
        return {
            "threshold": round(self.threshold, 4),
            "classification": matrix.as_dict(),
            "threshold_free": {
                "average_precision": round(average_precision(self.labels, self.scores), 4),
                "roc_auc": round(roc_auc(self.labels, self.scores), 4),
                "note": (
                    "average_precision is preferred on imbalanced security data; "
                    "roc_auc is reported for comparability only"
                ),
            },
            "per_category": category_breakdown(
                self.labels, predictions_at_threshold, self.categories
            ).as_dict(),
            "latency": {
                "total": latency_stats(latencies).as_dict(),
                "preprocess": latency_stats([p.preprocess_ms for p in self.predictions]).as_dict(),
                "inference": latency_stats([p.inference_ms for p in self.predictions]).as_dict(),
                "note": (
                    "Detector-level latency on this machine. NOT gateway overhead, which is "
                    "measured through the HTTP path (docs/15-performance-benchmarking.md)."
                ),
            },
            "errors": {
                "count": sum(1 for p in self.predictions if p.errored),
                "kinds": sorted({p.error_kind for p in self.predictions if p.error_kind}),
            },
        }


def make_run_id(detector: str, benchmark: str, split: Split, started: datetime) -> str:
    """Deterministic, sortable, and self-describing.

    Timestamped so no run can overwrite another (§22).
    """
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    safe_detector = detector.replace(".", "-")
    return f"{stamp}__{safe_detector}__{benchmark}-{split.value}"


async def run_evaluation(
    *,
    detector_name: str,
    benchmark: str,
    split: Split,
    threshold: float | None = None,
    objective: Objective | None = None,
    constraint: float | None = None,
    seed: int = DEFAULT_SEED,
    detector_options: dict[str, Any] | None = None,
) -> EvaluationResult:
    """Run one detector over one split and produce evidence.

    When `objective` is supplied the threshold is *calibrated* on this split,
    which is refused on test. Otherwise the supplied or configured threshold is
    used and only reporting happens.
    """
    started = datetime.now(UTC)
    all_samples, sources = load_benchmark(benchmark)

    dataset_report = validate_dataset(all_samples)
    warnings: list[str] = []
    if dataset_report["cross_split_leakage"]:
        warnings.append(
            f"{dataset_report['cross_split_leakage']} texts appear in more than one split; "
            "every metric below is inflated by leakage"
        )
    if dataset_report["duplicate_texts"]:
        warnings.append(
            f"{dataset_report['duplicate_texts']} duplicate texts within splits inflate "
            "whichever class they belong to"
        )
    if not dataset_report["split_assignment_verified"]:
        warnings.append("split assignment does not match sha256(sample_id) for every sample")

    detector = build_detector(detector_name, threshold=threshold, **(detector_options or {}))
    scope = detector.scope()

    split_samples = filter_split(all_samples, split)
    samples = [sample for sample in split_samples if sample.category in scope]
    skipped = len(split_samples) - len(samples)
    if skipped:
        warnings.append(
            f"{skipped} samples outside {detector_name}'s scope were excluded; it is not "
            "answerable for those categories and scoring them would fabricate a recall number"
        )

    if not samples:
        raise ValueError(f"no samples for detector {detector_name!r} on {benchmark}/{split.value}")

    await detector.warmup()
    try:
        predictions = [await detector.predict(sample) for sample in samples]
    finally:
        await detector.aclose()

    result = EvaluationResult(
        run_id=make_run_id(detector_name, benchmark, split, started),
        detector=detector_name,
        benchmark=benchmark,
        split=split,
        samples=samples,
        predictions=predictions,
        metadata={},
        dataset_report=dataset_report,
        sources=sources,
        warnings=warnings,
    )

    labels = result.labels
    scores = result.scores

    if objective is not None:
        # Raises on the frozen test split.
        operating_point, sweep = calibrate(
            labels, scores, split=split, objective=objective, constraint=constraint
        )
        result.operating_point = operating_point
        result.sweep = sweep
        result.threshold = operating_point.threshold
        if not operating_point.satisfied:
            warnings.append(operating_point.rationale)
    else:
        configured = detector.config().get("threshold", 0.5)
        result.threshold = threshold if threshold is not None else float(configured)
        from eval.metrics.classification import threshold_sweep

        result.sweep = threshold_sweep(labels, scores)

    if len({sample.label for sample in samples}) < 2:
        warnings.append(
            "the evaluated subset contains only one class; precision, recall and FPR are "
            "degenerate and must not be quoted"
        )

    result.metadata = run_metadata(
        run_id=result.run_id,
        detector=detector_name,
        detector_config=detector.config(),
        dataset_name=benchmark,
        dataset_checksum=dataset_checksum(all_samples),
        split=split.value,
        sample_count=len(samples),
        seed=seed,
        started_at=started.isoformat(),
        finished_at=datetime.now(UTC).isoformat(),
    )
    result.metadata["dataset"]["sources"] = {
        name: {
            "source": entry.source,
            "licence": entry.licence,
            "commercial_use": entry.commercial_use,
            "contamination_risk": entry.contamination_risk,
            "verified_on": entry.verified_on,
        }
        for name, entry in sources.items()
    }
    result.metadata["operating_point_table"] = operating_point_table(result.sweep)
    return result


def run_evaluation_sync(**kwargs: Any) -> EvaluationResult:
    return asyncio.run(run_evaluation(**kwargs))
