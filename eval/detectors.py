"""Adapters that let the harness drive any detector uniformly.

The evaluation layer **calls the production detector interfaces** from `app/`;
it never reimplements detection. A benchmark that measures a copy of the
detector measures the copy.

The adapter is what makes the framework detector-agnostic: a future transformer
classifier, a guard model or a remote service plugs in here and every metric,
report and safeguard works unchanged (docs/13-evaluation-strategy.md §10).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

from app.config.policy import DetectorPolicy
from app.core.normalize import decode_embedded, normalize
from app.core.types import DetectionContext, Direction, Role
from app.detectors import registry as app_registry
from eval.schema import DETECTOR_SCOPE, Category, Sample


@dataclass(frozen=True, slots=True)
class Prediction:
    """One detector's output for one sample, with its cost."""

    sample_id: str
    score: float
    detected_at_configured_threshold: bool
    reasons: tuple[str, ...]
    errored: bool
    error_kind: str | None
    preprocess_ms: float
    inference_ms: float

    @property
    def total_ms(self) -> float:
        return self.preprocess_ms + self.inference_ms


class EvaluableDetector(Protocol):
    name: str

    async def predict(self, sample: Sample) -> Prediction: ...
    async def warmup(self) -> None: ...
    async def aclose(self) -> None: ...
    def config(self) -> dict[str, Any]: ...
    def scope(self) -> frozenset[Category]: ...


class AppDetectorAdapter:
    """Drives a detector registered in `app.detectors.registry`.

    Preprocessing (normalisation, base64 surfacing) is timed **separately** from
    inference. A comparison that folds preprocessing into one number would
    flatter a detector that does less of it, and the split is what lets the
    report answer "where does the time actually go".
    """

    def __init__(self, name: str, *, threshold: float, options: dict[str, Any] | None = None):
        self.name = name
        self._threshold = threshold
        self._options = options or {}
        self._policy = DetectorPolicy(
            detector=name,
            threshold=threshold,
            action="block",
            options=self._options,
        )
        self._detector = app_registry.create(name, self._policy)

    def config(self) -> dict[str, Any]:
        return {
            "detector": self.name,
            "threshold": self._threshold,
            "options": self._options,
            "implementation": type(self._detector).__module__
            + "."
            + type(self._detector).__qualname__,
        }

    def scope(self) -> frozenset[Category]:
        return DETECTOR_SCOPE.get(
            self.name,
            frozenset(Category),  # unknown detector: evaluated on everything
        )

    async def warmup(self) -> None:
        await self._detector.warmup()

    async def aclose(self) -> None:
        await self._detector.aclose()

    def _context(self, sample: Sample) -> tuple[DetectionContext, float]:
        started = time.perf_counter()
        folded = normalize(sample.text)
        context = DetectionContext(
            request_id=f"eval-{sample.sample_id}",
            direction=Direction.INPUT,
            role=Role.USER,
            raw_text=sample.text,
            normalized_text=folded.text,
            normalized_offsets=folded.offsets,
            decoded_segments=decode_embedded(sample.text),
        )
        return context, (time.perf_counter() - started) * 1000.0

    async def predict(self, sample: Sample) -> Prediction:
        context, preprocess_ms = self._context(sample)
        started = time.perf_counter()
        try:
            result = await self._detector.detect(context)
        except Exception as exc:
            inference_ms = (time.perf_counter() - started) * 1000.0
            return Prediction(
                sample_id=sample.sample_id,
                score=0.0,
                detected_at_configured_threshold=False,
                reasons=(),
                errored=True,
                error_kind=type(exc).__name__,
                preprocess_ms=preprocess_ms,
                inference_ms=inference_ms,
            )
        inference_ms = (time.perf_counter() - started) * 1000.0
        return Prediction(
            sample_id=sample.sample_id,
            score=result.score,
            detected_at_configured_threshold=result.detected,
            reasons=result.reasons,
            errored=result.errored,
            error_kind=result.error_kind,
            preprocess_ms=preprocess_ms,
            inference_ms=inference_ms,
        )


# Baseline detectors, with the thresholds currently in the shipped policy. These
# are the control condition; anything proposed for production is measured
# against them on the same data (docs/13-evaluation-strategy.md).
BASELINE_DETECTORS: dict[str, dict[str, Any]] = {
    "injection.heuristic": {"threshold": 0.85},
    "jailbreak.heuristic": {"threshold": 0.85},
    "pii.regex": {"threshold": 0.50},
}


class AlwaysBenign:
    """Predicts benign for everything.

    Establishes the accuracy floor: on a 90%-benign corpus this scores 90%
    accuracy, which is why accuracy is never the headline metric.
    """

    name = "baseline.always_benign"

    async def predict(self, sample: Sample) -> Prediction:
        return Prediction(sample.sample_id, 0.0, False, (), False, None, 0.0, 0.0)

    async def warmup(self) -> None: ...
    async def aclose(self) -> None: ...

    def config(self) -> dict[str, Any]:
        return {"detector": self.name, "threshold": 1.0}

    def scope(self) -> frozenset[Category]:
        return frozenset(Category)


class AlwaysAttack:
    """Predicts attack for everything.

    Achieves perfect recall and 100% FPR, which makes the recall/FPR trade
    impossible to ignore in the comparison table.
    """

    name = "baseline.always_attack"

    async def predict(self, sample: Sample) -> Prediction:
        return Prediction(sample.sample_id, 1.0, True, (), False, None, 0.0, 0.0)

    async def warmup(self) -> None: ...
    async def aclose(self) -> None: ...

    def config(self) -> dict[str, Any]:
        return {"detector": self.name, "threshold": 0.0}

    def scope(self) -> frozenset[Category]:
        return frozenset(Category)


TRIVIAL_BASELINES: dict[str, type[AlwaysBenign] | type[AlwaysAttack]] = {
    AlwaysBenign.name: AlwaysBenign,
    AlwaysAttack.name: AlwaysAttack,
}


def build_detector(name: str, *, threshold: float | None = None, **options: Any) -> Any:
    """Resolve a detector by name for the harness.

    Candidates live in `eval.candidates` and are **evaluation-only** — resolving
    one here does not make it available to the gateway.
    """
    if name in TRIVIAL_BASELINES:
        return TRIVIAL_BASELINES[name]()

    from eval.candidates import CANDIDATES, build_candidate

    if name in CANDIDATES:
        return build_candidate(name, threshold=threshold if threshold is not None else 0.5)

    if name in app_registry.registered_names():
        default = BASELINE_DETECTORS.get(name, {}).get("threshold", 0.5)
        return AppDetectorAdapter(
            name, threshold=threshold if threshold is not None else default, options=options
        )

    raise ValueError(
        f"unknown detector {name!r}; available: "
        f"{', '.join(sorted([*app_registry.registered_names(), *TRIVIAL_BASELINES]))}"
    )


def available_detectors(*, include_candidates: bool = False) -> list[str]:
    names = [*app_registry.registered_names(), *TRIVIAL_BASELINES]
    if include_candidates:
        from eval.candidates import candidate_names

        names.extend(candidate_names())
    return sorted(names)
