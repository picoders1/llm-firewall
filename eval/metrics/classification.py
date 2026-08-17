"""Classification metrics, implemented directly and verified against a reference.

Implemented here rather than imported from scikit-learn for two reasons: a
security benchmark's arithmetic should be readable and auditable in the
repository that publishes it, and the `eval` extra stays small. Correctness is
not taken on trust — `tests/evaluation/test_metrics.py` checks every metric
against hand-computed confusion matrices *and*, when scikit-learn is installed,
against its implementation.

Convention throughout: **positive = attack**.

|                    | predicted attack | predicted benign |
|--------------------|------------------|------------------|
| **actually attack**| TP               | FN — the security failure |
| **actually benign**| FP — the usability failure | TN |
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

# 95% two-sided normal quantile, for Wilson intervals.
Z_95 = 1.959963984540054


def wilson_interval(successes: int, total: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Used instead of the normal approximation because it stays inside [0, 1] and
    behaves sensibly at small n and at proportions near 0 or 1 — exactly the
    conditions an early security benchmark operates under. Reporting a bare
    "0.94 recall" without this invites over-reading a difference that the sample
    size cannot support.
    """
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denominator = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / denominator
    margin = (z / denominator) * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2))
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


@dataclass(frozen=True, slots=True)
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def positives(self) -> int:
        """Actual attacks — the denominator of recall."""
        return self.tp + self.fn

    @property
    def negatives(self) -> int:
        """Actual benign samples — the denominator of FPR, and the number that
        decides whether this is deployable."""
        return self.tn + self.fp

    @property
    def precision(self) -> float:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _ratio(self.tp, self.positives)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        """Reported only alongside the matrix: with 90% benign traffic,
        "always allow" scores 90% accuracy."""
        return _ratio(self.tp + self.tn, self.total)

    @property
    def fpr(self) -> float:
        """The number that decides adoption. At 100 req/s, 1% is 3 600
        wrongly-blocked requests an hour."""
        return _ratio(self.fp, self.negatives)

    @property
    def fnr(self) -> float:
        """The residual risk being accepted."""
        return _ratio(self.fn, self.positives)

    @property
    def detection_rate(self) -> float:
        """Synonym for recall, in the security vocabulary."""
        return self.recall

    def as_dict(self) -> dict[str, Any]:
        recall_lo, recall_hi = wilson_interval(self.tp, self.positives)
        precision_lo, precision_hi = wilson_interval(self.tp, self.tp + self.fp)
        fpr_lo, fpr_hi = wilson_interval(self.fp, self.negatives)
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "n": self.total,
            "n_attack": self.positives,
            "n_benign": self.negatives,
            "precision": round(self.precision, 4),
            "precision_ci95": [round(precision_lo, 4), round(precision_hi, 4)],
            "recall": round(self.recall, 4),
            "recall_ci95": [round(recall_lo, 4), round(recall_hi, 4)],
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
            "fpr_ci95": [round(fpr_lo, 4), round(fpr_hi, 4)],
            "fnr": round(self.fnr, 4),
        }


def confusion(labels: Sequence[bool], predictions: Sequence[bool]) -> ConfusionMatrix:
    if len(labels) != len(predictions):
        raise ValueError(f"length mismatch: {len(labels)} labels, {len(predictions)} predictions")
    tp = fp = tn = fn = 0
    for actual, predicted in zip(labels, predictions, strict=True):
        if actual and predicted:
            tp += 1
        elif actual:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    return ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)


def confusion_at(
    labels: Sequence[bool], scores: Sequence[float], threshold: float
) -> ConfusionMatrix:
    """Confusion matrix at a threshold. Trigger is `score >= threshold`,
    matching the policy engine exactly (docs/06-policy-engine.md)."""
    return confusion(labels, [score >= threshold for score in scores])


@dataclass(frozen=True, slots=True)
class ThresholdPoint:
    threshold: float
    matrix: ConfusionMatrix

    def as_dict(self) -> dict[str, Any]:
        return {"threshold": round(self.threshold, 4), **self.matrix.as_dict()}


def threshold_sweep(
    labels: Sequence[bool], scores: Sequence[float], *, steps: int = 101
) -> list[ThresholdPoint]:
    """Metrics across the score range — the operator's actual decision surface.

    Candidate thresholds are the observed scores themselves plus a uniform grid:
    a detector whose scores cluster on a few values (any rule-based one) would
    otherwise have its real operating points missed entirely by a uniform sweep.
    """
    grid = {round(i / (steps - 1), 4) for i in range(steps)}
    grid.update(round(score, 6) for score in scores)
    grid.add(0.0)
    return [
        ThresholdPoint(threshold=t, matrix=confusion_at(labels, scores, t)) for t in sorted(grid)
    ]


def precision_recall_curve(
    labels: Sequence[bool], scores: Sequence[float]
) -> list[tuple[float, float, float]]:
    """`(threshold, recall, precision)` points, ordered by recall."""
    points = [
        (point.threshold, point.matrix.recall, point.matrix.precision)
        for point in threshold_sweep(labels, scores)
    ]
    return sorted(points, key=lambda p: (p[1], p[2]))


def average_precision(labels: Sequence[bool], scores: Sequence[float]) -> float:
    """Area under the precision-recall curve, by the step-wise sum.

    Preferred over AUROC on imbalanced security data: AUROC is dominated by the
    large benign class and flatters a detector that is useless at the operating
    points anyone would actually deploy.
    """
    ordered = sorted(zip(scores, labels, strict=True), key=lambda pair: -pair[0])
    total_positives = sum(1 for _, label in ordered if label)
    if total_positives == 0:
        return 0.0
    tp = 0
    seen = 0
    previous_recall = 0.0
    area = 0.0
    for _, label in ordered:
        seen += 1
        if label:
            tp += 1
        recall = tp / total_positives
        precision = tp / seen
        area += precision * (recall - previous_recall)
        previous_recall = recall
    return area


def roc_auc(labels: Sequence[bool], scores: Sequence[float]) -> float:
    """AUROC via the rank-sum identity, with ties averaged.

    Reported for comparability with published numbers, never as the headline.
    """
    positives = [s for s, label in zip(scores, labels, strict=True) if label]
    negatives = [s for s, label in zip(scores, labels, strict=True) if not label]
    if not positives or not negatives:
        return 0.0
    ordered = sorted(zip(scores, labels, strict=True), key=lambda pair: pair[0])
    ranks: dict[int, float] = {}
    index = 0
    while index < len(ordered):
        end = index
        while end + 1 < len(ordered) and ordered[end + 1][0] == ordered[index][0]:
            end += 1
        average_rank = (index + end) / 2 + 1
        for position in range(index, end + 1):
            ranks[position] = average_rank
        index = end + 1
    positive_rank_sum = sum(rank for position, rank in ranks.items() if ordered[position][1])
    n_pos, n_neg = len(positives), len(negatives)
    return (positive_rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


@dataclass
class CategoryBreakdown:
    """Per-category recall and FPR.

    An aggregate number hides that indirect injection is far harder than direct,
    which is precisely the fact an operator needs (docs/13-evaluation-strategy.md).
    """

    per_category: dict[str, ConfusionMatrix] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {name: matrix.as_dict() for name, matrix in sorted(self.per_category.items())}


def category_breakdown(
    labels: Sequence[bool],
    predictions: Sequence[bool],
    categories: Sequence[str],
) -> CategoryBreakdown:
    grouped: dict[str, list[tuple[bool, bool]]] = {}
    for label, prediction, category in zip(labels, predictions, categories, strict=True):
        grouped.setdefault(category, []).append((label, prediction))
    return CategoryBreakdown(
        per_category={
            category: confusion([p[0] for p in pairs], [p[1] for p in pairs])
            for category, pairs in grouped.items()
        }
    )
