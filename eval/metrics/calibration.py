"""Threshold selection — the only place a number is *chosen* rather than measured.

Two safeguards, both structural rather than advisory:

1. Every entry point calls :func:`eval.schema.require_tunable`, which raises on
   the test split. Tuning on test is the field's most common self-deception and
   a docstring asking people not to is not a control.
2. An operating point is selected against an **explicitly stated objective**,
   and the objective is recorded in the report next to the threshold. A
   threshold with no stated objective is a number someone liked the look of.

No default FPR budget is invented here. `docs/13-evaluation-strategy.md` refuses
to assert an operational tolerance the project has not earned, so the objective
is a required argument and the report prints the whole trade-off curve so a
reader can choose differently.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from eval.metrics.classification import ThresholdPoint, threshold_sweep
from eval.schema import Split, require_tunable


class Objective(StrEnum):
    """How an operating point is chosen. Recorded in every report."""

    MAX_RECALL_AT_FPR = "max_recall_at_fpr"
    MAX_F1 = "max_f1"
    MIN_FPR_AT_RECALL = "min_fpr_at_recall"


@dataclass(frozen=True, slots=True)
class OperatingPoint:
    threshold: float
    objective: Objective
    constraint: float | None
    satisfied: bool
    rationale: str
    point: ThresholdPoint

    def as_dict(self) -> dict[str, Any]:
        return {
            "threshold": round(self.threshold, 4),
            "objective": self.objective.value,
            "constraint": self.constraint,
            "constraint_satisfied": self.satisfied,
            "rationale": self.rationale,
            "metrics": self.point.as_dict(),
        }


def calibrate(
    labels: Sequence[bool],
    scores: Sequence[float],
    *,
    split: Split,
    objective: Objective,
    constraint: float | None = None,
) -> tuple[OperatingPoint, list[ThresholdPoint]]:
    """Select a threshold on a tunable split, and return the full sweep with it.

    The sweep is returned alongside so a report never shows a chosen threshold
    without the trade-off it was chosen from.
    """
    require_tunable(split)

    if len(labels) != len(scores):
        raise ValueError("labels and scores differ in length")
    if not labels:
        raise ValueError("cannot calibrate on an empty split")
    if not any(labels):
        raise ValueError("calibration split contains no attack samples")
    if all(labels):
        raise ValueError(
            "calibration split contains no benign samples: FPR would be undefined, "
            "and a threshold chosen without it is meaningless"
        )

    sweep = threshold_sweep(labels, scores)

    if objective is Objective.MAX_RECALL_AT_FPR:
        if constraint is None:
            raise ValueError("MAX_RECALL_AT_FPR requires an explicit FPR budget")
        eligible = [p for p in sweep if p.matrix.fpr <= constraint]
        if eligible:
            # Highest recall within budget; ties broken toward the higher
            # threshold, which is the more conservative choice.
            best = max(eligible, key=lambda p: (p.matrix.recall, p.threshold))
            # A budget met by detecting nothing is arithmetically satisfied and
            # operationally useless. Reporting it as a success would let a
            # detector that separates nothing look like it passed.
            degenerate = best.matrix.tp == 0
            return (
                OperatingPoint(
                    threshold=best.threshold,
                    objective=objective,
                    constraint=constraint,
                    satisfied=not degenerate,
                    rationale=(
                        (
                            f"DEGENERATE: the only thresholds meeting FPR <= {constraint} on the "
                            f"{split.value} split detect nothing at all (recall 0). The "
                            "constraint is met arithmetically and the operating point is "
                            "useless; the detector does not separate the classes at this budget."
                        )
                        if degenerate
                        else (
                            f"highest recall ({best.matrix.recall:.4f}) among thresholds with "
                            f"FPR <= {constraint} on the {split.value} split"
                        )
                    ),
                    point=best,
                ),
                sweep,
            )
        # No point meets the budget. Report that honestly rather than silently
        # relaxing the constraint — the useful finding is that the detector
        # cannot meet the requirement at any threshold.
        best = min(sweep, key=lambda p: (p.matrix.fpr, -p.matrix.recall))
        return (
            OperatingPoint(
                threshold=best.threshold,
                objective=objective,
                constraint=constraint,
                satisfied=False,
                rationale=(
                    f"NO threshold achieves FPR <= {constraint} on the {split.value} split; "
                    f"reporting the lowest-FPR point ({best.matrix.fpr:.4f}). The detector "
                    "does not meet the stated objective."
                ),
                point=best,
            ),
            sweep,
        )

    if objective is Objective.MAX_F1:
        best = max(sweep, key=lambda p: (p.matrix.f1, p.threshold))
        return (
            OperatingPoint(
                threshold=best.threshold,
                objective=objective,
                constraint=None,
                satisfied=True,
                rationale=(
                    f"maximum F1 ({best.matrix.f1:.4f}) on the {split.value} split. F1 weights "
                    "precision and recall equally, which is rarely what a security gateway "
                    "wants; reported for comparison, not as an operational recommendation"
                ),
                point=best,
            ),
            sweep,
        )

    if constraint is None:
        raise ValueError("MIN_FPR_AT_RECALL requires an explicit recall floor")
    eligible = [p for p in sweep if p.matrix.recall >= constraint]
    if eligible:
        best = min(eligible, key=lambda p: (p.matrix.fpr, -p.threshold))
        return (
            OperatingPoint(
                threshold=best.threshold,
                objective=objective,
                constraint=constraint,
                satisfied=True,
                rationale=(
                    f"lowest FPR ({best.matrix.fpr:.4f}) among thresholds with recall >= "
                    f"{constraint} on the {split.value} split"
                ),
                point=best,
            ),
            sweep,
        )
    best = max(sweep, key=lambda p: (p.matrix.recall, -p.threshold))
    return (
        OperatingPoint(
            threshold=best.threshold,
            objective=objective,
            constraint=constraint,
            satisfied=False,
            rationale=(
                f"NO threshold achieves recall >= {constraint} on the {split.value} split; "
                f"reporting the highest-recall point ({best.matrix.recall:.4f})"
            ),
            point=best,
        ),
        sweep,
    )


def operating_point_table(
    sweep: Sequence[ThresholdPoint], *, limit: int = 12
) -> list[dict[str, Any]]:
    """A readable subset of the sweep for the human report.

    Thresholds where the confusion matrix actually changes — a uniform sample
    would show a dozen identical rows for a detector whose scores cluster.
    """
    interesting: list[ThresholdPoint] = []
    previous: tuple[int, int, int, int] | None = None
    for point in sweep:
        key = (point.matrix.tp, point.matrix.fp, point.matrix.tn, point.matrix.fn)
        if key != previous:
            interesting.append(point)
            previous = key
    if len(interesting) <= limit:
        return [point.as_dict() for point in interesting]
    step = len(interesting) / limit
    sampled = [interesting[int(i * step)] for i in range(limit)]
    if interesting[-1] not in sampled:
        sampled[-1] = interesting[-1]
    return [point.as_dict() for point in sampled]
