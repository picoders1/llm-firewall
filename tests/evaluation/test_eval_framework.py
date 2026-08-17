"""The evaluation framework must be at least as trustworthy as what it measures.

A benchmark whose arithmetic is unverified produces confident nonsense. Every
metric here is checked against a hand-computed confusion matrix, and — when
scikit-learn is installed — against a reference implementation as well.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.metrics.calibration import Objective, calibrate, operating_point_table
from eval.metrics.classification import (
    ConfusionMatrix,
    average_precision,
    category_breakdown,
    confusion,
    confusion_at,
    precision_recall_curve,
    roc_auc,
    threshold_sweep,
    wilson_interval,
)
from eval.metrics.latency import MIN_SAMPLES_FOR_PERCENTILES, latency_stats, percentile
from eval.schema import (
    Category,
    FrozenSplitError,
    Sample,
    Split,
    assign_split,
    content_id,
    dataset_checksum,
    normalised_key,
    require_tunable,
    validate_dataset,
)

pytestmark = pytest.mark.evaluation


def sample(
    text: str = "hello",
    category: Category = Category.BENIGN,
    sample_id: str | None = None,
    split: Split | None = None,
) -> Sample:
    identifier = sample_id or content_id("test", text)
    return Sample(
        sample_id=identifier,
        text=text,
        category=category,
        label=category is not Category.BENIGN,
        source="test",
        split=split or assign_split(normalised_key(text)),
    )


# --- Schema ---------------------------------------------------------------


def test_label_must_agree_with_category():
    with pytest.raises(ValueError, match="contradicts category"):
        Sample(
            sample_id="x",
            text="t",
            category=Category.BENIGN,
            label=True,
            source="s",
            split=Split.DEV,
        )


def test_oversized_text_is_rejected():
    with pytest.raises(ValueError, match="benchmark limit"):
        Sample(
            sample_id="x",
            text="a" * 20_001,
            category=Category.BENIGN,
            label=False,
            source="s",
            split=Split.DEV,
        )


def test_sample_ids_are_deterministic():
    assert content_id("src", "text") == content_id("src", "text")
    assert content_id("src", "text") != content_id("src", "other")


@pytest.mark.parametrize("text", ["hello", "IGNORE ALL", "a b c", "x" * 500])
def test_split_assignment_is_deterministic(text: str):
    assert assign_split(normalised_key(text)) is assign_split(normalised_key(text))


def test_split_is_derived_from_content_not_from_the_id():
    """Regression: splitting on sample_id put the same text in two splits when it
    appeared in two source corpora, leaking test cases into dev."""
    text = "What is 1+1?"
    a = sample(text, sample_id="corpus-a-0001")
    b = sample(text, sample_id="corpus-b-9999")

    assert a.sample_id != b.sample_id
    assert a.split is b.split


def test_normalisation_folds_formatting_differences():
    assert normalised_key("What is 1+1?") == normalised_key("what is  1+1?  ")


def test_dataset_checksum_is_order_independent():
    samples = [sample("a"), sample("b"), sample("c")]
    assert dataset_checksum(samples) == dataset_checksum(list(reversed(samples)))


def test_dataset_checksum_changes_with_content():
    assert dataset_checksum([sample("a")]) != dataset_checksum([sample("b")])


def test_validate_detects_cross_split_leakage():
    leaked = [
        sample("same text", sample_id="a", split=Split.DEV),
        sample("same text", sample_id="b", split=Split.TEST),
    ]
    assert validate_dataset(leaked)["cross_split_leakage"] == 1


def test_validate_detects_duplicate_texts():
    duplicates = [
        sample("dup", sample_id="a", split=Split.DEV),
        sample("dup", sample_id="b", split=Split.DEV),
    ]
    assert validate_dataset(duplicates)["duplicate_texts"] == 1


def test_validate_rejects_duplicate_ids():
    with pytest.raises(ValueError, match="duplicate sample_ids"):
        validate_dataset([sample("a", sample_id="x"), sample("b", sample_id="x")])


def test_validate_rejects_an_empty_dataset():
    with pytest.raises(ValueError, match="empty"):
        validate_dataset([])


# --- The frozen test split ------------------------------------------------


def test_require_tunable_refuses_the_test_split():
    with pytest.raises(FrozenSplitError, match="frozen"):
        require_tunable(Split.TEST)


@pytest.mark.parametrize("split", [Split.DEV, Split.TRAIN])
def test_require_tunable_allows_other_splits(split: Split):
    assert require_tunable(split) is split


def test_calibration_refuses_the_test_split():
    """The safeguard lives below the CLI, so it holds for any caller."""
    with pytest.raises(FrozenSplitError):
        calibrate(
            [True, False],
            [0.9, 0.1],
            split=Split.TEST,
            objective=Objective.MAX_F1,
        )


# --- Confusion matrix -----------------------------------------------------


def test_confusion_against_a_hand_computed_matrix():
    labels = [True, True, True, False, False, False, False]
    predictions = [True, True, False, True, False, False, False]

    matrix = confusion(labels, predictions)

    assert (matrix.tp, matrix.fn, matrix.fp, matrix.tn) == (2, 1, 1, 3)
    assert matrix.precision == pytest.approx(2 / 3)
    assert matrix.recall == pytest.approx(2 / 3)
    assert matrix.f1 == pytest.approx(2 / 3)
    assert matrix.fpr == pytest.approx(1 / 4)
    assert matrix.fnr == pytest.approx(1 / 3)
    assert matrix.accuracy == pytest.approx(5 / 7)


def test_perfect_and_useless_detectors():
    labels = [True, True, False, False]

    perfect = confusion(labels, [True, True, False, False])
    assert (perfect.recall, perfect.precision, perfect.fpr) == (1.0, 1.0, 0.0)

    always_attack = confusion(labels, [True] * 4)
    assert (always_attack.recall, always_attack.fpr) == (1.0, 1.0)

    always_benign = confusion(labels, [False] * 4)
    assert (always_benign.recall, always_benign.fpr) == (0.0, 0.0)


def test_empty_denominators_do_not_divide_by_zero():
    matrix = ConfusionMatrix()
    assert (matrix.precision, matrix.recall, matrix.fpr, matrix.f1) == (0.0, 0.0, 0.0, 0.0)


def test_length_mismatch_is_rejected():
    with pytest.raises(ValueError, match="length mismatch"):
        confusion([True], [True, False])


def test_threshold_is_inclusive_matching_the_policy_engine():
    """`score >= threshold`, exactly as app/policy/engine.py decides."""
    matrix = confusion_at([True], [0.85], 0.85)
    assert matrix.tp == 1


# --- Wilson intervals -----------------------------------------------------


def test_wilson_interval_brackets_the_estimate():
    low, high = wilson_interval(8, 10)
    assert low < 0.8 < high
    assert 0.0 <= low and high <= 1.0


def test_wilson_interval_narrows_with_more_data():
    small = wilson_interval(8, 10)
    large = wilson_interval(800, 1000)
    assert (large[1] - large[0]) < (small[1] - small[0])


def test_wilson_interval_stays_in_range_at_the_extremes():
    assert wilson_interval(0, 10)[0] == 0.0
    assert wilson_interval(10, 10)[1] == pytest.approx(1.0)
    assert wilson_interval(0, 0) == (0.0, 0.0)


# --- Sweeps and curves ----------------------------------------------------


def test_sweep_includes_observed_scores():
    """A rule-based detector's scores cluster; a uniform grid would miss its
    actual operating points."""
    thresholds = {p.threshold for p in threshold_sweep([True, False], [0.123456, 0.7])}
    assert 0.123456 in thresholds


def test_sweep_is_monotone_in_recall():
    labels = [True] * 10 + [False] * 10
    scores = [0.9] * 10 + [0.1] * 10
    sweep = threshold_sweep(labels, scores)
    recalls = [p.matrix.recall for p in sweep]
    assert recalls == sorted(recalls, reverse=True)


def test_average_precision_is_perfect_for_a_perfect_ranking():
    assert average_precision([True, True, False, False], [0.9, 0.8, 0.2, 0.1]) == pytest.approx(1.0)


def test_average_precision_handles_no_positives():
    assert average_precision([False, False], [0.1, 0.2]) == 0.0


def test_roc_auc_is_perfect_for_a_separable_ranking():
    assert roc_auc([True, True, False, False], [0.9, 0.8, 0.2, 0.1]) == pytest.approx(1.0)


def test_roc_auc_is_half_for_a_constant_score():
    assert roc_auc([True, False, True, False], [0.5] * 4) == pytest.approx(0.5)


def test_precision_recall_curve_is_ordered_by_recall():
    points = precision_recall_curve([True, True, False], [0.9, 0.4, 0.1])
    recalls = [recall for _, recall, _ in points]
    assert recalls == sorted(recalls)


# --- Calibration ----------------------------------------------------------


def test_calibration_respects_an_fpr_budget():
    labels = [True] * 10 + [False] * 90
    scores = [0.9] * 10 + [0.6] * 5 + [0.1] * 85

    point, sweep = calibrate(
        labels,
        scores,
        split=Split.DEV,
        objective=Objective.MAX_RECALL_AT_FPR,
        constraint=0.01,
    )

    assert point.satisfied
    assert point.point.matrix.fpr <= 0.01
    assert sweep


def test_calibration_flags_a_degenerate_operating_point():
    """A detector that separates nothing meets any FPR budget by detecting
    nothing. That is arithmetically true and operationally useless, so it must
    not be reported as a satisfied objective."""
    labels = [True] * 10 + [False] * 10
    scores = [0.5] * 20  # indistinguishable

    point, _ = calibrate(
        labels,
        scores,
        split=Split.DEV,
        objective=Objective.MAX_RECALL_AT_FPR,
        constraint=0.0001,
    )

    assert point.satisfied is False
    assert "DEGENERATE" in point.rationale
    assert point.point.matrix.recall == 0.0


def test_calibration_reports_failure_when_no_threshold_meets_the_budget():
    """FPR budget unachievable at any threshold that detects anything."""
    labels = [True] * 5 + [False] * 5
    scores = [0.9, 0.9, 0.9, 0.9, 0.9, 0.9, 0.9, 0.9, 0.9, 0.9]

    point, _ = calibrate(
        labels,
        scores,
        split=Split.DEV,
        objective=Objective.MIN_FPR_AT_RECALL,
        constraint=1.0,
    )

    # Recall 1.0 is achievable, but only at FPR 1.0 — the trade is visible.
    assert point.point.matrix.fpr == 1.0


def test_calibration_requires_an_explicit_constraint():
    with pytest.raises(ValueError, match="explicit FPR budget"):
        calibrate(
            [True, False],
            [0.9, 0.1],
            split=Split.DEV,
            objective=Objective.MAX_RECALL_AT_FPR,
        )


def test_calibration_refuses_a_single_class_split():
    with pytest.raises(ValueError, match="no benign samples"):
        calibrate([True, True], [0.9, 0.8], split=Split.DEV, objective=Objective.MAX_F1)
    with pytest.raises(ValueError, match="no attack samples"):
        calibrate([False, False], [0.1, 0.2], split=Split.DEV, objective=Objective.MAX_F1)


def test_operating_point_table_collapses_identical_matrices():
    labels = [True] * 5 + [False] * 5
    scores = [0.9] * 5 + [0.1] * 5
    table = operating_point_table(threshold_sweep(labels, scores))
    assert 1 <= len(table) <= 12


# --- Category breakdown ---------------------------------------------------


def test_category_breakdown_separates_categories():
    breakdown = category_breakdown(
        [True, True, False],
        [True, False, False],
        ["jailbreak", "direct_prompt_injection", "benign"],
    ).as_dict()

    assert breakdown["jailbreak"]["recall"] == 1.0
    assert breakdown["direct_prompt_injection"]["recall"] == 0.0


# --- Latency --------------------------------------------------------------


def test_percentiles_are_ordered():
    stats = latency_stats([float(i) for i in range(100)])
    assert stats.p50_ms <= stats.p95_ms <= stats.p99_ms <= stats.max_ms


def test_small_samples_are_flagged_as_unreliable():
    assert latency_stats([1.0, 2.0]).percentiles_reliable is False
    assert latency_stats([1.0] * MIN_SAMPLES_FOR_PERCENTILES).percentiles_reliable is True


def test_unreliable_percentiles_carry_a_warning_in_the_payload():
    assert "percentiles_warning" in latency_stats([1.0, 2.0]).as_dict()


def test_empty_latency_is_not_an_error():
    assert latency_stats([]).n == 0


def test_percentile_interpolates():
    assert percentile([0.0, 10.0], 0.5) == pytest.approx(5.0)


# --- Reference cross-check ------------------------------------------------


def test_metrics_match_scikit_learn_when_available():
    """Hand-computed matrices prove the arithmetic; this proves it against an
    independent implementation."""
    sklearn = pytest.importorskip("sklearn.metrics")

    labels = [True, True, True, False, False, False, False, True, False, True]
    scores = [0.9, 0.8, 0.3, 0.7, 0.2, 0.1, 0.05, 0.95, 0.4, 0.6]
    predictions = [score >= 0.5 for score in scores]
    matrix = confusion(labels, predictions)

    assert matrix.precision == pytest.approx(
        sklearn.precision_score(labels, predictions, zero_division=0)
    )
    assert matrix.recall == pytest.approx(
        sklearn.recall_score(labels, predictions, zero_division=0)
    )
    assert matrix.f1 == pytest.approx(sklearn.f1_score(labels, predictions, zero_division=0))
    assert average_precision(labels, scores) == pytest.approx(
        sklearn.average_precision_score(labels, scores), abs=1e-6
    )
    assert roc_auc(labels, scores) == pytest.approx(sklearn.roc_auc_score(labels, scores))


# --- Report artefacts -----------------------------------------------------


def test_report_refuses_to_write_without_metadata(tmp_path: Path):
    from eval.report import UnstampedReportError, write_report
    from eval.runner import EvaluationResult

    result = EvaluationResult(
        run_id="x",
        detector="d",
        benchmark="b",
        split=Split.DEV,
        samples=[],
        predictions=[],
        metadata={},  # unstamped
        dataset_report={},
        sources={},
    )
    with pytest.raises(UnstampedReportError, match="not evidence"):
        write_report(result, root=tmp_path)


def test_committed_results_are_valid_and_self_describing():
    """Every committed run must carry the metadata that makes it reproducible."""
    results = Path(__file__).resolve().parents[2] / "eval" / "results"
    reports = sorted(results.glob("*/result.json"))
    if not reports:
        pytest.skip("no committed evaluation results yet")

    for report in reports:
        payload = json.loads(report.read_text())
        metadata = payload["metadata"]
        assert metadata["git"]["commit"] or metadata["git"]["commit"] is None
        assert metadata["dataset"]["checksum"].startswith("sha256:")
        assert metadata["machine"]["python_version"]
        assert "disclaimer" in payload
        assert payload["metrics"]["classification"]["n"] > 0
