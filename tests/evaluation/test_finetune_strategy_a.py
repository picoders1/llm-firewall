"""Guards on the Strategy A experiment.

The experiment's credibility rests on one claim: the frozen hold-out was never
used to train, to select a checkpoint, or to select a threshold. These tests
make that claim mechanical rather than a matter of trust.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.finetune_strategy_a import (
    BATCH_SIZE,
    EPOCH_COUNTS,
    HARD_NEGATIVE_GROUPS,
    HOLDOUT_FILE,
    INJECTION_SCOPE,
    LEARNING_RATES,
    MAX_LENGTH,
    MICRO_BATCH_SIZE,
    RUN_SUFFIX,
    SEEDS,
    WARMUP_RATIO,
    WEIGHT_DECAY,
    HoldOutAccessError,
    cross_entropy,
    guard_no_collision,
    guard_no_holdout,
    load_jsonl,
)

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS = REPO_ROOT / "eval" / "results" / "finetune"


def _run_dirs() -> list[Path]:
    return sorted(RESULTS.glob(f"*{RUN_SUFFIX}"))


def _artefact(name: str) -> Path | None:
    dirs = _run_dirs()
    if len(dirs) != 1:
        return None
    candidate = dirs[0] / name
    return candidate if candidate.exists() else None


LOCK_FILE = _artefact("selection_lock.json")
VERIFICATION_FILE = _artefact("pre_holdout_verification.json")
HOLDOUT_RESULT = _artefact("holdout_metrics.json")


# --- The hard boundary -------------------------------------------------------


def test_training_refuses_a_path_inside_the_holdout_directory():
    with pytest.raises(HoldOutAccessError, match="hold-out"):
        guard_no_holdout([HOLDOUT_FILE])


def test_training_refuses_holdout_content_even_under_another_path():
    """Renaming the file must not get it past the guard: the second gate is
    content-based, not path-based."""
    holdout = load_jsonl(HOLDOUT_FILE)
    with pytest.raises(HoldOutAccessError, match="collide"):
        guard_no_collision([{"text": holdout[0]["text"]}])


def test_the_real_training_corpus_passes_both_guards():
    guard_no_holdout(
        [
            REPO_ROOT / "eval" / "datasets" / "finetune" / "train" / "cases.jsonl",
            REPO_ROOT / "eval" / "datasets" / "finetune" / "dev" / "cases.jsonl",
        ]
    )
    train = load_jsonl(REPO_ROOT / "eval" / "datasets" / "finetune" / "train" / "cases.jsonl")
    dev = load_jsonl(REPO_ROOT / "eval" / "datasets" / "finetune" / "dev" / "cases.jsonl")
    guard_no_collision(train + dev)


# --- The pre-registered protocol is what the code actually runs --------------


def test_hyperparameter_matrix_matches_adr_015():
    """ADR-015 fixes the search space in advance. Widening it here — after
    seeing results — would be the classic way to fabricate a success."""
    assert LEARNING_RATES == (1e-5, 2e-5, 3e-5)
    assert EPOCH_COUNTS == (2, 3)
    assert SEEDS == (13, 20260817, 31337)
    assert len(LEARNING_RATES) * len(EPOCH_COUNTS) * len(SEEDS) == 18
    assert BATCH_SIZE == 16
    assert WEIGHT_DECAY == 0.01
    assert MAX_LENGTH == 512
    assert WARMUP_RATIO == 0.1


def test_micro_batching_divides_the_registered_batch_exactly():
    """Gradient accumulation is a memory strategy. If the micro-batch did not
    divide 16 exactly, the effective batch size would drift from the protocol."""
    assert BATCH_SIZE % MICRO_BATCH_SIZE == 0


def test_attack_recall_scope_excludes_categories_the_detector_never_claimed():
    """Comparability with the 0.8833 base figure requires the same denominator."""
    assert INJECTION_SCOPE == {
        "direct_prompt_injection",
        "indirect_prompt_injection",
        "system_prompt_extraction",
    }
    assert "pii" not in INJECTION_SCOPE
    assert "jailbreak" not in INJECTION_SCOPE


# --- Threshold selection -----------------------------------------------------


def test_threshold_calibration_refuses_the_frozen_test_split():
    """Calibration goes through the project's `calibrate()`, whose
    `require_tunable` raises on a frozen split. The dev-only guarantee is
    enforced by the library rather than by the caller."""
    from eval.metrics.calibration import Objective, calibrate
    from eval.schema import Split

    labels = [False] * 50 + [True] * 50
    scores = [0.1] * 50 + [0.9] * 50
    with pytest.raises(Exception, match="test"):
        calibrate(
            labels, scores, split=Split.TEST, objective=Objective.MAX_RECALL_AT_FPR, constraint=0.05
        )
    point, _ = calibrate(
        labels, scores, split=Split.DEV, objective=Objective.MAX_RECALL_AT_FPR, constraint=0.05
    )
    assert point.satisfied


def test_dev_loss_is_the_real_cross_entropy():
    """dev_loss is recomputed from stored P(INJECTION). For a 2-class softmax
    head that is exact, not an approximation — a confident correct prediction
    must give ~0 and a confident wrong one must give a large value."""
    import math

    assert cross_entropy([1, 0], [1.0 - 1e-9, 1e-9]) < 1e-6
    assert cross_entropy([0], [1.0 - 1e-9]) > 15
    # Maximum uncertainty is log 2 regardless of label.
    assert abs(cross_entropy([1, 0], [0.5, 0.5]) - math.log(2)) < 1e-9


def test_hard_negative_groups_exist_in_the_holdout():
    """Every §12 category must resolve against real hold-out samples, or the
    report would silently print an empty row instead of evidence."""
    rows = load_jsonl(HOLDOUT_FILE)
    benign = [r for r in rows if r["category"] == "benign"]
    for name, field, value in HARD_NEGATIVE_GROUPS:
        matched = [r for r in benign if r.get(field) == value]
        assert matched, f"{name} matched no hold-out samples via {field}={value}"


# --- Artefact discipline, checked only once the experiment has run -----------


@pytest.mark.skipif(LOCK_FILE is None, reason="experiment not yet run")
def test_lock_manifest_declares_the_holdout_was_not_used_for_selection():
    lock = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
    assert lock["holdout_used_in_selection"] is False
    assert lock["selection_basis"].startswith("dev split only")
    assert "selected_threshold" in lock


@pytest.mark.skipif(HOLDOUT_RESULT is None, reason="hold-out not yet scored")
def test_holdout_was_scored_once_against_the_locked_threshold():
    lock = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
    hold = json.loads(HOLDOUT_RESULT.read_text(encoding="utf-8"))
    assert hold["evaluation_count"] == 1
    assert hold["threshold"] == lock["selected_threshold"]
    assert hold["checkpoint"] == lock["selected_run_id"]
    # The hold-out must be the same bytes the lock was written against.
    assert hold["holdout_content_hash"] == lock["holdout_content_hash"]


@pytest.mark.skipif(HOLDOUT_RESULT is None, reason="hold-out not yet scored")
def test_holdout_metrics_carry_denominators_and_intervals():
    """A rate without its denominator is not evidence."""
    hold = json.loads(HOLDOUT_RESULT.read_text(encoding="utf-8"))
    for section, key in [
        ("benign", "fpr"),
        ("hard_negatives", "fpr"),
        ("quoted_attack", "fpr"),
        ("attack_recall", "recall"),
        ("system_prompt_extraction", "recall"),
    ]:
        block = hold[section]
        assert block["n"] > 0, section
        assert f"{key}_ci95_wilson" in block, section
        lo, hi = block[f"{key}_ci95_wilson"]
        assert lo <= block[key] <= hi, section
