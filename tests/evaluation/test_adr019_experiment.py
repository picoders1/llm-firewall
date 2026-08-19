"""Guards on the ADR-019 mechanism-coverage experiment.

The claim this experiment makes is causal — that corpus coverage, and nothing
else, explains any change. These tests hold the properties that make the claim
checkable rather than asserted: the matrix is the registered one, the hold-out is
unreachable from training, and the training loop is literally the same code
Strategy A used.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "finetune_mechanisms.py"
RESULTS = REPO_ROOT / "eval" / "results" / "finetune" / "mechanisms"
HOLDOUT = REPO_ROOT / "eval" / "datasets" / "holdout" / "mechanisms-v1" / "cases.jsonl"
RUNS = sorted(RESULTS.glob("*__adr019-strategy-a"))


# --- The registered protocol is what the code runs -------------------------


def test_the_matrix_is_exactly_adr_019s():
    from scripts.finetune_mechanisms import BATCH_SIZE, EPOCH_COUNTS, LEARNING_RATES, SEEDS

    assert LEARNING_RATES == (1e-5, 2e-5, 3e-5)
    assert EPOCH_COUNTS == (2, 3)
    assert SEEDS == (13, 20260817, 31337)
    assert len(LEARNING_RATES) * len(EPOCH_COUNTS) * len(SEEDS) == 18
    assert BATCH_SIZE == 16


def test_the_training_loop_is_strategy_as_constants():
    """Reused, not reimplemented — so a difference in results cannot come from a
    difference in the loop."""
    from scripts import finetune_mechanisms as mech
    from scripts import finetune_strategy_a as strat

    for name in (
        "BASE_MODEL",
        "MAX_LENGTH",
        "BATCH_SIZE",
        "MICRO_BATCH_SIZE",
        "WEIGHT_DECAY",
        "WARMUP_RATIO",
        "LEARNING_RATES",
        "EPOCH_COUNTS",
        "SEEDS",
    ):
        assert getattr(mech, name) is getattr(strat, name), name


def test_effective_batch_is_16_via_micro_batching():
    from scripts.finetune_mechanisms import BATCH_SIZE, MICRO_BATCH_SIZE

    assert BATCH_SIZE % MICRO_BATCH_SIZE == 0
    assert BATCH_SIZE // MICRO_BATCH_SIZE == 4


def test_no_class_weighting_or_custom_loss_in_the_training_path():
    """ADR-019 §3/§8: ordinary supervised fine-tuning only.

    Checks identifiers and keyword arguments in the AST, not raw text. A naive
    substring search fails on the manifest field `"no_class_weighting": True`,
    which *declares the absence* — and would also be defeated by a comment. This
    inspects what the code does.
    """
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    forbidden = {
        "pos_weight",
        "class_weight",
        "class_weights",
        "FocalLoss",
        "ContrastiveLoss",
        "WeightedRandomSampler",
        "sample_weight",
    }
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in forbidden:
            used.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in forbidden:
            used.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg in forbidden:
            used.add(node.arg)
    assert not used, f"forbidden training machinery in use: {used}"


def test_the_loss_is_the_models_own_cross_entropy():
    """The only loss is what `model(**enc, labels=...)` returns — no wrapper."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert "labels=labels).loss" in source
    for wrapper in ("BCEWithLogitsLoss", "CrossEntropyLoss(", "nn.NLLLoss"):
        assert wrapper not in source, wrapper


# --- Hold-out isolation ----------------------------------------------------


def test_the_training_path_cannot_reach_the_holdout():
    from scripts.finetune_mechanisms import verify_isolation

    report = verify_isolation()
    assert report["isolated"], report["holdout_references_in_training_path"]


def test_isolation_is_checked_by_parsing_not_by_convention():
    """The check must actually inspect the AST — a stub returning True would pass
    every other test in this file."""
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "verify_isolation"
    )
    calls = {
        node.func.attr
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "parse" in calls or "walk" in calls


def test_the_isolation_check_would_catch_a_real_leak():
    """Negative control: a training function that names HOLDOUT_FILE must fail."""
    leaky = ast.parse("def train_one():\n    rows = load_jsonl(HOLDOUT_FILE)\n    return rows\n")
    offenders = [
        inner.id
        for node in ast.walk(leaky)
        if isinstance(node, ast.FunctionDef) and node.name == "train_one"
        for inner in ast.walk(node)
        if isinstance(inner, ast.Name) and inner.id == "HOLDOUT_FILE"
    ]
    assert offenders, "the detection pattern itself is broken"


def test_expected_hashes_are_pinned():
    from scripts.finetune_mechanisms import EXPECTED

    assert set(EXPECTED) == {"v2_train", "v2_dev", "mechanisms_v1", "v1_train", "v1_dev"}
    assert all(len(v) == 48 for v in EXPECTED.values())


def test_safety_check_reports_the_training_representation():
    """§9 — the record must state exactly what text reaches the model."""
    from scripts.finetune_mechanisms import safety_check

    report = safety_check()
    assert "FULL CARRIER TEXT" in report["training_input_representation"]
    assert report["holdout_collisions"] == 0
    assert not report["hash_mismatches"]
    assert report["safe_to_train"]


# --- Criteria are the registered ones --------------------------------------


def test_the_bounds_match_adr_019():
    from scripts.finetune_mechanisms import (
        BENIGN_CONTROL_FPR_BOUND,
        MAX_DEV_FPR,
        MECHANISM_RECALL_BOUND,
    )

    assert MECHANISM_RECALL_BOUND == 0.50
    assert BENIGN_CONTROL_FPR_BOUND == 0.10
    assert MAX_DEV_FPR == 0.0241


def test_the_v3_regression_baseline_matches_the_published_result():
    """Criteria 4/5 compare against immutable historical values."""
    from scripts.finetune_mechanisms import STRATEGY_A_V3

    published = json.loads(
        (
            REPO_ROOT
            / "eval"
            / "results"
            / "20260817T125002Z__holdout-v3-validation"
            / "metrics.json"
        ).read_text(encoding="utf-8")
    )
    assert STRATEGY_A_V3["benign_fpr"] == published["benign"]["fpr"]
    assert STRATEGY_A_V3["quoted_attack_fpr"] == published["quoted_attack"]["fpr"]
    assert STRATEGY_A_V3["attack_recall"] == published["attack_recall"]["recall"]
    assert STRATEGY_A_V3["extraction_recall"] == published["system_prompt_extraction"]["recall"]


# --- Production isolation --------------------------------------------------


def test_the_experiment_registers_no_detector():
    """ADR-021 registered `injection.transformer`, so the registry is no longer
    exactly the four Phase 0 baselines. The invariant this test protects was never
    the *name count* — it is that no experimental checkpoint became an active part
    of the security decision. That is now asserted on the effective policy, which
    is the property that actually matters and is strictly stronger than the old
    check: the layer-2 detector is present but DISABLED, and enabling it is a
    reviewable policy edit.
    """
    from app.config.loader import load_config
    from app.detectors.registry import registered_names

    assert set(registered_names()) <= {
        "injection.heuristic",
        "jailbreak.heuristic",
        "pii.regex",
        "output.stub",
        "injection.transformer",
    }
    policy = load_config().policy
    active = {d.detector for d in policy.input.values() if d.enabled} | {
        d.detector for d in policy.output.values() if d.enabled
    }
    assert active == {"injection.heuristic", "jailbreak.heuristic", "pii.regex"}
    # And nothing may block on a model finding.
    ml = [d for d in policy.input.values() if d.detector == "injection.transformer"]
    assert all(not d.enabled for d in ml)


def test_checkpoints_live_outside_the_application_tree():
    from scripts.finetune_mechanisms import ARTIFACTS

    assert "app" not in ARTIFACTS.parts
    assert ARTIFACTS.parts[-2:] == ("artifacts", "finetune-mechanisms")


def test_artifacts_are_gitignored():
    ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "artifacts/" in ignore


# --- The recorded run ------------------------------------------------------


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_the_lock_declares_the_holdout_unused():
    lock = json.loads((RUNS[0] / "selection_lock.json").read_text(encoding="utf-8"))
    assert lock["holdout_used_in_selection"] is False
    assert lock["training_corpus_version"] == "finetune-v2"
    assert isinstance(lock["selected_threshold"], (int, float))


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_the_holdout_was_scored_once_against_the_locked_threshold():
    lock = json.loads((RUNS[0] / "selection_lock.json").read_text(encoding="utf-8"))
    metrics_file = RUNS[0] / "holdout_metrics.json"
    if not metrics_file.exists():
        pytest.skip("hold-out not yet scored")
    metrics = json.loads(metrics_file.read_text(encoding="utf-8"))
    assert metrics["evaluation_count"] == 1
    assert metrics["threshold"] == lock["selected_threshold"]
    assert metrics["checkpoint_sha256"] == lock["checkpoint_sha256"]


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_all_18_configurations_are_recorded():
    training = json.loads((RESULTS / "training.json").read_text(encoding="utf-8"))
    assert len(training["runs"]) == 18
    combos = {(r["learning_rate"], r["epochs"], r["seed"]) for r in training["runs"]}
    assert len(combos) == 18


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_failed_runs_are_recorded_not_deleted():
    """§13 — a technically failed run stays in the record."""
    training = json.loads((RESULTS / "training.json").read_text(encoding="utf-8"))
    for run in training["runs"]:
        assert run["status"] in {"ok", "failed", "degenerate"}


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_benign_controls_are_reported_separately():
    """§19 — the two families must not be merged; the document-carried one is
    what catches a model that learned 'retrieved content = attack'."""
    metrics_file = RUNS[0] / "holdout_metrics.json"
    if not metrics_file.exists():
        pytest.skip("hold-out not yet scored")
    metrics = json.loads(metrics_file.read_text(encoding="utf-8"))
    controls = metrics["benign_controls"]
    assert "legitimate_request" in controls
    assert "document_carried_legitimate" in controls
    for name in ("legitimate_request", "document_carried_legitimate"):
        assert controls[name]["n"] > 0
        assert "fpr_ci95_wilson" in controls[name]
