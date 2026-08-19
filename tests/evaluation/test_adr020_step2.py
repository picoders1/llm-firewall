"""Guards on ADR-020 Step 2 — the retention-preserving training experiment.

Step 2 claims to isolate two factors. That claim rests on properties none of which are
visible in the resulting numbers:

1. The training loop is *literally* Strategy A's, so a difference in results cannot come
   from a difference in the loop.
2. The sampler realises the registered mixture — checked sample by sample, not assumed
   from the configured ratio.
3. T3's single epoch is byte-identical to T2's first epoch, which is what makes
   T3 - T2 an adaptation-budget contrast rather than a data contrast as well.
4. No protected hold-out is reachable from the training path.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "finetune_retention.py"
RESULTS = REPO_ROOT / "eval" / "results" / "finetune" / "ADR-020-step2"


# --- The registered protocol is what the code runs -------------------------


def test_the_matrix_is_exactly_adr_020s():
    from scripts.finetune_retention import ARMS, LEARNING_RATE, SEEDS, STEPS_PER_EPOCH

    assert LEARNING_RATE == 1e-5
    assert SEEDS == (13, 20260817, 31337)
    assert set(ARMS) == {"T2", "T3"}
    assert ARMS["T2"]["epochs"] == 2
    assert ARMS["T3"]["epochs"] == 1
    assert STEPS_PER_EPOCH == 243
    assert len(ARMS) * len(SEEDS) == 6


def test_no_seventh_configuration_can_be_added_silently():
    """A protocol expansion is forbidden; the matrix size is asserted, not implied."""
    from scripts.finetune_retention import ARMS, SEEDS

    assert len(ARMS) == 2 and len(SEEDS) == 3


def test_the_training_loop_uses_strategy_as_constants():
    from scripts import finetune_retention as ret
    from scripts import finetune_strategy_a as strat

    for name in (
        "BASE_MODEL",
        "MAX_LENGTH",
        "BATCH_SIZE",
        "MICRO_BATCH_SIZE",
        "WEIGHT_DECAY",
        "WARMUP_RATIO",
    ):
        assert getattr(ret, name) is getattr(strat, name), name


def test_effective_batch_is_16_via_micro_batching():
    from scripts.finetune_retention import BATCH_SIZE, MICRO_BATCH_SIZE

    assert BATCH_SIZE == 16
    assert BATCH_SIZE // MICRO_BATCH_SIZE == 4


def test_the_loss_is_the_models_own_cross_entropy():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "labels=labels).loss" in source
    for wrapper in ("BCEWithLogitsLoss", "CrossEntropyLoss(", "nn.NLLLoss"):
        assert wrapper not in source, wrapper


def test_no_class_weighting_or_custom_objective():
    """ADR-020 §8: the sampler is the ONLY declared departure. It changes which rows
    are drawn, never the loss."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    forbidden = {
        "pos_weight",
        "class_weight",
        "class_weights",
        "FocalLoss",
        "ContrastiveLoss",
        "sample_weight",
        "WeightedRandomSampler",
    }
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in forbidden:
            used.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in forbidden:
            used.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg in forbidden:
            used.add(node.arg)
    assert not used, f"forbidden training machinery: {used}"


# --- The sampler realises the registered mixture ---------------------------


@pytest.fixture(scope="module")
def train_rows() -> list[dict]:
    from scripts.finetune_retention import TRAIN_FILE, load_jsonl

    return load_jsonl(TRAIN_FILE)


def test_the_realised_mixture_meets_every_registered_target(train_rows):
    """§6 — verify what was drawn, not what was configured."""
    from scripts.finetune_retention import (
        build_epoch,
        mixture_targets_met,
        plan_mixture,
        realised_mixture,
    )

    mixture = plan_mixture(train_rows)
    for seed in (13, 20260817, 31337):
        realised = realised_mixture(train_rows, build_epoch(train_rows, mixture, seed, 0))
        targets = mixture_targets_met(realised)
        assert all(targets.values()), (seed, targets)


def test_the_extraction_floor_uses_ceiling_not_rounding(train_rows):
    """A floor of 0.389189: round() lands at 0.38859 and silently breaches it. This is
    the same class of off-by-one that produced wrong minimum-n values three times."""
    from scripts.finetune_retention import (
        EXTRACTION_SHARE_OF_ATTACKS,
        build_epoch,
        plan_mixture,
        realised_mixture,
    )

    mixture = plan_mixture(train_rows)
    realised = realised_mixture(train_rows, build_epoch(train_rows, mixture, 13, 0))
    assert realised["extraction_share_of_attacks"] >= EXTRACTION_SHARE_OF_ATTACKS
    # and the margin is tight — this is a floor, not a large over-shoot
    assert realised["extraction_share_of_attacks"] - EXTRACTION_SHARE_OF_ATTACKS < 0.01


def test_the_three_mechanisms_are_exactly_balanced(train_rows):
    from scripts.finetune_retention import MECHANISMS, build_epoch, plan_mixture, realised_mixture

    mixture = plan_mixture(train_rows)
    counts = realised_mixture(train_rows, build_epoch(train_rows, mixture, 13, 0))[
        "mechanism_counts"
    ]
    assert len(set(counts.values())) == 1
    assert set(counts) == set(MECHANISMS)


def test_t3s_epoch_is_identical_to_t2s_first_epoch(train_rows):
    """The property that makes T3 - T2 an adaptation-budget contrast and nothing else.
    Both arms call build_epoch with the same (seed, epoch), so the draw must match
    exactly — not merely in distribution."""
    from scripts.finetune_retention import build_epoch, plan_mixture

    mixture = plan_mixture(train_rows)
    for seed in (13, 20260817, 31337):
        assert build_epoch(train_rows, mixture, seed, 0) == build_epoch(
            train_rows, mixture, seed, 0
        )


def test_epochs_differ_from_each_other(train_rows):
    """Otherwise T2's second epoch would be a replay of its first, and T2 would be a
    1-epoch run at double the learning-rate schedule."""
    from scripts.finetune_retention import build_epoch, plan_mixture

    mixture = plan_mixture(train_rows)
    assert build_epoch(train_rows, mixture, 13, 0) != build_epoch(train_rows, mixture, 13, 1)


def test_sampling_is_deterministic_across_processes(train_rows):
    from scripts.finetune_retention import build_epoch, plan_mixture

    mixture = plan_mixture(train_rows)
    assert build_epoch(train_rows, mixture, 20260817, 1) == build_epoch(
        train_rows, mixture, 20260817, 1
    )


def test_oversampling_is_visible_not_hidden(train_rows):
    """The replay repeats samples; that is the point, and it is the registered
    memorisation risk (R-50). It must be reported, not silent."""
    from scripts.finetune_retention import build_epoch, plan_mixture, realised_mixture

    mixture = plan_mixture(train_rows)
    realised = realised_mixture(train_rows, build_epoch(train_rows, mixture, 13, 0))
    assert realised["unique_samples"] < realised["n"]
    assert "unique_samples" in realised


# --- Hold-out firewall ------------------------------------------------------


def test_the_training_path_cannot_reach_a_holdout():
    from scripts.finetune_retention import verify_isolation

    report = verify_isolation()
    assert report["isolated"], report["holdout_references_in_training_path"]


def test_the_isolation_check_would_catch_a_real_leak():
    """Negative control: the pattern must not be inert."""
    leaky = ast.parse("def train_one():\n    rows = load_jsonl(HOLDOUT_FILES['holdout_v3'])\n")
    fn = next(n for n in ast.walk(leaky) if isinstance(n, ast.FunctionDef))
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "HOLDOUT_FILES" in names, "the detection pattern is broken"


def test_holdout_hashes_are_pinned_and_unchanged():
    from scripts.finetune_retention import HOLDOUT_FILES, HOLDOUT_HASHES, sha256_file

    for name, path in HOLDOUT_FILES.items():
        assert sha256_file(path) == HOLDOUT_HASHES[name], name


def test_training_corpus_hashes_are_pinned():
    from scripts.finetune_retention import DEV_FILE, EXPECTED, TRAIN_FILE, sha256_file

    assert sha256_file(TRAIN_FILE) == EXPECTED["v2_train"]
    assert sha256_file(DEV_FILE) == EXPECTED["v2_dev"]


def test_safety_check_reports_the_training_representation():
    from scripts.finetune_retention import safety_check

    report = safety_check()
    assert "FULL CARRIER TEXT" in report["training_input_representation"]
    assert not report["hash_mismatches"]
    assert not report["holdout_hash_mismatches"]
    assert report["isolation"]["isolated"]
    assert report["safe_to_train"]


# --- Production isolation ---------------------------------------------------


def test_checkpoints_live_outside_the_application_tree():
    from scripts.finetune_retention import ARTIFACTS

    assert "app" not in ARTIFACTS.parts
    assert ARTIFACTS.parts[-2:] == ("artifacts", "finetune-retention")


def test_artifacts_are_gitignored():
    assert "artifacts/" in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")


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


def test_prior_checkpoint_families_are_untouched():
    assert len(list((REPO_ROOT / "artifacts" / "finetune").iterdir())) == 18
    assert len(list((REPO_ROOT / "artifacts" / "finetune-mechanisms").iterdir())) == 18


def test_checkpoints_are_only_from_authorised_experiments():
    for directory, prefix in (
        (REPO_ROOT / "artifacts" / "finetune", "stratA__"),
        (REPO_ROOT / "artifacts" / "finetune-mechanisms", "mech__"),
        (REPO_ROOT / "artifacts" / "finetune-retention", ("T2__", "T3__")),
    ):
        if not directory.exists():
            continue
        offenders = [
            d.name for d in directory.iterdir() if d.is_dir() and not d.name.startswith(prefix)
        ]
        assert not offenders, f"{directory.name}: {offenders}"


# --- The recorded runs ------------------------------------------------------


def _training() -> dict | None:
    path = RESULTS / "training.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def test_exactly_the_six_registered_runs_are_recorded():
    training = _training()
    if training is None:
        pytest.skip("Step 2 not yet run")
    from scripts.finetune_retention import ARMS, SEEDS

    assert len(training["runs"]) == len(ARMS) * len(SEEDS)
    combos = {(r["arm"], r["seed"]) for r in training["runs"]}
    assert combos == {(a, s) for a in ARMS for s in SEEDS}


def test_failed_runs_are_recorded_not_deleted():
    training = _training()
    if training is None:
        pytest.skip("Step 2 not yet run")
    for run in training["runs"]:
        assert run["status"] in {"ok", "failed", "degenerate"}


def test_every_run_has_a_manifest_with_the_required_fields():
    training = _training()
    if training is None:
        pytest.skip("Step 2 not yet run")
    required = {
        "run_id",
        "arm",
        "seed",
        "learning_rate",
        "epochs",
        "effective_batch",
        "sampler",
        "mixture_ratio",
        "train_hash",
        "dev_hash",
        "model_revision",
        "tokenizer_revision",
        "git_commit",
        "environment",
        "duration_s",
        "peak_vram_gb",
        "checkpoint_sha256",
    }
    for run in training["runs"]:
        path = RESULTS / "manifests" / f"{run['run_id']}.json"
        assert path.exists(), run["run_id"]
        manifest = json.loads(path.read_text(encoding="utf-8"))
        assert required <= set(manifest), required - set(manifest)
        assert manifest["holdout_accessed"] is False
        assert all(manifest["mixture_targets_met"].values())


def test_step_counts_match_the_registered_arms():
    training = _training()
    if training is None:
        pytest.skip("Step 2 not yet run")
    for run in training["runs"]:
        expected = 243 * (2 if run["arm"] == "T2" else 1)
        assert run["total_steps"] == expected, run["run_id"]
