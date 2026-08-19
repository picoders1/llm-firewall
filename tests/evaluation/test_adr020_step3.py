"""Guards on ADR-020 Step 3 — the single authorised evaluation event.

Step 3 spends irreplaceable evidence: holdout-v3 and mechanisms-v1 are scored once and
cannot be un-scored. The properties that make the result trustworthy are all invisible
in the numbers themselves:

1. Both candidates were locked, with their thresholds, *before* any hold-out was read.
2. The thresholds come from dev/proxy data only.
3. The contrast arm is never selectable, whatever it scores.
4. The criteria are the ones registered in `success_criteria.json`, unmodified.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
STEP3 = REPO_ROOT / "eval" / "results" / "finetune" / "ADR-020-step3"
PROTOCOL = REPO_ROOT / "eval" / "results" / "finetune" / "ADR-020-protocol"


def _locks() -> dict | None:
    if not (STEP3 / "selection_lock_T2.json").exists():
        return None
    return {
        arm: json.loads((STEP3 / f"selection_lock_{arm}.json").read_text(encoding="utf-8"))
        for arm in ("T2", "T3")
    }


def _needs(path: Path):
    if not path.exists():
        pytest.skip(f"{path.name} not yet produced")
    return json.loads(path.read_text(encoding="utf-8"))


# --- Selection happened before, and without, the hold-out ------------------


def test_both_locks_declare_the_holdout_unused_in_selection():
    locks = _locks()
    if locks is None:
        pytest.skip("Step 3 selection not yet run")
    for arm, lock in locks.items():
        assert lock["holdout_used_in_selection"] is False, arm


def test_exactly_one_candidate_is_selectable():
    """A-3: the contrast arm is scored for causal evidence and can never be chosen."""
    locks = _locks()
    if locks is None:
        pytest.skip("Step 3 selection not yet run")
    selectable = [a for a, k in locks.items() if k["selectable"]]
    assert len(selectable) == 1, selectable
    contrast = [a for a, k in locks.items() if not k["selectable"]]
    assert len(contrast) == 1
    assert locks[contrast[0]]["role"] == "contrast_only"


def test_the_deployment_candidate_passed_the_a1_gate_unchanged():
    locks = _locks()
    if locks is None:
        pytest.skip("Step 3 selection not yet run")
    dep = next(k for k in locks.values() if k["selectable"])
    checks = dep["selection_metrics"]["eligibility_checks"]
    assert all(checks.values()), checks
    assert dep["selection_criteria"]["eligibility_applies"] is True


def test_the_contrast_target_is_exempt_from_the_gate_by_a4_not_by_accident():
    """A-4 must be recorded as the reason, so the exemption is auditable."""
    locks = _locks()
    if locks is None:
        pytest.skip("Step 3 selection not yet run")
    contrast = next(k for k in locks.values() if not k["selectable"])
    assert contrast["selection_criteria"]["eligibility_applies"] is False
    assert "A-4" in contrast["selection_criteria"]["eligibility_note"]


def test_the_primary_threshold_is_matched_fpr_not_dev_selected():
    """Amendment A-2 inverted these; a lock using the dev threshold would silently
    undo it."""
    locks = _locks()
    if locks is None:
        pytest.skip("Step 3 selection not yet run")
    for arm, lock in locks.items():
        assert "matched-FPR" in lock["primary_threshold_source"], arm
        assert lock["dev_selected_threshold_status"].startswith("secondary"), arm
        assert lock["primary_threshold"] != lock["dev_selected_threshold"], arm


def test_locks_carry_every_required_field():
    locks = _locks()
    if locks is None:
        pytest.skip("Step 3 selection not yet run")
    required = {
        "arm",
        "run_id",
        "checkpoint_sha256",
        "model_revision",
        "tokenizer_revision",
        "train_hash",
        "dev_hash",
        "holdout_v3_hash",
        "mechanisms_v1_hash",
        "primary_threshold",
        "dev_selected_threshold",
        "selection_criteria",
        "selection_metrics",
        "git_commit",
        "environment",
        "locked_at",
    }
    for arm, lock in locks.items():
        assert required <= set(lock), (arm, required - set(lock))


# --- The scoring happened after the lock, at the locked threshold ----------


def test_scoring_happened_after_locking():
    locks = _locks()
    if locks is None:
        pytest.skip("Step 3 selection not yet run")
    for arm in ("T2", "T3"):
        metrics_path = STEP3 / f"holdout_v3_{arm}_metrics.json"
        if not metrics_path.exists():
            pytest.skip("hold-out not yet scored")
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        locked = datetime.fromisoformat(locks[arm]["locked_at"])
        scored = datetime.fromisoformat(metrics["evaluated_at"])
        assert scored >= locked, f"{arm}: scored before it was locked"


def test_each_arm_was_scored_at_its_locked_threshold():
    locks = _locks()
    if locks is None:
        pytest.skip("Step 3 selection not yet run")
    for arm in ("T2", "T3"):
        for corpus in ("holdout_v3", "mechanisms_v1"):
            path = STEP3 / f"{corpus}_{arm}_metrics.json"
            if not path.exists():
                pytest.skip("hold-out not yet scored")
            metrics = json.loads(path.read_text(encoding="utf-8"))
            assert metrics["threshold"] == locks[arm]["primary_threshold"], (arm, corpus)
            assert metrics["checkpoint_sha256"] == locks[arm]["checkpoint_sha256"]


def test_pre_holdout_verification_cleared_before_scoring():
    checks = _needs(STEP3 / "pre_holdout_verification.json")
    assert checks["all_datasets_unchanged"] is True
    assert checks["all_candidates_immutable"] is True
    assert checks["cleared_to_score"] is True


def test_the_scored_corpora_are_the_frozen_ones():
    from scripts.finetune_retention import HOLDOUT_HASHES

    for arm in ("T2", "T3"):
        v3 = STEP3 / f"holdout_v3_{arm}_metrics.json"
        mv = STEP3 / f"mechanisms_v1_{arm}_metrics.json"
        if not v3.exists():
            pytest.skip("hold-out not yet scored")
        assert json.loads(v3.read_text())["dataset_sha256"] == HOLDOUT_HASHES["holdout_v3"]
        assert (
            json.loads(mv.read_text())["dataset_sha256"] == HOLDOUT_HASHES["holdout_mechanisms_v1"]
        )


# --- One event, two targets, nothing else ----------------------------------


def test_exactly_two_targets_were_scored_on_each_corpus():
    path = STEP3 / "predictions.jsonl"
    if not path.exists():
        pytest.skip("hold-out not yet scored")
    rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    arms = {r["arm"] for r in rows}
    corpora = {r["corpus"] for r in rows}
    assert arms == {"T2", "T3"}, arms
    assert corpora == {"holdout-v3", "mechanisms-v1"}, corpora
    for arm in arms:
        assert len([r for r in rows if r["arm"] == arm and r["corpus"] == "holdout-v3"]) == 792
        assert len([r for r in rows if r["arm"] == arm and r["corpus"] == "mechanisms-v1"]) == 358


# --- The criteria are the registered ones ----------------------------------


def test_the_bounds_match_the_registered_protocol():
    registered = json.loads((PROTOCOL / "success_criteria.json").read_text(encoding="utf-8"))
    from scripts.evaluate_retention import BENIGN_CONTROL_BOUND, MECHANISM_BOUND, RETENTION_MARGIN

    assert MECHANISM_BOUND == registered["new_mechanisms"]["bound"]
    assert BENIGN_CONTROL_BOUND == registered["benign_controls"]["wilson_upper_bound"]
    assert (
        RETENTION_MARGIN
        == registered["retention"]["system_prompt_extraction_recall"]["part_2_margin"]["margin_pp"]
    )


def test_the_strategy_a_reference_matches_the_published_result():
    published = json.loads(
        (
            REPO_ROOT
            / "eval"
            / "results"
            / "20260817T125002Z__holdout-v3-validation"
            / "metrics.json"
        ).read_text(encoding="utf-8")
    )
    from scripts.evaluate_retention import STRATEGY_A

    assert STRATEGY_A["benign_fpr"] == published["benign"]["fpr"]
    assert STRATEGY_A["quoted_attack_fpr"] == published["quoted_attack"]["fpr"]
    assert STRATEGY_A["attack_recall"] == published["attack_recall"]["recall"]
    assert STRATEGY_A["extraction_recall"] == published["system_prompt_extraction"]["recall"]
    assert STRATEGY_A["hard_negative_fpr"] == published["hard_negatives"]["fpr"]


def test_mechanism_bound_requires_38_of_60():
    from eval.metrics.classification import wilson_interval
    from scripts.evaluate_retention import MECHANISM_BOUND

    need = next(k for k in range(61) if wilson_interval(k, 60)[0] >= MECHANISM_BOUND)
    assert need == 38


# --- Production is untouched -----------------------------------------------


def test_no_model_entered_production():
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


def test_no_checkpoint_was_copied_into_the_app_tree():
    for pattern in ("*.safetensors", "*.bin", "*.onnx"):
        assert not list((REPO_ROOT / "app").rglob(pattern)), pattern


def test_checkpoint_counts_are_unchanged():
    assert len(list((REPO_ROOT / "artifacts" / "finetune").iterdir())) == 18
    assert len(list((REPO_ROOT / "artifacts" / "finetune-mechanisms").iterdir())) == 18
    assert len(list((REPO_ROOT / "artifacts" / "finetune-retention").iterdir())) == 6
