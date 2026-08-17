"""Guards on ADR-020 Steps 0 and 1.

These steps make a cheap claim carry weight: that a *public, contaminated* corpus may
rank two fine-tunes when nothing else can. Three properties have to hold or the claim
collapses, and none is visible from reading the numbers:

1. The proxy is disjoint from every training corpus and every frozen hold-out.
2. A threshold is never calibrated and measured on the same samples.
3. Nothing here trains, and nothing here scores a protected hold-out.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from eval.schema import normalised_key

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_proxy.py"
RESULTS = REPO_ROOT / "eval" / "results" / "finetune" / "ADR-020-steps-0-1"


def load(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


# --- The proxy is what it claims to be -------------------------------------


def test_the_proxy_is_disjoint_from_every_training_corpus_and_holdout():
    from scripts.validate_proxy import PROTECTED_HOLDOUTS, TRAINING_CORPORA, build_proxy

    proxy_keys = {normalised_key(r["text"]) for part in build_proxy().values() for r in part}
    for path in TRAINING_CORPORA + PROTECTED_HOLDOUTS:
        keys = {normalised_key(r["text"]) for r in load(path)}
        overlap = proxy_keys & keys
        assert not overlap, f"{len(overlap)} collisions with {path.name}"


def test_calibration_and_evaluation_benign_are_disjoint():
    """A threshold chosen and measured on the same samples measures nothing."""
    from scripts.validate_proxy import build_proxy

    proxy = build_proxy()
    cal = {normalised_key(r["text"]) for r in proxy["calibration_benign"]}
    ev = {normalised_key(r["text"]) for r in proxy["eval_benign"]}
    assert cal and ev
    assert not (cal & ev)


def test_the_proxy_contains_no_internal_duplicates():
    from scripts.validate_proxy import build_proxy

    keys = [normalised_key(r["text"]) for part in build_proxy().values() for r in part]
    assert len(keys) == len(set(keys))


def test_construction_is_deterministic():
    from scripts.validate_proxy import build_proxy

    first = {k: [r["sample_id"] for r in v] for k, v in build_proxy().items()}
    second = {k: [r["sample_id"] for r in v] for k, v in build_proxy().items()}
    assert first == second


# --- The integrity check screens the way production validates ---------------


def test_card_candidates_are_luhn_validated_like_production():
    """The dataset-build pattern is `\\b(?:\\d[ -]?){13,19}\\b` with no checksum, so it
    fires on any long digit run. Production requires Luhn. Screening more loosely
    than production validates produced a false 'PII found' on an analytics hash."""
    from scripts.validate_proxy import is_sensitive

    # 18 digits, not Luhn-valid — an analytics hash, not a card.
    assert is_sensitive("unique_hash 100000000000000004")[0] is False
    # Luhn-valid test card must still be caught.
    assert is_sensitive("card 4111111111111111 on file")[0] is True


def test_the_sensitivity_filter_would_catch_a_real_secret():
    """Negative control: the pattern set itself must not be inert."""
    from scripts.validate_proxy import is_sensitive

    assert is_sensitive("AKIAIOSFODNN7EXAMPLE")[0] is True
    assert is_sensitive("-----BEGIN RSA PRIVATE KEY-----")[0] is True
    assert is_sensitive("What is the capital of France?")[0] is False


def test_exclusions_are_uniform_rules_not_targeted_deletions():
    """Every excluded row must be excluded by a rule that applies to the whole pool."""
    from scripts.validate_proxy import build_proxy, is_sensitive

    _, provenance = build_proxy(with_provenance=True)
    for sample_id, _why in provenance["dropped_sensitive"]:
        assert sample_id  # recorded, not silently dropped
    # the rule, re-applied, reproduces the same verdict on what survived
    for part in build_proxy().values():
        for row in part:
            assert is_sensitive(row["text"])[0] is False


# --- Threshold selection ----------------------------------------------------


def test_matched_fpr_threshold_returns_the_smallest_qualifying_cut():
    """The downward-iteration bug — returning the last candidate instead of the
    first qualifying one — has appeared twice in this project."""
    from scripts.validate_proxy import matched_fpr_threshold

    scores = [i / 100 for i in range(100)]  # 0.00 .. 0.99
    tau = matched_fpr_threshold(scores, target=0.01)
    fpr = sum(1 for s in scores if s >= tau) / len(scores)
    assert fpr <= 0.01
    # and it is not needlessly conservative: a hair lower would breach the budget
    lower = sum(1 for s in scores if s >= tau - 0.011) / len(scores)
    assert lower > 0.01


def test_every_checkpoint_is_thresholded_by_the_same_two_methods():
    if not (RESULTS / "proxy_scores.json").exists():
        pytest.skip("scoring not yet run")
    data = json.loads((RESULTS / "proxy_scores.json").read_text(encoding="utf-8"))
    assert len(data["checkpoints"]) == 6
    for name, c in data["checkpoints"].items():
        assert isinstance(c["dev_selected_threshold"], (int, float)), name
        assert isinstance(c["matched_fpr_threshold"], (int, float)), name


# --- Nothing trains, nothing touches a protected hold-out -------------------


def test_no_training_machinery_in_the_script():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    forbidden = {"backward", "AdamW", "get_linear_schedule_with_warmup", "train_one", "step"}
    used = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr in forbidden
    } | {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id in forbidden}
    assert not used, f"training machinery present: {used}"


def test_the_scoring_path_never_reads_a_protected_holdout():
    """The integrity phase reads hold-out *text* for the collision check — the same
    contamination gate every corpus build uses, and no model touches it. The scoring
    phase must not reference them at all."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    scoring = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "phase_score"
    )
    names = {n.id for n in ast.walk(scoring) if isinstance(n, ast.Name)}
    assert "PROTECTED_HOLDOUTS" not in names


def test_the_isolation_check_would_catch_a_real_leak():
    """Negative control on the detection pattern itself."""
    leaky = ast.parse("def phase_score():\n    rows = load_jsonl(PROTECTED_HOLDOUTS[0])\n")
    fn = next(n for n in ast.walk(leaky) if isinstance(n, ast.FunctionDef))
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "PROTECTED_HOLDOUTS" in names, "the detection pattern is broken"


def test_only_the_six_selected_checkpoints_are_scored():
    """lr 1e-5 / 2 epochs is the configuration both experiments selected, so the two
    families differ only in training corpus."""
    from scripts.validate_proxy import CONFIG, SEEDS, checkpoint_paths

    assert CONFIG == "lr1e-05__ep2"
    assert SEEDS == (13, 20260817, 31337)
    specs = checkpoint_paths()
    assert len(specs) == 6
    assert {s["family"] for s in specs} == {"strategy_a", "adr_019"}
    for spec in specs:
        assert spec["path"].exists(), spec["path"]


# --- Production is untouched ------------------------------------------------


def test_the_experiment_registers_no_detector():
    from app.detectors.registry import registered_names

    assert set(registered_names()) == {
        "injection.heuristic",
        "jailbreak.heuristic",
        "pii.regex",
        "output.stub",
    }


def test_no_new_checkpoints_were_created():
    for directory, prefix in (
        (REPO_ROOT / "artifacts" / "finetune", "stratA__"),
        (REPO_ROOT / "artifacts" / "finetune-mechanisms", "mech__"),
    ):
        if not directory.exists():
            continue
        offenders = [
            d.name for d in directory.iterdir() if d.is_dir() and not d.name.startswith(prefix)
        ]
        assert not offenders, f"{directory.name}: {offenders}"
    assert len(list((REPO_ROOT / "artifacts" / "finetune").iterdir())) == 18
    assert len(list((REPO_ROOT / "artifacts" / "finetune-mechanisms").iterdir())) == 18


def test_the_integrity_gate_was_recorded_and_passed():
    if not (RESULTS / "integrity.json").exists():
        pytest.skip("integrity not yet run")
    report = json.loads((RESULTS / "integrity.json").read_text(encoding="utf-8"))
    assert report["exact_collisions_total"] == 0
    assert report["normalised_collisions_total"] == 0
    assert report["calibration_eval_overlap"] == 0
    assert not report["secret_or_pii_hits"]
    assert report["admissible"] is True
    assert report["used_in_any_training_run"] is False
    assert "NOT claimable as capability" in report["contamination_note"]
