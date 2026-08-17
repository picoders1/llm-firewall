"""Hold-out v3 integrity, and the immutability of v2.

v3 exists because v2's denominators made two blocking criteria unsatisfiable.
These tests assert the properties that make v3 worth having — independence,
adequate sizing, and the fact that building it did not disturb v2.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from eval.schema import normalised_key

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
V3_DIR = REPO_ROOT / "eval" / "datasets" / "holdout" / "v3"
V3_FILE = V3_DIR / "cases.jsonl"
V2_FILE = REPO_ROOT / "eval" / "datasets" / "holdout" / "cases.jsonl"

# Recorded at freeze. A change means v3 was edited, which voids every result
# measured against it.
EXPECTED_V3_SHA256 = "0e26dd6b7d0f545c0bd68b64c2a0b4b60397f8ad41436754dc38b679fbbb28bf"
EXPECTED_V2_SHA256_PREFIX = "fd91575272056d3b282804ddfbbbde63"


def load(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@pytest.fixture(scope="module")
def v3() -> list[dict]:
    return load(V3_FILE)


# --- Immutability ------------------------------------------------------------


def test_v3_content_hash_is_unchanged():
    actual = hashlib.sha256(V3_FILE.read_bytes()).hexdigest()
    assert actual == EXPECTED_V3_SHA256, (
        "Hold-out v3 changed. Either revert it, or create v4 deliberately — "
        "editing a frozen hold-out invalidates every result measured against it."
    )


def test_building_v3_did_not_disturb_v2():
    """v2 remains the artefact behind the Strategy A result."""
    actual = hashlib.sha256(V2_FILE.read_bytes()).hexdigest()[:32]
    assert actual == EXPECTED_V2_SHA256_PREFIX


def test_v3_does_not_live_inside_the_v2_path():
    assert V3_FILE.resolve() != V2_FILE.resolve()
    assert V3_FILE.parent.name == "v3"


# --- Independence ------------------------------------------------------------


def test_v3_has_zero_collisions_with_v2(v3):
    v2_keys = {normalised_key(r["text"]) for r in load(V2_FILE)}
    collisions = [r for r in v3 if normalised_key(r["text"]) in v2_keys]
    assert not collisions, f"{len(collisions)} v3 samples collide with v2"


def test_v3_has_zero_collisions_with_training_data(v3):
    keys = set()
    for split in ("train", "dev"):
        path = REPO_ROOT / "eval" / "datasets" / "finetune" / split / "cases.jsonl"
        keys |= {normalised_key(r["text"]) for r in load(path)}
    collisions = [r for r in v3 if normalised_key(r["text"]) in keys]
    assert not collisions, f"{len(collisions)} v3 samples are in the fine-tuning corpus"


def test_v3_attack_payloads_are_lexically_disjoint_from_training(v3):
    """The point of an independent hold-out: a model that memorised the training
    phrases must earn nothing here. If a training phrase leaked into v3's quoted
    payloads, a repeated result would prove recall rather than generalisation."""
    from eval.datasets.finetune.authoring.pools import ATTACK_PHRASES
    from scripts.datasets.authoring.holdout_v3_pools import QUOTED_PAYLOADS

    overlap = {p.lower() for p in QUOTED_PAYLOADS} & {p.lower() for p in ATTACK_PHRASES}
    assert not overlap, f"v3 reuses training attack phrases: {overlap}"


def test_v3_is_internally_deduplicated(v3):
    keys = [normalised_key(r["text"]) for r in v3]
    assert len(keys) == len(set(keys))


# --- Sizing ------------------------------------------------------------------


def test_every_critical_category_meets_its_calculated_minimum(v3):
    """The reason v3 exists. Each minimum comes from the Wilson calculation in
    the builder, evaluated at the rate Strategy A achieved on v2."""
    from scripts.datasets.build_holdout_v3 import sizing_analysis, sizing_check

    check = sizing_check(v3, sizing_analysis())
    unmet = [r for r in check["per_category"] if not r["satisfied"]]
    assert check["all_satisfied"], f"under-sized categories: {unmet}"


def test_the_two_previously_unachievable_criteria_are_now_reachable(v3):
    """At v2's n=16 / n=17 these could not be met by any model. Prove that a
    zero-false-positive result on v3 would now clear each bound."""
    from eval.metrics.classification import wilson_interval

    benign = [r for r in v3 if not r["label"]]
    quoted = sum(1 for r in benign if r["sub_category"] == "quoted_attack")
    incident = sum(1 for r in benign if r["domain"] == "incident_response")

    assert wilson_interval(0, quoted)[1] <= 0.15, f"quoted_attack still unreachable at n={quoted}"
    assert wilson_interval(0, incident)[1] <= 0.10, (
        f"incident_response still unreachable at n={incident}"
    )


def test_hard_negative_categories_are_all_represented(v3):
    """v3 must not become narrowly optimised around the two under-sized ones."""
    benign = [r for r in v3 if not r["label"]]
    for field, value in [
        ("sub_category", "quoted_attack"),
        ("domain", "incident_response"),
        ("domain", "security_operations"),
        ("sub_category", "security_policy"),
        ("domain", "technical_documentation"),
        ("sub_category", "human_instructions"),
        ("sub_category", "ignore_previous_ordinary"),
        ("sub_category", "code_with_attack_strings"),
    ]:
        assert [r for r in benign if r.get(field) == value], f"no samples for {field}={value}"


# --- Schema and safety -------------------------------------------------------


def test_every_sample_carries_the_required_metadata(v3):
    required = {
        "sample_id",
        "text",
        "label",
        "category",
        "sub_category",
        "domain",
        "difficulty",
        "language",
        "source",
        "source_type",
        "created_at",
        "generation_method",
        "holdout_version",
    }
    for row in v3:
        missing = required - row.keys()
        assert not missing, f"{row['sample_id']} missing {missing}"
        assert row["holdout_version"] == "v3"


def test_labels_agree_with_categories(v3):
    for row in v3:
        expected = 0 if row["category"] == "benign" else 1
        assert row["label"] == expected, row["sample_id"]


def test_no_secrets_or_pii(v3):
    from scripts.datasets.build_holdout_v3 import PII_PATTERNS, SECRET_PATTERNS

    for row in v3:
        for name, pattern in {**SECRET_PATTERNS, **PII_PATTERNS}.items():
            assert not pattern.search(row["text"]), f"{row['sample_id']}: {name}"


def test_sample_ids_are_unique(v3):
    ids = [r["sample_id"] for r in v3]
    assert len(ids) == len(set(ids))


def test_generation_is_deterministic():
    import random

    from scripts.datasets.build_holdout_v3 import SEED, generate

    assert [r["text"] for r in generate(random.Random(SEED))] == [
        r["text"] for r in generate(random.Random(SEED))
    ]


# --- The evaluation ----------------------------------------------------------

RESULTS = REPO_ROOT / "eval" / "results"
V3_RUNS = sorted(RESULTS.glob("*__holdout-v3-validation"))


@pytest.mark.skipif(len(V3_RUNS) != 1, reason="v3 not yet evaluated")
def test_v3_evaluation_used_the_frozen_checkpoint_and_threshold():
    metrics = json.loads((V3_RUNS[0] / "metrics.json").read_text(encoding="utf-8"))
    lock = json.loads(
        (RESULTS / "finetune" / "20260817T122701Z__strategy-a" / "selection_lock.json").read_text(
            encoding="utf-8"
        )
    )
    assert metrics["evaluation_count"] == 1
    assert metrics["threshold"] == lock["selected_threshold"]
    assert metrics["checkpoint_sha256"] == lock["checkpoint_sha256"]
    assert metrics["dataset_sha256"] == EXPECTED_V3_SHA256
    assert all(metrics["pre_evaluation_checks"].values())


@pytest.mark.skipif(len(V3_RUNS) != 1, reason="v3 not yet evaluated")
def test_v3_evaluation_declares_no_tuning():
    manifest = json.loads((V3_RUNS[0] / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["tuning_performed"] is False
