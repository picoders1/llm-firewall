"""Integrity of the indirect-injection hold-out, and immutability of v2/v3.

This corpus exists because two prior hold-outs reported indirect-injection recall
from single- and double-digit denominators (1.0000 at n=5, 0.4000 at n=20) and the
real figure is 0.1423. These tests assert the properties that make the third
measurement trustworthy: independence, adequate per-shape sizing, orthogonal
dimensions, and benign controls that share containers with the attacks.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest

from eval.schema import normalised_key

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "eval" / "datasets" / "holdout" / "indirect-v1"
DATA_FILE = DATA_DIR / "cases.jsonl"
V2_FILE = REPO_ROOT / "eval" / "datasets" / "holdout" / "cases.jsonl"
V3_FILE = REPO_ROOT / "eval" / "datasets" / "holdout" / "v3" / "cases.jsonl"

EXPECTED_SHA256 = "3ef8c0ec75d9aed9669332dd2e70987993459b39629a6f7109241e13f96d6e17"
V2_PINNED = "fd91575272056d3b282804ddfbbbde63"
V3_PINNED = "0e26dd6b7d0f545c0bd68b64c2a0b4b60397f8ad41436754dc38b679fbbb28bf"


def load(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@pytest.fixture(scope="module")
def corpus() -> list[dict]:
    return load(DATA_FILE)


# --- Immutability ------------------------------------------------------------


def test_content_hash_is_unchanged():
    assert hashlib.sha256(DATA_FILE.read_bytes()).hexdigest() == EXPECTED_SHA256, (
        "indirect-v1 changed. Frozen corpora are versioned, not edited — every "
        "result measured against it would be void."
    )


def test_building_this_corpus_did_not_disturb_v2_or_v3():
    assert hashlib.sha256(V2_FILE.read_bytes()).hexdigest()[:32] == V2_PINNED
    assert hashlib.sha256(V3_FILE.read_bytes()).hexdigest() == V3_PINNED


# --- Independence ------------------------------------------------------------


def test_payload_vocabulary_is_disjoint_from_training_and_v3():
    """The whole point: a detector that memorised either prior phrase set earns
    nothing here, so a result on this corpus speaks to generalisation."""
    from eval.datasets.finetune.authoring.pools import ATTACK_PHRASES
    from scripts.datasets.authoring.holdout_v3_pools import QUOTED_PAYLOADS
    from scripts.datasets.authoring.indirect_v1_pools import PAYLOADS

    ours = {p.lower().strip(" .") for p, _ in PAYLOADS}
    assert not ours & {p.lower().strip(" .") for p in ATTACK_PHRASES}
    assert not ours & {p.lower().strip(" .") for p in QUOTED_PAYLOADS}


@pytest.mark.parametrize(
    "other",
    [
        pytest.param(V2_FILE, id="holdout_v2"),
        pytest.param(V3_FILE, id="holdout_v3"),
        pytest.param(
            REPO_ROOT / "eval" / "datasets" / "finetune" / "train" / "cases.jsonl", id="train"
        ),
        pytest.param(
            REPO_ROOT / "eval" / "datasets" / "finetune" / "dev" / "cases.jsonl", id="dev"
        ),
    ],
)
def test_zero_collisions_with_every_other_corpus(corpus, other: Path):
    keys = {normalised_key(r["text"]) for r in load(other)}
    collisions = [r["sample_id"] for r in corpus if normalised_key(r["text"]) in keys]
    assert not collisions, f"{len(collisions)} collisions with {other.parent.name}"


def test_internally_deduplicated(corpus):
    keys = [normalised_key(r["text"]) for r in corpus]
    assert len(keys) == len(set(keys))


# --- The design that makes the result readable -------------------------------


def test_every_delivery_shape_meets_its_calculated_target(corpus):
    from scripts.datasets.build_indirect_v1 import sizing_check

    check = sizing_check(corpus)
    unmet = [r["delivery_shape"] for r in check["per_shape"] if not r["satisfied"]]
    assert check["all_satisfied"], f"under-sized shapes: {unmet}"


def test_shape_and_mechanism_are_crossed_not_confounded(corpus):
    """v3 could not attribute its 0.4000 to shape or mechanism because its 20
    samples did not cross them. Every shape must carry several mechanisms."""
    attacks = [r for r in corpus if r["label"]]
    by_shape: dict[str, set[str]] = {}
    for row in attacks:
        by_shape.setdefault(row["delivery_shape"], set()).add(row["attack_mechanism"])
    thin = {shape: sorted(m) for shape, m in by_shape.items() if len(m) < 4}
    assert not thin, f"shapes carrying fewer than 4 mechanisms: {thin}"


def test_benign_controls_share_containers_with_attacks(corpus):
    """The control that exposed `system_marker` firing on syntax. If a shape had
    attacks but no benign controls, a form-triggered false positive would be
    invisible."""
    attacks = {r["delivery_shape"] for r in corpus if r["label"]}
    controls = {r["delivery_shape"] for r in corpus if not r["label"]}
    # complicit_directive is a contrast condition and deliberately has no controls.
    assert (attacks - controls) == {"complicit_directive"}


def test_user_framing_is_recorded_separately_from_the_label(corpus):
    """Folding framing into the label would define the primary threat — the
    innocent user processing a planted payload — out of existence."""
    framings = Counter(r["user_framing"] for r in corpus)
    assert framings["innocent_processing"] > 0
    assert framings["complicit_directive"] > 0
    assert framings["security_discussion"] > 0
    # The victim case must be labelled as an attack, not as benign.
    victim = [r for r in corpus if r["user_framing"] == "innocent_processing"]
    assert victim and all(r["label"] == 1 for r in victim)
    # Security discussion is the benign control.
    discussion = [r for r in corpus if r["user_framing"] == "security_discussion"]
    assert discussion and all(r["label"] == 0 for r in discussion)


def test_labels_follow_intent_not_vocabulary(corpus):
    """Benign controls contain the same security vocabulary as the attacks. If a
    trigger word alone decided the label, this would fail."""
    trigger = ("instruction", "directive", "system", "assistant", "ignore")
    benign_with_triggers = [
        r for r in corpus if not r["label"] and any(t in r["text"].lower() for t in trigger)
    ]
    assert len(benign_with_triggers) >= 100, (
        "too few benign controls carry attack vocabulary; the corpus would be "
        "separable on keywords alone"
    )


# --- Schema and safety -------------------------------------------------------


def test_required_metadata_present(corpus):
    required = {
        "sample_id",
        "text",
        "label",
        "category",
        "delivery_shape",
        "attack_mechanism",
        "context",
        "difficulty",
        "language",
        "source",
        "source_type",
        "generation_method",
        "holdout_version",
        "created_at",
    }
    for row in corpus:
        assert not required - row.keys(), f"{row['sample_id']} missing {required - row.keys()}"
        assert row["holdout_version"] == "indirect-v1"


def test_labels_agree_with_categories(corpus):
    for row in corpus:
        assert row["label"] == (0 if row["category"] == "benign" else 1), row["sample_id"]


def test_no_secrets_or_pii(corpus):
    from scripts.datasets.build_indirect_v1 import PII_PATTERNS, SECRET_PATTERNS

    for row in corpus:
        for name, pattern in {**SECRET_PATTERNS, **PII_PATTERNS}.items():
            assert not pattern.search(row["text"]), f"{row['sample_id']}: {name}"


def test_sample_ids_unique(corpus):
    ids = [r["sample_id"] for r in corpus]
    assert len(ids) == len(set(ids))


def test_generation_is_deterministic():
    import random

    from scripts.datasets.build_indirect_v1 import SEED, generate

    assert [r["text"] for r in generate(random.Random(SEED))] == [
        r["text"] for r in generate(random.Random(SEED))
    ]


# --- The evaluation ----------------------------------------------------------

RUNS = sorted((REPO_ROOT / "eval" / "results").glob("*__indirect-delivery-shape"))


@pytest.mark.skipif(len(RUNS) != 1, reason="not yet evaluated")
def test_evaluation_used_the_frozen_checkpoint_and_threshold():
    metrics = json.loads((RUNS[0] / "metrics.json").read_text(encoding="utf-8"))
    lock = json.loads(
        (
            REPO_ROOT
            / "eval"
            / "results"
            / "finetune"
            / "20260817T122701Z__strategy-a"
            / "selection_lock.json"
        ).read_text(encoding="utf-8")
    )
    assert metrics["evaluation_count"] == 1
    assert metrics["tuning_performed"] is False
    assert metrics["threshold"] == lock["selected_threshold"] == 0.9955
    assert metrics["checkpoint_sha256"] == lock["checkpoint_sha256"]
    assert metrics["dataset_sha256"] == EXPECTED_SHA256
    assert all(metrics["pre_evaluation_checks"].values())


@pytest.mark.skipif(len(RUNS) != 1, reason="not yet evaluated")
def test_every_shape_reports_a_verdict_with_its_denominator():
    """A rate without its denominator, or without a verdict, is not evidence."""
    shapes = json.loads((RUNS[0] / "shape_metrics.json").read_text(encoding="utf-8"))
    for name, block in shapes["attacks"].items():
        assert block["n"] > 0, name
        assert "recall_ci95_wilson" in block, name
        assert block["verdict"] in {
            "RELIABLY DETECTED",
            "SYSTEMATICALLY MISSED",
            "INCONCLUSIVE",
            "NOT EVALUATED",
        }, name
        lo, hi = block["recall_ci95_wilson"]
        assert lo <= block["recall"] <= hi, name
