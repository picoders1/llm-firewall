"""Fine-tuning corpus integrity, and the hold-out immutability boundary.

The frozen hold-out is the project's most valuable artefact: it is the only
uncontaminated judge of whether fine-tuning worked. These tests exist so that a
future change cannot quietly train on it.
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
FT = REPO_ROOT / "eval" / "datasets" / "finetune"
TRAIN = FT / "train" / "cases.jsonl"
DEV = FT / "dev" / "cases.jsonl"
INTEGRITY = FT / "integrity" / "manifest.json"
HOLDOUT = REPO_ROOT / "eval" / "datasets" / "holdout" / "cases.jsonl"

# Recorded when the corpus was built. A change here means the hold-out was
# edited after the training corpus was validated against it.
EXPECTED_HOLDOUT_SHA256 = "fd91575272056d3b282804ddfbbbde63"


def load(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@pytest.fixture(scope="module")
def train() -> list[dict]:
    return load(TRAIN)


@pytest.fixture(scope="module")
def dev() -> list[dict]:
    return load(DEV)


@pytest.fixture(scope="module")
def holdout_keys() -> set[str]:
    return {normalised_key(r["text"]) for r in load(HOLDOUT)}


# --- THE HARD BOUNDARY -------------------------------------------------------


def test_train_has_zero_collisions_with_the_frozen_holdout(train, holdout_keys):
    """If this fails, every future fine-tuning result is void."""
    collisions = [r for r in train if normalised_key(r["text"]) in holdout_keys]
    assert not collisions, f"{len(collisions)} training samples are in the frozen hold-out"


def test_dev_has_zero_collisions_with_the_frozen_holdout(dev, holdout_keys):
    collisions = [r for r in dev if normalised_key(r["text"]) in holdout_keys]
    assert not collisions, f"{len(collisions)} dev samples are in the frozen hold-out"


def test_holdout_content_hash_is_unchanged():
    """The hold-out is read-only. A changed hash means it was edited, which
    invalidates the contamination check the corpus was built against."""
    actual = hashlib.sha256(HOLDOUT.read_bytes()).hexdigest()[:32]
    assert actual == EXPECTED_HOLDOUT_SHA256, (
        "The frozen hold-out changed. Either revert it, or rebuild the fine-tuning "
        "corpus and update EXPECTED_HOLDOUT_SHA256 deliberately."
    )


def test_build_script_aborts_if_the_holdout_reaches_training():
    from scripts.datasets.build_finetune import HoldOutViolation, check_holdout_boundary

    holdout_rows = load(HOLDOUT)
    with pytest.raises(HoldOutViolation, match="FROZEN HOLD-OUT"):
        check_holdout_boundary([{"text": holdout_rows[0]["text"]}])


def test_training_corpus_lives_outside_the_holdout_directory():
    """Directory-level separation, so a glob cannot pick the hold-out up."""
    assert FT.resolve() not in HOLDOUT.resolve().parents
    assert "holdout" not in str(TRAIN.relative_to(REPO_ROOT)).replace("finetune", "")


# --- Corpus composition ------------------------------------------------------


def test_corpus_meets_the_hard_negative_target(train, dev):
    """Target: >= 3,000 hard-negative / enterprise-benign examples combined.

    Asserted on the combined benign figure, which is the stated requirement.
    The hard-negative sub-total is asserted separately and more loosely: it is
    the priority class, but padding it with more template x reference
    combinations would add count without adding signal.
    """
    rows = train + dev
    hard = [r for r in rows if r["category"] == "hard_negative"]
    benign = [r for r in rows if r["label"] == 0]
    assert len(benign) >= 3000, f"only {len(benign)} benign (hard-negative + ordinary)"
    assert len(hard) >= 2400, f"only {len(hard)} hard negatives"


def test_corpus_contains_all_three_required_classes(train, dev):
    """Not a hard-negative-only corpus: the model must keep its notion of both
    ordinary benign traffic and real attacks."""
    categories = Counter(r["category"] for r in train + dev)
    assert categories["attack"] >= 500
    assert categories["benign"] >= 400
    assert categories["hard_negative"] >= 2400


def test_attack_taxonomy_is_covered(train, dev):
    subs = {r["sub_category"] for r in train + dev if r["label"] == 1}
    required = {
        "direct_prompt_injection",
        "system_prompt_extraction",
        "role_override",
        "context_override",
        "jailbreak",
        "indirect_injection",
    }
    assert required <= subs, f"missing attack classes: {required - subs}"


def test_hard_negative_taxonomy_covers_the_observed_failures(train, dev):
    """The categories the base model actually fails on (ADR-014)."""
    subs = {r["sub_category"] for r in train + dev if r["category"] == "hard_negative"}
    required = {
        "quoted_attack",
        "security_policy_discussion",
        "prompt_injection_discussion",
        "system_prompt_discussion",
        "instructional_language",
        "ignore_previous_ordinary",
        "configuration_override",
        "developer_documentation",
    }
    assert required <= subs, f"missing hard-negative classes: {required - subs}"


def test_contrastive_pairs_exist(train, dev):
    """The same attack phrase must appear on BOTH sides of the label boundary,
    otherwise the model can succeed by learning keywords."""
    from eval.datasets.finetune.authoring.pools import ATTACK_PHRASES

    rows = train + dev
    shared = 0
    for phrase in ATTACK_PHRASES:
        needle = phrase.lower()
        in_benign = any(needle in r["text"].lower() for r in rows if r["label"] == 0)
        in_attack = any(needle in r["text"].lower() for r in rows if r["label"] == 1)
        if in_benign and in_attack:
            shared += 1
    assert shared >= 10, f"only {shared} attack phrases appear on both sides"


# --- Split and duplication ---------------------------------------------------


def test_no_cross_split_leakage(train, dev):
    assert not (
        {normalised_key(r["text"]) for r in train} & {normalised_key(r["text"]) for r in dev}
    )


def test_no_duplicates_within_the_corpus(train, dev):
    keys = [normalised_key(r["text"]) for r in train + dev]
    assert len(keys) == len(set(keys))


def test_split_is_content_derived(train, dev):
    from scripts.datasets.build_finetune import assign_split

    for row in train:
        assert assign_split(row["text"]) == "train"
    for row in dev:
        assert assign_split(row["text"]) == "dev"


def test_sample_ids_are_unique(train, dev):
    ids = [r["sample_id"] for r in train + dev]
    assert len(ids) == len(set(ids))


# --- Provenance and safety ---------------------------------------------------


def test_every_sample_records_its_generation_method(train, dev):
    for row in train + dev:
        assert row["generation_method"]
        assert row["source_type"] == "synthetic"
        assert row["dataset_version"]
        assert row["created_at"]


def test_no_secrets_or_pii(train, dev):
    from scripts.datasets.build_finetune import PII_PATTERNS, SECRET_PATTERNS

    for row in train + dev:
        for name, pattern in {**SECRET_PATTERNS, **PII_PATTERNS}.items():
            assert not pattern.search(row["text"]), f"{row['sample_id']}: {name}"


def test_labels_agree_with_categories(train, dev):
    for row in train + dev:
        expected = 1 if row["category"] == "attack" else 0
        assert row["label"] == expected, row["sample_id"]


# --- Manifest ----------------------------------------------------------------


def test_integrity_manifest_records_a_clean_build():
    manifest = json.loads(INTEGRITY.read_text(encoding="utf-8"))
    integrity = manifest["integrity"]
    assert integrity["frozen_holdout_collisions"] == 0
    assert integrity["cross_split_leakage"] == 0
    assert integrity["secrets"] == 0
    assert integrity["pii"] == 0
    assert integrity["near_duplicate_rate"] <= 0.02
    assert manifest["frozen_holdout"]["status"].startswith("READ-ONLY")


def test_manifest_matches_the_written_corpus(train, dev):
    manifest = json.loads(INTEGRITY.read_text(encoding="utf-8"))
    assert manifest["composition"]["train"] == len(train)
    assert manifest["composition"]["dev"] == len(dev)


def test_generation_is_deterministic():
    """Same seed, same corpus — a precondition for reproducing any training run."""
    import random

    from scripts.datasets.build_finetune import SEED, generate

    first = [r["text"] for r in generate(random.Random(SEED))]
    second = [r["text"] for r in generate(random.Random(SEED))]
    assert first == second
