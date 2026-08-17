"""Integrity of the mechanism-coverage corpora.

ADR-019. Two properties carry the whole value of this data and neither is obvious
from reading it:

1. **The carrier must not predict the label.** The first build had every attack in a
   document wrapper and every hard negative as a direct request, so a model could
   have scored perfectly by detecting the wrapper — and would then flag all
   retrieved content. Closed by adding legitimate content inside the same carriers.
2. **Five vocabularies must stay disjoint.** Training pools, hold-out pools, and the
   three previously frozen corpora. A leak makes the hold-out measure recall of
   trained strings instead of generalisation.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import pytest

from eval.schema import normalised_key
from scripts.datasets.authoring.mechanism_pools import MECHANISMS

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
V1_TRAIN = REPO_ROOT / "eval" / "datasets" / "finetune" / "train" / "cases.jsonl"
V1_DEV = REPO_ROOT / "eval" / "datasets" / "finetune" / "dev" / "cases.jsonl"
V2 = REPO_ROOT / "eval" / "datasets" / "finetune" / "v2"
HOLDOUT = REPO_ROOT / "eval" / "datasets" / "holdout" / "mechanisms-v1"

EXPECTED_HOLDOUT_SHA = "bb562774663dea7580d7d1a97031b810c7a8aadebde10fcbfd04a116b521e91c"
V1_TRAIN_PINNED = "4a83c4cd1541cd265bd6f3b2a07c8df9"
V1_DEV_PINNED = "07a1e685aed81cdc66e233fa97f57fc8"


def load(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@pytest.fixture(scope="module")
def holdout() -> list[dict]:
    return load(HOLDOUT / "cases.jsonl")


@pytest.fixture(scope="module")
def v2() -> list[dict]:
    return load(V2 / "train" / "cases.jsonl") + load(V2 / "dev" / "cases.jsonl")


# --- v1 is untouched -------------------------------------------------------


def test_finetune_v1_is_byte_identical():
    """Its hashes are pinned in the Strategy A selection lock. Editing v1 would
    destroy the record of a completed experiment."""
    assert hashlib.sha256(V1_TRAIN.read_bytes()).hexdigest()[:32] == V1_TRAIN_PINNED
    assert hashlib.sha256(V1_DEV.read_bytes()).hexdigest()[:32] == V1_DEV_PINNED


def test_v2_contains_v1_in_full(v2):
    v1_keys = {normalised_key(r["text"]) for r in load(V1_TRAIN) + load(V1_DEV)}
    v2_keys = {normalised_key(r["text"]) for r in v2}
    assert v1_keys <= v2_keys, f"{len(v1_keys - v2_keys)} v1 samples missing from v2"


def test_v2_splits_preserve_v1_split_assignment():
    """v2 uses the same content-derived rule, so a v1 sample must not move split —
    otherwise a Strategy A dev sample could become a v2 training sample."""
    from scripts.datasets.build_mechanism_coverage import assign_split

    for path, expected in ((V1_TRAIN, "train"), (V1_DEV, "dev")):
        for row in load(path):
            assert assign_split(row["text"]) == expected, row["sample_id"]


def test_the_mechanism_holdout_hash_is_unchanged(holdout):
    actual = hashlib.sha256((HOLDOUT / "cases.jsonl").read_bytes()).hexdigest()
    assert actual == EXPECTED_HOLDOUT_SHA, (
        "mechanisms-v1 changed. Frozen corpora are versioned, not edited."
    )


# --- Coverage --------------------------------------------------------------


def test_every_target_mechanism_is_covered_in_training(v2):
    attacks = Counter(r["sub_category"] for r in v2 if r["label"])
    for mechanism in MECHANISMS:
        assert attacks[mechanism] >= 100, f"{mechanism}: only {attacks[mechanism]} attacks"


def test_every_target_mechanism_has_enough_holdout_attacks(holdout):
    attacks = Counter(r["attack_mechanism"] for r in holdout if r["label"])
    for mechanism in MECHANISMS:
        assert attacks[mechanism] >= 60, f"{mechanism}: only {attacks[mechanism]}"


def test_hard_negatives_outnumber_attacks_for_each_mechanism(v2):
    """The half that stops the model learning "mentions a tool → block"."""
    for mechanism in MECHANISMS:
        attacks = sum(1 for r in v2 if r["label"] and r["sub_category"] == mechanism)
        negatives = sum(
            1 for r in v2 if not r["label"] and r["sub_category"].startswith(f"{mechanism}_")
        )
        assert negatives > attacks, f"{mechanism}: {negatives} negatives vs {attacks} attacks"


def test_both_kinds_of_hard_negative_are_present(v2):
    """Direct requests *and* legitimate content inside document carriers. Without
    the second kind the carrier predicts the label."""
    subs = {r["sub_category"] for r in v2 if not r["label"]}
    for mechanism in MECHANISMS:
        assert f"{mechanism}_legitimate" in subs, mechanism
        assert f"{mechanism}_document_legitimate" in subs, mechanism


# --- The shortcut that was found and closed --------------------------------


def test_the_document_carrier_does_not_predict_the_label(v2):
    """The load-bearing test. Every carrier that hosts attacks must also host
    benign samples, or a model can score perfectly by detecting the wrapper and
    will then flag all retrieved content."""
    by_domain: dict[str, Counter] = defaultdict(Counter)
    extension = [r for r in v2 if r.get("dataset_version") == "finetune-v2"]
    assert extension, "no extension rows found; test is vacuous"
    for row in extension:
        by_domain[row["domain"]][row["label"]] += 1
    offenders = {
        domain: dict(counts)
        for domain, counts in by_domain.items()
        if counts[1] > 0 and counts[0] == 0
    }
    assert not offenders, f"carriers hosting only attacks: {offenders}"


def test_the_same_carriers_appear_on_both_sides_in_the_holdout(holdout):
    by_domain: dict[str, Counter] = defaultdict(Counter)
    for row in holdout:
        by_domain[row["domain"]][row["label"]] += 1
    shared = [d for d, c in by_domain.items() if c[0] and c[1]]
    assert shared, "no carrier hosts both labels; the wrapper predicts the label"


# --- Disjointness ----------------------------------------------------------


def test_all_five_attack_vocabularies_are_disjoint():
    from scripts.datasets.build_mechanism_coverage import vocabulary_independence

    report = vocabulary_independence()
    assert report["disjoint"], report["overlaps"]


def test_training_extension_does_not_collide_with_any_frozen_holdout(v2):
    from scripts.datasets.build_mechanism_coverage import FROZEN_HOLDOUTS

    v2_keys = {normalised_key(r["text"]) for r in v2}
    for name, path in FROZEN_HOLDOUTS.items():
        if not path.exists():
            continue
        keys = {normalised_key(r["text"]) for r in load(path)}
        assert not (v2_keys & keys), f"{len(v2_keys & keys)} collisions with {name}"


def test_the_mechanism_holdout_does_not_collide_with_the_training_corpus(holdout, v2):
    """The check that caught 14 real collisions on the first build attempt."""
    training = {normalised_key(r["text"]) for r in v2}
    collisions = [r["sample_id"] for r in holdout if normalised_key(r["text"]) in training]
    assert not collisions, f"{len(collisions)} hold-out samples are in the training corpus"


def test_the_mechanism_holdout_does_not_collide_with_other_holdouts(holdout):
    from scripts.datasets.build_mechanism_coverage import FROZEN_HOLDOUTS

    keys = {normalised_key(r["text"]) for r in holdout}
    for name, path in FROZEN_HOLDOUTS.items():
        if not path.exists():
            continue
        other = {normalised_key(r["text"]) for r in load(path)}
        assert not (keys & other), f"collides with {name}"


# --- Schema and safety -----------------------------------------------------


def test_no_duplicates_within_either_corpus(v2, holdout):
    for rows, label in ((v2, "v2"), (holdout, "mechanisms-v1")):
        keys = [normalised_key(r["text"]) for r in rows]
        assert len(keys) == len(set(keys)), label


def test_labels_agree_with_categories(v2, holdout):
    for row in v2:
        expected = 1 if row["category"] == "attack" else 0
        assert row["label"] == expected, row["sample_id"]
    for row in holdout:
        expected = 0 if row["category"] == "benign" else 1
        assert row["label"] == expected, row["sample_id"]


def test_no_secrets_or_pii(v2, holdout):
    from scripts.datasets.build_mechanism_coverage import PII_PATTERNS, SECRET_PATTERNS

    for rows in (v2, holdout):
        for row in rows:
            for name, pattern in {**SECRET_PATTERNS, **PII_PATTERNS}.items():
                assert not pattern.search(row["text"]), f"{row['sample_id']}:{name}"


def test_generation_is_deterministic():
    import random

    from scripts.datasets.build_mechanism_coverage import (
        SEED,
        generate_holdout,
        generate_training_extension,
    )

    assert [r["text"] for r in generate_training_extension(random.Random(SEED))] == [
        r["text"] for r in generate_training_extension(random.Random(SEED))
    ]
    assert [r["text"] for r in generate_holdout(random.Random(SEED + 1))] == [
        r["text"] for r in generate_holdout(random.Random(SEED + 1))
    ]


def test_the_build_refuses_to_pad_with_duplicates():
    """The guard that caught the pool being too small for the stated target."""
    import random

    from scripts.datasets.authoring.mechanism_pools import DOCUMENT_LEGITIMATE, TRAIN_ATTACKS
    from scripts.datasets.build_mechanism_coverage import CoverageError, _compose

    with pytest.raises(CoverageError, match="Expand the pools"):
        _compose(
            random.Random(0),
            TRAIN_ATTACKS,
            dict.fromkeys(MECHANISMS, ("only one request",)),
            DOCUMENT_LEGITIMATE,
            10,
            10_000,
            "x",
        )


# --- No training happened --------------------------------------------------


def test_only_the_registered_adr019_experiment_exists():
    """ADR-019 execution was authorised, so a mechanisms run may now exist — but
    only that one. This previously asserted no run existed at all; the invariant
    changed when execution was authorised, not because the assertion was
    inconvenient.

    Strategy B and C remain unauthorised and must leave no artefact.
    """
    results = REPO_ROOT / "eval" / "results" / "finetune"
    runs = [d for d in results.glob("mechanisms/*") if d.is_dir()]
    assert len(runs) <= 1, f"more than one mechanisms run: {[d.name for d in runs]}"
    for pattern in ("*strategy-b*", "*strategy_b*", "*strategy-c*", "*strategy_c*"):
        assert not list(results.rglob(pattern)), pattern


def test_checkpoints_are_only_from_authorised_experiments():
    """Strategy A (`stratA__`) and ADR-019 (`mech__`). Anything else means an
    unregistered training run happened."""
    for directory, prefix in (
        (REPO_ROOT / "artifacts" / "finetune", "stratA__"),
        (REPO_ROOT / "artifacts" / "finetune-mechanisms", "mech__"),
    ):
        if not directory.exists():
            continue
        offenders = [
            d.name for d in directory.iterdir() if d.is_dir() and not d.name.startswith(prefix)
        ]
        assert not offenders, f"{directory.name}: unexpected checkpoints {offenders}"
