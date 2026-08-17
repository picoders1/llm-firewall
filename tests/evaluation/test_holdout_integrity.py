"""The independent hold-out's integrity, asserted rather than assumed.

The hold-out's only value is its independence. If it shares text with a corpus a
model trained on, it is not a hold-out — it is more training data with a
misleading name. These tests re-run that check on every CI run, so a future
dataset addition cannot quietly contaminate it.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from eval.schema import normalised_key

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
HOLDOUT = REPO_ROOT / "eval" / "datasets" / "holdout" / "cases.jsonl"
MANIFEST = REPO_ROOT / "eval" / "datasets" / "holdout" / "build_manifest.json"

REQUIRED_FIELDS = {"sample_id", "text", "category", "source", "language"}
PROVENANCE_FIELDS = {"source_type", "created_at", "domain", "sub_category"}


def load() -> list[dict]:
    return [
        json.loads(line)
        for line in HOLDOUT.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return load()


@pytest.fixture(scope="module")
def benign(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["category"] == "benign"]


# --- Size and composition ---------------------------------------------------


def test_benign_holdout_meets_the_required_size(benign: list[dict]):
    """The 32-sample hold-out could not support a deployment claim; 500 was the
    agreed floor."""
    assert len(benign) >= 450, f"only {len(benign)} benign samples"


def test_hard_negatives_are_a_substantial_share(benign: list[dict]):
    """Hard negatives are the point of this corpus. Without them it measures a
    register nobody worries about."""
    hard = [r for r in benign if r.get("notes") == "hard_negative"]
    assert len(hard) >= 150
    assert 0.25 <= len(hard) / len(benign) <= 0.60


def test_domain_coverage_is_broad(benign: list[dict]):
    domains = {r.get("domain") for r in benign if r.get("domain")}
    assert len(domains) >= 12, f"only {len(domains)} domains: {sorted(domains)}"
    # The domains where false positives actually hurt must be present.
    assert {"security_operations", "incident_response", "compliance"} <= domains


def test_difficulty_is_stratified(benign: list[dict]):
    counts = Counter(r["difficulty"] for r in benign)
    assert counts["hard"] >= 100
    assert counts["easy"] >= 20
    assert counts["medium"] >= 50


def test_length_variation_is_realistic(rows: list[dict]):
    """A corpus of uniformly short sentences measures a register nobody types."""
    lengths = sorted(len(r["text"]) for r in rows)
    assert lengths[0] < 40, "no short prompts"
    assert lengths[-1] > 400, "no long prompts"
    assert lengths[len(lengths) // 2] < 250, "median suspiciously long"


# --- Schema and provenance --------------------------------------------------


def test_every_sample_has_the_required_fields(rows: list[dict]):
    for row in rows:
        missing = REQUIRED_FIELDS - set(row)
        assert not missing, f"{row.get('sample_id')} missing {missing}"


def test_authored_samples_carry_full_provenance(rows: list[dict]):
    """ "Where did this sample come from?" must be answerable per sample."""
    for row in rows:
        missing = {f for f in PROVENANCE_FIELDS if not row.get(f)}
        assert not missing, f"{row['sample_id']} missing provenance {missing}"
        assert row["source_type"] in {"authored", "synthetic", "public"}


def test_sample_ids_are_unique(rows: list[dict]):
    ids = [r["sample_id"] for r in rows]
    assert len(ids) == len(set(ids))


def test_benign_samples_are_labelled_benign(benign: list[dict]):
    for row in benign:
        assert row["category"] == "benign"


# --- Integrity ---------------------------------------------------------------


def test_no_internal_duplicates(rows: list[dict]):
    keys = [normalised_key(r["text"]) for r in rows]
    duplicates = [k for k, n in Counter(keys).items() if n > 1]
    assert not duplicates, f"{len(duplicates)} duplicated texts"


def test_no_contamination_with_any_other_corpus(rows: list[dict]):
    """The load-bearing property. If this fails, every hold-out number is void."""
    from eval.loaders.base import RAW_DIR

    ours = {normalised_key(r["text"]) for r in rows}
    collisions: list[str] = []

    for path in sorted(RAW_DIR.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            other = json.loads(line)
            if normalised_key(other["text"]) in ours:
                collisions.append(f"{path.stem}: {other['text'][:60]}")

    smoke = REPO_ROOT / "eval" / "datasets" / "smoke" / "cases.jsonl"
    if smoke.is_file():
        for line in smoke.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            other = json.loads(line)
            text = other.get("text") or other.get("prompt", "")
            if normalised_key(text) in ours:
                collisions.append(f"smoke: {text[:60]}")

    assert not collisions, f"{len(collisions)} contamination collisions: {collisions[:3]}"


# --- Safety ------------------------------------------------------------------


def test_no_credentials_or_secrets(rows: list[dict]):
    from scripts.datasets.build_holdout import SECRET_PATTERNS

    for row in rows:
        for name, pattern in SECRET_PATTERNS.items():
            assert not pattern.search(row["text"]), f"{row['sample_id']}: {name}"


def test_no_real_looking_pii_outside_the_pii_category(rows: list[dict]):
    from scripts.datasets.build_holdout import PII_PATTERNS, _is_real_card_risk

    for row in rows:
        if row["category"] == "pii":
            continue
        for name, pattern in PII_PATTERNS.items():
            match = pattern.search(row["text"])
            if not match:
                continue
            if name == "card_like" and not _is_real_card_risk(match.group(0)):
                continue
            pytest.fail(f"{row['sample_id']}: possible real PII ({name})")


def test_email_addresses_use_reserved_domains(rows: list[dict]):
    """RFC 2606 reserves example.com/org/net and the .example/.test/.invalid TLDs."""
    for row in rows:
        for address in re.findall(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b", row["text"]):
            domain = address.split("@", 1)[1].lower()
            assert domain.startswith("example.") or domain.endswith(
                (".example", ".test", ".invalid", ".localhost")
            ), f"{row['sample_id']}: non-reserved email domain {domain}"


# --- Build manifest ----------------------------------------------------------


def test_build_manifest_records_the_integrity_result():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["contamination"]["collisions"] == 0
    assert manifest["internal_duplicates_dropped"] == 0
    assert manifest["provenance"]["source_type"] == "authored"
    assert manifest["composition"]["benign"] >= 450


def test_manifest_matches_the_actual_file(rows: list[dict]):
    """A stale manifest would describe a corpus that no longer exists."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["composition"]["total"] == len(rows)


# --- Frozen-threshold discipline ---------------------------------------------


def test_validation_thresholds_match_the_shipped_policy():
    """The hold-out must be scored at the threshold in force, not a new one.

    If someone changes the policy threshold without re-running calibration, this
    fails — which is the point.
    """
    from app.config.policy import load_policy
    from scripts.validate_holdout import FROZEN_THRESHOLDS

    policy = load_policy(REPO_ROOT / "config" / "policies" / "default.yaml")
    entry = policy.input["prompt_injection"]
    assert FROZEN_THRESHOLDS["injection.heuristic"] == entry.threshold


def test_the_holdout_is_never_used_for_calibration():
    """`validate_holdout` reports; it must not contain a calibration call."""
    source = (REPO_ROOT / "scripts" / "validate_holdout.py").read_text(encoding="utf-8")
    assert "calibrate(" not in source
    assert "Objective." not in source


# --- Calibration-contamination guard ----------------------------------------


def test_calibration_split_excludes_the_independent_holdout():
    """The `full` benchmark CONTAINS the hold-out, so its dev split carries
    hold-out samples. Calibration must use `public/dev`, which does not.

    Regression: this was caught during the threshold analysis before any
    threshold was selected, and is asserted here so it cannot recur.
    """
    from eval.loaders.registry_loader import load_benchmark
    from eval.schema import DETECTOR_SCOPE, Split

    scope = DETECTOR_SCOPE["injection.heuristic"]

    public, _ = load_benchmark("public")
    public_dev = [s for s in public if s.split is Split.DEV and s.category in scope]
    assert public_dev, "public/dev is empty"
    assert not [s for s in public_dev if s.source == "internal_authored"], (
        "public/dev contains independent hold-out samples"
    )

    full, _ = load_benchmark("full")
    full_dev = [s for s in full if s.split is Split.DEV and s.category in scope]
    # Documents *why* public/dev is the calibration split.
    assert [s for s in full_dev if s.source == "internal_authored"], (
        "full/dev no longer contains hold-out samples; the guard's rationale has changed"
    )


def test_threshold_analysis_guards_against_holdout_in_calibration():
    from eval.loaders.registry_loader import load_benchmark
    from scripts.threshold_analysis import _assert_no_holdout

    holdout, _ = load_benchmark("holdout")
    with pytest.raises(RuntimeError, match="HOLD-OUT LEAK"):
        _assert_no_holdout(holdout, "test")


def test_threshold_analysis_freezes_before_scoring_the_holdout():
    """Source-level check: the freeze must precede hold-out loading."""
    source = (REPO_ROOT / "scripts" / "threshold_analysis.py").read_text(encoding="utf-8")
    freeze = source.index("operating_points.json")
    load_holdout = source.index('load_benchmark("holdout")')
    assert freeze < load_holdout, "hold-out is loaded before thresholds are frozen"
