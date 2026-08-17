"""Guards on the Phase 2P-D provenance experiment.

The experiment's claim is causal: the arms differ *only* in whether a span's
provenance is known and used. These tests hold that property mechanically, because
a silent divergence between arms — different text, a different threshold, a
different model — would invalidate the comparison without failing anything.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.types import Provenance, TrustLevel
from eval.provenance_arms import (
    ARMS,
    build_parts,
    combine,
    locate_embedded,
)

pytestmark = pytest.mark.evaluation

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS = REPO_ROOT / "eval" / "datasets" / "holdout" / "indirect-v1" / "cases.jsonl"
RUNS = sorted((REPO_ROOT / "eval" / "results" / "provenance").glob("*__provenance-secondary"))


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return [
        json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@pytest.fixture(scope="module")
def candidates() -> tuple[str, ...]:
    from scripts.datasets.authoring.indirect_v1_pools import INERT_REFERENCES, PAYLOADS

    return tuple(sorted([p for p, _ in PAYLOADS] + list(INERT_REFERENCES), key=len, reverse=True))


def arm(name: str):
    return next(a for a in ARMS if a.name == name)


# --- The arms differ only in provenance access -----------------------------


def test_the_control_arm_is_marked_as_such():
    assert arm("A0_content_only_flat").is_control


def test_capability_flags_match_the_arm_names():
    for a in ARMS:
        if "content_only" in a.name:
            assert a.consumes_provenance is False, a.name
        else:
            assert a.consumes_provenance is True, a.name


def test_split_adds_and_removes_no_content(rows, candidates):
    """The load-bearing property: segmentation must not alter what the model reads.

    Extracting the span *reorders*: the parts are (carrier, span) while the
    original had the span in the middle, and removing it joins the two neighbouring
    fragments. So the invariant is asserted over the multiset of **non-whitespace
    characters** — word-level comparison would fail on that join even though
    nothing was added or removed. Order between parts is irrelevant because each
    part is scored independently.
    """
    from collections import Counter

    def characters(text: str) -> Counter[str]:
        return Counter("".join(text.split()))

    flat_arm = arm("A0_content_only_flat")
    split_arm = arm("A2_provenance_aware_split")
    for row in rows:
        flat = "".join(p.text for p in build_parts(row["text"], flat_arm, candidates))
        split = "".join(p.text for p in build_parts(row["text"], split_arm, candidates))
        assert characters(flat) == characters(split), row["sample_id"]


def test_the_embedded_span_is_scored_verbatim(rows, candidates):
    """The span handed to the model must be exactly the authored payload — not a
    trimmed or re-joined approximation of it."""
    for row in rows:
        located = locate_embedded(row["text"], candidates)
        assert located is not None
        _, embedded = located
        parts = build_parts(row["text"], arm("A2_provenance_aware_split"), candidates)
        assert parts[-1].text == embedded, row["sample_id"]
        assert embedded in row["text"], row["sample_id"]


def test_a0_and_a1_see_identical_parts(rows, candidates):
    """A1 differs from A0 only in being allowed to read provenance."""
    for row in rows[:50]:
        a0 = build_parts(row["text"], arm("A0_content_only_flat"), candidates)
        a1 = build_parts(row["text"], arm("A1_provenance_aware_flat"), candidates)
        assert [p.text for p in a0] == [p.text for p in a1], row["sample_id"]


def test_a2_and_a3_see_identical_parts(rows, candidates):
    """A3 is A2 with the labels ignored. Same spans, same tags — only `combine`
    differs. This is what makes A3 a valid isolation of segmentation."""
    for row in rows[:50]:
        a2 = build_parts(row["text"], arm("A2_provenance_aware_split"), candidates)
        a3 = build_parts(row["text"], arm("A3_content_only_split"), candidates)
        assert [(p.text, p.trust) for p in a2] == [(p.text, p.trust) for p in a3], row["sample_id"]


# --- Segmentation and provenance assignment --------------------------------


def test_every_corpus_sample_can_be_split(rows, candidates):
    """If a sample could not be located, SPLIT would silently degenerate to FLAT
    for it and the arm would be a blend."""
    for row in rows:
        assert locate_embedded(row["text"], candidates) is not None, row["sample_id"]


def test_flat_assigns_what_the_gateway_derives(rows, candidates):
    for row in rows[:20]:
        (part,) = build_parts(row["text"], arm("A0_content_only_flat"), candidates)
        assert part.provenance is Provenance.USER_INPUT
        assert part.trust is TrustLevel.PRINCIPAL
        assert not part.untrusted


def test_split_tags_the_embedded_span_untrusted_and_the_carrier_not(rows, candidates):
    for row in rows[:20]:
        parts = build_parts(row["text"], arm("A2_provenance_aware_split"), candidates)
        assert parts[-1].provenance is Provenance.EXTERNAL
        assert parts[-1].untrusted
        assert all(not p.untrusted for p in parts[:-1])


def test_provenance_is_never_inferred_from_the_text(rows, candidates):
    """Attacks and benign controls must receive identical tags — otherwise the
    labelling leaks the answer and the experiment is worthless."""
    tags = set()
    for row in rows:
        parts = build_parts(row["text"], arm("A2_provenance_aware_split"), candidates)
        tags.add((row["label"], tuple(p.trust.value for p in parts)))
    attack_shapes = {shape for label, shape in tags if label == 1}
    benign_shapes = {shape for label, shape in tags if label == 0}
    assert attack_shapes & benign_shapes, "no tag pattern is shared; provenance leaks the label"


# --- Ablation modes behave as designed -------------------------------------


def test_removed_mode_marks_everything_unknown(rows, candidates):
    for row in rows[:20]:
        parts = build_parts(row["text"], arm("M2_provenance_removed"), candidates)
        assert all(p.provenance is Provenance.UNKNOWN for p in parts)
        assert all(not p.untrusted for p in parts)


def test_inverted_mode_swaps_the_tags(rows, candidates):
    for row in rows[:20]:
        parts = build_parts(row["text"], arm("M4_provenance_inverted"), candidates)
        if len(parts) < 2:
            continue
        assert parts[0].untrusted, "carrier should be untrusted when inverted"
        assert not parts[-1].untrusted, "embedded span should be trusted when inverted"


def test_ablation_modes_do_not_change_the_text(rows, candidates):
    """The ablations must vary labels only."""
    base = arm("A2_provenance_aware_split")
    for mode_name in ("M2_provenance_removed", "M4_provenance_inverted"):
        for row in rows[:30]:
            expected = [p.text for p in build_parts(row["text"], base, candidates)]
            actual = [p.text for p in build_parts(row["text"], arm(mode_name), candidates)]
            assert expected == actual, f"{mode_name} altered the text of {row['sample_id']}"


# --- Combination rule ------------------------------------------------------


def test_a_provenance_consuming_arm_scores_only_untrusted_spans():
    from eval.provenance_arms import Part

    parts = [
        Part("carrier", Provenance.USER_INPUT, TrustLevel.PRINCIPAL),
        Part("payload", Provenance.EXTERNAL, TrustLevel.UNTRUSTED),
    ]
    scores = [0.99, 0.10]
    assert combine(scores, parts, arm("A2_provenance_aware_split")) == 0.10
    assert combine(scores, parts, arm("A3_content_only_split")) == 0.99


def test_no_untrusted_span_means_zero_for_a_consuming_arm():
    """Not a failure — the correct answer to "is there an instruction in data
    that should not contain one" when there is no such data. This is exactly why
    the M2 ablation is informative."""
    from eval.provenance_arms import Part

    parts = [Part("only user text", Provenance.USER_INPUT, TrustLevel.PRINCIPAL)]
    assert combine([0.99], parts, arm("A2_provenance_aware_split")) == 0.0
    assert combine([0.99], parts, arm("A3_content_only_split")) == 0.99


# --- Production isolation --------------------------------------------------


def test_no_experimental_arm_is_registered_as_a_production_detector():
    """The experiment must be able to fail without having touched the gateway."""
    from app.detectors.registry import registered_names

    names = set(registered_names())
    for a in ARMS:
        assert a.name not in names
    assert names == {"injection.heuristic", "jailbreak.heuristic", "pii.regex", "output.stub"}


def test_the_experiment_module_lives_outside_the_application():
    import eval.provenance_arms as module

    assert "/app/" not in module.__file__.replace(str(REPO_ROOT), "")


# --- The recorded run ------------------------------------------------------


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_the_run_used_the_frozen_checkpoint_and_threshold():
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
    assert metrics["threshold"] == lock["selected_threshold"] == 0.9955
    assert metrics["checkpoint_sha256"] == lock["checkpoint_sha256"]
    assert metrics["retrained"] is False
    assert metrics["threshold_source"].endswith("NOT recalibrated")
    assert all(metrics["pre_evaluation_checks"].values())


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_the_run_declares_itself_a_secondary_evaluation():
    """It must not be presentable as a fresh hold-out."""
    manifest = json.loads((RUNS[0] / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["run_type"] == "provenance-aware secondary evaluation"
    assert manifest["corpus_modified"] is False
    assert manifest["previous_evaluation"]


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_the_control_arm_reproduces_the_prior_published_result():
    """A0 must match `20260817T130736Z__indirect-delivery-shape` exactly. If it
    does not, the harness is measuring something other than the prior run and no
    comparison to it is valid."""
    metrics = json.loads((RUNS[0] / "metrics.json").read_text(encoding="utf-8"))
    prior = json.loads(
        (
            REPO_ROOT
            / "eval"
            / "results"
            / "20260817T130736Z__indirect-delivery-shape"
            / "metrics.json"
        ).read_text(encoding="utf-8")
    )
    control = metrics["arms"]["A0_content_only_flat"]
    assert control["attack_recall"]["recall"] == prior["attack_recall"]["recall"]
    assert control["benign_control_fpr"]["fpr"] == prior["benign_control_fpr"]["fpr"]


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_the_criterion_defect_is_recorded_rather_than_silently_fixed():
    amendment = (RUNS[0] / "amendment.md").read_text(encoding="utf-8")
    assert "criterion 3" in amendment
    assert "decision is unchanged" in amendment


@pytest.mark.skipif(len(RUNS) != 1, reason="experiment not yet run")
def test_policy_ablation_is_labelled_as_not_a_detector_result():
    ablation = json.loads((RUNS[0] / "policy_ablation.json").read_text(encoding="utf-8"))
    assert "NOT a detector result" in ablation["note"]


# --- McNemar arithmetic ----------------------------------------------------


def test_mcnemar_matches_hand_computed_values():
    from scripts.evaluate_provenance import mcnemar_exact

    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(5, 5) == 1.0
    assert mcnemar_exact(6, 0) == pytest.approx(2 * 0.5**6)
    assert mcnemar_exact(1, 0) == 1.0
    assert mcnemar_exact(6, 0) < 0.05
    assert mcnemar_exact(5, 0) > 0.05


def test_mcnemar_is_symmetric():
    from scripts.evaluate_provenance import mcnemar_exact

    for b, c in [(3, 9), (0, 7), (12, 4)]:
        assert mcnemar_exact(b, c) == mcnemar_exact(c, b)
