"""Evaluation plumbing over the smoke fixture.

**These tests assert wiring, not detection quality.** They deliberately do not
assert an accuracy, precision or recall figure: with n=31 authored by the rule
author, any such number would be meaningless and quoting it would be exactly the
self-deception docs/13-evaluation-strategy.md exists to prevent.

What they do assert: the fixture parses, labels are handled correctly, detectors
are deterministic, and results can be grouped per category — the properties Phase
4's real harness will depend on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.config.policy import DetectorPolicy
from app.core.normalize import decode_embedded, normalize
from app.core.types import DetectionContext, Direction, Role
from app.detectors.injection.heuristic import build as build_injection
from app.detectors.jailbreak.heuristic import build as build_jailbreak
from app.detectors.pii.regex import build as build_pii

pytestmark = pytest.mark.evaluation

FIXTURE = Path(__file__).resolve().parents[2] / "eval" / "datasets" / "smoke" / "cases.jsonl"

REQUIRED_FIELDS = {
    "sample_id",
    "category",
    "prompt",
    "expected_label",
    "difficulty",
    "source",
    "language",
}
KNOWN_CATEGORIES = {
    "benign",
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "jailbreak",
    "pii",
    "system_prompt_extraction",
}


def load_cases() -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in FIXTURE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def context(prompt: str) -> DetectionContext:
    folded = normalize(prompt)
    return DetectionContext(
        request_id="eval",
        direction=Direction.INPUT,
        role=Role.USER,
        raw_text=prompt,
        normalized_text=folded.text,
        normalized_offsets=folded.offsets,
        decoded_segments=decode_embedded(prompt),
    )


# --- Fixture integrity -----------------------------------------------------


def test_fixture_exists_and_parses():
    cases = load_cases()
    assert len(cases) >= 30


def test_every_case_has_the_required_schema():
    for case in load_cases():
        missing = REQUIRED_FIELDS - set(case)
        assert not missing, f"{case.get('sample_id')} missing {missing}"
        assert case["category"] in KNOWN_CATEGORIES
        assert isinstance(case["expected_label"], bool)
        assert case["difficulty"] in {"easy", "medium", "hard"}


def test_sample_ids_are_unique_and_stable():
    """Splits are derived from `sample_id`; a duplicate would place one case in
    two splits and a rename would silently move it."""
    ids = [case["sample_id"] for case in load_cases()]
    assert len(ids) == len(set(ids))


def test_labels_and_categories_agree():
    for case in load_cases():
        if case["category"] == "benign":
            assert case["expected_label"] is False, case["sample_id"]
        else:
            assert case["expected_label"] is True, case["sample_id"]


def test_fixture_contains_all_four_required_classes():
    categories = {case["category"] for case in load_cases()}
    assert "benign" in categories
    assert {"direct_prompt_injection", "indirect_prompt_injection"} & categories
    assert "jailbreak" in categories
    assert "pii" in categories


def test_fixture_contains_hard_benign_cases():
    """Near-miss benign cases are what make a fixture worth anything: they are
    where a naive rule set produces its false positives."""
    hard_benign = [
        case
        for case in load_cases()
        if case["category"] == "benign" and case["difficulty"] == "hard"
    ]
    assert len(hard_benign) >= 3


def test_no_real_pii_in_the_fixture():
    """Synthetic values only — example.com, 555-01xx, the standard test card."""
    text = FIXTURE.read_text(encoding="utf-8")
    for case in load_cases():
        prompt = str(case["prompt"])
        if "@" in prompt:
            assert "example.com" in prompt or "example.org" in prompt, case["sample_id"]
    assert "4111 1111 1111 1111" in text  # the documented test card


# --- Plumbing --------------------------------------------------------------


@pytest.fixture
def detectors():
    return (
        build_injection(DetectorPolicy(detector="injection.heuristic", threshold=0.85)),
        build_jailbreak(DetectorPolicy(detector="jailbreak.heuristic", threshold=0.85)),
        build_pii(DetectorPolicy(detector="pii.regex", threshold=0.5, action="redact")),
    )


async def test_every_case_can_be_scored_without_error(detectors):
    injection, jailbreak, pii = detectors
    for case in load_cases():
        ctx = context(str(case["prompt"]))
        for detector in (injection, jailbreak, pii):
            result = await detector.detect(ctx)
            assert 0.0 <= result.score <= 1.0
            assert result.errored is False


async def test_detectors_are_deterministic(detectors):
    """Reproducibility is a precondition for every metric Phase 4 will publish."""
    injection, _, _ = detectors
    for case in load_cases()[:10]:
        ctx = context(str(case["prompt"]))
        first = await injection.detect(ctx)
        second = await injection.detect(ctx)
        assert first.score == second.score
        assert first.reasons == second.reasons


async def test_results_can_be_grouped_by_category(detectors):
    """Per-category recall is the reporting shape Phase 4 needs; aggregate
    numbers hide that indirect injection is far harder than direct."""
    injection, jailbreak, pii = detectors
    grouped: dict[str, list[bool]] = {}

    for case in load_cases():
        ctx = context(str(case["prompt"]))
        flagged = False
        for detector in (injection, jailbreak, pii):
            if (await detector.detect(ctx)).detected:
                flagged = True
        grouped.setdefault(str(case["category"]), []).append(flagged)

    assert set(grouped) <= KNOWN_CATEGORIES
    assert all(isinstance(values, list) and values for values in grouped.values())


def test_split_assignment_is_deterministic_and_content_derived():
    """`sha256(sample_id) % 100` — no RNG, no shuffle order, stable across
    machines and across dataset growth (docs/13-evaluation-strategy.md)."""
    import hashlib

    def split_of(sample_id: str) -> str:
        bucket = int(hashlib.sha256(sample_id.encode()).hexdigest()[:8], 16) % 100
        return "test" if bucket < 20 else "dev" if bucket < 40 else "train"

    cases = load_cases()
    first = {str(c["sample_id"]): split_of(str(c["sample_id"])) for c in cases}
    second = {str(c["sample_id"]): split_of(str(c["sample_id"])) for c in reversed(cases)}

    assert first == second
    assert set(first.values()) <= {"train", "dev", "test"}


def test_the_fixture_documents_that_it_is_not_a_benchmark():
    """The disclaimer is part of the artefact, not just of the docs."""
    readme = (FIXTURE.parent / "README.md").read_text(encoding="utf-8")
    assert "NOT a benchmark" in readme
    assert "may be reported as a project result" in readme
