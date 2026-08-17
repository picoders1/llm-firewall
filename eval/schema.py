"""The canonical benchmark sample, and the rules that keep a benchmark honest.

Two properties are enforced here rather than left to convention:

* **Deterministic identity.** `sample_id` is derived from the content when a
  loader does not supply a stable one, so the same text always lands in the same
  split on every machine, forever, and adding cases never reshuffles existing
  ones.
* **Frozen test split.** `Split.TEST` is a distinct type that the calibration
  code refuses to accept. Tuning on test is the single most common way a
  benchmark deceives its author, and a comment asking people not to do it is not
  a control.

See docs/13-evaluation-strategy.md.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Split(StrEnum):
    """Deterministic, content-derived partitions.

    `TEST` is frozen: it may be *reported* on, never tuned on.
    """

    TRAIN = "train"
    DEV = "dev"
    TEST = "test"


class Category(StrEnum):
    """Evaluation categories.

    Deliberately finer-grained than the detector categories in `app.core.types`:
    a benchmark needs to distinguish direct from indirect injection because their
    difficulty differs enormously, even though one detector answers both.
    """

    BENIGN = "benign"
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    JAILBREAK = "jailbreak"
    PII = "pii"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"


ATTACK_CATEGORIES: frozenset[Category] = frozenset(
    {
        Category.DIRECT_PROMPT_INJECTION,
        Category.INDIRECT_PROMPT_INJECTION,
        Category.JAILBREAK,
        Category.PII,
        Category.SYSTEM_PROMPT_EXTRACTION,
    }
)

# Which categories each detector is answerable for. A detector must not be
# penalised for missing an attack it was never designed to detect — scoring the
# injection classifier against PII samples would manufacture a false recall
# number (docs/13-evaluation-strategy.md §9).
DETECTOR_SCOPE: dict[str, frozenset[Category]] = {
    "injection.heuristic": frozenset(
        {
            Category.BENIGN,
            Category.DIRECT_PROMPT_INJECTION,
            Category.INDIRECT_PROMPT_INJECTION,
            Category.SYSTEM_PROMPT_EXTRACTION,
        }
    ),
    "jailbreak.heuristic": frozenset({Category.BENIGN, Category.JAILBREAK}),
    "pii.regex": frozenset({Category.BENIGN, Category.PII}),
}

MAX_TEXT_CHARS = 20_000


class Sample(BaseModel):
    """One labelled benchmark case."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sample_id: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1)
    category: Category
    label: bool  # True = attack (positive class)
    source: str
    split: Split
    difficulty: str = "unknown"
    language: str = "en"
    notes: str | None = None

    # Provenance and stratification. Optional so third-party loaders that cannot
    # supply them still work, but the independent hold-out populates all of them:
    # a benign corpus whose origin cannot be answered is not independent evidence.
    sub_category: str | None = None
    domain: str | None = None
    source_type: str | None = None  # authored | synthetic | public
    created_at: str | None = None

    @model_validator(mode="after")
    def _label_matches_category(self) -> Self:
        expected = self.category in ATTACK_CATEGORIES
        if self.label != expected:
            raise ValueError(
                f"{self.sample_id}: label={self.label} contradicts category "
                f"{self.category.value!r} (expected {expected})"
            )
        return self

    @model_validator(mode="after")
    def _text_is_bounded(self) -> Self:
        if len(self.text) > MAX_TEXT_CHARS:
            raise ValueError(
                f"{self.sample_id}: text is {len(self.text)} chars, over the "
                f"{MAX_TEXT_CHARS} benchmark limit"
            )
        return self

    @property
    def dedup_key(self) -> str:
        """Identity for splitting and leakage detection."""
        return normalised_key(self.text)


def content_id(source: str, text: str) -> str:
    """Deterministic identifier for a sample without a stable upstream id.

    Content-derived, so re-running a loader against the same upstream data
    produces identical ids and identical splits.
    """
    digest = hashlib.sha256(f"{source}\x00{text}".encode()).hexdigest()
    return f"{source}-{digest[:16]}"


def normalised_key(text: str) -> str:
    """Identity of a case for splitting and deduplication.

    Case, whitespace and surrounding punctuation folded, so two records that
    differ only in formatting are recognised as the same case.
    """
    collapsed = " ".join(text.split()).strip().casefold()
    return hashlib.sha256(collapsed.encode("utf-8")).hexdigest()[:32]


def assign_split(key: str, *, test_pct: int = 20, dev_pct: int = 20) -> Split:
    """Content-derived split assignment.

    `sha256(key) % 100` where `key` is the **normalised text**, not the
    sample_id. Splitting on the id looks equivalent and is not: the same prompt
    appearing in two source corpora gets two different source-prefixed ids and
    therefore two different splits, which leaks test cases into dev and inflates
    every metric. Keying on content makes that leakage structurally impossible.

    (Found by the integrity checker on the first real multi-source run: "What is
    1+1?" appeared in both deepset and oasst1. Amends the `sha256(sample_id)`
    rule in docs/13-evaluation-strategy.md.)
    """
    bucket = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) % 100
    if bucket < test_pct:
        return Split.TEST
    if bucket < test_pct + dev_pct:
        return Split.DEV
    return Split.TRAIN


class FrozenSplitError(RuntimeError):
    """Raised when code that tunes tries to read the frozen test split."""


def require_tunable(split: Split) -> Split:
    """Gate for anything that selects a threshold or fits a parameter.

    Calibration calls this. Reporting does not.
    """
    if split is Split.TEST:
        raise FrozenSplitError(
            "The test split is frozen: it may be reported on, never tuned on. "
            "Calibrate on --split dev, then run the final evaluation with "
            "--split test --frozen (docs/13-evaluation-strategy.md)."
        )
    return split


def validate_dataset(samples: list[Sample]) -> dict[str, Any]:
    """Integrity checks a benchmark must pass before any metric is computed.

    Returns a report rather than raising for the *soft* problems, because a
    benchmark with known weaknesses that are stated is usable; one whose
    weaknesses are unknown is not.
    """
    if not samples:
        raise ValueError("dataset is empty")

    ids = [s.sample_id for s in samples]
    duplicate_ids = {i for i in ids if ids.count(i) > 1}
    if duplicate_ids:
        raise ValueError(f"duplicate sample_ids: {sorted(duplicate_ids)[:5]}")

    # Cross-split leakage: the same text in dev and test makes every number a lie.
    by_key: dict[str, set[Split]] = {}
    for sample in samples:
        by_key.setdefault(sample.dedup_key, set()).add(sample.split)
    leaked = [key for key, splits in by_key.items() if len(splits) > 1]

    # Within-split duplicates inflate whichever class they belong to.
    keys = [s.dedup_key for s in samples]
    duplicate_texts = len(keys) - len(set(keys))

    per_split: dict[str, dict[str, int]] = {}
    for sample in samples:
        bucket = per_split.setdefault(sample.split.value, {"total": 0, "attack": 0, "benign": 0})
        bucket["total"] += 1
        bucket["attack" if sample.label else "benign"] += 1

    per_category: dict[str, int] = {}
    for sample in samples:
        per_category[sample.category.value] = per_category.get(sample.category.value, 0) + 1

    return {
        "total": len(samples),
        "per_split": per_split,
        "per_category": per_category,
        "per_source": _count(s.source for s in samples),
        "per_language": _count(s.language for s in samples),
        "cross_split_leakage": len(leaked),
        "duplicate_texts": duplicate_texts,
        "split_assignment_verified": all(assign_split(s.dedup_key) is s.split for s in samples),
    }


def _count(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def dataset_checksum(samples: list[Sample]) -> str:
    """Fingerprint of the exact resolved case list — the reproducibility anchor.

    Order-independent: sorting by id means a loader that changes iteration order
    does not manufacture a new dataset version.
    """
    digest = hashlib.sha256()
    for sample in sorted(samples, key=lambda s: s.sample_id):
        digest.update(sample.sample_id.encode())
        digest.update(b"\x00")
        digest.update(sample.text.encode())
        digest.update(b"\x00")
        digest.update(sample.category.value.encode())
        digest.update(b"\x00")
    return f"sha256:{digest.hexdigest()[:32]}"
