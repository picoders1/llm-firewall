"""Dataset loading and the registry that governs it.

Two rules the loaders enforce:

* **Nothing third-party is committed.** Loaders read from
  `eval/datasets/raw/`, which is git-ignored, and fail with a pointer to the
  download script when the data is absent.
* **Nothing is loaded without a registry entry** recording source, licence and
  redistribution terms. A dataset with an unclear licence is not used, and
  "it was on the internet" is not a licence (docs/14-dataset-strategy.md).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from eval.schema import Category, Sample, Split, assign_split, content_id, normalised_key

EVAL_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = EVAL_ROOT / "datasets" / "registry.yaml"
RAW_DIR = EVAL_ROOT / "datasets" / "raw"


class DatasetNotAvailable(RuntimeError):
    """Raised when registered data has not been fetched."""


class DatasetNotRegistered(RuntimeError):
    """Raised when a loader is asked for data with no registry entry."""


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    name: str
    source: str
    licence: str
    redistributable: bool
    commercial_use: str
    gated: bool
    categories: tuple[str, ...]
    languages: tuple[str, ...]
    verified_on: str
    notes: str
    download: str | None = None
    local: bool = False
    contamination_risk: str = "unknown"

    @property
    def usable(self) -> bool:
        """Whether the licence permits use in this project.

        Non-commercial licences are excluded: the project is Apache-2.0 and a
        benchmark that cannot be used commercially is a benchmark this project
        cannot rely on.

        Share-alike (CC-BY-SA) *is* permitted. It allows commercial use; the
        obligation binds derivative *datasets*, and this project consumes the
        data for measurement without redistributing it. If we ever publish a
        derived corpus, that corpus inherits the licence — recorded in the
        registry notes so the obligation is not forgotten.
        """
        return self.commercial_use in {
            "permitted",
            "permitted-with-attribution",
            "permitted-with-share-alike",
        }


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, RegistryEntry]:
    if not path.is_file():
        raise DatasetNotRegistered(f"dataset registry not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries: dict[str, RegistryEntry] = {}
    for item in raw.get("datasets", []):
        entry = RegistryEntry(
            name=item["name"],
            source=item["source"],
            licence=item["licence"],
            redistributable=bool(item.get("redistributable", False)),
            commercial_use=item.get("commercial_use", "unknown"),
            gated=bool(item.get("gated", False)),
            categories=tuple(item.get("categories", ())),
            languages=tuple(item.get("languages", ("en",))),
            verified_on=str(item.get("verified_on", "unverified")),
            notes=item.get("notes", ""),
            download=item.get("download"),
            local=bool(item.get("local", False)),
            contamination_risk=item.get("contamination_risk", "unknown"),
        )
        entries[entry.name] = entry
    return entries


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: malformed JSON: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{line_number}: expected a JSON object")
        yield record


def build_sample(
    *,
    text: str,
    category: Category,
    source: str,
    sample_id: str | None = None,
    difficulty: str = "unknown",
    language: str = "en",
    notes: str | None = None,
    sub_category: str | None = None,
    domain: str | None = None,
    source_type: str | None = None,
    created_at: str | None = None,
) -> Sample:
    """Construct a sample with a deterministic id and a derived split."""
    identifier = sample_id or content_id(source, text)
    return Sample(
        sample_id=identifier,
        text=text,
        category=category,
        label=category is not Category.BENIGN,
        source=source,
        split=assign_split(normalised_key(text)),
        difficulty=difficulty,
        language=language,
        notes=notes,
        sub_category=sub_category,
        domain=domain,
        source_type=source_type,
        created_at=created_at,
    )


def load_local_jsonl(name: str, path: Path) -> list[Sample]:
    """Load an in-repo, self-authored dataset.

    Split is recomputed from `sample_id` rather than trusted from the file, so a
    hand-edited `split` field cannot move a case between splits.
    """
    if not path.is_file():
        raise DatasetNotAvailable(f"{name}: not found at {path}")
    samples: list[Sample] = []
    for record in read_jsonl(path):
        text = record.get("text") or record.get("prompt")
        if not text:
            raise ValueError(f"{name}: record {record.get('sample_id')!r} has no text")
        samples.append(
            build_sample(
                text=str(text),
                category=Category(record["category"]),
                source=str(record.get("source", name)),
                sample_id=str(record["sample_id"]),
                difficulty=str(record.get("difficulty", "unknown")),
                language=str(record.get("language", "en")),
                notes=record.get("notes"),
                sub_category=record.get("sub_category"),
                domain=record.get("domain"),
                source_type=record.get("source_type"),
                created_at=record.get("created_at"),
            )
        )
    return samples


def filter_split(samples: Iterable[Sample], split: Split | None) -> list[Sample]:
    if split is None:
        return list(samples)
    return [sample for sample in samples if sample.split is split]
