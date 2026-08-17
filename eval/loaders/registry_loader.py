"""Composing registered datasets into one benchmark.

Third-party corpora are read from `eval/datasets/raw/<name>.jsonl`, produced by
`scripts/datasets/download.py`. That file is git-ignored: the repository records
*how to obtain* a dataset, never the dataset itself
(docs/14-dataset-strategy.md).
"""

from __future__ import annotations

from pathlib import Path

from eval.loaders.base import (
    RAW_DIR,
    DatasetNotAvailable,
    DatasetNotRegistered,
    RegistryEntry,
    build_sample,
    load_local_jsonl,
    load_registry,
    read_jsonl,
)
from eval.schema import Category, Sample

EVAL_ROOT = Path(__file__).resolve().parents[1]

# Benchmarks assembled from registered datasets. A benchmark is a *named*
# combination so a report can cite one string and a reader can reconstruct it.
BENCHMARKS: dict[str, tuple[str, ...]] = {
    # Internally authored only: no third-party data, therefore no contamination
    # from published corpora. Small, and the honest generalisation check.
    "holdout": ("holdout",),
    # Wiring fixture. Never a source of reported metrics.
    "smoke": ("smoke",),
    # Third-party corpora. `public` is the breadth benchmark; `full` adds the
    # internal hold-out so a single run reports both contaminated and
    # contamination-free performance.
    "public": (
        "deepset-prompt-injections",
        "jackhhao-jailbreak",
        "lakera-gandalf",
        "oasst1-benign",
        "dolly-benign",
    ),
    "full": (
        "holdout",
        "deepset-prompt-injections",
        "jackhhao-jailbreak",
        "lakera-gandalf",
        "oasst1-benign",
        "dolly-benign",
    ),
}


def _load_registered(entry: RegistryEntry) -> list[Sample]:
    if entry.local:
        path = EVAL_ROOT / "datasets" / entry.name / "cases.jsonl"
        return load_local_jsonl(entry.name, path)

    path = RAW_DIR / f"{entry.name}.jsonl"
    if not path.is_file():
        raise DatasetNotAvailable(
            f"{entry.name}: not present at {path}.\n"
            f"  Fetch it with:  uv run python -m scripts.datasets.download {entry.name}\n"
            f"  Source: {entry.source}\n"
            f"  Licence: {entry.licence}"
        )

    samples: list[Sample] = []
    for record in read_jsonl(path):
        samples.append(
            build_sample(
                text=str(record["text"]),
                category=Category(record["category"]),
                source=entry.name,
                sample_id=record.get("sample_id"),
                difficulty=str(record.get("difficulty", "unknown")),
                language=str(record.get("language", "en")),
                notes=record.get("notes"),
            )
        )
    return samples


def load_benchmark(name: str) -> tuple[list[Sample], dict[str, RegistryEntry]]:
    """Load a named benchmark and the registry entries backing it.

    Returns the entries too so a report can print the provenance and licence of
    every source it used.
    """
    if name not in BENCHMARKS:
        raise DatasetNotRegistered(
            f"unknown benchmark {name!r}; known: {', '.join(sorted(BENCHMARKS))}"
        )

    registry = load_registry()
    used: dict[str, RegistryEntry] = {}
    collected: list[Sample] = []

    for dataset_name in BENCHMARKS[name]:
        entry = registry.get(dataset_name)
        if entry is None:
            raise DatasetNotRegistered(
                f"{dataset_name}: no registry entry. Every dataset must record its "
                "source and licence before use (docs/14-dataset-strategy.md)."
            )
        if not entry.usable:
            raise DatasetNotRegistered(
                f"{dataset_name}: licence {entry.licence!r} does not permit use here "
                f"(commercial_use={entry.commercial_use!r})"
            )
        used[dataset_name] = entry
        collected.extend(_load_registered(entry))

    return _deduplicate(collected), used


def _deduplicate(samples: list[Sample]) -> list[Sample]:
    """Drop repeated texts, keeping the first occurrence.

    A prompt present in three corpora is one case, not three. Left in, it is
    counted three times in whichever class it belongs to, which silently
    reweights the benchmark toward whatever the source corpora happen to
    overlap on. Order is deterministic (registry order, then file order), so the
    survivor is stable across runs.

    Conflicting labels are a data-quality problem, not a dedup problem: the
    sample is dropped entirely rather than resolved by coin flip.
    """
    by_key: dict[str, list[Sample]] = {}
    for sample in samples:
        by_key.setdefault(sample.dedup_key, []).append(sample)

    kept: list[Sample] = []
    for group in by_key.values():
        if len({sample.category for sample in group}) > 1:
            # The same text labelled two ways. Unresolvable without a human;
            # keeping either would inject label noise.
            continue
        kept.append(group[0])
    return kept


def available_benchmarks() -> dict[str, bool]:
    """Which benchmarks can be loaded right now."""
    status: dict[str, bool] = {}
    for name in BENCHMARKS:
        try:
            load_benchmark(name)
        except (DatasetNotAvailable, DatasetNotRegistered):
            status[name] = False
        else:
            status[name] = True
    return status
