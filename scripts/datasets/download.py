"""Fetch registered third-party datasets into the git-ignored raw directory.

The repository records **how to obtain** a dataset, never the dataset itself
(docs/14-dataset-strategy.md). This script:

* refuses any dataset that is not in the registry, or whose licence does not
  permit use here;
* normalises each source to the canonical case schema;
* writes to `eval/datasets/raw/`, which is git-ignored;
* prints a checksum so a run can be tied to the exact data it saw.

    uv run python -m scripts.datasets.download --list
    uv run python -m scripts.datasets.download deepset-prompt-injections
    uv run python -m scripts.datasets.download --all

Requires the `eval` extra:  uv sync --extra eval
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from eval.loaders.base import RAW_DIR, load_registry

# Per-dataset normalisation into the canonical schema. Each entry names the HF
# dataset, the split to read, and a function mapping one upstream record to
# `(text, category)` or None to drop it.
BENIGN_SAMPLE_CAP = 4000


def _deepset(record: dict[str, Any]) -> tuple[str, str] | None:
    text = record.get("text")
    label = record.get("label")
    if not text or label is None:
        return None
    return str(text), ("direct_prompt_injection" if int(label) == 1 else "benign")


def _jackhhao(record: dict[str, Any]) -> tuple[str, str] | None:
    text = record.get("prompt")
    label = str(record.get("type", "")).lower()
    if not text or label not in {"jailbreak", "benign"}:
        return None
    return str(text), ("jailbreak" if label == "jailbreak" else "benign")


def _gandalf(record: dict[str, Any]) -> tuple[str, str] | None:
    text = record.get("text")
    if not text:
        return None
    # Attack-only corpus: it can measure recall, never FPR.
    return str(text), "direct_prompt_injection"


def _oasst1(record: dict[str, Any]) -> tuple[str, str] | None:
    if record.get("role") != "prompter" or record.get("lang") != "en":
        return None
    text = record.get("text")
    if not text or len(str(text)) < 12:
        return None
    return str(text), "benign"


def _dolly(record: dict[str, Any]) -> tuple[str, str] | None:
    text = record.get("instruction")
    if not text or len(str(text)) < 12:
        return None
    return str(text), "benign"


SOURCES: dict[str, dict[str, Any]] = {
    "deepset-prompt-injections": {
        "hf_id": "deepset/prompt-injections",
        "splits": ["train", "test"],
        "map": _deepset,
        "cap": None,
    },
    "jackhhao-jailbreak": {
        "hf_id": "jackhhao/jailbreak-classification",
        "splits": ["train", "test"],
        "map": _jackhhao,
        "cap": None,
    },
    "lakera-gandalf": {
        "hf_id": "Lakera/gandalf_ignore_instructions",
        "splits": ["train", "validation", "test"],
        "map": _gandalf,
        "cap": None,
    },
    "oasst1-benign": {
        "hf_id": "OpenAssistant/oasst1",
        "splits": ["train"],
        "map": _oasst1,
        "cap": BENIGN_SAMPLE_CAP,
    },
    "dolly-benign": {
        "hf_id": "databricks/databricks-dolly-15k",
        "splits": ["train"],
        "map": _dolly,
        "cap": BENIGN_SAMPLE_CAP,
    },
}


def _records(hf_id: str, splits: list[str]) -> Iterator[dict[str, Any]]:
    try:
        from datasets import load_dataset  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover - depends on the optional extra
        print(
            "The `datasets` library is required.\n"
            "  uv sync --extra eval   (or: uv pip install datasets)",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    for split in splits:
        try:
            data = load_dataset(hf_id, split=split)
        except Exception as exc:
            print(f"  ! split {split!r} unavailable: {type(exc).__name__}", file=sys.stderr)
            continue
        yield from (dict(row) for row in data)


def download(name: str, *, force: bool = False) -> Path:
    registry = load_registry()
    entry = registry.get(name)
    if entry is None:
        raise SystemExit(f"{name!r} is not in the registry; add it before use.")
    if entry.local:
        raise SystemExit(f"{name!r} is authored in-repo; nothing to download.")
    if not entry.usable:
        raise SystemExit(
            f"{name!r} REFUSED: licence {entry.licence!r} "
            f"(commercial_use={entry.commercial_use!r}) does not permit use here."
        )
    if entry.gated:
        raise SystemExit(
            f"{name!r} is gated upstream and needs an authenticated token, so it cannot be "
            "fetched by a reproducible unauthenticated script. See the registry notes."
        )
    if name not in SOURCES:
        raise SystemExit(f"{name!r} has a registry entry but no normaliser in this script.")

    spec = SOURCES[name]
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    destination = RAW_DIR / f"{name}.jsonl"
    if destination.exists() and not force:
        print(f"{name}: already present at {destination} (use --force to refetch)")
        return destination

    print(f"{name}: fetching {spec['hf_id']} …")
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for record in _records(spec["hf_id"], spec["splits"]):
        mapped = spec["map"](record)
        if mapped is None:
            continue
        text, category = mapped
        text = " ".join(text.split())
        if not text or len(text) > 20_000:
            continue
        key = hashlib.sha256(text.casefold().encode()).hexdigest()[:32]
        if key in seen:
            # Upstream duplicates would inflate whichever class they belong to.
            continue
        seen.add(key)
        rows.append(
            {
                "sample_id": f"{name}-{hashlib.sha256(text.encode()).hexdigest()[:16]}",
                "text": text,
                "category": category,
                "source": name,
                "language": "en",
                "difficulty": "unknown",
            }
        )
        if spec["cap"] and len(rows) >= spec["cap"]:
            break

    destination.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8"
    )
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()[:32]
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["category"]] = counts.get(row["category"], 0) + 1
    print(f"  wrote {len(rows)} samples → {destination}")
    print(f"  categories: {counts}")
    print(f"  sha256: {digest}")
    print(f"  licence: {entry.licence} | commercial_use: {entry.commercial_use}")
    print(f"  contamination risk: {entry.contamination_risk}")
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch registered benchmark datasets")
    parser.add_argument("names", nargs="*", help="registry names to fetch")
    parser.add_argument("--all", action="store_true", help="fetch every fetchable dataset")
    parser.add_argument("--list", action="store_true", help="show the registry")
    parser.add_argument("--force", action="store_true", help="refetch even if present")
    args = parser.parse_args(argv)

    registry = load_registry()

    if args.list:
        for name, entry in sorted(registry.items()):
            state = (
                "local"
                if entry.local
                else "GATED"
                if entry.gated
                else "REFUSED (licence)"
                if not entry.usable
                else "fetchable"
                if name in SOURCES
                else "no normaliser"
            )
            print(f"  {name:<28} {entry.licence:<14} {state}")
        return 0

    names = (
        [
            n
            for n, e in registry.items()
            if not e.local and e.usable and not e.gated and n in SOURCES
        ]
        if args.all
        else args.names
    )
    if not names:
        parser.error("give dataset names, or --all, or --list")

    for name in names:
        download(name, force=args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
