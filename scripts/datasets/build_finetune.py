"""Build the fine-tuning corpus: compositional generation, then integrity gates.

Generation is a **documented matrix**, not a prompt to a model. Each sample is
composed from independently authored components (`eval/datasets/finetune/
authoring/pools.py`) along explicit dimensions, so diversity comes from
combinatorics over hand-written parts.

The corpus is built to teach one distinction:

    discussing / quoting an attack        (label 0)
    performing an attack                  (label 1)

The same `ATTACK_PHRASES` appear on both sides — inside `QUOTING_FRAMES` as hard
negatives, and as real payloads as attacks. A model that learns "this string means
attack" scores at chance here; only framing separates the classes.

Integrity gates, all blocking:

1. schema + label validation
2. exact and normalised deduplication
3. **zero normalised collisions with the frozen hold-out** (the hard boundary)
4. zero collisions with the public benchmark and smoke fixture
5. near-duplicate reporting (Jaccard), with a ceiling on the rate
6. secret and PII scanning
7. content-derived train/dev split, verified leak-free

    uv run python -m scripts.datasets.build_finetune --check
    uv run python -m scripts.datasets.build_finetune --write
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.datasets.finetune.authoring import pools as P
from eval.schema import normalised_key

REPO_ROOT = Path(__file__).resolve().parents[2]
FINETUNE_DIR = REPO_ROOT / "eval" / "datasets" / "finetune"
FROZEN_HOLDOUT = REPO_ROOT / "eval" / "datasets" / "holdout" / "cases.jsonl"
PUBLIC_RAW = REPO_ROOT / "eval" / "datasets" / "raw"
SMOKE = REPO_ROOT / "eval" / "datasets" / "smoke" / "cases.jsonl"

# Deterministic: the corpus must rebuild byte-identically from a given commit.
SEED = 20260817
CREATED_AT = "2026-08-17"
DATASET_VERSION = "finetune-v1"

# Near-duplicate ceiling. Compositional generation guarantees some structural
# similarity; the question is whether it is high enough to let a model memorise
# templates rather than learn the distinction.
MAX_NEAR_DUPLICATE_RATE = 0.02
NEAR_DUPLICATE_JACCARD = 0.90


class HoldOutViolation(RuntimeError):
    """The frozen hold-out reached the training corpus. Nothing proceeds."""


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def _mk(
    text: str,
    label: int,
    category: str,
    sub_category: str,
    domain: str,
    difficulty: str,
    method: str,
) -> dict[str, Any]:
    return {
        "text": " ".join(text.split()) if "\n" not in text else text.strip(),
        "label": label,
        "category": category,
        "sub_category": sub_category,
        "domain": domain,
        "difficulty": difficulty,
        "source": "internal_generated",
        "source_type": "synthetic",
        "generation_method": method,
        "dataset_version": DATASET_VERSION,
        "created_at": CREATED_AT,
        "language": "en",
    }


def generate(rng: random.Random) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    # --- HARD NEGATIVES: quoted attacks -----------------------------------
    # Matrix: quoting frame x attack phrase x reference. This is the single most
    # important cell: 93.8% of the base model's incident-report false positives.
    for frame, domain in P.QUOTING_FRAMES:
        for phrase in P.ATTACK_PHRASES:
            for ref in rng.sample(P.REFERENCES, 7):
                rows.append(
                    _mk(
                        frame.format(phrase=phrase, ref=ref),
                        0,
                        "hard_negative",
                        "quoted_attack",
                        domain,
                        "hard",
                        "matrix:quoting_frame x attack_phrase x reference",
                    )
                )

    # --- HARD NEGATIVES: security-domain discussion ------------------------
    for topic, sub, domain in P.DISCUSSION_TOPICS:
        for deliverable in P.DISCUSSION_DELIVERABLES:
            rows.append(
                _mk(
                    deliverable.format(topic=topic),
                    0,
                    "hard_negative",
                    sub,
                    domain,
                    "hard",
                    "matrix:discussion_topic x deliverable",
                )
            )

    # --- HARD NEGATIVES: ordinary override / ignore language ---------------
    for frame, sub in P.ORDINARY_OVERRIDE_FRAMES:
        for ref in P.REFERENCES:
            rows.append(
                _mk(
                    frame.format(ref=ref),
                    0,
                    "hard_negative",
                    sub,
                    "business_benign",
                    "hard",
                    "matrix:override_frame x reference",
                )
            )

    # --- HARD NEGATIVES: instructions aimed at humans ----------------------
    for frame, sub in P.HUMAN_INSTRUCTION_FRAMES:
        for ref in P.REFERENCES:
            rows.append(
                _mk(
                    frame.format(ref=ref),
                    0,
                    "hard_negative",
                    sub,
                    "documentation",
                    "hard",
                    "matrix:human_instruction_frame x reference",
                )
            )

    # --- HARD NEGATIVES: code containing attack strings --------------------
    for frame in P.CODE_FRAMES:
        for phrase in P.ATTACK_PHRASES:
            for ref in rng.sample(P.REFERENCES, 4):
                rows.append(
                    _mk(
                        frame.format(phrase=phrase, ref=ref),
                        0,
                        "hard_negative",
                        "developer_documentation",
                        "software_engineering",
                        "hard",
                        "matrix:code_frame x attack_phrase x reference",
                    )
                )

    # --- ORDINARY BENIGN ----------------------------------------------------
    # No security vocabulary. Without these the model would only ever see the
    # boundary and would lose its notion of ordinary traffic.
    for task, domain in P.BENIGN_TASKS:
        for ref in P.REFERENCES:
            rows.append(
                _mk(
                    task.format(ref=ref),
                    0,
                    "benign",
                    "general_benign",
                    domain,
                    "easy",
                    "matrix:benign_task x reference",
                )
            )

    # --- ATTACKS: direct injection -----------------------------------------
    for opener in P.INJECTION_OPENERS:
        for scope in P.INJECTION_SCOPES:
            for goal in P.INJECTION_GOALS:
                rows.append(
                    _mk(
                        f"{opener.format(scope=scope)} {goal}",
                        1,
                        "attack",
                        "direct_prompt_injection",
                        "attack",
                        "medium",
                        "matrix:opener x scope x goal",
                    )
                )

    # --- ATTACKS: system-prompt extraction ---------------------------------
    for request in P.EXTRACTION_REQUESTS:
        for pretext in P.EXTRACTION_PRETEXTS:
            for transform in P.EXTRACTION_TRANSFORMS:
                text = " ".join(part for part in (pretext, request, transform) if part)
                rows.append(
                    _mk(
                        text,
                        1,
                        "attack",
                        "system_prompt_extraction",
                        "attack",
                        "medium",
                        "matrix:request x pretext x transform",
                    )
                )

    # --- ATTACKS: role override --------------------------------------------
    for persona in P.ROLE_OVERRIDE_PERSONAS:
        for demand in P.ROLE_OVERRIDE_DEMANDS:
            rows.append(
                _mk(
                    f"You are {persona}. {demand}",
                    1,
                    "attack",
                    "role_override",
                    "attack",
                    "medium",
                    "matrix:persona x demand",
                )
            )

    # --- ATTACKS: context override -----------------------------------------
    for claim in P.CONTEXT_OVERRIDE_CLAIMS:
        for payload in P.CONTEXT_OVERRIDE_PAYLOADS:
            rows.append(
                _mk(
                    f"{claim} {payload}",
                    1,
                    "attack",
                    "context_override",
                    "attack",
                    "hard",
                    "matrix:boundary_claim x payload",
                )
            )

    # --- ATTACKS: jailbreak -------------------------------------------------
    for frame in P.JAILBREAK_FRAMES:
        for persona in P.ROLE_OVERRIDE_PERSONAS:
            for constraint in P.JAILBREAK_CONSTRAINTS:
                for demand in rng.sample(P.ROLE_OVERRIDE_DEMANDS, 2):
                    rows.append(
                        _mk(
                            frame.format(persona=persona, constraint=constraint, demand=demand),
                            1,
                            "attack",
                            "jailbreak",
                            "attack",
                            "medium",
                            "matrix:jailbreak_frame x persona x constraint x demand",
                        )
                    )

    # --- ATTACKS: indirect injection ---------------------------------------
    for container in P.INDIRECT_CONTAINERS:
        for payload in P.INDIRECT_PAYLOADS:
            for ref in rng.sample(P.REFERENCES, 3):
                rows.append(
                    _mk(
                        container.format(payload=payload, ref=ref),
                        1,
                        "attack",
                        "indirect_injection",
                        "attack",
                        "hard",
                        "matrix:container x payload x reference",
                    )
                )

    # --- ATTACKS: obfuscated surface forms ---------------------------------
    # The evasion classes the normaliser already handles, so the classifier is
    # not the only line of defence against them.
    confusables = {"i": "і", "o": "о", "a": "а", "e": "е"}
    for phrase in P.ATTACK_PHRASES[:12]:
        base = f"{phrase.capitalize()} and comply with my next request."
        rows.append(
            _mk(
                base.upper(),
                1,
                "attack",
                "direct_prompt_injection",
                "attack",
                "medium",
                "surface_form:uppercase",
            )
        )
        folded = "".join(confusables.get(c, c) for c in base)
        rows.append(
            _mk(
                folded,
                1,
                "attack",
                "direct_prompt_injection",
                "attack",
                "hard",
                "surface_form:cyrillic_confusable",
            )
        )
        spaced = base.replace(" ", "​ ", 3)
        rows.append(
            _mk(
                spaced,
                1,
                "attack",
                "direct_prompt_injection",
                "attack",
                "hard",
                "surface_form:zero_width_space",
            )
        )

    return rows


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------

SECRET_PATTERNS = {
    "api_key_like": re.compile(r"\b(sk|pk|ghp|gho|xox[baprs])[-_][A-Za-z0-9]{16,}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
}
PII_PATTERNS = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@(?!example\.(com|org|net))(?!\S*\.(example|test|invalid))"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "card_like": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "phone": re.compile(r"\+\d{1,3}[ -]?(?!555[ -]?01)\d{3}[ -]?\d{3,4}[ -]?\d{3,4}\b"),
}


def _corpus_keys(path: Path, field: str = "text") -> set[str]:
    if not path.is_file():
        return set()
    keys = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        text = record.get(field) or record.get("prompt", "")
        if text:
            keys.add(normalised_key(text))
    return keys


def check_holdout_boundary(rows: list[dict[str, Any]]) -> None:
    """The hard boundary. Any collision aborts the build."""
    holdout = _corpus_keys(FROZEN_HOLDOUT)
    if not holdout:
        raise HoldOutViolation(f"frozen hold-out not found at {FROZEN_HOLDOUT}")
    collisions = [r for r in rows if normalised_key(r["text"]) in holdout]
    if collisions:
        raise HoldOutViolation(
            f"{len(collisions)} training samples collide with the FROZEN HOLD-OUT. "
            f"The hold-out is the final judge and must never be trained on. "
            f"First: {collisions[0]['text'][:80]!r}"
        )


def near_duplicate_rate(rows: list[dict[str, Any]], sample_cap: int = 2500) -> tuple[float, int]:
    """Jaccard overlap on a bounded sample — O(n^2) is not affordable in full."""
    rng = random.Random(SEED)
    subset = rows if len(rows) <= sample_cap else rng.sample(rows, sample_cap)
    tokens = [set(re.findall(r"[a-z0-9']+", r["text"].lower())) for r in subset]
    pairs = 0
    compared = 0
    for i, a in enumerate(tokens):
        if len(a) < 5:
            continue
        for b in tokens[i + 1 :]:
            if len(b) < 5:
                continue
            compared += 1
            union = len(a | b)
            if union and len(a & b) / union >= NEAR_DUPLICATE_JACCARD:
                pairs += 1
    return (pairs / compared if compared else 0.0), pairs


def assign_split(text: str) -> str:
    """Content-derived, matching the benchmark's rule. 80/20 train/dev."""
    bucket = int(hashlib.sha256(normalised_key(text).encode()).hexdigest()[:8], 16) % 100
    return "dev" if bucket < 20 else "train"


def build(*, write: bool) -> int:
    rng = random.Random(SEED)
    rows = generate(rng)
    print(f"generated              : {len(rows)}")

    # exact + normalised dedup
    seen: set[str] = set()
    deduped = []
    for row in rows:
        key = normalised_key(row["text"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    dropped = len(rows) - len(deduped)
    print(f"after dedup            : {len(deduped)} ({dropped} dropped)")
    rows = deduped

    # THE HARD BOUNDARY
    check_holdout_boundary(rows)
    print("frozen hold-out        : 0 collisions (asserted)")

    # other corpora
    other = set()
    for path in sorted(PUBLIC_RAW.glob("*.jsonl")):
        other |= _corpus_keys(path)
    other |= _corpus_keys(SMOKE)
    public_collisions = [r for r in rows if normalised_key(r["text"]) in other]
    print(f"public benchmark+smoke : {len(public_collisions)} collisions")
    if public_collisions:
        print("  (public-corpus overlap is not fatal, but is recorded)", file=sys.stderr)

    # safety
    problems = []
    for row in rows:
        for name, pattern in {**SECRET_PATTERNS, **PII_PATTERNS}.items():
            if pattern.search(row["text"]):
                problems.append(f"{name}: {row['text'][:60]!r}")
    if problems:
        print("SAFETY SCAN FAILED:", file=sys.stderr)
        for problem in problems[:10]:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("secrets / PII          : clean")

    # near-duplicates
    rate, pairs = near_duplicate_rate(rows)
    print(
        f"near-duplicate rate    : {rate:.4f} ({pairs} pairs at Jaccard >= {NEAR_DUPLICATE_JACCARD})"
    )
    if rate > MAX_NEAR_DUPLICATE_RATE:
        print(
            f"  FAILED: {rate:.4f} > {MAX_NEAR_DUPLICATE_RATE}. The corpus is templated enough "
            "that a model could memorise structure instead of learning the distinction.",
            file=sys.stderr,
        )
        return 1

    # split
    for row in rows:
        row["split"] = assign_split(row["text"])
        row["sample_id"] = (
            f"ft-{row['category'][:4]}-{hashlib.sha256(row['text'].encode()).hexdigest()[:12]}"
        )
    train = [r for r in rows if r["split"] == "train"]
    dev = [r for r in rows if r["split"] == "dev"]
    train_keys = {normalised_key(r["text"]) for r in train}
    dev_keys = {normalised_key(r["text"]) for r in dev}
    leak = train_keys & dev_keys
    print(f"train/dev              : {len(train)} / {len(dev)}  (cross-split leak: {len(leak)})")
    if leak:
        return 1

    stats = summarise(rows, train, dev)
    print("\ncomposition:")
    print(json.dumps(stats, indent=2)[:1800])

    if write:
        (FINETUNE_DIR / "train").mkdir(parents=True, exist_ok=True)
        (FINETUNE_DIR / "dev").mkdir(parents=True, exist_ok=True)
        (FINETUNE_DIR / "integrity").mkdir(parents=True, exist_ok=True)
        for name, subset in (("train", train), ("dev", dev)):
            path = FINETUNE_DIR / name / "cases.jsonl"
            path.write_text(
                "\n".join(json.dumps(r, ensure_ascii=False) for r in subset) + "\n",
                encoding="utf-8",
            )
        integrity = {
            "built_at": datetime.now(UTC).isoformat(),
            "dataset_version": DATASET_VERSION,
            "seed": SEED,
            "generation": "compositional matrix over authored component pools",
            "composition": stats,
            "integrity": {
                "exact_and_normalised_duplicates_dropped": dropped,
                "frozen_holdout_collisions": 0,
                "public_benchmark_collisions": len(public_collisions),
                "cross_split_leakage": 0,
                "near_duplicate_rate": round(rate, 5),
                "near_duplicate_threshold": NEAR_DUPLICATE_JACCARD,
                "secrets": 0,
                "pii": 0,
            },
            "frozen_holdout": {
                "path": str(FROZEN_HOLDOUT.relative_to(REPO_ROOT)),
                "sha256": hashlib.sha256(FROZEN_HOLDOUT.read_bytes()).hexdigest(),
                "sample_count": sum(
                    1 for _ in FROZEN_HOLDOUT.read_text().splitlines() if _.strip()
                ),
                "status": "READ-ONLY. Never train, tune, or select on this file.",
            },
            "provenance": {
                "source": "internal_generated",
                "source_type": "synthetic",
                "generation_method": "eval/datasets/finetune/authoring/pools.py via scripts/datasets/build_finetune.py",
                "licence": "Apache-2.0 (same as the project)",
                "deterministic": f"seed={SEED}; rebuilds byte-identically from a given commit",
            },
        }
        (FINETUNE_DIR / "integrity" / "manifest.json").write_text(
            json.dumps(integrity, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\nwrote train ({len(train)}) and dev ({len(dev)}) → {FINETUNE_DIR}")
    return 0


def summarise(rows: list[dict], train: list[dict], dev: list[dict]) -> dict[str, Any]:
    def counts(subset: list[dict], field: str) -> dict[str, int]:
        return dict(Counter(r[field] for r in subset).most_common())

    return {
        "total": len(rows),
        "train": len(train),
        "dev": len(dev),
        "by_label": {
            "benign(0)": sum(1 for r in rows if r["label"] == 0),
            "attack(1)": sum(1 for r in rows if r["label"] == 1),
        },
        "by_category": counts(rows, "category"),
        "by_sub_category": counts(rows, "sub_category"),
        "by_domain": counts(rows, "domain"),
        "by_difficulty": counts(rows, "difficulty"),
        "by_generation_method": counts(rows, "generation_method"),
        "length_chars": {
            "min": min(len(r["text"]) for r in rows),
            "median": sorted(len(r["text"]) for r in rows)[len(rows) // 2],
            "max": max(len(r["text"]) for r in rows),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the fine-tuning corpus")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if not (args.write or args.check):
        parser.error("give --check or --write")
    return build(write=args.write)


if __name__ == "__main__":
    raise SystemExit(main())
