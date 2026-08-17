"""Assemble the independent benign hold-out, with the checks that make it evidence.

Runs, in order:

1. **Assemble** authored batches into the canonical schema with full provenance.
2. **Safety scan** — reject any sample carrying real-looking PII or a credential.
   A hold-out that introduces secrets is worse than no hold-out.
3. **Internal dedup** by the same normalised key the benchmark integrity checker
   uses, so a duplicate cannot inflate the FPR denominator.
4. **Contamination check** against every other corpus in the benchmark — exact
   and normalised. A "hold-out" sharing text with the training data is not one.
5. **Near-duplicate report** by token overlap, reported for an explicit decision
   rather than silently dropped.

    uv run python -m scripts.datasets.build_holdout --check
    uv run python -m scripts.datasets.build_holdout --write
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.schema import normalised_key

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT = REPO_ROOT / "eval" / "datasets" / "holdout" / "cases.jsonl"
CREATED_AT = "2026-08-17"

# Patterns that must not appear in an authored corpus. Synthetic placeholders are
# permitted and are checked for explicitly.
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "api_key_like": re.compile(r"\b(sk|pk|ghp|gho|xox[baprs])[-_][A-Za-z0-9]{16,}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
    "password_assignment": re.compile(r"\b(password|passwd|secret)\s*[=:]\s*\S{6,}", re.I),
}
# Real-looking PII. Reserved-for-documentation values are permitted and are
# enumerated here rather than waved through case by case.
#
#   RFC 2606 reserves .example/.test/.invalid/.localhost and example.com/org/net
#   RFC 3330 / ITU reserve the 555-01xx telephone range
#   A Luhn-INVALID digit run cannot be a real payment card
RESERVED_TLD = r"(?!example\.(com|org|net)\b)(?!\S*\.(example|test|invalid|localhost)\b)"
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(rf"\b[A-Za-z0-9._%+-]+@{RESERVED_TLD}[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}\b"),
    "phone_e164": re.compile(r"\+\d{1,3}[ -]?(?!555[ -]?01)\d{3}[ -]?\d{3,4}[ -]?\d{3,4}\b"),
    "card_like": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}

# The single documented test card, safe to include anywhere.
TEST_CARD = "4111111111111111"


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _is_real_card_risk(candidate: str) -> bool:
    """A digit run is a card risk only if it could actually be one.

    Luhn-invalid runs cannot be payment cards, and the universal test card is
    documented for exactly this purpose. Everything else is treated as a risk.
    """
    digits = re.sub(r"\D", "", candidate)
    if not 13 <= len(digits) <= 19:
        return False
    if digits == TEST_CARD:
        return False
    return _luhn_valid(digits)


def _load_batches() -> list[dict[str, Any]]:
    from scripts.datasets.authoring.batch_hard_negatives import HARD_NEGATIVES
    from scripts.datasets.authoring.batch_hard_negatives_2 import (
        EXTRACTION_ATTACKS,
        HARD_NEGATIVES_2,
    )
    from scripts.datasets.authoring.batch_ordinary import ORDINARY
    from scripts.datasets.authoring.batch_varied import VARIED

    rows: list[dict[str, Any]] = []

    def add(
        batch: list[tuple[str, str, str, str]],
        *,
        category: str,
        prefix: str,
        hard_negative: bool = False,
    ) -> None:
        for index, (text, sub_category, domain, difficulty) in enumerate(batch, 1):
            rows.append(
                {
                    "sample_id": f"holdout2-{prefix}-{index:04d}",
                    "text": text,
                    "category": category,
                    "sub_category": sub_category,
                    "domain": domain,
                    "difficulty": difficulty,
                    "source": "internal_authored",
                    "source_type": "authored",
                    "language": "en",
                    "created_at": CREATED_AT,
                    "notes": "hard_negative" if hard_negative else None,
                }
            )

    add(ORDINARY, category="benign", prefix="ord")
    add(VARIED, category="benign", prefix="var")
    add(HARD_NEGATIVES, category="benign", prefix="hn1", hard_negative=True)
    add(HARD_NEGATIVES_2, category="benign", prefix="hn2", hard_negative=True)
    add(EXTRACTION_ATTACKS, category="system_prompt_extraction", prefix="ext")
    return rows


def _carry_forward_v1() -> list[dict[str, Any]]:
    """Keep the original 66-case hold-out.

    Retained rather than replaced so the before/after comparison in §20 uses the
    *same* samples that produced the first result, and so the attack coverage
    (direct/indirect injection, jailbreak, PII) is not lost.
    """
    path = OUTPUT
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record["sample_id"].startswith("holdout2-"):
            continue  # a previous run of this script; rebuilt below
        record.setdefault("source_type", "authored")
        record.setdefault("created_at", "2026-08-17")
        record.setdefault("domain", "mixed")
        record.setdefault("sub_category", "v1_original")
        record["notes"] = record.get("notes") or "holdout_v1"
        rows.append(record)
    return rows


def safety_scan(rows: list[dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    for row in rows:
        text = row["text"]
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                problems.append(f"{row['sample_id']}: possible secret ({name})")
        for name, pattern in PII_PATTERNS.items():
            if row["category"] == "pii":
                continue  # the PII attack samples use documented synthetic values
            match = pattern.search(text)
            if not match:
                continue
            if name == "card_like" and not _is_real_card_risk(match.group(0)):
                continue
            problems.append(
                f"{row['sample_id']}: possible real PII ({name}): {match.group(0)[:24]!r}"
            )
    return problems


def internal_dedup(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    seen: set[str] = set()
    kept: list[dict[str, Any]] = []
    dropped = 0
    for row in rows:
        key = normalised_key(row["text"])
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        kept.append(row)
    return kept, dropped


def contamination_check(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare against every other corpus used anywhere in the project."""
    from eval.loaders.base import RAW_DIR

    ours = {normalised_key(row["text"]): row["sample_id"] for row in rows}
    collisions: list[dict[str, str]] = []
    corpora_checked: list[str] = []

    for path in sorted(RAW_DIR.glob("*.jsonl")):
        corpora_checked.append(path.stem)
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            other = json.loads(line)
            key = normalised_key(other["text"])
            if key in ours:
                collisions.append(
                    {"holdout_id": ours[key], "corpus": path.stem, "text": other["text"][:60]}
                )

    smoke = REPO_ROOT / "eval" / "datasets" / "smoke" / "cases.jsonl"
    if smoke.is_file():
        corpora_checked.append("smoke")
        for line in smoke.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            other = json.loads(line)
            key = normalised_key(other.get("text") or other.get("prompt", ""))
            if key in ours:
                collisions.append(
                    {"holdout_id": ours[key], "corpus": "smoke", "text": str(other)[:60]}
                )

    return {"corpora_checked": corpora_checked, "collisions": collisions}


def near_duplicate_report(
    rows: list[dict[str, Any]], threshold: float = 0.85
) -> list[dict[str, Any]]:
    """Token-level Jaccard overlap within the hold-out.

    Reported, not auto-dropped: two prompts about the same topic are not
    necessarily the same case, and the decision belongs to a human.
    """
    tokens = [
        (row["sample_id"], set(re.findall(r"[a-z0-9']+", row["text"].lower()))) for row in rows
    ]
    pairs: list[dict[str, Any]] = []
    for i, (id_a, a) in enumerate(tokens):
        if len(a) < 5:
            continue
        for id_b, b in tokens[i + 1 :]:
            if len(b) < 5:
                continue
            union = len(a | b)
            if not union:
                continue
            similarity = len(a & b) / union
            if similarity >= threshold:
                pairs.append({"a": id_a, "b": id_b, "jaccard": round(similarity, 3)})
    return pairs


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    benign = [r for r in rows if r["category"] == "benign"]
    hard = [r for r in benign if r.get("notes") == "hard_negative"]
    return {
        "total": len(rows),
        "benign": len(benign),
        "hard_negatives": len(hard),
        "hard_negative_share": round(len(hard) / len(benign), 3) if benign else 0.0,
        "by_category": dict(Counter(r["category"] for r in rows)),
        "by_domain": dict(Counter(r.get("domain", "?") for r in benign).most_common()),
        "by_difficulty": dict(Counter(r["difficulty"] for r in benign)),
        "by_source_type": dict(Counter(r.get("source_type", "?") for r in rows)),
        "by_sub_category_top": dict(
            Counter(r.get("sub_category", "?") for r in hard).most_common(12)
        ),
        "length_chars": {
            "min": min(len(r["text"]) for r in rows),
            "median": sorted(len(r["text"]) for r in rows)[len(rows) // 2],
            "max": max(len(r["text"]) for r in rows),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the independent benign hold-out")
    parser.add_argument("--write", action="store_true", help="write cases.jsonl")
    parser.add_argument("--check", action="store_true", help="run checks without writing")
    args = parser.parse_args(argv)
    if not (args.write or args.check):
        parser.error("give --write or --check")

    rows = _carry_forward_v1() + _load_batches()

    problems = safety_scan(rows)
    if problems:
        print("SAFETY SCAN FAILED:", file=sys.stderr)
        for problem in problems[:20]:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"safety scan       : clean ({len(rows)} samples)")

    rows, internal_dropped = internal_dedup(rows)
    print(f"internal dedup    : {internal_dropped} dropped, {len(rows)} kept")

    contamination = contamination_check(rows)
    print(
        f"contamination     : checked {len(contamination['corpora_checked'])} corpora "
        f"({', '.join(contamination['corpora_checked'])})"
    )
    if contamination["collisions"]:
        print(f"  COLLISIONS: {len(contamination['collisions'])}", file=sys.stderr)
        for collision in contamination["collisions"][:10]:
            print(f"    {collision}", file=sys.stderr)
        return 1
    print("  0 exact/normalised collisions with any other corpus")

    near = near_duplicate_report(rows)
    print(f"near-duplicates   : {len(near)} pairs at Jaccard >= 0.85")
    for pair in near[:10]:
        print(f"    {pair}")

    stats = summarise(rows)
    print("\ncomposition:")
    print(json.dumps(stats, indent=2))

    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
            encoding="utf-8",
        )
        manifest = OUTPUT.parent / "build_manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "built_at": datetime.now(UTC).isoformat(),
                    "created_at": CREATED_AT,
                    "composition": stats,
                    "internal_duplicates_dropped": internal_dropped,
                    "contamination": {
                        "corpora_checked": contamination["corpora_checked"],
                        "collisions": len(contamination["collisions"]),
                    },
                    "near_duplicate_pairs_above_0.85": len(near),
                    "provenance": {
                        "source_type": "authored",
                        "source": "internal_authored",
                        "generation_method": (
                            "hand-authored by the project author in "
                            "scripts/datasets/authoring/, never published elsewhere"
                        ),
                        "licence": "Apache-2.0 (same as the project)",
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {len(rows)} samples → {OUTPUT}")
        print(f"wrote build manifest  → {manifest}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
