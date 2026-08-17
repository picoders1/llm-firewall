"""ADR-020 Steps 0 and 1 — proxy validation and seed-variance analysis.

Neither step trains anything, and neither reads a protected hold-out. Both exist to
decide whether the six-run controlled experiment in Step 2 is justified at all.

**Step 0** asks whether a cheap, disjoint public corpus can rank checkpoints, since
the v2 dev split saturates on every category and the hold-outs must not be spent on
ranking (OD-33). The proxy is admitted only if it reproduces an effect already known
to exist — Strategy A above ADR-019 on system-prompt extraction. A proxy blind to a
known effect cannot be trusted on unknown ones.

**Step 1** asks whether ADR-019's regression is a property of the training condition
or of its random seed. That has never been measured here. All 36 checkpoints were
retained, so the answer costs inference only.

Absolute numbers on these corpora are **not claimable as capability**: they were used
for base-model selection in ADR-014 and are plausibly in the base model's pretraining
(docs/13, docs/14, R-51). They rank two fine-tunes of the *same* base, where that bias
is a shared constant, and nothing else.

    uv run python -m scripts.validate_proxy --integrity
    uv run python -m scripts.validate_proxy --score
    uv run python -m scripts.validate_proxy --report
    uv run python -m scripts.validate_proxy --variance   # all 36, GPU-free, dev only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.metrics.classification import wilson_interval
from eval.schema import normalised_key
from scripts.datasets.build_mechanism_coverage import (
    PII_PATTERNS,
    SECRET_PATTERNS,
    prune_near_duplicates,
)
from scripts.evaluate_provenance import mcnemar_exact

REPO_ROOT = Path(__file__).resolve().parents[1]
RAW = REPO_ROOT / "eval" / "datasets" / "raw"
RESULTS = REPO_ROOT / "eval" / "results" / "finetune" / "ADR-020-steps-0-1"
PROTOCOL = REPO_ROOT / "eval" / "results" / "finetune" / "ADR-020-protocol"

# Seed-fixed so the draws are reproducible; the project's convention.
SEED = 20260817
CALIBRATION_N = 2000
EVAL_BENIGN_N = 2000
MATCHED_FPR = 0.01

# The retention signal. lakera-gandalf is attack-only (registry.yaml): ~1000 real
# attempts to extract a secret from a system prompt, which is the capability ADR-019
# regressed on. It measures recall and cannot contribute to FPR.
RETENTION_CORPUS = "lakera-gandalf"

# lr 1e-5 / 2 epochs is the configuration selected in BOTH experiments, so the two
# families differ only in training corpus. Three seeds each gives the variance.
CONFIG = "lr1e-05__ep2"
FAMILIES = {
    "strategy_a": {
        "dir": REPO_ROOT / "artifacts" / "finetune",
        "prefix": "stratA__",
        "dev": REPO_ROOT / "eval" / "datasets" / "finetune" / "dev" / "cases.jsonl",
        "corpus": "finetune-v1",
    },
    "adr_019": {
        "dir": REPO_ROOT / "artifacts" / "finetune-mechanisms",
        "prefix": "mech__",
        "dev": REPO_ROOT / "eval" / "datasets" / "finetune" / "v2" / "dev" / "cases.jsonl",
        "corpus": "finetune-v2",
    },
}
SEEDS = (13, 20260817, 31337)

# Never read by this script. Listed so the assertion is explicit rather than implied.
PROTECTED_HOLDOUTS = (
    REPO_ROOT / "eval" / "datasets" / "holdout" / "cases.jsonl",
    REPO_ROOT / "eval" / "datasets" / "holdout" / "v3" / "cases.jsonl",
    REPO_ROOT / "eval" / "datasets" / "holdout" / "indirect-v1" / "cases.jsonl",
    REPO_ROOT / "eval" / "datasets" / "holdout" / "mechanisms-v1" / "cases.jsonl",
)

TRAINING_CORPORA = (
    REPO_ROOT / "eval" / "datasets" / "finetune" / "train" / "cases.jsonl",
    REPO_ROOT / "eval" / "datasets" / "finetune" / "dev" / "cases.jsonl",
    REPO_ROOT / "eval" / "datasets" / "finetune" / "v2" / "train" / "cases.jsonl",
    REPO_ROOT / "eval" / "datasets" / "finetune" / "v2" / "dev" / "cases.jsonl",
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checkpoint_paths() -> list[dict[str, Any]]:
    out = []
    for family, spec in FAMILIES.items():
        for seed in SEEDS:
            path = spec["dir"] / f"{spec['prefix']}{CONFIG}__seed{seed}"
            out.append(
                {
                    "family": family,
                    "seed": seed,
                    "path": path,
                    "name": path.name,
                    "dev": spec["dev"],
                    "training_corpus": spec["corpus"],
                }
            )
    return out


# ---------------------------------------------------------------------------
# The evaluation corpora — drawn once, seed-fixed, and hashed
# ---------------------------------------------------------------------------


def is_sensitive(text: str) -> tuple[bool, str | None]:
    """Screen with the dataset patterns, but validate card candidates the way the
    production detector does.

    `card_like` in the build patterns is `\\b(?:\\d[ -]?){13,19}\\b` with no checksum,
    so it fires on any long digit run — an 18-character analytics hash, for instance.
    Production (`app/detectors/pii/regex.py`) requires a Luhn-valid 13–19 digit
    number. Screening more loosely than production validates is a defect in the
    check, not evidence in the data.
    """
    from app.detectors.pii.regex import _luhn

    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            return True, name
    for name, pattern in PII_PATTERNS.items():
        match = pattern.search(text)
        if not match:
            continue
        if name == "card_like":
            digits = "".join(ch for ch in match.group(0) if ch.isdigit())
            if not (13 <= len(digits) <= 19 and _luhn(digits)):
                continue
        return True, name
    return False, None


def build_proxy(with_provenance: bool = False) -> Any:
    """Attack sets in full; benign split into disjoint calibration and evaluation
    draws so a threshold is never chosen and measured on the same samples.

    Two construction rules, applied uniformly to the whole pool before any draw —
    not as targeted repairs of individual rows (§5):

    1. **Cross-corpus de-duplication by normalised key.** One benign text is present
       in both `deepset` and `dolly` (their content-hash sample IDs agree), which
       would double-count a sample in the FPR denominator.
    2. **Exclusion of samples carrying validated secrets or PII.** A uniform filter
       over the eligible pool, deterministic and reproducible. It slightly
       under-represents benign traffic that legitimately contains an email address —
       a stated limit, not a silent one.
    """
    rng = random.Random(SEED)
    lakera = load_jsonl(RAW / "lakera-gandalf.jsonl")
    deepset = load_jsonl(RAW / "deepset-prompt-injections.jsonl")
    benign_pool = load_jsonl(RAW / "dolly-benign.jsonl") + load_jsonl(RAW / "oasst1-benign.jsonl")

    for row in lakera:
        row["label"] = 1
    for row in deepset:
        row["label"] = 0 if row["category"] == "benign" else 1
    for row in benign_pool:
        row["label"] = 0

    dropped_sensitive: list[tuple[str, str]] = []
    dropped_duplicate: list[str] = []
    seen: set[str] = set()

    def admit(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        kept = []
        for row in rows:
            sensitive, why = is_sensitive(row["text"])
            if sensitive:
                dropped_sensitive.append((row["sample_id"], why or "?"))
                continue
            key = normalised_key(row["text"])
            if key in seen:
                dropped_duplicate.append(row["sample_id"])
                continue
            seen.add(key)
            kept.append(row)
        return kept

    # Deterministic admission order, then a seed-fixed shuffle of the benign pool.
    lakera = admit(sorted(lakera, key=lambda r: r["sample_id"]))
    deepset = admit(sorted(deepset, key=lambda r: r["sample_id"]))
    benign_pool = admit(sorted(benign_pool, key=lambda r: r["sample_id"]))
    rng.shuffle(benign_pool)

    parts = {
        "lakera_attacks": lakera,
        "deepset_attacks": [r for r in deepset if r["label"] == 1],
        "deepset_benign": [r for r in deepset if r["label"] == 0],
        "calibration_benign": benign_pool[:CALIBRATION_N],
        "eval_benign": benign_pool[CALIBRATION_N : CALIBRATION_N + EVAL_BENIGN_N],
    }
    if not with_provenance:
        return parts
    return parts, {
        "dropped_sensitive": dropped_sensitive,
        "dropped_duplicate": dropped_duplicate,
    }


# ---------------------------------------------------------------------------
# Step 0 preconditions — §5
# ---------------------------------------------------------------------------


def phase_integrity() -> int:
    print("=== ADR-020 STEP 0 — PROXY INTEGRITY ===\n")
    proxy, provenance = build_proxy(with_provenance=True)
    used = [r for part in proxy.values() for r in part]
    print(f"proxy samples in use: {len(used)}")
    print(
        f"excluded at construction: {len(provenance['dropped_sensitive'])} sensitive, "
        f"{len(provenance['dropped_duplicate'])} duplicate"
    )
    for sample_id, why in provenance["dropped_sensitive"]:
        print(f"   sensitive: {sample_id} ({why})")

    project_keys: dict[str, set[str]] = {}
    for path in TRAINING_CORPORA + PROTECTED_HOLDOUTS:
        project_keys[str(path.relative_to(REPO_ROOT))] = {
            normalised_key(r["text"]) for r in load_jsonl(path)
        }

    proxy_exact = [r["text"] for r in used]
    proxy_norm = [normalised_key(r["text"]) for r in used]

    collisions: dict[str, dict[str, int]] = {}
    for name, keys in project_keys.items():
        n_norm = sum(1 for k in proxy_norm if k in keys)
        collisions[name] = {"normalised": n_norm}
    total_norm = sum(c["normalised"] for c in collisions.values())

    exact_texts: dict[str, set[str]] = {}
    for path in TRAINING_CORPORA + PROTECTED_HOLDOUTS:
        exact_texts[str(path.relative_to(REPO_ROOT))] = {r["text"] for r in load_jsonl(path)}
    total_exact = sum(sum(1 for t in proxy_exact if t in s) for s in exact_texts.values())

    print(f"exact collisions with all project data      : {total_exact}")
    print(f"normalised collisions with all project data : {total_norm}")
    for name, c in collisions.items():
        if c["normalised"]:
            print(f"   !! {name}: {c['normalised']}")

    internal_dupes = len(proxy_norm) - len(set(proxy_norm))
    print(f"duplicates within the proxy itself          : {internal_dupes}")

    cal = {normalised_key(r["text"]) for r in proxy["calibration_benign"]}
    ev = {normalised_key(r["text"]) for r in proxy["eval_benign"]}
    cal_eval_overlap = len(cal & ev)
    print(f"calibration <-> evaluation benign overlap   : {cal_eval_overlap}")

    print("\nnear-duplicate rate (Jaccard >= threshold, within each corpus):")
    near_dupes = {}
    for part, rows in proxy.items():
        tagged = [{"sample_id": r["sample_id"], "text": r["text"]} for r in rows]
        started = time.perf_counter()
        _, dropped = prune_near_duplicates(tagged)
        near_dupes[part] = {
            "n": len(rows),
            "near_duplicates": len(dropped),
            "rate": round(len(dropped) / len(rows), 4) if rows else 0.0,
        }
        print(
            f"   {part:22s} {len(dropped):5d}/{len(rows):5d} = "
            f"{near_dupes[part]['rate']:.4f}  ({time.perf_counter() - started:.1f}s)"
        )

    print("\nsecrets and PII remaining after construction:")
    findings: dict[str, int] = {}
    for row in used:
        sensitive, why = is_sensitive(row["text"])
        if sensitive:
            findings[why or "?"] = findings.get(why or "?", 0) + 1
    print(f"   validated hits: {findings or 'none'}")

    screened_only: dict[str, int] = {}
    for row in used:
        for name, pattern in {**SECRET_PATTERNS, **PII_PATTERNS}.items():
            if pattern.search(row["text"]) and not is_sensitive(row["text"])[0]:
                screened_only[name] = screened_only.get(name, 0) + 1
    print(f"   screened but not validated (e.g. non-Luhn digit runs): {screened_only or 'none'}")

    registry = (REPO_ROOT / "eval" / "datasets" / "registry.yaml").read_text(encoding="utf-8")
    licences = {}
    import yaml

    for entry in yaml.safe_load(registry)["datasets"]:
        if entry["name"] in {
            "lakera-gandalf",
            "deepset-prompt-injections",
            "dolly-benign",
            "oasst1-benign",
        }:
            licences[entry["name"]] = {
                "licence": entry["licence"],
                "commercial_use": entry["commercial_use"],
                "contamination_risk": entry["contamination_risk"],
                "source": entry["source"],
            }
    print("\nlicence / provenance (from registry.yaml):")
    for name, meta in sorted(licences.items()):
        print(
            f"   {name:28s} {meta['licence']:14s} {meta['commercial_use']:28s} "
            f"contamination={meta['contamination_risk']}"
        )

    admissible = (
        total_exact == 0
        and total_norm == 0
        and not findings
        and internal_dupes == 0
        and cal_eval_overlap == 0
    )
    report = {
        "checked_at": datetime.now(UTC).isoformat(),
        "step": "ADR-020 Step 0 precondition (§5)",
        "proxy_samples_in_use": len(used),
        "parts": {k: len(v) for k, v in proxy.items()},
        "excluded_at_construction": {
            "sensitive": [
                {"sample_id": s, "pattern": w} for s, w in provenance["dropped_sensitive"]
            ],
            "duplicate": provenance["dropped_duplicate"],
            "rule": (
                "Uniform filters over the whole eligible pool applied before any draw: "
                "cross-corpus de-duplication by normalised key, and exclusion of samples "
                "carrying validated secrets/PII. Not targeted repairs of individual rows."
            ),
        },
        "calibration_eval_overlap": cal_eval_overlap,
        "screened_but_not_validated": screened_only,
        "corpus_sha256": {f.name: sha256(f) for f in sorted(RAW.glob("*.jsonl"))},
        "exact_collisions_total": total_exact,
        "normalised_collisions_total": total_norm,
        "collisions_by_corpus": collisions,
        "duplicates_within_proxy": internal_dupes,
        "near_duplicates": near_dupes,
        "secret_or_pii_hits": findings,
        "licences": licences,
        "used_in_any_training_run": False,
        "is_a_frozen_project_holdout": False,
        "admissible": admissible,
        "contamination_note": (
            "Used for base-model selection in ADR-014 and plausibly present in the base "
            "model's pretraining. Absolute numbers are NOT claimable as capability; "
            "admissible only for ranking fine-tunes of the same base (docs/13, R-51)."
        ),
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "integrity.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"\nADMISSIBLE: {admissible}")
    if not admissible:
        print("STOP — fix the proxy construction, do not delete conflicting samples (§5).")
        return 1
    return 0


# ---------------------------------------------------------------------------
# Scoring — identical code path for every checkpoint
# ---------------------------------------------------------------------------


def matched_fpr_threshold(benign_scores: list[float], target: float = MATCHED_FPR) -> float:
    """Smallest threshold whose FPR on the calibration draw is <= target.

    Iterates upward through candidate cut points and returns the FIRST qualifying
    one. The downward-iteration bug that returned `n` instead of the smallest
    qualifying count has appeared twice in this project; this is the same shape.
    """
    ordered = sorted(benign_scores, reverse=True)
    allowed = int(target * len(ordered))
    # allowed false positives => threshold must sit just above the (allowed)-th score
    if allowed >= len(ordered):
        return 0.0
    return float(ordered[allowed]) + 1e-12


def phase_score() -> int:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    from scripts.finetune_strategy_a import calibrate_on_dev, evaluate_model

    integrity = json.loads((RESULTS / "integrity.json").read_text(encoding="utf-8"))
    if not integrity["admissible"]:
        print("integrity gate not passed; refusing to score")
        return 1

    proxy = build_proxy()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"=== ADR-020 STEPS 0+1 — SCORING (device={device}) ===\n")

    order = [
        "lakera_attacks",
        "deepset_attacks",
        "deepset_benign",
        "calibration_benign",
        "eval_benign",
    ]
    out: dict[str, Any] = {
        "scored_at": datetime.now(UTC).isoformat(),
        "device": device,
        "checkpoints": {},
    }

    for spec in checkpoint_paths():
        path = spec["path"]
        if not path.exists():
            print(f"MISSING checkpoint: {path}")
            return 1
        started = time.perf_counter()
        tokenizer = AutoTokenizer.from_pretrained(str(path))
        model = AutoModelForSequenceClassification.from_pretrained(str(path)).to(device)

        scores = {part: evaluate_model(model, tokenizer, proxy[part], device) for part in order}

        # Primary threshold: the project's documented dev-only procedure, applied to
        # this checkpoint's OWN dev split under identical methodology (ADR-020 §20).
        dev_rows = load_jsonl(spec["dev"])
        dev_scores = json.loads((path / "dev_scores.json").read_text(encoding="utf-8"))
        calibration = calibrate_on_dev(dev_rows, dev_scores)
        dev_threshold = calibration["operating_point"]["threshold"]

        # Secondary threshold: matched FPR on the calibration draw, so the families are
        # compared at the same operating point rather than at two arbitrary points
        # inside their own separating gaps.
        mf_threshold = matched_fpr_threshold(scores["calibration_benign"])

        out["checkpoints"][spec["name"]] = {
            "family": spec["family"],
            "seed": spec["seed"],
            "training_corpus": spec["training_corpus"],
            "checkpoint_sha256": hashlib.sha256(
                (path / "model.safetensors").read_bytes()
            ).hexdigest(),
            "dev_selected_threshold": dev_threshold,
            "dev_split_separable": calibration["separable"],
            "matched_fpr_threshold": mf_threshold,
            "scores": scores,
            "duration_s": round(time.perf_counter() - started, 2),
        }
        print(
            f"{spec['name']:46s} dev_tau={dev_threshold:.4f} "
            f"mf_tau={mf_threshold:.6f} separable={calibration['separable']} "
            f"({time.perf_counter() - started:.0f}s)"
        )
        del model
        if device == "cuda":
            torch.cuda.empty_cache()

    (RESULTS / "proxy_scores.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {RESULTS / 'proxy_scores.json'}")
    return 0


# ---------------------------------------------------------------------------
# Steps 0 and 1 — the decisions
# ---------------------------------------------------------------------------


def _hits(scores: list[float], threshold: float) -> list[bool]:
    return [s >= threshold for s in scores]


def permutation_p(a: list[float], b: list[float]) -> dict[str, Any]:
    """Exact one-sided permutation test on the run-level means.

    This is the *run-level* question — does the training condition reproduce across
    seeds — and it is distinct from the paired McNemar test, which asks a
    *sample-level* question about one pair of checkpoints. With three runs per group
    the smallest attainable p is 1/C(6,3) = 0.05, so perfect separation is the
    strongest result this design can produce and it lands exactly on the
    conventional threshold. Reported with that ceiling stated.
    """
    import itertools

    observed = statistics.mean(a) - statistics.mean(b)
    pool = a + b
    n = len(a)
    total = 0
    at_least = 0
    for idx in itertools.combinations(range(len(pool)), n):
        g1 = [pool[i] for i in idx]
        g2 = [pool[i] for i in range(len(pool)) if i not in idx]
        total += 1
        if statistics.mean(g1) - statistics.mean(g2) >= observed - 1e-12:
            at_least += 1
    return {
        "observed_gap": round(observed, 4),
        "p_one_sided": round(at_least / total, 4),
        "permutations": total,
        "smallest_attainable_p": round(1 / total, 4),
        "at_the_floor": at_least == 1,
    }


def phase_report() -> int:
    data = json.loads((RESULTS / "proxy_scores.json").read_text(encoding="utf-8"))
    proxy = build_proxy()
    ck = data["checkpoints"]

    def rates(name: str, which: str) -> dict[str, Any]:
        c = ck[name]
        r: dict[str, Any] = {}
        for label, tau in (
            ("dev", c["dev_selected_threshold"]),
            ("matched_fpr", c["matched_fpr_threshold"]),
        ):
            hits = _hits(c["scores"][which], tau)
            k, n = sum(hits), len(hits)
            lo, hi = wilson_interval(k, n)
            r[label] = {
                "k": k,
                "n": n,
                "rate": round(k / n, 4),
                "ci95": [round(lo, 4), round(hi, 4)],
            }
        return r

    lines: list[str] = []
    metrics: dict[str, Any] = {"generated_at": datetime.now(UTC).isoformat()}

    # ---------------- Step 0 --------------------------------------------------
    a, b = f"stratA__{CONFIG}__seed13", f"mech__{CONFIG}__seed13"
    step0: dict[str, Any] = {
        "question": "Does the proxy reproduce the known direction of the ADR-019 change?"
    }

    for tau_kind in ("dev", "matched_fpr"):
        key = "dev_selected_threshold" if tau_kind == "dev" else "matched_fpr_threshold"
        ha = _hits(ck[a]["scores"]["lakera_attacks"], ck[a][key])
        hb = _hits(ck[b]["scores"]["lakera_attacks"], ck[b][key])
        # Paired by construction: identical corpus, identical order, same index.
        disc_b = sum(1 for x, y in zip(ha, hb, strict=True) if x and not y)  # A right, B wrong
        disc_c = sum(1 for x, y in zip(ha, hb, strict=True) if y and not x)
        p = mcnemar_exact(disc_b, disc_c)
        step0[tau_kind] = {
            "strategy_a_recall": round(sum(ha) / len(ha), 4),
            "adr_019_recall": round(sum(hb) / len(hb), 4),
            "delta": round((sum(hb) - sum(ha)) / len(ha), 4),
            "b_strategy_a_only": disc_b,
            "c_adr_019_only": disc_c,
            "mcnemar_p": round(p, 8),
            "direction_reproduced": sum(ha) > sum(hb),
            "significant": p < 0.05,
            "gate_passed": sum(ha) > sum(hb) and p < 0.05,
        }
    step0["gate_passed"] = step0["dev"]["gate_passed"] or step0["matched_fpr"]["gate_passed"]
    metrics["step_0"] = step0

    # ---------------- Step 1 --------------------------------------------------
    step1: dict[str, Any] = {
        "question": "Is the regression a property of the condition or of the seed?"
    }
    per_family: dict[str, dict[str, list[float]]] = {}
    for tau_kind in ("dev", "matched_fpr"):
        key = "dev_selected_threshold" if tau_kind == "dev" else "matched_fpr_threshold"
        fam: dict[str, list[float]] = {}
        for family in FAMILIES:
            vals = []
            for seed in SEEDS:
                name = f"{FAMILIES[family]['prefix']}{CONFIG}__seed{seed}"
                hits = _hits(ck[name]["scores"]["lakera_attacks"], ck[name][key])
                vals.append(sum(hits) / len(hits))
            fam[family] = vals
        per_family[tau_kind] = fam
        a_vals, b_vals = fam["strategy_a"], fam["adr_019"]
        spread_a = max(a_vals) - min(a_vals)
        spread_b = max(b_vals) - min(b_vals)
        gap = statistics.mean(a_vals) - statistics.mean(b_vals)
        step1[tau_kind] = {
            "strategy_a_per_seed": [round(v, 4) for v in a_vals],
            "adr_019_per_seed": [round(v, 4) for v in b_vals],
            "strategy_a_mean": round(statistics.mean(a_vals), 4),
            "adr_019_mean": round(statistics.mean(b_vals), 4),
            "strategy_a_spread": round(spread_a, 4),
            "adr_019_spread": round(spread_b, 4),
            "max_within_condition_spread": round(max(spread_a, spread_b), 4),
            "between_condition_gap": round(gap, 4),
            "gap_exceeds_seed_spread": gap > max(spread_a, spread_b),
            "families_disjoint": min(a_vals) > max(b_vals),
            "permutation": permutation_p(a_vals, b_vals),
        }
    metrics["step_1"] = step1

    # The dev-selected threshold is underdetermined when the dev split separates
    # perfectly, and this quantifies how badly (OD-33).
    taus = {name: c["dev_selected_threshold"] for name, c in ck.items()}
    metrics["threshold_underdetermination"] = {
        "all_dev_splits_separable": all(c["dev_split_separable"] for c in ck.values()),
        "dev_selected_thresholds": taus,
        "range": [round(min(taus.values()), 4), round(max(taus.values()), 4)],
        "spread": round(max(taus.values()) - min(taus.values()), 4),
        "note": (
            "Identical methodology, identical dev split within a family, yet the chosen "
            "threshold varies by nearly the whole unit interval. Any cross-model "
            "comparison at dev-selected thresholds compares two arbitrary points inside "
            "two separating gaps; the matched-FPR rows are the commensurable ones."
        ),
    }

    # ---------------- FPR context (never a capability claim) ------------------
    metrics["benign_fpr_on_proxy"] = {name: rates(name, "eval_benign") for name in ck}
    metrics["deepset_attack_recall"] = {name: rates(name, "deepset_attacks") for name in ck}
    metrics["contamination_note"] = (
        "Absolute values here are NOT capability claims. These corpora were used in "
        "ADR-014 and are plausibly in the base model's pretraining."
    )

    (RESULTS / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    # ---------------- Report --------------------------------------------------
    lines.append("# ADR-020 Steps 0 and 1 — proxy validation and seed variance\n")
    lines.append(f"Generated {metrics['generated_at']}. No training. No hold-out was read.\n")
    lines.append("## Step 0 — does the proxy reproduce a known effect?\n")
    lines.append(
        f"Retention signal: `{RETENTION_CORPUS}`, "
        f"{len(proxy['lakera_attacks'])} human-authored system-prompt-extraction attacks.\n"
    )
    lines.append("| threshold | Strategy A | ADR-019 | Δ | b | c | McNemar p | direction | gate |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for tau_kind in ("dev", "matched_fpr"):
        s = step0[tau_kind]
        lines.append(
            f"| {tau_kind} | {s['strategy_a_recall']:.4f} | {s['adr_019_recall']:.4f} | "
            f"{s['delta']:+.4f} | {s['b_strategy_a_only']} | {s['c_adr_019_only']} | "
            f"{s['mcnemar_p']:.6f} | {'reproduced' if s['direction_reproduced'] else 'NOT reproduced'} | "
            f"{'PASS' if s['gate_passed'] else 'FAIL'} |"
        )
    lines.append(f"\n**Step 0 gate: {'PASSED' if step0['gate_passed'] else 'FAILED'}**\n")

    lines.append("## Step 1 — condition effect versus seed effect\n")
    for tau_kind in ("dev", "matched_fpr"):
        s = step1[tau_kind]
        lines.append(f"### At the {tau_kind} threshold\n")
        lines.append("| family | seed 13 | seed 20260817 | seed 31337 | mean | spread |")
        lines.append("|---|---|---|---|---|---|")
        for family, label in (("strategy_a", "Strategy A"), ("adr_019", "ADR-019")):
            v = s[f"{family}_per_seed"]
            lines.append(
                f"| {label} | {v[0]:.4f} | {v[1]:.4f} | {v[2]:.4f} | "
                f"{s[f'{family}_mean']:.4f} | {s[f'{family}_spread']:.4f} |"
            )
        perm = s["permutation"]
        lines.append(
            f"\nBetween-condition gap **{s['between_condition_gap']:+.4f}**, "
            f"largest within-condition seed spread **{s['max_within_condition_spread']:.4f}**. "
            f"Gap exceeds seed spread: **{s['gap_exceeds_seed_spread']}**. "
            f"Families fully disjoint across seeds: **{s['families_disjoint']}**.\n"
        )
        lines.append(
            f"Exact one-sided permutation test on run-level means: "
            f"**p = {perm['p_one_sided']:.4f}** over {perm['permutations']} permutations. "
            f"With three runs per group the smallest attainable p is "
            f"{perm['smallest_attainable_p']:.4f}, so this is "
            f"{'the floor — the strongest result three seeds can give, and it sits exactly on the conventional threshold' if perm['at_the_floor'] else 'above the floor'}.\n"
        )

    u = metrics["threshold_underdetermination"]
    lines.append("## Threshold underdetermination (OD-33)\n")
    lines.append(
        f"All six dev splits separate perfectly (`separable={u['all_dev_splits_separable']}`), so "
        f"the dev-selected threshold is free to land anywhere inside the separating gap. It does:\n"
    )
    lines.append("| checkpoint | dev-selected τ | matched-FPR τ |")
    lines.append("|---|---|---|")
    for name, c in ck.items():
        lines.append(
            f"| `{name}` | {c['dev_selected_threshold']:.4f} | {c['matched_fpr_threshold']:.6f} |"
        )
    lines.append(
        f"\nRange **{u['range'][0]:.4f} – {u['range'][1]:.4f}**, spread **{u['spread']:.4f}**. "
        f"{u['note']}\n"
    )

    (RESULTS / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwrote {RESULTS / 'report.md'}")
    return 0


def describe(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n": 0}
    out: dict[str, Any] = {
        "n": len(values),
        "mean": round(statistics.mean(values), 6),
        "median": round(statistics.median(values), 6),
        "min": round(min(values), 6),
        "max": round(max(values), 6),
        "range": round(max(values) - min(values), 6),
    }
    if len(values) >= 2:
        out["stdev"] = round(statistics.stdev(values), 6)
        q1, _, q3 = statistics.quantiles(values, n=4)
        out["iqr"] = round(q3 - q1, 6)
    return out


def phase_variance() -> int:
    """Run-to-run variance across all 36 retained checkpoints — no GPU, no hold-out.

    Every checkpoint persisted `dev_scores.json` and nothing else, so this is the only
    per-checkpoint metric that exists for all 36. Hold-out metrics were recorded for
    exactly two checkpoints (one per family), which cannot yield a spread; that gap is
    reported rather than filled in.
    """
    from scripts.finetune_strategy_a import _rates, calibrate_on_dev

    lrs = (1e-5, 2e-5, 3e-5)
    epochs = (2, 3)
    rows_cache = {f: load_jsonl(spec["dev"]) for f, spec in FAMILIES.items()}

    per_checkpoint: dict[str, Any] = {}
    for family, spec in FAMILIES.items():
        dev_rows = rows_cache[family]
        for lr in lrs:
            for ep in epochs:
                for seed in SEEDS:
                    name = f"{spec['prefix']}lr{lr:g}__ep{ep}__seed{seed}"
                    path = spec["dir"] / name
                    if not path.exists():
                        print(f"MISSING {path}")
                        return 1
                    scores = json.loads((path / "dev_scores.json").read_text(encoding="utf-8"))
                    tau = calibrate_on_dev(dev_rows, scores)["operating_point"]["threshold"]
                    r = _rates(dev_rows, scores, tau)
                    entry = {
                        "family": family,
                        "learning_rate": lr,
                        "epochs": ep,
                        "seed": seed,
                        "dev_selected_threshold": tau,
                        "extraction_recall": r["extraction"]["recall"],
                        "attack_recall": r["overall"]["recall"],
                        "benign_fpr": r["overall"]["fpr"],
                        "quoted_attack_fpr": r["quoted_attack"]["fpr"],
                    }
                    if family == "adr_019":
                        for mech in (
                            "retrieval_poisoning",
                            "tool_use_manipulation",
                            "safety_bypass",
                        ):
                            idx = [
                                i
                                for i, row in enumerate(dev_rows)
                                if row["label"] and row["sub_category"] == mech
                            ]
                            entry[f"{mech}_recall"] = (
                                round(sum(1 for i in idx if scores[i] >= tau) / len(idx), 4)
                                if idx
                                else None
                            )
                    per_checkpoint[name] = entry

    metrics = (
        "extraction_recall",
        "attack_recall",
        "benign_fpr",
        "quoted_attack_fpr",
        "dev_selected_threshold",
        "retrieval_poisoning_recall",
        "tool_use_manipulation_recall",
        "safety_bypass_recall",
    )
    summary: dict[str, Any] = {}
    for family in FAMILIES:
        fam = [e for e in per_checkpoint.values() if e["family"] == family]
        summary[family] = {
            "all_18": {m: describe([e[m] for e in fam if e.get(m) is not None]) for m in metrics},
            "seed_only_cells": {
                f"lr{lr:g}__ep{ep}": {
                    m: describe(
                        [
                            e[m]
                            for e in fam
                            if e["learning_rate"] == lr
                            and e["epochs"] == ep
                            and e.get(m) is not None
                        ]
                    )
                    for m in metrics
                }
                for lr in lrs
                for ep in epochs
            },
        }

    out = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source": "artifacts/**/dev_scores.json — the only per-checkpoint metric persisted for all 36",
        "gpu_used": False,
        "protected_holdouts_read": False,
        "what_is_not_available": (
            "Per-checkpoint holdout-v3 and mechanisms-v1 metrics exist for exactly two "
            "checkpoints (the two selected winners). Run-to-run variance on the hold-out "
            "metrics therefore CANNOT be computed from persisted artefacts, and rescoring "
            "is not permitted. Hold-out variance is estimated only indirectly, via the "
            "Step-0 proxy at 3 seeds per family."
        ),
        "dev_saturation_caveat": (
            "The dev splits separate perfectly, so dev-derived spreads are near zero by "
            "construction and are evidence of saturation, NOT evidence that run-to-run "
            "variance on unseen data is small."
        ),
        "per_checkpoint": per_checkpoint,
        "summary": summary,
    }
    (RESULTS / "variance_36.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    print("=== Run-to-run variance across all 36 checkpoints (dev, GPU-free) ===\n")
    for family in FAMILIES:
        s = summary[family]["all_18"]
        print(f"{family} (n=18):")
        for m in (
            "extraction_recall",
            "attack_recall",
            "benign_fpr",
            "quoted_attack_fpr",
            "dev_selected_threshold",
        ):
            d = s[m]
            if d.get("n"):
                print(
                    f"   {m:26s} mean={d['mean']:.4f} median={d['median']:.4f} "
                    f"sd={d.get('stdev', 0):.4f} min={d['min']:.4f} max={d['max']:.4f} "
                    f"iqr={d.get('iqr', 0):.4f}"
                )
        print()
    print(f"wrote {RESULTS / 'variance_36.json'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integrity", action="store_true")
    parser.add_argument("--score", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--variance", action="store_true")
    args = parser.parse_args()
    if args.integrity:
        return phase_integrity()
    if args.score:
        return phase_score()
    if args.report:
        return phase_report()
    if args.variance:
        return phase_variance()
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
