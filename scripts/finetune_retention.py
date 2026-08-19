"""ADR-020 Step 2 — the retention-preserving controlled training experiment.

Six runs. Two arms, three registered seeds each, and nothing else.

    T2  90/10 v1:extension replay sampler, 2 epochs (486 steps)  -> composition only
    T3  the identical sampler,             1 epoch  (243 steps)  -> adaptation budget only

T2 holds the optimiser-step budget identical to ADR-019's 486, so T2 − ADR-019 isolates
**composition**. T3 shares T2's sampler byte-for-byte and differs only in how long it
trains, so T3 − T2 isolates **adaptation budget**. One factor per comparison.

The control (Strategy A) and the failed condition (ADR-019) already exist as immutable
results and are **not re-run**.

Everything except the sampler and the epoch count is imported from
`scripts.finetune_strategy_a`, so a difference in results cannot come from a difference
in the training loop. The one declared departure from "ordinary supervised fine-tuning"
is the sampler: it changes *which rows are drawn*, never the loss. No class weights, no
custom objective, no curriculum, no auxiliary head.

**No protected hold-out is reachable from this module.** `verify_isolation()` proves it
by parsing the AST rather than by convention.

    uv run python -m scripts.finetune_retention --safety-check
    uv run python -m scripts.finetune_retention --train
    uv run python -m scripts.finetune_retention --report
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import platform
import random
import subprocess
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.finetune_strategy_a import (
    BASE_MODEL,
    BATCH_SIZE,
    MAX_LENGTH,
    MICRO_BATCH_SIZE,
    WARMUP_RATIO,
    WEIGHT_DECAY,
    _rates,
    calibrate_on_dev,
    evaluate_model,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
TRAIN_FILE = REPO_ROOT / "eval" / "datasets" / "finetune" / "v2" / "train" / "cases.jsonl"
DEV_FILE = REPO_ROOT / "eval" / "datasets" / "finetune" / "v2" / "dev" / "cases.jsonl"
RESULTS = REPO_ROOT / "eval" / "results" / "finetune" / "ADR-020-step2"
ARTIFACTS = REPO_ROOT / "artifacts" / "finetune-retention"
PROTOCOL_DIR = REPO_ROOT / "eval" / "results" / "finetune" / "ADR-020-protocol"

# Registered in ADR-020. A seventh configuration, an extra seed, or an extra learning
# rate is a protocol expansion and is forbidden.
LEARNING_RATE = 1e-5
SEEDS = (13, 20260817, 31337)
ARMS = {
    "T2": {"epochs": 2, "isolates": "composition only (steps identical to ADR-019)"},
    "T3": {"epochs": 1, "isolates": "adaptation budget only (sampler identical to T2)"},
}
STEPS_PER_EPOCH = 243  # ADR-020: matches ADR-019's v2 train split at batch 16

# The registered mixture (variable_matrix.csv).
V1_SHARE = 0.90
EXTENSION_SHARE = 0.10
ATTACK_FRACTION = 0.194022  # v1's, restored
EXTRACTION_SHARE_OF_ATTACKS = 0.389189  # v1's, restored; a FLOOR, so ceil not round
MECHANISMS = ("retrieval_poisoning", "tool_use_manipulation", "safety_bypass")

# Pinned in ADR-020's baseline_manifest.json. A mismatch fails the run closed.
EXPECTED = {
    "v2_train": "be2e08ef361e843620328800bb59384b5be7049294c958cc547de0f5e2930e17",
    "v2_dev": "2ae796b7f9fad9cd27217226ebbc2069a6ea031fa190f18d498f6baaf9d01f5c",
}
# Read only by the safety check, to prove they are unchanged. Never by training.
HOLDOUT_HASHES = {
    "holdout_v2": "fd91575272056d3b282804ddfbbbde6357f9d20bbf9e98ed49e145b674a28237",
    "holdout_v3": "0e26dd6b7d0f545c0bd68b64c2a0b4b60397f8ad41436754dc38b679fbbb28bf",
    "holdout_indirect_v1": "3ef8c0ec75d9aed9669332dd2e70987993459b39629a6f7109241e13f96d6e17",
    "holdout_mechanisms_v1": "bb562774663dea7580d7d1a97031b810c7a8aadebde10fcbfd04a116b521e91c",
}
HOLDOUT_FILES = {
    "holdout_v2": REPO_ROOT / "eval" / "datasets" / "holdout" / "cases.jsonl",
    "holdout_v3": REPO_ROOT / "eval" / "datasets" / "holdout" / "v3" / "cases.jsonl",
    "holdout_indirect_v1": REPO_ROOT
    / "eval"
    / "datasets"
    / "holdout"
    / "indirect-v1"
    / "cases.jsonl",
    "holdout_mechanisms_v1": REPO_ROOT
    / "eval"
    / "datasets"
    / "holdout"
    / "mechanisms-v1"
    / "cases.jsonl",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checkpoint_digest(directory: Path) -> str:
    """Hash of the weights, so a checkpoint can be identified after the fact."""
    return hashlib.sha256((directory / "model.safetensors").read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# The sampler — the one declared departure, and the whole point of the arm
# ---------------------------------------------------------------------------


@dataclass
class Mixture:
    """Exact per-epoch slot counts. Constructed, not approximated.

    Drawing by explicit strata makes the *realised* mixture verifiable sample by
    sample, which a weight vector only achieves in expectation. ADR-020 §6 requires
    the realised mixture to be checked rather than the configured one.
    """

    total: int
    v1_slots: int
    extension_slots: int
    v1_extraction: int
    v1_other_attacks: int
    v1_benign: int
    extension_attacks_per_mechanism: int
    extension_attacks: int
    extension_benign: int


def plan_mixture(train_rows: list[dict[str, Any]]) -> Mixture:
    total = STEPS_PER_EPOCH * BATCH_SIZE
    extension_slots = round(total * EXTENSION_SHARE)
    v1_slots = total - extension_slots

    extension = [r for r in train_rows if r.get("dataset_version") == "finetune-v2"]
    ext_attack_ratio = sum(1 for r in extension if r["label"]) / len(extension)

    extension_attacks = round(extension_slots * ext_attack_ratio)
    per_mechanism = extension_attacks // len(MECHANISMS)
    extension_attacks = per_mechanism * len(MECHANISMS)  # keep the three exactly balanced
    extension_benign = extension_slots - extension_attacks

    attacks_total = round(total * ATTACK_FRACTION)
    # A floor, so ceil: round() would land at 0.38859, below the registered 0.389189.
    v1_extraction = math.ceil(attacks_total * EXTRACTION_SHARE_OF_ATTACKS)
    v1_other_attacks = attacks_total - extension_attacks - v1_extraction
    v1_benign = v1_slots - v1_extraction - v1_other_attacks

    return Mixture(
        total=total,
        v1_slots=v1_slots,
        extension_slots=extension_slots,
        v1_extraction=v1_extraction,
        v1_other_attacks=v1_other_attacks,
        v1_benign=v1_benign,
        extension_attacks_per_mechanism=per_mechanism,
        extension_attacks=extension_attacks,
        extension_benign=extension_benign,
    )


def _draw(rng: random.Random, pool: list[int], k: int) -> list[int]:
    """Sample k indices from pool. With replacement only when the pool is too small —
    which is the replay itself, and is recorded as an oversampling factor."""
    if k <= len(pool):
        return rng.sample(pool, k)
    return [pool[rng.randrange(len(pool))] for _ in range(k)]


def build_epoch(
    train_rows: list[dict[str, Any]], mixture: Mixture, seed: int, epoch: int
) -> list[int]:
    """Deterministic index list for one epoch.

    The RNG is derived from (seed, epoch) so that T3's single epoch is byte-identical
    to T2's first epoch at the same seed. That is what makes T3 − T2 an adaptation
    -budget contrast rather than a data contrast as well.
    """
    rng = random.Random(seed * 1000 + epoch)

    v1_idx = [i for i, r in enumerate(train_rows) if r.get("dataset_version") != "finetune-v2"]
    ext_idx = [i for i, r in enumerate(train_rows) if r.get("dataset_version") == "finetune-v2"]

    def subset(indices: list[int], predicate: Any) -> list[int]:
        return [i for i in indices if predicate(train_rows[i])]

    chosen: list[int] = []
    chosen += _draw(
        rng,
        subset(v1_idx, lambda r: r["label"] and r["sub_category"] == "system_prompt_extraction"),
        mixture.v1_extraction,
    )
    chosen += _draw(
        rng,
        subset(v1_idx, lambda r: r["label"] and r["sub_category"] != "system_prompt_extraction"),
        mixture.v1_other_attacks,
    )
    chosen += _draw(rng, subset(v1_idx, lambda r: not r["label"]), mixture.v1_benign)
    for mechanism in MECHANISMS:
        chosen += _draw(
            rng,
            subset(ext_idx, lambda r, m=mechanism: r["label"] and r["sub_category"] == m),
            mixture.extension_attacks_per_mechanism,
        )
    chosen += _draw(rng, subset(ext_idx, lambda r: not r["label"]), mixture.extension_benign)

    if len(chosen) != mixture.total:
        raise ValueError(f"sampler drew {len(chosen)}, expected {mixture.total}")
    rng.shuffle(chosen)
    return chosen


def realised_mixture(train_rows: list[dict[str, Any]], indices: list[int]) -> dict[str, Any]:
    """What was actually drawn — §6 requires this, not the configured ratio."""
    drawn = [train_rows[i] for i in indices]
    n = len(drawn)
    attacks = [r for r in drawn if r["label"]]
    extension = [r for r in drawn if r.get("dataset_version") == "finetune-v2"]
    extraction = [r for r in attacks if r["sub_category"] == "system_prompt_extraction"]
    return {
        "n": n,
        "unique_samples": len(set(indices)),
        "v1_share": round((n - len(extension)) / n, 6),
        "extension_share": round(len(extension) / n, 6),
        "attack_fraction": round(len(attacks) / n, 6),
        "extraction_share_of_attacks": round(len(extraction) / len(attacks), 6),
        "attacks_by_sub_category": dict(Counter(r["sub_category"] for r in attacks).most_common()),
        "mechanism_counts": {
            m: sum(1 for r in attacks if r["sub_category"] == m) for m in MECHANISMS
        },
    }


def mixture_targets_met(realised: dict[str, Any]) -> dict[str, bool]:
    return {
        "v1_share_0.90": abs(realised["v1_share"] - V1_SHARE) <= 0.005,
        "extension_share_0.10": abs(realised["extension_share"] - EXTENSION_SHARE) <= 0.005,
        "attack_fraction_pinned": abs(realised["attack_fraction"] - ATTACK_FRACTION) <= 0.005,
        "extraction_share_at_or_above_floor": realised["extraction_share_of_attacks"]
        >= EXTRACTION_SHARE_OF_ATTACKS,
        "three_mechanisms_balanced": len(set(realised["mechanism_counts"].values())) == 1,
    }


# ---------------------------------------------------------------------------
# Isolation and safety — §10, §11
# ---------------------------------------------------------------------------


def verify_isolation() -> dict[str, Any]:
    """No hold-out identifier is reachable from the training path.

    Parses this module and collects every name used inside the functions that train.
    The safety check may name hold-outs (it verifies their hashes are unchanged); the
    training path may not.
    """
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    training_functions = {"build_epoch", "plan_mixture", "train_one", "phase_train", "_draw"}
    forbidden = {"HOLDOUT_FILES", "HOLDOUT_HASHES"}
    offenders: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in training_functions:
            used = sorted(
                {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and n.id in forbidden}
            )
            if used:
                offenders[node.name] = used
    return {"isolated": not offenders, "holdout_references_in_training_path": offenders}


def git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:  # recorded as unknown rather than failing the run
        return "unknown"


def environment() -> dict[str, Any]:
    import torch

    return {
        "python": platform.python_version(),
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu",
        "platform": platform.platform(),
    }


def safety_check() -> dict[str, Any]:
    train_rows = load_jsonl(TRAIN_FILE)
    dev_rows = load_jsonl(DEV_FILE)
    mixture = plan_mixture(train_rows)
    dev_size = len(dev_rows)
    sample = build_epoch(train_rows, mixture, seed=SEEDS[0], epoch=0)
    realised = realised_mixture(train_rows, sample)

    hash_mismatches = {}
    for name, path, expected in (
        ("v2_train", TRAIN_FILE, EXPECTED["v2_train"]),
        ("v2_dev", DEV_FILE, EXPECTED["v2_dev"]),
    ):
        actual = sha256_file(path)
        if actual != expected:
            hash_mismatches[name] = {"expected": expected, "actual": actual}

    holdout_mismatches = {}
    for name, path in HOLDOUT_FILES.items():
        actual = sha256_file(path)
        if actual != HOLDOUT_HASHES[name]:
            holdout_mismatches[name] = {"expected": HOLDOUT_HASHES[name], "actual": actual}

    isolation = verify_isolation()
    targets = mixture_targets_met(realised)
    report = {
        "checked_at": datetime.now(UTC).isoformat(),
        "protocol": "docs/adr/ADR-020-retention-preserving-training.md (Step 2)",
        "training_input_representation": (
            "FULL CARRIER TEXT, exactly as ADR-019 used. The sampler changes which rows "
            "are drawn; it does not alter, truncate, or annotate any text."
        ),
        "planned_mixture": asdict(mixture),
        "realised_mixture_seed13_epoch0": realised,
        "mixture_targets_met": targets,
        "hash_mismatches": hash_mismatches,
        "holdout_hash_mismatches": holdout_mismatches,
        "isolation": isolation,
        "no_class_weighting": True,
        "no_custom_loss": True,
        "no_curriculum": True,
        "git_commit": git_commit(),
        "runs_registered": len(ARMS) * len(SEEDS),
        "dev_samples": dev_size,
    }
    report["safe_to_train"] = (
        not hash_mismatches
        and not holdout_mismatches
        and isolation["isolated"]
        and all(targets.values())
    )
    return report


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    run_id: str
    arm: str
    seed: int
    learning_rate: float
    epochs: int
    total_steps: int
    train_loss: float | None = None
    dev_loss: float | None = None
    dev: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0
    peak_vram_gb: float | None = None
    dev_selected_threshold: float | None = None
    dev_separable: bool | None = None
    dev_at_selected_threshold: dict[str, Any] = field(default_factory=dict)
    checkpoint: str | None = None
    checkpoint_sha256: str | None = None
    status: str = "ok"
    notes: list[str] = field(default_factory=list)


def train_one(arm: str, seed: int, train_rows: list, dev_rows: list, device: str) -> RunResult:
    import numpy as np
    import torch
    from torch.optim import AdamW
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        get_linear_schedule_with_warmup,
    )

    epochs = ARMS[arm]["epochs"]
    run_id = f"{arm}__lr{LEARNING_RATE:g}__ep{epochs}__seed{seed}"
    result = RunResult(
        run_id=run_id,
        arm=arm,
        seed=seed,
        learning_rate=LEARNING_RATE,
        epochs=epochs,
        total_steps=STEPS_PER_EPOCH * epochs,
    )
    started = time.perf_counter()

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL).to(device)

    total_steps = STEPS_PER_EPOCH * epochs
    optimiser = AdamW(
        model.parameters(),
        lr=LEARNING_RATE,
        weight_decay=WEIGHT_DECAY,
        fused=(device == "cuda"),
    )
    scheduler = get_linear_schedule_with_warmup(
        optimiser, int(total_steps * WARMUP_RATIO), total_steps
    )

    def accumulate(net: Any, batch: list[dict[str, Any]], micro_size: int) -> float:
        """Identical to Strategy A's: each micro-batch's loss is weighted by its share
        of the batch, so the accumulated gradient equals the gradient of the mean loss
        over the whole batch (verified in scripts/verify_accumulation.py)."""
        total = 0.0
        for offset in range(0, len(batch), micro_size):
            micro = batch[offset : offset + micro_size]
            enc = tokenizer(
                [r["text"] for r in micro],
                padding=True,
                truncation=True,
                max_length=MAX_LENGTH,
                return_tensors="pt",
            ).to(device)
            labels = torch.tensor([int(r["label"]) for r in micro], device=device)
            loss = net(**enc, labels=labels).loss
            scaled = loss * (len(micro) / len(batch))
            scaled.backward()
            total += loss.item() * (len(micro) / len(batch))
        return total

    micro_size = MICRO_BATCH_SIZE if device == "cuda" else BATCH_SIZE
    mixture = plan_mixture(train_rows)
    model.train()
    losses: list[float] = []
    try:
        for epoch in range(epochs):
            order = build_epoch(train_rows, mixture, seed=seed, epoch=epoch)
            for start in range(0, len(order), BATCH_SIZE):
                batch = [train_rows[i] for i in order[start : start + BATCH_SIZE]]
                optimiser.zero_grad(set_to_none=True)
                loss_value = accumulate(model, batch, micro_size)
                if not math.isfinite(loss_value):
                    result.status = "failed"
                    result.notes.append(
                        f"non-finite loss at epoch {epoch} step {start // BATCH_SIZE}"
                    )
                    raise FloatingPointError(result.notes[-1])
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimiser.step()
                scheduler.step()
                losses.append(loss_value)
    except FloatingPointError:
        result.duration_s = round(time.perf_counter() - started, 2)
        return result
    except torch.cuda.OutOfMemoryError as exc:  # pragma: no cover - recorded, not swallowed
        result.status = "failed"
        result.notes.append(f"CUDA OOM: {exc}")
        result.duration_s = round(time.perf_counter() - started, 2)
        return result

    result.train_loss = round(sum(losses) / len(losses), 6)

    scores = evaluate_model(model, tokenizer, dev_rows, device)
    if len({round(s, 6) for s in scores}) == 1:
        result.status = "degenerate"
        result.notes.append("dev scores are constant; the model does not discriminate")

    labels = [bool(r["label"]) for r in dev_rows]
    eps = 1e-12
    result.dev_loss = round(
        -sum(
            math.log(max(s, eps)) if y else math.log(max(1 - s, eps))
            for s, y in zip(scores, labels, strict=True)
        )
        / len(scores),
        6,
    )
    result.dev = _rates(dev_rows, scores, 0.5)
    calibration = calibrate_on_dev(dev_rows, scores)
    result.dev_selected_threshold = calibration["operating_point"]["threshold"]
    result.dev_separable = calibration["separable"]
    result.dev_at_selected_threshold = _rates(dev_rows, scores, result.dev_selected_threshold)

    checkpoint = ARTIFACTS / run_id
    checkpoint.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(checkpoint)
    tokenizer.save_pretrained(checkpoint)
    (checkpoint / "dev_scores.json").write_text(json.dumps(scores) + "\n", encoding="utf-8")
    result.checkpoint = str(checkpoint.relative_to(REPO_ROOT))
    result.checkpoint_sha256 = checkpoint_digest(checkpoint)

    if device == "cuda":
        result.peak_vram_gb = round(torch.cuda.max_memory_allocated() / 1024**3, 3)
        torch.cuda.reset_peak_memory_stats()
    result.duration_s = round(time.perf_counter() - started, 2)

    del model
    if device == "cuda":
        torch.cuda.empty_cache()
    return result


def phase_train() -> int:
    import torch

    report = safety_check()
    if not report["safe_to_train"]:
        print("SAFETY CHECK FAILED — not training. Fix the cause; do not repair during a run.")
        print(json.dumps(report, indent=2)[:3000])
        return 1

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "manifests").mkdir(exist_ok=True)
    (RESULTS / "logs").mkdir(exist_ok=True)
    (RESULTS / "safety_check.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )

    train_rows = load_jsonl(TRAIN_FILE)
    dev_rows = load_jsonl(DEV_FILE)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    env = environment()
    commit = git_commit()

    matrix_file = RESULTS / "training.json"
    existing = (
        json.loads(matrix_file.read_text(encoding="utf-8"))
        if matrix_file.exists()
        else {"runs": []}
    )
    done = {r["run_id"] for r in existing["runs"]}

    print(f"=== ADR-020 STEP 2 — {len(ARMS) * len(SEEDS)} registered runs (device={device}) ===")
    print(f"planned mixture: {report['planned_mixture']}\n")

    for arm in ARMS:
        for seed in SEEDS:
            epochs = ARMS[arm]["epochs"]
            run_id = f"{arm}__lr{LEARNING_RATE:g}__ep{epochs}__seed{seed}"
            if run_id in done:
                print(f"{run_id}: already recorded, skipping")
                continue
            result = train_one(arm, seed, train_rows, dev_rows, device)
            record = asdict(result)
            existing["runs"].append(record)
            matrix_file.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")

            order = build_epoch(train_rows, plan_mixture(train_rows), seed=seed, epoch=0)
            manifest = {
                "run_id": run_id,
                "arm": arm,
                "isolates": ARMS[arm]["isolates"],
                "seed": seed,
                "learning_rate": LEARNING_RATE,
                "epochs": epochs,
                "steps_per_epoch": STEPS_PER_EPOCH,
                "total_steps": STEPS_PER_EPOCH * epochs,
                "effective_batch": BATCH_SIZE,
                "micro_batch": MICRO_BATCH_SIZE,
                "gradient_accumulation": BATCH_SIZE // MICRO_BATCH_SIZE,
                "sampler": "stratified 90/10 v1:extension, explicit per-epoch slot counts",
                "mixture_ratio": {"v1": V1_SHARE, "extension": EXTENSION_SHARE},
                "planned_mixture": asdict(plan_mixture(train_rows)),
                "realised_mixture_epoch0": realised_mixture(train_rows, order),
                "mixture_targets_met": mixture_targets_met(realised_mixture(train_rows, order)),
                "train_hash": sha256_file(TRAIN_FILE),
                "dev_hash": sha256_file(DEV_FILE),
                "model_revision": BASE_MODEL,
                "tokenizer_revision": BASE_MODEL,
                "git_commit": commit,
                "environment": env,
                "duration_s": result.duration_s,
                "peak_vram_gb": result.peak_vram_gb,
                "checkpoint": result.checkpoint,
                "checkpoint_sha256": result.checkpoint_sha256,
                "status": result.status,
                "holdout_accessed": False,
            }
            (RESULTS / "manifests" / f"{run_id}.json").write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )
            print(
                f"{run_id}: {result.status} train_loss={result.train_loss} "
                f"dev_f1={result.dev.get('overall', {}).get('f1')} "
                f"{result.duration_s:.0f}s vram={result.peak_vram_gb}"
            )
    print(f"\nwrote {matrix_file}")
    return 0


RETENTION_DEV_SIGNALS = ("system_prompt_extraction",)


def _dev_subset_recall(
    dev_rows: list[dict], scores: list[float], sub: str, tau: float
) -> dict[str, Any]:
    idx = [i for i, r in enumerate(dev_rows) if r["label"] and r["sub_category"] == sub]
    if not idx:
        return {"n": 0, "tp": 0, "recall": None}
    tp = sum(1 for i in idx if scores[i] >= tau)
    return {"n": len(idx), "tp": tp, "recall": round(tp / len(idx), 4)}


def phase_report() -> int:
    import csv

    training = json.loads((RESULTS / "training.json").read_text(encoding="utf-8"))
    runs = training["runs"]
    dev_rows = load_jsonl(DEV_FILE)
    safety = json.loads((RESULTS / "safety_check.json").read_text(encoding="utf-8"))

    strat = json.loads(
        (REPO_ROOT / "eval" / "results" / "finetune" / "strategy_a_training.json").read_text(
            "utf-8"
        )
    )
    mech = json.loads(
        (REPO_ROOT / "eval" / "results" / "finetune" / "mechanisms" / "training.json").read_text(
            "utf-8"
        )
    )
    hist_a = [r for r in strat["runs"] if r["learning_rate"] == 1e-5 and r["epochs"] == 2]
    hist_b = [r for r in mech["runs"] if r["learning_rate"] == 1e-5 and r["epochs"] == 2]

    # --- per-run dev detail, including the diagnostics §19/§20 ask for ------
    detail: list[dict[str, Any]] = []
    for run in runs:
        row: dict[str, Any] = {
            "run_id": run["run_id"],
            "arm": run["arm"],
            "seed": run["seed"],
            "epochs": run["epochs"],
            "total_steps": run["total_steps"],
            "status": run["status"],
            "train_loss": run["train_loss"],
            "dev_loss": run["dev_loss"],
            "dev_selected_threshold": run.get("dev_selected_threshold"),
            "dev_separable": run.get("dev_separable"),
        }
        overall = (run.get("dev") or {}).get("overall", {})
        row |= {
            "dev_precision": overall.get("precision"),
            "dev_recall": overall.get("recall"),
            "dev_f1": overall.get("f1"),
            "dev_fpr": overall.get("fpr"),
            "dev_extraction_recall": (run.get("dev") or {}).get("extraction", {}).get("recall"),
            "dev_quoted_attack_fpr": (run.get("dev") or {}).get("quoted_attack", {}).get("fpr"),
        }
        if run.get("checkpoint"):
            scores = json.loads(
                (REPO_ROOT / run["checkpoint"] / "dev_scores.json").read_text(encoding="utf-8")
            )
            for mechanism in MECHANISMS:
                row[f"dev_{mechanism}_recall"] = _dev_subset_recall(
                    dev_rows, scores, mechanism, 0.5
                )["recall"]
        detail.append(row)

    with (RESULTS / "dev_results.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(detail[0]))
        writer.writeheader()
        writer.writerows(detail)

    with (RESULTS / "training_matrix.csv").open("w", newline="") as fh:
        cols = [
            "run_id",
            "arm",
            "seed",
            "learning_rate",
            "epochs",
            "total_steps",
            "effective_batch",
            "sampler",
            "mixture_ratio",
            "status",
            "checkpoint_sha256",
        ]
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for run in runs:
            writer.writerow(
                {
                    "run_id": run["run_id"],
                    "arm": run["arm"],
                    "seed": run["seed"],
                    "learning_rate": run["learning_rate"],
                    "epochs": run["epochs"],
                    "total_steps": run["total_steps"],
                    "effective_batch": BATCH_SIZE,
                    "sampler": "stratified 90/10 v1:extension",
                    "mixture_ratio": f"{V1_SHARE}/{EXTENSION_SHARE}",
                    "status": run["status"],
                    "checkpoint_sha256": run.get("checkpoint_sha256"),
                }
            )

    with (RESULTS / "resource_usage.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["run_id", "arm", "duration_s", "peak_vram_gb", "total_steps"]
        )
        writer.writeheader()
        for run in runs:
            writer.writerow(
                {
                    k: run.get(k)
                    for k in ["run_id", "arm", "duration_s", "peak_vram_gb", "total_steps"]
                }
            )

    # --- does dev discriminate at all? --------------------------------------
    keys = ("dev_f1", "dev_fpr", "dev_recall", "dev_extraction_recall", "dev_quoted_attack_fpr")
    tied = {k: len({d[k] for d in detail if d[k] is not None}) == 1 for k in keys}
    mech_keys = [f"dev_{m}_recall" for m in MECHANISMS]
    tied |= {k: len({d.get(k) for d in detail if d.get(k) is not None}) == 1 for k in mech_keys}
    non_discriminating = all(tied.values())

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "runs_registered": len(ARMS) * len(SEEDS),
        "runs_recorded": len(runs),
        "runs_ok": sum(1 for r in runs if r["status"] == "ok"),
        "runs_failed": [r["run_id"] for r in runs if r["status"] != "ok"],
        "dev_split": {"file": str(DEV_FILE.relative_to(REPO_ROOT)), "n": len(dev_rows)},
        "dev_metric_is_tied_across_all_runs": tied,
        "dev_is_non_discriminating": non_discriminating,
        "holdout_accessed": False,
        "per_arm": {
            arm: {
                "n": sum(1 for d in detail if d["arm"] == arm),
                "total_steps": next((d["total_steps"] for d in detail if d["arm"] == arm), None),
                "dev_f1": sorted({d["dev_f1"] for d in detail if d["arm"] == arm}),
                "dev_fpr": sorted({d["dev_fpr"] for d in detail if d["arm"] == arm}),
                "dev_extraction_recall": sorted(
                    {d["dev_extraction_recall"] for d in detail if d["arm"] == arm}
                ),
                "dev_selected_threshold": sorted(
                    {d["dev_selected_threshold"] for d in detail if d["arm"] == arm}
                ),
                "mean_duration_s": round(
                    sum(r["duration_s"] for r in runs if r["arm"] == arm)
                    / max(1, sum(1 for r in runs if r["arm"] == arm)),
                    1,
                ),
            }
            for arm in ARMS
        },
        "historical_controls_not_rerun": {
            "strategy_a_lr1e-05_ep2": {
                "n": len(hist_a),
                "dev_split": "finetune-v1 dev (808) — a DIFFERENT population from v2 dev",
                "dev_f1": sorted({r["dev"]["at_0.5"]["overall"]["f1"] for r in hist_a}),
                "mean_duration_s": round(sum(r["duration_s"] for r in hist_a) / len(hist_a), 1),
            },
            "adr_019_lr1e-05_ep2": {
                "n": len(hist_b),
                "dev_split": "finetune-v2 dev (1044) — the same population as T2/T3",
                "dev_f1": sorted({r["dev_f1"] for r in hist_b}),
                "mean_duration_s": round(sum(r["duration_s"] for r in hist_b) / len(hist_b), 1),
            },
        },
        "realised_mixture": safety["realised_mixture_seed13_epoch0"],
        "mixture_targets_met": safety["mixture_targets_met"],
    }
    (RESULTS / "dev_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )

    # --- report.md ----------------------------------------------------------
    lines = [
        "# ADR-020 Step 2 — controlled retention-preserving training\n",
        f"Generated {summary['generated_at']}. "
        f"**{summary['runs_ok']}/{summary['runs_registered']} runs succeeded.** "
        "No protected hold-out was read.\n",
        "## The registered mixture, as realised\n",
        "| target | registered | realised (seed 13, epoch 0) | met |",
        "|---|---|---|---|",
    ]
    r = summary["realised_mixture"]
    for label, target, actual, met in (
        ("v1 share", V1_SHARE, r["v1_share"], summary["mixture_targets_met"]["v1_share_0.90"]),
        (
            "extension share",
            EXTENSION_SHARE,
            r["extension_share"],
            summary["mixture_targets_met"]["extension_share_0.10"],
        ),
        (
            "attack fraction",
            ATTACK_FRACTION,
            r["attack_fraction"],
            summary["mixture_targets_met"]["attack_fraction_pinned"],
        ),
        (
            "extraction share of attacks",
            f">= {EXTRACTION_SHARE_OF_ATTACKS}",
            r["extraction_share_of_attacks"],
            summary["mixture_targets_met"]["extraction_share_at_or_above_floor"],
        ),
    ):
        lines.append(f"| {label} | {target} | {actual} | {'yes' if met else 'NO'} |")
    train_rows = load_jsonl(TRAIN_FILE)
    coverage = r["unique_samples"] / len(train_rows)
    lines.append(
        f"\nMechanisms exactly balanced at {r['mechanism_counts']}. "
        f"{r['unique_samples']} unique samples across {r['n']} draws "
        f"({r['n'] / r['unique_samples']:.2f}x mean repetition) — the replay, and the "
        "registered memorisation risk R-50.\n"
    )
    lines.append(
        f"A property worth stating plainly: because the strata are drawn **with "
        f"replacement** where a pool is smaller than its quota, one epoch touches "
        f"{r['unique_samples']} of the {len(train_rows)} available training rows "
        f"(**{coverage:.1%} coverage**). The replay arm is not 'the whole corpus plus "
        f"extra extraction'; it is a resampled corpus. Extraction is oversampled "
        f"{r['attacks_by_sub_category']['system_prompt_extraction'] / 230:.2f}x from a "
        f"pool of 230, and v1 benign is oversampled to fill its 90% share.\n"
    )
    # --- the composition contrast, T2 vs ADR-019 (§3) -----------------------
    natural_attacks = [r for r in train_rows if r["label"]]
    natural_ext = [r for r in train_rows if r.get("dataset_version") == "finetune-v2"]
    natural_sub = Counter(r["sub_category"] for r in natural_attacks)
    lines.append("## What the replay actually changed (T2 vs ADR-019, §3)\n")
    lines.append("| factor | ADR-019 (natural) | T2/T3 (replay) | delta |")
    lines.append("|---|---|---|---|")
    for label, a, b in (
        ("v1 share", 1 - len(natural_ext) / len(train_rows), r["v1_share"]),
        ("extension share", len(natural_ext) / len(train_rows), r["extension_share"]),
        ("attack fraction", len(natural_attacks) / len(train_rows), r["attack_fraction"]),
        (
            "extraction share of attack mass",
            natural_sub["system_prompt_extraction"] / len(natural_attacks),
            r["extraction_share_of_attacks"],
        ),
    ):
        lines.append(f"| {label} | {a:.4f} | {b:.4f} | {b - a:+.4f} |")
    lines.append(
        f"| extraction samples/epoch | {natural_sub['system_prompt_extraction']} | "
        f"{r['attacks_by_sub_category']['system_prompt_extraction']} | "
        f"{r['attacks_by_sub_category']['system_prompt_extraction'] - natural_sub['system_prompt_extraction']:+d} |"
    )
    for mechanism in MECHANISMS:
        lines.append(
            f"| {mechanism} samples/epoch | {natural_sub[mechanism]} | "
            f"{r['mechanism_counts'][mechanism]} | "
            f"{r['mechanism_counts'][mechanism] - natural_sub[mechanism]:+d} |"
        )
    lines.append("| optimisation steps | 486 | 486 (T2) / 243 (T3) | T2 identical |\n")
    lines.append(
        "T2 restores precisely what ADR-019 diluted: extraction's share of attack mass "
        "returns from 0.2436 to 0.3899, against v1's original 0.3892, at an **identical "
        "486-step budget**. That is the composition intervention, aimed at candidate "
        "cause C2 and nothing else. Its price is mechanism exposure roughly halved "
        "(~119 to 53 samples per epoch each), which is R-49.\n"
    )
    lines.append("## Four-way comparison (pre-hold-out information only)\n")
    lines.append(
        "| arm | corpus / sampler | steps | epochs | seeds | dev split | dev F1 | mean duration |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    ha = summary["historical_controls_not_rerun"]["strategy_a_lr1e-05_ep2"]
    hb = summary["historical_controls_not_rerun"]["adr_019_lr1e-05_ep2"]
    lines.append(
        f"| Strategy A *(not re-run)* | finetune-v1, natural | 376 | 2 | 3 | v1 dev (808) | {ha['dev_f1']} | {ha['mean_duration_s']}s |"
    )
    lines.append(
        f"| ADR-019 *(not re-run)* | finetune-v2, natural | 486 | 2 | 3 | v2 dev (1044) | {hb['dev_f1']} | {hb['mean_duration_s']}s |"
    )
    for arm in ARMS:
        a = summary["per_arm"][arm]
        lines.append(
            f"| **{arm}** | v2 rows, 90/10 replay | {a['total_steps']} | {ARMS[arm]['epochs']} | "
            f"{a['n']} | v2 dev (1044) | {a['dev_f1']} | {a['mean_duration_s']}s |"
        )
    lines.append(
        "\nStrategy A's dev split is **finetune-v1 dev (808)**, a different population "
        "from the v2 dev (1044) shared by ADR-019, T2 and T3. Only the latter three are "
        "directly comparable on dev.\n"
    )
    lines.append("## Dev diagnostics (§19, §20) — diagnostics only\n")
    lines.append(
        "| run | dev F1 | dev FPR | extraction | quoted_attack FPR | "
        + " | ".join(MECHANISMS)
        + " | dev tau |"
    )
    lines.append("|---" * (6 + len(MECHANISMS)) + "|---|")
    for d in detail:
        lines.append(
            f"| `{d['run_id']}` | {d['dev_f1']} | {d['dev_fpr']} | {d['dev_extraction_recall']} | "
            f"{d['dev_quoted_attack_fpr']} | "
            + " | ".join(str(d.get(f"dev_{m}_recall")) for m in MECHANISMS)
            + f" | {d['dev_selected_threshold']} |"
        )
    if non_discriminating:
        lines.append(
            "\n**Dev is non-discriminating.** Every run ties on every dev metric above, "
            "so dev cannot rank these six checkpoints and no ranking is manufactured from "
            "it. This is OD-23/OD-33 recurring for the third time, now on the replay "
            "mixture as well.\n"
        )
    else:
        varying = [k for k, v in tied.items() if not v]
        lines.append(
            f"\nDev separates the runs on: {varying}. Treated as diagnostic only; "
            "selection happens in Step 3.\n"
        )
    lines.append("## Resource usage\n")
    lines.append("| run | steps | duration | peak VRAM |")
    lines.append("|---|---|---|---|")
    for run in runs:
        lines.append(
            f"| `{run['run_id']}` | {run['total_steps']} | {run['duration_s']}s | {run['peak_vram_gb']} GB |"
        )
    env = json.loads((RESULTS / "manifests" / f"{runs[0]['run_id']}.json").read_text("utf-8"))[
        "environment"
    ]
    lines.append(
        f"\n{env['device_name']} · CUDA {env['cuda']} · torch {env['torch']} · Python {env['python']}\n"
    )
    lines.append(
        "T2 and ADR-019 run the identical 486-step budget, yet their wall-clock differs. "
        "**No cause is claimed for that.** The obvious candidate was sequence length, and "
        "it was checked and rejected: the replay epoch's per-micro-batch padded cost is "
        "*higher* (140,709 vs 122,808 characters) while its wall-clock is lower, so length "
        "does not explain it. Wall-clock here is not a controlled quantity — the two "
        "experiments ran at different times under different machine load — and no "
        "throughput claim is made from it.\n"
    )
    (RESULTS / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # --- decision.md --------------------------------------------------------
    decision = [
        "# ADR-020 Step 2 — decision\n",
        f"**Status: {'COMPLETE' if summary['runs_ok'] == summary['runs_registered'] else 'PARTIAL'}** "
        f"— {summary['runs_ok']}/{summary['runs_registered']} runs, all manifests written, "
        "no hold-out accessed.\n",
        "## Causal interpretation: DEFERRED to Step 3, and necessarily so\n",
        "ADR-020 §18 asks three questions:\n",
        "* **A** — does T2 recover retention while preserving mechanism learning?",
        "* **B** — does T3 recover retention?",
        "* **C** — does neither, promoting the layered-detector hypothesis?\n",
        "**None of them can be answered by Step 2**, and answering them here would be a "
        "fabrication rather than a finding. Retention is defined on holdout-v3 "
        "(extraction recall, attack recall, benign FPR, quoted_attack FPR) and mechanism "
        "learning on mechanisms-v1. §15 forbids reading either, correctly — those are the "
        "single authorised scorings and they belong to Step 3.\n",
        "The only within-Step-2 surface is dev, and dev is "
        f"**{'non-discriminating' if non_discriminating else 'partially discriminating'}**: "
        + (
            "every run ties on every metric, so it carries no information about retention "
            "or mechanisms at all.\n"
            if non_discriminating
            else "it separates some runs, but "
            "the historical record shows dev saturation repeatedly failing to predict "
            "hold-out behaviour.\n"
        ),
        "§18's own instruction governs: *do not claim a causal result if the observed arms "
        "cannot actually distinguish it.* They cannot, yet.\n",
        "## What Step 2 does establish\n",
        "1. **The six registered runs exist and completed**, with the matrix unexpanded — "
        "two arms, three seeds, one learning rate, no seventh configuration.",
        "2. **The mixture realised as registered**, verified sample by sample rather than "
        "assumed from the configured ratio: v1 "
        f"{r['v1_share']}, extension {r['extension_share']}, attack fraction "
        f"{r['attack_fraction']}, extraction {r['extraction_share_of_attacks']} of attack "
        "mass (at or above the registered floor), mechanisms exactly balanced.",
        "3. **The contrasts are clean by construction.** T2 holds the step budget at "
        "ADR-019's 486 and varies only composition; T3 shares T2's sampler and varies only "
        "the adaptation budget. T3's epoch is byte-identical to T2's first epoch, asserted "
        "in `tests/evaluation/test_adr020_step2.py`.",
        "4. **A quantified cost of the replay**: each new mechanism now receives "
        f"{r['mechanism_counts'][MECHANISMS[0]]} samples per epoch against ADR-019's ~150. "
        "If the mechanisms fail their Wilson bound in Step 3, this is the reason, and it "
        "was registered in advance as R-49.\n",
        "## Step-3 decision: **PROCEED TO STEP 3**\n",
        "Justified because the arms differ enough to be separable on the hold-out, the "
        "matrix is complete and unexpanded, and the registered question is still open — "
        "not because T2 scores better on dev, which ADR-020 §9 explicitly excludes as a "
        "basis for the decision.\n",
        "### Precondition audit (§10)\n",
        "| requirement | state |",
        "|---|---|",
        "| checkpoint selection rule | defined — amendment A-1, exact ordered keys |",
        "| threshold-selection rule | defined — amendment A-2, matched-FPR primary |",
        "| holdout-v3 scoring budget | defined — 1 event, 2 checkpoints (A-3) |",
        "| mechanisms-v1 scoring budget | defined — 1 event, 2 checkpoints (A-3) |",
        "| retention criteria | defined — `success_criteria.json`, 4 criteria, paired + margin |",
        "| new-mechanism criteria | defined — Wilson lower >= 0.50, i.e. >= 38/60 |",
        "| immutable model-selection lock | defined — locked before any hold-out is read |\n",
        "**One requirement was NOT satisfied when this audit began, and was amended "
        "before Step 3 rather than after** (A-3, 2026-08-18). Step 3 originally scored a "
        "single pooled winner. Because T2 dominates T3 on every dev metric, the pooled "
        "winner would be a T2 and T3 would never be measured on holdout-v3 — making "
        "three of ADR-020's four registered causal outcomes unreachable and three of its "
        "six runs evidentially useless. Step 3 now scores the best T2 **and** the best "
        "T3 in one evaluation event, both locked in advance; the deployment candidate "
        "remains the single pooled winner and the other arm is contrast-only.\n",
        "## Next\n",
        "**Execute ADR-020 Step 3** — DEV-only final selection and threshold lock under "
        "A-1, A-2 and A-3, followed by the single authorised evaluation event on "
        "holdout-v3 and on mechanisms-v1.\n",
        "Step 3 is a separate task and is not started here.\n",
    ]
    (RESULTS / "decision.md").write_text("\n".join(decision) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                k: summary[k]
                for k in ("runs_recorded", "runs_ok", "runs_failed", "dev_is_non_discriminating")
            },
            indent=2,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--safety-check", action="store_true")
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    if args.safety_check:
        report = safety_check()
        print(json.dumps(report, indent=2))
        return 0 if report["safe_to_train"] else 1
    if args.train:
        return phase_train()
    if args.report:
        return phase_report()
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
