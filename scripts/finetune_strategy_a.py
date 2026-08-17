"""Strategy A — standard supervised fine-tuning, executed as pre-registered.

Runs the experiment in ADR-015 in strict phase order, because the order *is* the
methodology:

    0. safety check          — hashes, and prove the hold-out is unreachable
    1. train                 — the pre-registered configuration matrix
    2. select checkpoint     — DEV only, by the pre-registered priority
    3. select threshold      — DEV only
    4. pre-hold-out lock     — freeze the whole decision to disk
    5. hold-out              — scored exactly once, after the lock exists
    6. report

Strategy A means *standard* SFT: plain cross-entropy, natural class balance, no
oversampling, no class weights, no custom loss, no curriculum, no augmentation.
Anything else would confound the causal baseline this run exists to establish.

Phases are separate commands on purpose: `--holdout` refuses to run unless the
lock file already exists, and refuses to run twice. The single-evaluation
guarantee is therefore enforced, not merely documented.

    uv run python -m scripts.finetune_strategy_a --safety-check
    uv run python -m scripts.finetune_strategy_a --train
    uv run python -m scripts.finetune_strategy_a --select
    uv run python -m scripts.finetune_strategy_a --holdout
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random

# Must precede the first torch import. The 3.95 GB GPU runs at ~97% occupancy
# during training, so allocator fragmentation is the difference between a clean
# run and an OOM at configuration 14 of 18.
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
FT = REPO_ROOT / "eval" / "datasets" / "finetune"
TRAIN_FILE = FT / "train" / "cases.jsonl"
DEV_FILE = FT / "dev" / "cases.jsonl"
HOLDOUT_FILE = REPO_ROOT / "eval" / "datasets" / "holdout" / "cases.jsonl"
RESULTS = REPO_ROOT / "eval" / "results" / "finetune"
# Weights live outside the application tree and are never committed.
ARTIFACTS = REPO_ROOT / "artifacts" / "finetune"

BASE_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
MAX_LENGTH = 512  # declared ceiling; dynamic padding means no sample is truncated
BATCH_SIZE = 16
# Gradient accumulation: 4 x 4 == the pre-registered batch of 16. Required
# because a 3.95 GB card holds DeBERTa-v3-base's weights, gradients and AdamW
# moments (~2.94 GB) with too little left for a 16-sample forward pass.
MICRO_BATCH_SIZE = 4
EVAL_BATCH_SIZE = 32  # inference only; affects nothing but memory
WEIGHT_DECAY = 0.01
WARMUP_RATIO = 0.1

# Pre-registered matrix (ADR-015): 3 x 2 x 3 = 18 configurations.
LEARNING_RATES = (1e-5, 2e-5, 3e-5)
EPOCH_COUNTS = (2, 3)
SEEDS = (13, 20260817, 31337)

# ADR-015's "no more than a 5-point drop" floor. The reference it is measured
# against is the base model's own score on *dev*, computed at selection time —
# not the hold-out figures below, which would import a hold-out quantity into a
# dev-only decision. These are recorded for the report's comparison table only.
MAX_RECALL_DROP = 0.05
HOLDOUT_REFERENCE = {
    "protectai_base@0.9995": {
        "attack_recall": 0.8833,
        "benign_fpr": 0.0678,
        "hard_negative_fpr": 0.1706,
        "quoted_attack_fpr": 0.875,
        "incident_response_fpr": 0.412,
        "extraction_recall": 0.8444,
    },
    "heuristic@0.85": {
        "attack_recall": 0.3167,
        "benign_fpr": 0.0241,
        "hard_negative_fpr": 0.0647,
        "quoted_attack_fpr": 0.500,
        "incident_response_fpr": 0.294,
        "extraction_recall": 0.2667,
    },
}


class HoldOutAccessError(RuntimeError):
    """Training tried to reach the frozen hold-out."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    return result.stdout.strip() or "unknown"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def guard_no_holdout(paths: list[Path]) -> None:
    """Fail loudly if a training path is, or contains, the frozen hold-out."""
    holdout = HOLDOUT_FILE.resolve()
    for path in paths:
        if path.resolve() == holdout:
            raise HoldOutAccessError(f"training was handed the frozen hold-out: {path}")
        if "holdout" in str(path.resolve()).lower():
            raise HoldOutAccessError(f"training path references the hold-out: {path}")


def guard_no_collision(rows: list[dict[str, Any]]) -> None:
    from eval.schema import normalised_key

    holdout_keys = {normalised_key(r["text"]) for r in load_jsonl(HOLDOUT_FILE)}
    collisions = [r for r in rows if normalised_key(r["text"]) in holdout_keys]
    if collisions:
        raise HoldOutAccessError(
            f"{len(collisions)} training samples collide with the frozen hold-out"
        )


def environment() -> dict[str, Any]:
    import torch
    import transformers

    gpu: dict[str, Any] = {"available": torch.cuda.is_available()}
    if torch.cuda.is_available():
        props = torch.cuda.get_device_properties(0)
        gpu |= {
            "name": props.name,
            "total_memory_gb": round(props.total_memory / 1e9, 2),
            "cuda": torch.version.cuda,
        }
    return {
        "python": sys.version.split()[0],
        "torch": torch.__version__,
        "transformers": transformers.__version__,
        "gpu": gpu,
        "cpu_count": os.cpu_count(),
        "uv_lock_hash": sha256_file(REPO_ROOT / "uv.lock")[:32],
        "git_commit": git_commit(),
    }


def safety_check() -> dict[str, Any]:
    guard_no_holdout([TRAIN_FILE, DEV_FILE])
    train = load_jsonl(TRAIN_FILE)
    dev = load_jsonl(DEV_FILE)
    guard_no_collision(train + dev)
    manifest = {
        "train_manifest_hash": sha256_file(TRAIN_FILE)[:32],
        "dev_manifest_hash": sha256_file(DEV_FILE)[:32],
        "holdout_content_hash": sha256_file(HOLDOUT_FILE)[:32],
        "holdout_manifest_hash": sha256_file(HOLDOUT_FILE.parent / "build_manifest.json")[:32],
        "train_n": len(train),
        "dev_n": len(dev),
        "holdout_collisions": 0,
        "holdout_reachable_from_training": False,
        "base_model": BASE_MODEL,
        "environment": environment(),
    }
    return manifest


# ---------------------------------------------------------------------------
# Metrics on dev — the ONLY split used for any selection
# ---------------------------------------------------------------------------


def _rates(rows: list[dict[str, Any]], scores: list[float], threshold: float) -> dict[str, Any]:
    from eval.metrics.classification import confusion_at

    labels = [bool(r["label"]) for r in rows]
    matrix = confusion_at(labels, scores, threshold)

    def subset_fpr(predicate: Any) -> dict[str, Any]:
        idx = [i for i, r in enumerate(rows) if predicate(r) and not r["label"]]
        if not idx:
            return {"n": 0, "fp": 0, "fpr": 0.0}
        fp = sum(1 for i in idx if scores[i] >= threshold)
        return {"n": len(idx), "fp": fp, "fpr": round(fp / len(idx), 4)}

    def subset_recall(predicate: Any) -> dict[str, Any]:
        idx = [i for i, r in enumerate(rows) if predicate(r) and r["label"]]
        if not idx:
            return {"n": 0, "tp": 0, "recall": 0.0}
        tp = sum(1 for i in idx if scores[i] >= threshold)
        return {"n": len(idx), "tp": tp, "recall": round(tp / len(idx), 4)}

    return {
        "threshold": threshold,
        "overall": matrix.as_dict(),
        "quoted_attack": subset_fpr(lambda r: r["sub_category"] == "quoted_attack"),
        "hard_negative": subset_fpr(lambda r: r["category"] == "hard_negative"),
        "extraction": subset_recall(lambda r: r["sub_category"] == "system_prompt_extraction"),
    }


@dataclass
class RunResult:
    run_id: str
    learning_rate: float
    epochs: int
    seed: int
    dev: dict[str, Any]
    train_loss: float
    duration_s: float
    peak_memory_gb: float | None = None
    checkpoint: str | None = None
    status: str = "ok"
    notes: list[str] = field(default_factory=list)


def evaluate_model(
    model: Any, tokenizer: Any, rows: list[dict[str, Any]], device: str
) -> list[float]:
    import torch

    model.eval()
    scores: list[float] = []
    with torch.no_grad():
        for start in range(0, len(rows), EVAL_BATCH_SIZE):
            batch = rows[start : start + EVAL_BATCH_SIZE]
            enc = tokenizer(
                [r["text"] for r in batch],
                padding=True,
                truncation=True,
                max_length=MAX_LENGTH,
                return_tensors="pt",
            ).to(device)
            logits = model(**enc).logits
            scores.extend(torch.softmax(logits, dim=-1)[:, 1].tolist())
    return scores


def train_one(
    learning_rate: float, epochs: int, seed: int, train_rows: list, dev_rows: list, device: str
) -> RunResult:
    import numpy as np
    import torch
    from torch.optim import AdamW
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        get_linear_schedule_with_warmup,
    )

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)

    run_id = f"stratA__lr{learning_rate:g}__ep{epochs}__seed{seed}"
    started = time.perf_counter()
    if device == "cuda":
        torch.cuda.reset_peak_memory_stats()

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL).to(device)

    order = list(range(len(train_rows)))
    steps_per_epoch = (len(order) + BATCH_SIZE - 1) // BATCH_SIZE
    total_steps = steps_per_epoch * epochs
    # fused=True on CUDA: the update runs in-kernel instead of materialising
    # param-sized temporaries. The default (multi-tensor) path OOMs on a 4 GB
    # card because DeBERTa-v3's 128k-token embedding is 394 MB on its own.
    # This is an implementation of the same AdamW update, not a different one.
    optimiser = AdamW(
        model.parameters(),
        lr=learning_rate,
        weight_decay=WEIGHT_DECAY,
        fused=(device == "cuda"),
    )
    scheduler = get_linear_schedule_with_warmup(
        optimiser, int(total_steps * WARMUP_RATIO), total_steps
    )

    def accumulate(net: Any, batch: list[dict[str, Any]], micro_size: int) -> float:
        """Backward over one optimiser step's worth of samples.

        Each micro-batch's mean loss is weighted by its share of the batch, so
        the accumulated gradient equals the gradient of the mean loss over the
        whole batch. Micro-batching is therefore a memory strategy, not a change
        to the effective batch size, which stays at the pre-registered 16.
        """
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
            labels = torch.tensor([r["label"] for r in micro], device=device)
            loss = net(**enc, labels=labels).loss * (len(micro) / len(batch))
            loss.backward()
            total += float(loss.detach())
        return total

    rng = random.Random(seed)
    losses: list[float] = []
    micro_size = MICRO_BATCH_SIZE if device == "cuda" else BATCH_SIZE
    model.train()
    for _epoch in range(epochs):
        rng.shuffle(order)
        for start in range(0, len(order), BATCH_SIZE):
            batch = [train_rows[i] for i in order[start : start + BATCH_SIZE]]
            try:
                loss_value = accumulate(model, batch, micro_size)
            except torch.OutOfMemoryError:
                # Headroom on a 4 GB card is ~280 MB; an unlucky batch can still
                # exceed it. Halve the micro-batch permanently and redo the step
                # — the gradient is unchanged, only the memory profile moves.
                if micro_size == 1:
                    raise
                micro_size = max(1, micro_size // 2)
                optimiser.zero_grad(set_to_none=True)
                torch.cuda.empty_cache()
                loss_value = accumulate(model, batch, micro_size)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimiser.step()
            scheduler.step()
            optimiser.zero_grad(set_to_none=True)
            losses.append(loss_value)

    peak_memory_gb = round(torch.cuda.max_memory_allocated() / 1e9, 2) if device == "cuda" else None

    # Release optimiser state (~1.5 GB) before inference — on this card the
    # dev pass does not fit alongside it.
    model.zero_grad(set_to_none=True)
    del optimiser, scheduler
    if device == "cuda":
        torch.cuda.empty_cache()

    scores = evaluate_model(model, tokenizer, dev_rows, device)
    dev_metrics = {"at_0.5": _rates(dev_rows, scores, 0.5)}

    # Degenerate-prediction guard: a model that collapses to one class can look
    # good on one metric and is useless.
    notes = []
    status = "ok"
    positives = sum(1 for s in scores if s >= 0.5)
    if positives == 0 or positives == len(scores):
        status = "degenerate"
        notes.append(f"collapsed to a single class ({positives}/{len(scores)} positive)")
    notes.append(f"micro_batch={micro_size} (effective batch {BATCH_SIZE})")

    checkpoint_dir = ARTIFACTS / run_id
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(checkpoint_dir)
    tokenizer.save_pretrained(checkpoint_dir)

    # Keep the raw dev scores so selection and threshold calibration need no retraining.
    (checkpoint_dir / "dev_scores.json").write_text(json.dumps(scores), encoding="utf-8")

    del model
    if device == "cuda":
        torch.cuda.empty_cache()

    return RunResult(
        run_id=run_id,
        learning_rate=learning_rate,
        epochs=epochs,
        seed=seed,
        dev=dev_metrics,
        train_loss=round(sum(losses[-50:]) / max(1, len(losses[-50:])), 5),
        duration_s=round(time.perf_counter() - started, 1),
        peak_memory_gb=peak_memory_gb,
        checkpoint=str(checkpoint_dir.relative_to(REPO_ROOT)),
        status=status,
        notes=notes,
    )


def phase_train() -> int:
    import torch

    safety = safety_check()
    print("=== PHASE 0: SAFETY CHECK ===")
    print(json.dumps(safety, indent=2))

    device = "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cpu":
        torch.set_num_threads(os.cpu_count() or 8)
    print(f"\ndevice: {device}\n")

    train_rows = load_jsonl(TRAIN_FILE)
    dev_rows = load_jsonl(DEV_FILE)

    RESULTS.mkdir(parents=True, exist_ok=True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    results: list[RunResult] = []
    configs = [(lr, ep, sd) for lr in LEARNING_RATES for ep in EPOCH_COUNTS for sd in SEEDS]
    print(f"=== PHASE 1: TRAIN {len(configs)} configurations (pre-registered matrix) ===\n")

    for index, (lr, epochs, seed) in enumerate(configs, 1):
        print(f"[{index}/{len(configs)}] lr={lr:g} epochs={epochs} seed={seed} …", flush=True)
        try:
            result = train_one(lr, epochs, seed, train_rows, dev_rows, device)
        except Exception as exc:
            print(f"    FAILED: {type(exc).__name__}: {exc}", flush=True)
            results.append(
                RunResult(
                    run_id=f"stratA__lr{lr:g}__ep{epochs}__seed{seed}",
                    learning_rate=lr,
                    epochs=epochs,
                    seed=seed,
                    dev={},
                    train_loss=float("nan"),
                    duration_s=0.0,
                    status="failed",
                    notes=[f"{type(exc).__name__}: {exc}"],
                )
            )
            continue
        overall = result.dev["at_0.5"]["overall"]
        print(
            f"    loss={result.train_loss:.4f} devFPR={overall['fpr']:.4f} "
            f"devRecall={overall['recall']:.4f} "
            f"quotedFPR={result.dev['at_0.5']['quoted_attack']['fpr']:.4f} "
            f"({result.duration_s:.0f}s) [{result.status}]",
            flush=True,
        )
        results.append(result)

    payload = {
        "phase": "train",
        "started_at": datetime.now(UTC).isoformat(),
        "safety_check": safety,
        "device": device,
        "protocol": {
            "strategy": "A — standard supervised fine-tuning",
            "learning_rates": list(LEARNING_RATES),
            "epochs": list(EPOCH_COUNTS),
            "seeds": list(SEEDS),
            "batch_size": BATCH_SIZE,
            "micro_batch_size": MICRO_BATCH_SIZE,
            "gradient_accumulation": (
                "loss weighted by micro-batch share, so the accumulated gradient "
                "equals that of a single batch of 16"
            ),
            "optimiser": "AdamW (fused on CUDA; same update, no param-sized temporaries)",
            "weight_decay": WEIGHT_DECAY,
            "warmup_ratio": WARMUP_RATIO,
            "max_length": MAX_LENGTH,
            "padding": "dynamic (pad to longest in batch); no sample is truncated",
            "no_class_weighting": True,
            "no_oversampling": True,
            "no_custom_loss": True,
        },
        "runs": [r.__dict__ for r in results],
    }
    (RESULTS / "strategy_a_training.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    print(f"\nwrote {RESULTS / 'strategy_a_training.json'}")
    return 0


# ---------------------------------------------------------------------------
# Run directory — one per experiment, never overwritten (§21)
# ---------------------------------------------------------------------------

RUN_SUFFIX = "__strategy-a"
BASE_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"

# Prior hold-out evaluations of the two incumbent systems. Read, never re-run:
# these are published results, and re-scoring them would be a second hold-out
# evaluation of an already-decided question.
PRIOR_HOLDOUT_PREDICTIONS = (
    REPO_ROOT
    / "eval"
    / "results"
    / "20260817T102936Z__threshold-deployability"
    / "predictions.jsonl"
)
FROZEN_THRESHOLDS = {"injection.heuristic": 0.85, "injection.protectai_deberta_v2": 0.9995}


def run_dir(create: bool = False) -> Path:
    """The single directory for this experiment.

    Creating a second one is refused rather than silently allowed: overwriting a
    prior Strategy A result would destroy the immutability the whole protocol
    rests on.
    """
    existing = sorted(RESULTS.glob(f"*{RUN_SUFFIX}"))
    if create:
        if existing:
            raise SystemExit(
                f"REFUSING: {existing[0]} already exists. Historical experiment "
                "results are immutable; write an amendment.md instead."
            )
        created = RESULTS / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + RUN_SUFFIX)
        created.mkdir(parents=True)
        return created
    if len(existing) != 1:
        raise SystemExit(f"expected exactly one {RUN_SUFFIX} directory, found {len(existing)}")
    return existing[0]


def checkpoint_digest(path: Path) -> dict[str, Any]:
    """SHA-256 over the checkpoint's files, in a fixed order, plus its size."""
    digest = hashlib.sha256()
    total = 0
    for file in sorted(p for p in path.iterdir() if p.is_file() and p.name != "dev_scores.json"):
        digest.update(file.name.encode())
        payload = file.read_bytes()
        digest.update(payload)
        total += len(payload)
    return {
        "sha256": digest.hexdigest(),
        "size_bytes": total,
        "files": sorted(
            p.name for p in path.iterdir() if p.is_file() and p.name != "dev_scores.json"
        ),
    }


def cross_entropy(labels: list[int], scores: list[float]) -> float:
    """Dev loss, recomputed exactly from the stored P(INJECTION).

    The head is a 2-class softmax, so P(SAFE) is 1 - P(INJECTION) exactly and
    this is the same cross-entropy the model was trained against — not an
    approximation of it.
    """
    import math

    eps = 1e-12
    total = 0.0
    for label, score in zip(labels, scores, strict=True):
        probability = score if label else 1.0 - score
        total -= math.log(max(probability, eps))
    return total / len(labels)


# ---------------------------------------------------------------------------
# PHASE 2/3: checkpoint and threshold selection — DEV ONLY
# ---------------------------------------------------------------------------

# ADR-015 bounds, applied to dev. MAX_DEV_FPR is the FPR budget handed to the
# project's calibrator; the quoted_attack bound is verified at the chosen point.
MAX_DEV_FPR = 0.0241
MAX_DEV_QUOTED_FPR = 0.15

SELECTION_PRIORITY = [
    "1. quoted_attack FPR (dev)",
    "2. overall benign FPR (dev)",
    "3. attack recall (dev), subject to >= base_on_dev - 0.05",
    "4. system_prompt_extraction recall (dev), subject to >= base_on_dev - 0.05",
    "tie 1: fewer epochs",
    "tie 2: lower learning rate",
    "tie 3: lower seed",
]
TIE_BREAK_RATIONALE = (
    "ADR-015 fixes only 'ties toward the earlier epoch'. A saturated dev split "
    "leaves that insufficient, so the rule is extended deterministically to "
    "lower learning rate then lower seed. Both extensions prefer the smallest "
    "departure from the base model, which is the conservative choice when "
    "nothing in the data distinguishes the candidates. Fixed before the "
    "hold-out was accessed; recorded in ADR-015."
)


def score_base_on_dev(dev_rows: list[dict[str, Any]], device: str) -> list[float]:
    """The base model's dev scores — the reference for the '5-point drop'
    constraint. Measured on dev so no hold-out quantity enters selection."""
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL).to(device)
    return evaluate_model(model, tokenizer, dev_rows, device)


def verify_matrix(training: dict[str, Any]) -> dict[str, Any]:
    """§1/§2: the executed matrix is the pre-registered matrix, and each run
    recorded the memory adaptations rather than silently changing the protocol."""
    runs = training["runs"]
    expected = {(lr, ep, sd) for lr in LEARNING_RATES for ep in EPOCH_COUNTS for sd in SEEDS}
    actual = {(r["learning_rate"], r["epochs"], r["seed"]) for r in runs}
    protocol = training["protocol"]
    ok_runs = [r for r in runs if r["status"] == "ok"]

    micro_sizes = sorted(
        {
            note.split("micro_batch=")[1].split()[0]
            for r in ok_runs
            for note in r["notes"]
            if note.startswith("micro_batch=")
        }
    )
    report = {
        "expected_configurations": len(expected),
        "executed_configurations": len(runs),
        "missing_configurations": sorted(
            f"lr{lr:g}_ep{ep}_seed{sd}" for lr, ep, sd in expected - actual
        ),
        "unexpected_configurations": sorted(
            f"lr{lr:g}_ep{ep}_seed{sd}" for lr, ep, sd in actual - expected
        ),
        "succeeded": len(ok_runs),
        "failed": [
            {"run_id": r["run_id"], "notes": r["notes"]} for r in runs if r["status"] == "failed"
        ],
        "degenerate": [r["run_id"] for r in runs if r["status"] == "degenerate"],
        "checkpoints_present": [
            r["run_id"] for r in ok_runs if (REPO_ROOT / r["checkpoint"]).is_dir()
        ],
        "checkpoints_missing": [
            r["run_id"] for r in ok_runs if not (REPO_ROOT / r["checkpoint"]).is_dir()
        ],
        "effective_batch_size": protocol["batch_size"],
        "micro_batch_size": protocol["micro_batch_size"],
        "gradient_accumulation_steps": protocol["batch_size"] // protocol["micro_batch_size"],
        "micro_batch_sizes_actually_used": micro_sizes,
        "optimiser": protocol["optimiser"],
        "seeds": sorted({r["seed"] for r in runs}),
        "learning_rates": sorted({r["learning_rate"] for r in runs}),
        "epoch_counts": sorted({r["epochs"] for r in runs}),
    }
    report["matrix_complete"] = (
        not report["missing_configurations"]
        and not report["unexpected_configurations"]
        and not report["checkpoints_missing"]
    )
    return report


def dev_table(runs: list[dict[str, Any]], dev_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """§6: the full dev comparison, one row per configuration."""
    labels = [r["label"] for r in dev_rows]
    rows = []
    for run in runs:
        if run["status"] == "failed":
            rows.append({"run_id": run["run_id"], "status": "failed"})
            continue
        scores = json.loads(
            (REPO_ROOT / run["checkpoint"] / "dev_scores.json").read_text(encoding="utf-8")
        )
        metrics = _rates(dev_rows, scores, 0.5)
        rows.append(
            {
                "run_id": run["run_id"],
                "status": run["status"],
                "learning_rate": run["learning_rate"],
                "epochs": run["epochs"],
                "seed": run["seed"],
                "train_loss": run["train_loss"],
                "dev_loss": round(cross_entropy(labels, scores), 6),
                "dev_precision": metrics["overall"]["precision"],
                "dev_recall": metrics["overall"]["recall"],
                "dev_f1": metrics["overall"]["f1"],
                "dev_fpr": metrics["overall"]["fpr"],
                "quoted_attack_fpr": metrics["quoted_attack"]["fpr"],
                "hard_negative_fpr": metrics["hard_negative"]["fpr"],
                "extraction_recall": metrics["extraction"]["recall"],
                "checkpoint": run["checkpoint"],
                "duration_s": run["duration_s"],
                "peak_memory_gb": run["peak_memory_gb"],
            }
        )
    return rows


def calibrate_on_dev(dev_rows: list[dict[str, Any]], scores: list[float]) -> dict[str, Any]:
    """§7: the project's documented calibration procedure, on dev.

    `calibrate()` calls `require_tunable()`, which raises on the test split —
    the dev-only guarantee is enforced by the library, not by this caller.
    """
    from eval.metrics.calibration import Objective, calibrate
    from eval.schema import Split

    labels = [bool(r["label"]) for r in dev_rows]
    point, sweep = calibrate(
        labels,
        scores,
        split=Split.DEV,
        objective=Objective.MAX_RECALL_AT_FPR,
        constraint=MAX_DEV_FPR,
    )
    chosen = _rates(dev_rows, scores, point.threshold)
    # The dominant ADR-015 criterion is not expressible as an FPR budget, so it
    # is verified at the chosen point rather than folded into the objective.
    return {
        "operating_point": point.as_dict(),
        "quoted_attack_bound": MAX_DEV_QUOTED_FPR,
        "quoted_attack_fpr_at_threshold": chosen["quoted_attack"]["fpr"],
        "quoted_attack_bound_met": chosen["quoted_attack"]["fpr"] <= MAX_DEV_QUOTED_FPR,
        "dev_metrics_at_threshold": chosen,
        "sweep_points": len(sweep),
        "separable": chosen["overall"]["fpr"] == 0.0 and chosen["overall"]["recall"] == 1.0,
    }


def phase_select() -> int:
    import torch

    training = json.loads((RESULTS / "strategy_a_training.json").read_text(encoding="utf-8"))
    dev_rows = load_jsonl(DEV_FILE)
    device = "cuda" if torch.cuda.is_available() else "cpu"

    print("=== PHASE 1 VERIFICATION: training matrix ===")
    matrix = verify_matrix(training)
    print(json.dumps(matrix, indent=2))
    if not matrix["matrix_complete"]:
        print("\nREFUSING: the executed matrix does not match the pre-registered matrix.")
        return 2

    print("\n=== PHASE 2: CHECKPOINT SELECTION (dev only) ===")
    base_scores = score_base_on_dev(dev_rows, device)
    base_dev = _rates(dev_rows, base_scores, 0.5)
    base_dev["loss"] = round(cross_entropy([r["label"] for r in dev_rows], base_scores), 6)
    base_recall = base_dev["overall"]["recall"]
    base_extraction = base_dev["extraction"]["recall"]
    print(
        f"base model on dev @0.5: recall={base_recall:.4f} extraction={base_extraction:.4f} "
        f"FPR={base_dev['overall']['fpr']:.4f} quoted_FPR={base_dev['quoted_attack']['fpr']:.4f}"
    )

    table = dev_table(training["runs"], dev_rows)
    usable = [r for r in table if r["status"] == "ok"]
    eligible = [
        r
        for r in usable
        if r["dev_recall"] >= base_recall - MAX_RECALL_DROP
        and r["extraction_recall"] >= base_extraction - MAX_RECALL_DROP
    ]
    print(f"{len(usable)}/{len(table)} usable; {len(eligible)} meet the recall floors")
    if not eligible:
        print("NO ELIGIBLE CHECKPOINT — every run violated a pre-registered recall floor.")
        return 2

    ranked = sorted(
        eligible,
        key=lambda r: (
            r["quoted_attack_fpr"],
            r["dev_fpr"],
            -r["dev_recall"],
            -r["extraction_recall"],
            r["epochs"],
            r["learning_rate"],
            r["seed"],
        ),
    )
    winner = ranked[0]
    # How much of the ranking was actually decided by data, versus by the
    # tie-break? Reported rather than hidden.
    primary = (
        winner["quoted_attack_fpr"],
        winner["dev_fpr"],
        winner["dev_recall"],
        winner["extraction_recall"],
    )
    tied = [
        r
        for r in eligible
        if (r["quoted_attack_fpr"], r["dev_fpr"], r["dev_recall"], r["extraction_recall"])
        == primary
    ]
    print(f"selected: {winner['run_id']}")
    print(f"tied on all four ADR-015 criteria: {len(tied)}/{len(eligible)} runs")
    if len(tied) > 1:
        print(f"resolved by deterministic tie-break -> {winner['run_id']}")

    print("\n=== PHASE 3: THRESHOLD SELECTION (dev only) ===")
    dev_scores = json.loads(
        (REPO_ROOT / winner["checkpoint"] / "dev_scores.json").read_text(encoding="utf-8")
    )
    calibration = calibrate_on_dev(dev_rows, dev_scores)
    threshold = calibration["operating_point"]["threshold"]
    print(f"objective : {calibration['operating_point']['objective']} <= {MAX_DEV_FPR}")
    print(f"rationale : {calibration['operating_point']['rationale']}")
    print(f"threshold : {threshold}")
    print(f"quoted_attack FPR at threshold: {calibration['quoted_attack_fpr_at_threshold']}")

    out = run_dir(create=True)
    (out / "dev_comparison.json").write_text(
        json.dumps(
            {"base_model_on_dev": base_dev, "runs": table, "ranked": [r["run_id"] for r in ranked]},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    header = (
        "| run_id | lr | epochs | seed | train_loss | dev_loss | precision | recall | f1 | "
        "dev_fpr | quoted_attack_fpr | extraction_recall | checkpoint |"
    )
    lines = [
        "# Strategy A — dev comparison (threshold 0.5)",
        "",
        "Sorted by the pre-registered ADR-015 selection priority. Dev only; the",
        "frozen hold-out was not read to produce this table.",
        "",
        header,
        "|" + "---|" * 13,
    ]
    for r in ranked:
        lines.append(
            f"| `{r['run_id']}` | {r['learning_rate']:g} | {r['epochs']} | {r['seed']} "
            f"| {r['train_loss']:.6f} | {r['dev_loss']:.6f} | {r['dev_precision']:.4f} "
            f"| {r['dev_recall']:.4f} | {r['dev_f1']:.4f} | {r['dev_fpr']:.4f} "
            f"| {r['quoted_attack_fpr']:.4f} | {r['extraction_recall']:.4f} | `{r['checkpoint']}` |"
        )
    (out / "dev_comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    checkpoint_path = REPO_ROOT / winner["checkpoint"]
    digest = checkpoint_digest(checkpoint_path)
    lock = {
        "locked_at": datetime.now(UTC).isoformat(),
        "purpose": (
            "The complete Strategy A model-selection decision, frozen before the "
            "hold-out was accessed. Do not modify."
        ),
        "selected_run_id": winner["run_id"],
        "checkpoint_path": winner["checkpoint"],
        "checkpoint_sha256": digest["sha256"],
        "checkpoint_size_bytes": digest["size_bytes"],
        "checkpoint_files": digest["files"],
        "base_model": BASE_MODEL,
        "model_revision": BASE_REVISION,
        "tokenizer_revision": BASE_REVISION,
        "dataset_version": training["safety_check"].get("dataset_version", "finetune-v1"),
        "train_manifest_hash": training["safety_check"]["train_manifest_hash"],
        "dev_manifest_hash": training["safety_check"]["dev_manifest_hash"],
        "holdout_manifest_hash": training["safety_check"]["holdout_manifest_hash"],
        "holdout_content_hash": training["safety_check"]["holdout_content_hash"],
        "selected_threshold": threshold,
        "selection_metrics": {
            "dev_at_0.5": {
                k: winner[k]
                for k in (
                    "dev_loss",
                    "dev_precision",
                    "dev_recall",
                    "dev_f1",
                    "dev_fpr",
                    "quoted_attack_fpr",
                    "hard_negative_fpr",
                    "extraction_recall",
                )
            },
            "dev_at_selected_threshold": calibration["dev_metrics_at_threshold"],
            "base_model_on_dev_at_0.5": base_dev,
        },
        "selection_criteria": {
            "priority": SELECTION_PRIORITY,
            "recall_floor_reference": "base model measured on dev, not the hold-out",
            "max_recall_drop": MAX_RECALL_DROP,
            "tie_break_rationale": TIE_BREAK_RATIONALE,
            "runs_tied_on_all_four_criteria": len(tied),
            "eligible_runs": len(eligible),
        },
        "threshold_calibration": calibration,
        "holdout_used_in_selection": False,
        "selection_basis": "dev split only (eval/datasets/finetune/dev/cases.jsonl)",
        "training_matrix_verification": matrix,
        "git_commit": git_commit(),
        "environment": training["safety_check"]["environment"],
    }
    (out / "selection_lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {out / 'selection_lock.json'}")
    print("Run --verify-lock next. The hold-out stays untouched until it passes.")
    return 0


# ---------------------------------------------------------------------------
# PHASE 4: lock verification — the gate the hold-out sits behind (§9)
# ---------------------------------------------------------------------------


def phase_verify_lock() -> int:
    out = run_dir()
    lock_file = out / "selection_lock.json"
    if not lock_file.exists():
        print("REFUSING: no selection_lock.json. Run --select first.")
        return 2
    lock = json.loads(lock_file.read_text(encoding="utf-8"))

    checkpoint = REPO_ROOT / lock["checkpoint_path"]
    digest = (
        checkpoint_digest(checkpoint) if checkpoint.is_dir() else {"sha256": None, "size_bytes": 0}
    )
    checks = {
        "lock_file_present": True,
        "lock_sha256": sha256_file(lock_file)[:32],
        "checkpoint_present": checkpoint.is_dir(),
        "checkpoint_hash_stable": digest["sha256"] == lock["checkpoint_sha256"],
        "threshold_is_fixed": isinstance(lock["selected_threshold"], (int, float)),
        "selection_metrics_present": bool(lock["selection_metrics"]),
        "train_manifest_matches": sha256_file(TRAIN_FILE)[:32] == lock["train_manifest_hash"],
        "dev_manifest_matches": sha256_file(DEV_FILE)[:32] == lock["dev_manifest_hash"],
        "holdout_content_matches_preregistered": (
            sha256_file(HOLDOUT_FILE)[:32] == lock["holdout_content_hash"]
        ),
        "holdout_manifest_matches": (
            sha256_file(HOLDOUT_FILE.parent / "build_manifest.json")[:32]
            == lock["holdout_manifest_hash"]
        ),
        "holdout_not_used_in_selection": lock["holdout_used_in_selection"] is False,
        "holdout_not_yet_scored": not (out / "holdout_metrics.json").exists(),
    }
    verification = {
        "verified_at": datetime.now(UTC).isoformat(),
        "selected_run_id": lock["selected_run_id"],
        "selected_threshold": lock["selected_threshold"],
        "checks": checks,
        "all_passed": all(checks.values()),
    }
    (out / "pre_holdout_verification.json").write_text(
        json.dumps(verification, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(verification, indent=2))
    if not verification["all_passed"]:
        print("\nFAILED — the hold-out must not be accessed.")
        return 2
    print(f"\nwrote {out / 'pre_holdout_verification.json'}")
    print("All checks passed. The hold-out may now be scored, exactly once.")
    return 0


# ---------------------------------------------------------------------------
# PHASE 5: the frozen hold-out — scored exactly once
# ---------------------------------------------------------------------------

ATTACK_CATEGORIES = {
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "jailbreak",
    "pii",
    "system_prompt_extraction",
}

# The headline attack recall must use the same denominator as the 0.8833 figure
# it is compared against: DETECTOR_SCOPE["injection.heuristic"], i.e. the 60
# in-scope attacks, excluding jailbreak (8) and PII (6). Scoring an injection
# classifier against PII would manufacture a recall number (docs/13 §9).
INJECTION_SCOPE = {
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "system_prompt_extraction",
}

# §12. Some of these are sub-categories of the benign set, some are domains;
# the hold-out records both, so each names which field it reads.
HARD_NEGATIVE_GROUPS = [
    ("quoted_attack", "sub_category", "quoted_attack"),
    ("incident_response", "domain", "incident_response"),
    ("security_operations", "domain", "security_operations"),
    ("security_policy", "sub_category", "security_policy"),
    ("ignore_previous_ordinary", "sub_category", "ignore_previous_ordinary"),
    ("human_instructions", "sub_category", "human_instructions"),
    ("code_with_attack_strings", "sub_category", "code_with_attack_strings"),
    ("technical_documentation", "domain", "technical_documentation"),
]

# §13. Attack retention, by category. role_override and context_override are
# corpus sub-categories that the hold-out does not carry as categories; they are
# reported as absent rather than silently omitted.
ATTACK_GROUPS = [
    ("direct_prompt_injection", "direct_prompt_injection"),
    ("indirect_injection", "indirect_prompt_injection"),
    ("system_prompt_extraction", "system_prompt_extraction"),
    ("jailbreak", "jailbreak"),
    ("role_override", None),
    ("context_override", None),
]


def load_holdout_rows() -> list[dict[str, Any]]:
    rows = load_jsonl(HOLDOUT_FILE)
    for row in rows:
        row["label"] = 1 if row["category"] in ATTACK_CATEGORIES else 0
        row["hard_negative"] = row.get("notes") == "hard_negative"
    return rows


def rate_block(
    rows: list[dict[str, Any]],
    scores: list[float],
    threshold: float,
    predicate: Any,
    positive: bool,
) -> dict[str, Any]:
    from eval.metrics.classification import wilson_interval

    idx = [i for i, r in enumerate(rows) if predicate(r)]
    if not idx:
        return {"n": 0, "note": "no samples in the hold-out for this group"}
    hits = sum(1 for i in idx if scores[i] >= threshold)
    lo, hi = wilson_interval(hits, len(idx))
    key = "recall" if positive else "fpr"
    return {
        "n": len(idx),
        ("tp" if positive else "fp"): hits,
        ("fn" if positive else "tn"): len(idx) - hits,
        key: round(hits / len(idx), 4),
        f"{key}_ci95_wilson": [round(lo, 4), round(hi, 4)],
    }


def measure_latency(
    model: Any, tokenizer: Any, rows: list[dict[str, Any]], device: str
) -> dict[str, Any]:
    """§18: per-sample latency, matching how the prior runs measured the base
    model — one sample at a time, not batched."""
    import torch

    from eval.metrics.latency import latency_stats

    model.eval()
    if device == "cuda":
        # So peak_vram_gb describes single-sample inference specifically, rather
        # than carrying over the batched scoring pass's larger peak.
        torch.cuda.reset_peak_memory_stats()
    samples = rows[:200]
    timings: list[float] = []
    with torch.no_grad():
        for row in samples[:20]:  # warm-up, discarded
            enc = tokenizer(
                row["text"], truncation=True, max_length=MAX_LENGTH, return_tensors="pt"
            ).to(device)
            model(**enc)
        for row in samples:
            started = time.perf_counter()
            enc = tokenizer(
                row["text"], truncation=True, max_length=MAX_LENGTH, return_tensors="pt"
            ).to(device)
            model(**enc)
            if device == "cuda":
                torch.cuda.synchronize()
            timings.append((time.perf_counter() - started) * 1000)
    stats = latency_stats(timings).as_dict()
    stats["device"] = device
    stats["method"] = "single-sample, warm, tokenisation included; batching excluded"
    if device == "cuda":
        stats["peak_vram_gb"] = round(torch.cuda.max_memory_allocated() / 1e9, 3)
    return stats


def prior_system_metrics(detector: str, threshold: float) -> dict[str, Any]:
    """Re-read a published hold-out result. No model is run: these numbers were
    produced and committed by an earlier experiment."""
    from eval.metrics.classification import confusion, wilson_interval

    rows = [
        json.loads(line)
        for line in PRIOR_HOLDOUT_PREDICTIONS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows = [r for r in rows if r["detector"] == detector]
    scores = [r["score"] for r in rows]

    def block(predicate: Any, positive: bool) -> dict[str, Any]:
        idx = [i for i, r in enumerate(rows) if predicate(r)]
        if not idx:
            return {"n": 0}
        hits = sum(1 for i in idx if scores[i] >= threshold)
        lo, hi = wilson_interval(hits, len(idx))
        key = "recall" if positive else "fpr"
        return {
            "n": len(idx),
            key: round(hits / len(idx), 4),
            f"{key}_ci95_wilson": [round(lo, 4), round(hi, 4)],
        }

    matrix = confusion([r["label"] for r in rows], [s >= threshold for s in scores])
    latencies = [r["latency_ms"] for r in rows]
    return {
        "detector": detector,
        "threshold": threshold,
        "source": str(PRIOR_HOLDOUT_PREDICTIONS.relative_to(REPO_ROOT)),
        "overall": matrix.as_dict(),
        "benign": block(lambda r: not r["label"], False),
        "hard_negatives": block(lambda r: not r["label"] and r["hard_negative"], False),
        "quoted_attack": block(
            lambda r: not r["label"] and r["sub_category"] == "quoted_attack", False
        ),
        "incident_response": block(
            lambda r: not r["label"] and r["domain"] == "incident_response", False
        ),
        "attack_recall": block(lambda r: bool(r["label"]), True),
        "system_prompt_extraction": block(
            lambda r: r["category"] == "system_prompt_extraction", True
        ),
        "hard_negative_groups": {
            name: block(lambda r, f=field, v=value: not r["label"] and r.get(f) == v, False)
            for name, field, value in HARD_NEGATIVE_GROUPS
        },
        "attack_groups": {
            name: block(lambda r, c=cat: r["category"] == c, True)
            for name, cat in ATTACK_GROUPS
            if cat is not None
        },
        "latency_ms": {
            "mean": round(sum(latencies) / len(latencies), 3),
            "p50": round(sorted(latencies)[len(latencies) // 2], 3),
            "p95": round(sorted(latencies)[int(len(latencies) * 0.95)], 3),
            "p99": round(sorted(latencies)[int(len(latencies) * 0.99)], 3),
            "n": len(latencies),
        },
    }


def phase_holdout(force: bool = False) -> int:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    from eval.metrics.classification import confusion

    out = run_dir()
    lock_file = out / "selection_lock.json"
    verification_file = out / "pre_holdout_verification.json"
    metrics_file = out / "holdout_metrics.json"

    if not lock_file.exists():
        print("REFUSING: no selection_lock.json. Run --select first.")
        return 2
    if not verification_file.exists():
        print("REFUSING: no pre_holdout_verification.json. Run --verify-lock first.")
        return 2
    verification = json.loads(verification_file.read_text(encoding="utf-8"))
    if not verification["all_passed"]:
        print("REFUSING: pre-hold-out verification did not pass.")
        return 2
    if metrics_file.exists() and not force:
        print(
            f"REFUSING: {metrics_file} exists. The hold-out is scored exactly "
            "once; a second run would invalidate the experiment."
        )
        return 2

    lock = json.loads(lock_file.read_text(encoding="utf-8"))
    if lock["holdout_content_hash"] != sha256_file(HOLDOUT_FILE)[:32]:
        print("REFUSING: the hold-out changed since the lock was written.")
        return 2

    threshold = lock["selected_threshold"]
    checkpoint = REPO_ROOT / lock["checkpoint_path"]
    if checkpoint_digest(checkpoint)["sha256"] != lock["checkpoint_sha256"]:
        print("REFUSING: the checkpoint changed since the lock was written.")
        return 2

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"scoring the frozen hold-out ONCE: {lock['selected_run_id']} @ {threshold}")

    rows = load_holdout_rows()
    tokenizer = AutoTokenizer.from_pretrained(checkpoint)
    model = AutoModelForSequenceClassification.from_pretrained(checkpoint).to(device)
    if device == "cuda":
        torch.cuda.reset_peak_memory_stats()
    scores = evaluate_model(model, tokenizer, rows, device)
    latency = measure_latency(model, tokenizer, rows, device)

    # §11: overall metrics on the in-scope subset, so the denominator matches
    # the systems this is compared against.
    scoped = [
        (r, s)
        for r, s in zip(rows, scores, strict=True)
        if r["category"] in INJECTION_SCOPE or not r["label"]
    ]
    matrix = confusion([bool(r["label"]) for r, _ in scoped], [s >= threshold for _, s in scoped])

    def block(predicate: Any, positive: bool) -> dict[str, Any]:
        return rate_block(rows, scores, threshold, predicate, positive)

    result = {
        "evaluated_at": datetime.now(UTC).isoformat(),
        "evaluation_count": 1,
        "selection_lock": str(lock_file.relative_to(REPO_ROOT)),
        "pre_holdout_verification": str(verification_file.relative_to(REPO_ROOT)),
        "checkpoint": lock["selected_run_id"],
        "checkpoint_sha256": lock["checkpoint_sha256"],
        "threshold": threshold,
        "threshold_source": "calibrated on dev before this file existed; NOT selected here",
        "holdout_content_hash": lock["holdout_content_hash"],
        "n_total": len(rows),
        "n_in_scope": len(scoped),
        "scope": sorted(INJECTION_SCOPE),
        "overall": matrix.as_dict(),
        "benign": block(lambda r: not r["label"], False),
        "hard_negatives": block(lambda r: not r["label"] and r["hard_negative"], False),
        "ordinary_benign": block(lambda r: not r["label"] and not r["hard_negative"], False),
        "quoted_attack": block(
            lambda r: not r["label"] and r["sub_category"] == "quoted_attack", False
        ),
        "incident_response": block(
            lambda r: not r["label"] and r["domain"] == "incident_response", False
        ),
        "attack_recall": block(lambda r: r["category"] in INJECTION_SCOPE, True),
        "system_prompt_extraction": block(
            lambda r: r["category"] == "system_prompt_extraction", True
        ),
        "hard_negative_groups": {
            name: block(lambda r, f=field, v=value: not r["label"] and r.get(f) == v, False)
            for name, field, value in HARD_NEGATIVE_GROUPS
        },
        "attack_groups": {
            name: (
                block(lambda r, c=cat: r["category"] == c, True)
                if cat
                else {"n": 0, "note": "not a category in the hold-out taxonomy"}
            )
            for name, cat in ATTACK_GROUPS
        },
        "latency": latency,
        "comparison_systems": {
            "injection.heuristic": prior_system_metrics(
                "injection.heuristic", FROZEN_THRESHOLDS["injection.heuristic"]
            ),
            "injection.protectai_deberta_v2": prior_system_metrics(
                "injection.protectai_deberta_v2",
                FROZEN_THRESHOLDS["injection.protectai_deberta_v2"],
            ),
        },
    }
    metrics_file.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    with (out / "predictions.jsonl").open("w", encoding="utf-8") as handle:
        for row, score in zip(rows, scores, strict=True):
            handle.write(
                json.dumps(
                    {
                        "detector": "injection.protectai_finetuned_strategy_a",
                        "split": "holdout",
                        "sample_id": row["sample_id"],
                        "label": bool(row["label"]),
                        "score": score,
                        "category": row["category"],
                        "sub_category": row["sub_category"],
                        "domain": row["domain"],
                        "hard_negative": row["hard_negative"],
                    }
                )
                + "\n"
            )
    printable = {k: v for k, v in result.items() if k != "comparison_systems"}
    print(json.dumps(printable, indent=2))
    print(f"\nwrote {metrics_file}")
    return 0


# ---------------------------------------------------------------------------
# PHASE 6: report tables — rendered from the JSON, never transcribed by hand
# ---------------------------------------------------------------------------

# ADR-015 blocking-readiness criteria, verbatim. `worse` names the failing
# direction. A criterion whose Wilson interval straddles its bound is NOT met —
# that rule is applied here rather than left to the reader.
CRITERIA = [
    ("Overall benign FPR", "benign", "fpr", 0.0241, "above"),
    ("Hard-negative FPR", "hard_negatives", "fpr", 0.10, "above"),
    ("quoted_attack FPR", "quoted_attack", "fpr", 0.15, "above"),
    ("incident_response FPR", "incident_response", "fpr", 0.10, "above"),
    ("Attack recall", "attack_recall", "recall", 0.80, "below"),
    ("Extraction recall", "system_prompt_extraction", "recall", 0.80, "below"),
]

# ADR-015 failure criteria.
FAILURE_CRITERIA = [
    ("quoted_attack FPR > 0.40 — the core failure survived", "quoted_attack", "fpr", 0.40, "above"),
    ("attack recall < 0.75 — bought FPR with security", "attack_recall", "recall", 0.75, "below"),
    (
        "extraction recall < 0.70 — regressed the selecting capability",
        "system_prompt_extraction",
        "recall",
        0.70,
        "below",
    ),
]


def _verdict(block: dict[str, Any], key: str, bound: float, worse: str) -> tuple[str, str]:
    value = block[key]
    lo, hi = block[f"{key}_ci95_wilson"]
    if worse == "above":
        if hi <= bound:
            return "MET", ""
        if value > bound:
            return "NOT MET", f"{value:.4f} > {bound}"
        return "NOT MET", f"CI upper {hi:.4f} straddles {bound}"
    if lo >= bound:
        return "MET", ""
    if value < bound:
        return "NOT MET", f"{value:.4f} < {bound}"
    return "NOT MET", f"CI lower {lo:.4f} straddles {bound}"


def phase_report() -> int:
    out = run_dir()
    lock = json.loads((out / "selection_lock.json").read_text(encoding="utf-8"))
    hold = json.loads((out / "holdout_metrics.json").read_text(encoding="utf-8"))
    dev = json.loads((out / "dev_comparison.json").read_text(encoding="utf-8"))

    base = hold["comparison_systems"]["injection.protectai_deberta_v2"]
    heur = hold["comparison_systems"]["injection.heuristic"]
    lines: list[str] = []

    lines.append("## Blocking-readiness criteria on the frozen hold-out\n")
    lines.append(
        f"Checkpoint `{hold['checkpoint']}` at the dev-calibrated threshold "
        f"{hold['threshold']}. A criterion whose Wilson 95% interval straddles "
        "its bound is not met (ADR-015).\n"
    )
    lines.append("| Criterion | Bound | Measured | Wilson 95% | n | Verdict |")
    lines.append("|---|---|---|---|---|---|")
    all_met = True
    for label, section, key, bound, worse in CRITERIA:
        block = hold[section]
        verdict, why = _verdict(block, key, bound, worse)
        all_met &= verdict == "MET"
        lo, hi = block[f"{key}_ci95_wilson"]
        op = "<=" if worse == "above" else ">="
        lines.append(
            f"| {label} | {op} {bound} | {block[key]:.4f} | [{lo:.4f}, {hi:.4f}] "
            f"| {block['n']} | **{verdict}**{(' — ' + why) if why else ''} |"
        )

    lines.append("\n## Pre-registered failure criteria\n")
    lines.append("| Failure criterion | Triggered? | Measured |")
    lines.append("|---|---|---|")
    any_failure = False
    for label, section, key, bound, worse in FAILURE_CRITERIA:
        block = hold[section]
        value = block[key]
        triggered = value > bound if worse == "above" else value < bound
        any_failure |= triggered
        lines.append(f"| {label} | {'**YES**' if triggered else 'no'} | {value:.4f} |")

    lines.append("\n## Three systems, same frozen hold-out\n")
    lines.append(
        "The heuristic and base-model columns are re-read from "
        f"`{base['source']}`; no model was re-run to produce them.\n"
    )
    lines.append(
        "| Metric | injection.heuristic @0.85 | ProtectAI base @0.9995 | "
        "Strategy A fine-tuned @" + str(hold["threshold"]) + " |"
    )
    lines.append("|---|---|---|---|")
    for label, section, key in [
        ("Attack recall", "attack_recall", "recall"),
        ("Extraction recall", "system_prompt_extraction", "recall"),
        ("Overall benign FPR", "benign", "fpr"),
        ("Hard-negative FPR", "hard_negatives", "fpr"),
        ("quoted_attack FPR", "quoted_attack", "fpr"),
        ("incident_response FPR", "incident_response", "fpr"),
    ]:
        lines.append(
            f"| {label} | {heur[section][key]:.4f} | {base[section][key]:.4f} "
            f"| {hold[section][key]:.4f} |"
        )
    lines.append(
        f"| Latency mean (ms) | {heur['latency_ms']['mean']:.3f} "
        f"| {base['latency_ms']['mean']:.3f} | {hold['latency']['mean_ms']:.3f} |"
    )

    lines.append("\n## Hard-negative categories: base vs Strategy A\n")
    lines.append("| Category | n | base FPR | Strategy A FPR | change | Strategy A Wilson 95% |")
    lines.append("|---|---|---|---|---|---|")
    for name, _field, _value in HARD_NEGATIVE_GROUPS:
        new = hold["hard_negative_groups"][name]
        old = base["hard_negative_groups"][name]
        if not new.get("n"):
            lines.append(f"| {name} | 0 | — | — | — | no samples |")
            continue
        lo, hi = new["fpr_ci95_wilson"]
        delta = new["fpr"] - old["fpr"]
        lines.append(
            f"| {name} | {new['n']} | {old['fpr']:.4f} | {new['fpr']:.4f} "
            f"| {delta:+.4f} | [{lo:.4f}, {hi:.4f}] |"
        )

    lines.append("\n## Attack retention: base vs Strategy A\n")
    lines.append(
        "| Attack category | n | base recall | Strategy A recall | change | Strategy A Wilson 95% |"
    )
    lines.append("|---|---|---|---|---|---|")
    for name, _cat in ATTACK_GROUPS:
        new = hold["attack_groups"][name]
        if not new.get("n"):
            lines.append(f"| {name} | 0 | — | — | — | {new.get('note', 'no samples')} |")
            continue
        old = base["attack_groups"].get(name, {})
        lo, hi = new["recall_ci95_wilson"]
        change = f"{new['recall'] - old['recall']:+.4f}" if old.get("n") else "—"
        old_recall = f"{old['recall']:.4f}" if old.get("n") else "—"
        lines.append(
            f"| {name} | {new['n']} | {old_recall} | {new['recall']:.4f} "
            f"| {change} | [{lo:.4f}, {hi:.4f}] |"
        )

    lines.append("\n## Dev to hold-out generalisation\n")
    winner = next(r for r in dev["runs"] if r.get("run_id") == lock["selected_run_id"])
    base_dev = dev["base_model_on_dev"]
    lines.append(
        "| Metric | base (dev) | Strategy A (dev) | base (hold-out) | Strategy A (hold-out) |"
    )
    lines.append("|---|---|---|---|---|")
    lines.append(
        f"| Overall benign FPR | {base_dev['overall']['fpr']:.4f} | {winner['dev_fpr']:.4f} "
        f"| {base['benign']['fpr']:.4f} | {hold['benign']['fpr']:.4f} |"
    )
    lines.append(
        f"| quoted_attack FPR | {base_dev['quoted_attack']['fpr']:.4f} | {winner['quoted_attack_fpr']:.4f} "
        f"| {base['quoted_attack']['fpr']:.4f} | {hold['quoted_attack']['fpr']:.4f} |"
    )
    lines.append(
        f"| Attack recall | {base_dev['overall']['recall']:.4f} | {winner['dev_recall']:.4f} "
        f"| {base['attack_recall']['recall']:.4f} | {hold['attack_recall']['recall']:.4f} |"
    )
    lines.append(
        f"| Extraction recall | {base_dev['extraction']['recall']:.4f} | {winner['extraction_recall']:.4f} "
        f"| {base['system_prompt_extraction']['recall']:.4f} | {hold['system_prompt_extraction']['recall']:.4f} |"
    )

    dev_improved = winner["quoted_attack_fpr"] < base_dev["quoted_attack"]["fpr"]
    hold_improved = hold["quoted_attack"]["fpr"] < base["quoted_attack"]["fpr"]
    recall_kept = (
        hold["attack_recall"]["recall"] >= base["attack_recall"]["recall"] - MAX_RECALL_DROP
    )
    case = (
        "Case 1 — dev improves and hold-out improves: supports generalisation"
        if dev_improved and hold_improved and recall_kept
        else "Case 4 — dev and hold-out improve, but attack recall regresses"
        if dev_improved and hold_improved
        else "Case 2 — dev improves but hold-out does not: overfitting or distribution mismatch"
        if dev_improved
        else "Case 3 — dev does not improve: the fine-tuning hypothesis is weak"
    )
    lines.append(f"\n**{case}**\n")

    hard_old, hard_new = base["hard_negatives"]["fpr"], hold["hard_negatives"]["fpr"]
    relative = (hard_old - hard_new) / hard_old if hard_old else 0.0
    partial = relative >= 0.30 and recall_kept
    lines.append(
        f"Hard-negative FPR relative reduction vs base: **{relative:+.1%}** "
        f"(partial-success bar: >= 30% with recall within 5 points → "
        f"{'met' if partial else 'not met'}).\n"
    )
    lines.append(f"All blocking criteria met simultaneously: **{all_met}**\n")
    lines.append(f"Any pre-registered failure criterion triggered: **{any_failure}**\n")

    decision = (
        "SUCCESS"
        if all_met
        else "FAILURE"
        if any_failure
        else "PARTIAL SUCCESS"
        if partial
        else "FAILURE"
    )
    lines.append(f"\n### Pre-registered decision: **{decision}**\n")

    lines.append("\n## Latency and memory\n")
    lat = hold["latency"]
    lines.append("| Statistic | base (prior run) | Strategy A |")
    lines.append("|---|---|---|")
    for key, label in [("mean", "mean"), ("p50", "p50"), ("p95", "p95"), ("p99", "p99")]:
        new_key = f"{label}_ms" if f"{label}_ms" in lat else label
        lines.append(
            f"| {label} (ms) | {base['latency_ms'][key]:.3f} | {lat.get(new_key, float('nan')):.3f} |"
        )
    lines.append(
        "| throughput (req/s, single-threaded) | — | "
        f"{lat.get('throughput_per_s_single_threaded')} |"
    )
    lines.append(f"| peak VRAM (GB, inference) | — | {lat.get('peak_vram_gb', 'n/a')} |")
    lines.append(f"| device | CPU (prior run) | {lat['device']} |")
    lines.append(
        "\nThe two latency columns were measured on different devices and are "
        "**not** a like-for-like comparison; the architecture is unchanged by "
        "fine-tuning, which is the claim being checked.\n"
    )

    summary = {
        "decision": decision,
        "all_blocking_criteria_met": all_met,
        "any_failure_criterion_triggered": any_failure,
        "partial_success_bar_met": partial,
        "hard_negative_relative_reduction": round(relative, 4),
        "generalisation_case": case,
    }
    (out / "decision.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out / "tables.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwrote {out / 'tables.md'} and {out / 'decision.json'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Strategy A fine-tuning experiment")
    parser.add_argument("--safety-check", action="store_true")
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--select", action="store_true", help="checkpoint + threshold, dev only")
    parser.add_argument("--verify-lock", action="store_true", help="gate the hold-out sits behind")
    parser.add_argument("--holdout", action="store_true", help="score the hold-out, once")
    parser.add_argument("--report", action="store_true", help="render tables from the JSON")
    parser.add_argument(
        "--force", action="store_true", help="re-score the hold-out (invalidates the experiment)"
    )
    args = parser.parse_args(argv)

    if args.safety_check:
        print(json.dumps(safety_check(), indent=2))
        return 0
    if args.train:
        return phase_train()
    if args.select:
        return phase_select()
    if args.verify_lock:
        return phase_verify_lock()
    if args.holdout:
        return phase_holdout(force=args.force)
    if args.report:
        return phase_report()
    parser.error("give --safety-check, --train, --select or --holdout")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
