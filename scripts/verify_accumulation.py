"""Prove that 4 x 4 gradient accumulation equals one batch of 16.

The Strategy A protocol pre-registers an effective batch size of 16. A 4 GB card
cannot hold a 16-sample forward pass alongside DeBERTa-v3-base's optimiser
state, so the implementation accumulates four micro-batches of four. That is
only legitimate if the resulting gradient is the *same vector*.

This checks it numerically against the real model and real training samples,
rather than asserting it in a comment. Dropout is disabled (`model.eval()`) so
the two paths are comparable; gradients still flow.

    uv run python -m scripts.verify_accumulation
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
TRAIN_FILE = REPO_ROOT / "eval" / "datasets" / "finetune" / "train" / "cases.jsonl"
BATCH_SIZE = 16
MICRO_BATCH_SIZE = 4


def main() -> int:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    rows = [json.loads(line) for line in TRAIN_FILE.read_text().splitlines() if line.strip()]
    # A batch with both classes present, or the comparison tests very little.
    batch = [r for r in rows if r["label"] == 1][:8] + [r for r in rows if r["label"] == 0][:8]
    if len(batch) != BATCH_SIZE:
        raise RuntimeError(f"expected {BATCH_SIZE} samples, built {len(batch)}")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL)
    model.eval()  # deterministic forward: no dropout divergence between paths

    def encode(items: list[dict]) -> tuple[dict, torch.Tensor]:
        enc = tokenizer(
            [r["text"] for r in items],
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
        )
        return enc, torch.tensor([r["label"] for r in items])

    # --- Path 1: one batch of 16 -------------------------------------------
    model.zero_grad(set_to_none=True)
    enc, labels = encode(batch)
    loss_full = model(**enc, labels=labels).loss
    loss_full.backward()
    full = {n: p.grad.detach().clone() for n, p in model.named_parameters() if p.grad is not None}

    # --- Path 2: four micro-batches of four, weighted by sample share -------
    model.zero_grad(set_to_none=True)
    loss_accumulated = 0.0
    for start in range(0, len(batch), MICRO_BATCH_SIZE):
        micro = batch[start : start + MICRO_BATCH_SIZE]
        enc, labels = encode(micro)
        loss = model(**enc, labels=labels).loss * (len(micro) / len(batch))
        loss.backward()
        loss_accumulated += float(loss.detach())
    accumulated = {
        n: p.grad.detach().clone() for n, p in model.named_parameters() if p.grad is not None
    }

    # --- Compare -------------------------------------------------------------
    if set(full) != set(accumulated):
        raise RuntimeError("the two paths produced gradients for different parameters")
    worst_name, worst_abs, worst_rel = "", 0.0, 0.0
    for name, grad in full.items():
        other = accumulated[name]
        abs_diff = (grad - other).abs().max().item()
        scale = grad.abs().max().item()
        rel = abs_diff / scale if scale > 0 else 0.0
        if rel > worst_rel:
            worst_name, worst_abs, worst_rel = name, abs_diff, rel

    loss_diff = abs(float(loss_full.detach()) - loss_accumulated)
    # In float64: the dot product over 184M elements loses too much precision in
    # float32 to be meaningful (it can even exceed 1).
    a = torch.cat([g.flatten() for g in full.values()]).double()
    b = torch.cat([accumulated[n].flatten() for n in full]).double()
    cosine = (a @ b / (a.norm() * b.norm())).item()

    print(f"parameters compared      : {len(full)}")
    print(f"loss  full={float(loss_full.detach()):.8f}  accumulated={loss_accumulated:.8f}")
    print(f"loss absolute difference : {loss_diff:.3e}")
    print(f"worst relative grad diff : {worst_rel:.3e}  ({worst_name}, abs {worst_abs:.3e})")
    print(f"gradient cosine similarity: {cosine:.10f}")

    # Tolerances are for float32 accumulation order, not for a real difference.
    ok = loss_diff < 1e-6 and worst_rel < 1e-4 and cosine > 1 - 1e-7
    print()
    print("VERDICT:", "EQUIVALENT — effective batch size is 16" if ok else "NOT EQUIVALENT")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
