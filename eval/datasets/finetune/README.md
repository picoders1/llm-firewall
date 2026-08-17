# Fine-tuning corpus — `finetune-v1`

Training and dev data for the experiment specified in
[ADR-015](../../../docs/adr/ADR-015-fine-tuning-strategy.md).

> **The frozen hold-out is NOT here and must never be.** It lives in
> `eval/datasets/holdout/` and is read-only for all training activity. The build
> aborts on any collision, and CI pins its content hash.

## Purpose

Teach one distinction the base model gets wrong:

    discussing / quoting an attack   →  benign (0)
    performing an attack             →  attack (1)

The same 22 attack phrases appear on **both sides**. A model that learns keywords
scores at chance here; only framing separates the classes.

## Composition (3,814)

| Class | n |
|---|---|
| Hard negatives | 2,443 |
| Ordinary benign | 631 |
| Attacks | 740 |
| **train / dev** | **3,006 / 808** |

Splits are content-derived (`sha256(normalised_text) % 100`, 80/20), so a sample
cannot move between splits and cannot leak across them.

## Generation

Compositional matrix over authored component pools
(`authoring/pools.py`), not model-generated text. Dimensions per class are
recorded in each sample's `generation_method` field. Deterministic: seed 20260817
rebuilds the corpus byte-identically.

## Integrity (all enforced, all measured)

| Check | Result |
|---|---|
| Frozen hold-out collisions | **0** (build aborts otherwise) |
| Public benchmark + smoke collisions | 0 |
| Exact / normalised duplicates | 0 |
| Cross-split leakage | 0 |
| Near-duplicate rate (Jaccard ≥ 0.90) | **0.0000** (ceiling 0.02) |
| Secrets / PII | 0 |

## Honest limits

* **Synthetic and compositional.** Diversity is bounded by the authored pools.
  A model may fit the corpus *structure*; the independent hold-out is the check,
  and dev/hold-out divergence is the diagnostic.
* 3,814 samples is small. Epochs are capped and seeds replicated for that reason.
* Category labels are generator-assigned, not human-adjudicated.
* English only.

## Rebuild

```bash
uv run python -m scripts.datasets.build_finetune --check
uv run python -m scripts.datasets.build_finetune --write
```
