# Mechanism-coverage hold-out (mechanisms-v1)

**Frozen 2026-08-17.** `dataset_sha256`
`bb562774663dea7580d7d1a97031b810c7a8aadebde10fcbfd04a116b521e91c`
**Seed:** 20260820 · **Protocol:** [ADR-019](../../../../docs/adr/ADR-019-mechanism-coverage-fine-tuning.md)

**Read-only.** Do not append, relabel, or regenerate.

## Why it exists

ADR-018 measured three attack mechanisms at **exactly 0.0000 recall** even as
isolated spans with provenance declared — around 1e-6, six orders of magnitude
below the override and extraction payloads the model scores at 0.9999:

| Mechanism | attacks | legitimate controls |
|---|---|---|
| retrieval_poisoning | 60 | 59 |
| tool_use_manipulation | 60 | 60 |
| safety_bypass | 60 | 60 |

358 samples: **180 attacks, 178 controls.**

`holdout-indirect-v1` already carries these mechanisms, but it has been scored
**twice** (ADR-016, ADR-018). A third scoring after training on the same relations
would measure nothing. This corpus exists so the ADR-019 protocol has a clean
denominator.

## Sizing, calculated before authoring

| | |
|---|---|
| Attacks per mechanism | 60 |
| RELIABLY DETECTED needs | 55/60 = 0.9167 |
| SYSTEMATICALLY MISSED needs | ≤ 41/60 = 0.6833 |
| Inconclusive band | 0.683 – 0.917 |
| Controls total | 178 → 0 FP gives FPR ≤ 0.0211 |

Current recall is 0.0000, so the question is whether a mechanism moves at all.
n=60 brackets any outcome worth acting on.

Reproduce: `uv run python -m scripts.datasets.build_mechanism_coverage --sizing`

## Two controls, not one

| Control | n | What it catches |
|---|---|---|
| `*_legitimate` | 88 | A model that learned "mentions a tool → block" and rejects ordinary agent traffic |
| `*_document_legitimate` | 90 | A model that learned "text inside a document → block" and rejects all retrieved content |

The second is the more important and the less obvious. During authoring, a first
build had every attack in a document carrier and every control as a direct request,
which made **the carrier a perfect predictor of the label**. A model could have
scored 100% without reading the payload — and would then flag every retrieved
document. Adding legitimate content inside the same carriers closed it; every
document carrier now hosts both labels.

## Independence

| Check | Result |
|---|---|
| Attack vocabulary vs finetune-v1 (22), holdout-v3 (26), holdout-indirect-v1 (27) | **disjoint** |
| Attack vocabulary vs the ADR-019 training pool | **disjoint** |
| Document-carried legitimate content vs the training pool | **disjoint** |
| Exact + normalised collisions vs every frozen corpus and 5 public corpora | **0 / 0** |
| Secrets / PII | **0 / 0** |

The last two disjointness checks are not decoration: the first build shared its
document-legitimate pool between training and hold-out and produced **14 exact
collisions**, which the gate caught and refused to write.

## Schema

```json
{"sample_id": "mechho-atk-0001", "text": "...", "label": 1,
 "category": "indirect_prompt_injection", "sub_category": "retrieval_poisoning",
 "attack_mechanism": "retrieval_poisoning", "domain": "web_page",
 "difficulty": "hard", "language": "en", "source": "internal_authored",
 "source_type": "synthetic", "created_at": "2026-08-17",
 "generation_method": "matrix: carrier x payload x body",
 "dataset_version": "holdout-mechanisms-v1",
 "holdout_version": "holdout-mechanisms-v1", "notes": null}
```

## Limitations

1. **Compositional.** 24 hold-out attack phrasings × 6 carriers × 8 bodies. A real
   attacker is not drawn from a matrix.
2. **`safety_bypass` may be unlearnable from text alone.** "The moderation step
   already ran" is a false claim about system state, not a linguistic pattern; only
   provenance distinguishes it from a true statement. Registered in ADR-019 as an
   expected failure mode.
3. **Three mechanisms only.** `role_manipulation` (0.3115 on ADR-018) is not
   covered here and remains open.
4. English only, one authoring source, no independent review.
