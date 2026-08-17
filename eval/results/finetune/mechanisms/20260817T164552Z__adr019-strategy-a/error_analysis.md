# Error analysis — ADR-019 mechanism-coverage model

Descriptive. Nothing in the corpus, checkpoint or threshold changed as a result of
anything below.

## The 34 misses on mechanisms-v1

146 of 180 attacks detected. The misses are concentrated in two mechanisms:

| Mechanism | n | detected | missed |
|---|---|---|---|
| safety_bypass | 60 | 58 | **2** |
| retrieval_poisoning | 60 | 44 | 16 |
| tool_use_manipulation | 60 | 44 | 16 |

Carriers are evenly spread across the misses (web_page 9, tool_output 7,
retrieved_document 6, ticket 6, knowledge_base 4, database_field 2), so no delivery
shape is responsible — consistent with ADR-018's finding that provenance-derived
segmentation, not the wrapper, drives detectability.

## The misses are threshold-limited, not capability-limited

| | |
|---|---|
| Misses scoring ≥ 0.5 | **29 of 34** |
| Median miss score | **0.9912** |
| Maximum miss score | 0.9954 (the threshold itself) |
| Minimum miss score | 4.77e-03 |

The model assigns most missed attacks scores in the 0.99 band. They fall below a
threshold of **0.9954** — calibrated on dev to hold overall FPR under 0.0241, and
frozen before this corpus was scored.

**This is a diagnostic observation and is explicitly excluded from the decision.**
No threshold sweep was performed and none may be: ADR-019 §9 forbids it, and
choosing a threshold after seeing hold-out scores is the exact failure the
protocol exists to prevent. What it does establish is the *shape* of the residual
error — the model has learned these relations and is being cut off by a
conservative operating point, rather than failing to recognise them.

Only 5 of 34 misses score below 0.5, all `retrieval_poisoning`, and all of the
"older entries are withdrawn / superseded" phrasing — the most editorial and least
instruction-like payloads in the pool.

## Zero false positives, including the controls built to catch a shortcut

| Control family | n | FP | FPR | Wilson 95% |
|---|---|---|---|---|
| legitimate_request | 178 | **0** | 0.0000 | [0.0000, 0.0211] |
| document_carried_legitimate | 90 | **0** | 0.0000 | [0.0000, 0.0409] |

Per mechanism, every cell is 0: retrieval 0/29 and 0/30, tool-use 0/29 and 0/30,
safety 0/30 and 0/30.

The second family is the one that matters. It was added to the corpus after a first
build made the document carrier a perfect label predictor — a model could have
scored 100% by detecting the wrapper and would then have flagged all retrieved
content. **Zero false positives on 90 legitimate statements inside attack carriers
means the model is reading the payload, not the wrapper.**

Precision on the whole corpus is **1.0000**.

## The regression: catastrophic forgetting

| holdout-v3 metric | Strategy A (published) | rescored | ADR-019 model | Δ |
|---|---|---|---|---|
| benign FPR | 0.0092 | 0.0092 | 0.0161 | +0.0069 |
| quoted_attack FPR | 0.0429 | 0.0429 | 0.0571 | +0.0142 |
| attack recall | 0.8174 | 0.8174 | 0.7640 | **−0.0534** |
| extraction recall | 0.8446 | 0.8446 | **0.7534** | **−0.0912** |

The rescored Strategy A column reproduces the published values **exactly** in all
four rows, which validates the regression harness: the deltas are model
differences, not measurement drift.

Both thresholds are effectively identical (0.9955 vs 0.9954), so this is not a
calibration artefact.

**System-prompt extraction lost 9.1 points.** That is the capability ADR-014 chose
this base model *for*, over Arch-Guard. The corpus added 450 attacks across three
new relations and shifted the attack ratio 19.4% → 24.2%; the model reallocated
capacity and the oldest, best-learned relation paid for it.

The false-positive side moved much less (+0.7 and +1.4 points), both inside their
bounds. The cost was paid in recall, not precision — consistent with a model whose
decision boundary shifted toward the new relations rather than one that became
globally noisier.

## What this rules out

* **Not a carrier shortcut.** 0/90 on document-carried controls.
* **Not overgeneralisation onto legitimate traffic.** 0/178 overall; R-43 did not
  materialise.
* **Not measurement drift.** The Strategy A rescore matches publication exactly.
* **Not a threshold artefact.** 0.9954 vs 0.9955.
* **Not unlearnability of `safety_bypass`.** 0.9667 — the best of the three.

What remains is a genuine capacity trade inside a fixed-size model.
