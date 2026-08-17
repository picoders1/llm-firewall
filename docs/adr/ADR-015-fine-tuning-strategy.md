# ADR-015: Fine-Tuning Strategy — Pre-Registered Protocol

**Status:** Accepted (protocol). **No training has been performed.**
**Date:** 2026-08-17
**Phase:** 2 preparation
**Resolves the "how" of** [ADR-014](ADR-014-detector-selection.md) **Option D / OD-19.**

## Context

ProtectAI DeBERTa-v3 v2 was selected as the layer-2 candidate on measured
evidence, then held in `warn` because it false-positives on legitimate
security-domain language. The threshold sweep proved this is **not fixable by
calibration**: at threshold 0.9995 — effectively maximum confidence — it still
fires on 87.5% of incident reports quoting an attacker payload and 41.2% of
incident-response traffic. Those are 0.99+ predictions, not borderline scores.

The failure is representational. The model appears to have learned that certain
*strings* indicate an attack, rather than that certain *intents* do.

## Observed problem, stated precisely

The model cannot distinguish:

| | |
|---|---|
| **Discussing / quoting / documenting an attack** | benign |
| **Performing an attack** | attack |

Measured on the independent hold-out (n=457 benign), base model at 0.5:

| Category | FPR |
|---|---|
| quoted_attack | 0.938 |
| override_ordinary | 0.600 |
| ignore_previous_ordinary | 0.471 |
| human_instructions | 0.417 |
| security_policy | 0.400 |
| incident_response (domain) | 0.471 |
| security_operations (domain) | 0.281 |

## Training objective

**Binary sequence classification, unchanged.**

The base model is `DebertaV2ForSequenceClassification` with `{0: SAFE, 1: INJECTION}`
and a 512-token window. Alternatives were considered and rejected:

| Objective | Rejected because |
|---|---|
| **Binary (chosen)** | Simplest thing that addresses the failure. The confusion is *within* the existing label space — benign text scored as INJECTION — so no new head is needed to express the fix. |
| Multi-class (attack technique) | Solves a problem we do not have. The gateway needs a decision, not a technique label, and the policy engine already carries category. |
| Binary + auxiliary category head | Plausible: an explicit "is this security discussion" signal might regularise the representation. Adds a second loss to weight and tune, on a corpus whose category labels are generator-assigned rather than human-adjudicated. Deferred; revisit if Strategy B fails. |
| Contrastive / pairwise loss | The signal it provides is obtained more cheaply **as data**: the corpus embeds the same attack phrase on both sides of the boundary, so standard cross-entropy already sees matched pairs. Changing the loss adds machinery without adding information. |

**The contrastive property is a dataset property, not a loss function.** That is
the central design decision here.

## Data strategy

Corpus: `eval/datasets/finetune/`, built by `scripts/datasets/build_finetune.py`
from authored component pools, deterministically (seed 20260817).

| | Count |
|---|---|
| Total | 3,814 |
| Benign (label 0) | 3,074 |
| — hard negatives | 2,443 |
| — ordinary benign | 631 |
| Attacks (label 1) | 740 |
| train / dev | 3,006 / 808 |

**Generation is a documented matrix, not a prompt.** Each sample composes
independently authored components along explicit dimensions — quoting frame ×
attack phrase × reference; discussion topic × deliverable; opener × scope × goal;
container × payload × reference. Diversity comes from combinatorics over
hand-written parts, which is why the measured near-duplicate rate is **0.0000**
at Jaccard ≥ 0.90 against a 0.02 ceiling.

**The same 22 attack phrases appear on both sides of the label boundary** — as
payloads in attacks, and quoted inside incident reports, test fixtures, training
slides and detection rules as hard negatives. A model that learns keywords scores
at chance on this corpus. `test_contrastive_pairs_exist` asserts the property.

Ordinary benign (631) is included deliberately: a corpus of only hard negatives
would teach the boundary while destroying the model's notion of normal traffic.

## Contamination controls

The frozen hold-out is the only uncontaminated judge of whether this works, so it
is protected by code rather than convention:

* `check_holdout_boundary()` **aborts the build** on any normalised collision.
  Measured: **0**.
* The hold-out's SHA-256 is pinned in `test_holdout_content_hash_is_unchanged`;
  editing it fails CI.
* `test_train_has_zero_collisions_with_the_frozen_holdout` and the dev equivalent
  run on every CI invocation.
* Training data lives in `eval/datasets/finetune/`, a different directory tree
  from `eval/datasets/holdout/`.
* Hard negatives were authored from the *phenomenon* (quoting, policy language,
  human instructions), never by paraphrasing hold-out samples.

Also verified: 0 collisions with the public benchmark and smoke fixture, 0
cross-split leakage, 0 duplicates, 0 secrets, 0 PII.

## Experimental sequence

Bounded and ordered. Stop at the first strategy that satisfies the criteria.

| # | Strategy | Rationale |
|---|---|---|
| **A** | Standard supervised fine-tuning on the full corpus | The control. If plain SFT fixes it, nothing more is warranted. |
| **B** | Hard-negative-aware: oversample hard negatives (ratio ∈ {1:1, 2:1} against ordinary benign) | Directly targets the failure distribution. |
| **C** | Cost-sensitive: class weights penalising false positives more than false negatives | Tests whether the trade can be moved by loss weighting alone. |
| D | Auxiliary category head | **Only if A–C fail.** Recorded so it is not reinvented. |

### Hyperparameter bounds

Deliberately small — a wide search over 3.8k samples would fit the search, not the
problem.

| Dimension | Values |
|---|---|
| Learning rate | 1e-5, 2e-5, 3e-5 |
| Epochs | 2, 3 |
| Batch size | 16 |
| Weight decay | 0.01 |
| Max length | 512 (base model limit) |
| Warmup | 10% linear |
| Seeds | 3 per configuration (13, 20260817, 31337) |

≤ 18 configurations × 3 seeds. Selection uses **dev only**.

### Checkpoint selection

Selected on **dev**, by this priority, fixed in advance:

1. `quoted_attack` FPR (the dominant failure)
2. overall benign FPR
3. attack recall, subject to no more than a 5-point drop from base
4. `system_prompt_extraction` recall, subject to no more than a 5-point drop

Ties broken toward the earlier epoch. Once selected, **checkpoint and threshold
are frozen**, then the hold-out is scored exactly once per experiment.

## Success criteria — pre-registered

Reference points, both measured on the independent hold-out at frozen thresholds:

| | heuristic @0.85 | ProtectAI base @0.9995 |
|---|---|---|
| Attack recall | 0.3167 | 0.8833 |
| Benign FPR | 0.0241 | 0.0678 |
| Hard-negative FPR | 0.0647 | 0.1706 |
| quoted_attack FPR | 0.500 | 0.875 |
| incident_response FPR | 0.294 | 0.412 |
| Extraction recall | 0.2667 | 0.8444 |
| Latency | 0.098 ms | ~120 ms |

### Blocking-readiness hypothesis

Fine-tuning succeeds **for blocking** if, on the hold-out at a dev-frozen
threshold, all hold simultaneously:

| Criterion | Threshold | Why |
|---|---|---|
| Overall benign FPR | **≤ 0.0241** | No worse than the heuristic it would sit beside |
| Hard-negative FPR | **≤ 0.10** | Down from 0.1706; the class that decides usability |
| **quoted_attack FPR** | **≤ 0.15** | Down from 0.875. The single most important number |
| incident_response FPR | **≤ 0.10** | Down from 0.412 |
| Attack recall | **≥ 0.80** | At most a 5-point regression from 0.8833 |
| Extraction recall | **≥ 0.80** | At most a 5-point regression from 0.8444 |
| Latency | no material change | Same architecture; verify, do not assume |

Each reported with a Wilson 95% interval and its denominator. **A criterion whose
interval straddles its bound is not met.**

### Partial success — warn-mode improvement

If blocking criteria fail but hard-negative FPR improves materially (≥ 30%
relative reduction) with recall within 5 points, the fine-tuned model **replaces
the base model in warn mode** and blocking stays closed.

## Failure criteria — also pre-registered

Fine-tuning is **unsuccessful** if any of:

* `quoted_attack` FPR stays > 0.40 — the core failure survived;
* attack recall drops below 0.75 — bought FPR with security;
* extraction recall drops below 0.70 — regressed the capability that selected
  this model over Arch-Guard;
* dev improves but hold-out does not — the model fitted the generated corpus;
* hold-out FPR exceeds the base model anywhere in the critical categories;
* latency changes materially.

**"Fine-tuning unsuccessful" is an acceptable outcome and must be published as
one.** The fallback is context-aware gating (OD-19 option C) or retaining the
heuristic alone.

## Consequences

### Positive
* The experiment is falsifiable: criteria are fixed before any training runs.
* The hold-out is protected by four independent mechanisms, not by discipline.
* The corpus targets the measured failure rather than a general notion of quality.
* The contrastive-as-data design keeps the objective and architecture unchanged.

### Negative / accepted costs
* **The corpus is synthetic and compositional.** Its diversity is bounded by the
  authored pools; a model can plausibly fit its *structure*. The hold-out is
  authored differently and independently, which is exactly the check for this —
  and if dev improves while the hold-out does not, that is the diagnosis.
* 3,814 samples is small for fine-tuning; over-fitting risk is real and is why
  epochs are capped at 3 and seeds are replicated.
* Generator-assigned category labels are not human-adjudicated. Acceptable for
  binary training; it is why the auxiliary-head strategy is deferred.
* No multilingual coverage. The benchmark is English-only and the scope is
  unchanged.

### Revisit when
A–C complete, or the hold-out shows dev/hold-out divergence indicating the corpus
is being memorised rather than generalised from.

## Verification

```bash
uv run python -m scripts.datasets.build_finetune --check   # integrity gates
uv run pytest -m evaluation -q                             # boundary + corpus tests
```
