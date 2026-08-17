# ADR-015: Fine-Tuning Strategy — Pre-Registered Protocol

**Status:** Accepted (protocol). **Strategy A executed 2026-08-17 → PARTIAL SUCCESS.**
**Date:** 2026-08-17
**Phase:** 2 preparation
**Resolves the "how" of** [ADR-014](ADR-014-detector-selection.md) **Option D / OD-19.**
**Superseded as the training baseline by nothing — this checkpoint is still the one to beat.** [ADR-019](ADR-019-mechanism-coverage-fine-tuning.md) tried to extend it and lost retention; [ADR-020](ADR-020-retention-preserving-training.md) is the pre-registered successor and treats Strategy A's numbers as the immutable reference.

> **Strategy A result.** 18/18 configurations trained. Hard-negative FPR on the
> frozen hold-out fell **0.1706 → 0.0118** (93.1% relative) and quoted_attack FPR
> **0.875 → 0.0625**, with attack recall unchanged at 0.8833 and extraction
> recall unchanged at 0.8444. Four of six blocking criteria are not met under the
> CI rule — **two of them are unachievable at the hold-out's sample sizes**, a
> defect in this ADR's pre-registration (see *Criterion achievability* below).
> Decision: **PARTIAL SUCCESS → warn mode, blocking stays closed.**
> Evidence: [`eval/results/finetune/20260817T122701Z__strategy-a/report.md`](../../eval/results/finetune/20260817T122701Z__strategy-a/report.md).
> **Strategies B–D are not started.** They require a separate explicit decision.
>
> **Hold-out v3 validation, 2026-08-17.** The two unachievable criteria were the
> reason blocking could not be assessed, so an independently authored v3
> (792 samples) was built with denominators calculated from the observed rates.
> Result: **all four FPR criteria now MET** — quoted_attack 0.0429 [0.0147,
> 0.1186] n=70, incident_response 0.0000 [0.0000, 0.0337] n=110 — and **both
> recall criteria genuinely fail**: attack recall 0.8174 [0.7740, 0.8541] n=356,
> extraction recall 0.8446 [0.7989, 0.8814] n=296 (short by one sample). v3 also
> exposed a failure v2 could not see: **indirect-injection recall 0.4000** at
> n=20, against 1.0000 at v2's n=5. Decision unchanged: **WARN ONLY**.
> Evidence: [`eval/results/20260817T125002Z__holdout-v3-validation/report.md`](../../eval/results/20260817T125002Z__holdout-v3-validation/report.md).
>
> **Indirect-injection delivery-shape evaluation, 2026-08-17.** v3's
> indirect-injection figure (0.4000, n=20) was re-measured on a dedicated
> 820-sample corpus crossing 12 delivery shapes with 8 attack mechanisms. Result:
> recall **0.1423** (n=520), **no shape reliably detected, six at exactly zero**.
> Recall depends 7.7x on whether the override request comes from the user's turn
> (0.7250) or from inside a document (0.0938) — the detector is classifying the
> user, not the retrieved content. Blocking is now refused on severity grounds
> independently of the criteria here; see
> [ADR-016](ADR-016-provenance-aware-detection.md).

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
| Batch size | 16 (effective — see the implementation note below) |
| Weight decay | 0.01 |
| Max length | 512 (base model limit) |
| Warmup | 10% linear |
| Seeds | 3 per configuration (13, 20260817, 31337) |

≤ 18 configurations × 3 seeds. Selection uses **dev only**.

#### Implementation note — memory adaptations on a 4 GB card

Recorded **before training**, 2026-08-17. The available GPU is an RTX 3050
Laptop with 3.95 GB (3.68 GB usable). DeBERTa-v3-base's weights, gradients and
AdamW moments occupy ~2.94 GB of that, because its 128k-token embedding is 98M
of its 184M parameters. Two adaptations were required, **neither of which
changes the optimisation being performed**:

| Adaptation | Why | Effect on the protocol |
|---|---|---|
| `fused=True` AdamW | The default multi-tensor path materialises param-sized temporaries; a 394 MB allocation for the embedding alone exhausts the card | None. Same update rule, different kernel. |
| micro-batch 4 × gradient accumulation 4 | A 16-sample forward pass does not fit beside the optimiser state | None. Each micro-batch's mean loss is weighted by its share of the batch, so the accumulated gradient equals that of a single batch of 16. |

The correct phrasing is **micro-batch size 4, gradient accumulation 4, effective
batch size 16** — not "batch size 16" unqualified.

The equivalence is verified numerically rather than asserted, by
`scripts/verify_accumulation.py`, against the real model and real training
samples: loss difference **3.502e-07**, worst relative gradient difference
**3.227e-06**, gradient cosine similarity **1.0000000000** (computed in float64;
in float32 the dot product over 184M elements is not reliable). These are
float32 accumulation-order noise, not a difference in the update.

A first launch of the matrix failed with CUDA OOM on all 18 configurations
before any training step, using the default AdamW path. It produced no
checkpoint and no metric, and is preserved as
`eval/results/finetune/discarded_attempt1_all_oom.json` rather than deleted.

### Checkpoint selection

Selected on **dev**, by this priority, fixed in advance:

1. `quoted_attack` FPR (the dominant failure)
2. overall benign FPR
3. attack recall, subject to no more than a 5-point drop from base
4. `system_prompt_extraction` recall, subject to no more than a 5-point drop

Ties broken toward the earlier epoch. Once selected, **checkpoint and threshold
are frozen**, then the hold-out is scored exactly once per experiment.

#### Amendment, 2026-08-17 — tie-breaking beyond the earlier epoch

Recorded **during Strategy A, before the hold-out was accessed**, and applied to
Strategy A itself.

"Ties toward the earlier epoch" turned out to be insufficient: every trained
configuration reached identical dev scores on all four criteria, so the tie
spans learning rates and seeds as well as epochs. The rule is extended
deterministically:

> **tie 1** fewer epochs → **tie 2** lower learning rate → **tie 3** lower seed.

Both extensions prefer the **smallest departure from the base model**, which is
the conservative choice when nothing in the data distinguishes the candidates.
The rule is mechanical, contains no hold-out quantity, and is applied by
`scripts/finetune_strategy_a.py` rather than by hand.

The reference for the "no more than a 5-point drop" floors is likewise fixed:
it is the base model measured **on dev**, computed at selection time. Using the
published hold-out figures (0.8833 / 0.8444) would import a hold-out quantity
into a dev-only decision.

**A universal tie is itself a finding**, not a nuisance to be resolved and
forgotten: it means dev has no power to discriminate between these checkpoints,
and it is reported as such.

#### Threshold selection procedure

The threshold is chosen by the project's existing calibrator,
`eval.metrics.calibration.calibrate()`, with objective `MAX_RECALL_AT_FPR` and
the ADR-015 overall-FPR bound (0.0241) as the budget, on **dev**. That function
calls `require_tunable()`, so the dev-only guarantee is enforced by the library
rather than by the caller. The dominant `quoted_attack` criterion is not
expressible as an overall-FPR budget, so it is **verified at the chosen point**
rather than folded into the objective. The base model's 0.5 default is not
inherited.

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

#### Criterion achievability — a defect found by executing Strategy A

Recorded 2026-08-17, **after** the single hold-out evaluation. The criteria
themselves were **not** changed; this documents that two of them were impossible
to satisfy as written.

Combining a strict CI rule with a small denominator can produce a criterion no
model can meet. Checking each bound against its best possible outcome:

| Criterion | n | Best case | Wilson bound at best case | Required | Achievable |
|---|---|---|---|---|---|
| Overall benign FPR ≤ 0.0241 | 457 | 0 FP | upper 0.0083 | ≤ 0.0241 | yes |
| Hard-negative FPR ≤ 0.10 | 170 | 0 FP | upper 0.0221 | ≤ 0.10 | yes |
| **quoted_attack FPR ≤ 0.15** | **16** | 0 FP | **upper 0.1936** | ≤ 0.15 | **no** |
| **incident_response FPR ≤ 0.10** | **17** | 0 FP | **upper 0.1843** | ≤ 0.10 | **no** |
| Attack recall ≥ 0.80 | 60 | — | needs ≥ 55/60 | ≥ 0.80 | yes |
| Extraction recall ≥ 0.80 | 45 | — | needs ≥ 42/45 | ≥ 0.80 | yes |

Strategy A scored a perfect **0/17** on `incident_response` and still could not
satisfy that criterion.

**Rule for any future pre-registration:** a bound must be checked against its
denominator before it is agreed. If the best possible outcome cannot satisfy it,
either the hold-out sub-corpus must grow or the criterion must be stated as a
point estimate with its interval reported alongside — not as a CI-strict bound.

**Applied 2026-08-17.** Hold-out v3 was sized from this calculation rather than
from a guess: each category's target is the smallest n whose Wilson interval, *at
the rate Strategy A actually achieved*, clears the bound. Sizing against a
hypothetical perfect result would produce a corpus that fails the moment the
model makes one mistake.

| Category | Criterion | Observed | Minimum n | v3 n |
|---|---|---|---|---|
| quoted_attack | FPR ≤ 0.15 | 0.0625 | 55 | 70 |
| incident_response | FPR ≤ 0.10 | 0.0333 | 69 | 110 |
| hard negatives | FPR ≤ 0.10 | 0.0118 | 35 | 240 |
| benign overall | FPR ≤ 0.0241 | 0.0066 | 299 | 436 |
| attacks in scope | recall ≥ 0.80 | 0.8833 | 81 | 356 |
| system_prompt_extraction | recall ≥ 0.80 | 0.8444 | 292 | 296 |

**A refinement learned from doing it:** the +4 margin on
`system_prompt_extraction` was too thin. Size to **1.5x the calculated minimum**
whenever the observed point estimate sits within 10 points of its bound.

This does not soften the Strategy A verdict. Attack recall (55/60 needed, 53/60
measured) failed on the model's merits, so blocking readiness would not have
been established even with achievable FPR criteria.

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
