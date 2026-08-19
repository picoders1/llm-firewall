# ADR-020: Retention-preserving successor training — pre-registered protocol

**Status:** **EXECUTED AND CLOSED 2026-08-18 → FAILURE.** Steps 0–1 passed, Step 2
complete (6/6 runs), Step 3 evaluated both arms once. The successor does not replace
Strategy A.
**Date:** 2026-08-17
**Phase:** 2 continuation
**Follows** [ADR-015](ADR-015-fine-tuning-strategy.md) (Strategy A),
[ADR-018](ADR-018-provenance-aware-detector-evaluation.md) (found the gap),
[ADR-019](ADR-019-mechanism-coverage-fine-tuning.md) (closed the gap, lost retention).

> **Steps 0 and 1 executed 2026-08-17. Both passed. Step 2 is justified and remains
> unauthorised.**
>
> The proxy reproduces the known effect, so it may rank checkpoints: on
> `lakera-gandalf` (999 human-authored extraction attacks) Strategy A beats ADR-019
> **0.9690 → 0.9069** at matched FPR, exact McNemar **p < 1e-6** (63 discordant pairs
> against 1). The regression is **not seed noise**: across three seeds per family the
> two are **fully disjoint** — every Strategy A run beats every ADR-019 run — with a
> between-condition gap of 0.0594 against a largest within-condition spread of 0.0230.
> The exact permutation test gives p = 0.0500, which is the *floor* at three runs per
> group and therefore the strongest run-level result this design can produce.
>
> An unregistered finding, recorded because it changes how every prior comparison
> reads: the dev-selected threshold is not merely underdetermined but wildly so.
> All six dev splits separate perfectly and the chosen thresholds span
> **0.0694 – 0.9955**. `mech__lr1e-05__ep2__seed20260817` selected 0.0694 where its
> sibling seed selected 0.9954, under identical methodology on the identical split.
>
> Evidence: [`eval/results/finetune/ADR-020-steps-0-1/report.md`](../../eval/results/finetune/ADR-020-steps-0-1/report.md).
> **No training. No hold-out was read. No production change.**
>
> ---
>
> **The rest of this ADR designs Step 2. It authorises no training.**
>
> ADR-019 proved the three missing mechanisms are learnable — 0.0000 → 0.7333 /
> 0.7333 / 0.9667 with zero false positives on all 178 controls. It failed on
> retention: holdout-v3 extraction recall 0.8446 → 0.7534 and attack recall
> 0.8174 → 0.7640. Six variables moved at once, so the cause is unattributed.
>
> The question is now: **can the new mechanisms be added without surrendering the
> capabilities that made Strategy A preferable?**
>
> **No production change. Registry, threshold 0.85, overlays 0, blocking disabled —
> all unchanged.**

## Context

ADR-019's checkpoint must not replace Strategy A's. But its failure is not a reason
to train again immediately; it is a reason to find out *why* it failed. §2 of the
governing brief is explicit that catastrophic forgetting, overtraining, class
imbalance, insufficient replay, excessive attack density, and synthetic-corpus
artefacts must not be assumed without an experiment that separates them.

## Three things the existing artefacts already settle, at no compute cost

### 1. The regression is a real loss of discrimination, not a threshold artefact

| holdout-v3 | Strategy A | ADR-019 | direction |
|---|---|---|---|
| benign FPR | 0.0092 | 0.0161 | worse |
| quoted_attack FPR | 0.0429 | 0.0571 | worse |
| attack recall | 0.8174 | 0.7640 | worse |
| extraction recall | 0.8446 | 0.7534 | worse |

Recall fell *while* FPR rose. A change of threshold moves recall and FPR in the
**same** direction, so no threshold on the ADR-019 model reproduces Strategy A's
operating point: returning FPR to 0.0092 requires raising the threshold, which drives
recall below the already-lower 0.7640. ADR-019 is **dominated** throughout the region
of interest.

This is a threshold-free argument from published aggregates. It answers §28's
question — "could any result be explained by a changed threshold rather than model
learning?" — with *no*. The **existence** of degradation is threshold-independent;
only its **magnitude** (−0.0912) is threshold-dependent.

### 2. The v2 dev split is saturated and can rank nothing

The ADR-019 winner at its locked threshold 0.9954, on v2 dev:

| category | recall | | category | recall |
|---|---|---|---|---|
| direct_prompt_injection | 62/62 | | jailbreak | 18/18 |
| system_prompt_extraction | 58/58 | | indirect_injection | 9/9 |
| tool_use_manipulation | 34/34 | | role_override | 3/3 |
| safety_bypass | 31/31 | | context_override | 3/3 |
| retrieval_poisoning | 28/28 | | **benign FPR** | **0/798** |

Perfect separation on every category. OD-23 is confirmed and escalated: dev cannot
rank arms, **and** the dev-selected threshold is underdetermined — every value inside
the separating gap scores identically, so 0.9955 vs 0.9954 was settled by tie-break,
not by data. Any protocol that selects arms or thresholds on this dev split is
selecting on noise.

### 3. All 36 checkpoints survive

`artifacts/finetune/` and `artifacts/finetune-mechanisms/` each retain all 18 runs.
Run-to-run seed variance — never measured in this project — is therefore obtainable
**without training anything**.

## Confounded variables, ADR-015 → ADR-019 (§8)

| Variable | Strategy A (v1) | ADR-019 (v2) | Status |
|---|---|---|---|
| Corpus size (train+dev) | 3,814 | 4,922 | **changed** (+29.0%) |
| Attack fraction | 19.4022% | 24.1772% | **changed** |
| Extraction share *of attack mass* | 38.9189% | 24.2017% | **changed** (−14.72pp) |
| Direct-injection share of attacks | 37.97% | 23.61% | **changed** (−14.36pp) |
| New mechanism classes | 0 | 3 (450 attacks) | **changed** |
| Ordinary-benign fraction | 16.544% | 12.820% | **changed** |
| Hard-negative fraction | 64.053% | 63.003% | ~unchanged |
| Optimiser steps @ 2 epochs | 376 | 486 | **changed** (+29.3%) |
| LR, schedule, batch, base model, loss, seeds | — | identical | controlled |

Step counts use the training split and the exact ceiling formula the trainer uses
(`scripts/finetune_strategy_a.py:284`).

Extraction's **absolute** count is identical in both corpora — 288 samples. Only its
**share of attack signal** moved, by −14.72pp. Extraction is exactly the capability
that lost 9.1 points. That coincidence is the leading hypothesis, and it is confounded
with five other simultaneous changes.

### Candidate causes

| | Cause | Status |
|---|---|---|
| C1 | Capacity / interference from three new relations | live — the residual explanation |
| C2 | Extraction diluted in relative terms | live — **leading** (H1, H3) |
| C3 | +29.3% optimiser steps → over-adaptation | live (H2) |
| C4 | Attack fraction 19.4% → 24.2% | live |
| C5 | Ordinary-benign fraction fell | live, weakest prior |
| C6 | Threshold artefact | **eliminated** (finding 1) |
| C7 | Seed noise | **reduced** — families fully disjoint over 3 seeds each (Step 1); not eliminated at n=3 |

C7 needs care. The exact McNemar test on ADR-019's extraction result gives p = 1e-08,
but that establishes only that *these two checkpoints* differ beyond **sampling**
error on holdout-v3. It says nothing about **run-to-run** variance across seeds, a
different source of variability that this project has never quantified. If the
condition effect sits inside seed spread, ADR-019's verdict itself needs qualifying.

## A defect in the proposed replay ratios (§12)

The brief offers 25/75, 50/50, 75/25 as candidate v1:extension mixtures. The
extension is 1,108 of 4,922 samples, so **v2's implicit ratio is already 77.5/22.5**.
Every candidate is at or below the v1 share ADR-019 already had, so none of them tests
replay in the direction that could preserve extraction. This is the same class of
error as the denominator problems caught in ADR-016 and ADR-019: a knob specified in
a range that cannot produce the effect being tested.

A replay arm must push the v1 share **up**. Under a fixed step budget, v1 share and
extension share trade off directly — and that trade-off *is* the quantity being
measured, not a flaw in the design.

**Selected mixture: 90/10.** One mixture, not three, per §12's instruction to choose
the smallest identifying set. At 90/10 the extension gets ~389 samples per epoch
against ADR-019's ~875 (243 steps × 16 = 3,888 samples per epoch, at 10% versus the
22.51% the extension holds naturally). ADR-019 cleared the mechanism bar with real margin (44, 44,
58 against a required 38/60), so roughly halving exposure is a bounded risk, and the
unweakened mechanism criterion is precisely the instrument that detects it.

## Successor strategies evaluated (§9)

| | Strategy | Decision |
|---|---|---|
| **R1** | Distribution-preserving replay | **Selected** (absorbing R3, R4) — targets C2, the leading cause |
| **R2** | Reduced adaptation | **Selected** as the second arm — targets C3. ADR-019 tested 2 and 3 epochs but never **1** (§15), so this is genuinely unexplored rather than a reaction to failure |
| **R3** | Balanced mixture, bounded proportions | **Merged into R1** — the mixture *is* the bounding mechanism; a separate arm would restate it |
| **R4** | Fixed v1 fraction per epoch | **Merged into R1** — this is R1's implementation, not an alternative to it |
| **R5** | Layered detector | **Deferred; experiment defined below, not authorised.** Not rejected for complexity (§9 forbids that reasoning) but as *premature*: it sidesteps the trade-off instead of explaining it, and its value is conditional on the outcome of R1 |
| **R6** | Distillation / retention loss | **Rejected for now.** No current evidence justifies it, and §9 warns against adopting it because it sounds advanced. Reconsider only if R1 and R2 both fail, which would implicate C1 |

## The experiment (§10, §11)

Four steps. **Steps 0 and 1 train nothing and touch no hold-out**, and either may
terminate the sequence before any GPU training happens.

### Step 0 — Validate a hold-out-free selection signal

Dev cannot rank arms (finding 2) and hold-outs must not (§22). A third signal is
required, and one already exists: the public corpora in `eval/datasets/raw/` were
never used in fine-tuning and are **0-collision disjoint from v2**, verified across
all 10,947 samples by `eval.schema.normalised_key`.

| Corpus | n | Role |
|---|---|---|
| `lakera-gandalf` | 999 attacks | Human-authored attempts to extract a secret from a system prompt — the exact regressed capability |
| `deepset-prompt-injections` | 263 attack / 399 benign | Second attack family, multilingual |
| `dolly-benign` + `oasst1-benign` | 8,000 benign | FPR signal and calibration pool |

**Pre-registered gate.** Score the Strategy A and ADR-019 winners on the proxy. It is
validated **only if** it reproduces the known direction: Strategy A strictly above
ADR-019 on `lakera-gandalf`, significant by exact McNemar. A proxy that cannot see an
effect already known to exist cannot be trusted to rank unknown arms.

**Contamination is stated, not hidden.** These corpora were used for base-model
selection in ADR-014 and are plausibly inside the base model's pretraining, so
**absolute** numbers on them are not claimable and will not be reported as capability.
The proxy ranks two fine-tunes of the *same* base, where that bias is a shared
constant that cancels in the comparison.

**Fallback if the gate fails:** author a retention hold-out (`holdout-v4`) targeting
extraction, or declare additional holdout-v3 scorings in advance. Not: quietly score
the hold-out more often.

**Executed 2026-08-17 — GATE PASSED.** Integrity first: 0 exact and 0 normalised
collisions against all four training corpora and all four hold-outs, 0 internal
duplicates, 0 calibration/evaluation overlap, near-duplicate rates recorded per corpus
(highest 0.0304 on deepset attacks), licences and contamination risk read from
`registry.yaml`.

The gate itself, on `lakera-gandalf`:

| threshold | Strategy A | ADR-019 | delta | discordant b/c | McNemar p |
|---|---|---|---|---|---|
| dev-selected | 0.9720 | 0.9520 | -0.0200 | 23 / 3 | 0.000088 |
| matched-FPR | 0.9690 | 0.9069 | -0.0621 | 63 / 1 | < 1e-6 |

The direction is reproduced at both, so the proxy is admitted for ranking. Note that
the matched-FPR gap is **three times** the dev-threshold gap: comparing at dev-selected
thresholds *understated* the regression, which is exactly the incommensurability that
§20 warns about.

**Two defects the integrity gate caught, both fixed in the construction process rather
than by dropping rows (§5).** One benign text was present in both `deepset` and
`dolly` — their content-hash sample IDs agree — which would have double-counted a
sample in the FPR denominator; cross-corpus de-duplication now runs before any draw.
And two apparent PII hits were **false positives of the check, not findings in the
data**: the dataset-build `card_like` pattern carries no checksum, so it fired on an
18-digit analytics hash, while production (`app/detectors/pii/regex.py`) requires
Luhn. Screening more loosely than production validates is a defect in the check. Three
genuine addresses were excluded pool-wide by a uniform rule, which slightly
under-represents benign traffic legitimately containing an email — a stated limit.

### Step 1 — Measure seed variance (C7) — still no training

Score `mech__lr1e-05__ep2__seed{20260817,31337}` and
`stratA__lr1e-05__ep2__seed{20260817,31337}` on the validated proxy, giving three
runs per condition.

**Decision rule, registered now:** if the between-condition gap is smaller than the
within-condition seed spread, **stop**. The regression would not be attributable to
the corpus change, ADR-019's verdict would be amended to INCONCLUSIVE, and retention
training would be unjustified. Otherwise proceed.

**Executed 2026-08-17 — the gap survives.** On `lakera-gandalf`:

| threshold | Strategy A (3 seeds) | ADR-019 (3 seeds) | gap | max within-family spread | disjoint |
|---|---|---|---|---|---|
| dev-selected | 0.9720 / 0.9780 / 0.9770 | 0.9520 / 0.9630 / 0.9580 | +0.0180 | 0.0110 | yes |
| matched-FPR | 0.9690 / 0.9700 / 0.9770 | 0.9069 / 0.9269 / 0.9039 | +0.0594 | 0.0230 | yes |

The families are **fully disjoint** at both thresholds — every Strategy A run beats
every ADR-019 run. The exact one-sided permutation test on run-level means gives
**p = 0.0500** in both cases, and with three runs per group 1/C(6,3) = 0.0500 is the
smallest attainable value. This is therefore the strongest run-level evidence three
seeds can produce, and it sits exactly on the conventional threshold: suggestive, not
decisive. It is reported that way rather than as "significant".

The two tests answer different questions and both are needed. McNemar's p < 1e-6 is
**sample-level** — these two checkpoints differ on these 999 samples. The permutation
p = 0.0500 is **run-level** — the training condition reproduces across seeds. ADR-019
had only the first kind of evidence, which is why C7 was live.

**C7 is reduced, not eliminated.** Seed noise does not explain the regression; three
seeds per family cannot bound run-to-run variance more tightly than this.

### Step 2 — Two arms, three seeds, one factor each

Control and Treatment 1 already exist as immutable results and are **not re-run** —
two thirds of the GPU cost of the brief's four-condition design is already paid.

| Arm | Sampler | Steps | Isolates |
|---|---|---|---|
| Control | Strategy A on v1 | 376 | — (exists) |
| T1 | ADR-019 on v2 | 486 | — (exists, confounded) |
| **T2 — replay** | 90/10 v1:extension weighted; attack fraction pinned to 0.194022; extraction ≥ 38.9189% of attack mass | **486, identical to T1** | **composition only** |
| **T3 — reduced adaptation** | T2's sampler, unchanged | **243 (1 epoch)** | **adaptation budget only**, vs T2 |

Everything else is held at the configuration that won both prior experiments: lr 1e-5,
effective batch 16 (micro-batch 4 × accumulation 4, fused AdamW — ADR-015's verified
equivalence), max length 512, weight decay 0.01, warmup 10%. Seeds 13, 20260817,
31337.

**Six runs, not eighteen.** With dev saturated, a wider hyperparameter grid buys only
tie-breaks; three seeds per arm buy a variance estimate the project has never had.

T2 holds steps identical to T1, so **T2 − T1 isolates composition**. T3 shares T2's
sampler exactly, so **T3 − T2 isolates adaptation budget**. One factor per comparison,
as §10 requires.

**One declared departure from "ordinary supervised fine-tuning."** T2 and T3 need a
weighted sampler, which ADR-019's guard test forbids. That test is scoped to
`scripts/finetune_mechanisms.py`, so a new `scripts/finetune_retention.py` does not
trip it and **no existing test is modified or weakened**. The sampler changes *which
rows are drawn*, never the loss: no class weights, no custom objective, no curriculum.

### Step 3 — Select, then score once

Rank the six checkpoints on the validated proxy. Score the **best T2 and the best T3**
on holdout-v3 and mechanisms-v1, in a single evaluation event with both checkpoints
locked in advance. These are the only hold-out uses this ADR authorises.

**Amended 2026-08-18 (amendment 2, A-3).** This step originally scored one pooled
winner. Step 2's dev results show T2 dominating T3 on every metric, so the pooled winner
would be a T2 and **T3 would never be measured on holdout-v3** — making three of
ADR-020's four registered causal outcomes unreachable and three of its six runs
evidentially useless. The deployment candidate remains the single pooled proxy-ranked
winner; the other arm's best checkpoint is scored **for causal evidence only** and is not
eligible for selection. Choosing between them after seeing hold-out numbers is
forbidden. Raised before any hold-out was read.

**Amended 2026-08-17 (amendment 1, A-1).** This step originally read "rank on the
validated proxy *plus dev*", which specified no combination rule and relied on a signal
Step 1 then measured at **sd 0.0000** for extraction recall, benign FPR and
quoted_attack FPR across all 18 Strategy A checkpoints. Dev is now an eligibility gate
only — it rejects a degenerate run and contributes no ranking information. The exact
ranking keys, in order, all at the matched-FPR threshold: `lakera-gandalf` recall,
then deepset attack recall, then `eval_benign` FPR, then ADR-015's deterministic
tie-break. Mechanism recall is deliberately excluded, being measurable only on a
protected hold-out that is scored after selection.
See [`amendment.md`](../../eval/results/finetune/ADR-020-steps-0-1/amendment.md).

**Further amended 2026-08-18 (amendment 3, A-4).** The eligibility gate excludes every T3 checkpoint — all three dev splits are non-separable, which for a deliberately under-trained arm is the expected outcome rather than a defect — while A-3 requires a locked best-T3 contrast target. The gate governs eligibility for *selection*; the ranking keys govern *ordering*. The contrast target is chosen by ranking keys alone, the gate applying unchanged to the deployment candidate. **No T3 checkpoint is deployable on the registered criteria, and that stands as a Step-3 finding.**

## Threshold methodology (§20)

Dev saturation makes a dev-selected threshold underdetermined, which would let two
models be compared at incompatible operating points — the exact failure §20 forbids.
The registered rule is therefore **both**:

1. **Primary:** matched-FPR — the smallest τ giving ≤ 1% FPR on a frozen, seed-fixed
   2,000-sample calibration draw from the unused public benign pool, disjoint from the
   evaluation draw and applied identically to every model.
2. **Secondary, recorded for continuity:** every model still gets a dev-selected
   threshold under the identical documented methodology and the same deterministic
   tie-break, reported alongside.

**Amended 2026-08-17 (amendment 1, A-2) — this ordering is inverted from the original.**
The ADR first made the dev-selected threshold primary. Step 1 then measured it across
all 36 checkpoints: the ADR-019 family has **sd 0.2179, min 0.0694**, with
`mech__lr1e-05__ep2__seed20260817` selecting 0.0694 where its sibling seed selected
0.9954 under identical methodology. The quantity is arbitrary, not merely noisy, and
Step 0 showed the consequence — comparing at dev-selected thresholds put the ADR-019
gap at 0.0200 against 0.0621 at matched FPR, understating it roughly threefold. Step 3
spends the single authorised holdout-v3 scoring, which must not happen at an arbitrary
operating point. The governing brief's §20 is still satisfied: every model gets and
records a dev-selected threshold, and §20 equally forbids comparing incompatible
thresholds — which Step 1 proved these to be.

Published historical numbers are **not restated**. Matched-FPR figures are reported
as a clearly labelled additional analysis beside them.

## Pre-registered success criteria

Machine-readable in
[`success_criteria.json`](../../eval/results/finetune/ADR-020-protocol/success_criteria.json).
Denominators are the real ones. Every criterion states its direction, per the rule
added to docs/13 after ADR-018.

**Retention — paired against Strategy A on the same samples. Both parts required.**

| Criterion | n | Rule |
|---|---|---|
| Extraction recall | 296 | McNemar exact **not** significant in the degradation direction (p ≥ 0.05) **and** point estimate ≥ **0.7946** |
| Attack recall | 356 | same paired rule **and** point estimate ≥ **0.7674** |
| Benign FPR | 436 | must not increase beyond Strategy A's interval (0.0092, CI 0.0036–0.0233) |
| quoted_attack FPR | 70 | must not increase beyond Strategy A's interval (0.0429, CI 0.0147–0.1186) |

The paired test is materially stronger than ADR-019's unpaired bound: on extraction it
detects a **net 6-sample** change (2.03pp, p = 0.0312), against roughly 15 samples for
a 5-point point-estimate bound. It is also not vacuous — net losses of 5 (with 0
gains), 9 (with 5 gains) or 12 (with 10 gains) all remain non-significant. ADR-019's
actual net −27 gives p = 1e-08.

**New mechanisms — unweakened from ADR-019 §17.** Wilson 95% lower bound ≥ **0.50**
for each of `retrieval_poisoning`, `tool_use_manipulation`, `safety_bypass`. At n = 60
this requires **≥ 38/60 = 0.6333**. ADR-019 achieved 44, 44, 58, so the bar is
attainable — and the ~2× reduction in extension exposure under 90/10 is exactly what
it is positioned to detect.

**Benign controls.** Both families reported separately, never merged; Wilson upper
≤ 0.10 each. Zero FP on 178 controls gives 0.0211; on the 90 document-carried
controls, 0.0409.

**Performance (§24).** Identical methodology across Strategy A, ADR-019 and the
successor: mean, p50, p95, p99, throughput, peak VRAM. No improvement claimed unless
measured. Strategy A's reference: p50 11.96 ms, p95 12.31 ms, p99 14.79 ms, 85.1/s.

**SUCCESS** = all three mechanism bounds **and** all four retention criteria **and**
both benign bounds **and** no unacceptable performance regression.
**FAILURE** = any retention criterion fails, or no mechanism meets its bound.
**INVALID** = the matrix does not complete, or contamination is detected.

Any retention failure is disqualifying, exactly as it was in ADR-019.

## Pre-registered failure modes

Recorded now so they cannot later be presented as insight.

1. **The 90/10 mixture starves the mechanisms.** Halving extension exposure may drop
   one or more below 38/60. This is the central risk of the replay arm and would show
   that the trade-off is real rather than an artefact of ADR-019's proportions.
2. **The proxy gate fails** — saturated, or blind to the known regression. Step 0
   ends the cheap path and the fallback cost must be paid.
3. **Seed variance swamps the effect**, and ADR-019's verdict needs amending.
4. **Both arms retain and neither learns**, or both learn and neither retains —
   implicating C1 (capacity) and promoting R5.
5. **Dev saturates again**, so thresholds stay underdetermined and only the
   matched-FPR analysis is interpretable.
6. **The replay sampler introduces its own artefact**: oversampling 3,006 v1 rows at
   90% for 486 steps repeats individual samples far more often than ADR-019 did, which
   is a memorisation risk the dev split is too saturated to detect.

## The layered-detector experiment (§19) — defined, not authorised

Should R1 and R2 both fail, C1 is the surviving explanation and a single classifier is
the wrong shape. The successor experiment would then be:

- **Arm L:** Strategy A's checkpoint, unmodified, **plus** a specialised detector
  trained only on the three mechanisms, combined by policy aggregation under the
  existing BLOCK > REDACT > WARN > ALLOW precedence.
- **Measured against:** the same retention and mechanism criteria as above, so results
  are directly comparable.
- **Additional cost that must be measured, not assumed:** a second model's inference
  latency and VRAM against the §24 budget, plus the aggregation semantics — which do
  not exist today and would need their own ADR.

This ADR does not authorise building, training, or integrating it.

## Hold-out protection (§22)

Training and selection touch **train and dev only**. holdout-v2, holdout-v3,
holdout-indirect-v1 and mechanisms-v1 are never reachable from the training path,
enforced by the AST-based `verify_isolation()` pattern established in ADR-019. No
hold-out text generates a training sample. The proxy is public data, not a hold-out.

| Corpus | scorings before ADR-020 | authorised by ADR-020 |
|---|---|---|
| holdout-v3 | 2 | **1** (winner only) |
| mechanisms-v1 | 1 | **1** (winner only) |
| holdout-indirect-v1 | 2 | 0 |
| holdout-v2 | 1 | 0 |

**Disclosure.** This diagnosis reasoned from ADR-019's *published* holdout-v3
aggregates. That is hold-out-informed design. It is declared here rather than
concealed, it is bounded (aggregates only — per-sample v3 scores for the ADR-019
checkpoint were never persisted, so no finer information was available), and it is a
further reason the eventual retention claim would be stronger on a corpus scored
fewer times.

## Explicitly not authorised by this ADR

**Running the training.** This is a protocol; executing it is a separate decision.

Also not authorised: production integration, enabling `by_trust` overlays, enabling
blocking, changing the 0.85 heuristic threshold, touching the detector registry,
modifying any frozen corpus or any ADR-019 artefact, building the R5 layered detector,
and building the Phase 8 dashboard.

## Verification

```bash
uv run pytest -m evaluation -q
uv run python -m scripts.datasets.build_mechanism_coverage --check
```

## Step 2 result — executed 2026-08-17, 6/6 runs

**COMPLETE.** All six registered runs succeeded, the matrix was not expanded, and no
protected hold-out was read. Evidence:
[`eval/results/finetune/ADR-020-step2/`](../../eval/results/finetune/ADR-020-step2/).

The mixture realised as registered, verified sample by sample rather than assumed from
the configured ratio: v1 0.899949 / extension 0.100051, attack fraction 0.19393,
extraction **0.38992** of attack mass (at or above the registered 0.389189 floor), the
three mechanisms exactly balanced at 53 each per epoch.

| arm | steps | dev F1 | dev FPR | dev separable | retrieval_poisoning | tool_use | safety_bypass |
|---|---|---|---|---|---|---|---|
| **T2** (2 epochs) | 486 | 0.998 / 1.0000 / 0.998 | 0.0000 ×3 | **True** ×3 | 1.0 ×3 | 1.0, 1.0, 0.9706 | 1.0 ×3 |
| **T3** (1 epoch) | 243 | 0.9753 / 0.9639 / 0.9732 | 0.0038 / 0.0150 / 0.0038 | **False** ×3 | 0.9286 / 0.9643 / 0.9643 | 0.8235 / 0.8824 / 0.7647 | 1.0 ×3 |

**Dev discriminated for the first time in this project** — T2 and T3 are fully disjoint
on dev F1, dev FPR, separability, and two of the three mechanisms. The saturation that
defeated selection in ADR-015, ADR-019 and ADR-020 Steps 0–1 did not recur here, because
T3's one-epoch budget leaves the model genuinely undertrained: its dev split does not
separate at all, the first `separable=False` in the project's history.

**But the retention signal stayed saturated.** Dev extraction recall is **1.0000 for all
six runs**, as is `quoted_attack` FPR (0.0000) and `safety_bypass` recall. So dev
acquired discriminating power over *general* quality and over the two hardest mechanisms
while remaining completely blind to the capability the experiment exists to protect.

**No causal claim is made here, and none can be.** ADR-020 §18's questions — does T2 or
T3 recover retention — are defined on holdout-v3 extraction and attack recall, which
§15 forbids reading in Step 2 and which Step 3 scores once. What Step 2 establishes is
that the runs exist, the contrasts are clean by construction, and the arms differ enough
that Step 3 can distinguish them.

One quantified cost, registered in advance as R-49: each mechanism now receives 53
samples per epoch against ADR-019's ~150. T3's tool-use recall (0.76–0.88 on dev, where
T2 reaches 0.97–1.00) is the first visible consequence.

A property of the replay worth stating plainly: strata are drawn **with replacement**
where a pool is smaller than its quota, so one epoch touches 2,579 of 3,878 training
rows — **66.5% coverage**, with extraction oversampled 1.28× from a pool of 230. The
replay arm is a *resampled* corpus, not the whole corpus plus extra extraction.

Wall-clock differed between T2 (≈209 s) and ADR-019 (≈260 s) at an identical 486-step
budget. **No cause is claimed.** The obvious candidate, sequence length, was checked and
rejected — the replay epoch's per-micro-batch padded cost is *higher* (140,709 vs
122,808 characters) while its wall-clock is lower. The two experiments ran at different
times under different machine load, so no throughput conclusion is drawn.

## Step 3 result — executed 2026-08-18 → **FAILURE**

Deployment candidate `T2__lr1e-05__ep2__seed13`, contrast `T3__lr1e-05__ep1__seed13`,
both locked with their matched-FPR thresholds before either hold-out was read. One
evaluation event; holdout-v3 and mechanisms-v1 each consumed one scoring. Evidence:
[`eval/results/finetune/ADR-020-step3/`](../../eval/results/finetune/ADR-020-step3/).

| holdout-v3 | Strategy A | ADR-019 | T2 | T3 | floor |
|---|---|---|---|---|---|
| extraction recall | 0.8446 | 0.7534 | **0.7669** | 0.7905 | 0.7946 |
| attack recall | 0.8174 | 0.7640 | **0.7725** | 0.7809 | 0.7674 |
| benign FPR | 0.0092 | 0.0161 | 0.0069 | 0.0069 | — |
| quoted_attack FPR | 0.0429 | 0.0571 | 0.0143 | 0.0286 | — |
| hard-negative FPR | 0.0167 | — | 0.0125 | 0.0125 | — |

Extraction recall misses its registered floor, and the paired exact-McNemar test shows
**significant degradation against Strategy A for both arms** (T2 p = 0.000034, net −23 of
296; T3 p = 0.000145, net −16). The registered rule — FAILURE if any retention criterion
fails — applies, exactly as it did to ADR-019.

| mechanisms-v1 | ADR-019 | T2 | T3 |
|---|---|---|---|
| retrieval_poisoning | 0.7333 | **0.3167** | 0.1167 |
| tool_use_manipulation | 0.7333 | **0.3500** | 0.0500 |
| safety_bypass | 0.9667 | **0.8500** | 0.6833 |

Only `safety_bypass` still clears the unweakened Wilson bound. **R-49 materialised at
full force**: mechanism exposure fell from ~119 to 53 samples per epoch and recall fell
with it. Benign controls held perfectly — 0 false positives on all 178, including all 90
document-carried — so neither model learned "retrieved content is malicious".

### The causal finding

ADR-019 lost 0.0912 of extraction recall. Restoring extraction's share of attack mass
(T2) recovered **15%** of that; halving the adaptation budget (T3) recovered **41%**.
Neither closes it, and both pay for it in mechanism coverage.

**The leading hypothesis was the weaker factor.** C2 (relative dilution) is substantially
weakened: it was the most-implicated variable in the causal table and buying it back
returned less than a sixth of the loss. C3 (adaptation budget) matters more but also
falls short.

**C1 — capacity / interference — is now the best-supported explanation.** Two independent
interventions, one on the data and one on the schedule, both slide along the same
trade-off curve without stepping off it. That is what a capacity constraint looks like at
fixed model size, and it is not something more data or another schedule repairs.

Taken with ADR-019 — which proved these mechanisms *are* learnable — the pair of results
says the mechanisms are learnable, but **not in the same model as extraction**. That
promotes OD-34, the layered detector.

### Also recorded

No T3 checkpoint was ever deployable: all three failed A-1's eligibility gate before
scoring, their dev splits being non-separable. That is independent of anything holdout-v3
showed.

The proxy anticipated the direction. On `lakera-gandalf` at matched FPR the ordering was
Strategy A 0.9720 > T3 0.9503 > T2 0.9303 > ADR-019 0.9126 — both arms above ADR-019,
neither reaching Strategy A, and T3 above T2. The hold-out reproduced that ordering
exactly, which is a point in the proxy's favour for future use.

**No production change. WARN ONLY, unchanged.**

## Revisit when

Step 0 or Step 1 returns, since either can end the sequence; when a decision is taken
to run Step 2; or when evidence arrives that the trade-off is intrinsic to a single
classifier, which promotes R5.
