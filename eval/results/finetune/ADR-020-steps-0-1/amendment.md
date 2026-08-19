# ADR-020 amendment 1 — selection rule and threshold ordering

**Date:** 2026-08-17. **Raised by:** the §9 pre-Step-2 completeness check.
**Status:** required before Step 2 may run. **No hold-out has been read**, so this is a
change to a protocol, not a reinterpretation after seeing results.

ADRs in this project are amended, not edited. Both items below were identified by
evidence produced in Steps 0 and 1, and both would have corrupted Step 3 if left alone.

---

## A-1 — The selection rule was ambiguous, and half of it cannot work

ADR-020 Step 3 read:

> Rank the six checkpoints on the validated proxy plus dev.

That specifies no combination of the two signals, no tie-break, and — as Step 1
measured — **dev cannot rank anything**. Across all 36 checkpoints the dev metrics that
matter are saturated to the point of carrying zero information:

| dev metric | Strategy A family (n=18) | ADR-019 family (n=18) |
|---|---|---|
| extraction recall | mean 1.0000, **sd 0.0000** | mean 0.9990, sd 0.0041 |
| benign FPR | mean 0.0000, **sd 0.0000** | mean 0.0000, **sd 0.0000** |
| quoted_attack FPR | mean 0.0000, **sd 0.0000** | mean 0.0000, **sd 0.0000** |

A ranking key with zero variance is not a weak signal; it is no signal.

### Replacement rule, exact

Eligibility gate (dev, pass/fail only — contributes no ranking information):

* the dev split separates (`separable == True`), and
* dev attack recall ≥ 0.99 and dev benign FPR ≤ `MAX_DEV_FPR` (0.0241),

which together reject a degenerate or failed run without letting dev influence order.

Ranking keys, applied in order, all computed at each checkpoint's **matched-FPR**
threshold:

1. `lakera-gandalf` recall — descending. The retention signal, and the only
   non-saturated surface validated in Step 0.
2. `deepset-prompt-injections` attack recall — descending.
3. `eval_benign` FPR — ascending.
4. ADR-015's existing deterministic tie-break: lowest learning rate, then fewest
   epochs, then smallest seed.

Recorded in the selection lock before any hold-out is read, with
`holdout_used_in_selection: false`.

**Mechanism recall is deliberately excluded from the ranking key.** It is only
measurable on `mechanisms-v1`, which is a protected hold-out and is scored once, after
selection. Ranking on it would be selecting on the test set.

---

## A-2 — The primary threshold must become matched-FPR

ADR-020 made the dev-selected threshold **primary** and matched-FPR a secondary
comparability analysis. Step 1 measured the dev-selected threshold across all 36
checkpoints and that ordering is no longer defensible:

| family | dev-selected threshold across 18 runs |
|---|---|
| Strategy A | mean 0.9888, sd 0.0242, min **0.8954**, max 0.9999 |
| ADR-019 | mean 0.9422, **sd 0.2179**, min **0.0694**, max 0.9999 |

`mech__lr1e-05__ep2__seed20260817` selected **0.0694** where its sibling seed selected
**0.9954**, under identical methodology on the identical split. The quantity is not
noisy, it is arbitrary — an artefact of where a perfectly separating gap happens to
fall.

Step 0 also showed the practical consequence: comparing the two families at their
dev-selected thresholds put the gap at 0.0200, while comparing them at matched FPR put
it at 0.0621. **The dev-threshold comparison understated the regression roughly
threefold.**

Step 3 spends the single authorised holdout-v3 scoring. Doing that at a threshold drawn
from a distribution with sd 0.2179 would spend it at an arbitrary operating point.

### Replacement rule

* **Primary**, for the Step-3 hold-out scoring and every cross-model comparison:
  matched-FPR — smallest τ with FPR ≤ 1% on the frozen, seed-fixed 2,000-sample
  calibration draw, disjoint from the evaluation draw, applied identically to every
  model.
* **Secondary**, recorded for every model and reported alongside: the dev-selected
  threshold under the identical documented methodology, preserving continuity with the
  historical record.

This does **not** abandon the governing brief's §20 requirement that "every model gets a
DEV-selected threshold under the same documented methodology" — every model still gets
one and it is still recorded. What changes is which threshold the *comparison* is made
at, because §20 equally forbids comparing incompatible thresholds across models, and
Step 1 proved these are incompatible.

Historical published numbers are **not** restated. Strategy A's holdout-v3 results
remain the immutable reference at their own frozen threshold; the matched-FPR
comparison is reported as a separate, clearly labelled analysis.

---

## What is unchanged

The arms, the 90/10 mixture, the epoch strategy, the seeds, the retention criteria, the
mechanism criteria, and the hold-out budget are all unchanged. Amendment A-2 changes the
operating point at which retention is measured, so the registered retention criteria are
evaluated at the matched-FPR threshold and the dev-threshold figures are reported beside
them.

---

# ADR-020 amendment 2 — the Step-3 scoring plan cannot answer the Step-2 question

**Date:** 2026-08-18. **Raised by:** the §10 Step-3 precondition check, after Step 2
completed and **before any hold-out was read**. Nothing about this amendment depends on
a hold-out result, because none has been seen.

## A-3 — score the best of *each* arm, not one pooled winner

ADR-020 Step 3 reads:

> Rank the six checkpoints on the validated proxy. Score **one** winner on holdout-v3
> and mechanisms-v1.

Retention is defined on holdout-v3 (extraction recall, attack recall, benign FPR,
quoted_attack FPR) and mechanism learning on mechanisms-v1. Neither is measurable
anywhere else. So under the current plan, whichever arm loses the pooled ranking is
**never measured on the quantity the experiment exists to measure**.

Step 2's dev results make that concrete rather than hypothetical: T2 dominates T3 on
every dev metric (TP 245–246 vs 236–240, FP 0 vs 3–12, separable vs not), so the pooled
winner will almost certainly be a T2 checkpoint and T3 will go unscored.

The registered causal outcomes then collapse:

| ADR-020 §18 outcome | reachable under one pooled winner? |
|---|---|
| Composition strengthened (T2 restores retention) | yes |
| Adaptation budget strengthened (T3 restores retention) | **no — T3 never scored** |
| Both factors relevant | **no** |
| Neither (promoting the layered detector, OD-34) | only half — T2 failing says nothing about T3 |

Three of the six runs would produce no evidence toward the question that justified
spending them.

### Replacement rule

**One evaluation event, two pre-registered checkpoints**: the highest-ranked T2 and the
highest-ranked T3, each chosen by the A-1 ranking keys *within its own arm*, both locked
before any hold-out is read.

**The two are not equivalent in status, and conflating them would reintroduce exactly
the selection effect this discipline exists to prevent:**

* The **deployment candidate** is the pooled proxy-ranked winner across all six,
  locked in `selection_lock.json` before scoring. It is judged against the
  pre-registered criteria in `success_criteria.json`.
* The **contrast checkpoint** is the best of the other arm, scored in the same event
  **for causal evidence only**. It is explicitly *not* eligible for selection or
  deployment, and a better hold-out result for it does **not** make it the winner.
  Choosing between them after seeing hold-out numbers is forbidden.

### Why this is not budget inflation

The hazard a scoring budget guards against is **adaptive peeking** — look, adjust, look
again. Two checkpoints scored simultaneously, both fixed in advance, against criteria
fixed in advance, is a single look. ADR-019 set the precedent: it scored its own
checkpoint *and* rescored Strategy A on holdout-v3 in one event, and that counted as one
use.

Stated honestly, the cost is real but bounded: two arms judged against the same criteria
carries a slightly higher chance that one clears a bound by luck. It is not corrected
for, because each arm is judged against its **own** pre-registered criteria rather than
against the other, and no "best of two" selection is permitted.

### Revised budget

| Corpus | before ADR-020 | this ADR | after |
|---|---|---|---|
| holdout-v3 | 2 | 1 event, 2 checkpoints | 3 |
| mechanisms-v1 | 1 | 1 event, 2 checkpoints | 2 |
| holdout-indirect-v1 | 2 | 0 | 2 |
| holdout-v2 | 1 | 0 | 1 |

Anything beyond this requires a new ADR.

## What is unchanged

Arms, mixture, epochs, seeds, ranking keys (A-1), threshold ordering (A-2), retention
criteria, mechanism criteria, and the deployment-selection discipline.

---

# ADR-020 amendment 3 — A-1's eligibility gate and A-3's contrast target conflict

**Date:** 2026-08-18. **Raised by:** the Step-3 selection procedure, **before any
hold-out was read.** Determined from DEV data only. No hold-out result exists for any
T2 or T3 checkpoint at the time of writing, so nothing here can be a reaction to one.

## A-4 — the selection gate does not govern the contrast target

A-1 defined an eligibility gate:

> the dev split separates (`separable == True`), and dev attack recall >= 0.99 and dev
> benign FPR <= MAX_DEV_FPR (0.0241) — **which together reject a degenerate or failed
> run** without letting dev influence order.

Applied to Step 2's six runs at each checkpoint's dev-selected threshold:

| run | separable | dev recall | dev FPR | eligible |
|---|---|---|---|---|
| T2 seed13 | True | 1.0000 | 0.0000 | yes |
| T2 seed20260817 | True | 0.9959 | 0.0000 | yes |
| T2 seed31337 | True | 1.0000 | 0.0000 | yes |
| T3 seed13 | **False** | 0.9919 | 0.0175 | **no** |
| T3 seed20260817 | **False** | 0.9797 | 0.0201 | **no** |
| T3 seed31337 | **False** | 0.9878 | 0.0163 | **no** |

**Every T3 checkpoint fails the gate**, so A-3's required best-T3 contrast target cannot
be selected under A-1. The two amendments contradict each other and the protocol does
not resolve. ADR-020 Step 3 §21's instruction applies: stop, do not choose manually,
amend first.

### Why the gate misfires here

Its stated purpose is to *reject a degenerate or failed run*. None of the T3 runs is
either: all six carry `status: ok`, none produced constant dev scores, and dev F1 ranges
0.9639–0.9753. The gate's thresholds were calibrated against families whose dev splits
saturated perfectly, where `separable=False` really would have signalled a broken run.
Applied to a **deliberately under-trained arm** — the entire point of T3 — non-separability
is the expected outcome, not a defect. The gate cannot distinguish "this run failed" from
"this arm was registered to train less".

### Resolution

The gate governs **eligibility for selection and deployment**. The ranking keys govern
**ordering**. These are separate functions and A-3 already separates the roles:

> The **contrast checkpoint** ... is explicitly *not* eligible for selection or
> deployment.

Applying a selection-eligibility gate to a checkpoint that is by definition not eligible
for selection is a category error. Therefore:

* **Deployment candidate** — the pooled winner across all runs that **pass the A-1 gate
  unchanged**, ranked by the A-1 keys. Unchanged by this amendment.
* **Contrast target** — the best T3 by the A-1 **ranking keys alone**, with the
  eligibility gate not applied, scored for causal evidence only.

### What this amendment cannot do, and does not do

* It **does not change the deployment candidate.** All three T2 runs pass the gate
  either way; the pooled winner is drawn from them regardless.
* It **does not make any T3 checkpoint deployable.** All three remain ineligible, and
  that ineligibility is itself a Step-3 finding to be reported: the one-epoch arm
  produces no deployable model on the registered criteria, independent of anything
  holdout-v3 may show.
* It **cannot favour an outcome**, because no hold-out number exists yet for any
  candidate.

Its only effect is to permit the measurement that A-3 was created to obtain.
