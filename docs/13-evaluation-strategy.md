# Evaluation Methodology

The evaluation harness is a first-class component, not a reporting afterthought. Its purpose
is to make every security claim in this repository **falsifiable by a reader on their own
machine**.

## Rules

1. **No number without a run.** Every metric in any document cites a committed report file
   under `eval/reports/`, which records the dataset, checksum, git commit, configuration and
   machine metadata that produced it.
2. **No metric without a denominator.** `n` is printed next to every metric. "94% recall"
   over 50 samples is noise wearing a lab coat.
3. **The harness never touches production traffic.** It drives detectors and the policy
   engine directly, or the HTTP API of a dedicated instance. Production data is never an
   evaluation input.
4. **A benchmark that contains the hold-out is not a calibration set.** The `full`
   benchmark includes the independent hold-out, so its dev split carries hold-out
   samples; calibration therefore reads `public/dev`, and a runtime guard raises if
   a hold-out sample reaches threshold selection. Caught before any threshold was
   chosen, and asserted by test.
5. **Test data is never tuned on.** Thresholds and rules are developed against `dev` and
   reported on `test`. Reporting a number after tuning on the same split is the most common
   way this category of project deceives itself.
5. **Negative results are published.** A detector that fails to beat the heuristic baseline
   is reported as such, in the same report.

## Label convention

Binary detection, **positive = attack**.

| | Predicted attack | Predicted benign |
|---|---|---|
| **Actually attack** | TP | FN — *the security failure* |
| **Actually benign** | FP — *the usability failure* | TN |

Prediction is `score ≥ threshold` for the detector under test, evaluated against a policy
configuration. This distinction matters: we report **detector-level** metrics (does the
classifier separate the classes) and **system-level** metrics (does the configured policy
produce the right action), because a good detector behind a badly configured threshold is a
bad firewall.

## Metrics

Computed with `scikit-learn`; definitions restated so no one has to guess the convention.

| Metric | Definition | Why it matters here |
|---|---|---|
| Precision | TP / (TP + FP) | Of blocked requests, how many deserved it |
| Recall (detection rate) | TP / (TP + FN) | Of attacks, how many were caught |
| F1 | harmonic mean | Single comparison number; **never reported alone** |
| **FPR** | FP / (FP + TN) | **The number that decides adoption.** At 100 req/s, a 1% FPR is 3 600 wrongly-blocked user requests per hour |
| FNR | FN / (TP + FN) | The residual risk being accepted |
| Per-category recall | recall within each attack category | An aggregate hides that indirect injection is far harder than direct |
| AUROC / AUPRC | threshold-free | Compares detectors independently of threshold choice |
| Threshold sweep | metrics across the score range | The operator's actual decision surface |

**Reported together, always.** Precision alone rewards a detector that blocks one obvious
attack and nothing else; recall alone rewards blocking everything. A block-everything
detector scores 100% recall and is a denial-of-service tool, which is why FPR on a large
benign corpus is the headline number in every report.

Confidence: Wilson score intervals at 95% on precision/recall/FPR. With a few hundred
samples the intervals are wide, and showing them prevents over-reading a difference between
0.91 and 0.93.

## Datasets and splits

Sources, licences and redistribution policy: [datasets.md](14-dataset-strategy.md).

Case schema:

```
sample_id      stable identifier, survives dataset regeneration
category       benign | direct_prompt_injection | indirect_prompt_injection
               | jailbreak | pii | system_prompt_extraction
expected_label true = attack
difficulty     easy | medium | hard   (author-assigned; used for stratified reporting)
source         dataset name + version
language       ISO code (coverage is currently English-dominated; reported, not hidden)
notes          optional
```

Splits are **deterministic and content-derived**:

```python
bucket = int(sha256(sample_id).hexdigest()[:8], 16) % 100
split = "test" if bucket < 20 else "dev" if bucket < 40 else "train"
```

No RNG seed, no shuffle order dependency: the same `sample_id` lands in the same split on
every machine, forever, and adding new cases never reshuffles existing ones. Class balance
per split is asserted by the harness and printed in the report.

**Benign corpus sizing.** FPR is the metric with the least tolerance for a small denominator
— it is also the one most often computed over a handful of hand-written benign prompts. The
benign set must be substantially larger than the attack set and drawn from realistic
application traffic patterns, not from prompts written by the same person who wrote the
attacks. Deviation from this is reported as a validity threat in the report itself.

## Baselines

Every detector is reported against baselines, because "94% recall" means nothing without
knowing what trivial approaches achieve:

| Baseline | Purpose |
|---|---|
| Always-benign | Establishes the floor; its accuracy is the class-imbalance sanity check |
| Always-attack | Its FPR is 100%; makes the recall/FPR trade explicit |
| **`injection.heuristic` (Phase 0)** | **The control condition.** A transformer detector's value is its delta over this, on the same split, on the same machine |
| Published model, off-the-shelf | Whether fine-tuning was worth it |

## Harness design

```
eval/
├── datasets/    registry.yaml (source, licence, checksum) · download scripts
│                · smoke/ (~40 hand-authored, ours, Apache-2.0)
├── runners/     InProcessRunner  — detectors + policy directly, no HTTP.
│                                   Used for detection quality; fastest, no server needed.
│                HttpRunner       — drives a running gateway over HTTP.
│                                   Used for latency/throughput; measures what a client sees.
├── metrics/     classification.py · latency.py · report.py
└── reports/     <run_id>.json  (machine-readable) + <run_id>.md (human-readable)
```

Two runners exist because the two questions are different. Detection quality must not be
measured through HTTP (network noise, no benefit); latency must not be measured in-process
(it would omit serialisation, routing and the upstream call — i.e. most of the cost).

Every run emits both a JSON report (for diffing and CI) and a Markdown report (for humans),
stamped with:

```
run_id · UTC timestamps · git commit + dirty flag · dataset name/version/split/checksum
detector configuration and thresholds · policy_version · sample counts per category
machine: CPU model, physical/logical cores, RAM, GPU + VRAM, OS, Python version
library versions · concurrency settings
```

A report that cannot name the commit and the machine is not evidence.

## Threats to validity (stated in every report)

1. **Static datasets underestimate an adaptive attacker.** Every attack in the corpus is one
   someone already published; a real T1 attacker iterates against *this* deployment. Static
   benchmark performance is an upper bound on real-world performance, not an estimate of it.
2. **Public attack corpora leak into training data.** Any published model may have seen
   these exact prompts. Reported numbers on public benchmarks are optimistically biased for
   published detectors — including the one we plan to use in Phase 2.
3. **Benign corpus representativeness.** FPR measured on generic instruction data does not
   predict FPR on a specific application's traffic. Security-adjacent applications
   ("summarise this phishing email") sit near the decision boundary by nature.
4. **Label noise.** "Jailbreak" versus "roleplay" is a judgement call; boundary cases are
   labelled by rule and the rule is documented with the dataset.
5. **Category imbalance.** Indirect injection is under-represented in public data relative
   to its real-world importance, so aggregate recall flatters the system.
6. **Single machine.** Latency figures are from one laptop-class machine unless stated;
   they characterise relative overhead, not absolute production performance.
7. **A criterion can be unsatisfiable at its denominator.** Combining a strict
   confidence-interval rule ("a straddling interval means not met") with a small
   sub-corpus produces a bound no model can reach. Two ADR-015 blocking criteria
   were found to be impossible at n=16 and n=17 — one of them measured a perfect
   zero and was still recorded as unmet. **Every pre-registered bound must be
   checked against its best possible outcome before it is agreed** (OD-22).
8. **A saturated split stops selecting silently.** All 18 Strategy A configurations
   reached identical perfect dev scores, so the selection criteria could not rank
   them and the checkpoint was decided entirely by tie-break. A split that cannot
   separate candidates looks like success and is a measurement failure; report the
   tie rather than the winner (OD-23).
9. **A category too small to measure will report a flattering number.**
   Indirect-injection recall was 1.0000 on the v2 hold-out at n=5, 0.4000 on v3
   at n=20, and **0.1423** on a corpus of 520 sized to answer the question.
   Nothing about the model changed across those three figures. Any category whose
   denominator is single-digit should be reported as *not evaluated*, not as a
   rate (OD-25, resolved).
10. **An aggregate rate hides a categorical failure.** The same 0.1423 decomposes
   into six delivery shapes at exactly 0.0000 and one at 0.7250. Reporting only
   the aggregate would have described a weak detector rather than a detector that
   is blind to entire channels. Where a threat arrives through distinguishable
   channels, measure per channel or state that you did not.
11. **Benign controls must share the container with the attacks.** Pairing every
   attack shape with the same shape carrying inert content is what revealed that
   `system_marker` recall (0.5667) and `system_marker` false positives (0.2000)
   move together — a detector firing on syntax, not intent. Recall alone cannot
   show this.

## LLM-as-judge

Permitted **only** in the offline harness, for labelling assistance and output-quality
grading, and never in the production request path
([ADR-006](adr/ADR-006-evaluation-methodology.md)). Where used, the report records the
judge model, version, prompt, and its agreement rate against human labels on a sample. An
unvalidated judge is an opinion, not a measurement.

## Reproducing a report

```bash
uv run python -m eval.runners.run \
    --dataset smoke --split test \
    --detectors injection.heuristic,pii.regex \
    --report eval/reports/
```

Determinism: same dataset checksum + same config + same commit ⇒ identical classification
metrics. Latency metrics are *not* deterministic and are reported as distributions with the
machine metadata attached; the harness refuses to emit latency figures from a run with fewer
than the configured minimum iterations.

## Status

**The framework is built, tested and has produced measured results**
(`eval/`, `eval/results/`, [ADR-014](adr/ADR-014-detector-selection.md)). Metrics are
implemented directly rather than via scikit-learn — a security benchmark's arithmetic should
be auditable in the repository that publishes it — and are verified against hand-computed
confusion matrices *and* against scikit-learn where it is installed.

**Gateway latency and throughput benchmarking has NOT been run.** Those figures still read
`pending benchmark execution`. The detector-level latencies in `eval/results/` are a
different measurement and are labelled as such in every report.

## Sizing an evaluation corpus

A bound and a confidence-interval rule together imply a **minimum denominator**,
and it is not optional. Before agreeing any criterion:

```python
minimum_n_for_fpr(bound, rate)  # smallest n with wilson_upper(round(rate*n), n) <= bound
minimum_n_for_recall(bound, rate)  # smallest n with wilson_lower(round(rate*n), n) >= bound
```

Both live in `scripts/datasets/build_holdout_v3.py`; `--sizing` prints the table.

Three rules, each learned by violating it:

1. **Check achievability before agreeing a bound.** ADR-015 paired
   `quoted_attack FPR <= 0.15` with n=16. Even 0 false positives yields a Wilson
   upper bound of 0.1936, so no model could ever pass. `incident_response`
   measured a perfect 0/17 and was recorded as failing.
2. **Size against the observed rate, not against perfection.** A corpus sized for
   a flawless result fails the moment the model makes one mistake.
3. **Size to 1.5x the minimum when the estimate is within 10 points of the
   bound.** Hold-out v3 gave `system_prompt_extraction` a margin of +4 over its
   292 minimum; the result then missed the bound by a single sample, which is too
   close to distinguish model behaviour from sampling noise.
4. **Size a category to the decision it must support, not to "coverage".** v3
   sized indirect injection at n=20 as supporting coverage; its 0.4000
   [0.2188, 0.6134] could not be acted on, and the true figure turned out to be
   0.1423. Where the question is *"is this reliably detected?"*, size so the
   interval lands on one side of the bound: at n=50 a shape is conclusive unless
   its true recall sits in 0.68–0.92.

Worked example: [the delivery-shape sizing](../eval/results/20260817T130736Z__indirect-delivery-shape/report.md).

Worked example: [hold-out v3's sizing analysis](../eval/results/20260817T125002Z__holdout-v3-validation/sample_size_analysis.md).

**Fine-tuning experiments follow the same discipline, enforced in code.** Strategy A
([ADR-015](adr/ADR-015-fine-tuning-strategy.md)) ran as four separate commands so the
ordering is a filesystem property rather than a claim: `--select` (dev only) writes
`selection_lock.json`; `--verify-lock` writes `pre_holdout_verification.json` after
twelve checks; `--holdout` refuses to run without a passing verification, refuses if
the checkpoint or hold-out hash moved, and refuses to run twice. Threshold calibration
goes through `eval.metrics.calibration.calibrate()`, whose `require_tunable()` raises
on a frozen split, so the dev-only guarantee is enforced by the library rather than by
the caller.

*Superseded status note:*

What exists today is `eval/datasets/smoke/` — 31 hand-authored cases plus plumbing tests
(`tests/evaluation/`) proving the case schema parses, labels are handled correctly, detectors
are deterministic, results group by category, and split assignment is content-derived and
stable. **No metric is computed from it and none may be quoted**: n=31, authored by the same
person who wrote the detection rules, with no realistic benign distribution. Its own README
says so, and a test asserts that the README says so.

The runner, metrics module and report writer are Phase 4, together with licensed corpora and
a benign set large enough to give FPR a credible denominator.

---

## Evaluating a provenance-aware detector (planned)

[ADR-017](adr/ADR-017-provenance-aware-detection-context.md) is a design; no
provenance-aware detector exists. When one does, the experiment has one property
the delivery-shape corpus already supplies, and two constraints that follow from
what has already been spent.

**The corpus is ready.** `holdout-indirect-v1` records `user_framing`
(`innocent_processing` / `complicit_directive` / `security_discussion`) as a
dimension independent of the label. That is exactly the manipulation a provenance
experiment needs: **hold the text constant and vary the declared provenance.** A
detector that genuinely consumes provenance must show a different score for
identical bytes under different provenance; one that merely advertises
`consumes_provenance = True` will not (R-35).

**`holdout-indirect-v1` has been scored once.** Any future run against it is a
**second** evaluation of that corpus and must be declared as such in its report.
It is now a fixed reference point — 0.1423 overall, per-shape verdicts recorded —
which is what makes a before/after comparison meaningful, and also what makes
re-use a methodological cost rather than a free measurement. A provenance
experiment that needs a clean hold-out needs a new one.

**Criteria must be achievability-checked before they are agreed** — the rule this
project learned twice (ADR-015's unsatisfiable bounds, then v3's `system_marker`
sizing). For a provenance detector the per-shape decision bound and its
denominator are already worked out in
`scripts/datasets/build_indirect_v1.py --sizing`; reuse that calculation rather
than picking round numbers.

### Paired comparisons need a paired test

Executed in [ADR-018](adr/ADR-018-provenance-aware-detector-evaluation.md). When two
detector variants are scored on **the same samples**, independent Wilson intervals
are the wrong instrument: they ignore the pairing and discard most of the power.
The correct test is **McNemar's exact binomial on discordant pairs**, implemented in
`scripts/evaluate_provenance.py` rather than imported, on the same principle that
keeps the rest of the benchmark's arithmetic auditable in-repo.

The gain in sensitivity is large. At n=520, **six net detections with zero losses
reaches p = 0.031** — so a null result from such a comparison cannot be explained
away as insufficient power, which is exactly the property that makes it worth
running.

Wilson intervals remain the right descriptive statistic per arm. Both are reported.

### Every criterion must state its direction

A defect found while executing ADR-018 and recorded in that run's `amendment.md`.
Criterion 3 read "McNemar p < 0.05 on recall **or** FPR", which is satisfiable by a
*significant degradation* — and the run tripped exactly that case. The verdict did
not change, but the wording would eventually have accepted a worse arm as evidence
of improvement.

**Rule:** a criterion comparing two arms must state which direction counts as a
pass, and the check must test it.

### An arm that cannot fail is not a control

ADR-018's arm A1 (provenance available but constant across classes) scored 0.0000 by
construction: the corpus is flat, so no span is untrusted and a provenance-consuming
detector has nothing to score. That is a tautology, not a measurement.

Before running an arm, ask what value the manipulated variable actually takes across
the classes. If it is constant, the arm answers nothing — and if *every* arm has
that property, the experiment does not exist yet. ADR-018 found this before designing
the treatment, which is why it has a segmentation condition at all.

---

## Extending a corpus: what to check that nothing else does

Learned building the ADR-019 mechanism extension. Each of these was a real defect
caught by a gate, not a hypothetical.

**A shortcut feature invalidates a corpus even when every metric improves.** If every
attack arrives in one kind of wrapper and every negative in another, the wrapper
predicts the label and a model can score perfectly without reading the payload. It
will then fire on the wrapper in production. Check the label distribution of *every*
structural feature — carrier, domain, length band — before training, and require both
labels in each.

**Reproduce a prior split rule exactly, digest slice and boundary included.** A rule
that differs by one character silently moves samples between splits, and if the old
corpus is a subset of the new one, that leaks prior *training* data into the new *dev*
split. Assert the round-trip.

**A hold-out needs disjoint pools for every population, not just the attacks.** Benign
and filler content shared between train and hold-out produces collisions in exactly
the samples nobody inspects.

**Set a target the pools can reach without repetition.** Padding to hit a number
inflates the count and teaches nothing; the builder should refuse rather than repeat.

**Record the class-balance change.** Adding attacks shifts the ratio, and a ratio
shift is a confound against comparing to the prior experiment. Say so where the
comparison is made.

---

## Capability retention is a first-class criterion, not an afterthought

ADR-019 is the case. A corpus extension took three attack mechanisms from **0.0000**
to 0.73–0.97 with **zero** false positives — an unambiguous success on everything it
was built to do — and the run still failed, because system-prompt extraction on a
prior hold-out fell 9.1 points.

Three things that made the failure visible rather than invisible:

**Regression criteria were pre-registered with numeric bounds against published
values.** Without criteria 4 and 5, the run would have been reported as a clean
success and a 9-point loss in the capability the base model was *selected for*
would have shipped unnoticed.

**The baseline was rescored, not merely cited.** Both checkpoints were scored on
holdout-v3 at their own frozen thresholds, and the old model's numbers reproduced the
published values exactly in all four rows. That is what licenses reading the deltas
as model differences rather than measurement drift — a citation alone would not have.

**The direction of each criterion was stated.** Following the ADR-018 amendment,
every comparison declares which way counts as a pass, so a regression cannot satisfy
a criterion written to detect an improvement.

**Rule:** any experiment that adds training data must measure what the model could
already do, against a rescored baseline, under bounds fixed in advance. An
improvement on the new thing is not evidence of an improvement overall.

---

## When nothing left can rank checkpoints

ADR-020 hit a wall the earlier phases only warned about: the v2 dev split scores
perfectly on all nine attack categories and 0/798 on benign, so it can neither rank
candidates nor fix a threshold. Hold-outs cannot substitute — holdout-v3 has been
scored twice and mechanisms-v1 once, and ranking six checkpoints on either destroys
them.

**A third signal must be found outside both.** The rule adopted, which generalises
beyond this case:

**1. It must be provably disjoint from training.** The public corpora in
`eval/datasets/raw/` were never used in fine-tuning; disjointness from finetune-v2 is
verified across all 10,947 samples by `eval.schema.normalised_key`, not assumed from
provenance.

**2. Contamination bounds what it may be used for, and is stated up front.** Those
corpora were used for base-model selection in ADR-014 and are plausibly in the base
model's pretraining. Absolute numbers on them are therefore **not claimable as
capability**. They may rank two fine-tunes of the *same* base, where the bias is a
shared constant that cancels in the comparison — and nothing else.

**3. The signal must be gated on reproducing a known effect.** This is the part that
makes the argument falsifiable rather than convenient. ADR-020 uses the proxy only if
it recovers the already-established Strategy A > ADR-019 gap by exact McNemar. A proxy
blind to an effect known to exist cannot be trusted on effects that are not.

**Rule:** a substitute evaluation signal is admissible only when its disjointness is
verified, its contamination is stated as a limit on the claims it can support, and its
sensitivity is demonstrated against an effect already measured by other means.

## Comparing models whose thresholds are not commensurable

A saturated dev split does not merely fail to rank — it leaves the selected threshold
**underdetermined**, because every value inside the separating gap scores identically.
ADR-019's 0.9954 and Strategy A's 0.9955 were separated by tie-break, not by data.
Comparing two models at two arbitrary points inside their own gaps is the "incompatible
thresholds" error.

Two thresholds are therefore recorded per model from ADR-020 onward:

**Primary — dev-selected**, under the identical documented methodology and tie-break,
so the successor stays comparable with the historical record. Where dev is saturated,
say so, and say the threshold is underdetermined.

**Secondary — matched-FPR, for comparability only**: the smallest τ giving ≤ 1% FPR on
a frozen, seed-fixed benign draw, applied identically to every model, so models are
compared at the same operating point.

Published historical numbers are **never restated** when a new comparison method is
adopted. The matched-FPR figures are reported as a clearly labelled additional
analysis beside them.

## Paired tests are cheaper than bigger hold-outs

ADR-019 judged retention with an unpaired 5-point bound on a point estimate. On
holdout-v3's 296 extraction samples that needs roughly 15 samples of movement before
it can distinguish a regression from noise.

The same corpus, tested **paired** with exact McNemar on the same samples, detects a
**net 6-sample** change — 2.03pp, p = 0.0312. Two and a half times the sensitivity at
no cost in data, because both models are scored on identical samples and only the
discordant pairs carry information.

**Rule:** when comparing two models on the same corpus, test the pairs, not the rates.
Retention criteria should state both a paired significance test **and** a point-estimate
margin, so that a change is disqualifying when it is either statistically detectable or
practically large.

**And separate the two kinds of variance.** ADR-019's regression carries p = 1e-08,
but that is **sampling** error on one corpus for one pair of checkpoints. It says
nothing about **run-to-run** variance across seeds, which is a different question and
had never been measured here at all. A p-value against sampling noise is not evidence
that a training condition reproduces.

## A saturated split cannot estimate variance either

ADR-020 Step 1 needed run-to-run variance. All 36 checkpoints had persisted per-sample
dev scores, so the obvious move was to compute the spread across them. The result:

| dev metric | Strategy A (n=18) | ADR-019 (n=18) |
|---|---|---|
| extraction recall | mean 1.0000, **sd 0.0000** | mean 0.9990, sd 0.0041 |
| benign FPR | mean 0.0000, **sd 0.0000** | mean 0.0000, **sd 0.0000** |
| quoted_attack FPR | mean 0.0000, **sd 0.0000** | mean 0.0000, **sd 0.0000** |

Read carelessly this says "run-to-run variance is essentially zero", which would be a
strong and completely unfounded claim. It says nothing of the sort: the split separates
perfectly, so every checkpoint scores identically **by construction**. The near-zero
spread measures the saturation, not the models.

**Rule:** a variance estimate is only meaningful on a surface where the metric can
actually move. Before quoting a spread, check that the metric is not already at its
ceiling or floor — and if it is, say the variance is *unmeasured*, not *small*.

The corollary bites harder. Per-checkpoint hold-out metrics were recorded for only the
two selected winners, so hold-out run-to-run variance **cannot** be recovered from the
artefacts at all, and rescoring is not permitted. The estimate had to come from the
public proxy at three seeds per family — a surface that is contaminated for absolute
claims but *not saturated*, which is exactly the property required here.

**Rule:** persist per-checkpoint metrics for every run, not only the winner. The
marginal cost is a JSON file; the alternative is discovering later that the question you
need to answer was made unanswerable by an earlier convenience.

## A ranking key with zero variance is not a weak signal

The same measurement retired a selection rule. ADR-020 originally ranked candidates on
"the validated proxy plus dev" without specifying how the two combined — and dev's
contribution turned out to be identically zero across all 18 runs of a family.

**Rule:** when a protocol names multiple selection signals, state the combination rule
and the tie-break explicitly, and verify each signal has non-zero variance on the
population it will rank. An unspecified combination is not a detail to settle at
execution time; settling it then is selection pressure applied after seeing results.

## A split can discriminate and still be blind to the thing under test

ADR-020 Step 2 broke the saturation pattern: T2 and T3 separate cleanly on dev F1, dev
FPR, dev separability and two of three mechanisms. After three experiments in which dev
could rank nothing, that looks like the problem being solved.

It is not. Dev **extraction recall is 1.0000 for all six runs** — and extraction is the
capability the whole experiment exists to protect. `quoted_attack` FPR (0.0000) and
`safety_bypass` recall (1.0000) are equally flat. The split gained discriminating power
over general quality while staying completely blind on the retention question.

**Rule:** "does the split discriminate?" is the wrong question. Ask "does it discriminate
*on the metric the decision turns on*?" Report per-metric saturation, not a single
verdict for the split — a headline F1 that finally moves can disguise a flat line on the
one measurement that matters.

The corollary is that a discriminating split is not a licence to skip the hold-out. Here
it would have justified exactly the wrong inference: T3 looks clearly worse on dev, yet
reduced adaptation is precisely the arm that might *preserve* retention at the cost of
new-mechanism learning — a trade-off dev cannot see because its extraction recall has no
room to move.

## When two controlled arms both fail, the failure is the finding

ADR-020 tested the two cheapest explanations for ADR-019's regression as separate arms,
each varying one factor. Both failed, and the *pattern* of failure carried more
information than either arm alone.

| arm | varies | recovered of the 0.0912 loss | cost |
|---|---|---|---|
| T2 | composition (replay), step budget fixed | 15% | two of three mechanisms collapsed |
| T3 | adaptation budget, sampler fixed | 41% | collapsed further |

Two independent interventions — one on the data, one on the schedule — moved along the
same trade-off curve without stepping off it. Neither result would have been decisive on
its own; together they implicate a cause neither arm manipulated (capacity), and they do
so *because* both arms were controlled and comparable.

**Rule:** design the arms so that a shared failure is interpretable, not just so that a
success would be. Two arms that fail differently tell you where the cause is not; two
arms that fail the same way tell you where it is.

The corollary is that **the leading hypothesis is worth testing precisely because it is
leading.** Relative dilution was the most-implicated variable in ADR-020's causal table —
extraction's share of attack mass had fallen 14.72pp while its absolute count never moved
— and restoring it recovered less than a sixth of the loss. Had it not been tested
directly, that hypothesis would still be the standing explanation.

## Score the arm you will not deploy

ADR-020's original Step 3 scored one pooled winner. Because one arm dominated on dev, the
other would never have been measured on the hold-out — and three of six runs would have
produced no evidence toward the question that funded them. Amendment A-3 changed it to
score both arms in one pre-registered event.

That decision produced the finding. The contrast arm (T3) recovered **2.7× more** of the
regression than the deployment candidate, while being simultaneously undeployable. Under
the original plan the result would have read "replay recovers 15%, cause unknown"; under
the amendment it reads "composition is the weaker of the two factors, and neither
suffices".

**Rule:** when arms are registered to isolate different factors, every arm needs a
measurement on the deciding corpus, or the factors it isolates were never tested. Scoring
two pre-registered checkpoints simultaneously is one look, not two — the hazard a scoring
budget guards against is adaptive peeking, and there is none when both targets and all
criteria are fixed in advance. Keep the roles distinct: one candidate is selectable, the
other is contrast-only and cannot be promoted by a good result.
