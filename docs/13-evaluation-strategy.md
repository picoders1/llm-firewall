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

*Superseded status note:*

What exists today is `eval/datasets/smoke/` — 31 hand-authored cases plus plumbing tests
(`tests/evaluation/`) proving the case schema parses, labels are handled correctly, detectors
are deterministic, results group by category, and split assignment is content-derived and
stable. **No metric is computed from it and none may be quoted**: n=31, authored by the same
person who wrote the detection rules, with no realistic benign distribution. Its own README
says so, and a test asserts that the README says so.

The runner, metrics module and report writer are Phase 4, together with licensed corpora and
a benign set large enough to give FPR a credible denominator.
