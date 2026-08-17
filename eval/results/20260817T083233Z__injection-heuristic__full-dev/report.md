# Evaluation — injection.heuristic

**Run:** `20260817T083233Z__injection-heuristic__full-dev`  
**Benchmark:** `full` / `dev`  
**Samples:** 2032 (234 attack, 1798 benign)  
**Threshold:** 0.55

> Internal benchmark result. **Not** a published project metric.

## ⚠ Validity warnings

* 118 samples outside injection.heuristic's scope were excluded; it is not answerable for those categories and scoring them would fabricate a recall number

## Classification

| Metric | Value | 95% CI |
|---|---|---|
| Recall (detection rate) | 0.4402 | [0.378, 0.504] |
| Precision | 0.9115 | [0.845, 0.951] |
| **FPR** | **0.0056** | [0.003, 0.010] |
| FNR | 0.5598 | — |
| F1 | 0.5937 | — |
| Accuracy | 0.9306 | — |

Confusion: TP=103 FP=10 TN=1788 FN=131

Threshold-free: average precision 0.7375, ROC-AUC 0.7185

## Per category

| Category | n | Recall | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| benign | 1798 | 0.0000 | 0.0056 | 0 | 10 | 0 |
| direct_prompt_injection | 228 | 0.4342 | 0.0000 | 99 | 0 | 129 |
| indirect_prompt_injection | 3 | 0.6667 | 0.0000 | 2 | 0 | 1 |
| system_prompt_extraction | 3 | 0.6667 | 0.0000 | 2 | 0 | 1 |

## Latency (detector only, not gateway overhead)

| Stage | mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| preprocess | 0.050 ms | 0.032 | 0.124 | 0.324 | 1.073 |
| inference | 0.052 ms | 0.037 | 0.118 | 0.306 | 0.912 |
| total | 0.102 ms | 0.069 | 0.243 | 0.619 | 1.985 |

Single-threaded throughput: 9832.9/s (reciprocal of mean latency — not a concurrency measurement).

## Threshold selection

* Objective: `max_recall_at_fpr` (constraint: 0.01)
* Selected threshold: **0.55**
* Constraint satisfied: **True**
* Rationale: highest recall (0.4402) among thresholds with FPR <= 0.01 on the dev split

## Operating points

| Threshold | Recall | Precision | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| 0.0 | 1.0000 | 0.1152 | 1.0000 | 234 | 1798 | 0 |
| 0.01 | 0.4402 | 0.9115 | 0.0056 | 103 | 10 | 131 |
| 0.56 | 0.4316 | 1.0000 | 0.0000 | 101 | 0 | 133 |
| 0.71 | 0.4274 | 1.0000 | 0.0000 | 100 | 0 | 134 |
| 0.76 | 0.4188 | 1.0000 | 0.0000 | 98 | 0 | 136 |
| 0.86 | 0.3761 | 1.0000 | 0.0000 | 88 | 0 | 146 |
| 0.91 | 0.0385 | 1.0000 | 0.0000 | 9 | 0 | 225 |
| 0.96 | 0.0342 | 1.0000 | 0.0000 | 8 | 0 | 226 |
| 0.99 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 234 |

## Data sources

| Dataset | Licence | Commercial use | Contamination risk |
|---|---|---|---|
| holdout | Apache-2.0 | permitted | none |
| deepset-prompt-injections | apache-2.0 | permitted | high |
| jackhhao-jailbreak | apache-2.0 | permitted | high |
| lakera-gandalf | mit | permitted | high |
| oasst1-benign | apache-2.0 | permitted | medium |
| dolly-benign | cc-by-sa-3.0 | permitted-with-share-alike | medium |

## Reproducibility

* Commit: `None` (dirty: True)
* Dataset checksum: `sha256:a643d90722025e53ff492c9a55bc2546`
* Config hash: `sha256:5e2f66536b1f7093`
* Lockfile: `sha256:3db9ddec3208c4f0`
* Python 3.12.3 on Linux 7.0.0-28-generic
* CPU: 12th Gen Intel(R) Core(TM) i7-12650H (16 logical), 31.0 GB RAM
* GPU: NVIDIA GeForce RTX 3050 Laptop GPU 4096 MiB
* Seed: 20260817

> laptop — relative overhead only, not production capacity

## Threats to validity

* **Static datasets underestimate an adaptive attacker.** Every case here is one someone already published; a real attacker iterates against *this* deployment.
* **Public corpora may be in a model's training data.** Any published detector's numbers on them are optimistically biased.
* **Benign representativeness.** FPR measured on this corpus does not predict FPR on a specific application's traffic.
* **Label noise.** The jailbreak/roleplay boundary is a judgement call.

