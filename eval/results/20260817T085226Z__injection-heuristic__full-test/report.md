# Evaluation — injection.heuristic

**Run:** `20260817T085226Z__injection-heuristic__full-test`  
**Benchmark:** `full` / `test`  
**Samples:** 2051 (251 attack, 1800 benign)  
**Threshold:** 0.85

> Internal benchmark result. **Not** a published project metric.

## ⚠ Validity warnings

* 131 samples outside injection.heuristic's scope were excluded; it is not answerable for those categories and scoring them would fabricate a recall number

## Classification

| Metric | Value | 95% CI |
|---|---|---|
| Recall (detection rate) | 0.4183 | [0.359, 0.480] |
| Precision | 1.0000 | [0.965, 1.000] |
| **FPR** | **0.0000** | [0.000, 0.002] |
| FNR | 0.5817 | — |
| F1 | 0.5899 | — |
| Accuracy | 0.9288 | — |

Confusion: TP=105 FP=0 TN=1800 FN=146

Threshold-free: average precision 0.7128, ROC-AUC 0.7164

## Per category

| Category | n | Recall | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| benign | 1800 | 0.0000 | 0.0000 | 0 | 0 | 0 |
| direct_prompt_injection | 250 | 0.4160 | 0.0000 | 104 | 0 | 146 |
| indirect_prompt_injection | 1 | 1.0000 | 0.0000 | 1 | 0 | 0 |

## Latency (detector only, not gateway overhead)

| Stage | mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| preprocess | 0.048 ms | 0.030 | 0.120 | 0.320 | 1.657 |
| inference | 0.050 ms | 0.035 | 0.116 | 0.288 | 1.506 |
| total | 0.098 ms | 0.065 | 0.234 | 0.604 | 3.163 |

Single-threaded throughput: 10191.3/s (reciprocal of mean latency — not a concurrency measurement).

## Operating points

| Threshold | Recall | Precision | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| 0.0 | 1.0000 | 0.1224 | 1.0000 | 251 | 1800 | 0 |
| 0.01 | 0.4382 | 0.8661 | 0.0094 | 110 | 17 | 141 |
| 0.56 | 0.4263 | 1.0000 | 0.0000 | 107 | 0 | 144 |
| 0.76 | 0.4183 | 1.0000 | 0.0000 | 105 | 0 | 146 |
| 0.86 | 0.3386 | 1.0000 | 0.0000 | 85 | 0 | 166 |
| 0.91 | 0.0279 | 1.0000 | 0.0000 | 7 | 0 | 244 |
| 0.96 | 0.0199 | 1.0000 | 0.0000 | 5 | 0 | 246 |
| 0.99 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 251 |

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

