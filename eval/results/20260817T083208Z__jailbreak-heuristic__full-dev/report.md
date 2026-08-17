# Evaluation — jailbreak.heuristic

**Run:** `20260817T083208Z__jailbreak-heuristic__full-dev`  
**Benchmark:** `full` / `dev`  
**Samples:** 1915 (117 attack, 1798 benign)  
**Threshold:** 0.85

> Internal benchmark result. **Not** a published project metric.

## ⚠ Validity warnings

* 235 samples outside jailbreak.heuristic's scope were excluded; it is not answerable for those categories and scoring them would fabricate a recall number

## Classification

| Metric | Value | 95% CI |
|---|---|---|
| Recall (detection rate) | 0.4786 | [0.390, 0.568] |
| Precision | 0.9655 | [0.883, 0.991] |
| **FPR** | **0.0011** | [0.000, 0.004] |
| FNR | 0.5214 | — |
| F1 | 0.6400 | — |
| Accuracy | 0.9671 | — |

Confusion: TP=56 FP=2 TN=1796 FN=61

Threshold-free: average precision 0.7693, ROC-AUC 0.8224

## Per category

| Category | n | Recall | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| benign | 1798 | 0.0000 | 0.0011 | 0 | 2 | 0 |
| jailbreak | 117 | 0.4786 | 0.0000 | 56 | 0 | 61 |

## Latency (detector only, not gateway overhead)

| Stage | mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| preprocess | 0.098 ms | 0.032 | 0.412 | 1.405 | 4.372 |
| inference | 0.089 ms | 0.033 | 0.374 | 1.147 | 3.661 |
| total | 0.187 ms | 0.066 | 0.796 | 2.514 | 8.033 |

Single-threaded throughput: 5355.7/s (reciprocal of mean latency — not a concurrency measurement).

## Operating points

| Threshold | Recall | Precision | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| 0.0 | 1.0000 | 0.0611 | 1.0000 | 117 | 1798 | 0 |
| 0.01 | 0.6496 | 0.8000 | 0.0106 | 76 | 19 | 41 |
| 0.31 | 0.5897 | 0.9718 | 0.0011 | 69 | 2 | 48 |
| 0.66 | 0.5812 | 0.9714 | 0.0011 | 68 | 2 | 49 |
| 0.83 | 0.4786 | 0.9655 | 0.0011 | 56 | 2 | 61 |
| 0.86 | 0.2991 | 1.0000 | 0.0000 | 35 | 0 | 82 |
| 0.9 | 0.2051 | 1.0000 | 0.0000 | 24 | 0 | 93 |
| 0.9685 | 0.1453 | 1.0000 | 0.0000 | 17 | 0 | 100 |
| 0.9775 | 0.1197 | 1.0000 | 0.0000 | 14 | 0 | 103 |
| 0.98 | 0.0427 | 1.0000 | 0.0000 | 5 | 0 | 112 |
| 0.99 | 0.0342 | 1.0000 | 0.0000 | 4 | 0 | 113 |
| 0.9986 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 117 |

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
* Config hash: `sha256:a769b40194e1f450`
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

