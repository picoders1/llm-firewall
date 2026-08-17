# Evaluation — pii.regex

**Run:** `20260817T083213Z__pii-regex__full-dev`  
**Benchmark:** `full` / `dev`  
**Samples:** 1799 (1 attack, 1798 benign)  
**Threshold:** 0.5

> Internal benchmark result. **Not** a published project metric.

## ⚠ Validity warnings

* 351 samples outside pii.regex's scope were excluded; it is not answerable for those categories and scoring them would fabricate a recall number

## Classification

| Metric | Value | 95% CI |
|---|---|---|
| Recall (detection rate) | 1.0000 | [0.206, 1.000] |
| Precision | 0.1667 | [0.030, 0.564] |
| **FPR** | **0.0028** | [0.001, 0.006] |
| FNR | 0.0000 | — |
| F1 | 0.2857 | — |
| Accuracy | 0.9972 | — |

Confusion: TP=1 FP=5 TN=1793 FN=0

Threshold-free: average precision 1.0000, ROC-AUC 1.0000

## Per category

| Category | n | Recall | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| benign | 1798 | 0.0000 | 0.0028 | 0 | 5 | 0 |
| pii | 1 | 1.0000 | 0.0000 | 1 | 0 | 0 |

## Latency (detector only, not gateway overhead)

| Stage | mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| preprocess | 0.050 ms | 0.031 | 0.125 | 0.357 | 1.112 |
| inference | 0.027 ms | 0.018 | 0.067 | 0.187 | 0.537 |
| total | 0.077 ms | 0.049 | 0.189 | 0.518 | 1.649 |

Single-threaded throughput: 12963.9/s (reciprocal of mean latency — not a concurrency measurement).

## Operating points

| Threshold | Recall | Precision | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| 0.0 | 1.0000 | 0.0006 | 1.0000 | 1 | 1798 | 0 |
| 0.01 | 1.0000 | 0.1667 | 0.0028 | 1 | 5 | 0 |
| 0.61 | 1.0000 | 1.0000 | 0.0000 | 1 | 0 | 0 |
| 0.71 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 1 |

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
* Config hash: `sha256:775234f0d6d8535f`
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

