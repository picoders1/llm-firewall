# Evaluation — injection.arch_guard

**Run:** `20260817T085647Z__injection-arch_guard__full-test`  
**Benchmark:** `full` / `test`  
**Samples:** 2051 (251 attack, 1800 benign)  
**Threshold:** 0.5

> Internal benchmark result. **Not** a published project metric.

## ⚠ Validity warnings

* 131 samples outside injection.arch_guard's scope were excluded; it is not answerable for those categories and scoring them would fabricate a recall number

## Classification

| Metric | Value | 95% CI |
|---|---|---|
| Recall (detection rate) | 0.9402 | [0.904, 0.964] |
| Precision | 0.9255 | [0.887, 0.952] |
| **FPR** | **0.0106** | [0.007, 0.016] |
| FNR | 0.0598 | — |
| F1 | 0.9328 | — |
| Accuracy | 0.9834 | — |

Confusion: TP=236 FP=19 TN=1781 FN=15

Threshold-free: average precision 0.9742, ROC-AUC 0.9928

## Per category

| Category | n | Recall | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| benign | 1800 | 0.0000 | 0.0106 | 0 | 19 | 0 |
| direct_prompt_injection | 250 | 0.9400 | 0.0000 | 235 | 0 | 15 |
| indirect_prompt_injection | 1 | 1.0000 | 0.0000 | 1 | 0 | 0 |

## Latency (detector only, not gateway overhead)

| Stage | mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| preprocess | 0.481 ms | 0.409 | 0.843 | 1.646 | 5.502 |
| inference | 123.903 ms | 107.936 | 176.638 | 360.315 | 952.073 |
| total | 124.384 ms | 108.326 | 177.387 | 361.932 | 955.332 |

Single-threaded throughput: 8.0/s (reciprocal of mean latency — not a concurrency measurement).

## Operating points

| Threshold | Recall | Precision | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| 0.0 | 1.0000 | 0.1224 | 1.0000 | 251 | 1800 | 0 |
| 0.0 | 1.0000 | 0.2783 | 0.3617 | 251 | 651 | 0 |
| 0.0001 | 0.9960 | 0.3536 | 0.2539 | 250 | 457 | 1 |
| 0.0001 | 0.9880 | 0.4066 | 0.2011 | 248 | 362 | 3 |
| 0.0002 | 0.9801 | 0.4598 | 0.1606 | 246 | 289 | 5 |
| 0.0002 | 0.9721 | 0.5010 | 0.1350 | 244 | 243 | 7 |
| 0.0004 | 0.9641 | 0.5525 | 0.1089 | 242 | 196 | 9 |
| 0.0007 | 0.9641 | 0.6253 | 0.0806 | 242 | 145 | 9 |
| 0.0014 | 0.9641 | 0.7139 | 0.0539 | 242 | 97 | 9 |
| 0.01 | 0.9522 | 0.8020 | 0.0328 | 239 | 59 | 12 |
| 0.316 | 0.9442 | 0.9222 | 0.0111 | 237 | 20 | 14 |
| 0.9999 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 251 |

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
* Config hash: `sha256:0d3b911a460dbca9`
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

