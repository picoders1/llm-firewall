# Evaluation — injection.protectai_deberta_v2

**Run:** `20260817T085230Z__injection-protectai_deberta_v2__full-test`  
**Benchmark:** `full` / `test`  
**Samples:** 2051 (251 attack, 1800 benign)  
**Threshold:** 0.5

> Internal benchmark result. **Not** a published project metric.

## ⚠ Validity warnings

* 131 samples outside injection.protectai_deberta_v2's scope were excluded; it is not answerable for those categories and scoring them would fabricate a recall number

## Classification

| Metric | Value | 95% CI |
|---|---|---|
| Recall (detection rate) | 0.9283 | [0.889, 0.954] |
| Precision | 0.9066 | [0.865, 0.936] |
| **FPR** | **0.0133** | [0.009, 0.020] |
| FNR | 0.0717 | — |
| F1 | 0.9173 | — |
| Accuracy | 0.9795 | — |

Confusion: TP=233 FP=24 TN=1776 FN=18

Threshold-free: average precision 0.9592, ROC-AUC 0.9760

## Per category

| Category | n | Recall | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| benign | 1800 | 0.0000 | 0.0133 | 0 | 24 | 0 |
| direct_prompt_injection | 250 | 0.9280 | 0.0000 | 232 | 0 | 18 |
| indirect_prompt_injection | 1 | 1.0000 | 0.0000 | 1 | 0 | 0 |

## Latency (detector only, not gateway overhead)

| Stage | mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| preprocess | 0.458 ms | 0.390 | 0.784 | 1.466 | 6.030 |
| inference | 119.529 ms | 106.940 | 164.813 | 318.535 | 925.633 |
| total | 119.987 ms | 107.291 | 165.632 | 320.249 | 927.768 |

Single-threaded throughput: 8.3/s (reciprocal of mean latency — not a concurrency measurement).

## Operating points

| Threshold | Recall | Precision | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| 0.0 | 1.0000 | 0.1224 | 1.0000 | 251 | 1800 | 0 |
| 0.0 | 0.9602 | 0.4949 | 0.1367 | 241 | 246 | 10 |
| 0.0 | 0.9602 | 0.5465 | 0.1111 | 241 | 200 | 10 |
| 0.0001 | 0.9602 | 0.5907 | 0.0928 | 241 | 167 | 10 |
| 0.0001 | 0.9562 | 0.6316 | 0.0778 | 240 | 140 | 11 |
| 0.0002 | 0.9562 | 0.6685 | 0.0661 | 240 | 119 | 11 |
| 0.0006 | 0.9562 | 0.7143 | 0.0533 | 240 | 96 | 11 |
| 0.0011 | 0.9522 | 0.7563 | 0.0428 | 239 | 77 | 12 |
| 0.0032 | 0.9363 | 0.8020 | 0.0322 | 235 | 58 | 16 |
| 0.0145 | 0.9323 | 0.8571 | 0.0217 | 234 | 39 | 17 |
| 0.78 | 0.9203 | 0.9059 | 0.0133 | 231 | 24 | 20 |
| 1.0 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 251 |

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
* Config hash: `sha256:274d95c147c9d407`
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

