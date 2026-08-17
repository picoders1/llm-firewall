# Evaluation — injection.protectai_deberta_v2

**Run:** `20260817T083455Z__injection-protectai_deberta_v2__full-dev`  
**Benchmark:** `full` / `dev`  
**Samples:** 2032 (234 attack, 1798 benign)  
**Threshold:** 0.5

> Internal benchmark result. **Not** a published project metric.

## ⚠ Validity warnings

* 118 samples outside injection.protectai_deberta_v2's scope were excluded; it is not answerable for those categories and scoring them would fabricate a recall number

## Classification

| Metric | Value | 95% CI |
|---|---|---|
| Recall (detection rate) | 0.8846 | [0.837, 0.919] |
| Precision | 0.9000 | [0.854, 0.932] |
| **FPR** | **0.0128** | [0.009, 0.019] |
| FNR | 0.1154 | — |
| F1 | 0.8922 | — |
| Accuracy | 0.9754 | — |

Confusion: TP=207 FP=23 TN=1775 FN=27

Threshold-free: average precision 0.9299, ROC-AUC 0.9738

## Per category

| Category | n | Recall | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| benign | 1798 | 0.0000 | 0.0128 | 0 | 23 | 0 |
| direct_prompt_injection | 228 | 0.8816 | 0.0000 | 201 | 0 | 27 |
| indirect_prompt_injection | 3 | 1.0000 | 0.0000 | 3 | 0 | 0 |
| system_prompt_extraction | 3 | 1.0000 | 0.0000 | 3 | 0 | 0 |

## Latency (detector only, not gateway overhead)

| Stage | mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| preprocess | 0.476 ms | 0.405 | 0.805 | 1.601 | 4.922 |
| inference | 121.786 ms | 108.481 | 169.941 | 342.156 | 929.672 |
| total | 122.262 ms | 108.875 | 170.688 | 343.826 | 932.788 |

Single-threaded throughput: 8.2/s (reciprocal of mean latency — not a concurrency measurement).

## Operating points

| Threshold | Recall | Precision | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| 0.0 | 1.0000 | 0.1152 | 1.0000 | 234 | 1798 | 0 |
| 0.0 | 0.9487 | 0.4713 | 0.1385 | 222 | 249 | 12 |
| 0.0 | 0.9487 | 0.5248 | 0.1118 | 222 | 201 | 12 |
| 0.0001 | 0.9444 | 0.5638 | 0.0951 | 221 | 171 | 13 |
| 0.0001 | 0.9402 | 0.6077 | 0.0790 | 220 | 142 | 14 |
| 0.0002 | 0.9359 | 0.6499 | 0.0656 | 219 | 118 | 15 |
| 0.0004 | 0.9274 | 0.6911 | 0.0539 | 217 | 97 | 17 |
| 0.0015 | 0.9231 | 0.7474 | 0.0406 | 216 | 73 | 18 |
| 0.0075 | 0.9060 | 0.7940 | 0.0306 | 212 | 55 | 22 |
| 0.03 | 0.8889 | 0.8387 | 0.0222 | 208 | 40 | 26 |
| 0.52 | 0.8846 | 0.9039 | 0.0122 | 207 | 22 | 27 |
| 1.0 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 234 |

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

