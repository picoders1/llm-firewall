# Evaluation — baseline.always_benign

**Run:** `20260817T083203Z__baseline-always_benign__full-dev`  
**Benchmark:** `full` / `dev`  
**Samples:** 2150 (352 attack, 1798 benign)  
**Threshold:** 1.0

> Internal benchmark result. **Not** a published project metric.

## Classification

| Metric | Value | 95% CI |
|---|---|---|
| Recall (detection rate) | 0.0000 | [0.000, 0.011] |
| Precision | 0.0000 | [0.000, 0.000] |
| **FPR** | **0.0000** | [0.000, 0.002] |
| FNR | 1.0000 | — |
| F1 | 0.0000 | — |
| Accuracy | 0.8363 | — |

Confusion: TP=0 FP=0 TN=1798 FN=352

Threshold-free: average precision 0.4832, ROC-AUC 0.5000

## Per category

| Category | n | Recall | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| benign | 1798 | 0.0000 | 0.0000 | 0 | 0 | 0 |
| direct_prompt_injection | 228 | 0.0000 | 0.0000 | 0 | 0 | 228 |
| indirect_prompt_injection | 3 | 0.0000 | 0.0000 | 0 | 0 | 3 |
| jailbreak | 117 | 0.0000 | 0.0000 | 0 | 0 | 117 |
| pii | 1 | 0.0000 | 0.0000 | 0 | 0 | 1 |
| system_prompt_extraction | 3 | 0.0000 | 0.0000 | 0 | 0 | 3 |

## Latency (detector only, not gateway overhead)

| Stage | mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| preprocess | 0.000 ms | 0.000 | 0.000 | 0.000 | 0.000 |
| inference | 0.000 ms | 0.000 | 0.000 | 0.000 | 0.000 |
| total | 0.000 ms | 0.000 | 0.000 | 0.000 | 0.000 |

Single-threaded throughput: 0.0/s (reciprocal of mean latency — not a concurrency measurement).

## Operating points

| Threshold | Recall | Precision | FPR | TP | FP | FN |
|---|---|---|---|---|---|---|
| 0.0 | 1.0000 | 0.1637 | 1.0000 | 352 | 1798 | 0 |
| 0.01 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 352 |

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
* Config hash: `sha256:530c4dddf1fa965a`
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

