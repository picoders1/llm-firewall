# ADR-020 Step 2 — controlled retention-preserving training

Generated 2026-08-17T18:36:53.868621+00:00. **6/6 runs succeeded.** No protected hold-out was read.

## The registered mixture, as realised

| target | registered | realised (seed 13, epoch 0) | met |
|---|---|---|---|
| v1 share | 0.9 | 0.899949 | yes |
| extension share | 0.1 | 0.100051 | yes |
| attack fraction | 0.194022 | 0.19393 | yes |
| extraction share of attacks | >= 0.389189 | 0.38992 | yes |

Mechanisms exactly balanced at {'retrieval_poisoning': 53, 'tool_use_manipulation': 53, 'safety_bypass': 53}. 2579 unique samples across 3888 draws (1.51x mean repetition) — the replay, and the registered memorisation risk R-50.

A property worth stating plainly: because the strata are drawn **with replacement** where a pool is smaller than its quota, one epoch touches 2579 of the 3878 available training rows (**66.5% coverage**). The replay arm is not 'the whole corpus plus extra extraction'; it is a resampled corpus. Extraction is oversampled 1.28x from a pool of 230, and v1 benign is oversampled to fill its 90% share.

## What the replay actually changed (T2 vs ADR-019, §3)

| factor | ADR-019 (natural) | T2/T3 (replay) | delta |
|---|---|---|---|
| v1 share | 0.7751 | 0.8999 | +0.1248 |
| extension share | 0.2249 | 0.1001 | -0.1248 |
| attack fraction | 0.2434 | 0.1939 | -0.0495 |
| extraction share of attack mass | 0.2436 | 0.3899 | +0.1463 |
| extraction samples/epoch | 230 | 294 | +64 |
| retrieval_poisoning samples/epoch | 122 | 53 | -69 |
| tool_use_manipulation samples/epoch | 116 | 53 | -63 |
| safety_bypass samples/epoch | 119 | 53 | -66 |
| optimisation steps | 486 | 486 (T2) / 243 (T3) | T2 identical |

T2 restores precisely what ADR-019 diluted: extraction's share of attack mass returns from 0.2436 to 0.3899, against v1's original 0.3892, at an **identical 486-step budget**. That is the composition intervention, aimed at candidate cause C2 and nothing else. Its price is mechanism exposure roughly halved (~119 to 53 samples per epoch each), which is R-49.

## Four-way comparison (pre-hold-out information only)

| arm | corpus / sampler | steps | epochs | seeds | dev split | dev F1 | mean duration |
|---|---|---|---|---|---|---|---|
| Strategy A *(not re-run)* | finetune-v1, natural | 376 | 2 | 3 | v1 dev (808) | [1.0] | 161.5s |
| ADR-019 *(not re-run)* | finetune-v2, natural | 486 | 2 | 3 | v2 dev (1044) | [0.998, 1.0] | 260.0s |
| **T2** | v2 rows, 90/10 replay | 486 | 2 | 3 | v2 dev (1044) | [0.998, 1.0] | 209.0s |
| **T3** | v2 rows, 90/10 replay | 243 | 1 | 3 | v2 dev (1044) | [0.9639, 0.9732, 0.9753] | 133.8s |

Strategy A's dev split is **finetune-v1 dev (808)**, a different population from the v2 dev (1044) shared by ADR-019, T2 and T3. Only the latter three are directly comparable on dev.

## Dev diagnostics (§19, §20) — diagnostics only

| run | dev F1 | dev FPR | extraction | quoted_attack FPR | retrieval_poisoning | tool_use_manipulation | safety_bypass | dev tau |
|---|---|---|---|---|---|---|---|---|---|
| `T2__lr1e-05__ep2__seed13` | 0.998 | 0.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.38 |
| `T2__lr1e-05__ep2__seed20260817` | 1.0 | 0.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 | 0.6296 |
| `T2__lr1e-05__ep2__seed31337` | 0.998 | 0.0 | 1.0 | 0.0 | 1.0 | 0.9706 | 1.0 | 0.17 |
| `T3__lr1e-05__ep1__seed13` | 0.9753 | 0.0038 | 1.0 | 0.0 | 0.9286 | 0.8235 | 1.0 | 0.1035 |
| `T3__lr1e-05__ep1__seed20260817` | 0.9639 | 0.015 | 1.0 | 0.0 | 0.9643 | 0.8824 | 1.0 | 0.3231 |
| `T3__lr1e-05__ep1__seed31337` | 0.9732 | 0.0038 | 1.0 | 0.0 | 0.9643 | 0.7647 | 1.0 | 0.0642 |

Dev separates the runs on: ['dev_f1', 'dev_fpr', 'dev_recall', 'dev_retrieval_poisoning_recall', 'dev_tool_use_manipulation_recall']. Treated as diagnostic only; selection happens in Step 3.

## Resource usage

| run | steps | duration | peak VRAM |
|---|---|---|---|
| `T2__lr1e-05__ep2__seed13` | 486 | 199.63s | 3.182 GB |
| `T2__lr1e-05__ep2__seed20260817` | 486 | 212.79s | 3.182 GB |
| `T2__lr1e-05__ep2__seed31337` | 486 | 214.46s | 3.182 GB |
| `T3__lr1e-05__ep1__seed13` | 243 | 133.01s | 3.182 GB |
| `T3__lr1e-05__ep1__seed20260817` | 243 | 134.41s | 3.182 GB |
| `T3__lr1e-05__ep1__seed31337` | 243 | 133.87s | 3.182 GB |

NVIDIA GeForce RTX 3050 Laptop GPU · CUDA 12.4 · torch 2.6.0+cu124 · Python 3.12.3

T2 and ADR-019 run the identical 486-step budget, yet their wall-clock differs. **No cause is claimed for that.** The obvious candidate was sequence length, and it was checked and rejected: the replay epoch's per-micro-batch padded cost is *higher* (140,709 vs 122,808 characters) while its wall-clock is lower, so length does not explain it. Wall-clock here is not a controlled quantity — the two experiments ran at different times under different machine load — and no throughput claim is made from it.

