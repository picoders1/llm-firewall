# ADR-020 Step 3 — final evaluation

**Decision: FAILURE.** Deployment candidate `T2__lr1e-05__ep2__seed13`; `T3__lr1e-05__ep1__seed13` scored as contrast only and never selectable.

One evaluation event, two locked targets, thresholds frozen before the hold-out was read. holdout-v3 and mechanisms-v1 each consumed one scoring.

## Retention — the criterion that decides

| metric | Strategy A | ADR-019 | T2 | T3 | registered floor | T2 meets |
|---|---|---|---|---|---|---|
| extraction recall | 0.8446 | 0.7534 | **0.7669** | 0.7905 | 0.7946 | **NO** |
| attack recall | 0.8174 | 0.764 | **0.7725** | 0.7809 | 0.7674 | yes |
| benign FPR | 0.0092 | 0.0161 | 0.0069 | 0.0069 | not worse | yes |
| quoted_attack FPR | 0.0429 | 0.0571 | 0.0143 | 0.0286 | not worse | yes |
| hard-negative FPR | 0.0167 | — | 0.0125 | 0.0125 | not worse | yes |

**Both arms degrade significantly against Strategy A on the paired test** (extraction p = 0.000034 for T2, 0.000145 for T3). False-positive rates improved across the board — the replay made both models more conservative — but that is not what the criterion asks.

## How much of ADR-019's regression each intervention recovered

ADR-019 lost 0.0912 of extraction recall against Strategy A.

| arm | varies | extraction | recovered | share of the gap |
|---|---|---|---|---|
| T2 | composition (90/10 replay, 486 steps) | 0.7669 | +0.0135 | **15%** |
| T3 | adaptation budget (same sampler, 243 steps) | 0.7905 | +0.0371 | **41%** |

Neither closes it. **Composition — the leading hypothesis — is the weaker of the two.**

## What it cost

| mechanism | ADR-019 | T2 | T3 |
|---|---|---|---|
| retrieval_poisoning | 0.7333 | 0.3167 | 0.1167 |
| tool_use_manipulation | 0.7333 | 0.35 | 0.05 |
| safety_bypass | 0.9667 | 0.85 | 0.6833 |

Two of the three mechanisms collapsed. R-49 was registered in advance as the central risk of the 90/10 mixture and it materialised at full force: mechanism exposure fell from ~119 to 53 samples per epoch, and recall fell with it.

Benign controls held perfectly for both arms — 0 false positives on all 178 controls including all 90 document-carried. The models did not learn 'retrieved content is malicious'.

## Performance

| arm | mean | p50 | p95 | p99 | throughput | peak VRAM |
|---|---|---|---|---|---|---|
| T2 | 11.6149 ms | 11.8261 ms | 12.3604 ms | 12.6472 ms | 86.1/s | 0.952 GB |
| T3 | 11.7956 ms | 12.0565 ms | 12.4935 ms | 12.7174 ms | 84.78/s | 0.952 GB |

Latency is detector-only, GPU, single-sample, warm, tokenisation included — the same methodology as every prior run, so the percentiles are comparable with them. **Peak VRAM is not.** It was captured after the batched scoring pass over 792 + 358 samples, so it reflects batch-32 inference rather than the single-sample figure ADR-019 reported (0.755 GB). The two measure different things and are not compared here. No gateway-overhead claim is made from any of these.

