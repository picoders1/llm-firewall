## Blocking-readiness criteria on the frozen hold-out

Checkpoint `stratA__lr1e-05__ep2__seed13` at the dev-calibrated threshold 0.9955. A criterion whose Wilson 95% interval straddles its bound is not met (ADR-015).

| Criterion | Bound | Measured | Wilson 95% | n | Verdict |
|---|---|---|---|---|---|
| Overall benign FPR | <= 0.0241 | 0.0066 | [0.0022, 0.0191] | 457 | **MET** |
| Hard-negative FPR | <= 0.1 | 0.0118 | [0.0032, 0.0419] | 170 | **MET** |
| quoted_attack FPR | <= 0.15 | 0.0625 | [0.0111, 0.2833] | 16 | **NOT MET** — CI upper 0.2833 straddles 0.15 |
| incident_response FPR | <= 0.1 | 0.0000 | [0.0000, 0.1843] | 17 | **NOT MET** — CI upper 0.1843 straddles 0.1 |
| Attack recall | >= 0.8 | 0.8833 | [0.7782, 0.9423] | 60 | **NOT MET** — CI lower 0.7782 straddles 0.8 |
| Extraction recall | >= 0.8 | 0.8444 | [0.7122, 0.9225] | 45 | **NOT MET** — CI lower 0.7122 straddles 0.8 |

## Pre-registered failure criteria

| Failure criterion | Triggered? | Measured |
|---|---|---|
| quoted_attack FPR > 0.40 — the core failure survived | no | 0.0625 |
| attack recall < 0.75 — bought FPR with security | no | 0.8833 |
| extraction recall < 0.70 — regressed the selecting capability | no | 0.8444 |

## Three systems, same frozen hold-out

The heuristic and base-model columns are re-read from `eval/results/20260817T102936Z__threshold-deployability/predictions.jsonl`; no model was re-run to produce them.

| Metric | injection.heuristic @0.85 | ProtectAI base @0.9995 | Strategy A fine-tuned @0.9955 |
|---|---|---|---|
| Attack recall | 0.3167 | 0.8833 | 0.8833 |
| Extraction recall | 0.2667 | 0.8444 | 0.8444 |
| Overall benign FPR | 0.0241 | 0.0678 | 0.0066 |
| Hard-negative FPR | 0.0647 | 0.1706 | 0.0118 |
| quoted_attack FPR | 0.5000 | 0.8750 | 0.0625 |
| incident_response FPR | 0.2941 | 0.4118 | 0.0000 |
| Latency mean (ms) | 0.053 | 97.590 | 11.352 |

## Hard-negative categories: base vs Strategy A

| Category | n | base FPR | Strategy A FPR | change | Strategy A Wilson 95% |
|---|---|---|---|---|---|
| quoted_attack | 16 | 0.8750 | 0.0625 | -0.8125 | [0.0111, 0.2833] |
| incident_response | 17 | 0.4118 | 0.0000 | -0.4118 | [0.0000, 0.1843] |
| security_operations | 32 | 0.2188 | 0.0000 | -0.2188 | [0.0000, 0.1072] |
| security_policy | 10 | 0.2000 | 0.0000 | -0.2000 | [0.0000, 0.2775] |
| ignore_previous_ordinary | 17 | 0.1765 | 0.0000 | -0.1765 | [0.0000, 0.1843] |
| human_instructions | 12 | 0.1667 | 0.0833 | -0.0834 | [0.0149, 0.3539] |
| code_with_attack_strings | 5 | 0.4000 | 0.0000 | -0.4000 | [0.0000, 0.4345] |
| technical_documentation | 30 | 0.0667 | 0.0333 | -0.0334 | [0.0059, 0.1667] |

## Attack retention: base vs Strategy A

| Attack category | n | base recall | Strategy A recall | change | Strategy A Wilson 95% |
|---|---|---|---|---|---|
| direct_prompt_injection | 10 | 1.0000 | 1.0000 | +0.0000 | [0.7225, 1.0000] |
| indirect_injection | 5 | 1.0000 | 1.0000 | +0.0000 | [0.5655, 1.0000] |
| system_prompt_extraction | 45 | 0.8444 | 0.8444 | +0.0000 | [0.7122, 0.9225] |
| jailbreak | 8 | — | 0.6250 | — | [0.3057, 0.8632] |
| role_override | 0 | — | — | — | not a category in the hold-out taxonomy |
| context_override | 0 | — | — | — | not a category in the hold-out taxonomy |

## Dev to hold-out generalisation

| Metric | base (dev) | Strategy A (dev) | base (hold-out) | Strategy A (hold-out) |
|---|---|---|---|---|
| Overall benign FPR | 0.4992 | 0.0000 | 0.0678 | 0.0066 |
| quoted_attack FPR | 0.7949 | 0.0000 | 0.8750 | 0.0625 |
| Attack recall | 0.9477 | 1.0000 | 0.8833 | 0.8833 |
| Extraction recall | 0.8793 | 1.0000 | 0.8444 | 0.8444 |

**Case 1 — dev improves and hold-out improves: supports generalisation**

Hard-negative FPR relative reduction vs base: **+93.1%** (partial-success bar: >= 30% with recall within 5 points → met).

All blocking criteria met simultaneously: **False**

Any pre-registered failure criterion triggered: **False**


### Pre-registered decision: **PARTIAL SUCCESS**


## Latency and memory

| Statistic | base (prior run) | Strategy A |
|---|---|---|
| mean (ms) | 97.590 | 11.352 |
| p50 (ms) | 94.478 | 11.141 |
| p95 (ms) | 117.160 | 12.510 |
| p99 (ms) | 188.794 | 17.895 |
| throughput (req/s, single-threaded) | — | 88.09 |
| peak VRAM (GB, inference) | — | 0.767 |
| device | CPU (prior run) | cuda |

The two latency columns were measured on different devices and are **not** a like-for-like comparison; the architecture is unchanged by fine-tuning, which is the claim being checked.

