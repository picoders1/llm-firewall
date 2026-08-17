# Threshold sweep and deployability analysis

Calibration: `public/dev` (n=2018) — **excludes the independent hold-out**.  
Validation: independent hold-out (n=517), frozen thresholds only.

## Operating points

| Point | Threshold | Dev recall | Dev FPR | HO recall | HO FPR | HO FPR CI95 | HO hard-neg FPR | Latency |
|---|---|---|---|---|---|---|---|---|
| **heuristic (production)** | 0.85 | 0.4204 | 0.0000 | 0.3167 | **0.0241** | [0.0135, 0.0426] | 0.0647 | 0.053 ms |
| fpr<=0.005 | 0.9995 | 0.8584 | 0.0028 | 0.8833 | **0.0678** | [0.0482, 0.0947] | 0.1706 | 97.6 ms |
| fpr<=0.01 | 0.9850 | 0.8805 | 0.0067 | 0.9000 | **0.1050** | [0.0801, 0.1365] | 0.2529 | 97.6 ms |
| fpr<=0.02 | 0.9850 | 0.8805 | 0.0067 | 0.9000 | **0.1050** | [0.0801, 0.1365] | 0.2529 | 97.6 ms |
| fpr<=0.0241 | 0.0310 | 0.8850 | 0.0218 | 0.9500 | **0.1510** | [0.1211, 0.1867] | 0.3588 | 97.6 ms |
| fpr<=0.025 | 0.0310 | 0.8850 | 0.0218 | 0.9500 | **0.1510** | [0.1211, 0.1867] | 0.3588 | 97.6 ms |
| fpr<=0.05 | 0.0016 | 0.9204 | 0.0391 | 0.9500 | **0.1947** | [0.161, 0.2335] | 0.4353 | 97.6 ms |

## Hold-out false positives by sub-category, at each frozen point

| Sub-category | n benign | fpr<=0.005 | fpr<=0.01 | fpr<=0.02 | fpr<=0.0241 | fpr<=0.025 | fpr<=0.05 |
|---|---|---|---|---|---|---|---|
| quoted_attack | 16 | 0.875 | 0.938 | 0.938 | 0.938 | 0.938 | 0.938 |
| ignore_previous_ordinary | 17 | 0.176 | 0.353 | 0.353 | 0.647 | 0.647 | 0.706 |
| override_ordinary | 5 | 0.000 | 0.200 | 0.200 | 0.600 | 0.600 | 0.800 |
| human_instructions | 12 | 0.167 | 0.333 | 0.333 | 0.667 | 0.667 | 0.667 |
| security_policy | 10 | 0.200 | 0.400 | 0.400 | 0.500 | 0.500 | 0.800 |
| system_prompt_engineering | 10 | 0.200 | 0.200 | 0.200 | 0.300 | 0.300 | 0.300 |
| injection_discussion | 15 | 0.067 | 0.067 | 0.067 | 0.133 | 0.133 | 0.267 |
| jailbreak_discussion | 7 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| guardrail_docs | 18 | 0.056 | 0.167 | 0.167 | 0.222 | 0.222 | 0.333 |
| code_with_attack_strings | 5 | 0.400 | 0.400 | 0.400 | 0.600 | 0.600 | 0.600 |

## Hold-out false positives by business domain

| Domain | n benign | fpr<=0.005 | fpr<=0.01 | fpr<=0.02 | fpr<=0.0241 | fpr<=0.025 | fpr<=0.05 |
|---|---|---|---|---|---|---|---|
| security_operations | 32 | 0.219 | 0.281 | 0.281 | 0.344 | 0.344 | 0.438 |
| incident_response | 17 | 0.412 | 0.471 | 0.471 | 0.529 | 0.529 | 0.529 |
| technical_documentation | 30 | 0.067 | 0.133 | 0.133 | 0.267 | 0.267 | 0.267 |
| software_engineering | 75 | 0.040 | 0.040 | 0.040 | 0.107 | 0.107 | 0.133 |
| compliance | 36 | 0.056 | 0.111 | 0.111 | 0.139 | 0.139 | 0.278 |
| ai_safety | 31 | 0.097 | 0.129 | 0.129 | 0.161 | 0.161 | 0.161 |

## System-prompt extraction (ADR-014 rationale)

| Detector | threshold | n | TP | FN | recall | 95% CI |
|---|---|---|---|---|---|---|
| ProtectAI @ fpr<=0.005 | 0.9995 | 45 | 38 | 7 | 0.8444 | [0.7122, 0.9225] |
| ProtectAI @ fpr<=0.01 | 0.9850 | 45 | 39 | 6 | 0.8667 | [0.7382, 0.9374] |
| ProtectAI @ fpr<=0.02 | 0.9850 | 45 | 39 | 6 | 0.8667 | [0.7382, 0.9374] |
| ProtectAI @ fpr<=0.0241 | 0.0310 | 45 | 42 | 3 | 0.9333 | [0.8214, 0.9771] |
| ProtectAI @ fpr<=0.025 | 0.0310 | 45 | 42 | 3 | 0.9333 | [0.8214, 0.9771] |
| ProtectAI @ fpr<=0.05 | 0.0016 | 45 | 42 | 3 | 0.9333 | [0.8214, 0.9771] |
| Arch-Guard | 0.5 | 45 | 22 | 23 | 0.4889 | [0.3496, 0.63] |
| heuristic | 0.85 | 45 | 12 | 33 | 0.2667 | [0.1596, 0.4104] |

## Latency

| Detector | mean ms | p95 ms | vs heuristic |
|---|---|---|---|
| `injection.protectai_deberta_v2` | 97.590 | 115.392 | 1848x |
| `injection.heuristic` | 0.053 | 0.084 | 1x |
| `injection.arch_guard` | 93.305 | 106.620 | 1767x |

## Methodology guarantees

* Thresholds selected on `public/dev`, which excludes the independent hold-out; `_assert_no_holdout` raises if a hold-out sample reaches calibration.
* Operating points frozen to `operating_points.json` **before** the hold-out was scored.
* No threshold was adjusted after seeing hold-out results.
* Wilson 95% intervals on every rate; denominators reported throughout.

