# Independent hold-out — FPR validation

Benign denominator: **457**. Thresholds **frozen** from prior calibration; none was selected on this data.

| Detector | threshold | benign n | FP | TN | FPR | 95% CI (Wilson) |
|---|---|---|---|---|---|---|
| `injection.heuristic` | 0.85 | 457 | 11 | 446 | **0.0241** | [0.0135, 0.0426] |
| `injection.protectai_deberta_v2` | 0.5 | 457 | 55 | 402 | **0.1204** | [0.0936, 0.1534] |
| `injection.arch_guard` | 0.5 | 457 | 64 | 393 | **0.1400** | [0.1112, 0.1749] |

## Hard negatives vs ordinary benign

| Detector | hard n | hard FP | hard FPR | ordinary n | ord FP | ord FPR |
|---|---|---|---|---|---|---|
| `injection.heuristic` | 170 | 11 | **0.0647** | 287 | 0 | 0.0000 |
| `injection.protectai_deberta_v2` | 170 | 49 | **0.2882** | 287 | 6 | 0.0209 |
| `injection.arch_guard` | 170 | 52 | **0.3059** | 287 | 12 | 0.0418 |

## System-prompt extraction (ADR-014 rationale check)

| Detector | n | detected | recall | 95% CI |
|---|---|---|---|---|
| `injection.heuristic` | 45 | 12 | **0.2667** | [0.1596, 0.4104] |
| `injection.protectai_deberta_v2` | 45 | 42 | **0.9333** | [0.8214, 0.9771] |
| `injection.arch_guard` | 45 | 22 | **0.4889** | [0.3496, 0.6300] |

## Latency (detector only)

| Detector | mean ms | p95 ms |
|---|---|---|
| `injection.heuristic` | 0.045 | 0.071 |
| `injection.protectai_deberta_v2` | 84.524 | 97.218 |
| `injection.arch_guard` | 92.255 | 118.430 |

Artefacts: `metrics.json`, `predictions.jsonl`, `fpr_analysis.md`, `fpr_comparison.svg`, `hard_negative_fpr.svg`, `score_distribution.svg`.

