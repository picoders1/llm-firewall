# ADR-020 Step 3 — retention analysis

Reference is Strategy A, published and unrestated. Both candidates are scored at their own matched-FPR thresholds (amendment A-2), frozen before the hold-out was read.

## holdout-v3, against Strategy A

| metric | Strategy A | ADR-019 | T2 | T3 | floor |
|---|---|---|---|---|---|
| attack_recall | 0.8174 | 0.764 | 0.7725 | 0.7809 | 0.7674 |
| extraction_recall | 0.8446 | 0.7534 | 0.7669 | 0.7905 | 0.7946 |
| benign_fpr | 0.0092 | 0.0161 | 0.0069 | 0.0069 | — |
| quoted_attack_fpr | 0.0429 | 0.0571 | 0.0143 | 0.0286 | — |
| hard_negative_fpr | 0.0167 | — | 0.0125 | 0.0125 | — |

## Paired comparison against Strategy A (same samples, exact McNemar)

| arm | metric | n | b (A only) | c (arm only) | net | p | degradation significant |
|---|---|---|---|---|---|---|---|
| T2 | extraction_recall | 296 | 27 | 4 | -23 | 0.000034 | YES |
| T2 | attack_recall | 356 | 29 | 13 | -16 | 0.019520 | YES |
| T3 | extraction_recall | 296 | 17 | 1 | -16 | 0.000145 | YES |
| T3 | attack_recall | 356 | 20 | 7 | -13 | 0.019157 | YES |

## Strategy A re-thresholded to its own matched-FPR point

Included so the comparison is at a matched operating point rather than at two arbitrary points inside two separating gaps (A-2). Computed from **stored** per-sample scores: no model was run and no scoring budget was consumed.

At tau=0.996223: attack recall 0.8118, extraction 0.8378, benign FPR 0.0092, quoted_attack FPR 0.0429.

## holdout-v3 benign-group breakdown

| group | n | T2 FP | T2 FPR | T2 CI95 | T3 FP | T3 FPR | T3 CI95 |
|---|---|---|---|---|---|---|---|
| quoted_attack | 70 | 1 | 0.0143 | [0.0025, 0.0766] | 2 | 0.0286 | [0.0079, 0.0983] |
| incident_response | 110 | 2 | 0.0182 | [0.005, 0.0639] | 1 | 0.0091 | [0.0016, 0.0497] |
| security_operations | 41 | 1 | 0.0244 | [0.0043, 0.126] | 2 | 0.0488 | [0.0135, 0.1614] |
| security_policy | 10 | 0 | 0.0 | [0.0, 0.2775] | 0 | 0.0 | [0.0, 0.2775] |
| technical_documentation | 14 | 0 | 0.0 | [0.0, 0.2153] | 0 | 0.0 | [0.0, 0.2153] |
| human_instructions | 12 | 0 | 0.0 | [0.0, 0.2425] | 0 | 0.0 | [0.0, 0.2425] |
| ignore_previous_ordinary | 10 | 0 | 0.0 | [0.0, 0.2775] | 0 | 0.0 | [0.0, 0.2775] |
| code_with_attack_strings | 24 | 0 | 0.0 | [0.0, 0.138] | 0 | 0.0 | [0.0, 0.138] |
| routine_request | 150 | 0 | 0.0 | [0.0, 0.025] | 0 | 0.0 | [0.0, 0.025] |
| short_form | 16 | 0 | 0.0 | [0.0, 0.1936] | 0 | 0.0 | [0.0, 0.1936] |
