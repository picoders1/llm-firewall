# ADR-020 Steps 0 and 1 — proxy validation and seed variance

Generated 2026-08-17T17:51:45.059552+00:00. No training. No hold-out was read.

## Step 0 — does the proxy reproduce a known effect?

Retention signal: `lakera-gandalf`, 999 human-authored system-prompt-extraction attacks.

| threshold | Strategy A | ADR-019 | Δ | b | c | McNemar p | direction | gate |
|---|---|---|---|---|---|---|---|---|
| dev | 0.9720 | 0.9520 | -0.0200 | 23 | 3 | 0.000088 | reproduced | PASS |
| matched_fpr | 0.9690 | 0.9069 | -0.0621 | 63 | 1 | 0.000000 | reproduced | PASS |

**Step 0 gate: PASSED**

## Step 1 — condition effect versus seed effect

### At the dev threshold

| family | seed 13 | seed 20260817 | seed 31337 | mean | spread |
|---|---|---|---|---|---|
| Strategy A | 0.9720 | 0.9780 | 0.9770 | 0.9756 | 0.0060 |
| ADR-019 | 0.9520 | 0.9630 | 0.9580 | 0.9576 | 0.0110 |

Between-condition gap **+0.0180**, largest within-condition seed spread **0.0110**. Gap exceeds seed spread: **True**. Families fully disjoint across seeds: **True**.

Exact one-sided permutation test on run-level means: **p = 0.0500** over 20 permutations. With three runs per group the smallest attainable p is 0.0500, so this is the floor — the strongest result three seeds can give, and it sits exactly on the conventional threshold.

### At the matched_fpr threshold

| family | seed 13 | seed 20260817 | seed 31337 | mean | spread |
|---|---|---|---|---|---|
| Strategy A | 0.9690 | 0.9700 | 0.9770 | 0.9720 | 0.0080 |
| ADR-019 | 0.9069 | 0.9269 | 0.9039 | 0.9126 | 0.0230 |

Between-condition gap **+0.0594**, largest within-condition seed spread **0.0230**. Gap exceeds seed spread: **True**. Families fully disjoint across seeds: **True**.

Exact one-sided permutation test on run-level means: **p = 0.0500** over 20 permutations. With three runs per group the smallest attainable p is 0.0500, so this is the floor — the strongest result three seeds can give, and it sits exactly on the conventional threshold.

## Threshold underdetermination (OD-33)

All six dev splits separate perfectly (`separable=True`), so the dev-selected threshold is free to land anywhere inside the separating gap. It does:

| checkpoint | dev-selected τ | matched-FPR τ |
|---|---|---|
| `stratA__lr1e-05__ep2__seed13` | 0.9955 | 0.996223 |
| `stratA__lr1e-05__ep2__seed20260817` | 0.8954 | 0.993047 |
| `stratA__lr1e-05__ep2__seed31337` | 0.9931 | 0.993923 |
| `mech__lr1e-05__ep2__seed13` | 0.9954 | 0.999380 |
| `mech__lr1e-05__ep2__seed20260817` | 0.0694 | 0.998492 |
| `mech__lr1e-05__ep2__seed31337` | 0.9900 | 0.999559 |

Range **0.0694 – 0.9955**, spread **0.9261**. Identical methodology, identical dev split within a family, yet the chosen threshold varies by nearly the whole unit interval. Any cross-model comparison at dev-selected thresholds compares two arbitrary points inside two separating gaps; the matched-FPR rows are the commensurable ones.

