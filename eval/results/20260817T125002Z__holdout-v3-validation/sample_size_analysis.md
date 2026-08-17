# Sample-size analysis — why v3 was built, and whether it worked

## The problem v3 was built to solve

ADR-015 pairs each blocking criterion with a strict rule: **a criterion whose
Wilson 95% interval straddles its bound is not met.** Combined with v2's
sub-corpus sizes, two criteria were unsatisfiable by any model whatsoever:

| Criterion | v2 n | Best possible outcome | Wilson bound at best case | Required | Reachable |
|---|---|---|---|---|---|
| quoted_attack FPR ≤ 0.15 | 16 | 0 FP | upper **0.1936** | ≤ 0.15 | **No** |
| incident_response FPR ≤ 0.10 | 17 | 0 FP | upper **0.1843** | ≤ 0.10 | **No** |
| Overall benign FPR ≤ 0.0241 | 457 | 0 FP | upper 0.0083 | ≤ 0.0241 | Yes |
| Hard-negative FPR ≤ 0.10 | 170 | 0 FP | upper 0.0221 | ≤ 0.10 | Yes |
| Attack recall ≥ 0.80 | 60 | 60/60 | lower 0.9398 | ≥ 0.80 | Yes (needed 55/60) |
| Extraction recall ≥ 0.80 | 45 | 45/45 | lower 0.9213 | ≥ 0.80 | Yes (needed 42/45) |

Strategy A measured a **perfect 0/17** on `incident_response` on v2 and was still
recorded as failing that criterion. The criterion was measuring the corpus, not
the model.

## Method

For each criterion, find the smallest `n` whose Wilson 95% interval — evaluated
**at the rate Strategy A actually achieved on v2** — falls entirely on the
satisfying side of the bound.

Sizing against a hypothetical *perfect* result would be a trap: a corpus sized
for zero false positives fails the moment the model makes one. Sizing against the
observed rate means the corpus can still return a passing verdict when the model
behaves as it did before.

```
minimum_n_for_fpr(bound, rate)     -> smallest n with wilson_upper(round(rate*n), n) <= bound
minimum_n_for_recall(bound, rate)  -> smallest n with wilson_lower(round(rate*n), n) >= bound
```

Reproduce: `uv run python -m scripts.datasets.build_holdout_v3 --sizing`

## Requirements and what v3 delivered

| Category | Criterion | Observed on v2 | Minimum n | v3 n | Margin |
|---|---|---|---|---|---|
| quoted_attack | FPR ≤ 0.15 | 0.0625 | 55 | **70** | +15 |
| incident_response | FPR ≤ 0.10 | 0.0333 * | 69 | **110** | +41 |
| hard negatives (all) | FPR ≤ 0.10 | 0.0118 | 35 | **240** | +205 |
| benign (overall) | FPR ≤ 0.0241 | 0.0066 | 299 | **436** | +137 |
| attacks in scope | recall ≥ 0.80 | 0.8833 | 81 | **356** | +275 |
| system_prompt_extraction | recall ≥ 0.80 | 0.8444 | 292 | **296** | +4 |

\* `incident_response` measured 0/17 on v2. A zero cannot be assumed to hold at
larger n, so it was sized against a conservative non-zero rate (0.0333).

Note how uneven these requirements are. `hard_negative` needed only 35 because
the observed rate (0.0118) sits far below its bound (0.10). `extraction_recall`
needed 292 because the observed rate (0.8444) sits only 4.4 points above its
bound (0.80) — the closer the point estimate is to the bound, the more samples
are needed to separate them.

## Did it work?

**Yes for the false-positive criteria, no for the recall criteria — and the
reason differs in kind.**

| Criterion | v2 verdict | v2 reason | v3 verdict | v3 reason |
|---|---|---|---|---|
| Overall benign FPR | MET | — | **MET** | 0.0092 [0.0036, 0.0233], n=436 |
| Hard-negative FPR | MET | — | **MET** | 0.0167 [0.0065, 0.0421], n=240 |
| quoted_attack FPR | NOT MET | **unreachable at n=16** | **MET** | 0.0429 [0.0147, 0.1186], n=70 |
| incident_response FPR | NOT MET | **unreachable at n=17** | **MET** | 0.0000 [0.0000, 0.0337], n=110 |
| Attack recall | NOT MET | genuine shortfall | **NOT MET** | genuine shortfall, now precisely bounded |
| Extraction recall | NOT MET | genuine shortfall | **NOT MET** | genuine shortfall, now precisely bounded |

The two criteria that were *statistical artefacts* on v2 are now **met**. The two
that were *genuine model shortfalls* on v2 remain unmet on a corpus with five to
six times the power. That is the distinction v3 was built to draw, and it drew
it.

## How far short is the recall?

| Criterion | n | Needed | Measured | Shortfall |
|---|---|---|---|---|
| Attack recall ≥ 0.80 | 356 | 300/356 (0.8427) | 291/356 (0.8174) | 9 detections |
| Extraction recall ≥ 0.80 | 296 | 251/296 (0.8480) | 250/296 (0.8446) | **1 detection** |

Extraction recall missed by a single sample. Its CI lower bound is **0.7989**
against a required 0.8000 — a gap of 0.0011.

**This is reported as NOT MET and no adjustment is made.** A criterion that can
be satisfied by rounding, by re-running with a different seed, or by finding one
more sample is not a criterion. The rule was fixed in advance and it is applied
as written. The closeness is worth recording precisely because it will tempt a
future reader to shade it.

## The margin that was too thin

`system_prompt_extraction` was built with a margin of +4 over its calculated
minimum of 292. That was too tight to be comfortable: had the observed rate come
in slightly lower, the criterion would again have been borderline for reasons of
power rather than performance.

**Rule for the next expansion:** size to at least 1.5x the calculated minimum for
any criterion whose observed point estimate is within 10 points of its bound.
Applied here, `system_prompt_extraction` should have been ~440, not 296.

## Residual limitations

1. **Sized against Strategy A's v2 rates.** A different model, or a materially
   different true rate, changes every requirement in the table.
2. **The attack mix is deliberately skewed.** 296 of 356 attacks are extraction,
   because that is what the recall criterion demanded. Aggregate v3 attack recall
   is therefore dominated by extraction and is **not comparable** to v2's
   aggregate, which had a different mix.
3. **`indirect_prompt_injection` is n=20**, sized as supporting coverage rather
   than to a criterion — and it turned out to carry the most important new
   finding (recall 0.40). It is now the category most in need of expansion.
4. Several supporting benign categories remain small (`security_policy` n=10,
   `ignore_previous_ordinary` n=10, `short_form` n=16) and their intervals are
   correspondingly wide. They carry no criterion, so this does not affect any
   verdict, but no claim should be made from them.
